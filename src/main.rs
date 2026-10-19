use clap::{ArgGroup, Parser, Subcommand};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::num::NonZeroUsize;
use std::process::ExitCode;

use pwned_core::{check, download};
use pwned_core::download::Progress;

/// Exit code returned when at least one checked password was found in the corpus.
const EXIT_CODE_PWNED: u8 = 1;

/// Exit code for a run that failed for an operational reason, or that panicked.
///
/// Picked to stay clear of the two codes a caller is most likely to care about:
/// `1` means "found something", and clap owns `2` for usage errors. Neither can
/// be used to signal a broken run, so `pwned` reports:
///
/// | code | meaning                                    |
/// |------|--------------------------------------------|
/// | 0    | success; nothing was found                 |
/// | 1    | at least one password was found            |
/// | 2    | usage error (printed by clap, never by us) |
/// | 3    | operational failure, including a panic     |
const EXIT_CODE_OPERATIONAL: u8 = 3;

/// Where the corpus is stored, if `--cache-dir` was not given.
///
/// Follows each platform's convention: `$XDG_CACHE_HOME/pwned` or `~/.cache/pwned`
/// on Linux, `~/Library/Caches/pwned` on macOS, `%LOCALAPPDATA%\pwned\cache` on Windows.
fn default_cache_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("", "", "pwned")
        .map(|dirs| dirs.cache_dir().to_path_buf())
        .context(
            "could not determine the default cache directory; \
             pass one explicitly with --cache-dir",
        )
}

/// Makes a panic exit the process instead of being swallowed.
///
/// Most of the work happens in spawned tokio tasks, and a panic in a task that
/// is never joined is caught by the runtime: the task dies, the run carries on,
/// and the process can still exit `0`. Reporting a crash as success is the worst
/// possible outcome, so keep the default message and then exit non-zero.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(EXIT_CODE_OPERATIONAL.into());
    }));
}

/// Draws the progress reported by `download` onto a terminal bar.
///
/// Kept here rather than in the library so that embedding `pwned-core` never
/// writes to anyone's stdout.
struct ProgressPrinter {
    count: usize,
    pb: progress_bar::pb::ProgressBar,
}

impl ProgressPrinter {
    fn new() -> Self {
        let mut pb = progress_bar::pb::ProgressBar::new_with_eta(0.3, 0x1_00000 / 0x400);
        pb.set_progress_style(progress_bar::ProgressStyle::Percentage);
        pb.set_action("Downloading", progress_bar::Color::Blue, progress_bar::Style::Bold);
        ProgressPrinter { count: 0, pb }
    }

    fn on_progress(&mut self, ev: Progress) {
        match ev {
            Progress::Shard => {
                self.count += 1;
                if self.count % 0x400 == 0 {
                    self.pb.inc();
                }
            }
            Progress::Error(msg) => {
                self.pb.print_info("error", &msg, progress_bar::Color::Red, progress_bar::Style::Bold);
            }
        }
    }

    fn finish(mut self) {
        self.pb.finalize();
    }
}

#[derive(Debug, Parser)]
#[command(name = "pwned")]
#[command(version)]
#[command(about = "Search for pwned passwords", long_about = None)]
struct Cli {
    /// Directory holding the downloaded corpus
    #[arg(short = 'd', long, global = true, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Download the full Pwned Passwords corpus into local shard files
    Download {
        /// Number of shards to download concurrently
        ///
        /// Defaults to four times the CPU count, capped at 64.
        #[arg(short = 'j', long, value_name = "N")]
        concurrency: Option<NonZeroUsize>,
    },

    /// Check passwords against the local corpus
    ///
    /// Prompts securely on a TTY when no password is given as an argument.
    #[command(group = ArgGroup::new("source")
        .multiple(false)
        .args(["password", "file", "file0"]))]
    Check {
        /// Passwords to check; omit to be prompted securely
        password: Option<Vec<String>>,

        /// Read passwords from a file, one per line ("-" reads standard input)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Read NUL-separated passwords from a file ("-" reads standard input)
        ///
        /// Use this when a password may itself contain newlines.
        #[arg(long)]
        file0: Option<PathBuf>,

        /// Print results as a JSON array
        ///
        /// Errors and log messages go to stderr, so stdout stays parseable.
        #[arg(long)]
        json: bool,
    },
}


#[tokio::main]
async fn main() -> ExitCode {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .parse_default_env()
        .init();

    install_panic_hook();

    match run().await {
        Ok(true) => ExitCode::from(EXIT_CODE_PWNED),
        Ok(false) => ExitCode::SUCCESS,
        // print the full context chain, the way returning `Err` from `main` did
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::from(EXIT_CODE_OPERATIONAL)
        }
    }
}

/// Runs the selected subcommand, reporting whether any password was pwned.
async fn run() -> Result<bool> {
    let args = Cli::parse();

    let cache_dir: PathBuf = match args.cache_dir {
        Some(dir) => dir,
        None => default_cache_dir()?,
    };

    let mut any_pwned = false;

    match args.command {
        Commands::Download { concurrency } => {
            let mut bar = ProgressPrinter::new();
            download::download(&cache_dir, concurrency, |ev| bar.on_progress(ev)).await?;
            bar.finish();
        }
        Commands::Check { password, file, file0, json } => {
            // File input is used byte-for-byte; arguments and prompts are text,
            // so they are the only paths that need encoding.
            let passwords: Vec<Vec<u8>> = match (password, file, file0) {
                (Some(passwords), None, None) => passwords
                    .iter()
                    .map(|pwd| pwd.as_bytes().to_vec())
                    .collect(),
                (None, Some(file), None) => read_passwords(&file, b'\n')?,
                (None, None, Some(file)) => read_passwords(&file, 0)?,
                (None, None, None) => vec![passterm::prompt_password_tty(Some("Password: "))
                    .context("could not read a password from the terminal")?
                    .into_bytes()],
                // clap's `source` group rejects this, but don't panic if it ever slips through
                _ => anyhow::bail!("give passwords as arguments, --file or --file0, not together"),
            };
            // Buffer results rather than streaming them. A check that fails
            // partway must not leave a half-written array on stdout: emitting
            // nothing keeps stdout parseable and lets the exit code carry the
            // failure, which matters more than early output on a slow run.
            let mut items: Vec<String> = Vec::new();
            for password in passwords {
                let res = check::check(&password, Some(&cache_dir)).await?;
                any_pwned |= res.is_pwned();
                if json {
                    items.push(res.to_json());
                } else {
                    println!("{res}");
                }
            }
            if json {
                println!("[{}]", items.join(","));
            }
        }
    }

    Ok(any_pwned)
}

/// Reads passwords to check from `file`, separated by `separator`.
///
/// A `file` of `-` means standard input. Empty records are skipped so that
/// trailing separators and empty input don't get hashed as an empty password.
///
/// For newline-separated input a trailing `\r` is stripped to tolerate CRLF
/// files. For NUL-separated input newlines are preserved, since they may be
/// part of the password itself.
///
/// Records are returned as the literal bytes read. The corpus holds hashes of
/// whatever bytes were leaked, so a file in Latin-1 (or any other encoding) is
/// checked as-is instead of being forced through UTF-8.
fn read_passwords(file: &PathBuf, separator: u8) -> Result<Vec<Vec<u8>>> {
    let mut reader: Box<dyn BufRead> = if file == &PathBuf::from("-") {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        let f = std::fs::File::open(file)
            .with_context(|| format!("could not open {}", file.display()))?;
        Box::new(BufReader::new(f))
    };

    let mut passwords = Vec::new();
    let mut record = Vec::new();
    loop {
        record.clear();
        if reader.read_until(separator, &mut record)? == 0 {
            break;
        }
        // read_until includes the separator; drop it
        if record.last() == Some(&separator) {
            record.pop();
        }
        if separator == b'\n' {
            while record.last() == Some(&b'\r') {
                record.pop();
            }
        }
        // passwords are bytes: hash exactly what the file contains
        let password = std::mem::take(&mut record);
        if !password.is_empty() {
            passwords.push(password);
        }
    }
    Ok(passwords)
}




