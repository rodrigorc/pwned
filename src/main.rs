use clap::{ArgGroup, Parser, Subcommand};
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::num::NonZeroUsize;

/// Exit code returned when at least one checked password was found in the corpus.
const EXIT_CODE_PWNED: i32 = 1;

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

mod download;
mod check;

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
async fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .parse_default_env()
        .init();

    let args = Cli::parse();

    let cache_dir: PathBuf = match args.cache_dir {
        Some(dir) => dir,
        None => default_cache_dir()?,
    };

    let mut any_pwned = false;

    match args.command {
        Commands::Download { concurrency } => {
            download::download(&cache_dir, concurrency).await?;
        }
        Commands::Check { password, file, file0, json } => {
            let passwords: Vec<String> = match (password, file, file0) {
                (Some(passwords), None, None) => passwords,
                (None, Some(file), None) => read_passwords(&file, b'\n')?,
                (None, None, Some(file)) => read_passwords(&file, 0)?,
                (None, None, None) => vec![passterm::prompt_password_tty(Some("Password: "))
                    .context("could not read a password from the terminal")?],
                // clap's `source` group rejects this, but don't panic if it ever slips through
                _ => anyhow::bail!("give passwords as arguments, --file or --file0, not together"),
            };
            // Buffer results rather than streaming them. A check that fails
            // partway must not leave a half-written array on stdout: emitting
            // nothing keeps stdout parseable and lets the exit code carry the
            // failure, which matters more than early output on a slow run.
            let mut items: Vec<String> = Vec::new();
            for password in passwords {
                let res = check::check(&password, &cache_dir).await?;
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

    if any_pwned {
        std::process::exit(EXIT_CODE_PWNED);
    }
    Ok(())
}

/// Reads passwords to check from `file`, separated by `separator`.
///
/// A `file` of `-` means standard input. Empty records are skipped so that
/// trailing separators and empty input don't get hashed as an empty password.
///
/// For newline-separated input a trailing `\r` is stripped to tolerate CRLF
/// files. For NUL-separated input newlines are preserved, since they may be
/// part of the password itself.
fn read_passwords(file: &PathBuf, separator: u8) -> Result<Vec<String>> {
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
        // passwords are text: reject invalid UTF-8 rather than hashing garbage
        let password = String::from_utf8(std::mem::take(&mut record))
            .context("input contains a password that is not valid UTF-8")?;
        if !password.is_empty() {
            passwords.push(password);
        }
    }
    Ok(passwords)
}




