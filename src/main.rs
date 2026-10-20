use clap::{ArgGroup, Parser, Subcommand};
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
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

    /// Check a password manager's CSV export, read from standard input
    ///
    /// The export must start with a header naming the Group, Title and
    /// Password columns; every other column is ignored. Each password is
    /// checked as usual, but reported under its `Group/Title` identifier
    /// instead of the hash.
    ///
    /// Standard input only: the point is to pipe the export straight out of
    /// the manager, so the clear passwords never touch the disk.
    CheckCsv {
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
            let items = passwords.into_iter().map(|pwd| (None, pwd)).collect();
            any_pwned |= run_checks(items, &cache_dir, json).await?;
        }
        Commands::CheckCsv { json } => {
            let items = read_csv_passwords()?
                .into_iter()
                .map(|entry| (Some(entry.id), entry.password))
                .collect();
            any_pwned |= run_checks(items, &cache_dir, json).await?;
        }
    }

    Ok(any_pwned)
}

/// Checks every password, prints its result, and reports whether any was pwned.
///
/// Each item pairs the password bytes with an optional label that names the
/// entry in the output: `check-csv` supplies the entry's `Group/Title`, while
/// plain `check` passes `None` and gets the password hash instead.
///
/// Results are buffered rather than streamed in JSON mode. A check that fails
/// partway must not leave a half-written array on stdout: emitting nothing
/// keeps stdout parseable and lets the exit code carry the failure, which
/// matters more than early output on a slow run. Plain output is streamed as
/// each password is checked.
async fn run_checks(
    items: Vec<(Option<String>, Vec<u8>)>,
    cache_dir: &Path,
    json: bool,
) -> Result<bool> {
    let mut any_pwned = false;
    let mut rendered: Vec<String> = Vec::new();
    for (label, password) in items {
        let res = check::check(&password, Some(cache_dir)).await?;
        any_pwned |= res.is_pwned();
        // Plain `check` names the entry by its hash, `check-csv` by Group/Title.
        let (key, label) = match &label {
            Some(id) => ("id", id.as_str()),
            None => ("hash", res.hash.as_str()),
        };
        if json {
            rendered.push(to_json(&res, key, label));
        } else {
            println!("{}", to_line(&res, label));
        }
    }
    if json {
        println!("[{}]", rendered.join(","));
    }
    Ok(any_pwned)
}

/// Renders one result as a plain line of output.
///
/// `label` names the entry: the password hash for `check`, its `Group/Title`
/// for `check-csv`.
///
/// ```text
/// XXX 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 is pwned 52372427 times
///     Root/Netflix is not pwned!
/// ```
fn to_line(res: &check::CheckResult, label: &str) -> String {
    match res.pwned {
        Some(count) => format!("XXX {label} is pwned {count} times"),
        None => format!("    {label} is not pwned!"),
    }
}

/// Renders one result as a single JSON object, for one element of the array
/// printed by `--json`.
///
/// `key`/`label` identify the entry: `"hash"` with the password hash for
/// `check`, `"id"` with the `Group/Title` for `check-csv`. `count` is how many
/// times the password appears in the corpus, or null when it never does.
///
/// Written by hand rather than via `serde_json`: the only variable parts are
/// the label, which is escaped, and the count, which is a number.
fn to_json(res: &check::CheckResult, key: &str, label: &str) -> String {
    let label = json_escape(label);
    match res.pwned {
        Some(count) => format!(r#"{{"{key}":"{label}","pwned":true,"count":{count}}}"#),
        None => format!(r#"{{"{key}":"{label}","pwned":false,"count":null}}"#),
    }
}

/// Escapes `text` so it can be embedded between the quotes of a JSON string.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // the control characters JSON does not allow raw
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
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

/// One entry of a password manager's CSV export: its name and its password.
struct CsvEntry {
    /// How the entry is reported in place of the password hash: `Group/Title`.
    id: String,
    /// The password, bytes exactly as the export holds them.
    password: Vec<u8>,
}

/// Reads a password manager's CSV export from standard input.
///
/// The first record must be a header naming the `Group`, `Title` and
/// `Password` columns. Matching is case-insensitive and any other column is
/// ignored, so a straight export works as it comes out of the manager. Each
/// entry becomes a `Group/Title` identifier plus its password bytes.
///
/// Standard input is the only source on purpose: writing the export to a file
/// first would put every clear password on disk, which is what this subcommand
/// exists to avoid.
///
/// Password bytes are kept exactly as the file holds them, the same as
/// [`read_passwords`]; the identifier only ever gets printed, so it is decoded
/// lossily. Records with no password in them are skipped.
fn read_csv_passwords() -> Result<Vec<CsvEntry>> {
    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("could not read the CSV from standard input")?;
    // A byte-order mark in front of the header would become part of the name
    // of the first column.
    if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        input.drain(..3);
    }

    let mut reader = csv::ReaderBuilder::new()
        // A record shorter than the header is one lacking those columns, not
        // a reason to reject the whole export.
        .flexible(true)
        .from_reader(input.as_slice());

    let header = reader
        .byte_headers()
        .context("could not read the header of the CSV")?
        .clone();
    let names = header
        .iter()
        .map(|field| String::from_utf8_lossy(field.trim_ascii()).into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    let column = |name: &str| -> Result<usize> {
        header
            .iter()
            .position(|field| field.trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
            .with_context(|| format!("the CSV header has no {name} column (found: {names})"))
    };
    let group = column("Group")?;
    let title = column("Title")?;
    let password = column("Password")?;

    let mut entries = Vec::new();
    for (index, record) in reader.byte_records().enumerate() {
        let record = record
            .with_context(|| format!("could not read record {} of the CSV", index + 1))?;
        // Nothing to check without a password, same as the empty records
        // `read_passwords` skips.
        let Some(pwd) = record.get(password).filter(|pwd| !pwd.is_empty()) else {
            continue;
        };
        let id = format!(
            "{}/{}",
            String::from_utf8_lossy(record.get(group).unwrap_or(b"")),
            String::from_utf8_lossy(record.get(title).unwrap_or(b"")),
        );
        entries.push(CsvEntry {
            id,
            password: pwd.to_vec(),
        });
    }
    Ok(entries)
}




