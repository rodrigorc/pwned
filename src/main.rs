use clap::{Parser, Subcommand};
use anyhow::{Context, Result};

/// Exit code returned when at least one checked password was found in the corpus.
const EXIT_CODE_PWNED: i32 = 1;

mod download;
mod check;

#[derive(Debug, Parser)]
#[command(name = "pwned")]
#[command(version)]
#[command(about = "Search for pwned passwords", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Download the full Pwned Passwords corpus into local shard files
    Download,

    /// Check passwords against the local corpus
    ///
    /// Prompts securely on a TTY when no password is given as an argument.
    Check {
        /// Passwords to check; omit to be prompted securely
        password: Option<Vec<String>>,
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

    let mut any_pwned = false;

    match args.command {
        Commands::Download => {
            download::download().await?;
        }
        Commands::Check { password } => {
            let passwords: Vec<String> = match password {
                Some(passwords) => passwords,
                None => vec![passterm::prompt_password_tty(Some("Password: "))
                    .context("could not read a password from the terminal")?],
            };
            for password in passwords {
                let res = check::check(&password).await?;
                any_pwned |= res.is_pwned();
                println!("{res}");
            }
        }
    }

    if any_pwned {
        std::process::exit(EXIT_CODE_PWNED);
    }
    Ok(())
}




