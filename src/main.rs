use clap::{Parser, Subcommand};
use anyhow::Result;


mod download;
mod check;

#[derive(Debug, Parser)]
#[command(name = "pwned")]
#[command(about = "Search for pwned passwords", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Download,
    Check { password: Option<Vec<String>> },
}


#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .parse_default_env()
        .init();

    let args = Cli::parse();

    match args.command {
        Commands::Download => {
            download::download().await?;
        }
        Commands::Check { password: None } => {
            let password = passterm::prompt_password_tty(Some("Password: ")).unwrap();
            let res = check::check(&password).await?;
            println!("{res}");
        }
        Commands::Check { password: Some(passwords) } => {
            for password in passwords {
                let res = check::check(&password).await?;
                println!("{res}");
            }
        }
    }
    Ok(())
}




