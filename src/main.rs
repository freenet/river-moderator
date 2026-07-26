use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use river_moderator::{budget::BudgetLedger, config::Config};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, default_value = "/etc/river-moderator/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate configuration without reading credentials or contacting River.
    CheckConfig,
    /// Print current persistent budget counters.
    BudgetStatus,
    /// Run the classifier. Only shadow mode is implemented in this pre-release.
    Run,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "river_moderator=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load {}", cli.config.display()))?;

    match cli.command {
        Command::CheckConfig => {
            config.validate()?;
            println!("configuration is valid (mode: {:?})", config.service.mode);
        }
        Command::BudgetStatus => {
            config.validate()?;
            let ledger = BudgetLedger::open(&config.service.state_database)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&ledger.status(chrono::Utc::now())?)?
            );
        }
        Command::Run => {
            config.validate()?;
            anyhow::ensure!(
                config.service.mode.is_shadow(),
                "enforcement is release-gated; only shadow mode is currently accepted"
            );
            anyhow::bail!(
                "the provider and River transports are intentionally disabled in this pre-release"
            );
        }
    }

    Ok(())
}
