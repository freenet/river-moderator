use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use river_moderator::{
    budget::BudgetLedger,
    config::{Config, ModelProvider},
    local_model::LocalModelClient,
    membership::MemberRegistry,
    model::{ModelPass, ModelResult},
    openai_model::OpenAiModelClient,
    policy::severe_categories_compatible,
    runtime::run_moderator,
    verdict::{Category, Verdict},
};
use serde::Deserialize;

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
    /// Run real-time classification and the actions enabled by the configured mode.
    Run,
    /// Explicitly mark a newline-delimited current roster as pre-existing.
    BootstrapMembers { member_ids_file: PathBuf },
    /// Evaluate the configured local model against a JSON fixture.
    Evaluate { fixture: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
            run_moderator(config).await?;
        }
        Command::BootstrapMembers { member_ids_file } => {
            config.validate()?;
            let text = std::fs::read_to_string(&member_ids_file).with_context(|| {
                format!("failed to read member roster {}", member_ids_file.display())
            })?;
            let mut members: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect();
            members.sort();
            members.dedup();
            anyhow::ensure!(!members.is_empty(), "member roster is empty");
            anyhow::ensure!(
                members.iter().all(|member| {
                    member.len() == 8
                        && member
                            .chars()
                            .all(|ch| ch.is_ascii_uppercase() || ('2'..='7').contains(&ch))
                }),
                "member roster contains a non-canonical River member ID"
            );
            let registry = MemberRegistry::open(&config.service.state_database)?;
            let count = registry.bootstrap_room(
                &config.room.owner_verifying_key,
                members,
                chrono::Utc::now(),
            )?;
            println!("bootstrapped {count} existing member(s)");
        }
        Command::Evaluate { fixture } => evaluate(&config, &fixture).await?,
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalCase {
    name: String,
    payload: serde_json::Value,
    acceptable_verdicts: Vec<Verdict>,
    acceptable_categories: Vec<Category>,
}

async fn evaluate(config: &Config, fixture: &PathBuf) -> anyhow::Result<()> {
    config.validate()?;
    let cases: Vec<EvalCase> = serde_json::from_slice(
        &std::fs::read(fixture).with_context(|| format!("failed to read {}", fixture.display()))?,
    )
    .context("invalid evaluation fixture")?;
    anyhow::ensure!(!cases.is_empty(), "evaluation fixture is empty");
    let model = ConfiguredModel::new(config)?;
    model.health().await?;
    let mut passed = 0usize;
    for case in &cases {
        let payload = serde_json::to_vec(&case.payload)?;
        anyhow::ensure!(
            payload.len() <= config.model.max_input_bytes as usize,
            "fixture case {} exceeds model input limit",
            case.name
        );
        let started = std::time::Instant::now();
        let result = model
            .classify(&payload, ModelPass::Classifier, "evaluation-fixture")
            .await;
        let elapsed_ms = started.elapsed().as_millis();
        match result {
            Ok(result) => {
                let mut ok = case
                    .acceptable_verdicts
                    .contains(&result.classification.verdict)
                    && case
                        .acceptable_categories
                        .contains(&result.classification.category);
                let verifier = if result.classification.verdict == Verdict::BanSevereHarm {
                    match model
                        .classify(
                            &payload,
                            ModelPass::SevereHarmVerifier,
                            "evaluation-fixture",
                        )
                        .await
                    {
                        Ok(verification) => {
                            ok &= verification.classification.verdict == Verdict::BanSevereHarm
                                && severe_categories_compatible(
                                    verification.classification.category,
                                    result.classification.category,
                                );
                            Some(serde_json::json!({
                                "verdict": verification.classification.verdict,
                                "category": verification.classification.category,
                                "confidence_millionths": verification.classification.confidence_millionths,
                                "reason": verification.classification.reason,
                                "prompt_tokens": verification.usage.prompt_tokens,
                                "completion_tokens": verification.usage.completion_tokens,
                            }))
                        }
                        Err(error) => {
                            ok = false;
                            Some(serde_json::json!({"error": format!("{error:#}")}))
                        }
                    }
                } else {
                    None
                };
                if ok {
                    passed += 1;
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "case": case.name,
                        "ok": ok,
                        "verdict": result.classification.verdict,
                        "category": result.classification.category,
                        "confidence_millionths": result.classification.confidence_millionths,
                        "reason": result.classification.reason,
                        "prompt_tokens": result.usage.prompt_tokens,
                        "completion_tokens": result.usage.completion_tokens,
                        "elapsed_ms": elapsed_ms,
                        "verifier": verifier,
                    })
                );
            }
            Err(error) => println!(
                "{}",
                serde_json::json!({
                    "case": case.name,
                    "ok": false,
                    "error": format!("{error:#}"),
                    "elapsed_ms": elapsed_ms,
                })
            ),
        }
    }
    println!("evaluation: {passed}/{} passed", cases.len());
    anyhow::ensure!(passed == cases.len(), "local model failed evaluation gate");
    Ok(())
}

enum ConfiguredModel {
    Local(LocalModelClient),
    OpenAi(OpenAiModelClient),
}

impl ConfiguredModel {
    fn new(config: &Config) -> anyhow::Result<Self> {
        match config.model.provider {
            ModelProvider::Local => Ok(Self::Local(LocalModelClient::new(&config.model)?)),
            ModelProvider::OpenAi => Ok(Self::OpenAi(OpenAiModelClient::new(&config.model)?)),
        }
    }

    async fn health(&self) -> anyhow::Result<()> {
        match self {
            Self::Local(client) => client.health().await,
            Self::OpenAi(_) => Ok(()),
        }
    }

    async fn classify(
        &self,
        payload: &[u8],
        pass: ModelPass,
        authenticated_author_id: &str,
    ) -> anyhow::Result<ModelResult> {
        match self {
            Self::Local(client) => client.classify(payload, pass).await,
            Self::OpenAi(client) => {
                client
                    .classify(payload, pass, authenticated_author_id)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fixture under `tests/fixtures/` must deserialize into `Vec<EvalCase>`.
    ///
    /// `EvalCase` is `deny_unknown_fields` and its verdict/category enums are
    /// closed, so a typo in a fixture -- a misspelled case key, a verdict that is
    /// not in the schema, a trailing comma -- is a hard error here rather than a
    /// runtime failure minutes into a paid evaluation run. Nothing in the test
    /// suite touched `tests/fixtures/` before this, so a fixture edit could
    /// previously ship without anything checking that it even parsed.
    ///
    /// This is deliberately the whole contract: it is deterministic and offline.
    /// Gating CI on the model's actual verdicts would need a defined sample count
    /// and per-case pass-rate threshold, because the classifier is stochastic;
    /// that is a separate design question, not something to smuggle in here.
    #[test]
    fn every_fixture_parses_as_evaluation_cases() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&dir).expect("tests/fixtures is readable") {
            let path = entry.expect("readable directory entry").path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("fixture is readable");
            let cases: Vec<EvalCase> = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                panic!("{} is not a valid fixture: {error}", path.display())
            });
            assert!(!cases.is_empty(), "{} has no cases", path.display());
            for case in &cases {
                assert!(
                    !case.name.trim().is_empty(),
                    "{} has an unnamed case",
                    path.display()
                );
                assert!(
                    !case.acceptable_verdicts.is_empty(),
                    "{} case {} accepts no verdict, so it can never pass",
                    path.display(),
                    case.name
                );
                assert!(
                    !case.acceptable_categories.is_empty(),
                    "{} case {} accepts no category, so it can never pass",
                    path.display(),
                    case.name
                );
                assert!(
                    case.payload
                        .pointer("/untrusted_data/target_message/content")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|content| !content.is_empty()),
                    "{} case {} has no target message content",
                    path.display(),
                    case.name
                );
            }
            checked += 1;
        }
        assert!(checked > 0, "no fixtures found in {}", dir.display());
    }
}
