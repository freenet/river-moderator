//! Shadow replay: re-run historical tone decisions through the CURRENT
//! classifier instructions and report what changed. Read-only against the room;
//! it only calls the model. Spend here bypasses the budget ledger, so keep the
//! case count small and deliberate.
use anyhow::Result;
use river_moderator::{
    classifier::{build_payload, PayloadInput},
    config::Config,
    event::{TemporalSignals, VerifiedMessage},
    membership::{MemberTenure, TrustTier},
    model::ModelPass,
    openai_model::OpenAiModelClient,
};
use serde::Deserialize;
use std::io::BufRead;

#[derive(Deserialize)]
struct Record {
    decision_id: String,
    trigger: VerifiedMessage,
    #[serde(default)]
    context: Vec<VerifiedMessage>,
    temporal_signals: TemporalSignals,
    trust_tier: TrustTier,
    classifier: Stored,
}
#[derive(Deserialize)]
struct Stored {
    verdict: String,
    category: String,
    confidence_millionths: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::load(std::path::Path::new("/etc/river-moderator/config.toml"))?;
    let model = OpenAiModelClient::new(&config.model)?;

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: replay_tone <decision-audit-subset.jsonl>");
        std::process::exit(2);
    });
    let f = std::fs::File::open(&path)?;
    let records: Vec<Record> = std::io::BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect();

    println!(
        "replaying {} tone cases against current instructions\n",
        records.len()
    );
    let (mut same, mut softened, mut hardened) = (0, 0, 0);

    for r in &records {
        let tenure = MemberTenure {
            room_owner: r.trigger.room_owner.clone(),
            member_id: r.trigger.author_id.clone(),
            first_observed_at: r.trigger.first_observed_at,
            last_observed_at: r.trigger.first_observed_at,
            observation_count: 1,
            active_days: 1,
            bootstrapped_as_existing: false,
        };
        let payload = build_payload(
            PayloadInput {
                room_topic: &config.room.topic,
                target: &r.trigger,
                context: &r.context,
                signals: r.temporal_signals.clone(),
                tenure: &tenure,
                trust_tier: r.trust_tier,
                active_warning: None,
                moderator_member_ids: &config.room.protected_member_ids,
                join_name_candidate: false,
            },
            12_000 - 6_000,
        )?;
        let out = model
            .classify(&payload, ModelPass::Classifier, &r.trigger.author_id)
            .await?;
        let new_v = format!("{:?}", out.classification.verdict).to_lowercase();
        let allow_before = r.classifier.verdict == "allow";
        let allow_after = new_v.contains("allow");
        let tag = if allow_before == allow_after {
            same += 1;
            "same "
        } else if allow_after {
            softened += 1;
            "SOFTENED"
        } else {
            hardened += 1;
            "HARDENED"
        };
        println!(
            "{tag} [{}] {}/{} {} -> {}/{:?} {}\n   {:?}",
            &r.decision_id[..8],
            r.classifier.verdict,
            r.classifier.category,
            r.classifier.confidence_millionths,
            new_v,
            out.classification.category,
            out.classification.confidence_millionths,
            &r.trigger.content[..r.trigger.content.len().min(95)]
        );
    }
    println!("\nunchanged {same}   softened(now allow) {softened}   hardened {hardened}");
    Ok(())
}
