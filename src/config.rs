use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: ServiceConfig,
    pub audit: AuditConfig,
    pub river: RiverConfig,
    pub room: RoomConfig,
    pub model: ModelConfig,
    pub limits: LimitConfig,
    pub policy: PolicyConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let text = std::str::from_utf8(&bytes).context("configuration is not UTF-8")?;
        toml::from_str(text).context("invalid TOML configuration")
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.room.owner_verifying_key.trim().is_empty(),
            "room owner key is empty"
        );
        anyhow::ensure!(!self.room.topic.trim().is_empty(), "room topic is empty");
        anyhow::ensure!(
            !self.model.classifier_name.trim().is_empty(),
            "classifier model name is empty"
        );
        anyhow::ensure!(
            !self.model.verifier_name.trim().is_empty(),
            "verifier model name is empty"
        );
        match self.model.provider {
            ModelProvider::Local => anyhow::ensure!(
                self.model
                    .unix_socket
                    .as_ref()
                    .is_some_and(|path| path.is_absolute()),
                "local model unix_socket must be absolute"
            ),
            ModelProvider::OpenAi => anyhow::ensure!(
                self.model
                    .api_key_file
                    .as_ref()
                    .is_some_and(|path| path.is_absolute()),
                "OpenAI api_key_file must be absolute"
            ),
        }
        anyhow::ensure!(
            self.model.request_timeout_seconds > 0,
            "model request timeout must be positive"
        );
        anyhow::ensure!(
            (1024..=1_048_576).contains(&self.model.max_response_bytes),
            "model max_response_bytes is invalid"
        );
        anyhow::ensure!(
            self.model.max_input_bytes > 0,
            "max_input_bytes must be positive"
        );
        anyhow::ensure!(
            self.model.max_output_tokens > 0,
            "max_output_tokens must be positive"
        );
        anyhow::ensure!(
            self.limits.daily_budget_microusd > 0,
            "daily budget must be positive"
        );
        anyhow::ensure!(
            self.limits.monthly_budget_microusd >= self.limits.daily_budget_microusd,
            "monthly budget must be at least daily budget"
        );
        anyhow::ensure!(
            self.limits.requests_per_minute > 0,
            "requests_per_minute must be positive"
        );
        anyhow::ensure!(
            self.limits.requests_per_hour >= self.limits.requests_per_minute,
            "hourly request limit is below minute limit"
        );
        anyhow::ensure!(
            self.limits.requests_per_day >= self.limits.requests_per_hour,
            "daily request limit is below hourly limit"
        );
        anyhow::ensure!(
            self.limits.requests_per_author_hour > 0,
            "per-author request limit must be positive"
        );
        anyhow::ensure!(self.limits.concurrency > 0, "concurrency must be positive");
        anyhow::ensure!(
            self.limits.queue_depth >= self.limits.concurrency,
            "queue depth must be at least concurrency"
        );
        anyhow::ensure!(
            self.audit.retention_days > 0,
            "audit retention must be positive"
        );
        anyhow::ensure!(
            self.audit.max_context_messages > 0,
            "audit context limit must be positive"
        );
        anyhow::ensure!(
            self.audit.max_message_bytes > 0,
            "audit message size must be positive"
        );
        anyhow::ensure!(
            self.audit.path.is_absolute() && self.audit.decision_path.is_absolute(),
            "audit paths must be absolute"
        );
        anyhow::ensure!(
            self.river.riverctl_path.is_absolute(),
            "riverctl_path must be absolute"
        );
        anyhow::ensure!(
            self.river.config_dir.is_absolute(),
            "River config_dir must be absolute"
        );
        anyhow::ensure!(
            !self.river.expected_contract_key.trim().is_empty(),
            "expected River contract key is empty"
        );
        anyhow::ensure!(
            self.river.ban_signing_key_file.is_absolute()
                && self
                    .river
                    .ban_signing_key_file
                    .starts_with("/run/credentials/"),
            "ban signing key must be a systemd credential path"
        );
        if self.service.mode == Mode::Warn {
            anyhow::ensure!(
                self.service.activation_at.is_some(),
                "warn mode requires an explicit activation_at cutoff"
            );
            anyhow::ensure!(
                !self.room.service_member_ids.is_empty(),
                "warn mode requires at least one service member ID"
            );
        }
        anyhow::ensure!(
            self.river.max_event_bytes > 0 && self.river.max_event_bytes <= 1_048_576,
            "max_event_bytes is invalid"
        );
        if !self.river.allow_remote_node {
            anyhow::ensure!(
                self.river.node_url.starts_with("ws://127.0.0.1:")
                    || self.river.node_url.starts_with("ws://[::1]:"),
                "River node must be loopback unless allow_remote_node is true"
            );
        }
        anyhow::ensure!(
            self.policy.max_ban_descendants == 0 || !self.service.mode.is_enforce(),
            "nonzero descendant collateral is forbidden in enforcement mode"
        );
        anyhow::ensure!(
            self.policy.ban_global_interval_seconds > 0
                && self.policy.bans_per_hour > 0
                && self.policy.bans_per_day >= self.policy.bans_per_hour,
            "automatic ban rate limits are invalid"
        );
        anyhow::ensure!(
            self.policy.regular_after_days <= self.policy.established_after_days,
            "established tenure must not be shorter than regular tenure"
        );
        anyhow::ensure!(
            self.policy.regular_after_messages <= self.policy.established_after_messages,
            "established message count must not be below regular message count"
        );
        anyhow::ensure!(
            self.policy.global_action_interval_seconds > 0
                && self.policy.member_action_cooldown_hours > 0
                && self.policy.max_pending_action_age_seconds > 0,
            "action cooldowns and maximum pending age must be positive"
        );
        anyhow::ensure!(
            self.policy.nudge_confidence_millionths <= self.policy.warning_confidence_millionths
                && self.policy.warning_confidence_millionths
                    <= self.policy.ban_confidence_millionths
                && self.policy.ban_confidence_millionths
                    <= self.policy.deputy_ban_confidence_millionths
                && self.policy.deputy_ban_confidence_millionths <= 1_000_000,
            "confidence thresholds must be ordered and at most one million"
        );
        anyhow::ensure!(
            self.policy.future_timestamp_ban_grace_seconds
                > self.policy.future_timestamp_grace_seconds,
            "future-timestamp ban deadline must be strictly after the escalation deadline, \
             or the stern second warning would arm an already-elapsed ban"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Shadow,
    Warn,
    Enforce,
}

impl Mode {
    pub fn is_shadow(self) -> bool {
        self == Self::Shadow
    }
    pub fn is_enforce(self) -> bool {
        self == Self::Enforce
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub mode: Mode,
    pub state_database: PathBuf,
    #[serde(default)]
    pub activation_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub decision_path: PathBuf,
    pub retention_days: u32,
    pub max_context_messages: usize,
    pub max_message_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RiverConfig {
    pub riverctl_path: PathBuf,
    pub config_dir: PathBuf,
    pub node_url: String,
    /// Known production contract key derived from the pinned room WASM and owner.
    pub expected_contract_key: String,
    /// Room-owner key exposed only through a systemd credential mount.
    pub ban_signing_key_file: PathBuf,
    #[serde(default)]
    pub allow_remote_node: bool,
    pub max_event_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoomConfig {
    pub owner_verifying_key: String,
    pub topic: String,
    #[serde(default)]
    pub protected_member_ids: Vec<String>,
    #[serde(default)]
    pub service_member_ids: Vec<String>,
    /// Exact normalized names whose use impersonates a protected identity.
    #[serde(default)]
    pub protected_nicknames: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub provider: ModelProvider,
    pub classifier_name: String,
    pub verifier_name: String,
    /// llama.cpp's Unix-domain socket. Used only by the local provider.
    pub unix_socket: Option<PathBuf>,
    /// A file containing only the API key. Used only by the OpenAI provider.
    pub api_key_file: Option<PathBuf>,
    pub request_timeout_seconds: u64,
    pub max_response_bytes: usize,
    pub max_input_bytes: u64,
    pub max_output_tokens: u64,
    pub classifier_input_microusd_per_million_tokens: u64,
    pub classifier_output_microusd_per_million_tokens: u64,
    pub verifier_input_microusd_per_million_tokens: u64,
    pub verifier_output_microusd_per_million_tokens: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelProvider {
    Local,
    OpenAi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelRole {
    Classifier,
    Verifier,
}

impl ModelConfig {
    /// A UTF-8 byte cannot encode more than one token. Reserving one input token
    /// per request byte is deliberately conservative and independent of tokenizer drift.
    pub fn maximum_request_cost_microusd(
        &self,
        request_bytes: u64,
        role: ModelRole,
    ) -> Result<u64> {
        anyhow::ensure!(
            request_bytes <= self.max_input_bytes,
            "request exceeds max_input_bytes"
        );
        self.token_cost_microusd(request_bytes, self.max_output_tokens, role)
    }

    pub fn token_cost_microusd(
        &self,
        input_tokens: u64,
        output_tokens: u64,
        role: ModelRole,
    ) -> Result<u64> {
        let (input_price, output_price) = match role {
            ModelRole::Classifier => (
                self.classifier_input_microusd_per_million_tokens,
                self.classifier_output_microusd_per_million_tokens,
            ),
            ModelRole::Verifier => (
                self.verifier_input_microusd_per_million_tokens,
                self.verifier_output_microusd_per_million_tokens,
            ),
        };
        let input = input_tokens
            .checked_mul(input_price)
            .context("input price overflow")?;
        let output = output_tokens
            .checked_mul(output_price)
            .context("output price overflow")?;
        input
            .checked_add(output)
            .and_then(|v| v.checked_add(999_999))
            .map(|v| v / 1_000_000)
            .context("total price overflow")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitConfig {
    /// One USD is 1,000,000 micro-USD.
    pub daily_budget_microusd: u64,
    pub monthly_budget_microusd: u64,
    pub requests_per_minute: u64,
    pub requests_per_hour: u64,
    pub requests_per_day: u64,
    pub requests_per_author_hour: u64,
    pub queue_depth: usize,
    pub concurrency: usize,
}

fn default_future_timestamp_seconds() -> i64 {
    60
}

fn default_future_timestamp_grace_seconds() -> u64 {
    120
}

fn default_future_timestamp_ban_grace_seconds() -> u64 {
    240
}

fn default_embedded_image_grace_seconds() -> u64 {
    60
}

fn default_bad_reaction_grace_seconds() -> u64 {
    120
}

fn default_leaked_invitation_grace_seconds() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// How far ahead of local observation a claimed timestamp may be before the
    /// message is treated as pinning itself to the bottom of the room.
    ///
    /// Measured against 2523 production messages: 97.7% land within +/-1 minute
    /// and the 99th percentile is +5 SECONDS, so 60s is still an order of
    /// magnitude beyond normal drift.
    ///
    /// Set to 60 rather than a looser bound because the damage does not depend
    /// on intent: any future dating pushes the message out of order in the UI,
    /// and an accidental one is just as disruptive to read past as a deliberate
    /// one. In the sample this catches one extra author (61s, 61s, 67s ahead)
    /// alongside the three that were an hour or more out.
    #[serde(default = "default_future_timestamp_seconds")]
    pub future_timestamp_seconds: i64,
    /// How long the author has to delete a future-dated message before a
    /// sterner second warning is posted. Their own deletion is the only
    /// remedy: the contract lets only the author delete, so the moderator
    /// cannot clear it for them.
    #[serde(default = "default_future_timestamp_grace_seconds")]
    pub future_timestamp_grace_seconds: u64,
    /// How long, from the original warning, the author has before the
    /// message is enforced (the account removed). Measured budget was
    /// 2026-08-08: 26 of 34 bans over two weeks were this reason, and content
    /// was routinely benign (a new member's first "Hello") -- a single
    /// 120-second window gives no room for a newcomer to miss one notice.
    /// Must be greater than `future_timestamp_grace_seconds`; the gap between
    /// the two is the stern-warning window.
    #[serde(default = "default_future_timestamp_ban_grace_seconds")]
    pub future_timestamp_ban_grace_seconds: u64,
    /// Deletion window for an embedded image. Shorter than the timestamp case:
    /// a future-dated "hlo" is usually a broken clock, whereas an embedded image
    /// is always deliberate, and what it shows is visible to everyone meanwhile.
    #[serde(default = "default_embedded_image_grace_seconds")]
    pub embedded_image_grace_seconds: u64,
    /// Deletion window for a non-emoji reaction.
    #[serde(default = "default_bad_reaction_grace_seconds")]
    pub bad_reaction_grace_seconds: u64,
    /// Deletion window for a publicly-posted invitation link. Longer than the
    /// other self-delete cases: the poster likely does not realize the link is
    /// a live keypair rather than an inert code, so they need real time to see
    /// the notice and act, not just a moment to notice a formatting problem.
    #[serde(default = "default_leaked_invitation_grace_seconds")]
    pub leaked_invitation_grace_seconds: u64,
    pub warning_window_hours: u64,
    pub low_severity_grace_seconds: u64,
    pub global_action_interval_seconds: u64,
    pub member_action_cooldown_hours: u64,
    pub max_pending_action_age_seconds: u64,
    pub max_ban_descendants: usize,
    pub ban_global_interval_seconds: u64,
    pub bans_per_hour: u64,
    pub bans_per_day: u64,
    pub ban_confidence_millionths: u32,
    pub deputy_ban_confidence_millionths: u32,
    pub nudge_confidence_millionths: u32,
    pub warning_confidence_millionths: u32,
    pub regular_after_days: u32,
    pub regular_after_messages: u64,
    pub established_after_days: u32,
    pub established_after_active_days: u32,
    pub established_after_messages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_cost_is_conservative_and_bounded() {
        let model = ModelConfig {
            provider: ModelProvider::OpenAi,
            classifier_name: "classifier".into(),
            verifier_name: "verifier".into(),
            unix_socket: None,
            api_key_file: Some("/run/credentials/openai_api_key".into()),
            request_timeout_seconds: 30,
            max_response_bytes: 65_536,
            max_input_bytes: 4_000,
            max_output_tokens: 100,
            classifier_input_microusd_per_million_tokens: 50_000,
            classifier_output_microusd_per_million_tokens: 400_000,
            verifier_input_microusd_per_million_tokens: 1_000_000,
            verifier_output_microusd_per_million_tokens: 2_000_000,
        };
        assert_eq!(
            model
                .maximum_request_cost_microusd(4_000, ModelRole::Classifier)
                .unwrap(),
            240
        );
        assert_eq!(
            model
                .maximum_request_cost_microusd(4_000, ModelRole::Verifier)
                .unwrap(),
            4_200
        );
        assert!(model
            .maximum_request_cost_microusd(4_001, ModelRole::Classifier)
            .is_err());
    }

    #[test]
    fn price_overflow_is_rejected() {
        let model = ModelConfig {
            provider: ModelProvider::OpenAi,
            classifier_name: "classifier".into(),
            verifier_name: "verifier".into(),
            unix_socket: None,
            api_key_file: Some("/run/credentials/openai_api_key".into()),
            request_timeout_seconds: 30,
            max_response_bytes: 65_536,
            max_input_bytes: u64::MAX,
            max_output_tokens: 1,
            classifier_input_microusd_per_million_tokens: u64::MAX,
            classifier_output_microusd_per_million_tokens: 1,
            verifier_input_microusd_per_million_tokens: 1,
            verifier_output_microusd_per_million_tokens: 1,
        };
        assert!(model
            .maximum_request_cost_microusd(2, ModelRole::Classifier)
            .is_err());
    }

    /// A ban deadline at or before the escalation deadline would collapse
    /// this feature's whole point: `ban_after` (computed at `warned_at`) is
    /// already elapsed by the time the escalation sweep even fires, so the
    /// stern second warning would arm a ban the very next 5-second tick --
    /// the 2-minute cushion this exists to add silently becomes ~5 seconds.
    /// Loads the repo's own shipped example config rather than hand-building
    /// a full `Config` literal, since nothing else in this file does that.
    #[test]
    fn future_timestamp_ban_deadline_must_be_after_the_escalation_deadline() {
        let mut config = Config::load(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config.example.toml"
        )))
        .expect("the shipped example config must parse");
        config
            .validate()
            .expect("the shipped example config must be valid as shipped");

        config.policy.future_timestamp_ban_grace_seconds =
            config.policy.future_timestamp_grace_seconds;
        assert!(
            config.validate().is_err(),
            "a ban deadline equal to the escalation deadline must be rejected"
        );

        config.policy.future_timestamp_ban_grace_seconds =
            config.policy.future_timestamp_grace_seconds - 1;
        assert!(
            config.validate().is_err(),
            "a ban deadline before the escalation deadline must be rejected"
        );
    }
}
