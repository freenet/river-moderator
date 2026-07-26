use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
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
        anyhow::ensure!(!self.model.name.trim().is_empty(), "model name is empty");
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
            self.river.riverctl_path.is_absolute(),
            "riverctl_path must be absolute"
        );
        anyhow::ensure!(
            self.river.config_dir.is_absolute(),
            "River config_dir must be absolute"
        );
        anyhow::ensure!(
            self.river.max_event_bytes > 0 && self.river.max_event_bytes <= 1_048_576,
            "max_event_bytes is invalid"
        );
        anyhow::ensure!(
            self.policy.max_ban_descendants == 0 || !self.service.mode.is_enforce(),
            "nonzero descendant collateral is forbidden in enforcement mode"
        );
        anyhow::ensure!(
            self.policy.regular_after_days <= self.policy.established_after_days,
            "established tenure must not be shorter than regular tenure"
        );
        anyhow::ensure!(
            self.policy.regular_after_messages <= self.policy.established_after_messages,
            "established message count must not be below regular message count"
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
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
    pub max_event_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoomConfig {
    pub owner_verifying_key: String,
    pub topic: String,
    #[serde(default)]
    pub protected_member_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelConfig {
    pub name: String,
    pub max_input_bytes: u64,
    pub max_output_tokens: u64,
    /// Price in micro-USD per one million tokens. $0.05 is 50,000 micro-USD.
    pub input_microusd_per_million_tokens: u64,
    pub output_microusd_per_million_tokens: u64,
}

impl ModelConfig {
    /// A UTF-8 byte cannot encode more than one token. Reserving one input token
    /// per request byte is deliberately conservative and independent of tokenizer drift.
    pub fn maximum_request_cost_microusd(&self, request_bytes: u64) -> Result<u64> {
        anyhow::ensure!(
            request_bytes <= self.max_input_bytes,
            "request exceeds max_input_bytes"
        );
        let input = request_bytes
            .checked_mul(self.input_microusd_per_million_tokens)
            .context("input price overflow")?;
        let output = self
            .max_output_tokens
            .checked_mul(self.output_microusd_per_million_tokens)
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub warning_window_hours: u64,
    pub max_ban_descendants: usize,
    pub ban_confidence_millionths: u32,
    pub deputy_ban_confidence_millionths: u32,
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
            name: "test".into(),
            max_input_bytes: 4_000,
            max_output_tokens: 100,
            input_microusd_per_million_tokens: 50_000,
            output_microusd_per_million_tokens: 400_000,
        };
        assert_eq!(model.maximum_request_cost_microusd(4_000).unwrap(), 240);
        assert!(model.maximum_request_cost_microusd(4_001).is_err());
    }

    #[test]
    fn price_overflow_is_rejected() {
        let model = ModelConfig {
            name: "test".into(),
            max_input_bytes: u64::MAX,
            max_output_tokens: 1,
            input_microusd_per_million_tokens: u64::MAX,
            output_microusd_per_million_tokens: 1,
        };
        assert!(model.maximum_request_cost_microusd(2).is_err());
    }
}
