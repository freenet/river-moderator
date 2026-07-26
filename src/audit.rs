use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    sync::Mutex,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    event::{TemporalSignals, VerifiedMessage},
    membership::TrustTier,
    verdict::{Category, Classification},
};

pub const AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Pending,
    ShadowOnly,
    Executed,
    RefusedProtectedIdentity,
    RefusedDescendantCollateral,
    RefusedChangedOrDeletedMessage,
    RefusedStaleAuthorization,
    RateLimited,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WarningEvidence {
    pub category: Category,
    pub warned_at: DateTime<Utc>,
    pub triggering_message_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelEvidence {
    pub model: String,
    pub prompt_version: String,
    pub classifier_request_id: String,
    pub classifier: Classification,
    pub verifier_request_id: Option<String>,
    pub verifier: Option<Classification>,
    pub reserved_microusd: u64,
    pub actual_microusd: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MembershipEvidence {
    pub target_member_id: String,
    pub target_nickname: String,
    pub trust_tier: TrustTier,
    pub first_observed_at: DateTime<Utc>,
    pub observation_count: u64,
    pub active_days: u32,
    pub bootstrapped_as_existing: bool,
    pub invited_by_member_id: Option<String>,
    pub ancestor_member_ids: Vec<String>,
    pub descendant_member_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BanAuditRecord {
    pub schema_version: u32,
    pub decision_id: String,
    pub recorded_at: DateTime<Utc>,
    pub room_owner: String,
    pub outcome: AuditOutcome,
    pub normalized_reason: String,
    pub trigger: VerifiedMessage,
    pub context: Vec<VerifiedMessage>,
    pub temporal_signals: TemporalSignals,
    pub warning_history: Vec<WarningEvidence>,
    pub model: ModelEvidence,
    pub membership: MembershipEvidence,
    pub classified_content_hash: String,
    pub river_result: Option<String>,
}

impl BanAuditRecord {
    pub fn validate(&self, max_context_messages: usize, max_message_bytes: usize) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == AUDIT_SCHEMA_VERSION,
            "unsupported audit schema"
        );
        anyhow::ensure!(!self.decision_id.is_empty(), "decision ID is empty");
        anyhow::ensure!(
            !self.membership.target_member_id.is_empty(),
            "target member ID is empty"
        );
        anyhow::ensure!(
            self.normalized_reason.len() <= 240,
            "normalized reason is too long"
        );
        anyhow::ensure!(
            self.context.len() <= max_context_messages,
            "audit context has too many messages"
        );
        anyhow::ensure!(
            self.trigger.content.len() <= max_message_bytes,
            "trigger exceeds audit message size"
        );
        anyhow::ensure!(
            self.context
                .iter()
                .all(|message| message.content.len() <= max_message_bytes),
            "context message exceeds audit message size"
        );
        anyhow::ensure!(
            self.trigger.author_id == self.membership.target_member_id,
            "trigger author and ban target differ"
        );
        anyhow::ensure!(
            self.trigger.content_hash() == self.classified_content_hash,
            "classified content hash does not match trigger"
        );
        self.model
            .classifier
            .validate()
            .map_err(anyhow::Error::msg)?;
        if let Some(verifier) = &self.model.verifier {
            verifier.validate().map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }
}

/// Append-only audit log. A pending record is synced before an enforcer request;
/// its outcome is a separate record with the same decision ID.
pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(path)
            .with_context(|| format!("cannot open audit log {}", path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn append_ban(
        &self,
        record: &BanAuditRecord,
        max_context_messages: usize,
        max_message_bytes: usize,
    ) -> Result<()> {
        record.validate(max_context_messages, max_message_bytes)?;
        let mut encoded = serde_json::to_vec(record)?;
        anyhow::ensure!(
            encoded.len() <= 256 * 1024,
            "encoded audit record exceeds hard limit"
        );
        encoded.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
        file.write_all(&encoded)?;
        file.flush()?;
        file.sync_data()?;
        Ok(())
    }

    pub fn read_all(path: &Path) -> Result<Vec<BanAuditRecord>> {
        let file = File::open(path)?;
        BufReader::new(file)
            .lines()
            .map(|line| Ok(serde_json::from_str(&line?)?))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Category, Verdict};
    use tempfile::tempdir;

    fn message() -> VerifiedMessage {
        let now = Utc::now();
        VerifiedMessage {
            message_id: "message-1".into(),
            room_owner: "owner".into(),
            author_id: "full-member-id".into(),
            nickname: "nick".into(),
            content: "trigger text".into(),
            author_claimed_at: now,
            first_observed_at: now,
            edited: false,
            reply_to_message_id: None,
        }
    }

    fn record() -> BanAuditRecord {
        let trigger = message();
        BanAuditRecord {
            schema_version: AUDIT_SCHEMA_VERSION,
            decision_id: "decision-1".into(),
            recorded_at: Utc::now(),
            room_owner: "owner".into(),
            outcome: AuditOutcome::Pending,
            normalized_reason: "severe spam".into(),
            context: vec![trigger.clone()],
            temporal_signals: TemporalSignals {
                author_messages_10_seconds: 3,
                author_messages_1_minute: 3,
                author_messages_5_minutes: 3,
                milliseconds_since_author_previous: Some(500),
                exact_duplicate_count_5_minutes: 2,
                claimed_clock_skew_seconds: 0,
            },
            warning_history: vec![],
            model: ModelEvidence {
                model: "test-model".into(),
                prompt_version: "v1".into(),
                classifier_request_id: "request-1".into(),
                classifier: Classification {
                    verdict: Verdict::BanSevereHarm,
                    category: Category::Spam,
                    confidence_millionths: 999_000,
                    reason: "repeated unsolicited promotion".into(),
                },
                verifier_request_id: Some("request-2".into()),
                verifier: Some(Classification {
                    verdict: Verdict::BanSevereHarm,
                    category: Category::Spam,
                    confidence_millionths: 999_000,
                    reason: "evidence supports spam classification".into(),
                }),
                reserved_microusd: 400,
                actual_microusd: Some(80),
            },
            membership: MembershipEvidence {
                target_member_id: trigger.author_id.clone(),
                target_nickname: trigger.nickname.clone(),
                trust_tier: TrustTier::Probationary,
                first_observed_at: trigger.first_observed_at,
                observation_count: 3,
                active_days: 1,
                bootstrapped_as_existing: false,
                invited_by_member_id: Some("invite-bot-full-id".into()),
                ancestor_member_ids: vec!["invite-bot-full-id".into()],
                descendant_member_ids: vec![],
            },
            classified_content_hash: trigger.content_hash(),
            trigger,
            river_result: None,
        }
    }

    #[test]
    fn durable_audit_round_trip_contains_full_member_and_context() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.append_ban(&record(), 20, 4096).unwrap();
        let records = AuditLog::read_all(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].membership.target_member_id, "full-member-id");
        assert_eq!(records[0].context[0].content, "trigger text");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn refuses_target_not_matching_authenticated_author() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        let mut bad = record();
        bad.membership.target_member_id = "victim-selected-by-prompt".into();
        assert!(log.append_ban(&bad, 20, 4096).is_err());
    }
}
