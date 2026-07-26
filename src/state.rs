use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{event::VerifiedMessage, verdict::Category};

const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("moderation_events_v1");
const HISTORY: TableDefinition<&str, &[u8]> = TableDefinition::new("room_history_v1");
const WARNINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("moderation_warnings_v1");
const OBSERVATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("policy_observations_v1");
const PENDING_BANS: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_bans_v1");
const BAN_ACTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("ban_actions_v1");
const PENDING_LOW_SEVERITY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("pending_low_severity_v1");
const ACTION_LIMITS: TableDefinition<&str, &[u8]> = TableDefinition::new("action_limits_v1");
const REPORT_OUTCOMES: TableDefinition<&str, &[u8]> = TableDefinition::new("report_outcomes_v1");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventDisposition {
    New,
    Edited,
    Duplicate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredEvent {
    message: VerifiedMessage,
    content_hash: String,
    deleted_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct WarningRecord {
    pub room_owner: String,
    pub member_id: String,
    pub category: Category,
    pub warning_group: String,
    pub warned_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub triggering_message_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ObservationHistory {
    times: Vec<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PendingBan {
    pub room_owner: String,
    pub member_id: String,
    pub decision_id: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanClaim {
    Claimed,
    AlreadyPending,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LowSeverityAction {
    Nudge,
    FormalWarning,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LowSeverityOutcome {
    Claimed,
    Sent,
    Failed,
    SuppressedStale,
    SuppressedChangedOrDeleted,
    SuppressedPolicyChanged,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PendingLowSeverity {
    /// A queued warning must never survive a policy/prompt deployment. Empty
    /// deserializes old records safely and is deliberately treated as stale.
    #[serde(default)]
    pub policy_version: String,
    pub decision_id: String,
    pub room_owner: String,
    pub target_message_id: String,
    pub target_member_id: String,
    pub classified_content_hash: String,
    pub action: LowSeverityAction,
    pub category: Category,
    pub created_at: DateTime<Utc>,
    pub execute_after: DateTime<Utc>,
    pub cancelled_by_member_id: Option<String>,
    pub completed_at: Option<DateTime<Utc>>,
    pub outcome: Option<LowSeverityOutcome>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ActionLimitRecord {
    last_action_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ReportOutcome {
    room_owner: String,
    reporter_id: String,
    observed_at: DateTime<Utc>,
    target_is_spam: bool,
}

pub struct ModerationState {
    database: Arc<Database>,
}

impl ModerationState {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_database(Arc::new(Database::create(path)?))
    }

    pub fn from_database(database: Arc<Database>) -> Result<Self> {
        let write = database.begin_write()?;
        write.open_table(EVENTS)?;
        write.open_table(HISTORY)?;
        write.open_table(WARNINGS)?;
        write.open_table(OBSERVATIONS)?;
        write.open_table(PENDING_BANS)?;
        write.open_table(BAN_ACTIONS)?;
        write.open_table(PENDING_LOW_SEVERITY)?;
        write.open_table(ACTION_LIMITS)?;
        write.open_table(REPORT_OUTCOMES)?;
        write.commit()?;
        Ok(Self { database })
    }

    /// Persist an authenticated event before any classification. Existing local
    /// first-observed time wins over a reconnect or attacker-controlled timestamp.
    pub fn record_message(
        &self,
        mut message: VerifiedMessage,
        max_history: usize,
        max_message_bytes: usize,
    ) -> Result<(EventDisposition, VerifiedMessage)> {
        anyhow::ensure!(max_history > 0, "history limit must be positive");
        anyhow::ensure!(
            message.content.len() <= max_message_bytes,
            "message exceeds persistent content limit"
        );
        let key = event_key(&message.room_owner, &message.message_id);
        let new_hash = message.content_hash();
        let write = self.database.begin_write()?;
        let mut events = write.open_table(EVENTS)?;
        let existing = events.get(key.as_str())?;
        let disposition = match existing.as_ref() {
            Some(value) => {
                let old: StoredEvent = serde_json::from_slice(value.value())?;
                message.first_observed_at = old.message.first_observed_at;
                if old.content_hash == new_hash && old.deleted_at.is_none() {
                    EventDisposition::Duplicate
                } else {
                    EventDisposition::Edited
                }
            }
            None => EventDisposition::New,
        };
        drop(existing);

        if disposition != EventDisposition::Duplicate {
            let stored = StoredEvent {
                message: message.clone(),
                content_hash: new_hash,
                deleted_at: None,
            };
            let encoded = serde_json::to_vec(&stored)?;
            events.insert(key.as_str(), encoded.as_slice())?;
            drop(events);

            let mut history_table = write.open_table(HISTORY)?;
            let existing_history = history_table.get(message.room_owner.as_str())?;
            let mut history: Vec<VerifiedMessage> = existing_history
                .as_ref()
                .map(|value| serde_json::from_slice(value.value()))
                .transpose()?
                .unwrap_or_default();
            drop(existing_history);
            history.retain(|entry| entry.message_id != message.message_id);
            history.push(message.clone());
            history.sort_by_key(|entry| entry.first_observed_at);
            if history.len() > max_history {
                history.drain(..history.len() - max_history);
            }
            let encoded = serde_json::to_vec(&history)?;
            history_table.insert(message.room_owner.as_str(), encoded.as_slice())?;
        } else {
            drop(events);
        }
        write.commit()?;
        Ok((disposition, message))
    }

    pub fn record_deletion(
        &self,
        room_owner: &str,
        message_id: &str,
        deleted_at: DateTime<Utc>,
    ) -> Result<bool> {
        let key = event_key(room_owner, message_id);
        let write = self.database.begin_write()?;
        let mut events = write.open_table(EVENTS)?;
        let existing = events.get(key.as_str())?;
        let Some(value) = existing.as_ref() else {
            return Ok(false);
        };
        let mut stored: StoredEvent = serde_json::from_slice(value.value())?;
        drop(existing);
        stored.deleted_at = Some(deleted_at);
        let encoded = serde_json::to_vec(&stored)?;
        events.insert(key.as_str(), encoded.as_slice())?;
        drop(events);

        let mut history_table = write.open_table(HISTORY)?;
        let history_value = history_table.get(room_owner)?;
        let mut history: Vec<VerifiedMessage> = history_value
            .as_ref()
            .map(|value| serde_json::from_slice(value.value()))
            .transpose()?
            .unwrap_or_default();
        drop(history_value);
        history.retain(|message| message.message_id != message_id);
        let encoded = serde_json::to_vec(&history)?;
        history_table.insert(room_owner, encoded.as_slice())?;
        drop(history_table);
        write.commit()?;
        Ok(true)
    }

    /// Confirm that the authenticated message still has exactly the content
    /// that was classified and has not since been deleted.
    pub fn message_is_current(
        &self,
        room_owner: &str,
        message_id: &str,
        member_id: &str,
        classified_content_hash: &str,
    ) -> Result<bool> {
        let key = event_key(room_owner, message_id);
        let read = self.database.begin_read()?;
        let table = read.open_table(EVENTS)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(false);
        };
        let stored: StoredEvent = serde_json::from_slice(value.value())?;
        Ok(stored.message.author_id == member_id
            && stored.content_hash == classified_content_hash
            && stored.deleted_at.is_none())
    }

    pub fn context(
        &self,
        room_owner: &str,
        current_message_id: &str,
        room_messages: usize,
        author_messages: usize,
    ) -> Result<Vec<VerifiedMessage>> {
        let read = self.database.begin_read()?;
        let table = read.open_table(HISTORY)?;
        let value = table.get(room_owner)?;
        let history: Vec<VerifiedMessage> = value
            .as_ref()
            .map(|entry| serde_json::from_slice(entry.value()))
            .transpose()?
            .unwrap_or_default();
        let current = history
            .iter()
            .find(|message| message.message_id == current_message_id)
            .context("current message missing from history")?;

        let mut selected: Vec<VerifiedMessage> = history
            .iter()
            .rev()
            .filter(|message| message.message_id != current_message_id)
            .take(room_messages)
            .cloned()
            .collect();
        selected.extend(
            history
                .iter()
                .rev()
                .filter(|message| {
                    message.message_id != current_message_id
                        && message.author_id == current.author_id
                })
                .take(author_messages)
                .cloned(),
        );
        selected.sort_by_key(|message| message.first_observed_at);
        selected.dedup_by(|left, right| left.message_id == right.message_id);
        Ok(selected)
    }

    pub fn record_report_outcome(
        &self,
        report: &VerifiedMessage,
        target_is_spam: bool,
    ) -> Result<()> {
        let key = event_key(&report.room_owner, &report.message_id);
        let outcome = ReportOutcome {
            room_owner: report.room_owner.clone(),
            reporter_id: report.author_id.clone(),
            observed_at: report.first_observed_at,
            target_is_spam,
        };
        let encoded = serde_json::to_vec(&outcome)?;
        let write = self.database.begin_write()?;
        write
            .open_table(REPORT_OUTCOMES)?
            .insert(key.as_str(), encoded.as_slice())?;
        write.commit()?;
        Ok(())
    }

    pub fn recent_negative_reports(
        &self,
        room_owner: &str,
        reporter_id: &str,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<usize> {
        let read = self.database.begin_read()?;
        let table = read.open_table(REPORT_OUTCOMES)?;
        let mut count = 0;
        for entry in table.iter()? {
            let (_, value) = entry?;
            let outcome: ReportOutcome = serde_json::from_slice(value.value())?;
            if outcome.room_owner == room_owner
                && outcome.reporter_id == reporter_id
                && !outcome.target_is_spam
                && outcome.observed_at >= since
                && outcome.observed_at <= until
            {
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn record_policy_observation(
        &self,
        policy_version: &str,
        room_owner: &str,
        member_id: &str,
        category: Category,
        now: DateTime<Utc>,
        window: Duration,
    ) -> Result<u32> {
        let key = observation_key(policy_version, room_owner, member_id, category);
        let write = self.database.begin_write()?;
        let mut table = write.open_table(OBSERVATIONS)?;
        let existing = table.get(key.as_str())?;
        let mut history: ObservationHistory = existing
            .as_ref()
            .map(|entry| serde_json::from_slice(entry.value()))
            .transpose()?
            .unwrap_or(ObservationHistory { times: vec![] });
        drop(existing);
        history
            .times
            .retain(|time| *time >= now - window && *time <= now);
        let prior = history.times.len().try_into().unwrap_or(u32::MAX);
        history.times.push(now);
        if history.times.len() > 100 {
            history.times.drain(..history.times.len() - 100);
        }
        let encoded = serde_json::to_vec(&history)?;
        table.insert(key.as_str(), encoded.as_slice())?;
        drop(table);
        write.commit()?;
        Ok(prior)
    }

    pub fn record_warning(&self, warning: &WarningRecord) -> Result<()> {
        let key = warning_key(&warning.room_owner, &warning.member_id, warning.category);
        let encoded = serde_json::to_vec(warning)?;
        let write = self.database.begin_write()?;
        write
            .open_table(WARNINGS)?
            .insert(key.as_str(), encoded.as_slice())?;
        write.commit()?;
        Ok(())
    }

    pub fn active_warning(
        &self,
        room_owner: &str,
        member_id: &str,
        category: Category,
        now: DateTime<Utc>,
    ) -> Result<Option<WarningRecord>> {
        let key = warning_key(room_owner, member_id, category);
        let read = self.database.begin_read()?;
        let table = read.open_table(WARNINGS)?;
        let value = table.get(key.as_str())?;
        let warning: Option<WarningRecord> = value
            .as_ref()
            .map(|entry| serde_json::from_slice(entry.value()))
            .transpose()?;
        Ok(warning.filter(|entry| entry.warned_at <= now && entry.expires_at >= now))
    }

    pub fn mark_pending_ban(&self, pending: &PendingBan) -> Result<()> {
        let key = member_key(&pending.room_owner, &pending.member_id);
        let encoded = serde_json::to_vec(pending)?;
        let write = self.database.begin_write()?;
        let mut table = write.open_table(PENDING_BANS)?;
        anyhow::ensure!(
            table.get(key.as_str())?.is_none(),
            "member already has a pending ban"
        );
        table.insert(key.as_str(), encoded.as_slice())?;
        drop(table);
        write.commit()?;
        Ok(())
    }

    pub fn pending_ban(&self, room_owner: &str, member_id: &str) -> Result<Option<PendingBan>> {
        let key = member_key(room_owner, member_id);
        let read = self.database.begin_read()?;
        let table = read.open_table(PENDING_BANS)?;
        let value = table.get(key.as_str())?;
        value
            .as_ref()
            .map(|entry| serde_json::from_slice(entry.value()).context("invalid pending ban"))
            .transpose()
    }

    /// Persist the no-retry marker and consume the rate-limit slot in one
    /// transaction before any external River I/O.
    pub fn claim_ban(
        &self,
        pending: &PendingBan,
        now: DateTime<Utc>,
        global_interval: Duration,
        per_hour: u64,
        per_day: u64,
    ) -> Result<BanClaim> {
        let member_key = member_key(&pending.room_owner, &pending.member_id);
        let write = self.database.begin_write()?;
        let mut pending_table = write.open_table(PENDING_BANS)?;
        if pending_table.get(member_key.as_str())?.is_some() {
            return Ok(BanClaim::AlreadyPending);
        }

        let mut actions = write.open_table(BAN_ACTIONS)?;
        let mut hour_count = 0u64;
        let mut day_count = 0u64;
        let mut latest = None;
        let room_prefix = format!("{}:", pending.room_owner);
        for entry in actions.iter()? {
            let (key, value) = entry?;
            if !key.value().starts_with(&room_prefix) {
                continue;
            }
            let action: ActionLimitRecord = serde_json::from_slice(value.value())?;
            if action.last_action_at > now - Duration::hours(1) {
                hour_count = hour_count.saturating_add(1);
            }
            if action.last_action_at > now - Duration::days(1) {
                day_count = day_count.saturating_add(1);
            }
            latest = Some(latest.map_or(action.last_action_at, |seen: DateTime<Utc>| {
                seen.max(action.last_action_at)
            }));
        }
        if latest.is_some_and(|last| last > now - global_interval)
            || hour_count >= per_hour
            || day_count >= per_day
        {
            return Ok(BanClaim::RateLimited);
        }

        let pending_encoded = serde_json::to_vec(pending)?;
        pending_table.insert(member_key.as_str(), pending_encoded.as_slice())?;
        let action_key = format!("{}:{}", pending.room_owner, pending.decision_id);
        let action_encoded = serde_json::to_vec(&ActionLimitRecord {
            last_action_at: now,
        })?;
        actions.insert(action_key.as_str(), action_encoded.as_slice())?;
        drop(actions);
        drop(pending_table);
        write.commit()?;
        Ok(BanClaim::Claimed)
    }

    pub fn schedule_low_severity(&self, pending: &PendingLowSeverity) -> Result<bool> {
        let key = event_key(&pending.room_owner, &pending.target_message_id);
        let encoded = serde_json::to_vec(pending)?;
        let write = self.database.begin_write()?;
        let mut table = write.open_table(PENDING_LOW_SEVERITY)?;
        if table.get(key.as_str())?.is_some() {
            return Ok(false);
        }
        for entry in table.iter()? {
            let (_, value) = entry?;
            let existing: PendingLowSeverity = serde_json::from_slice(value.value())?;
            if existing.room_owner == pending.room_owner
                && existing.target_member_id == pending.target_member_id
                && warning_group(existing.category) == warning_group(pending.category)
                && existing.cancelled_by_member_id.is_none()
                && existing.completed_at.is_none()
            {
                return Ok(false);
            }
        }
        table.insert(key.as_str(), encoded.as_slice())?;
        drop(table);
        write.commit()?;
        Ok(true)
    }

    /// Cancel only when a locally configured moderator authored an authenticated
    /// reply to the exact target message. Nicknames and preview text are ignored.
    pub fn cancel_if_handled_by_moderator(
        &self,
        room_owner: &str,
        reply_target_message_id: &str,
        responder_member_id: &str,
        moderator_member_ids: &[String],
    ) -> Result<bool> {
        if !moderator_member_ids
            .iter()
            .any(|member| member == responder_member_id)
        {
            return Ok(false);
        }
        let key = event_key(room_owner, reply_target_message_id);
        let write = self.database.begin_write()?;
        let mut table = write.open_table(PENDING_LOW_SEVERITY)?;
        let existing = table.get(key.as_str())?;
        let Some(value) = existing.as_ref() else {
            return Ok(false);
        };
        let mut pending: PendingLowSeverity = serde_json::from_slice(value.value())?;
        drop(existing);
        pending.cancelled_by_member_id = Some(responder_member_id.to_owned());
        let encoded = serde_json::to_vec(&pending)?;
        table.insert(key.as_str(), encoded.as_slice())?;
        drop(table);
        write.commit()?;
        Ok(true)
    }

    pub fn due_low_severity(&self, now: DateTime<Utc>) -> Result<Vec<PendingLowSeverity>> {
        let read = self.database.begin_read()?;
        let table = read.open_table(PENDING_LOW_SEVERITY)?;
        let mut due = Vec::new();
        for entry in table.iter()? {
            let (_, value) = entry?;
            let pending: PendingLowSeverity = serde_json::from_slice(value.value())?;
            if pending.cancelled_by_member_id.is_none()
                && pending.completed_at.is_none()
                && pending.execute_after <= now
            {
                due.push(pending);
            }
        }
        Ok(due)
    }

    /// Claim at most one due action transactionally. The claim consumes global
    /// and per-member cooldowns before external I/O, so a crash cannot produce a
    /// duplicate warning after restart. Stale queued actions are suppressed.
    pub fn claim_due_low_severity(
        &self,
        now: DateTime<Utc>,
        current_policy_version: &str,
        global_interval: Duration,
        member_interval: Duration,
        max_age: Duration,
    ) -> Result<Option<PendingLowSeverity>> {
        let write = self.database.begin_write()?;
        let mut pending_table = write.open_table(PENDING_LOW_SEVERITY)?;
        let mut due = Vec::new();
        for entry in pending_table.iter()? {
            let (key, value) = entry?;
            let pending: PendingLowSeverity = serde_json::from_slice(value.value())?;
            if pending.cancelled_by_member_id.is_none()
                && pending.completed_at.is_none()
                && pending.execute_after <= now
            {
                due.push((key.value().to_owned(), pending));
            }
        }
        due.sort_by_key(|(_, pending)| pending.execute_after);

        for (key, mut pending) in due {
            if pending.policy_version != current_policy_version {
                pending.completed_at = Some(now);
                pending.outcome = Some(LowSeverityOutcome::SuppressedPolicyChanged);
                let encoded = serde_json::to_vec(&pending)?;
                pending_table.insert(key.as_str(), encoded.as_slice())?;
                continue;
            }
            if pending.created_at < now - max_age {
                pending.completed_at = Some(now);
                pending.outcome = Some(LowSeverityOutcome::SuppressedStale);
                let encoded = serde_json::to_vec(&pending)?;
                pending_table.insert(key.as_str(), encoded.as_slice())?;
                continue;
            }

            let mut limits = write.open_table(ACTION_LIMITS)?;
            let global_key = format!("{}:global", pending.room_owner);
            let member_key = format!("{}:member:{}", pending.room_owner, pending.target_member_id);
            let global_last = read_action_limit(&limits, &global_key)?;
            let member_last = read_action_limit(&limits, &member_key)?;
            if global_last.is_some_and(|last| last > now - global_interval)
                || member_last.is_some_and(|last| last > now - member_interval)
            {
                drop(limits);
                continue;
            }
            let limit = serde_json::to_vec(&ActionLimitRecord {
                last_action_at: now,
            })?;
            limits.insert(global_key.as_str(), limit.as_slice())?;
            limits.insert(member_key.as_str(), limit.as_slice())?;
            drop(limits);

            pending.completed_at = Some(now);
            pending.outcome = Some(LowSeverityOutcome::Claimed);
            let encoded = serde_json::to_vec(&pending)?;
            pending_table.insert(key.as_str(), encoded.as_slice())?;
            drop(pending_table);
            write.commit()?;
            return Ok(Some(pending));
        }
        drop(pending_table);
        write.commit()?;
        Ok(None)
    }

    pub fn complete_low_severity(
        &self,
        pending: &PendingLowSeverity,
        outcome: LowSeverityOutcome,
        now: DateTime<Utc>,
    ) -> Result<()> {
        anyhow::ensure!(
            matches!(
                outcome,
                LowSeverityOutcome::Sent
                    | LowSeverityOutcome::Failed
                    | LowSeverityOutcome::SuppressedChangedOrDeleted
            ),
            "invalid terminal low-severity outcome"
        );
        let key = event_key(&pending.room_owner, &pending.target_message_id);
        let write = self.database.begin_write()?;
        let mut table = write.open_table(PENDING_LOW_SEVERITY)?;
        let existing = table
            .get(key.as_str())?
            .context("pending action disappeared")?;
        let mut stored: PendingLowSeverity = serde_json::from_slice(existing.value())?;
        drop(existing);
        anyhow::ensure!(
            stored.outcome == Some(LowSeverityOutcome::Claimed),
            "action was not claimed"
        );
        stored.outcome = Some(outcome);
        stored.completed_at = Some(now);
        let encoded = serde_json::to_vec(&stored)?;
        table.insert(key.as_str(), encoded.as_slice())?;
        drop(table);
        write.commit()?;
        Ok(())
    }
}

fn read_action_limit(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<DateTime<Utc>>> {
    table
        .get(key)?
        .map(|entry| {
            serde_json::from_slice::<ActionLimitRecord>(entry.value())
                .map(|record| record.last_action_at)
                .context("invalid action limit record")
        })
        .transpose()
}

fn event_key(room: &str, message: &str) -> String {
    format!("{room}:{message}")
}

fn member_key(room: &str, member: &str) -> String {
    format!("{room}:{member}")
}

fn observation_key(policy_version: &str, room: &str, member: &str, category: Category) -> String {
    format!(
        "{}:{}:{}:{}",
        policy_version,
        room,
        member,
        warning_group(category)
    )
}

fn warning_key(room: &str, member: &str, category: Category) -> String {
    format!("{}:{}:{}", room, member, warning_group(category))
}

pub fn warning_group(category: Category) -> &'static str {
    match category {
        Category::OffTopic => "topic",
        Category::Conduct | Category::Incivility | Category::PersonalAttack => "civility",
        Category::Flooding => "flooding",
        Category::Spam | Category::Scam | Category::Phishing | Category::SelfPromotion => {
            "spam_scam"
        }
        Category::Misinformation => "misinformation",
        Category::Hate | Category::Harassment => "hate_harassment",
        Category::Malware => "malware",
        Category::Privacy => "privacy",
        Category::Threat => "threat",
        Category::Impersonation | Category::AccountCompromise => "identity_abuse",
        Category::PromptInjection => "prompt_injection",
        Category::SexualExploitation => "sexual_exploitation",
        Category::None | Category::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, second).unwrap()
    }

    fn message(id: &str, content: &str, observed: DateTime<Utc>) -> VerifiedMessage {
        VerifiedMessage {
            message_id: id.into(),
            room_owner: "room".into(),
            author_id: "member".into(),
            nickname: "nick".into(),
            content: content.into(),
            author_claimed_at: observed + Duration::days(100),
            first_observed_at: observed,
            edited: false,
            reply_to_message_id: None,
            reply_to_author_id: None,
        }
    }

    #[test]
    fn dedup_and_edit_preserve_original_observed_time_across_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.redb");
        {
            let state = ModerationState::open(&path).unwrap();
            assert_eq!(
                state
                    .record_message(message("m", "one", at(1)), 100, 4096)
                    .unwrap()
                    .0,
                EventDisposition::New
            );
        }
        let state = ModerationState::open(&path).unwrap();
        let (duplicate, replay) = state
            .record_message(message("m", "one", at(20)), 100, 4096)
            .unwrap();
        assert_eq!(duplicate, EventDisposition::Duplicate);
        assert_eq!(replay.first_observed_at, at(1));
        let (edited, edit) = state
            .record_message(message("m", "two", at(30)), 100, 4096)
            .unwrap();
        assert_eq!(edited, EventDisposition::Edited);
        assert_eq!(edit.first_observed_at, at(1));
    }

    #[test]
    fn context_includes_room_and_same_author_without_duplicates() {
        let dir = tempdir().unwrap();
        let state = ModerationState::open(&dir.path().join("state.redb")).unwrap();
        for second in 1..=10 {
            let mut item = message(&format!("m{second}"), "text", at(second));
            if second % 2 == 0 {
                item.author_id = "other".into();
            }
            state.record_message(item, 100, 4096).unwrap();
        }
        let context = state.context("room", "m9", 3, 4).unwrap();
        assert!(context.len() >= 4);
        let mut ids: Vec<_> = context
            .iter()
            .map(|item| item.message_id.as_str())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), context.len());
    }

    #[test]
    fn warning_preflight_refuses_edited_deleted_or_wrong_author_messages() {
        let dir = tempdir().unwrap();
        let state = ModerationState::open(&dir.path().join("state.redb")).unwrap();
        let original = message("m", "original", at(1));
        let original_hash = original.content_hash();
        state.record_message(original, 100, 4096).unwrap();
        assert!(state
            .message_is_current("room", "m", "member", &original_hash)
            .unwrap());
        assert!(!state
            .message_is_current("room", "m", "wrong-member", &original_hash)
            .unwrap());

        state
            .record_message(message("m", "edited", at(2)), 100, 4096)
            .unwrap();
        assert!(!state
            .message_is_current("room", "m", "member", &original_hash)
            .unwrap());
        let edited_hash = message("m", "edited", at(2)).content_hash();
        assert!(state
            .message_is_current("room", "m", "member", &edited_hash)
            .unwrap());

        state.record_deletion("room", "m", at(3)).unwrap();
        assert!(!state
            .message_is_current("room", "m", "member", &edited_hash)
            .unwrap());
    }

    #[test]
    fn warning_groups_prevent_category_label_evasion() {
        let dir = tempdir().unwrap();
        let state = ModerationState::open(&dir.path().join("state.redb")).unwrap();
        let warning = WarningRecord {
            room_owner: "room".into(),
            member_id: "member".into(),
            category: Category::Incivility,
            warning_group: "civility".into(),
            warned_at: at(1),
            expires_at: at(1) + Duration::hours(24),
            triggering_message_id: "m1".into(),
        };
        state.record_warning(&warning).unwrap();
        assert!(state
            .active_warning("room", "member", Category::PersonalAttack, at(2))
            .unwrap()
            .is_some());
    }

    #[test]
    fn pending_ban_suppresses_repeated_classification_after_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.redb");
        {
            let state = ModerationState::open(&path).unwrap();
            state
                .mark_pending_ban(&PendingBan {
                    room_owner: "room".into(),
                    member_id: "member".into(),
                    decision_id: "decision".into(),
                    created_at: at(1),
                })
                .unwrap();
        }
        let state = ModerationState::open(&path).unwrap();
        assert_eq!(
            state
                .pending_ban("room", "member")
                .unwrap()
                .unwrap()
                .decision_id,
            "decision"
        );
    }

    #[test]
    fn ban_claim_is_persistent_rate_limited_and_never_retried() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let state = ModerationState::open(&path).unwrap();
        let pending = |member: &str, decision: &str, created_at| PendingBan {
            room_owner: "room".into(),
            member_id: member.into(),
            decision_id: decision.into(),
            created_at,
        };
        assert_eq!(
            state
                .claim_ban(
                    &pending("member-a", "decision-a", at(1)),
                    at(1),
                    Duration::seconds(60),
                    5,
                    20,
                )
                .unwrap(),
            BanClaim::Claimed
        );
        assert_eq!(
            state
                .claim_ban(
                    &pending("member-a", "decision-retry", at(2)),
                    at(2),
                    Duration::seconds(60),
                    5,
                    20,
                )
                .unwrap(),
            BanClaim::AlreadyPending
        );
        assert_eq!(
            state
                .claim_ban(
                    &pending("member-b", "decision-b", at(2)),
                    at(2),
                    Duration::seconds(60),
                    5,
                    20,
                )
                .unwrap(),
            BanClaim::RateLimited
        );
        drop(state);
        let state = ModerationState::open(&path).unwrap();
        assert_eq!(
            state
                .claim_ban(
                    &pending("member-a", "decision-after-restart", at(2)),
                    at(2),
                    Duration::seconds(60),
                    5,
                    20,
                )
                .unwrap(),
            BanClaim::AlreadyPending
        );
    }

    #[test]
    fn authenticated_moderator_reply_cancels_delayed_nudge() {
        let dir = tempdir().unwrap();
        let state = ModerationState::open(&dir.path().join("state.redb")).unwrap();
        assert!(state
            .schedule_low_severity(&PendingLowSeverity {
                policy_version: "policy-v1".into(),
                decision_id: "d".into(),
                room_owner: "room".into(),
                target_message_id: "target-message".into(),
                target_member_id: "new-member".into(),
                classified_content_hash: "hash".into(),
                action: LowSeverityAction::Nudge,
                category: Category::Incivility,
                created_at: at(1),
                execute_after: at(1) + Duration::seconds(60),
                cancelled_by_member_id: None,
                completed_at: None,
                outcome: None,
            })
            .unwrap());
        assert!(!state
            .cancel_if_handled_by_moderator(
                "room",
                "target-message",
                "nickname-spoofing-attacker",
                &["owner-id".into()],
            )
            .unwrap());
        assert!(state
            .cancel_if_handled_by_moderator(
                "room",
                "target-message",
                "owner-id",
                &["owner-id".into()],
            )
            .unwrap());
        assert!(state
            .due_low_severity(at(1) + Duration::seconds(120))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn claims_only_one_action_per_global_interval_and_never_replays_claim() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let state = ModerationState::open(&path).unwrap();
        for (id, member) in [("one", "member-a"), ("two", "member-b")] {
            assert!(state
                .schedule_low_severity(&PendingLowSeverity {
                    policy_version: "policy-v1".into(),
                    decision_id: id.into(),
                    room_owner: "room".into(),
                    target_message_id: id.into(),
                    target_member_id: member.into(),
                    classified_content_hash: "hash".into(),
                    action: LowSeverityAction::FormalWarning,
                    category: Category::OffTopic,
                    created_at: at(1),
                    execute_after: at(2),
                    cancelled_by_member_id: None,
                    completed_at: None,
                    outcome: None,
                })
                .unwrap());
        }
        let first = state
            .claim_due_low_severity(
                at(3),
                "policy-v1",
                Duration::seconds(300),
                Duration::hours(24),
                Duration::seconds(600),
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.outcome, Some(LowSeverityOutcome::Claimed));
        drop(state);
        let state = ModerationState::open(&path).unwrap();
        assert!(state
            .claim_due_low_severity(
                at(4),
                "policy-v1",
                Duration::seconds(300),
                Duration::hours(24),
                Duration::seconds(600),
            )
            .unwrap()
            .is_none());
        state
            .complete_low_severity(&first, LowSeverityOutcome::Sent, at(4))
            .unwrap();
        assert!(state
            .claim_due_low_severity(
                at(4),
                "policy-v1",
                Duration::seconds(300),
                Duration::hours(24),
                Duration::seconds(600),
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn queued_action_from_an_old_policy_is_suppressed() {
        let dir = tempdir().unwrap();
        let state = ModerationState::open(&dir.path().join("state.redb")).unwrap();
        assert!(state
            .schedule_low_severity(&PendingLowSeverity {
                policy_version: "old-policy".into(),
                decision_id: "old-decision".into(),
                room_owner: "room".into(),
                target_message_id: "old-message".into(),
                target_member_id: "member".into(),
                classified_content_hash: "hash".into(),
                action: LowSeverityAction::Nudge,
                category: Category::Incivility,
                created_at: at(1),
                execute_after: at(2),
                cancelled_by_member_id: None,
                completed_at: None,
                outcome: None,
            })
            .unwrap());

        assert!(state
            .claim_due_low_severity(
                at(3),
                "new-policy",
                Duration::seconds(300),
                Duration::hours(24),
                Duration::seconds(600),
            )
            .unwrap()
            .is_none());
        assert!(state.due_low_severity(at(4)).unwrap().is_empty());
    }
}
