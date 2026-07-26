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

    pub fn record_policy_observation(
        &self,
        room_owner: &str,
        member_id: &str,
        category: Category,
        now: DateTime<Utc>,
        window: Duration,
    ) -> Result<u32> {
        let key = observation_key(room_owner, member_id, category);
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
}

fn event_key(room: &str, message: &str) -> String {
    format!("{room}:{message}")
}

fn member_key(room: &str, member: &str) -> String {
    format!("{room}:{member}")
}

fn observation_key(room: &str, member: &str, category: Category) -> String {
    format!("{}:{}:{}", room, member, warning_group(category))
}

fn warning_key(room: &str, member: &str, category: Category) -> String {
    format!("{}:{}:{}", room, member, warning_group(category))
}

pub fn warning_group(category: Category) -> &'static str {
    match category {
        Category::OffTopic => "topic",
        Category::Conduct | Category::Incivility | Category::PersonalAttack => "civility",
        Category::Flooding => "flooding",
        Category::SelfPromotion => "promotion",
        Category::Misinformation => "misinformation",
        _ => "severe_or_other",
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
}
