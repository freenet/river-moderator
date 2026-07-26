use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedMessage {
    pub message_id: String,
    pub room_owner: String,
    pub author_id: String,
    pub nickname: String,
    pub content: String,
    /// Signed by the author but not a trustworthy rate-limit clock.
    pub author_claimed_at: DateTime<Utc>,
    /// Assigned and persisted on first local observation.
    pub first_observed_at: DateTime<Utc>,
    pub edited: bool,
    pub reply_to_message_id: Option<String>,
}

impl VerifiedMessage {
    pub fn content_hash(&self) -> String {
        blake3::hash(self.content.as_bytes()).to_hex().to_string()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemporalSignals {
    pub author_messages_10_seconds: u32,
    pub author_messages_1_minute: u32,
    pub author_messages_5_minutes: u32,
    pub milliseconds_since_author_previous: Option<u64>,
    pub exact_duplicate_count_5_minutes: u32,
    pub claimed_clock_skew_seconds: i64,
}

pub fn temporal_signals(current: &VerifiedMessage, history: &[VerifiedMessage]) -> TemporalSignals {
    let same_author = history.iter().filter(|m| m.author_id == current.author_id);
    let mut in_10s = 1u32;
    let mut in_1m = 1u32;
    let mut in_5m = 1u32;
    let mut duplicates = 0u32;
    let mut previous_gap = None;
    let mut newest_prior: Option<DateTime<Utc>> = None;

    for message in same_author {
        let age = current
            .first_observed_at
            .signed_duration_since(message.first_observed_at);
        if age.num_milliseconds() < 0 {
            continue;
        }
        if age.num_seconds() <= 10 {
            in_10s = in_10s.saturating_add(1);
        }
        if age.num_seconds() <= 60 {
            in_1m = in_1m.saturating_add(1);
        }
        if age.num_seconds() <= 300 {
            in_5m = in_5m.saturating_add(1);
            if message.content_hash() == current.content_hash() {
                duplicates = duplicates.saturating_add(1);
            }
        }
        if newest_prior.is_none_or(|value| message.first_observed_at > value) {
            newest_prior = Some(message.first_observed_at);
        }
    }

    if let Some(previous) = newest_prior {
        previous_gap = current
            .first_observed_at
            .signed_duration_since(previous)
            .num_milliseconds()
            .try_into()
            .ok();
    }

    TemporalSignals {
        author_messages_10_seconds: in_10s,
        author_messages_1_minute: in_1m,
        author_messages_5_minutes: in_5m,
        milliseconds_since_author_previous: previous_gap,
        exact_duplicate_count_5_minutes: duplicates,
        claimed_clock_skew_seconds: current
            .author_claimed_at
            .signed_duration_since(current.first_observed_at)
            .num_seconds(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn message(id: &str, claimed: DateTime<Utc>, observed: DateTime<Utc>) -> VerifiedMessage {
        VerifiedMessage {
            message_id: id.into(),
            room_owner: "owner".into(),
            author_id: "author".into(),
            nickname: "nick".into(),
            content: "ordinary-looking message".into(),
            author_claimed_at: claimed,
            first_observed_at: observed,
            edited: false,
            reply_to_message_id: None,
        }
    }

    #[test]
    fn burst_uses_observation_time_not_attacker_clock() {
        let now = Utc::now();
        let history = vec![
            message("1", now - Duration::days(30), now - Duration::seconds(2)),
            message("2", now + Duration::days(30), now - Duration::seconds(1)),
        ];
        let current = message("3", now + Duration::days(365), now);
        let signals = temporal_signals(&current, &history);
        assert_eq!(signals.author_messages_10_seconds, 3);
        assert_eq!(signals.milliseconds_since_author_previous, Some(1_000));
        assert!(signals.claimed_clock_skew_seconds > 31_000_000);
    }
}
