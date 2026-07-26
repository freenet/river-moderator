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
    pub reply_to_author_id: Option<String>,
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

/// Arrival gap below which two messages came from one delivery rather than from
/// someone typing. Messages posted separately traverse the network separately,
/// so even a scripted flood arrives milliseconds apart; a replayed backlog
/// arrives in a single batch sharing one instant.
const SAME_DELIVERY_MILLIS: i64 = 50;

/// Whether two messages from the same author belong to the same burst.
///
/// Arrival time remains the primary clock, because the author controls their
/// own claimed time and could otherwise spread a real flood by backdating it
/// (see `burst_uses_observation_time_not_attacker_clock`).
///
/// The one case arrival time gets wrong is replay. When the reader reconnects
/// and receives a backlog, the whole batch shares a single arrival instant, so
/// old messages look exactly like a live flood. On 2026-07-26 the reader
/// delivered ten of one member's messages, authored the previous evening across
/// ten minutes, within 0.06ms of each other. They scored
/// `author_messages_10_seconds = 10`, hit the flooding gate, and were
/// classified `BanSevereHarm` at 0.999. The member had posted a bug report
/// about room desync; the moderator replayed its own backlog and then accused
/// him of flooding with it. He survived only because deputies divert to a
/// branch that never executes, so an ordinary member would have been banned.
///
/// So claimed time is consulted for exactly one purpose: vetoing a pair that
/// arrived in the same delivery but was authored far apart. That is replay, not
/// typing. An attacker cannot reach this veto by backdating alone, because
/// their messages still arrive spread out and the veto only applies inside one
/// delivery window; and if they do land in one delivery with honest timestamps,
/// the claimed times are tight and the burst still counts.
fn within_burst(
    current: &VerifiedMessage,
    previous: &VerifiedMessage,
    window_seconds: i64,
) -> bool {
    let arrival_millis = current
        .first_observed_at
        .signed_duration_since(previous.first_observed_at)
        .num_milliseconds();
    if !(0..=window_seconds.saturating_mul(1_000)).contains(&arrival_millis) {
        return false;
    }
    if arrival_millis > SAME_DELIVERY_MILLIS {
        return true;
    }
    let claimed_apart = current
        .author_claimed_at
        .signed_duration_since(previous.author_claimed_at)
        .num_seconds()
        .abs();
    claimed_apart <= window_seconds
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
        if within_burst(current, message, 10) {
            in_10s = in_10s.saturating_add(1);
        }
        if within_burst(current, message, 60) {
            in_1m = in_1m.saturating_add(1);
        }
        if within_burst(current, message, 300) {
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
            reply_to_author_id: None,
        }
    }

    /// The production incident, verbatim. Ten messages authored the previous
    /// evening across ten minutes, all delivered in the same millisecond by a
    /// reader reconnect. Counting arrival alone scored this 10 and tripped the
    /// flooding gate against a member who had done nothing.
    #[test]
    fn replayed_backlog_is_not_a_live_burst() {
        let observed = Utc::now();
        let authored = observed - Duration::hours(19);
        let history: Vec<_> = (0..9)
            .map(|i| {
                message(
                    &format!("old{i}"),
                    authored + Duration::seconds(i * 60),
                    observed - Duration::microseconds(60 - i),
                )
            })
            .collect();
        let current = message("old9", authored + Duration::seconds(540), observed);
        let signals = temporal_signals(&current, &history);
        assert_eq!(
            signals.author_messages_10_seconds, 1,
            "a replayed backlog must not read as a live burst"
        );
        assert!(signals.claimed_clock_skew_seconds < -60_000);
    }

    /// The counterpart: messages that genuinely arrived together AND were
    /// authored together are a real burst and must still count, so the veto
    /// cannot be reached just by delivering fast.
    #[test]
    fn simultaneous_delivery_with_honest_timestamps_still_counts() {
        let observed = Utc::now();
        let history: Vec<_> = (0..9)
            .map(|i| {
                message(
                    &format!("live{i}"),
                    observed - Duration::seconds(9 - i),
                    observed - Duration::microseconds(60 - i),
                )
            })
            .collect();
        let current = message("live9", observed, observed);
        let signals = temporal_signals(&current, &history);
        assert_eq!(signals.author_messages_10_seconds, 10);
    }

    /// A real flood arrives spread out, so the replay veto never applies to it
    /// regardless of what the author claims about timing.
    #[test]
    fn spread_out_flood_still_counts_even_if_backdated() {
        let now = Utc::now();
        let history: Vec<_> = (0..9)
            .map(|i| {
                message(
                    &format!("f{i}"),
                    now - Duration::days(30) + Duration::seconds(i),
                    now - Duration::seconds(9 - i),
                )
            })
            .collect();
        let current = message("f9", now - Duration::days(30), now);
        let signals = temporal_signals(&current, &history);
        assert_eq!(
            signals.author_messages_10_seconds, 10,
            "backdating must not buy an attacker an escape from burst counting"
        );
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
