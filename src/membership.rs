use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Duration, Utc};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::config::PolicyConfig;

const MEMBERS: TableDefinition<&str, &[u8]> = TableDefinition::new("member_tenure_v1");
const ACTIVE_DAYS: TableDefinition<&str, u8> = TableDefinition::new("member_active_days_v1");
const META: TableDefinition<&str, u8> = TableDefinition::new("member_registry_meta_v1");

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    Probationary,
    Regular,
    Established,
    Deputy,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemberTenure {
    pub room_owner: String,
    pub member_id: String,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
    pub observation_count: u64,
    pub active_days: u32,
    pub bootstrapped_as_existing: bool,
}

impl MemberTenure {
    pub fn trust_tier(
        &self,
        now: DateTime<Utc>,
        is_current_deputy: bool,
        policy: &PolicyConfig,
    ) -> TrustTier {
        if is_current_deputy {
            return TrustTier::Deputy;
        }
        if self.bootstrapped_as_existing {
            return TrustTier::Established;
        }
        let age = now
            .signed_duration_since(self.first_observed_at)
            .max(Duration::zero());
        if age.num_days() >= i64::from(policy.established_after_days)
            && self.active_days >= policy.established_after_active_days
            && self.observation_count >= policy.established_after_messages
        {
            TrustTier::Established
        } else if age.num_days() >= i64::from(policy.regular_after_days)
            && self.observation_count >= policy.regular_after_messages
        {
            TrustTier::Regular
        } else {
            TrustTier::Probationary
        }
    }
}

pub struct MemberRegistry {
    database: Arc<Database>,
}

impl MemberRegistry {
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_database(Arc::new(Database::create(path)?))
    }

    pub fn from_database(database: Arc<Database>) -> Result<Self> {
        let write = database.begin_write()?;
        write.open_table(MEMBERS)?;
        write.open_table(ACTIVE_DAYS)?;
        write.open_table(META)?;
        write.commit()?;
        Ok(Self { database })
    }

    /// Explicit one-time bootstrap. The daemon must never call this implicitly.
    pub fn bootstrap_room(
        &self,
        room_owner: &str,
        member_ids: impl IntoIterator<Item = String>,
        now: DateTime<Utc>,
    ) -> Result<usize> {
        let write = self.database.begin_write()?;
        {
            let meta = write.open_table(META)?;
            anyhow::ensure!(
                meta.get(bootstrap_key(room_owner).as_str())?.is_none(),
                "room registry is already bootstrapped"
            );
        }

        let mut count = 0usize;
        let mut members = write.open_table(MEMBERS)?;
        let mut days = write.open_table(ACTIVE_DAYS)?;
        for member_id in member_ids {
            let key = member_key(room_owner, &member_id);
            if members.get(key.as_str())?.is_some() {
                continue;
            }
            let record = MemberTenure {
                room_owner: room_owner.to_owned(),
                member_id: member_id.clone(),
                first_observed_at: now,
                last_observed_at: now,
                observation_count: 0,
                active_days: 0,
                bootstrapped_as_existing: true,
            };
            let encoded = serde_json::to_vec(&record)?;
            members.insert(key.as_str(), encoded.as_slice())?;
            days.insert(active_day_key(room_owner, &member_id, now).as_str(), 1)?;
            count += 1;
        }
        drop(days);
        drop(members);
        write
            .open_table(META)?
            .insert(bootstrap_key(room_owner).as_str(), 1)?;
        write.commit()?;
        Ok(count)
    }

    pub fn is_bootstrapped(&self, room_owner: &str) -> Result<bool> {
        let read = self.database.begin_read()?;
        Ok(read
            .open_table(META)?
            .get(bootstrap_key(room_owner).as_str())?
            .is_some())
    }

    pub fn observe(
        &self,
        room_owner: &str,
        member_id: &str,
        now: DateTime<Utc>,
    ) -> Result<MemberTenure> {
        anyhow::ensure!(
            self.is_bootstrapped(room_owner)?,
            "room registry is not bootstrapped"
        );
        let write = self.database.begin_write()?;
        let key = member_key(room_owner, member_id);
        let mut members = write.open_table(MEMBERS)?;
        let existing = members.get(key.as_str())?;
        let mut record = match existing.as_ref() {
            Some(value) => serde_json::from_slice::<MemberTenure>(value.value())?,
            None => MemberTenure {
                room_owner: room_owner.to_owned(),
                member_id: member_id.to_owned(),
                first_observed_at: now,
                last_observed_at: now,
                observation_count: 0,
                active_days: 0,
                bootstrapped_as_existing: false,
            },
        };
        drop(existing);

        record.last_observed_at = record.last_observed_at.max(now);
        record.observation_count = record
            .observation_count
            .checked_add(1)
            .context("observation counter overflow")?;

        let day_key = active_day_key(room_owner, member_id, now);
        let mut days = write.open_table(ACTIVE_DAYS)?;
        if days.get(day_key.as_str())?.is_none() {
            days.insert(day_key.as_str(), 1)?;
            record.active_days = record
                .active_days
                .checked_add(1)
                .context("active-day counter overflow")?;
        }
        drop(days);

        let encoded = serde_json::to_vec(&record)?;
        members.insert(key.as_str(), encoded.as_slice())?;
        drop(members);
        write.commit()?;
        Ok(record)
    }

    pub fn get(&self, room_owner: &str, member_id: &str) -> Result<Option<MemberTenure>> {
        let read = self.database.begin_read()?;
        let members = read.open_table(MEMBERS)?;
        let value = members.get(member_key(room_owner, member_id).as_str())?;
        value
            .map(|entry| {
                serde_json::from_slice(entry.value()).context("invalid member tenure record")
            })
            .transpose()
    }
}

fn member_key(room: &str, member: &str) -> String {
    format!("{room}:{member}")
}
fn bootstrap_key(room: &str) -> String {
    format!("bootstrapped:{room}")
}
fn active_day_key(room: &str, member: &str, now: DateTime<Utc>) -> String {
    format!(
        "{room}:{member}:{:04}-{:02}-{:02}",
        now.year(),
        now.month(),
        now.day()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn policy() -> PolicyConfig {
        PolicyConfig {
            warning_window_hours: 24,
            max_ban_descendants: 0,
            ban_confidence_millionths: 980_000,
            deputy_ban_confidence_millionths: 995_000,
            nudge_confidence_millionths: 850_000,
            warning_confidence_millionths: 900_000,
            regular_after_days: 7,
            regular_after_messages: 2,
            established_after_days: 30,
            established_after_active_days: 2,
            established_after_messages: 3,
        }
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, day, 12, 0, 0).unwrap()
    }

    #[test]
    fn bootstrap_is_explicit_one_time_and_marks_old_timers_established() {
        let dir = tempdir().unwrap();
        let registry = MemberRegistry::open(&dir.path().join("members.redb")).unwrap();
        assert!(!registry.is_bootstrapped("room").unwrap());
        assert!(registry.observe("room", "new", at(1)).is_err());
        assert_eq!(
            registry
                .bootstrap_room("room", vec!["old".into()], at(1))
                .unwrap(),
            1
        );
        assert!(registry
            .bootstrap_room("room", Vec::<String>::new(), at(2))
            .is_err());
        let old = registry.get("room", "old").unwrap().unwrap();
        assert_eq!(
            old.trust_tier(at(1), false, &policy()),
            TrustTier::Established
        );
    }

    #[test]
    fn new_member_ages_using_local_observations_and_active_days() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("members.redb");
        {
            let registry = MemberRegistry::open(&path).unwrap();
            registry
                .bootstrap_room("room", Vec::<String>::new(), at(1))
                .unwrap();
            let first = registry.observe("room", "new", at(1)).unwrap();
            assert_eq!(
                first.trust_tier(at(1), false, &policy()),
                TrustTier::Probationary
            );
            registry.observe("room", "new", at(8)).unwrap();
        }
        let registry = MemberRegistry::open(&path).unwrap();
        let regular = registry.observe("room", "new", at(8)).unwrap();
        assert_eq!(
            regular.trust_tier(at(8), false, &policy()),
            TrustTier::Regular
        );
        let established = registry.observe("room", "new", at(31)).unwrap();
        assert_eq!(
            established.trust_tier(at(31), false, &policy()),
            TrustTier::Established
        );
    }

    #[test]
    fn current_deputy_tier_overrides_tenure() {
        let dir = tempdir().unwrap();
        let registry = MemberRegistry::open(&dir.path().join("members.redb")).unwrap();
        registry
            .bootstrap_room("room", Vec::<String>::new(), at(1))
            .unwrap();
        let member = registry.observe("room", "new", at(1)).unwrap();
        assert_eq!(member.trust_tier(at(1), true, &policy()), TrustTier::Deputy);
    }
}
