use std::path::Path;

use chrono::{DateTime, Datelike, Timelike, Utc};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::LimitConfig;

const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("budget_counters_v1");
const RESERVATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("budget_reservations_v1");

#[derive(Debug)]
pub struct BudgetLedger {
    database: Database,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Reservation {
    pub request_id: String,
    pub author_id: String,
    pub reserved_microusd: u64,
    pub created_at: DateTime<Utc>,
    pub reconciled_microusd: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BudgetStatus {
    pub day_reserved_microusd: u64,
    pub month_reserved_microusd: u64,
    pub requests_this_minute: u64,
    pub requests_this_hour: u64,
    pub requests_today: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BudgetDenied {
    #[error("request id was already reserved")]
    DuplicateRequest,
    #[error("daily spending cap reached")]
    DailySpend,
    #[error("monthly spending cap reached")]
    MonthlySpend,
    #[error("per-minute request cap reached")]
    RequestsMinute,
    #[error("hourly request cap reached")]
    RequestsHour,
    #[error("daily request cap reached")]
    RequestsDay,
    #[error("per-author hourly request cap reached")]
    RequestsAuthorHour,
    #[error("budget ledger failure: {0}")]
    Ledger(String),
}

impl BudgetLedger {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let database = Database::create(path)?;
        let write = database.begin_write()?;
        write.open_table(COUNTERS)?;
        write.open_table(RESERVATIONS)?;
        write.commit()?;
        Ok(Self { database })
    }

    pub fn reserve(
        &self,
        request_id: &str,
        author_id: &str,
        amount_microusd: u64,
        now: DateTime<Utc>,
        limits: &LimitConfig,
    ) -> Result<Reservation, BudgetDenied> {
        let write = self.database.begin_write().map_err(ledger)?;
        {
            let reservations = write.open_table(RESERVATIONS).map_err(ledger)?;
            if reservations.get(request_id).map_err(ledger)?.is_some() {
                return Err(BudgetDenied::DuplicateRequest);
            }
        }

        let keys = BucketKeys::new(now, author_id);
        let mut counters = write.open_table(COUNTERS).map_err(ledger)?;
        let day_spend = counter(&counters, &keys.spend_day)?;
        let month_spend = counter(&counters, &keys.spend_month)?;
        let minute_count = counter(&counters, &keys.requests_minute)?;
        let hour_count = counter(&counters, &keys.requests_hour)?;
        let day_count = counter(&counters, &keys.requests_day)?;
        let author_count = counter(&counters, &keys.requests_author_hour)?;

        checked_cap(
            day_spend,
            amount_microusd,
            limits.daily_budget_microusd,
            BudgetDenied::DailySpend,
        )?;
        checked_cap(
            month_spend,
            amount_microusd,
            limits.monthly_budget_microusd,
            BudgetDenied::MonthlySpend,
        )?;
        checked_cap(
            minute_count,
            1,
            limits.requests_per_minute,
            BudgetDenied::RequestsMinute,
        )?;
        checked_cap(
            hour_count,
            1,
            limits.requests_per_hour,
            BudgetDenied::RequestsHour,
        )?;
        checked_cap(
            day_count,
            1,
            limits.requests_per_day,
            BudgetDenied::RequestsDay,
        )?;
        checked_cap(
            author_count,
            1,
            limits.requests_per_author_hour,
            BudgetDenied::RequestsAuthorHour,
        )?;

        increment(&mut counters, &keys.spend_day, amount_microusd)?;
        increment(&mut counters, &keys.spend_month, amount_microusd)?;
        increment(&mut counters, &keys.requests_minute, 1)?;
        increment(&mut counters, &keys.requests_hour, 1)?;
        increment(&mut counters, &keys.requests_day, 1)?;
        increment(&mut counters, &keys.requests_author_hour, 1)?;
        drop(counters);

        let reservation = Reservation {
            request_id: request_id.to_owned(),
            author_id: author_id.to_owned(),
            reserved_microusd: amount_microusd,
            created_at: now,
            reconciled_microusd: None,
        };
        let encoded = serde_json::to_vec(&reservation).map_err(ledger)?;
        write
            .open_table(RESERVATIONS)
            .map_err(ledger)?
            .insert(request_id, encoded.as_slice())
            .map_err(ledger)?;
        write.commit().map_err(ledger)?;
        Ok(reservation)
    }

    /// Reconcile downward only. The original full reservation remains when usage
    /// is missing and an impossible above-reservation report is rejected.
    pub fn reconcile(&self, request_id: &str, actual_microusd: u64) -> anyhow::Result<()> {
        let write = self.database.begin_write()?;
        let mut reservations = write.open_table(RESERVATIONS)?;
        let existing = reservations
            .get(request_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown reservation"))?;
        let mut reservation: Reservation = serde_json::from_slice(existing.value())?;
        drop(existing);
        anyhow::ensure!(
            reservation.reconciled_microusd.is_none(),
            "reservation already reconciled"
        );
        anyhow::ensure!(
            actual_microusd <= reservation.reserved_microusd,
            "actual cost exceeds worst-case reservation"
        );

        let refund = reservation.reserved_microusd - actual_microusd;
        if refund > 0 {
            let keys = BucketKeys::new(reservation.created_at, &reservation.author_id);
            let mut counters = write.open_table(COUNTERS)?;
            decrement(&mut counters, &keys.spend_day, refund)?;
            decrement(&mut counters, &keys.spend_month, refund)?;
        }
        reservation.reconciled_microusd = Some(actual_microusd);
        let encoded = serde_json::to_vec(&reservation)?;
        reservations.insert(request_id, encoded.as_slice())?;
        drop(reservations);
        write.commit()?;
        Ok(())
    }

    pub fn status(&self, now: DateTime<Utc>) -> anyhow::Result<BudgetStatus> {
        let keys = BucketKeys::new(now, "");
        let read = self.database.begin_read()?;
        let counters = read.open_table(COUNTERS)?;
        Ok(BudgetStatus {
            day_reserved_microusd: counter_anyhow(&counters, &keys.spend_day)?,
            month_reserved_microusd: counter_anyhow(&counters, &keys.spend_month)?,
            requests_this_minute: counter_anyhow(&counters, &keys.requests_minute)?,
            requests_this_hour: counter_anyhow(&counters, &keys.requests_hour)?,
            requests_today: counter_anyhow(&counters, &keys.requests_day)?,
        })
    }
}

struct BucketKeys {
    spend_day: String,
    spend_month: String,
    requests_minute: String,
    requests_hour: String,
    requests_day: String,
    requests_author_hour: String,
}

impl BucketKeys {
    fn new(now: DateTime<Utc>, author: &str) -> Self {
        let day = format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day());
        let hour = format!("{day}T{:02}", now.hour());
        let minute = format!("{hour}:{:02}", now.minute());
        Self {
            spend_day: format!("spend:day:{day}"),
            spend_month: format!("spend:month:{:04}-{:02}", now.year(), now.month()),
            requests_minute: format!("requests:minute:{minute}"),
            requests_hour: format!("requests:hour:{hour}"),
            requests_day: format!("requests:day:{day}"),
            requests_author_hour: format!("requests:author-hour:{author}:{hour}"),
        }
    }
}

fn ledger(error: impl std::fmt::Display) -> BudgetDenied {
    BudgetDenied::Ledger(error.to_string())
}

fn checked_cap(current: u64, add: u64, cap: u64, denied: BudgetDenied) -> Result<(), BudgetDenied> {
    match current.checked_add(add) {
        Some(value) if value <= cap => Ok(()),
        _ => Err(denied),
    }
}

fn counter(table: &impl ReadableTable<&'static str, u64>, key: &str) -> Result<u64, BudgetDenied> {
    Ok(table
        .get(key)
        .map_err(ledger)?
        .map(|v| v.value())
        .unwrap_or(0))
}

fn counter_anyhow(table: &impl ReadableTable<&'static str, u64>, key: &str) -> anyhow::Result<u64> {
    Ok(table.get(key)?.map(|v| v.value()).unwrap_or(0))
}

fn increment(
    table: &mut redb::Table<&str, u64>,
    key: &str,
    amount: u64,
) -> Result<(), BudgetDenied> {
    let value = counter(table, key)?
        .checked_add(amount)
        .ok_or_else(|| ledger("counter overflow"))?;
    table.insert(key, value).map_err(ledger)?;
    Ok(())
}

fn decrement(table: &mut redb::Table<&str, u64>, key: &str, amount: u64) -> anyhow::Result<()> {
    let value = counter_anyhow(table, key)?;
    table.insert(
        key,
        value
            .checked_sub(amount)
            .ok_or_else(|| anyhow::anyhow!("counter underflow"))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn limits() -> LimitConfig {
        LimitConfig {
            daily_budget_microusd: 1_000,
            monthly_budget_microusd: 2_000,
            requests_per_minute: 2,
            requests_per_hour: 3,
            requests_per_day: 4,
            requests_per_author_hour: 2,
            queue_depth: 10,
            concurrency: 2,
        }
    }

    fn at(day: u32, hour: u32, minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, day, hour, minute, 0).unwrap()
    }

    #[test]
    fn reservation_survives_restart_and_blocks_duplicate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.redb");
        {
            let ledger = BudgetLedger::open(&path).unwrap();
            ledger
                .reserve("r1", "a", 400, at(25, 1, 0), &limits())
                .unwrap();
        }
        let ledger = BudgetLedger::open(&path).unwrap();
        assert_eq!(
            ledger.status(at(25, 1, 0)).unwrap().day_reserved_microusd,
            400
        );
        assert_eq!(
            ledger.reserve("r1", "a", 1, at(25, 1, 0), &limits()),
            Err(BudgetDenied::DuplicateRequest)
        );
    }

    #[test]
    fn spend_is_reserved_before_call_and_reconciled_downward() {
        let dir = tempdir().unwrap();
        let ledger = BudgetLedger::open(&dir.path().join("state.redb")).unwrap();
        ledger
            .reserve("r1", "a", 600, at(25, 1, 0), &limits())
            .unwrap();
        assert_eq!(
            ledger.reserve("r2", "b", 500, at(25, 1, 0), &limits()),
            Err(BudgetDenied::DailySpend)
        );
        ledger.reconcile("r1", 100).unwrap();
        ledger
            .reserve("r2", "b", 500, at(25, 1, 0), &limits())
            .unwrap();
        assert_eq!(
            ledger.status(at(25, 1, 0)).unwrap().day_reserved_microusd,
            600
        );
    }

    #[test]
    fn missing_usage_retains_full_reservation() {
        let dir = tempdir().unwrap();
        let ledger = BudgetLedger::open(&dir.path().join("state.redb")).unwrap();
        ledger
            .reserve("timed-out", "a", 1_000, at(25, 1, 0), &limits())
            .unwrap();
        assert_eq!(
            ledger.reserve("later", "b", 1, at(25, 1, 0), &limits()),
            Err(BudgetDenied::DailySpend)
        );
    }

    #[test]
    fn independent_request_and_author_caps_apply() {
        let dir = tempdir().unwrap();
        let ledger = BudgetLedger::open(&dir.path().join("state.redb")).unwrap();
        ledger
            .reserve("1", "a", 1, at(25, 1, 0), &limits())
            .unwrap();
        ledger
            .reserve("2", "a", 1, at(25, 1, 0), &limits())
            .unwrap();
        assert_eq!(
            ledger.reserve("3", "a", 1, at(25, 1, 1), &limits()),
            Err(BudgetDenied::RequestsAuthorHour)
        );
        assert_eq!(
            ledger.reserve("4", "b", 1, at(25, 1, 0), &limits()),
            Err(BudgetDenied::RequestsMinute)
        );
    }

    #[test]
    fn day_and_month_buckets_roll_independently() {
        let dir = tempdir().unwrap();
        let ledger = BudgetLedger::open(&dir.path().join("state.redb")).unwrap();
        ledger
            .reserve("1", "a", 900, at(25, 1, 0), &limits())
            .unwrap();
        ledger
            .reserve("2", "a", 900, at(26, 1, 0), &limits())
            .unwrap();
        assert_eq!(
            ledger.reserve("3", "b", 201, at(27, 1, 0), &limits()),
            Err(BudgetDenied::MonthlySpend)
        );
    }
}
