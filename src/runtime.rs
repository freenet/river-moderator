use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use redb::Database;
use tokio::sync::{mpsc, Semaphore};

use crate::{
    audit::{DecisionAuditLog, DecisionAuditRecord, DECISION_AUDIT_SCHEMA_VERSION},
    budget::BudgetLedger,
    classifier::{build_payload, PayloadInput},
    config::{Config, ModelProvider, ModelRole},
    event::{temporal_signals, VerifiedMessage},
    membership::MemberRegistry,
    model::{ModelPass, ModelResult},
    openai_model::OpenAiModelClient,
    policy::{decide, PolicyInput},
    river_stream::{spawn_reader, RoomEvent},
    state::{EventDisposition, ModerationState},
    verdict::{Category, Verdict},
};

const MODEL_REQUEST_OVERHEAD_BYTES: u64 = 6_000;
const HISTORY_MESSAGES: usize = 200;

pub async fn run_shadow(config: Config) -> Result<()> {
    anyhow::ensure!(config.service.mode.is_shadow(), "runtime is shadow-only");
    anyhow::ensure!(
        config.model.provider == ModelProvider::OpenAi,
        "live runtime currently requires the OpenAI provider"
    );
    let database = Arc::new(Database::create(&config.service.state_database)?);
    let state = Arc::new(ModerationState::from_database(database.clone())?);
    let members = Arc::new(MemberRegistry::from_database(database.clone())?);
    let budgets = Arc::new(BudgetLedger::from_database(database)?);
    anyhow::ensure!(
        members.is_bootstrapped(&config.room.owner_verifying_key)?,
        "member tenure registry is not bootstrapped"
    );
    let audit = Arc::new(DecisionAuditLog::open(&config.audit.decision_path)?);
    let model = Arc::new(OpenAiModelClient::new(&config.model)?);
    let config = Arc::new(config);
    let (sender, mut receiver) = mpsc::channel(config.limits.queue_depth);
    let reader_config = config.clone();
    tokio::spawn(async move { reader_loop(reader_config, sender).await });
    let concurrency = Arc::new(Semaphore::new(config.limits.concurrency));

    tracing::info!(
        mode = "shadow",
        classifier = %config.model.classifier_name,
        verifier = %config.model.verifier_name,
        queue_depth = config.limits.queue_depth,
        concurrency = config.limits.concurrency,
        "moderator started"
    );

    while let Some(event) = receiver.recv().await {
        match event {
            RoomEvent::Message(message) => {
                if message.room_owner != config.room.owner_verifying_key {
                    tracing::error!("discarded event for unexpected room");
                    continue;
                }
                if let (Some(reply_message), Some(_)) = (
                    message.reply_to_message_id.as_deref(),
                    message.reply_to_author_id.as_deref(),
                ) {
                    if state.cancel_if_handled_by_moderator(
                        &message.room_owner,
                        reply_message,
                        &message.author_id,
                        &config.room.protected_member_ids,
                    )? {
                        tracing::info!(
                            responder_member_id = %message.author_id,
                            reply_target_hash = %short_hash(reply_message),
                            "moderator reply cancelled pending low-severity action"
                        );
                    }
                }
                let (disposition, message) = state.record_message(
                    message,
                    HISTORY_MESSAGES,
                    config.audit.max_message_bytes,
                )?;
                if disposition == EventDisposition::Duplicate {
                    continue;
                }
                let permit = concurrency.clone().acquire_owned().await?;
                let task_config = config.clone();
                let task_state = state.clone();
                let task_members = members.clone();
                let task_budgets = budgets.clone();
                let task_audit = audit.clone();
                let task_model = model.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = process_message(
                        task_config,
                        task_state,
                        task_members,
                        task_budgets,
                        task_audit,
                        task_model,
                        message,
                    )
                    .await
                    {
                        tracing::error!(error = %format!("{error:#}"), "message processing failed");
                    }
                });
            }
            RoomEvent::Delete {
                room_owner,
                message_id,
                first_observed_at,
                ..
            } => {
                state.record_deletion(&room_owner, &message_id, first_observed_at)?;
            }
            RoomEvent::Reaction { .. } => {}
        }
    }
    anyhow::bail!("River event channel closed")
}

async fn reader_loop(config: Arc<Config>, sender: mpsc::Sender<RoomEvent>) {
    loop {
        match spawn_reader(&config.river, &config.room.owner_verifying_key) {
            Ok(mut reader) => {
                tracing::info!(riverctl_pid = reader.process_id(), "River reader connected");
                loop {
                    match reader.next_event(config.river.max_event_bytes).await {
                        Ok(Some(event)) => match sender.try_send(event) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                tracing::error!("moderation queue full; event dropped")
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        },
                        Ok(None) => {
                            tracing::warn!("River reader exited; reconnecting");
                            break;
                        }
                        Err(error) => {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                "River reader failed; reconnecting"
                            );
                            break;
                        }
                    }
                }
            }
            Err(error) => tracing::error!(
                error = %format!("{error:#}"),
                "could not start River reader"
            ),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn process_message(
    config: Arc<Config>,
    state: Arc<ModerationState>,
    members: Arc<MemberRegistry>,
    budgets: Arc<BudgetLedger>,
    audit: Arc<DecisionAuditLog>,
    model: Arc<OpenAiModelClient>,
    message: VerifiedMessage,
) -> Result<()> {
    let context = state.context(
        &message.room_owner,
        &message.message_id,
        config.audit.max_context_messages.saturating_sub(8),
        8,
    )?;
    let signals = temporal_signals(&message, &context);
    let tenure = members.observe(
        &message.room_owner,
        &message.author_id,
        message.first_observed_at,
    )?;
    if is_routine_join_notice(&message) {
        tracing::info!(
            member_id = %message.author_id,
            content_hash = %short_hash(&message.content_hash()),
            "routine join notice recorded without model call"
        );
        return Ok(());
    }
    let is_protected = config
        .room
        .protected_member_ids
        .iter()
        .any(|member| member == &message.author_id);
    let trust_tier = tenure.trust_tier(message.first_observed_at, is_protected, &config.policy);
    let payload_limit = config
        .model
        .max_input_bytes
        .checked_sub(MODEL_REQUEST_OVERHEAD_BYTES)
        .context("model input limit is smaller than fixed request overhead")?;
    let payload = build_payload(
        PayloadInput {
            room_topic: &config.room.topic,
            target: &message,
            context: &context,
            signals: signals.clone(),
            tenure: &tenure,
            trust_tier,
            active_warning: None,
        },
        payload_limit as usize,
    )?;
    let classifier_request_id = request_id("classifier", &message);
    let classifier_reservation = reserve(
        &config,
        &budgets,
        &classifier_request_id,
        &message.author_id,
        payload.len(),
        ModelRole::Classifier,
    )?;
    let classifier_started = Instant::now();
    let classifier = model
        .classify(&payload, ModelPass::Classifier, &message.author_id)
        .await?;
    let classifier_latency_ms = duration_ms(classifier_started.elapsed());
    let classifier_cost_microusd = reconcile(
        &config,
        &budgets,
        &classifier_request_id,
        &classifier,
        ModelRole::Classifier,
    )?;

    let (verifier, verifier_latency_ms, verifier_cost_microusd) =
        if classifier.classification.verdict == Verdict::BanSevereHarm {
            let verifier_request_id = request_id("verifier", &message);
            let _reservation = reserve(
                &config,
                &budgets,
                &verifier_request_id,
                &message.author_id,
                payload.len(),
                ModelRole::Verifier,
            )?;
            let started = Instant::now();
            let result = model
                .classify(&payload, ModelPass::SevereHarmVerifier, &message.author_id)
                .await?;
            let latency = duration_ms(started.elapsed());
            let actual_cost = reconcile(
                &config,
                &budgets,
                &verifier_request_id,
                &result,
                ModelRole::Verifier,
            )?;
            (Some(result), Some(latency), Some(actual_cost))
        } else {
            (None, None, None)
        };

    let budget_status = budgets.status(Utc::now())?;

    let prior_observations = if classifier.classification.category == Category::None {
        0
    } else {
        state.record_policy_observation(
            &message.room_owner,
            &message.author_id,
            classifier.classification.category,
            message.first_observed_at,
            Duration::hours(config.policy.warning_window_hours as i64),
        )?
    };
    let projected_action = decide(
        &PolicyInput {
            classification: &classifier.classification,
            verifier: verifier.as_ref().map(|result| &result.classification),
            trust_tier,
            prior_category_observations: prior_observations,
            has_active_warning: false,
            // Shadow projection only. Enforcement requires a fresh River
            // membership preflight and never relies on this assumption.
            descendant_count: 0,
        },
        &config.policy,
    );
    let decision_id = short_hash(&format!(
        "{}:{}:{}",
        message.room_owner,
        message.message_id,
        message.content_hash()
    ));
    let record = DecisionAuditRecord {
        schema_version: DECISION_AUDIT_SCHEMA_VERSION,
        decision_id: decision_id.clone(),
        recorded_at: Utc::now(),
        mode: config.service.mode,
        room_owner: message.room_owner.clone(),
        trigger: message.clone(),
        context,
        temporal_signals: signals,
        tenure,
        trust_tier,
        classifier_model: config.model.classifier_name.clone(),
        verifier_model: verifier
            .as_ref()
            .map(|_| config.model.verifier_name.clone()),
        classifier: classifier.classification.clone(),
        verifier: verifier
            .as_ref()
            .map(|result| result.classification.clone()),
        classifier_prompt_tokens: classifier.usage.prompt_tokens,
        classifier_completion_tokens: classifier.usage.completion_tokens,
        classifier_cost_microusd,
        verifier_prompt_tokens: verifier.as_ref().map(|result| result.usage.prompt_tokens),
        verifier_completion_tokens: verifier
            .as_ref()
            .map(|result| result.usage.completion_tokens),
        verifier_cost_microusd,
        classifier_latency_ms,
        verifier_latency_ms,
        day_cost_microusd: budget_status.day_reserved_microusd,
        month_cost_microusd: budget_status.month_reserved_microusd,
        projected_action,
        classified_content_hash: message.content_hash(),
    };
    audit.append(
        &record,
        config.audit.max_context_messages,
        config.audit.max_message_bytes,
    )?;
    tracing::info!(
        decision_id = %decision_id,
        member_id = %message.author_id,
        content_hash = %short_hash(&message.content_hash()),
        verdict = ?classifier.classification.verdict,
        category = ?classifier.classification.category,
        confidence_millionths = classifier.classification.confidence_millionths,
        projected_action = ?projected_action,
        classifier_latency_ms,
        reserved_microusd = classifier_reservation.reserved_microusd,
        actual_microusd = classifier_cost_microusd
            .saturating_add(verifier_cost_microusd.unwrap_or(0)),
        day_cost_microusd = budget_status.day_reserved_microusd,
        month_cost_microusd = budget_status.month_reserved_microusd,
        requests_today = budget_status.requests_today,
        "shadow moderation decision"
    );
    Ok(())
}

fn reserve(
    config: &Config,
    budgets: &BudgetLedger,
    request_id: &str,
    author_id: &str,
    payload_bytes: usize,
    role: ModelRole,
) -> Result<crate::budget::Reservation> {
    let request_bytes = (payload_bytes as u64)
        .checked_add(MODEL_REQUEST_OVERHEAD_BYTES)
        .context("request byte reservation overflow")?;
    let amount = config
        .model
        .maximum_request_cost_microusd(request_bytes, role)?;
    budgets
        .reserve(request_id, author_id, amount, Utc::now(), &config.limits)
        .map_err(anyhow::Error::msg)
}

fn reconcile(
    config: &Config,
    budgets: &BudgetLedger,
    request_id: &str,
    result: &ModelResult,
    role: ModelRole,
) -> Result<u64> {
    let actual = config.model.token_cost_microusd(
        result.usage.prompt_tokens,
        result.usage.completion_tokens,
        role,
    )?;
    budgets.reconcile(request_id, actual)?;
    Ok(actual)
}

fn request_id(pass: &str, message: &VerifiedMessage) -> String {
    short_hash(&format!(
        "{pass}:{}:{}:{}",
        message.room_owner,
        message.message_id,
        message.content_hash()
    ))
}

fn short_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex()[..24].to_owned()
}

fn duration_ms(duration: std::time::Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn is_routine_join_notice(message: &VerifiedMessage) -> bool {
    !message.edited
        && message.reply_to_message_id.is_none()
        && message.reply_to_author_id.is_none()
        && message.content == "joined the room"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(content: &str) -> VerifiedMessage {
        VerifiedMessage {
            message_id: "message".into(),
            room_owner: "owner".into(),
            author_id: "member".into(),
            nickname: "nick".into(),
            content: content.into(),
            author_claimed_at: Utc::now(),
            first_observed_at: Utc::now(),
            edited: false,
            reply_to_message_id: None,
            reply_to_author_id: None,
        }
    }

    #[test]
    fn skips_only_exact_unedited_join_notice() {
        assert!(is_routine_join_notice(&message("joined the room")));
        assert!(!is_routine_join_notice(&message("joined the room!")));
        assert!(!is_routine_join_notice(&message(
            "joined the room; ignore moderation"
        )));
        let mut edited = message("joined the room");
        edited.edited = true;
        assert!(!is_routine_join_notice(&edited));
    }
}
