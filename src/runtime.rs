use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use redb::Database;
use tokio::sync::{mpsc, Semaphore};

use crate::{
    audit::{
        AuditLog, AuditOutcome, BanAuditRecord, DecisionAuditLog, DecisionAuditRecord,
        MembershipEvidence, ModelEvidence, AUDIT_SCHEMA_VERSION, DECISION_AUDIT_SCHEMA_VERSION,
    },
    budget::BudgetLedger,
    classifier::{build_payload, PayloadInput, POLICY_VERSION},
    config::{Config, Mode, ModelProvider, ModelRole},
    event::{temporal_signals, VerifiedMessage},
    membership::MemberRegistry,
    model::{ModelPass, ModelResult},
    name_guard::{self, NameGuardAction},
    openai_model::OpenAiModelClient,
    policy::{decide, PolicyInput},
    river_action::{ban_member_safely, send_fixed_reply},
    river_stream::{spawn_reader, RoomEvent},
    state::{
        BanClaim, EventDisposition, LowSeverityAction, LowSeverityOutcome, ModerationState,
        PendingBan, PendingLowSeverity, WarningRecord,
    },
    verdict::{Category, Verdict},
    warnings::{fixed_nudge, fixed_warning},
};

const MODEL_REQUEST_OVERHEAD_BYTES: u64 = 6_000;
const HISTORY_MESSAGES: usize = 200;

#[derive(Clone)]
struct RuntimeAudits {
    decisions: Arc<DecisionAuditLog>,
    bans: Arc<AuditLog>,
}

pub async fn run_moderator(config: Config) -> Result<()> {
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
    let audits = RuntimeAudits {
        decisions: Arc::new(DecisionAuditLog::open(&config.audit.decision_path)?),
        bans: Arc::new(AuditLog::open(&config.audit.path)?),
    };
    let model = Arc::new(OpenAiModelClient::new(&config.model)?);
    let config = Arc::new(config);
    if matches!(config.service.mode, Mode::Warn | Mode::Enforce) {
        let action_config = config.clone();
        let action_state = state.clone();
        tokio::spawn(async move { warning_loop(action_config, action_state).await });
    }
    let (sender, mut receiver) = mpsc::channel(config.limits.queue_depth);
    let reader_config = config.clone();
    tokio::spawn(async move { reader_loop(reader_config, sender).await });
    let concurrency = Arc::new(Semaphore::new(config.limits.concurrency));

    tracing::info!(
        mode = ?config.service.mode,
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
                let task_audits = audits.clone();
                let task_model = model.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = process_message(
                        task_config,
                        task_state,
                        task_members,
                        task_budgets,
                        task_audits,
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

/// First reconnect delay. Short, because most reader exits are a single blip
/// and waiting out a long backoff is dead time for moderation.
const RECONNECT_BASE_DELAY_MILLIS: u64 = 1_000;

/// Ceiling on the reconnect delay. Capped low enough that a sustained outage
/// still leaves the room checked roughly twice a minute.
const RECONNECT_MAX_DELAY_MILLIS: u64 = 30_000;

/// A session lasting at least this long counts as healthy and resets the
/// backoff, so one bad patch does not slow recovery for the rest of the day.
const HEALTHY_SESSION_SECONDS: u64 = 30;

/// Spread reconnects by ±20% so a node that is refusing subscriptions does not
/// get retried on a metronome, and so restarts do not line up. Derived from the
/// clock rather than adding an RNG dependency for a single jitter value.
fn jittered_delay(delay_millis: u64) -> std::time::Duration {
    let spread = delay_millis / 5;
    if spread == 0 {
        return std::time::Duration::from_millis(delay_millis);
    }
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::from(since.subsec_nanos()))
        .unwrap_or(0);
    let offset = entropy % (2 * spread);
    std::time::Duration::from_millis(delay_millis.saturating_sub(spread).saturating_add(offset))
}

async fn reader_loop(config: Arc<Config>, sender: mpsc::Sender<RoomEvent>) {
    // The reader has been observed exiting ~55 times an hour with "Unexpected
    // response to SUBSCRIBE request", median session life 3s. A fixed 5s retry
    // hammers a node that is already refusing.
    //
    // Each reconnect also replays whatever the local room cache had not yet
    // seen. That is correct catch-up, not a bug, and it is how messages posted
    // during a blind window still get moderated: `--initial-messages 0`
    // suppresses history, and `subscribe_and_stream` seeds its seen-set from
    // local state first. But the whole catch-up batch shares one arrival
    // instant, which is what corrupted the burst signals behind the flooding
    // false positive; see `event::within_burst`. Fewer reconnects means fewer
    // such batches, so this backoff reduces the exposure even though the real
    // correction lives in the signal computation.
    let mut delay_millis = RECONNECT_BASE_DELAY_MILLIS;
    loop {
        match spawn_reader(&config.river, &config.room.owner_verifying_key) {
            Ok(mut reader) => {
                tracing::info!(riverctl_pid = reader.process_id(), "River reader connected");
                let connected_at = Instant::now();
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
                if connected_at.elapsed().as_secs() >= HEALTHY_SESSION_SECONDS {
                    delay_millis = RECONNECT_BASE_DELAY_MILLIS;
                }
            }
            Err(error) => tracing::error!(
                error = %format!("{error:#}"),
                "could not start River reader"
            ),
        }
        let wait = jittered_delay(delay_millis);
        tracing::debug!(
            delay_ms = wait.as_millis() as u64,
            "waiting before River reader reconnect"
        );
        tokio::time::sleep(wait).await;
        delay_millis = delay_millis
            .saturating_mul(2)
            .min(RECONNECT_MAX_DELAY_MILLIS);
    }
}

async fn process_message(
    config: Arc<Config>,
    state: Arc<ModerationState>,
    members: Arc<MemberRegistry>,
    budgets: Arc<BudgetLedger>,
    audits: RuntimeAudits,
    model: Arc<OpenAiModelClient>,
    incoming_message: VerifiedMessage,
) -> Result<()> {
    let incoming_context = state.context(
        &incoming_message.room_owner,
        &incoming_message.message_id,
        config.audit.max_context_messages.saturating_sub(8),
        8,
    )?;
    let is_report = is_spam_report(&incoming_message);
    let report_target = if is_report {
        let target_id = incoming_message
            .reply_to_message_id
            .as_deref()
            .expect("spam report requires a reply target");
        let Some(target) = incoming_context
            .iter()
            .find(|candidate| candidate.message_id == target_id)
            .cloned()
        else {
            tracing::warn!(
                reporter_id = %incoming_message.author_id,
                target_message_id = %target_id,
                "spam report target is outside retained context"
            );
            return Ok(());
        };
        tracing::info!(
            reporter_id = %incoming_message.author_id,
            target_member_id = %target.author_id,
            target_message_hash = %short_hash(&target.content_hash()),
            "spam report accepted for moderation review"
        );
        Some(target)
    } else {
        None
    };
    let message = report_target.unwrap_or_else(|| incoming_message.clone());
    let context = if is_report {
        state.context(
            &message.room_owner,
            &message.message_id,
            config.audit.max_context_messages.saturating_sub(8),
            8,
        )?
    } else {
        incoming_context.clone()
    };
    let signals = temporal_signals(&message, &context);
    let tenure = members.observe(
        &message.room_owner,
        &message.author_id,
        message.first_observed_at,
    )?;

    let is_protected = config
        .room
        .protected_member_ids
        .iter()
        .any(|member| member == &message.author_id);
    let is_service = config
        .room
        .service_member_ids
        .iter()
        .any(|member| member == &message.author_id);
    let trust_tier = tenure.trust_tier(message.first_observed_at, is_protected, &config.policy);

    if is_service {
        tracing::info!(member_id = %message.author_id, "service-authored message ignored");
        return Ok(());
    }
    if !is_routine_join_notice(&message)
        && !is_high_signal_message(&message, &signals)
        && !is_report
    {
        tracing::debug!(
            member_id = %message.author_id,
            content_hash = %short_hash(&message.content_hash()),
            "ordinary message recorded without model call"
        );
        return Ok(());
    }
    let join_name_candidate = if is_routine_join_notice(&message) {
        match name_guard::inspect(&message.nickname, &config.room.protected_nicknames) {
            NameGuardAction::Observe => {
                tracing::info!(
                    member_id = %message.author_id,
                    nickname = %message.nickname,
                    content_hash = %short_hash(&message.content_hash()),
                    "routine join notice recorded; nickname guard allowed"
                );
                false
            }
            NameGuardAction::Ban { reason } if is_protected => {
                tracing::warn!(
                    member_id = %message.author_id,
                    nickname = %message.nickname,
                    reason = %reason,
                    "nickname guard refused protected identity target"
                );
                false
            }
            NameGuardAction::Ban { reason } => {
                tracing::warn!(
                    member_id = %message.author_id,
                    nickname = %message.nickname,
                    reason = %reason,
                    "nickname guard triggered model verification before any action"
                );
                true
            }
        }
    } else {
        false
    };
    if is_routine_join_notice(&message) && !join_name_candidate {
        return Ok(());
    }
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
            moderator_member_ids: &config.room.protected_member_ids,
            join_name_candidate,
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
            POLICY_VERSION,
            &message.room_owner,
            &message.author_id,
            classifier.classification.category,
            message.first_observed_at,
            Duration::hours(config.policy.warning_window_hours as i64),
        )?
    };
    let active_warning = if classifier.classification.category == Category::None {
        None
    } else {
        state.active_warning(
            &message.room_owner,
            &message.author_id,
            classifier.classification.category,
            message.first_observed_at,
        )?
    };
    let projected_action = decide(
        &PolicyInput {
            classification: &classifier.classification,
            verifier: verifier.as_ref().map(|result| &result.classification),
            trust_tier,
            prior_category_observations: prior_observations,
            has_active_warning: active_warning.is_some(),
            // Policy projects against the conservative zero-descendant case.
            // Execution still performs a fresh River membership preflight and
            // refuses any target that actually has descendants.
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
    audits.decisions.append(
        &record,
        config.audit.max_context_messages,
        config.audit.max_message_bytes,
    )?;
    if is_report {
        let target_is_spam = matches!(
            classifier.classification.category,
            Category::Spam | Category::Scam | Category::Phishing | Category::Flooding
        );
        let negative_before = state.recent_negative_reports(
            &incoming_message.room_owner,
            &incoming_message.author_id,
            incoming_message.first_observed_at - Duration::seconds(60),
            incoming_message.first_observed_at,
        )?;
        state.record_report_outcome(&incoming_message, target_is_spam)?;
        let negative_reports = negative_before + usize::from(!target_is_spam);
        if negative_reports >= 5 {
            let reporter_tenure = members.observe(
                &incoming_message.room_owner,
                &incoming_message.author_id,
                incoming_message.first_observed_at,
            )?;
            let reporter_is_protected = config
                .room
                .protected_member_ids
                .iter()
                .any(|member| member == &incoming_message.author_id);
            let decision = report_abuse_decision(
                &config,
                &incoming_message,
                incoming_context.clone(),
                reporter_tenure,
                reporter_is_protected,
                negative_reports,
            );
            audits.decisions.append(
                &decision,
                config.audit.max_context_messages,
                config.audit.max_message_bytes,
            )?;
            tracing::error!(
                decision_id = %decision.decision_id,
                member_id = %incoming_message.author_id,
                negative_reports,
                "report flooding classified as severe abuse"
            );
            if config.service.mode == Mode::Enforce {
                enforce_severe_ban(&config, &state, &audits.bans, &decision).await?;
            }
        }
    }
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
        "moderation decision"
    );
    if config.service.mode == Mode::Warn
        || (config.service.mode == Mode::Enforce
            && classifier.classification.verdict == Verdict::BanSevereHarm
            && projected_action == crate::policy::PolicyAction::WarnAsModerator)
    {
        schedule_warning_if_eligible(
            &config,
            &state,
            &message,
            &decision_id,
            classifier.classification.category,
            projected_action,
        )?;
    }
    if config.service.mode == Mode::Enforce
        && classifier.classification.verdict == Verdict::BanSevereHarm
        && verifier.is_some()
        && projected_action == crate::policy::PolicyAction::BanAsModerator
    {
        enforce_severe_ban(&config, &state, &audits.bans, &record).await?;
    }
    Ok(())
}

async fn enforce_severe_ban(
    config: &Config,
    state: &ModerationState,
    audit: &AuditLog,
    decision: &DecisionAuditRecord,
) -> Result<()> {
    let member_id = &decision.trigger.author_id;
    if config
        .room
        .protected_member_ids
        .iter()
        .any(|protected| protected == member_id)
    {
        tracing::error!(
            decision_id = %decision.decision_id,
            member_id,
            "automatic ban refused for protected identity"
        );
        return Ok(());
    }

    if !state.message_is_current(
        &decision.room_owner,
        &decision.trigger.message_id,
        member_id,
        &decision.classified_content_hash,
    )? {
        let record = ban_record(decision, AuditOutcome::RefusedChangedOrDeletedMessage, None);
        audit.append_ban(
            &record,
            config.audit.max_context_messages,
            config.audit.max_message_bytes,
        )?;
        tracing::warn!(
            decision_id = %decision.decision_id,
            member_id,
            "automatic ban refused because trigger changed or was deleted"
        );
        return Ok(());
    }

    let pending = PendingBan {
        room_owner: decision.room_owner.clone(),
        member_id: member_id.clone(),
        decision_id: decision.decision_id.clone(),
        created_at: Utc::now(),
    };
    match state.claim_ban(
        &pending,
        Utc::now(),
        Duration::seconds(config.policy.ban_global_interval_seconds as i64),
        config.policy.bans_per_hour,
        config.policy.bans_per_day,
    )? {
        BanClaim::AlreadyPending => {
            tracing::warn!(
                decision_id = %decision.decision_id,
                member_id,
                "automatic ban suppressed because this member was already claimed"
            );
            return Ok(());
        }
        BanClaim::RateLimited => {
            let record = ban_record(decision, AuditOutcome::RateLimited, None);
            audit.append_ban(
                &record,
                config.audit.max_context_messages,
                config.audit.max_message_bytes,
            )?;
            tracing::error!(
                decision_id = %decision.decision_id,
                member_id,
                "automatic ban rate limited; human action required"
            );
            return Ok(());
        }
        BanClaim::Claimed => {}
    }

    // Sync the complete reason, trigger, context, member ID and model evidence
    // before the first external write. A crash or ambiguous timeout is never
    // retried automatically because the persistent claim already exists.
    let pending_record = ban_record(decision, AuditOutcome::Pending, None);
    audit.append_ban(
        &pending_record,
        config.audit.max_context_messages,
        config.audit.max_message_bytes,
    )?;

    match ban_member_safely(&config.river, &decision.room_owner, member_id).await {
        Ok(result) => {
            let record = ban_record(decision, AuditOutcome::Executed, Some(result));
            audit.append_ban(
                &record,
                config.audit.max_context_messages,
                config.audit.max_message_bytes,
            )?;
            tracing::error!(
                decision_id = %decision.decision_id,
                member_id,
                category = ?decision.classifier.category,
                "automatic severe-harm ban executed"
            );
        }
        Err(error) => {
            let error_text = format!("{error:#}");
            let record = ban_record(decision, AuditOutcome::Failed, Some(error_text.clone()));
            audit.append_ban(
                &record,
                config.audit.max_context_messages,
                config.audit.max_message_bytes,
            )?;
            tracing::error!(
                decision_id = %decision.decision_id,
                member_id,
                error = %error_text,
                "automatic ban failed or was refused and will not be retried"
            );
        }
    }
    Ok(())
}

fn ban_record(
    decision: &DecisionAuditRecord,
    outcome: AuditOutcome,
    river_result: Option<String>,
) -> BanAuditRecord {
    let verifier_cost = decision.verifier_cost_microusd.unwrap_or(0);
    BanAuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        decision_id: decision.decision_id.clone(),
        recorded_at: Utc::now(),
        room_owner: decision.room_owner.clone(),
        outcome,
        normalized_reason: format!(
            "{:?}: {}",
            decision.classifier.category, decision.classifier.reason
        ),
        trigger: decision.trigger.clone(),
        context: decision.context.clone(),
        temporal_signals: decision.temporal_signals.clone(),
        warning_history: Vec::new(),
        model: ModelEvidence {
            model: format!(
                "{} + {}",
                decision.classifier_model,
                decision
                    .verifier_model
                    .as_deref()
                    .unwrap_or("missing-verifier")
            ),
            prompt_version: POLICY_VERSION.into(),
            classifier_request_id: request_id("classifier", &decision.trigger),
            classifier: decision.classifier.clone(),
            verifier_request_id: decision
                .verifier
                .as_ref()
                .map(|_| request_id("verifier", &decision.trigger)),
            verifier: decision.verifier.clone(),
            reserved_microusd: decision
                .classifier_cost_microusd
                .saturating_add(verifier_cost),
            actual_microusd: Some(
                decision
                    .classifier_cost_microusd
                    .saturating_add(verifier_cost),
            ),
        },
        membership: MembershipEvidence {
            target_member_id: decision.trigger.author_id.clone(),
            target_verifying_key: None,
            target_nickname: decision.trigger.nickname.clone(),
            trust_tier: decision.trust_tier,
            first_observed_at: decision.tenure.first_observed_at,
            observation_count: decision.tenure.observation_count,
            active_days: decision.tenure.active_days,
            bootstrapped_as_existing: decision.tenure.bootstrapped_as_existing,
            invited_by_member_id: None,
            ancestor_member_ids: Vec::new(),
            // `riverctl --require-no-descendants` independently verifies this
            // from fresh state before signing. Its success/refusal is retained
            // verbatim in river_result.
            descendant_member_ids: Vec::new(),
        },
        classified_content_hash: decision.classified_content_hash.clone(),
        river_result,
    }
}

fn report_abuse_decision(
    config: &Config,
    message: &VerifiedMessage,
    context: Vec<VerifiedMessage>,
    tenure: crate::membership::MemberTenure,
    is_protected: bool,
    recent_reports: usize,
) -> DecisionAuditRecord {
    let trust_tier = tenure.trust_tier(message.first_observed_at, is_protected, &config.policy);
    let classification = crate::verdict::Classification {
        verdict: Verdict::BanSevereHarm,
        category: Category::Spam,
        confidence_millionths: 1_000_000,
        reason: format!("Report flooding: {recent_reports} negative reports in one minute."),
    };
    DecisionAuditRecord {
        schema_version: DECISION_AUDIT_SCHEMA_VERSION,
        decision_id: short_hash(&format!(
            "report-abuse:{}:{}",
            message.room_owner, message.author_id
        )),
        recorded_at: Utc::now(),
        mode: config.service.mode,
        room_owner: message.room_owner.clone(),
        trigger: message.clone(),
        context,
        temporal_signals: temporal_signals(message, &[]),
        tenure,
        trust_tier,
        classifier_model: "report-abuse-guard".into(),
        verifier_model: None,
        classifier: classification,
        verifier: None,
        classifier_prompt_tokens: 0,
        classifier_completion_tokens: 0,
        classifier_cost_microusd: 0,
        verifier_prompt_tokens: None,
        verifier_completion_tokens: None,
        verifier_cost_microusd: None,
        classifier_latency_ms: 0,
        verifier_latency_ms: None,
        day_cost_microusd: 0,
        month_cost_microusd: 0,
        projected_action: crate::policy::PolicyAction::BanAsModerator,
        classified_content_hash: message.content_hash(),
    }
}

fn schedule_warning_if_eligible(
    config: &Config,
    state: &ModerationState,
    message: &VerifiedMessage,
    decision_id: &str,
    category: Category,
    action: crate::policy::PolicyAction,
) -> Result<()> {
    if let Some(activation_at) = config.service.activation_at {
        if message.first_observed_at < activation_at {
            return Ok(());
        }
    }
    let action = match action {
        crate::policy::PolicyAction::NudgeAsModerator => LowSeverityAction::Nudge,
        crate::policy::PolicyAction::WarnAsModerator => LowSeverityAction::FormalWarning,
        _ => return Ok(()),
    };
    let pending = PendingLowSeverity {
        policy_version: POLICY_VERSION.to_owned(),
        decision_id: decision_id.to_owned(),
        room_owner: message.room_owner.clone(),
        target_message_id: message.message_id.clone(),
        target_member_id: message.author_id.clone(),
        classified_content_hash: message.content_hash(),
        action,
        category,
        created_at: message.first_observed_at,
        execute_after: if config.service.mode == Mode::Enforce {
            message.first_observed_at
        } else {
            message.first_observed_at
                + Duration::seconds(config.policy.low_severity_grace_seconds as i64)
        },
        cancelled_by_member_id: None,
        completed_at: None,
        outcome: None,
    };
    let scheduled = state.schedule_low_severity(&pending)?;
    tracing::info!(
        decision_id,
        member_id = %message.author_id,
        message_hash = %short_hash(&message.message_id),
        scheduled,
        execute_after = %pending.execute_after,
        "low-severity public action considered"
    );
    Ok(())
}

async fn warning_loop(config: Arc<Config>, state: Arc<ModerationState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let now = Utc::now();
        let claimed = state.claim_due_low_severity(
            now,
            POLICY_VERSION,
            Duration::seconds(config.policy.global_action_interval_seconds as i64),
            Duration::hours(config.policy.member_action_cooldown_hours as i64),
            Duration::seconds(config.policy.max_pending_action_age_seconds as i64),
        );
        let pending = match claimed {
            Ok(Some(pending)) => pending,
            Ok(None) => continue,
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "warning queue claim failed");
                continue;
            }
        };
        match state.message_is_current(
            &pending.room_owner,
            &pending.target_message_id,
            &pending.target_member_id,
            &pending.classified_content_hash,
        ) {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(
                    decision_id = %pending.decision_id,
                    message_id = %pending.target_message_id,
                    "suppressed warning because the classified message changed or was deleted"
                );
                if let Err(error) = state.complete_low_severity(
                    &pending,
                    LowSeverityOutcome::SuppressedChangedOrDeleted,
                    Utc::now(),
                ) {
                    tracing::error!(error = %format!("{error:#}"), "failed to record suppressed warning");
                }
                continue;
            }
            Err(error) => {
                tracing::error!(
                    error = %format!("{error:#}"),
                    decision_id = %pending.decision_id,
                    "failed warning message-state preflight; refusing to send"
                );
                if let Err(error) =
                    state.complete_low_severity(&pending, LowSeverityOutcome::Failed, Utc::now())
                {
                    tracing::error!(error = %format!("{error:#}"), "failed to record warning preflight failure");
                }
                continue;
            }
        }
        let text = match pending.action {
            LowSeverityAction::Nudge => fixed_nudge(pending.category),
            LowSeverityAction::FormalWarning => fixed_warning(pending.category),
        };
        match send_fixed_reply(
            &config.river,
            &pending.room_owner,
            &pending.target_message_id,
            text,
        )
        .await
        {
            Ok(()) => {
                if pending.action == LowSeverityAction::FormalWarning {
                    let warning = WarningRecord {
                        room_owner: pending.room_owner.clone(),
                        member_id: pending.target_member_id.clone(),
                        category: pending.category,
                        warning_group: crate::state::warning_group(pending.category).into(),
                        warned_at: Utc::now(),
                        expires_at: Utc::now()
                            + Duration::hours(config.policy.warning_window_hours as i64),
                        triggering_message_id: pending.target_message_id.clone(),
                    };
                    if let Err(error) = state.record_warning(&warning) {
                        tracing::error!(error = %format!("{error:#}"), "sent warning but failed to record warning state");
                    }
                }
                if let Err(error) =
                    state.complete_low_severity(&pending, LowSeverityOutcome::Sent, Utc::now())
                {
                    tracing::error!(error = %format!("{error:#}"), "sent warning but failed to finalize action record");
                }
                tracing::warn!(
                    decision_id = %pending.decision_id,
                    member_id = %pending.target_member_id,
                    message_hash = %short_hash(&pending.target_message_id),
                    action = ?pending.action,
                    category = ?pending.category,
                    "public moderation reply sent"
                );
            }
            Err(error) => {
                let _ =
                    state.complete_low_severity(&pending, LowSeverityOutcome::Failed, Utc::now());
                tracing::error!(
                    decision_id = %pending.decision_id,
                    member_id = %pending.target_member_id,
                    error = %format!("{error:#}"),
                    "public moderation reply failed and was not retried"
                );
            }
        }
    }
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

fn is_spam_report(message: &VerifiedMessage) -> bool {
    message.reply_to_message_id.is_some()
        && message.reply_to_author_id.is_some()
        && message.content.trim().eq_ignore_ascii_case("spam")
}

fn is_high_signal_message(
    message: &VerifiedMessage,
    signals: &crate::event::TemporalSignals,
) -> bool {
    signals.author_messages_10_seconds >= 10
        || signals.exact_duplicate_count_5_minutes >= 2
        || (message.content.len() >= 1024
            && message
                .content
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .count()
                < message.content.chars().count() / 4)
        || compression_ratio_is_suspicious(&message.content)
        || name_guard::contains_severe_slur(&message.content)
        || {
            let lower = message.content.to_ascii_lowercase();
            ["dm me", "message me", "cash app", "send crypto"]
                .iter()
                .any(|needle| lower.contains(needle))
        }
}

/// Detect pathological repetition cheaply. This is a positive routing signal:
/// a normal ratio never suppresses any other moderation path.
fn compression_ratio_is_suspicious(content: &str) -> bool {
    const MIN_BYTES: usize = 512;
    const MAX_RATIO: f64 = 0.50;
    if content.len() < MIN_BYTES {
        return false;
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    if encoder.write_all(content.as_bytes()).is_err() {
        return false;
    }
    let Ok(compressed) = encoder.finish() else {
        return false;
    };
    (compressed.len() as f64 / content.len() as f64) < MAX_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signals for a lone message from an otherwise idle author, so these
    /// tests exercise the content clause and nothing else.
    fn quiet_signals() -> crate::event::TemporalSignals {
        crate::event::TemporalSignals {
            author_messages_10_seconds: 1,
            author_messages_1_minute: 1,
            author_messages_5_minutes: 1,
            milliseconds_since_author_previous: None,
            exact_duplicate_count_5_minutes: 0,
            claimed_clock_skew_seconds: 0,
        }
    }

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

    /// The router was blind to what a message said. On 2026-07-26 a member
    /// posted "redditfag" and then "tranny faggots love to censor..."; neither
    /// drew any review, and the account was examined only four minutes later
    /// when another member reported it by hand. Both lines are verbatim.
    ///
    /// Measured against every distinct message the room saw that day (1,630 of
    /// them), this clause fires on 6 and none of the 6 is a false positive.
    #[test]
    fn routes_messages_containing_severe_slurs_for_review() {
        let quiet = quiet_signals();
        for content in [
            "redditfag",
            "yes because tranny faggots love to censor boo boo words that hurts their delusions",
            "Calling all glowniggers, come in",
            "eu chat control is a nigger",
        ] {
            assert!(
                is_high_signal_message(&message(content), &quiet),
                "{content:?} should route for review"
            );
        }
    }

    /// Ordinary conversation must not buy a model call. These are real messages
    /// from the same room and day, including ones from the account that was
    /// eventually banned, taken from before it began using slurs.
    #[test]
    fn does_not_route_ordinary_conversation() {
        let quiet = quiet_signals();
        for content in [
            "sounds like a skill issue",
            "this is simply logic",
            "no matter what your opinion on the topic is, i can overpower you in many forms",
            "I am currently using `riverctl`, and also River webUI on other VM.",
            "wtf is your username???",
        ] {
            assert!(
                !is_high_signal_message(&message(content), &quiet),
                "{content:?} should not route for review"
            );
        }
    }

    #[test]
    fn reconnect_backoff_grows_and_is_capped() {
        let mut delay = RECONNECT_BASE_DELAY_MILLIS;
        let mut seen = vec![delay];
        for _ in 0..12 {
            delay = delay.saturating_mul(2).min(RECONNECT_MAX_DELAY_MILLIS);
            seen.push(delay);
        }
        assert_eq!(seen[0], 1_000, "first retry stays fast for a single blip");
        assert!(seen.windows(2).all(|w| w[1] >= w[0]), "must be monotonic");
        assert_eq!(
            *seen.last().unwrap(),
            RECONNECT_MAX_DELAY_MILLIS,
            "a sustained outage must still recheck about twice a minute"
        );
    }

    /// Jitter must actually spread the delay, or a node refusing subscriptions
    /// gets retried on a metronome by every restarted instance at once.
    #[test]
    fn reconnect_jitter_stays_within_twenty_percent() {
        for base in [1_000u64, 4_000, RECONNECT_MAX_DELAY_MILLIS] {
            for _ in 0..64 {
                let actual = jittered_delay(base).as_millis() as u64;
                let spread = base / 5;
                assert!(
                    actual >= base - spread && actual <= base + spread,
                    "{actual} outside +/-20% of {base}"
                );
            }
        }
    }

    #[test]
    fn jitter_handles_a_delay_too_small_to_spread() {
        assert_eq!(jittered_delay(0).as_millis(), 0);
        assert_eq!(jittered_delay(4).as_millis(), 4);
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

    #[test]
    fn accepts_only_exact_spam_replies_as_reports() {
        let mut report = message(" spam ");
        report.reply_to_message_id = Some("target".into());
        report.reply_to_author_id = Some("author".into());
        assert!(is_spam_report(&report));
        report.content = "spam please".into();
        assert!(!is_spam_report(&report));
        report.content = "spam".into();
        report.reply_to_author_id = None;
        assert!(!is_spam_report(&report));
    }

    #[test]
    fn compression_signal_catches_long_repetition_but_not_short_text() {
        assert!(!compression_ratio_is_suspicious(&"x".repeat(511)));
        assert!(compression_ratio_is_suspicious(&"repeat me ".repeat(100)));
    }
}
