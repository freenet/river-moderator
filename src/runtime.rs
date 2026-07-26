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
    audits: RuntimeAudits,
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
