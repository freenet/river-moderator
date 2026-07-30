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
    membership::{MemberRegistry, TrustTier},
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
    // The moderator's own automated replies must never become evidence against
    // the member they were sent to. On 2026-07-30 a nudge ("Let's keep this room
    // on topic") landed in the context window, and the classifier then justified
    // the next two verdicts with "Continues unrelated chess discussion AFTER
    // MODERATOR REDIRECTED ROOM" -- including for a message about C# that had
    // nothing to do with the original subject. One nudge poisoned every
    // subsequent message from that member, escalating nudge -> warn -> ban. Only
    // the 24h per-member cooldown stopped it becoming a ban.
    //
    // Service identities are the automated ones (`service_member_ids`), and
    // their messages are already refused as classification TRIGGERS a few lines
    // below. Feeding them back as CONTEXT is the same mistake in the other
    // direction: it lets the moderator manufacture the evidence for its own
    // escalation. Human moderators are deliberately NOT filtered -- a real
    // person asking the room to drop a subject is genuine context, and ignoring
    // a human redirect is exactly the repeat behaviour that should escalate.
    let context = strip_service_messages(context, &config.room.service_member_ids);
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
    // The room's norms are safe-for-work and on-topic, and both are broken
    // almost entirely by members who have not yet earned tenure. Screening their
    // ordinary messages is the only routing path that catches a first offence
    // that nobody reports and that trips no deterministic trigger. Established
    // members and deputies are deliberately exempt, which is what "more tolerant
    // with established users" means at the routing layer; they are still reached
    // by high-signal triggers and by an explicit `spam` report.
    let tier_screened = matches!(trust_tier, TrustTier::Probationary | TrustTier::Regular)
        && tier_screening_within_budget(&budgets, &config)?;
    if !is_routine_join_notice(&message)
        && !is_high_signal_message(&message, &signals)
        && !is_report
        && !tier_screened
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

    // READ the count here; the write happens further down and only for a
    // classification that survived confirmation. See `policy_observation_count`.
    let prior_observations = if classifier.classification.category == Category::None {
        0
    } else {
        state.policy_observation_count(
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
    // Enforce mode is a superset of warn mode, so it must still deliver the
    // public nudge or warning for an ordinary conduct verdict rather than only
    // for a severe-harm verdict that policy downgraded to a warning. Gating the
    // low-severity path on `verdict == BanSevereHarm` disabled every conduct
    // reply in production, because an SFW or on-topic breach classifies as
    // `NudgeConduct`/`WarnDisruptive` and so never satisfied that condition.
    // `schedule_warning_if_eligible` already ignores any action that is not a
    // nudge or a formal warning, so widening the mode test cannot introduce a
    // public action that policy did not ask for.
    //
    // A public reply must never rest on a single sample. The classifier is
    // stochastic, and on 2026-07-30 one unlucky sample called an on-topic chess
    // remark ("my queen shouldnt be here lol", amid talk of implementing
    // castling) a sexualized off-topic tangent at 97% confidence and nudged a
    // blameless member in public. Replaying the exact captured payload against
    // the exact same prompt returned `allow` three times out of three, so it was
    // sampling noise, not something a prompt edit could fix.
    //
    // Severe-harm bans already require an independent second pass before acting.
    // Low-severity actions are also public and also irreversible in the only way
    // that matters (everyone saw it), so they get the same treatment. The cost is
    // bounded: the second call happens only when a public action is actually
    // projected, which the global interval and per-member cooldown make rare.
    let projected_action = if matches!(
        projected_action,
        crate::policy::PolicyAction::NudgeAsModerator
            | crate::policy::PolicyAction::WarnAsModerator
    ) && matches!(config.service.mode, Mode::Warn | Mode::Enforce)
    {
        confirm_low_severity_action(
            &config,
            &budgets,
            &model,
            &message,
            &payload,
            projected_action,
            classifier.classification.category,
        )
        .await?
    } else {
        projected_action
    };
    // Only now, and only for a finding that survived confirmation and produced a
    // real outcome, does the observation get written. A recorded observation is
    // a deferred action -- it escalates the member's NEXT nudge into a formal
    // warning, and the one after that into a ban -- so a classification that the
    // system itself declined to act on must not leave a mark. `HumanReview` and
    // `None` deliberately record nothing: the first means the system was unsure,
    // the second that it decided against acting.
    if classifier.classification.category != Category::None
        && matches!(
            projected_action,
            crate::policy::PolicyAction::RecordDisruption
                | crate::policy::PolicyAction::NudgeAsModerator
                | crate::policy::PolicyAction::WarnAsModerator
                | crate::policy::PolicyAction::BanAsModerator
                | crate::policy::PolicyAction::BanAsOwnerPolicyEscalation
                | crate::policy::PolicyAction::BanAsOwnerEmergency
        )
    {
        state.record_policy_observation(
            POLICY_VERSION,
            &message.room_owner,
            &message.author_id,
            classifier.classification.category,
            message.first_observed_at,
            Duration::hours(config.policy.warning_window_hours as i64),
        )?;
    }
    if matches!(config.service.mode, Mode::Warn | Mode::Enforce) {
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

/// Remove the moderator's own automated messages from the classifier context.
///
/// Only the automated `service_member_ids` are removed. A human moderator asking
/// the room to drop a subject is genuine context, and ignoring a human redirect
/// is exactly the repeat behaviour that SHOULD escalate; the bug is the machine
/// citing its own output as proof the member is defying it.
fn strip_service_messages(
    context: Vec<VerifiedMessage>,
    service_member_ids: &[String],
) -> Vec<VerifiedMessage> {
    context
        .into_iter()
        .filter(|candidate| {
            !service_member_ids
                .iter()
                .any(|service| service == &candidate.author_id)
        })
        .collect()
}

/// Take an independent second sample before any public low-severity reply, and
/// drop the action unless that sample independently agrees the message is not
/// allowable.
///
/// This mirrors the severe-harm verifier. It exists because the first sample is
/// a draw from a distribution, not a measurement: a single 97%-confidence
/// `off_topic` finding against an on-topic chess remark reached the room on
/// 2026-07-30, and replaying that exact payload against that exact prompt
/// returned `allow` 3/3. Confidence does not express sampling stability, so no
/// threshold on it would have caught that; only a second draw does.
///
/// Deliberately asymmetric. Disagreement always cancels the action and never
/// creates or escalates one, so the worst case is a missed nudge rather than an
/// unearned public reprimand. Budget refusal cancels too, on the same principle.
async fn confirm_low_severity_action(
    config: &Config,
    budgets: &BudgetLedger,
    model: &OpenAiModelClient,
    message: &VerifiedMessage,
    payload: &[u8],
    projected_action: crate::policy::PolicyAction,
    category: Category,
) -> Result<crate::policy::PolicyAction> {
    let confirm_request_id = request_id("low-severity-confirm", message);
    if reserve(
        config,
        budgets,
        &confirm_request_id,
        &message.author_id,
        payload.len(),
        ModelRole::Classifier,
    )
    .is_err()
    {
        tracing::warn!(
            member_id = %message.author_id,
            ?projected_action,
            "public action cancelled: no budget for the confirming sample"
        );
        return Ok(crate::policy::PolicyAction::None);
    }
    let confirmation = model
        .classify(payload, ModelPass::Classifier, &message.author_id)
        .await?;
    let _ = reconcile(
        config,
        budgets,
        &confirm_request_id,
        &confirmation,
        ModelRole::Classifier,
    );
    let agrees = confirmation.classification.verdict != Verdict::Allow
        && confirmation.classification.category == category;
    if agrees {
        return Ok(projected_action);
    }
    tracing::warn!(
        member_id = %message.author_id,
        message_hash = %short_hash(&message.content_hash()),
        first_category = ?category,
        second_verdict = ?confirmation.classification.verdict,
        second_category = ?confirmation.classification.category,
        ?projected_action,
        "public action cancelled: independent second sample disagreed"
    );
    Ok(crate::policy::PolicyAction::None)
}

/// Tenure screening is the lowest-priority consumer of the model budget. It is
/// speculative, whereas an explicit report or a deterministic high-signal
/// trigger is evidence that something is already wrong. A busy day of newcomer
/// chatter must therefore never exhaust the budget a later report will need, so
/// screening stops short of the daily cap and the remaining headroom is reserved
/// for the evidence-backed routing paths.
const TIER_SCREENING_BUDGET_PERCENT: u64 = 70;

/// Both the daily and the monthly cap must be respected, because they bind on
/// very different timescales and only the monthly one can strand the service.
/// The daily cap refills every day, so exhausting it costs at most a few hours
/// of screening. The monthly cap does not: sustained screening at 70% of the
/// daily cap would exhaust a monthly cap set to a few days' worth of daily caps
/// in about a week, and once `reserve()` starts refusing on `MonthlySpend`
/// nothing is classified at all for the rest of the month, reports included.
/// Checking only the daily figure would therefore trade a fixed daily pause for
/// a multi-week outage.
fn tier_screening_within_budget(budgets: &BudgetLedger, config: &Config) -> Result<bool> {
    let status = budgets.status(Utc::now())?;
    let within =
        |spent: u64, cap: u64| spent < cap.saturating_mul(TIER_SCREENING_BUDGET_PERCENT) / 100;
    Ok(within(
        status.day_reserved_microusd,
        config.limits.daily_budget_microusd,
    ) && within(
        status.month_reserved_microusd,
        config.limits.monthly_budget_microusd,
    ))
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
        || contains_explicit_sexual_term(&message.content)
        || contains_phrase(&message.content, CONTACT_LURE_PHRASES)
}

/// Unsolicited-contact lures. Matched on word boundaries, not as raw
/// substrings: `"dm me"` appears inside `"DM me**chanism"`, which routed two
/// ordinary on-topic messages about River's DM feature to the classifier on
/// 2026-07-30. Both were correctly allowed, so the only cost was budget and
/// noise, but the same class of match is why the explicit-term list below is
/// token-based too.
const CONTACT_LURE_PHRASES: &[&str] = &["dm me", "message me", "cash app", "send crypto"];

/// Unambiguous explicit terms, matched whole-token.
const EXPLICIT_SEXUAL_TOKENS: &[&str] = &[
    "bdsm",
    "blowjob",
    "bukkake",
    "bukake",
    "buttplug",
    "cockring",
    "creampie",
    "cumshot",
    "cunt",
    "deepthroat",
    "dildo",
    "fleshlight",
    "gangbang",
    "handjob",
    "hentai",
    "horny",
    "milf",
    "nsfw",
    "nudes",
    "onlyfans",
    "porn",
    "porno",
    "pornhub",
    "sexting",
    "titties",
];

/// Explicit multi-word lures, matched as substrings because the individual
/// words are each innocuous.
const EXPLICIT_SEXUAL_PHRASES: &[&str] = &[
    "anal sex",
    "dick pic",
    "jack off",
    "jerk off",
    "oral sex",
    "sugar daddy",
    "talk dirty",
];

/// The room's norm is safe-for-work, so an unambiguous explicit term routes a
/// message to the classifier regardless of the author's tenure. This is a
/// positive routing signal only: it decides whether the model LOOKS at a
/// message, never what happens to it. The verdict, and the tenure-graduated
/// tolerance applied to that verdict, remain with the classifier and
/// `policy::decide`, so a term appearing in genuine technical or moderation
/// discussion is routed and then allowed rather than acted on.
///
/// Single words match whole-token rather than by substring, so ordinary words
/// that merely contain a shorter term are never routed on this signal. That is
/// the classic "Scunthorpe" failure and it is pinned by tests.
fn contains_explicit_sexual_term(content: &str) -> bool {
    if contains_phrase(content, EXPLICIT_SEXUAL_PHRASES) {
        return true;
    }
    content
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .any(|token| EXPLICIT_SEXUAL_TOKENS.contains(&token))
}

/// Match a multi-word phrase against whole tokens rather than raw bytes.
///
/// The content is reduced to its lowercase alphanumeric tokens joined by single
/// spaces, then compared space-delimited, so a phrase matches only when each of
/// its words is a complete token. Raw `contains` would match a phrase that
/// merely straddles a longer word, which is how `"dm me"` fired on
/// `"DM mechanism"` in production.
fn contains_phrase(content: &str, phrases: &[&str]) -> bool {
    let lower = content.to_lowercase();
    let normalized: String = lower
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let padded = format!(" {normalized} ");
    phrases
        .iter()
        .any(|phrase| padded.contains(&format!(" {phrase} ")))
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

    /// The message that went unmoderated on 2026-07-30. It trips no burst,
    /// duplicate, size, or compression trigger, so before the SFW term routing
    /// existed nothing would send it to the classifier at all.
    #[test]
    fn routes_the_unmoderated_sfw_breach() {
        assert!(contains_explicit_sexual_term(
            "how about a mandatory cockring"
        ));
        assert!(contains_explicit_sexual_term("point me to the nsfw room?"));
        let quiet = crate::event::TemporalSignals {
            author_messages_10_seconds: 1,
            author_messages_1_minute: 1,
            author_messages_5_minutes: 1,
            milliseconds_since_author_previous: None,
            exact_duplicate_count_5_minutes: 0,
            claimed_clock_skew_seconds: 0,
        };
        assert!(is_high_signal_message(
            &message("how about a mandatory cockring"),
            &quiet
        ));
        assert!(!is_high_signal_message(
            &message("how does River recover after a peer goes offline?"),
            &quiet
        ));
    }

    /// Whole-token matching, so an ordinary word that merely contains a shorter
    /// term is never routed on this signal. Substring matching would route all
    /// of these and quietly spend budget on innocuous technical chatter.
    #[test]
    fn explicit_term_routing_avoids_scunthorpe_false_positives() {
        for benign in [
            "the cockpit display needs a redesign",
            "assert that the analysis completed",
            "this class inherits from the base class",
            "a peacock is not a threat model",
            "Dick reviewed the pull request",
            "we should document the assumptions",
            "titanium alloys are not relevant here",
        ] {
            assert!(
                !contains_explicit_sexual_term(benign),
                "false positive on {benign:?}"
            );
        }
    }

    /// Real production misfire, 2026-07-30: this on-topic message about
    /// River's DM feature was sent to the classifier because `"dm me"` is a
    /// substring of `"DM me`chanism`"`. The model correctly allowed it, so the
    /// only cost was budget, but the routing was wrong.
    #[test]
    fn contact_lure_routing_does_not_fire_on_dm_mechanism() {
        let quiet = crate::event::TemporalSignals {
            author_messages_10_seconds: 1,
            author_messages_1_minute: 1,
            author_messages_5_minutes: 1,
            milliseconds_since_author_previous: None,
            exact_duplicate_count_5_minutes: 0,
            claimed_clock_skew_seconds: 0,
        };
        assert!(!is_high_signal_message(
            &message("now just invite people to your room via DM mechanism."),
            &quiet
        ));
        // The genuine lure it exists to catch must still route.
        assert!(is_high_signal_message(
            &message("Can Someone DM me so i can give info and test"),
            &quiet
        ));
        assert!(contains_phrase("please cash app me", CONTACT_LURE_PHRASES));
        assert!(!contains_phrase(
            "the cash appraisal is due",
            CONTACT_LURE_PHRASES
        ));
    }

    #[test]
    fn explicit_term_routing_matches_multiword_lures() {
        assert!(contains_explicit_sexual_term("wanna talk dirty to me"));
        assert!(contains_explicit_sexual_term("looking for a Sugar Daddy"));
        assert!(!contains_explicit_sexual_term(
            "my dad works on distributed systems"
        ));
    }

    /// Routing is not judgement. A term appearing in genuine moderation or
    /// technical discussion is still sent to the classifier, which is what
    /// allows it to be allowed rather than silently dropped before review.
    #[test]
    fn explicit_term_routing_is_a_signal_not_a_verdict() {
        assert!(contains_explicit_sexual_term(
            "should we add an nsfw filter to the room contract?"
        ));
    }

    /// 2026-07-30: a nudge the moderator itself had just sent sat in the context
    /// window, and the classifier justified the next two verdicts with
    /// "Continues unrelated chess discussion after moderator redirected room" --
    /// including for a message about C#. One nudge poisoned every later message
    /// from that member, escalating nudge -> warn -> ban.
    #[test]
    fn own_automated_replies_are_stripped_from_context() {
        let service = vec!["4CLPTJPM".to_string(), "NRKA4WVX".to_string()];
        let mut nudge = message("Let's keep this room on topic. Back to Freenet.");
        nudge.author_id = "4CLPTJPM".into();
        nudge.nickname = "River Marshal".into();
        let mut human_mod = message("folks, can we drop this thread please");
        human_mod.author_id = "7XSOGJTK".into();
        let member = message("a completely open source chess.com alternative");

        let kept = strip_service_messages(vec![nudge, human_mod.clone(), member.clone()], &service);

        let authors: Vec<_> = kept.iter().map(|m| m.author_id.as_str()).collect();
        assert!(
            !authors.contains(&"4CLPTJPM"),
            "the moderator's own reply must not be evidence against the member it targeted"
        );
        // A HUMAN moderator's redirect is genuine context and must survive, or
        // ignoring a real person's request stops being escalatable.
        assert_eq!(authors, vec!["7XSOGJTK", "member"]);
    }

    #[test]
    fn stripping_service_messages_is_a_no_op_without_service_ids() {
        let m = message("ordinary");
        assert_eq!(strip_service_messages(vec![m], &[]).len(), 1);
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
