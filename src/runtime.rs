use std::{sync::Arc, time::Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
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
    river_action::{
        ban_member_safely, delete_own_message, reaction_is_present, send_fixed_reply,
        send_room_message,
    },
    river_stream::{spawn_reader, RoomEvent},
    state::{
        BanClaim, EventDisposition, LowSeverityAction, LowSeverityOutcome, ModerationState,
        PendingBan, PendingLowSeverity, PendingTimestampEnforcement, SelfDeleteReason, StallGuard,
        WarningRecord,
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
        let timestamp_config = config.clone();
        let timestamp_state = state.clone();
        tokio::spawn(
            async move { timestamp_enforcement_loop(timestamp_config, timestamp_state).await },
        );
    }
    let (sender, mut receiver) = mpsc::channel(config.limits.queue_depth);
    let reader_config = config.clone();
    tokio::spawn(async move { reader_loop(reader_config, sender).await });
    let concurrency = Arc::new(Semaphore::new(config.limits.concurrency));
    let stall_guard = StallGuard::new();

    tracing::info!(
        mode = ?config.service.mode,
        classifier = %config.model.classifier_name,
        verifier = %config.model.verifier_name,
        queue_depth = config.limits.queue_depth,
        concurrency = config.limits.concurrency,
        "moderator started"
    );

    while let Some(event) = receiver.recv().await {
        // Recorded for EVERY event, not just messages -- a delete or reaction
        // is just as valid a liveness signal, and the stall this guards
        // against silences all of them equally.
        stall_guard.record_event();
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
                let task_stall_guard = stall_guard.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = process_message(
                        task_config,
                        task_state,
                        task_members,
                        task_budgets,
                        task_audits,
                        task_model,
                        task_stall_guard,
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
                // Retract the notice the INSTANT its target is gone, rather
                // than waiting for the deadline sweep. The sweep only evaluates
                // at `enforce_after`, so a member who complied at second 10 was
                // left staring at a live "delete this or be removed" notice for
                // the remaining ~110 seconds -- and once their message went, it
                // rendered as "Original message unavailable", which reads as an
                // unexplained accusation.
                //
                // Taking the record removes it, so the sweep cannot also act on
                // this offence and ban someone who already complied.
                if let Some(pending) = state.take_timestamp_enforcement(&room_owner, &message_id)? {
                    if let Some(warning_id) = pending.warning_message_id.as_deref() {
                        let retract_config = config.clone();
                        let owner = room_owner.clone();
                        let warning = warning_id.to_owned();
                        let member = pending.member_id.clone();
                        tokio::spawn(async move {
                            match delete_own_message(&retract_config.river, &owner, &warning).await
                            {
                                Ok(()) => tracing::info!(
                                    member_id = %member,
                                    "target deleted by its author; notice retracted immediately"
                                ),
                                Err(error) => tracing::error!(
                                    error = %format!("{error:#}"),
                                    "could not retract the notice after compliance"
                                ),
                            }
                        });
                    }
                }
            }
            RoomEvent::Reaction {
                room_owner,
                message_id,
                reactors,
            } => {
                if room_owner != config.room.owner_verifying_key {
                    tracing::error!("discarded reaction for unexpected room");
                    continue;
                }
                // The event carries the message's FULL current reactions map,
                // not a delta, so every reaction on that message is re-checked
                // on each change. That is deliberately self-healing: an
                // offending reaction is caught even if its own event was
                // missed, and the per-member reservation stops re-warning.
                //
                // Validation is pure string inspection. A text model could not
                // judge codepoints better than arithmetic, and reactions are
                // far too frequent to spend a model call on.
                for (emoji, members) in &reactors {
                    if crate::emoji::reaction_problem(emoji).is_none() {
                        continue;
                    }
                    for member_id in members {
                        // Never act on a protected identity, and never on the
                        // moderator itself.
                        if config
                            .room
                            .protected_member_ids
                            .iter()
                            .any(|id| id == member_id)
                        {
                            continue;
                        }
                        if let Err(error) = begin_reaction_enforcement(
                            &config,
                            &state,
                            &room_owner,
                            &message_id,
                            emoji,
                            member_id,
                        )
                        .await
                        {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                member_id,
                                "failed to start reaction enforcement"
                            );
                        }
                    }
                }
            }
        }
    }
    anyhow::bail!("River event channel closed")
}

/// If no event arrives for this long, the subscription is presumed dead and
/// the reader forces a reconnect rather than waiting indefinitely.
///
/// 2026-07-31: the underlying node hit real transport congestion (cwnd/ACK
/// stalls, "peer not found", WebSocket resets -- all node-side, confirmed in
/// its own logs) and the riverctl subscription went silent for ~40 minutes,
/// TWICE, with no error on either end: the subprocess never exited, so the
/// existing `Ok(None)`/`Err` reconnect paths never fired. `next_event` has no
/// timeout of its own, so the reader just waited.
///
/// This does not fix the underlying network congestion -- that's an external
/// condition, not a bug here. It bounds how long a stall can silently persist
/// before the reader takes matters into its own hands. 3 minutes is well
/// above ordinary quiet-room gaps observed today (activity resumes within
/// seconds to low minutes even during lulls), so it should not trigger a
/// reconnect during a merely-quiet period, while cutting a real stall from
/// ~40 minutes down to a few.
const READER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

async fn reader_loop(config: Arc<Config>, sender: mpsc::Sender<RoomEvent>) {
    loop {
        match spawn_reader(&config.river, &config.room.owner_verifying_key) {
            Ok(mut reader) => {
                tracing::info!(riverctl_pid = reader.process_id(), "River reader connected");
                loop {
                    match tokio::time::timeout(
                        READER_IDLE_TIMEOUT,
                        reader.next_event(config.river.max_event_bytes),
                    )
                    .await
                    {
                        Ok(Ok(Some(event))) => match sender.try_send(event) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                tracing::error!("moderation queue full; event dropped")
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        },
                        Ok(Ok(None)) => {
                            tracing::warn!("River reader exited; reconnecting");
                            break;
                        }
                        Ok(Err(error)) => {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                "River reader failed; reconnecting"
                            );
                            break;
                        }
                        Err(_elapsed) => {
                            tracing::error!(
                                idle_seconds = READER_IDLE_TIMEOUT.as_secs(),
                                "no events received within the idle timeout; forcing reconnect \
                                 (possible silent subscription stall)"
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

// One more Arc than clippy's default threshold, added for the stall guard.
// Bundling it into an existing struct would mix an unrelated concern (event
// timing) into either `RuntimeAudits` (decision/ban logs) or a new type not
// worth introducing for one field.
#[allow(clippy::too_many_arguments)]
async fn process_message(
    config: Arc<Config>,
    state: Arc<ModerationState>,
    members: Arc<MemberRegistry>,
    budgets: Arc<BudgetLedger>,
    audits: RuntimeAudits,
    model: Arc<OpenAiModelClient>,
    stall_guard: Arc<StallGuard>,
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

    // A message dated far enough ahead pins itself to the bottom of the room:
    // River orders AND prunes by the sender-supplied time, so it outlives every
    // legitimate message instead of scrolling away. Detection is deterministic
    // and needs no model call -- the skew is arithmetic on two timestamps we
    // already hold, and the classifier is explicitly told not to trust
    // `author_claimed_at` for anything.
    //
    // Processing then CONTINUES rather than returning early. A future-dated
    // message can also be abusive on its content, and short-circuiting here
    // would downgrade an immediate severe-harm ban into a two-minute grace
    // period. Whichever path acts first wins; if the content ban lands, the
    // member's messages are swept and the pending enforcement finds its target
    // already gone.
    let self_delete_reason = if is_protected {
        None
    } else if signals.claimed_clock_skew_seconds > config.policy.future_timestamp_seconds {
        Some(SelfDeleteReason::FutureTimestamp)
    } else if contains_embedded_image(&message.content) {
        Some(SelfDeleteReason::EmbeddedImage)
    } else if contains_leaked_invitation(&message.content) {
        Some(SelfDeleteReason::LeakedInvitation)
    } else {
        None
    };
    if let Some(reason) = self_delete_reason {
        if let Err(error) =
            begin_self_delete_enforcement(&config, &state, &message, &signals, reason).await
        {
            tracing::error!(
                error = %format!("{error:#}"),
                member_id = %message.author_id,
                ?reason,
                "failed to start self-delete enforcement"
            );
        }
        // An embedded image ends processing here: detection is pure string
        // matching, and the classifier is a TEXT model that cannot see the image
        // at all, so a model call could only judge the caption. Spending budget
        // to do that on a message already scheduled for removal is waste.
        //
        // A future-dated message deliberately continues to classification. Its
        // text IS visible to the model, and short-circuiting would downgrade an
        // immediate severe-harm ban into a grace period.
        // Same reasoning as the image case: a leaked invitation is detected by
        // exact string match, and there is nothing for a text classifier to add
        // by reading the surrounding sentence -- the link itself is the entire
        // problem regardless of what the poster says about it.
        if matches!(
            reason,
            SelfDeleteReason::EmbeddedImage | SelfDeleteReason::LeakedInvitation
        ) {
            return Ok(());
        }
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
            service_member_ids: &config.room.service_member_ids,
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
    let mut projected_action = decide(
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
    // `Category::Flooding` is fed by `author_messages_10_seconds`, which counts
    // by OBSERVATION time, not send time. A reader stall followed by a
    // catch-up burst compresses unrelated messages' observed timestamps
    // together, spiking that count for reasons that have nothing to do with
    // how the messages were actually typed. Two members were falsely flagged
    // this way on 2026-07-31, and one received a public warning that had to
    // be manually retracted -- the independent-confirmation pass does not
    // save this case, because both samples see the same corrupted count and
    // tend to agree rather than disagree. Suppress here instead, before any
    // action (including the confirmation call) is taken.
    if classifier.classification.category == Category::Flooding
        && stall_guard.is_suppressing_flooding()
    {
        tracing::warn!(
            member_id = %message.author_id,
            "flooding action suppressed: recent reader stall makes the observed timing unreliable"
        );
        projected_action = crate::policy::PolicyAction::None;
    }
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

/// Detect a markdown image embed.
///
/// River renders message text as GFM markdown with raw HTML escaped
/// (`allow_dangerous_html = false`), so `<img>` cannot be injected directly and
/// the only route to a rendered image is markdown syntax: `![alt](url)` inline,
/// or `![alt][ref]` reference style. `url` may be a `data:` URI, so matching on
/// the syntax rather than on any host list is what actually covers the vector.
///
/// Deliberately slightly broad. A false positive costs the author a one-minute
/// deletion window, not an instant ban, whereas a miss puts arbitrary imagery in
/// front of the whole room.
fn contains_embedded_image(content: &str) -> bool {
    let bytes = content.as_bytes();
    let mut index = 0;
    while let Some(offset) = content[index..].find("![") {
        let start = index + offset + 2;
        if let Some(close) = content[start..].find(']') {
            let after = start + close + 1;
            if matches!(bytes.get(after), Some(b'(') | Some(b'[')) {
                return true;
            }
            index = after;
        } else {
            break;
        }
    }
    false
}

/// Detect a leaked River invitation link.
///
/// River invitation links (`freenet:<owner-key>/?invitation=<code>`) embed a
/// real, usable member keypair, generated one-time and meant for exactly one
/// person -- see the Invite Member modal's own notice: "Each invitation
/// creates a unique identity and is good for exactly one person." Posting one
/// publicly hands that identity to anyone reading the room. Each claimant CAN
/// use it -- it keeps working for all of them -- but they all share the one
/// identity, appear as the same member, and a ban on that identity removes
/// everyone who claimed it (2026-08-01: exactly this happened -- "it worked
/// for Proud Hound so... try this").
///
/// Matched on the literal query parameter rather than a full URL parser: the
/// parameter is the entire signal (an ordinary message could not otherwise
/// contain it by coincidence), and the invitation CODE itself is exactly the
/// secret that must never be logged or echoed back, so this deliberately does
/// not parse or capture it.
fn contains_leaked_invitation(content: &str) -> bool {
    content.contains("?invitation=")
}

/// Warn the author of a message that must be self-deleted, and queue the
/// deadline.
///
/// Only the author can delete a message, so asking is the only remedy available
/// short of removing the account.
async fn begin_self_delete_enforcement(
    config: &Config,
    state: &ModerationState,
    message: &VerifiedMessage,
    signals: &crate::event::TemporalSignals,
    reason: SelfDeleteReason,
) -> Result<()> {
    // `ban_grace_seconds` is `Some` only for the one reason that gets a
    // stern second warning before enforcement (see `timestamp_enforcement_loop`).
    // Every other reason keeps today's single-deadline behavior: `enforce_after`
    // IS the ban deadline and `ban_after` stays `None`.
    let (grace_seconds, ban_grace_seconds, warning_text) = match reason {
        SelfDeleteReason::FutureTimestamp => (
            config.policy.future_timestamp_grace_seconds,
            Some(config.policy.future_timestamp_ban_grace_seconds),
            crate::warnings::FUTURE_TIMESTAMP_WARNING,
        ),
        SelfDeleteReason::EmbeddedImage => (
            config.policy.embedded_image_grace_seconds,
            None,
            crate::warnings::EMBEDDED_IMAGE_WARNING,
        ),
        SelfDeleteReason::LeakedInvitation => (
            config.policy.leaked_invitation_grace_seconds,
            None,
            crate::warnings::LEAKED_INVITATION_WARNING,
        ),
        // Reactions take `begin_reaction_enforcement`: the notice is a
        // top-level mention rather than a reply, because a reaction has no
        // message of its own. Reaching here means a caller routed the wrong
        // way; refuse rather than post a reply naming the wrong person.
        SelfDeleteReason::BadReaction => {
            anyhow::bail!("reaction offences must use begin_reaction_enforcement")
        }
    };
    let warned_at = Utc::now();
    let pending = PendingTimestampEnforcement {
        reason,
        room_owner: message.room_owner.clone(),
        member_id: message.author_id.clone(),
        target_message_id: message.message_id.clone(),
        target_content_hash: message.content_hash(),
        warning_message_id: None,
        claimed_skew_seconds: signals.claimed_clock_skew_seconds,
        reaction_emoji: None,
        warned_at,
        enforce_after: warned_at + Duration::seconds(grace_seconds as i64),
        escalated: false,
        ban_after: ban_grace_seconds.map(|secs| warned_at + Duration::seconds(secs as i64)),
    };
    // Reserve BEFORE sending, so a redelivery cannot warn the same message
    // twice, and so a crash between send and store cannot re-warn on restart.
    if !state.schedule_timestamp_enforcement(&pending)? {
        return Ok(());
    }
    if config.service.mode != Mode::Enforce {
        tracing::info!(
            member_id = %message.author_id,
            ?reason,
            "self-delete offence observed; no action outside enforce mode"
        );
        return Ok(());
    }
    let warning_message_id = send_fixed_reply(
        &config.river,
        &message.room_owner,
        &message.message_id,
        warning_text,
    )
    .await?;
    // Re-store with the warning's own ID so it can be retracted later. An older
    // riverctl returns None, in which case the warning simply stays put.
    let stored = PendingTimestampEnforcement {
        warning_message_id,
        ..pending
    };
    state.clear_timestamp_enforcement(&stored.room_owner, &stored.target_message_id)?;
    state.schedule_timestamp_enforcement(&stored)?;
    tracing::warn!(
        member_id = %stored.member_id,
        reason = ?stored.reason,
        skew_seconds = stored.claimed_skew_seconds,
        enforce_after = %stored.enforce_after,
        retractable = stored.warning_message_id.is_some(),
        "warned a message that must be self-deleted; deadline started"
    );
    Ok(())
}

/// Warn the members who set a non-emoji reaction, and queue the deadline.
///
/// The notice is a TOP-LEVEL message that `@`-mentions the offender, not a
/// reply. A reaction has no message of its own, and replying to the reacted-to
/// message would render the notice under an innocent party's post -- the same
/// wrong-person attribution that makes the reaction event's `author` field a
/// trap (it names the message author, never the reactor).
async fn begin_reaction_enforcement(
    config: &Config,
    state: &ModerationState,
    room_owner: &str,
    message_id: &str,
    emoji: &str,
    member_id: &str,
) -> Result<()> {
    let pending = PendingTimestampEnforcement {
        reason: SelfDeleteReason::BadReaction,
        room_owner: room_owner.to_owned(),
        member_id: member_id.to_owned(),
        target_message_id: message_id.to_owned(),
        target_content_hash: String::new(),
        warning_message_id: None,
        claimed_skew_seconds: 0,
        reaction_emoji: Some(emoji.to_owned()),
        warned_at: Utc::now(),
        enforce_after: Utc::now()
            + Duration::seconds(config.policy.bad_reaction_grace_seconds as i64),
        escalated: false,
        ban_after: None,
    };
    // Reserve before posting, so a redelivered event cannot warn twice. The
    // stream re-sends the FULL reactions map on every change to a message, so
    // the same offending reaction is seen again on each subsequent reaction.
    if !state.schedule_timestamp_enforcement(&pending)? {
        return Ok(());
    }
    if config.service.mode != Mode::Enforce {
        tracing::info!(
            member_id,
            "non-emoji reaction observed; no action outside enforce mode"
        );
        return Ok(());
    }
    // `@[name](rv:id)` binds the mention to the member ID. A bare `@nickname`
    // resolves by NAME, and nicknames are not unique in River, so an ambiguous
    // one degrades to plain text and the person is never notified.
    let notice = format!(
        "@[{member_id}](rv:{member_id}){}",
        crate::warnings::BAD_REACTION_NOTICE
    );
    let warning_message_id = send_room_message(&config.river, room_owner, &notice).await?;
    let stored = PendingTimestampEnforcement {
        warning_message_id,
        ..pending
    };
    state.clear_timestamp_enforcement(&stored.room_owner, &stored.target_message_id)?;
    state.schedule_timestamp_enforcement(&stored)?;
    tracing::warn!(
        member_id = %stored.member_id,
        enforce_after = %stored.enforce_after,
        retractable = stored.warning_message_id.is_some(),
        "warned a non-emoji reaction; deadline started"
    );
    Ok(())
}

/// Never let a stale `ban_after` collapse the escalation window to nothing.
/// `ban_after` is an ABSOLUTE deadline computed once at `warned_at`; if the
/// sweep loop resumes after it has already elapsed (a stalled service, a
/// deploy, a slow earlier call in the same loop), a bare `ban_after` would
/// arm a ban for the very next sweep tick -- the member reads "you have 2
/// minutes" and is banned five seconds later. Re-anchoring to at least
/// `min_notice` seconds from `now` (evaluated just before the send is
/// attempted, so the member's real window is `min_notice` minus however long
/// that `riverctl` call takes -- typically small, bounded by its own
/// timeout) guarantees close to the full window regardless of how stale the
/// precomputed deadline had become. A pure function so the stale-sweep case
/// (`ban_after` already in the past) has a direct numeric test, not just a
/// source-pin checking the expression is present.
fn reanchor_ban_deadline(
    ban_after: DateTime<Utc>,
    now: DateTime<Utc>,
    min_notice: Duration,
) -> DateTime<Utc> {
    ban_after.max(now + min_notice)
}

/// Resolve future-dated (and other self-delete) offences once their next
/// deadline passes.
///
/// A reason with an escalation stage (`ban_after: Some`, currently only
/// `FutureTimestamp`) gets two notices: deleted before `enforce_after` ->
/// retract; still present -> a sterner second warning, then re-armed for
/// `ban_after`. Every other reason keeps the original single deadline:
/// deleted in time -> retract the moderator's own warning, since a public
/// notice pointing at nothing is just litter; still present -> remove the
/// account, because nothing else can clear the message.
async fn timestamp_enforcement_loop(config: Arc<Config>, state: Arc<ModerationState>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let due = match state.due_timestamp_enforcements(Utc::now()) {
            Ok(due) => due,
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "timestamp enforcement scan failed");
                continue;
            }
        };
        for pending in due {
            // Neither escalation nor the ban call further down may run
            // outside enforce mode -- mirrors the check
            // `begin_self_delete_enforcement` already applies to the FIRST
            // warning's send. Checked FIRST, before the presence preflight
            // below, and CLEARS the record rather than just skipping: both
            // `begin_self_delete_enforcement` and `begin_reaction_enforcement`
            // reserve regardless of mode, so shadow/warn mode does persist
            // records here. A `continue` without clearing would leave this
            // exact record "due" again on every subsequent 5-second tick
            // forever -- unbounded growth in `PENDING_TIMESTAMP`, a wasted
            // `riverctl` presence-check subprocess every tick per stuck
            // record, and (via the per-member dedup in
            // `schedule_timestamp_enforcement`) that member permanently
            // blocked from ever being flagged again. Shadow mode is
            // `config.example.toml`'s shipped default, so this is not an
            // edge case.
            if config.service.mode != Mode::Enforce {
                tracing::info!(
                    member_id = %pending.member_id,
                    escalated = pending.escalated,
                    "timestamp enforcement due; no action outside enforce mode"
                );
                let _ = state
                    .clear_timestamp_enforcement(&pending.room_owner, &pending.target_message_id);
                continue;
            }

            // A reaction is identified by (message, emoji, member) rather than
            // by an ID of its own, so its presence is read fresh from the room.
            // Message offences are answered from local state as before.
            let presence = match (&pending.reason, pending.reaction_emoji.as_deref()) {
                (SelfDeleteReason::BadReaction, Some(emoji)) => reaction_is_present(
                    &config.river,
                    &pending.room_owner,
                    &pending.target_message_id,
                    emoji,
                    &pending.member_id,
                )
                .await
                .map_err(|error| anyhow::anyhow!("{error:#}")),
                _ => state.message_is_current(
                    &pending.room_owner,
                    &pending.target_message_id,
                    &pending.member_id,
                    &pending.target_content_hash,
                ),
            };
            let still_present = match presence {
                Ok(present) => present,
                Err(error) => {
                    tracing::error!(
                        error = %format!("{error:#}"),
                        "timestamp enforcement preflight failed; refusing to act"
                    );
                    let _ = state.clear_timestamp_enforcement(
                        &pending.room_owner,
                        &pending.target_message_id,
                    );
                    continue;
                }
            };

            if !still_present {
                // They complied (or edited it away). Retract our own notice.
                if let Some(warning_id) = pending.warning_message_id.as_deref() {
                    if let Err(error) =
                        delete_own_message(&config.river, &pending.room_owner, warning_id).await
                    {
                        tracing::error!(
                            error = %format!("{error:#}"),
                            "could not retract the timestamp warning"
                        );
                    }
                }
                tracing::info!(
                    member_id = %pending.member_id,
                    "future-dated message deleted by its author; warning retracted"
                );
                let _ = state
                    .clear_timestamp_enforcement(&pending.room_owner, &pending.target_message_id);
                continue;
            }

            // Not yet escalated, and this reason has an escalation stage: send
            // the sterner second warning and re-arm for the ban deadline,
            // rather than banning on the first missed notice. A reason with no
            // escalation stage (`ban_after: None`) always has `escalated ==
            // false` and falls straight through to the ban below, unchanged.
            if !pending.escalated {
                if let Some(ban_after) = pending.ban_after {
                    // Reserve the escalated stage BEFORE sending, mirroring
                    // `begin_self_delete_enforcement`'s "reserve before
                    // sending" rule (see its comment). Without this, a crash
                    // or error between the send below and persisting here
                    // would leave `escalated: false` with an `enforce_after`
                    // already in the past -- every 5-second sweep after that
                    // would re-enter this branch and re-send the stern
                    // warning, forever.
                    //
                    // Deliberately NOT clearing `warning_message_id` here
                    // (via `..pending.clone()` it carries the FIRST warning's
                    // ID through unchanged): if `send_fixed_reply` below then
                    // fails, this reservation is what's left standing --
                    // `escalated: true` is not retried (matching this same
                    // function's crash-before-send tradeoff elsewhere), so
                    // the member proceeds toward a ban having received only
                    // the first warning. If the first warning's ID were
                    // nulled here regardless of send outcome, that failure
                    // would ALSO leave nothing retractable at ban time --
                    // orphaning the one warning that was actually sent. The
                    // ID is only replaced with the stern warning's real ID
                    // once send_fixed_reply has actually confirmed one below.
                    // `ban_after` is an ABSOLUTE deadline computed once at
                    // `warned_at`. If the sweep itself was stalled past it --
                    // a service restart or deploy, a slow riverctl call
                    // earlier in this same loop, the node hanging -- it can
                    // already be in the past by the time we get here, which
                    // would arm a ban for the very next 5-second tick: the
                    // member reads "you have 2 minutes" and is banned before
                    // they could act on it. Re-anchoring to at least
                    // `ban_grace - grace` seconds from NOW (the moment the
                    // stern warning is actually sent, below) guarantees the
                    // full second window regardless of how stale the
                    // precomputed deadlines had become. This assumes the only
                    // reason with an escalation stage is `FutureTimestamp`;
                    // revisit if a second one is ever added.
                    let min_notice = Duration::seconds(
                        config
                            .policy
                            .future_timestamp_ban_grace_seconds
                            .saturating_sub(config.policy.future_timestamp_grace_seconds)
                            as i64,
                    );
                    let reserved = PendingTimestampEnforcement {
                        escalated: true,
                        enforce_after: reanchor_ban_deadline(ban_after, Utc::now(), min_notice),
                        ..pending.clone()
                    };
                    match state.advance_timestamp_enforcement(&reserved) {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::info!(
                                member_id = %pending.member_id,
                                "offence resolved concurrently before escalating; nothing sent"
                            );
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                member_id = %pending.member_id,
                                "could not reserve the escalation stage; will retry next sweep"
                            );
                            continue;
                        }
                    }
                    let stern_warning_id = match send_fixed_reply(
                        &config.river,
                        &pending.room_owner,
                        &pending.target_message_id,
                        crate::warnings::FUTURE_TIMESTAMP_STERN_WARNING,
                    )
                    .await
                    {
                        Ok(id) => id,
                        Err(error) => {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                member_id = %pending.member_id,
                                "reserved the escalation stage but could not send the stern \
                                 warning; ban deadline stays armed with no stern warning sent"
                            );
                            continue;
                        }
                    };
                    // Best-effort: retract the first notice now that the
                    // sterner one is posted. Only when the stern warning
                    // actually got a trackable ID back: an older riverctl
                    // returns `None`, and trading the first notice (still
                    // retractable in the DB, per the reserve above) for an
                    // untrackable second one would leave NOTHING retractable
                    // -- keep the one notice we can still clean up later.
                    if stern_warning_id.is_some() {
                        if let Some(old_warning_id) = pending.warning_message_id.as_deref() {
                            if let Err(error) = delete_own_message(
                                &config.river,
                                &pending.room_owner,
                                old_warning_id,
                            )
                            .await
                            {
                                tracing::error!(
                                    error = %format!("{error:#}"),
                                    "could not retract the first warning after escalating"
                                );
                            }
                        }
                    }
                    // `.or(reserved.warning_message_id)`: when the stern
                    // warning got no trackable ID back, the guard above just
                    // left the FIRST notice deliberately un-retracted and
                    // still in the room -- persisting `None` here regardless
                    // would still orphan it, discarding the one ID that
                    // stays valid (`reserved.warning_message_id`, unchanged
                    // from `pending.warning_message_id`) for exactly the
                    // record this branch just chose to keep.
                    let with_new_warning = PendingTimestampEnforcement {
                        warning_message_id: stern_warning_id
                            .clone()
                            .or(reserved.warning_message_id.clone()),
                        ..reserved
                    };
                    match state.advance_timestamp_enforcement(&with_new_warning) {
                        Ok(true) => tracing::warn!(
                            member_id = %with_new_warning.member_id,
                            reason = ?with_new_warning.reason,
                            skew_seconds = with_new_warning.claimed_skew_seconds,
                            // The actual persisted deadline, not the
                            // pre-re-anchor `ban_after` -- the sweep interval
                            // plus send time means these routinely differ,
                            // and in the stale-sweep case `ban_after` is the
                            // exact value the re-anchor exists to override.
                            ban_after = %with_new_warning.enforce_after,
                            "sent stern second warning; ban deadline armed"
                        ),
                        Ok(false) => {
                            // The author complied while we were sending. The
                            // delete-event handler only knew the FIRST
                            // warning's ID when it took the record, so it
                            // could not have retracted the stern one -- we
                            // must, or it sits in the room forever replying
                            // to a now-deleted message.
                            tracing::info!(
                                member_id = %with_new_warning.member_id,
                                "offence resolved concurrently while sending the stern warning; \
                                 retracting it"
                            );
                            if let Some(warning_id) = stern_warning_id.as_deref() {
                                if let Err(error) = delete_own_message(
                                    &config.river,
                                    &pending.room_owner,
                                    warning_id,
                                )
                                .await
                                {
                                    tracing::error!(
                                        error = %format!("{error:#}"),
                                        "could not retract the stern warning after concurrent compliance"
                                    );
                                }
                            }
                        }
                        Err(error) => tracing::error!(
                            error = %format!("{error:#}"),
                            member_id = %with_new_warning.member_id,
                            "could not persist the stern warning's ID to the ban stage"
                        ),
                    }
                    continue;
                }
            }

            match ban_member_safely(
                &config.river,
                &config.room.owner_verifying_key,
                &pending.member_id,
            )
            .await
            {
                // No decision-audit record: this path is deterministic and makes
                // no model call, so there is no `DecisionAuditRecord` to attach.
                // The ERROR line below is the durable record in journald.
                Ok(evidence) => {
                    tracing::error!(
                        member_id = %pending.member_id,
                        reason = ?pending.reason,
                        skew_seconds = pending.claimed_skew_seconds,
                        evidence = %evidence,
                        "banned: message not deleted before the deadline"
                    );
                    // Retract the warning on THIS path too. The ban sweeps the
                    // member's messages, so a surviving warning replies to
                    // something that no longer exists and renders as "Original
                    // message unavailable" -- which reads to everyone else as a
                    // ban with no warning, the exact opposite of what happened.
                    if let Some(warning_id) = pending.warning_message_id.as_deref() {
                        if let Err(error) =
                            delete_own_message(&config.river, &pending.room_owner, warning_id).await
                        {
                            tracing::error!(
                                error = %format!("{error:#}"),
                                "could not retract the warning after banning"
                            );
                        }
                    }
                }
                Err(error) => tracing::error!(
                    error = %format!("{error:#}"),
                    member_id = %pending.member_id,
                    "timestamp enforcement ban failed and was not retried"
                ),
            }
            let _ =
                state.clear_timestamp_enforcement(&pending.room_owner, &pending.target_message_id);
        }
    }
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
            // The reply ID is unused on this path for now: retracting a
            // nudge when its target is deleted needs the ID persisted on
            // `PendingLowSeverity`, which the timestamp path below does.
            Ok(_reply_message_id) => {
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

    /// `reader_loop` is a subprocess-driven I/O loop, not cleanly unit-testable
    /// without mocking process I/O, so this pins the WIRING by source scrape
    /// instead: the idle-timeout path must exist, wrap the actual read, and
    /// force a reconnect exactly like the existing exited/errored paths do.
    /// Cut at `mod tests` so the needles cannot match their own literals here
    /// -- the trap that made the sibling `message reply` pin vacuous.
    #[test]
    fn reader_loop_forces_reconnect_on_idle_timeout() {
        let source = include_str!("runtime.rs");
        let production = source
            .split_once("mod tests")
            .map(|(before, _)| before)
            .expect("test module marker missing; the cut would scan everything");
        let squashed: String = production.chars().filter(|c| !c.is_whitespace()).collect();

        assert!(
            squashed.contains("tokio::time::timeout(READER_IDLE_TIMEOUT,reader.next_event("),
            "next_event must be wrapped in the idle timeout; the pin would pass vacuously otherwise"
        );
        assert!(
            squashed.contains("forcingreconnect"),
            "an elapsed idle timeout must log and force a reconnect, not retry silently"
        );
        // A `break` inside that arm is what actually drops the old `RiverReader`
        // (killing the stale subprocess via `kill_on_drop`) and falls through
        // to the existing 5-second-sleep-then-`spawn_reader` reconnect path --
        // the same recovery mechanism the exited/errored branches already use.
        assert!(
            squashed.contains(r#"idle_seconds=READER_IDLE_TIMEOUT.as_secs(),"#),
            "the elapsed branch must report the timeout that fired"
        );
    }

    /// Shared setup for the `future_timestamp_escalation_*` pin tests below:
    /// the production source (everything before `mod tests`, so a test's own
    /// assertion strings can never self-match) with all whitespace stripped.
    /// Split across several tests -- see the doc comment that used to sit on
    /// one giant `future_timestamp_escalation_control_flow_is_wired_correctly`
    /// -- so a failure names the specific invariant that broke instead of an
    /// undifferentiated wall of asserts, and later changes to one aspect (say,
    /// the retraction guard) don't force touching an unrelated assertion block
    /// (say, the reason mapping).
    ///
    /// The escalate-vs-ban decision in `timestamp_enforcement_loop`, and which
    /// reasons even have an escalation stage, are exercised in `state.rs`'s
    /// tests only through already-correct `PendingTimestampEnforcement`
    /// values -- nothing there proves the loop wires them up right, and there
    /// is no fake-riverctl harness to drive the real async loop end to end.
    /// Pinned here the same way `reader_loop_forces_reconnect_on_idle_timeout`
    /// pins its otherwise-untestable control flow.
    fn squashed_production_source() -> String {
        let source = include_str!("runtime.rs");
        let production = source
            .split_once("mod tests")
            .map(|(before, _)| before)
            .expect("test module marker missing; the cut would scan everything");
        production.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn future_timestamp_reason_mapping_gives_only_it_an_escalation_stage() {
        let squashed = squashed_production_source();

        // Only FutureTimestamp gets a ban deadline distinct from its warning
        // deadline -- every other self-delete reason must keep `None`, or it
        // would silently gain an (unwarned) escalation stage of its own.
        assert!(
            squashed.contains(
                "SelfDeleteReason::FutureTimestamp=>(config.policy.future_timestamp_grace_seconds,\
                 Some(config.policy.future_timestamp_ban_grace_seconds)"
            ),
            "FutureTimestamp must be the reason with an escalation stage"
        );
        assert!(
            squashed.contains(
                "SelfDeleteReason::EmbeddedImage=>(config.policy.embedded_image_grace_seconds,None,"
            ),
            "EmbeddedImage must not gain an escalation stage"
        );
        assert!(
            squashed.contains(
                "SelfDeleteReason::LeakedInvitation=>(config.policy.leaked_invitation_grace_seconds,None,"
            ),
            "LeakedInvitation must not gain an escalation stage"
        );
    }

    #[test]
    fn escalation_gate_and_enforce_mode_gate_cover_both_reserve_and_ban() {
        let squashed = squashed_production_source();

        // The sweep loop must gate the stern-warning branch on BOTH "not
        // already escalated" and "this reason has a ban_after" -- dropping
        // either check would re-send the stern warning forever, or treat a
        // no-escalation reason as if it had one.
        assert!(
            squashed.contains("if!pending.escalated{ifletSome(ban_after)=pending.ban_after{"),
            "escalation must be gated on both !escalated and ban_after being Some"
        );

        // Neither escalation nor the ban call below may run outside enforce
        // mode -- without this gate, shadow/warn mode would post the stern
        // warning for real and (pre-existing bug this closes too) execute
        // real bans. Must appear before BOTH the reservation and the ban
        // call, AND before the presence preflight (a wasted riverctl
        // subprocess call per stuck record every 5s otherwise). Pinned as one
        // contiguous block -- condition, AND that it actually clears the
        // record and continues, not just skips -- because a `continue`
        // without clearing leaves the record due again on every subsequent
        // tick forever (unbounded PENDING_TIMESTAMP growth, permanently
        // blocking that member's dedup slot). `config.service.mode !=
        // Mode::Enforce` is also checked in TWO unrelated functions earlier
        // in this file (the first-warning and first-reaction-notice sends)
        // -- search from this function's own signature so this finds the
        // sweep loop's gate, not one of those.
        let loop_body_start = squashed
            .find("asyncfntimestamp_enforcement_loop(")
            .expect("timestamp_enforcement_loop's signature must exist");
        assert!(
            squashed[loop_body_start..].contains(
                "ifconfig.service.mode!=Mode::Enforce{\
                 tracing::info!(member_id=%pending.member_id,escalated=pending.escalated,\
                 \"timestampenforcementdue;noactionoutsideenforcemode\");\
                 let_=state.clear_timestamp_enforcement(&pending.room_owner,\
                 &pending.target_message_id);continue;}"
            ),
            "the enforce-mode gate must clear the record and continue, not just skip -- \
             otherwise a due record in shadow/warn mode is re-swept every 5 seconds forever"
        );
        let mode_gate = squashed[loop_body_start..]
            .find("ifconfig.service.mode!=Mode::Enforce{")
            .map(|offset| offset + loop_body_start)
            .expect("the sweep loop must gate escalation and ban on enforce mode");
        let reserve_call = squashed
            .find("matchstate.advance_timestamp_enforcement(&reserved){")
            .expect("the reservation must be persisted via the race-safe advance method");
        let send_call = squashed
            .find("=matchsend_fixed_reply(")
            .expect("the stern warning must be sent via send_fixed_reply");
        // `ban_member_safely` is also called from the UNRELATED severe-harm
        // ban path earlier in this file -- search from `send_call` onward so
        // this finds the sweep loop's own ban call, not that one.
        let ban_call = squashed[send_call..]
            .find("matchban_member_safely(")
            .map(|offset| offset + send_call)
            .expect("the sweep loop's own ban call must exist after the escalation branch");
        assert!(
            mode_gate < reserve_call,
            "the enforce-mode gate must run before the reservation, not after"
        );
        assert!(
            mode_gate < ban_call,
            "the enforce-mode gate must also cover the ban call below, not just escalation"
        );
    }

    #[test]
    fn escalation_reserves_before_sending_and_reanchors_the_ban_deadline() {
        let squashed = squashed_production_source();

        // The escalated stage must be RESERVED (escalated: true, enforce_after
        // re-anchored via `reanchor_ban_deadline`, unit-tested separately
        // below) before anything is sent -- a crash or send error after this
        // point must never leave `escalated: false` with an already-past
        // `enforce_after`, or every subsequent sweep would re-enter this
        // branch and re-send the stern warning forever. Deliberately does
        // NOT override `warning_message_id` -- `..pending.clone()` must carry
        // the FIRST warning's ID through unchanged, so a send failure after
        // this point leaves it retractable rather than orphaned.
        assert!(
            squashed.contains(
                "letreserved=PendingTimestampEnforcement{\
                 escalated:true,\
                 enforce_after:reanchor_ban_deadline(ban_after,Utc::now(),min_notice),\
                 ..pending.clone()};"
            ),
            "the reservation must flip escalated and re-anchor enforce_after via \
             reanchor_ban_deadline, not blindly trust the stale ban_after"
        );
        assert!(
            !squashed.contains("letreserved=PendingTimestampEnforcement{warning_message_id:None,"),
            "the reservation must NOT null warning_message_id -- doing so before send_fixed_reply \
             confirms a replacement leaves the first warning permanently unretractable if the \
             send then fails"
        );
        assert!(
            squashed.contains(
                "future_timestamp_ban_grace_seconds.saturating_sub(config.policy.future_timestamp_grace_seconds)"
            ),
            "min_notice must be derived from the configured escalate/ban gap, not hardcoded"
        );
        let reserve_call = squashed
            .find("matchstate.advance_timestamp_enforcement(&reserved){")
            .expect("the reservation must be persisted via the race-safe advance method");
        let send_call = squashed
            .find("=matchsend_fixed_reply(")
            .expect("the stern warning must be sent via send_fixed_reply");
        assert!(
            reserve_call < send_call,
            "the reservation must be persisted BEFORE the stern warning is sent, not after \
             -- reserve-then-send is what makes a crash mid-send fail safe instead of \
             re-sending on every later sweep"
        );
    }

    #[test]
    fn escalation_retraction_and_persistence_are_correct() {
        let squashed = squashed_production_source();

        // The (retractable) first notice must only be discarded when the
        // stern warning actually got a trackable ID back -- an older riverctl
        // returns `None`, and trading a retractable notice for an untrackable
        // one would leave nothing retractable at all.
        assert!(
            squashed.contains("ifstern_warning_id.is_some(){ifletSome(old_warning_id)"),
            "retracting the first notice must be gated on the stern warning having a real ID"
        );

        // Persisting the final record (with the stern warning's real ID) must
        // also go through the race-safe advance method, distinct from the
        // reservation above. When the stern warning got no trackable ID back
        // (`stern_warning_id: None`, older riverctl), the guard above left
        // the FIRST notice deliberately un-retracted and still in the room --
        // `.or(reserved.warning_message_id.clone())` is what keeps that ID
        // (not `None`) persisted so it stays retractable later, rather than
        // discarding the one ID the branch just chose to keep.
        assert!(
            squashed.contains(
                "letwith_new_warning=PendingTimestampEnforcement{\
                 warning_message_id:stern_warning_id\
                 .clone().or(reserved.warning_message_id.clone()),..reserved};"
            ),
            "the stern warning's ID must be persisted onto the reserved record, falling back to \
             the first warning's ID when the stern warning got no trackable ID back"
        );
        assert!(
            squashed.contains("state.advance_timestamp_enforcement(&with_new_warning)"),
            "the final record must be persisted via the race-safe advance method"
        );

        // If the author complies WHILE the stern warning is being sent, the
        // delete-event handler only knows the FIRST warning's ID (it took the
        // record before the stern warning existed), so it cannot retract the
        // stern one -- this branch must do it itself, or it sits in the room
        // forever replying to a now-deleted message.
        assert!(
            squashed.contains(
                "delete_own_message(&config.river,&pending.room_owner,warning_id,).await"
            ),
            "concurrent compliance during the send must retract the just-sent stern warning, \
             not just leave the database resurrection-safe"
        );

        // A dropped `continue` here would fall straight through into the ban
        // call in the SAME sweep iteration the stern warning was just sent --
        // banning on the first missed notice exactly as before this feature.
        assert!(
            squashed.contains("continue;}}matchban_member_safely("),
            "the escalation branch must continue, never fall through to an immediate ban"
        );
    }

    /// Direct numeric coverage for `reanchor_ban_deadline`, the arithmetic
    /// the fix above only pins as a source string. This is what actually
    /// exercises the stale-sweep case: without it, nothing in the suite ever
    /// evaluates the expression with `ban_after` in the past.
    #[test]
    fn reanchor_keeps_a_ban_after_that_is_comfortably_in_the_future() {
        let now = Utc::now();
        let min_notice = Duration::seconds(120);
        let ban_after = now + Duration::seconds(200);
        assert_eq!(reanchor_ban_deadline(ban_after, now, min_notice), ban_after);
    }

    #[test]
    fn reanchor_pulls_a_stale_ban_after_up_to_the_minimum_notice_window() {
        let now = Utc::now();
        let min_notice = Duration::seconds(120);
        // The stale-sweep case: the sweep resumed after ban_after had already
        // elapsed. Without the fix this stays `ban_after` (in the past), and
        // the record is immediately due for a ban on the very next tick.
        let ban_after = now - Duration::seconds(500);
        assert_eq!(
            reanchor_ban_deadline(ban_after, now, min_notice),
            now + min_notice,
            "a stale ban_after must be pulled forward to exactly now + min_notice"
        );
    }

    #[test]
    fn reanchor_is_exact_at_the_boundary() {
        let now = Utc::now();
        let min_notice = Duration::seconds(120);
        let ban_after = now + min_notice;
        assert_eq!(reanchor_ban_deadline(ban_after, now, min_notice), ban_after);
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

    /// River renders GFM markdown, so `![](...)` becomes a live `<img>`. Match
    /// the syntax, not a host list: the URL may be a `data:` URI.
    #[test]
    fn embedded_images_are_detected_by_markdown_syntax() {
        for embed in [
            "![](https://example.com/a.png)",
            "look ![cat](https://example.com/cat.gif) cute",
            "![x](data:image/png;base64,iVBORw0KGgo=)",
            "![alt][ref]",
        ] {
            assert!(contains_embedded_image(embed), "missed embed: {embed:?}");
        }
    }

    /// A false positive costs a one-minute deletion window, so the matcher is
    /// allowed to be broad -- but not so broad it fires on ordinary prose,
    /// links, or code.
    #[test]
    fn ordinary_text_is_not_an_embedded_image() {
        for benign in [
            "wow! [this link](https://example.com) is good",
            "the array is a![0] in that language",
            "no images here at all",
            "shout! [bracketed aside] then more",
            "vec![1, 2, 3] is a Rust macro",
        ] {
            assert!(
                !contains_embedded_image(benign),
                "false positive on {benign:?}"
            );
        }
    }

    /// The real message that prompted this: an owner-VK-prefixed invitation
    /// link, base58 code, posted openly to invite others to a game-dev room.
    #[test]
    fn detects_the_real_leaked_invitation() {
        let real = "ok. it worked for Proud Hound so... try this if you want to enter room for game devel: freenet:raAqMhMG/?invitation=ThxZ8m6e6SVNEAME9qv1Af6Hqh3VRE7EGexis8SoEQEB8zk4ezfocLt2pH3fBouf5B8mjTQNxeq3AKjrtF233j3DutXzd6EBtx7Ub9rwDwpRDLAXjkTKuXDDf6faUK935K9nz4oSqkCG6L6sMT4QKEcuyZwM8ibWCnVaaCtqHANU2oqHLzE3HK693fE4Ww3SLoiZLvG6zHufG6tzP6RHgyh31mXRkGBnj4q6gxyVKzs86yj2FTYTCywXFbY7uhjsV3EnMcnVvRGHjjHk34bwREMA2cJ34cHQWMunbotRM17axrvyoDhDMWvMqd6KgGFBgKj1a5uZRvbAvazF7xpDt5weCgY7cLDAGTm7dxtJXoiucQ8VheJaboMKkY2tF2RrwyicDtRARRhhpeJXoL52JvyQqf9gsWXPxfeRv7dKcZTf4vJHmEa9WVfnhGP4jQPbfSh2nSEtDJj3zMYjzp2NybmnomRc7qc9qhPWM7rTJ58gGnjzXKg2xdAfkfe3UxtMjZpEDx3hgdibbriyMhUCPr8BMbdfYudQzoTH1rJzHc2eoimsR5ET93WokuRvzNGaD5915jqXkW5NJEVneHHQpGbZ9tsGg2xgXuzFXDdXDNgJP36KeGhkGWt2HLVM4FnJffMPD8jkavwweSD8wAGPCcKpyxzBZSLiQwbFer5kogTdp7VTg5KdHKSXHBudazxcejoKxjWvaLAePHywuhCB5FHkR7NUWrYfTtSJAiN";
        assert!(contains_leaked_invitation(real));
    }

    #[test]
    fn detects_leaked_invitation_link_variants() {
        for leaked in [
            "freenet:raAqMhMG/?invitation=abc123",
            "join here: freenet:SomeOwnerKey/?invitation=xyz",
            "?invitation=onlytheparam",
        ] {
            assert!(contains_leaked_invitation(leaked), "missed: {leaked:?}");
        }
    }

    /// The word "invitation" alone, or the modal's own instructional text,
    /// must never trigger this -- only the actual link parameter is the
    /// secret; talking ABOUT invitations is exactly what the warning text
    /// itself does, and must not re-trigger on replies quoting it.
    #[test]
    fn ordinary_mentions_of_invitations_are_not_flagged() {
        for benign in [
            "click their name in the member list, choose Share Invite",
            "did you get my invitation to the party?",
            "each invitation creates a unique identity",
            "how do invitations work in River?",
            crate::warnings::LEAKED_INVITATION_WARNING,
        ] {
            assert!(
                !contains_leaked_invitation(benign),
                "false positive on {benign:?}"
            );
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
