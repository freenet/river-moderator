# Threat model

## Status

This document is normative for the initial implementation. A release must not enable automatic enforcement until every release gate below is covered by a test or a documented operator procedure.

The design assumes an attacker knows the complete source code, prompts, model names, thresholds, rate limits, service layout, and moderation policy. Confidential signing keys and provider credentials are the only secrets.

## Protected assets

1. Room membership and the integrity of moderation actions.
2. The Room Owner and moderator signing keys.
3. Availability of the room and its moderation capacity.
4. The operator's provider account and bounded financial exposure.
5. Members' message content and moderation history.
6. An audit trail sufficient to explain each warning or ban.

## Trust boundaries

- Message content, nicknames, claimed timestamps, links, edits, and quoted text are hostile input.
- A cryptographically verified River author identity and message ID may be trusted only after verification by River code.
- A message's author-supplied timestamp is not a rate-limit clock. It can be in the past or future.
- The first local observation time is the rate-limit clock and must be persisted so reconnects and restarts cannot reset it.
- Model output is untrusted data. It never selects a target, supplies warning text, names a River operation, or becomes a command.
- Provider errors, timeouts, malformed output, and refusals are normal failure modes, not permission to retry or enforce.
- Configuration is trusted only when owned by root and not writable by the service accounts.

## Policy taxonomy

The classifier returns one of five closed verdicts:

- `allow`
- `nudge_conduct`
- `warn_disruptive`
- `ban_severe_harm`
- `needs_human_review`

It also selects a closed category, confidence, and a short audit reason. Intent is not an input to enforcement. `nudge_conduct` is a visible but non-punitive reminder for a mildly rude or dismissive formulation; it does not start the warning-to-ban clock. Repeated nudges in the same conduct group escalate to a formal warning.

Low-severity nudges and warnings have a configurable grace period (60 seconds by default). If the Room Owner or a current deputy sends an authenticated reply to the exact target message during that period, trusted code cancels the automated action and records `handled_by_moderator`. Nicknames and reply preview text are not sufficient; cancellation requires River's verified reply target message ID and responder member ID. Severe-harm actions do not wait for this grace period.

`warn_disruptive` covers sustained off-topic discussion, rudeness, incivility, ad hominem or other personal attacks below the severe-harm threshold, repetitive promotion, monopolizing the room, inflammatory derailment, excessive posting, and persistently harmful misinformation. Members may disagree strongly and criticize ideas, code, projects, and decisions, but must do so politely. Repetition after a category-specific warning may be escalated to a ban.

`ban_severe_harm` covers spam, scams, phishing, malware, doxxing, credible threats, targeted harassment or hate, impersonation, sexual exploitation, and extreme flooding. A severe outcome does not require proof of malicious intent.

Good-faith mistakes, disagreement, criticism, frustration, one brief tangent, profanity by itself, and unpopular opinions are not violations.

## Context and temporal behavior

Each classification request contains a bounded, speaker-labelled structure with:

- the current message and whether it is an edit;
- the previous messages from the same verified author;
- nearby room messages and authenticated reply relationships when available;
- the author-claimed River timestamp and the persisted first-observed timestamp for every entry;
- derived counts for the author over short time windows;
- inter-arrival gaps based only on first-observed times;
- duplicate and near-duplicate signals;
- active warning state; and
- the fixed room topic and policy.

The model must not recommend a ban based solely on hostile context supplied by other users. Except for behavior that inherently spans messages, such as flooding, the target's own authenticated content must establish the violation.

## Durable tenure and role-aware policy

River's retained room state is not used as a long-term tenure database. The moderator maintains a local persistent member registry containing first and last observed time, observation count, active-day count, bootstrap provenance, and warning history. All durations use local observation time.

An operator performs an explicit one-time bootstrap of the current room roster. Those members are marked pre-existing and established so installing or restarting the moderator does not nag long-time members. Members first observed after bootstrap begin probation. The daemon refuses to infer or repeat a bootstrap automatically: loss of the registry is an operational alert and blocks off-topic enforcement until the operator restores a backup or explicitly bootstraps again.

Trusted code assigns one of these policy tiers:

- `probationary`: stricter disruption and off-topic handling;
- `regular`: standard handling;
- `established`: a longer sustained pattern is required before off-topic warnings; and
- `deputy`: current River deputies are not automatically warned or banned for off-topic discussion. This leniency does not extend to rudeness or personal attacks. Unmistakable severe harm can trigger the higher-threshold deputy emergency path; other concerns are routed to the owner for review.

Deputy status is refreshed from authenticated room state and is not granted by the model or by a locally stored nickname. Tenure never exempts severe harm. An automatic deputy ban requires an agreeing independent verifier, the higher configured deputy threshold, an eligible severe category, and all ordinary descendant-collateral checks. Trusted code selects the Room Owner signer for this exceptional path because a fellow deputy may not have authority to ban the target; the model cannot select the signer.

## Enforcement architecture

The internet-facing classifier holds no River signing key. It sends a closed internal action request to a local enforcer over a permission-restricted Unix socket.

The enforcer:

1. accepts only the closed actions `warn` and `ban`;
2. derives the target from the stored, verified event rather than model output;
3. rejects protected identities, the Room Owner, its own identities, and ambiguous short IDs;
4. fetches fresh room state before acting;
5. recomputes authorization and the complete ban removal set;
6. enforces independent warning and ban rate limits;
7. uses fixed, operator-reviewed warning text; and
8. records an idempotency key before submitting an action.

Before any ban submission, the service durably appends a structured pending-decision record. It stores the target's canonical River `MemberId` plus the full Ed25519 verifying key from fresh membership state, and includes the trigger and bounded context, claimed and observed timestamps, temporal signals, normalized and model reasons, warning history, model/prompt versions, usage and reserved cost, inviter and ancestor IDs, the full descendant removal set, and the content hash that was classified. A second record captures the River submission outcome. This supports later correlation with invite-issuance logs by canonical member ID or verifying key.

Raw audit context is stored in a mode-0600 local audit file with bounded size and retention. Ordinary service logs contain member IDs, content hashes, categories, and outcomes but no complete message bodies.

Warnings may be signed by the Room Owner through the restricted enforcer. Bans should be signed by a dedicated owner-appointed Moderator identity. Revoking that deputy grant invalidates its bans, limiting recovery impact if its key is compromised.

River bans remove the target and their transitive invite descendants. Automatic enforcement therefore defaults to `max_ban_descendants = 0`. A target with descendants goes to human review. Operators may explicitly raise this limit, but the model cannot override it.

## Prompt-injection and false-ban resistance

- Messages are serialized as data, never interpolated into instructions.
- The model has no tools and cannot fetch URLs found in messages.
- A strict response schema rejects unknown verdicts, categories, and fields.
- Target identifiers in provider output are ignored even if the provider returns them.
- Proposed bans require a separate verification pass with a minimal evidence view. Failure or disagreement becomes human review.
- Protected-identity and descendant checks happen after classification in trusted code.
- Model reasons are for audit only and are never displayed verbatim or executed.
- Rapid edits are debounced. Enforcement uses the content hash that was actually classified and aborts if the current message changed.
- Replayed events and reconnect duplicates are suppressed with persistent message-ID and content-hash state.

Structured output reduces parser ambiguity; it does not make prompt injection impossible. The trusted enforcement checks remain necessary even if the classifier is replaced by a perfect model.

## Financial denial-of-service resistance

Every paid request must pass one transactional, persistent budget gate before network I/O. No other code path may call a paid provider.

The gate reserves the worst-case configured cost before a request, using an integer micro-dollar ledger. It checks all of these independent limits:

- daily and calendar-month cost;
- requests per minute, hour, and day;
- requests per author;
- maximum input bytes/tokens and maximum output tokens;
- maximum concurrent requests and bounded queue depth; and
- circuit-breaker state.

Provider-reported usage reconciles a reservation downward or upward, but a missing usage record retains the full reservation. A timeout after request submission is never automatically retried because the first request may already have been billed. Persistent reservations survive crashes and restarts.

Additional controls:

- exact message and normalized-content deduplication;
- a verdict cache for repeated spam;
- edit debounce;
- immediate local suppression once an identity is pending ban;
- no calls for joins, reactions, deletions, protected service identities, or the moderator's own messages;
- per-author fairness so one identity cannot consume the queue;
- a reserved incident budget that ordinary traffic cannot consume;
- deterministic high-signal flood and duplicate rules when the provider is unavailable; and
- a separate provider project/key with a provider-side budget limit.

Budget exhaustion fails open for ambiguous content: it logs and alerts but does not make an unreviewed punitive decision. High-signal deterministic rules may still act if separately enabled and tested.

Hard spending limits convert an unbounded financial attack into a bounded moderation-availability attack; they do not solve that attack. A distributed adversary with many identities can exhaust all remote-classifier capacity. Operational alerts, protected reserve capacity, signup controls, and an optional local no-marginal-cost fallback are needed to reduce that residual risk.

## Key and host compromise resistance

- Classifier and enforcer run as distinct unprivileged users.
- Only the enforcer can read River keys; only the classifier can reach the model provider.
- The enforcer's network access is restricted to the local Freenet gateway.
- Credentials are supplied by systemd credentials or root-owned files, never environment values visible to unrelated processes or command-line arguments.
- The Room Owner key is not copied into the repository, database, logs, crash reports, or model context.
- The Unix socket validates peer credentials and is writable only by the classifier service group.
- Executables and configuration are absolute paths owned by root. No shell is used for River operations.
- The initial River reader invokes the absolute root-owned `riverctl` binary directly with an argument array and its JSONL subscription format. It never invokes a shell, inherits no credential-bearing environment, caps each line before parsing, and accepts only the closed event schema. The reader is localhost-only and the internet-facing classifier receives verified events over a Unix socket.
- Logs escape control characters and do not store complete message bodies by default.

## Other evasion and abuse cases

- Unicode confusables, zero-width characters, URL shorteners, encoded links, image-only spam, and attachments require normalization or explicit unsupported-content handling.
- Coordinated accounts can frame another member with hostile context. Context authorship and reply relationships must remain explicit.
- Attackers can alternate categories to evade category-specific warning counters. A bounded aggregate disruption score is also required.
- Warning messages can themselves flood the room. The enforcer has a warning cooldown and action budget.
- A provider can drift without a model-name change. Prompt/model versions and evaluation results are recorded with each verdict.
- State corruption must fail closed for spending and fail open for punishment: no provider call and no enforcement until the ledger is readable.
- URLs in messages are never fetched by the moderator, preventing SSRF and tracking callbacks.
- Content deleted after classification and content edited after classification invalidate pending enforcement.

## Release gates

Automatic warnings or bans remain disabled until all of the following pass:

1. Persistent budget tests cover process restart, concurrent reservation, day/month boundaries, missing usage, provider timeout without retry, price overflow, and state corruption.
2. Deduplication tests cover reconnects, edits, duplicate content, and pending-ban suppression.
3. Adversarial prompt tests prove that message text cannot select a target, action, warning text, executable, endpoint, model, or budget.
4. Context tests prove burst signals use first-observed time, not author-claimed timestamps.
5. Enforcement tests cover protected identities, ambiguous IDs, authorization changes, stale room state, changed/deleted messages, action rate limits, and idempotency.
6. Ban tests cover zero, one, and many invite descendants and refuse collateral beyond the configured threshold.
7. Shadow-mode evaluation includes real benign traffic, known spam, prompt injection, discussion of prohibited topics in a legitimate moderation context, quoted abuse, and adversarially split spam.
8. The classifier runs in production shadow mode long enough for an owner to review its proposed actions and false-positive rate.
9. The service has a tested kill switch that revokes the Moderator identity and stops both units.
10. Provider and local hard budgets are confirmed independently.

## Explicit non-goals and residual risk

- No classifier can guarantee correct judgments about nuanced speech.
- Open source permits attackers to tune content near thresholds; secrecy of prompts is not a defense.
- A remote provider outage or exhausted budget can leave ambiguous abuse unclassified.
- A Room Owner warning helper necessarily places the owner key on the host. Operators unwilling to accept that risk should speak as the dedicated Moderator identity instead.
- Image, audio, and file moderation are not covered by the initial text-only release and must not be silently treated as safe.
