# River Moderator

Real-time, budget-bounded LLM moderation for [River](https://github.com/freenet/river) rooms.

The daemon supports production shadow, warning, and enforcement modes. It
subscribes to verified River message events, evaluates them, and writes a
private decision audit. Public replies are fixed, source-defined text posted by
an ordinary River member identity. In enforcement mode, automatic bans are
limited to severe-harm decisions independently confirmed by both models, or a
comparable severe repeat after a warning.

The initial policy is designed for a highly moderated project room:

- Be civil.
- Stay on topic.
- Severe harmful behavior can result in an immediate ban.
- Disruptive behavior receives a warning, then a ban if it continues.

The system evaluates behavior and impact rather than trying to infer intent. It
starts in shadow mode, has hard persistent spending limits, and treats every
room message as hostile input. Enabling warning mode requires an explicit UTC
activation cutoff: messages first observed before that time can never be queued
for a public action.

## Production service

The reference files in [`packaging/systemd`](packaging/systemd) run the service
as the dedicated `river-moderator` user. The service uses:

- an ordinary River identity under `/var/lib/river-moderator/river`;
- root-owned OpenAI and room-owner signing credentials loaded through systemd
  credentials;
- a root-owned `riverctl` binary with verified reply-target event support;
- persistent state and budget reservations in
  `/var/lib/river-moderator/state.redb`; and
- a mode-0600 decision audit at
  `/var/lib/river-moderator/decision-audit.jsonl`.

Before first start, explicitly bootstrap a current member-ID roster so existing
members are treated as established:

```sh
sudo -u river-moderator /usr/local/bin/river-moderator \
  --config /etc/river-moderator/config.toml \
  bootstrap-members /var/lib/river-moderator/bootstrap-current-members.txt
```

Useful read-only checks:

```sh
sudo systemctl status river-moderator
sudo journalctl -u river-moderator --since today
```

The journal contains IDs, content hashes, categories, projected actions, and
latency plus current daily/monthly cost counters, but no message bodies. Full
bounded context is retained only in the private audit file for operator review.
The standalone `budget-status` command is for offline inspection while the
daemon is stopped; the database intentionally permits only one process to hold
its lock.

Warning mode adds a grace period for human moderator intervention, persists a
global public-action interval and per-member cooldown across restarts, drops
stale queued actions, and rechecks the classified message immediately before
posting. Edited, deleted, missing, or author-mismatched messages are suppressed.
Model output cannot choose reply text, command arguments, or targets.

Enforcement mode leaves ordinary tone and topic decisions in the audit log. It
posts only severe borderline warnings, without a delayed burst, and bans only
when the severe-harm gate is satisfied. Before signing a ban, it pins the room
contract, rechecks the exact member ID and triggering message, refuses deputies
and members with descendants, protects configured service/operator IDs, and
applies persistent per-minute, hourly, and daily ban caps. Ban operations are
fixed CLI calls signed by the configured room-owner credential; untrusted model
text is never interpreted as a command or command argument.

Join notices receive a separate high-confidence nickname prefilter before the
member's first message. It normalizes Unicode, strips zero-width characters,
checks severe-name and protected-identity patterns, and sends only candidates
to the classifier and independent verifier. The pattern match never bans by
itself; ambiguous names remain log-only.

For high-volume rooms, ordinary messages are recorded without a provider call.
An exact `spam` reply to a message routes that target plus bounded surrounding
context and timestamps to the classifier/verifier. Deterministic high-signal
events such as extreme bursts, duplicate floods, oversized ASCII walls, and
common unsolicited-contact lures also trigger review. Five reports from one
member within sixty seconds are treated as report flooding and enter the same
guarded ban path. Only reports whose targets were adjudicated as non-spam count
toward that threshold; reports of confirmed spam, scams, phishing, or flooding
do not punish the reporter.
