# River Moderator

Real-time, budget-bounded LLM moderation for [River](https://github.com/freenet/river) rooms.

The daemon supports production shadow and warning modes. It subscribes to
verified River message events, evaluates them, and writes a private decision
audit. Warning mode may post only fixed, source-defined replies from an ordinary
River member identity with no deputy authority. Automatic bans remain disabled
until a separately isolated enforcer satisfies the remaining
[threat-model](docs/THREAT_MODEL.md) release gates.

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
- a root-owned OpenAI credential loaded through systemd credentials;
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
