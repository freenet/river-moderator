# River Moderator

Real-time, budget-bounded LLM moderation for [River](https://github.com/freenet/river) rooms.

The daemon is suitable for a production **shadow-mode** rollout: it subscribes to
verified River message events, evaluates them, and writes a private decision
audit without posting messages or changing room membership. The executable
rejects warning and enforcement modes at startup, and the shadow service should
receive only an ordinary River member identity with no deputy authority.

Automatic warnings and bans are deliberately not implemented yet. See the
[threat model](docs/THREAT_MODEL.md) for the security invariants and release
gates that must be satisfied before an enforcer is introduced.

The initial policy is designed for a highly moderated project room:

- Be civil.
- Stay on topic.
- Severe harmful behavior can result in an immediate ban.
- Disruptive behavior receives a warning, then a ban if it continues.

The system evaluates behavior and impact rather than trying to infer intent. It starts in shadow mode, has hard persistent spending limits, and treats every room message as hostile input.

## Production shadow service

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
