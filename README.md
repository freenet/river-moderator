# River Moderator

Real-time, budget-bounded LLM moderation for [River](https://github.com/freenet/river) rooms.

This repository is under active design. It is not yet safe to give it a River signing key or run it in enforcement mode. See the [threat model](docs/THREAT_MODEL.md) for the security invariants and release gates.

The initial policy is designed for a highly moderated project room:

- Be civil.
- Stay on topic.
- Severe harmful behavior can result in an immediate ban.
- Disruptive behavior receives a warning, then a ban if it continues.

The system evaluates behavior and impact rather than trying to infer intent. It starts in shadow mode, has hard persistent spending limits, and treats every room message as hostile input.
