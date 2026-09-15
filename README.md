# Sentinel Loop

Sentinel Loop is a closed-loop detection engineering system: an alert comes in, a multi-agent
pipeline triages it, maps it to MITRE ATT&CK, and for real threats with no existing coverage,
writes a Sigma rule, validates it against labeled telemetry, measures its false-positive rate,
and opens a PR — merged only if it passes an automated eval gate in CI. Its differentiator is
treating log fields as attacker-controlled input: a red-team suite attacks the pipeline through
indirect prompt injection, measures attack success rate, the agent is hardened, and the
before/after curve is published against the OWASP LLM Top 10.

Built by Mouheb (AI/agent engineering) and **Partner** (detection engineering / AI security).

## Status

Week 1, Day 1 — environment and contracts.

## Setup

```bash
uv sync
docker compose up -d
cp .env.example .env   # fill in ANTHROPIC_API_KEY, LANGFUSE_* keys
uv run pytest
```
