# data/validation

Held out from `data/golden/` on purpose. `data/golden/` scores the triage agent (does it call
the right verdict/technique); `data/validation/` is a separate pool used only to check whether a
*generated Sigma rule* actually fires on real telemetry (Week 3 repair loop, Zircolite).

## The split rule

Every raw capture in `data/raw/security-datasets/*.zip` (113 total, gitignored — see README
"Setup" to re-download) is assigned to exactly one pool:

- **golden pool**: any zip referenced by `source_dataset` in a `data/golden/v1.jsonl` row (69 zips).
- **validation pool**: everything else (44 zips), frozen in `validation_datasets.txt`.

**No zip is ever in both pools.** A generated Sigma rule must never be validated against the same
capture the triage agent was scored on — that would be grading against the answer key.

`validation_datasets.txt` is frozen the same day golden-v1 was frozen (2026-09-22). If golden ever
adds a new capture (v2+), re-derive this list (any golden zip must be removed from here) and note
it in `data/golden/CHANGELOG.md`.

Enforced by `tests/test_no_leakage.py`.

## Status

Event-level validation labels (which event in which validation capture, matching Sigma rule,
expected hit count) are **not built yet** — that's Week 3 work, once the rule-gen agent exists.
This freeze only reserves the capture pool so it can't accidentally get consumed by golden set
growth in the meantime.
