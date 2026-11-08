"""Data for the read-only dashboard (ADR 0004): stored results only, no model, no database.

Everything here is plain Python so it is tested without Streamlit; `app/dashboard.py` only
renders it. Values in the rows (command lines, rule YAML, model reasoning) come from attacker-
controlled logs or from a model reading them: the app shows them as code or table cells, never
as markdown or HTML.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[2] / "results"
TRACE_PREFIX = "https://cloud.langfuse.com/"


def load_rows(path: Path) -> list[dict]:
    """Rows of a *.rows.jsonl file with an alert id (skips the fingerprint line of triage runs)."""
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if "alert_id" in row:
                rows.append(row)
    return rows


def loop_runs(results: Path = RESULTS) -> dict[str, Path]:
    """Runs of the full loop (rows that carry a generated rule), newest file first."""
    found = {}
    for path in sorted(results.glob("*.rows.jsonl"), key=lambda p: -p.stat().st_mtime):
        rows = load_rows(path)
        if any("rule_yaml" in r for r in rows):
            found[path.name.removesuffix(".rows.jsonl")] = path
    return found


def loop_summary(rows: list[dict]) -> dict:
    """Headline numbers of one loop run: outcomes, pass on attempt 1 vs after repair."""
    graded = [r for r in rows if r.get("attempt_passes")]
    return {
        "alerts": len(rows),
        "outcomes": dict(Counter(r.get("outcome") for r in rows)),
        "rules": len(graded),
        "pass_first_try": sum(r["attempt_passes"][0] for r in graded),
        "pass_after_repair": sum(any(r["attempt_passes"]) for r in graded),
    }


def attempts(row: dict) -> list[dict]:
    """One line per rule version: passed, recall, benign hits (recall/hits only from 22 Oct)."""
    passes = row.get("attempt_passes") or []
    recalls = row.get("attempt_recalls") or [None] * len(passes)
    fps = row.get("attempt_fps") or [None] * len(passes)
    return [
        {"attempt": i + 1, "passed": p, "recall": r, "benign_hits": f}
        for i, (p, r, f) in enumerate(zip(passes, recalls, fps, strict=False))
    ]


def trace_url(row: dict) -> str | None:
    """The Langfuse link, only if it points where we expect (a row is data, not a link source)."""
    url = row.get("trace")
    return url if isinstance(url, str) and url.startswith(TRACE_PREFIX) else None


def injection_runs(results: Path = RESULTS) -> dict[str, dict]:
    """Injection results (asr-*.json, stub runs skipped): name -> {config, models, totals,
    by_category}."""
    out = {}
    for path in sorted(results.glob("asr-*.json")):
        if "stub" in path.stem:
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        out[path.stem] = {
            "models": data.get("models") or (data.get("meta") or {}).get("rulegen_model"),
            "totals": data.get("totals") or data.get("summary"),
            "by_category": data.get("by_category"),
        }
    return out
