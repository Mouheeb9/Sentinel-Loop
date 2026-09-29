"""Failure reader for error analysis: every failed alert of a results file, one card each.

    uv run python -m evals.failures                     # every config in results/, -> markdown
    uv run python -m evals.failures --configs rag --limit 10

A failure is a row with a schema error, a wrong verdict, or technique credit below 1 (the best
partial credit per gold technique, labeling guide section 4). Transport errors are not failures
(the model never answered); they are counted and skipped.

Each card shows what a human needs to judge it: the event, the label and why it was given, the
model's answer and reasoning, what retrieval handed the model, and the trace link. A pre-sort
hint says which bucket the card probably belongs to, so the session is about judgement, not
copy-paste:

    schema error          the model never produced a valid verdict
    retrieval miss?       a gold technique is not in the retrieved top K (not even its parent)
    reasoning error?      the gold technique was retrieved and the model still got it wrong
    (no retrieval)        single-prompt: nothing was retrieved, so no retrieval hint applies
    draft label           appended when the gold label is still `labeler: claude-draft`

Hints are guesses. The bucket that counts (retrieval miss / reasoning error / schema error /
label error) is decided by a human, written into the card's `bucket:` line, and tallied in
docs/error-analysis-v1.md.

Output: results/failures-<config>.md, plus a hint tally on the terminal. Labels are the current
golden file's (same rule as --score-only), so a fixed label drops out of the failures.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals.eval_row import EvalRow
from evals.scorers import AttackMap, credit
from evals.triage_smoke import GOLDEN, load_golden
from sentinel.agents.enrich import K
from sentinel.schemas import Alert, Event

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
CONFIG_ORDER = ("single-prompt", "rag", "rag-tools")
CMD_CHARS = 600  # long encoded PowerShell lines: enough to judge, not a wall of base64


@dataclass
class Failure:
    row: EvalRow
    detail: dict[str, Any]
    reasons: list[str]  # why it counts as a failure
    technique_credit: float | None  # None when the label has no techniques
    hint: str
    draft_label: bool


# --- classification -------------------------------------------------------------------------


def technique_credit(row: EvalRow, attack: AttackMap) -> float | None:
    """Mean over gold IDs of the best credit any prediction earns (the scorer's recall term)."""
    if not row.label_techniques:
        return None
    pred = row.technique_ids if row.error is None else []
    gold = row.label_techniques
    return sum(max((credit(p, g, attack) for p in pred), default=0.0) for g in gold) / len(gold)


def failure_reasons(row: EvalRow, credit_: float | None) -> list[str]:
    if row.error:
        return [row.error.split(":", 1)[0] + " error"]
    reasons = []
    if row.verdict != row.label:
        reasons.append(f"verdict {row.verdict} != {row.label}")
    if credit_ is not None and credit_ < 1:
        reasons.append(f"technique credit {credit_:.2f}")
    return reasons


def retrieval_hint(row: EvalRow, retrieved: list[str] | None, attack: AttackMap) -> str:
    """Pre-sort a failure. `retrieved` is None for a config without retrieval."""
    if row.error:
        return "schema error"
    if retrieved is None:
        return "(no retrieval)"
    if not row.label_techniques:
        return "reasoning error?"  # benign alert: there is no technique to retrieve
    top = [attack.canonical(t) for t in retrieved[:K]]
    missing = [
        g
        for g in row.label_techniques
        if attack.canonical(g) not in top
        and not any(t.split(".")[0] == attack.canonical(g).split(".")[0] for t in top)
    ]
    if missing:
        return f"retrieval miss? ({', '.join(missing)} not in top {K})"
    return "reasoning error?"


def find_failures(
    result: dict, labels: dict[str, dict], attack: AttackMap
) -> tuple[list[Failure], int]:
    """Failures of one results file, and how many rows were skipped as transport errors."""
    retrieval_on = result["meta"].get("retrieval", True)
    failures, transport = [], 0
    for raw in result["rows"]:
        lab = labels.get(raw["alert_id"])
        if lab is None:  # dropped from the golden set since the run
            continue
        row = EvalRow.model_validate(
            raw | {"label": lab["label"], "label_techniques": lab["technique_ids"]}
        )
        if row.error and row.error.startswith("transport"):
            transport += 1
            continue
        c = technique_credit(row, attack)
        reasons = failure_reasons(row, c)
        if not reasons:
            continue
        detail = result["details"].get(row.alert_id, {})
        retrieved = (detail.get("retrieved_techniques") or []) if retrieval_on else None
        draft = lab.get("labeler") == "claude-draft"
        failures.append(
            Failure(row, detail, reasons, c, retrieval_hint(row, retrieved, attack), draft)
        )
    failures.sort(key=lambda f: (f.hint, f.row.alert_id))
    return failures, transport


# --- rendering ------------------------------------------------------------------------------


def render_event(event: Event) -> list[str]:
    lines = [f"- source `{event.source}`, host `{event.host}`, user `{event.user}`"]
    p = event.process
    if p:
        lines.append(f"- process `{p.image}`")
        if p.command_line:
            lines.append(f"- command line `{_clip(p.command_line)}`")
        if p.parent:
            lines.append(f"- parent `{p.parent.image}` `{_clip(p.parent.command_line or '')}`")
    n = event.network
    if n:
        lines.append(f"- network {n.src_ip} -> {n.dst_ip}:{n.dst_port} ({n.protocol})")
    r = event.registry
    if r:
        lines.append(f"- registry `{r.target_object}` = `{_clip(r.details or '')}`")
    return lines


def render_card(f: Failure, alert: Alert, label: dict) -> str:
    row, d = f.row, f.detail
    draft = "  [draft label]" if f.draft_label else ""
    out = [
        f"### {row.alert_id}  ({'; '.join(f.reasons)})",
        "",
        f"**hint:** {f.hint}{draft}  ",
        "**bucket:** _retrieval miss | reasoning error | schema error | label error_  ",
        "**note:** ",
        "",
        f"**Alert:** {alert.detection_name} ({alert.severity}), "
        f"source dataset `{label.get('source_dataset')}`",
    ]
    for i, event in enumerate(alert.events):
        out += ["", f"Event {i}:", *render_event(event)]
    got = row.error or f"{row.verdict} {row.technique_ids} (confidence {row.confidence})"
    out += [
        "",
        f"**Label:** {row.label} {row.label_techniques} by `{label.get('labeler')}`: "
        f"{label.get('rationale')}",
        f"**Model:** {got}, tier {row.tier}"
        + (f", escalated: {d['escalation']}" if d.get("escalation") else ""),
    ]
    if f.technique_credit is not None:
        out.append(f"**Technique credit:** {f.technique_credit:.2f}")
    if d.get("reasoning"):
        out += ["", "> " + d["reasoning"].replace("\n", "\n> ")]
    if d.get("retrieved_techniques") is not None:
        out += [
            "",
            f"**Retrieved techniques (top {K}):** {d.get('retrieved_techniques')}  ",
            f"**Retrieved Sigma rules:** {d.get('retrieved_rules')}",
        ]
    if d.get("lookups"):
        out.append(f"**Lookups:** {d['lookups']}")
    if row.trace:
        out.append(f"**Trace:** {row.trace}")
    return "\n".join(out) + "\n"


def render_report(
    config: str, result: dict, failures: list[Failure], transport: int, alerts, labels
) -> str:
    meta = result["meta"]
    split = (meta.get("split") or {}).get("name", "ad-hoc sample")
    tally = Counter(f.hint.split(" (")[0] for f in failures)
    head = [
        f"# Failures: {config}",
        "",
        f"{len(failures)} failures out of {len(result['rows'])} rows ({split}; "
        f"{transport} transport errors skipped). Model {meta.get('tier1_model')}, "
        f"prompt {meta.get('prompt_sha')}, labels {meta.get('golden_sha')}.",
        "",
        "Hints (guesses, not buckets): " + ", ".join(f"{h} {n}" for h, n in sorted(tally.items())),
        "",
        "---",
        "",
    ]
    cards = [render_card(f, alerts[f.row.alert_id], labels[f.row.alert_id]) for f in failures]
    return "\n".join(head) + "\n---\n\n".join(cards)


def _clip(text: str) -> str:
    text = text.replace("`", "'")
    return text if len(text) <= CMD_CHARS else text[:CMD_CHARS] + f"... (+{len(text) - CMD_CHARS})"


# --- CLI ------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.failures")
    p.add_argument("--configs", nargs="+", choices=CONFIG_ORDER, default=list(CONFIG_ORDER))
    p.add_argument("--results-dir", type=Path, default=RESULTS)
    p.add_argument("--limit", type=int, default=None, help="first N cards per config")
    args = p.parse_args(argv)

    label_rows, alerts = load_golden()
    labels = {lab["alert_id"]: lab for lab in label_rows}
    attack = AttackMap.from_bundle()
    print(f"labels: {GOLDEN.relative_to(ROOT).as_posix()}")
    for config in args.configs:
        path = args.results_dir / f"{config}.json"
        if not path.exists():
            continue
        result = json.loads(path.read_text(encoding="utf-8"))
        failures, transport = find_failures(result, labels, attack)
        shown = failures[: args.limit] if args.limit else failures
        report = render_report(config, result, shown, transport, alerts, labels)
        out = args.results_dir / f"failures-{config}.md"
        out.write_text(report, encoding="utf-8")
        tally = Counter(f.hint.split(" (")[0] for f in failures)
        drafts = sum(f.draft_label for f in failures)
        print(
            f"{config:14} {len(failures):3} failures / {len(result['rows'])} rows  "
            f"{dict(sorted(tally.items()))}  draft labels {drafts}  -> {out.name}"
        )


if __name__ == "__main__":
    main()
