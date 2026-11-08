"""Rule generation end to end on uncovered attacks (Day 13): alert -> triage -> route -> rule_gen
-> validate, through the real pipeline.

    uv run python -m evals.rulegen                    # 5 uncovered dev attacks, resumable
    uv run python -m evals.rulegen --validate-only    # re-grade stored rules, no model calls
    uv run python -m evals.rulegen --set testable --gold-technique --run gold-v1   # rule_gen alone
    uv run python -m evals.rulegen --set testable --run e2e-v1                    # with triage

Alert sets (--set):
    uncovered   the first --n dev attacks no existing rule covers (Day 13 default)
    testable    every non-test attack the validator can grade: at least --min-positives (2)
                held-out repeats (same procedure, other capture). Covered alerts are included:
                their rule is written anyway, with every retrieved rule that fires on the alert
                removed from the style examples (nodes._ignore_coverage). Picked by grading a
                rule that never fires (all positives show up as missed), cached in
                results/testable.json. On 2026-10-19: 14 alerts, 4 procedures at >= 2.

--gold-technique: the golden label stands in for triage (oracle verdict), so a failure is rule
generation's own. Without it, a wrong triage technique grades the rule against unrelated attacks
(day3-048). Run both: the gap is what triage mistakes cost the loop.

Picks the dev true_positive alerts that no existing Sigma rule covers (results/coverage.json, from
evals/coverage.py), the first --n by alert id, and runs each through `run_alert` with everything
live. Cost: about 2-4 model requests per alert (triage, maybe escalation, rule generation, maybe
its one retry).

Per alert it records the outcome, the triage verdict, the generated rule and its validation.
Until Mouadh's validator exists every rule is "unvalidated" (it compiles and fires on its own
alert, nothing more); `--validate-only` then grades the stored rules without new model calls.

Summary (results/rulegen-v0.json):
    rules_generated / generation_failures   how many alerts got a rule
    compile_rate                            share of generated rules that compile
    validation_pass_rate, median_fp_rate    None while no validator ran
    needs_review                            0 FP but no held-out repeat to test (pass bar v2)
    first_attempt_pass_rate                 share passing on version 1 (before any repair)
    repairs                                 repair calls made (Week 3 loop, max 2 per alert)
    outcomes                                count per pipeline outcome

Resumable like evals/run.py: rows go to results/rulegen-v0.rows.jsonl as they finish; a re-run
skips finished alerts and retries transport errors; it stops on the provider's daily quota.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from evals.run import DAILY_QUOTA_MARKERS
from evals.split import load_split
from evals.triage_smoke import load_golden
from sentinel.agents.enrich import search_plan
from sentinel.graph.nodes import (
    StubScript,
    held_out_positives,
    rule_passed,
    rule_recall,
    rule_verdict,
)
from sentinel.llm import rulegen_model_name
from sentinel.run import default_owner, models_label, run_alert
from sentinel.schemas import Alert, TriageVerdict
from sentinel.validation import validate as validate_module

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
COVERAGE = RESULTS / "coverage.json"
TESTABLE = RESULTS / "testable.json"
NAME = "rulegen-v0"


def uncovered_dev_attacks(n: int) -> list[str]:
    """The first n dev true_positive alerts (by id) no existing rule covers."""
    dev, _ = load_split("dev")
    rows = json.loads(COVERAGE.read_text(encoding="utf-8"))["rows"]
    uncovered = {r["alert_id"] for r in rows if not r["covering_rule_id"]}
    return sorted(a for a in dev if a in uncovered)[:n]


_NEVER_RULE = """title: never fires
id: 00000000-0000-0000-0000-000000000000
logsource: {{category: {category}, product: windows}}
detection:
  selection1: {{Image|endswith: '__sentinel_never__'}}
  condition: selection1
"""


def held_out_counts(labels: list[dict], alerts: dict[str, Alert]) -> dict[str, int]:
    """alert id -> held-out repeats the validator would grade a rule for it on, for every
    non-test golden attack. A rule that never fires reports every positive as missed. Cached
    in results/testable.json, keyed by the label, procedure and split files."""
    files = [
        validate_module.GOLDEN_LABELS,
        validate_module.PROCEDURES,
        ROOT / "data" / "golden" / "split-v1.json",
    ]
    key = hashlib.sha256(b"".join(f.read_bytes() for f in files)).hexdigest()[:12]
    if TESTABLE.exists():
        cached = json.loads(TESTABLE.read_text(encoding="utf-8"))
        if cached.get("key") == key:
            return cached["counts"]
    test, _ = load_split("test")
    counts = {}
    for lab in labels:
        aid = lab["alert_id"]
        category = search_plan(alerts[aid])[2]
        if lab["label"] != "true_positive" or aid in test or not category:
            continue
        rule = _NEVER_RULE.format(category=category)
        result = validate_module.validate(rule, alerts[aid], lab["technique_ids"])
        counts[aid] = held_out_positives(result)
    TESTABLE.write_text(json.dumps({"key": key, "counts": counts}, indent=1) + "\n", "utf-8")
    return counts


def testable_attacks(labels: list[dict], alerts: dict[str, Alert], min_positives: int) -> list[str]:
    counts = held_out_counts(labels, alerts)
    return sorted(a for a, n in counts.items() if n >= min_positives)


def oracle_verdict(label: dict) -> TriageVerdict:
    return TriageVerdict(
        verdict="true_positive",
        confidence=1.0,
        technique_ids=label["technique_ids"],
        reasoning="golden label (oracle triage for the rule-generation eval)",
        evidence_refs=[],
        ioc_refs=[],
    )


def run_one(
    alert: Alert, trace: bool, name: str = NAME, configurable: dict | None = None
) -> dict[str, Any]:
    try:
        res = run_alert(
            alert,
            live=True,
            stub=StubScript(),
            config_name=name,
            owner=default_owner(),
            trace=trace,
            configurable=configurable,
        )
    except Exception as e:  # rate limit, provider down, DB down: retried on the next run
        return {"error": f"transport: {type(e).__name__}: {str(e)[:300]}"}
    f = res.final
    validations = f.get("validations") or []
    # The version output kept (best_attempt), else the last one.
    best = validations[f.get("best_attempt", len(validations)) - 1] if validations else None
    v = f["verdict"]
    return {
        "outcome": f.get("outcome"),
        "path": res.path,
        "verdict": v.verdict,
        "triage_techniques": v.technique_ids,
        "covering_rule_id": f.get("covering_rule_id"),
        "coverage_ignored": (f.get("coverage") or {}).get("ignored"),
        "rulegen": f.get("rulegen"),
        "rule_yaml": f.get("draft_rule") or None,
        "validation": best.model_dump(mode="json") if best else None,
        "validation_pending": bool(f.get("validation_pending")),
        "recall": rule_recall(best) if best else None,
        "best_attempt": f.get("best_attempt"),
        # One entry per rule version validated, oldest first: did that version pass?
        "attempt_passes": [rule_passed(v) for v in f.get("validations", [])],
        "repairs": f.get("repairs", []),
        "trace": res.trace_url,
    }


def regrade(row: dict[str, Any], alert: Alert) -> dict[str, Any]:
    """Run the validator on a stored rule (no model call). Unchanged when there is none yet."""
    if not row.get("rule_yaml"):
        return row
    techniques = (row.get("rulegen") or {}).get("technique_ids") or row["triage_techniques"]
    try:
        result = validate_module.validate(row["rule_yaml"], alert, techniques)
    except NotImplementedError:
        return row
    verdict = rule_verdict(result)
    return row | {
        "validation": result.model_dump(mode="json"),
        "validation_pending": False,
        "recall": rule_recall(result),
        "outcome": f"rule_{verdict}",
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    done = [r for r in rows if not str(r.get("error", "")).startswith("transport")]
    with_rule = [r for r in done if r.get("rule_yaml")]
    graded = [r for r in with_rule if r.get("validation") and not r.get("validation_pending")]
    compiled = [r for r in with_rule if (r.get("validation") or {}).get("compiled", True)]
    return {
        "alerts": len(rows),
        "finished": len(done),
        "rules_generated": len(with_rule),
        "generation_failures": sum(bool((r.get("rulegen") or {}).get("error")) for r in done),
        "compile_rate": len(compiled) / len(with_rule) if with_rule else None,
        "validated": len(graded),
        "validation_pass_rate": (
            sum(r["outcome"] == "rule_passed" for r in graded) / len(graded) if graded else None
        ),
        "needs_review": sum(r["outcome"] == "rule_needs_review" for r in graded),
        "first_attempt_pass_rate": (
            sum((r.get("attempt_passes") or [False])[0] for r in graded) / len(graded)
            if graded
            else None
        ),
        "repairs": sum(len(r.get("repairs") or []) for r in done),
        "median_recall": (
            statistics.median(recalls)
            if (recalls := [r["recall"] for r in graded if r.get("recall") is not None])
            else None
        ),
        "median_fp_rate": (
            statistics.median(r["validation"]["fp_rate"] for r in graded) if graded else None
        ),
        "outcomes": dict(Counter(r.get("outcome") for r in done)),
        "schema_retries": sum((r.get("rulegen") or {}).get("schema_retries", 0) for r in with_rule),
    }


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    p = argparse.ArgumentParser(prog="python -m evals.rulegen")
    p.add_argument("--n", type=int, default=5, help="uncovered dev attacks to run")
    p.add_argument("--no-trace", action="store_true")
    p.add_argument("--fresh", action="store_true", help="drop earlier rows")
    p.add_argument("--validate-only", action="store_true", help="re-grade stored rules only")
    p.add_argument("--run", default=NAME, help=f"results name (default {NAME})")
    p.add_argument("--ids", nargs="+", help="these alert ids instead of the --set")
    p.add_argument("--set", choices=("uncovered", "testable"), default="uncovered")
    p.add_argument("--min-positives", type=int, default=2, help="--set testable threshold")
    p.add_argument("--gold-technique", action="store_true", help="golden label instead of triage")
    args = p.parse_args(argv)
    name = args.run

    labels, alerts = load_golden()
    if args.ids:
        ids = args.ids
    elif args.set == "testable":
        ids = testable_attacks(labels, alerts, args.min_positives)
    else:
        ids = uncovered_dev_attacks(args.n)
    counts = held_out_counts(labels, alerts) if args.set == "testable" else {}
    rows_path = RESULTS / f"{name}.rows.jsonl"
    done: dict[str, dict] = {}
    if rows_path.exists() and not args.fresh:
        for line in rows_path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if not str(row.get("error", "")).startswith("transport"):
                done[row["alert_id"]] = row

    if args.validate_only:
        done = {a: regrade(r, alerts[a]) for a, r in done.items()}
    else:
        print(f"[{name}] {len(done)} done, {len([i for i in ids if i not in done])} to run")
        for aid in ids:
            if aid in done:
                continue
            lab = next(x for x in labels if x["alert_id"] == aid)
            row = {"alert_id": aid, "label": lab["label"], "label_techniques": lab["technique_ids"]}
            configurable: dict[str, Any] = {"ignore_coverage": args.set == "testable"}
            if args.gold_technique:
                configurable["oracle_verdict"] = oracle_verdict(lab)
            if aid in counts:
                row["held_out_repeats"] = counts[aid]
            row |= run_one(alerts[aid], not args.no_trace, name, configurable) | {
                "at": datetime.now(UTC).isoformat(timespec="seconds")
            }
            err = str(row.get("error", ""))
            title = (row.get("rulegen") or {}).get("title", "-")
            print(f"[{name}] {aid:10} {row.get('outcome', 'ERR'):18} {title[:60]}")
            if err:
                print(f"           {err[:160]}")
            if not err.startswith("transport"):
                done[aid] = row
            with rows_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            if any(m in err for m in DAILY_QUOTA_MARKERS):
                print(f"[{name}] daily quota hit: re-run tomorrow to resume")
                break

    rows = [done[a] for a in ids if a in done]
    rows_path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), "utf-8")
    meta = {
        "triage_models": models_label(),
        "rulegen_model": rulegen_model_name(),
        "alert_ids": ids,
        "set": "ids" if args.ids else args.set,
        "min_positives": args.min_positives if args.set == "testable" else None,
        "gold_technique": args.gold_technique,
        "written_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    summary = summarize(rows)
    out = RESULTS / f"{name}.json"
    out.write_text(
        json.dumps({"meta": meta, "summary": summary, "rows": rows}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    for r in rows:
        if r.get("rule_yaml"):
            title = yaml.safe_load(r["rule_yaml"]).get("title")
            print(f"  {r['alert_id']}: {title}")
    shown = out.relative_to(ROOT) if out.is_relative_to(ROOT) else out
    print(f"written: {shown.as_posix()}")


if __name__ == "__main__":
    main()
