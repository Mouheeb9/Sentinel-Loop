"""Rule generation end to end on uncovered attacks (Day 13): alert -> triage -> route -> rule_gen
-> validate, through the real pipeline.

    uv run python -m evals.rulegen                    # 5 uncovered dev attacks, resumable
    uv run python -m evals.rulegen --validate-only    # re-grade stored rules, no model calls

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
    first_attempt_pass_rate                 share passing on version 1 (before any repair)
    repairs                                 repair calls made (Week 3 loop, max 2 per alert)
    outcomes                                count per pipeline outcome

Resumable like evals/run.py: rows go to results/rulegen-v0.rows.jsonl as they finish; a re-run
skips finished alerts and retries transport errors; it stops on the provider's daily quota.
"""

from __future__ import annotations

import argparse
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
from sentinel.graph.nodes import StubScript, rule_passed, rule_recall
from sentinel.llm import rulegen_model_name
from sentinel.run import default_owner, models_label, run_alert
from sentinel.schemas import Alert
from sentinel.validation import validate as validate_module

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
COVERAGE = RESULTS / "coverage.json"
NAME = "rulegen-v0"


def uncovered_dev_attacks(n: int) -> list[str]:
    """The first n dev true_positive alerts (by id) no existing rule covers."""
    dev, _ = load_split("dev")
    rows = json.loads(COVERAGE.read_text(encoding="utf-8"))["rows"]
    uncovered = {r["alert_id"] for r in rows if not r["covering_rule_id"]}
    return sorted(a for a in dev if a in uncovered)[:n]


def run_one(alert: Alert, trace: bool, name: str = NAME) -> dict[str, Any]:
    try:
        res = run_alert(
            alert,
            live=True,
            stub=StubScript(),
            config_name=name,
            owner=default_owner(),
            trace=trace,
        )
    except Exception as e:  # rate limit, provider down, DB down: retried on the next run
        return {"error": f"transport: {type(e).__name__}: {str(e)[:300]}"}
    f = res.final
    v = f["verdict"]
    return {
        "outcome": f.get("outcome"),
        "path": res.path,
        "verdict": v.verdict,
        "triage_techniques": v.technique_ids,
        "covering_rule_id": f.get("covering_rule_id"),
        "rulegen": f.get("rulegen"),
        "rule_yaml": f.get("draft_rule") or None,
        "validation": f["validations"][-1].model_dump(mode="json")
        if f.get("validations")
        else None,
        "validation_pending": bool(f.get("validation_pending")),
        "recall": rule_recall(f["validations"][-1]) if f.get("validations") else None,
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
    passed = rule_passed(result)
    return row | {
        "validation": result.model_dump(mode="json"),
        "validation_pending": False,
        "recall": rule_recall(result),
        "outcome": "rule_passed" if passed else "rule_failed",
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
    p.add_argument("--ids", nargs="+", help="these alert ids instead of the first n uncovered")
    args = p.parse_args(argv)
    name = args.run

    labels, alerts = load_golden()
    ids = args.ids or uncovered_dev_attacks(args.n)
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
            row |= run_one(alerts[aid], trace=not args.no_trace, name=name) | {
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
