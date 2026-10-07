"""Rule gate (Day 17, Mouadh): re-validate every generated rule before it can be merged.

A rule reaches rules/generated/<alert-id>.yml through a draft PR (sentinel.publish). The
validator already graded it inside the loop, but the file in the PR is what gets merged, and
anyone (a human, a model, poisoned logs) can change it after that grade. So CI grades the file
again, exactly as it is, with validator v2 and pass bar v2 (nodes.rule_verdict, ADR 0003).

A rule FAILS the gate (exit 1) when any of these holds:
- it doesn't compile (invalid YAML or Sigma the matcher can't run),
- it fires on any benign event (golden benign_noisy + background + benign set v1),
- it catches fewer than min(2, n) of the n held-out repeats of its attack (pass bar v2),
- a lint fires: a filter on a process name (RG-3) or '/' path values that never match,
- its source alert is not in the golden set, or it claims no ATT&CK technique (can't be graded).
A rule with no held-out repeats (n = 0) passes the gate as NEEDS HUMAN REVIEW: nothing can
prove it works, so the reviewer decides (the PR needs an approval anyway).

Every file in rules/generated/ is checked on every run, not just the changed ones: a change to
the validator or the benign set must re-check the rules already merged. No model, no database,
no network; the noise pool (data/raw/) is skipped when absent, as in CI.

    uv run python -m evals.validate_rules                 # every rules/generated/*.yml
    uv run python -m evals.validate_rules path/to/x.yml   # these files only
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from evals.triage_smoke import load_golden
from sentinel.graph.nodes import held_out_positives, rule_verdict
from sentinel.schemas import Alert
from sentinel.validation import validate as validate_module

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "rules" / "generated"
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass(frozen=True)
class GateResult:
    path: Path
    verdict: str  # passed | needs_review | failed
    reasons: list[str]  # why it failed; empty when it didn't
    report: str  # validator feedback, for the reviewer


def techniques(rule_yaml: str) -> list[str]:
    """ATT&CK ids from the rule's tags (attack.t1059.003 -> T1059.003)."""
    try:
        tags = (yaml.safe_load(rule_yaml) or {}).get("tags") or []
    except yaml.YAMLError:
        return []
    return [m.group(1).upper() for t in tags if (m := TECHNIQUE_TAG.match(str(t)))]


def check(path: Path, alerts: dict[str, Alert]) -> GateResult:
    """Grade one rule file; the alert id is the file name (rules/generated/<alert-id>.yml)."""
    text = path.read_text(encoding="utf-8")
    alert = alerts.get(path.stem)
    if alert is None:
        reason = f"source alert {path.stem!r} is not in the golden set: can't grade it"
        return GateResult(path, "failed", [reason], "")
    claimed = techniques(text)
    result = validate_module.validate(text, alert, claimed)
    verdict = rule_verdict(result)
    reasons = []
    if not result.compiled or result.compile_errors:
        reasons += [f"does not compile: {e}" for e in result.compile_errors] or ["not compiled"]
    elif not claimed:
        reasons.append("no ATT&CK technique in tags: can't grade it")
    elif result.false_positives:
        reasons.append(f"fires on {result.false_positives} benign event(s)")
    elif verdict == "failed":
        n = held_out_positives(result)
        reasons.append(f"catches {result.true_positives}/{n} held-out repeats, needs {min(2, n)}")
    reasons += validate_module.lint(text)
    if reasons:
        verdict = "failed"
    return GateResult(path, verdict, reasons, result.feedback)


def rule_files(paths: list[str]) -> list[Path]:
    if paths:
        return [Path(p) for p in paths]
    return sorted(RULES_DIR.glob("*.yml")) if RULES_DIR.is_dir() else []


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("paths", nargs="*", help="rule files (default: every rules/generated/*.yml)")
    args = p.parse_args(argv)

    files = rule_files(args.paths)
    if not files:
        print("rule gate: no generated rules to check")
        return 0
    _, alerts = load_golden()
    results = [check(f, alerts) for f in files]
    for r in results:
        label = {"passed": "PASS", "needs_review": "PASS, NEEDS HUMAN REVIEW"}.get(
            r.verdict, "FAIL"
        )
        print(f"{label}  {r.path.as_posix()}")
        for reason in r.reasons:
            print(f"    x {reason}")
        for line in r.report.splitlines():
            if line not in r.reasons:  # lint lines are already listed as reasons
                print(f"      {line}")
    failed = sum(r.verdict == "failed" for r in results)
    print(f"rule gate: {len(results) - failed}/{len(results)} rules pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
