"""Coverage of the golden attacks by existing public Sigma rules. No model calls.

    uv run python -m evals.coverage             # golden true positives, retrieved top K rules
    uv run python -m evals.coverage --k 20      # look deeper than what triage is shown

For every true_positive in the golden set (the LABEL, not a model verdict, so the number doesn't
depend on triage quality), the Sigma rules retrieval finds for it are run through the matcher,
exactly as the route node does. Covered = one of them fires on the alert's event.

The README number: "X% of our attacks are already caught by a public SigmaHQ rule that our
retrieval finds; the loop writes rules for the rest." It is a lower bound on coverage by the
whole SigmaHQ corpus: a rule retrieval doesn't surface in the top K is not tried.

Needs Postgres (retrieval) and the SigmaHQ checkout in data/raw/sigma. Output:
results/coverage.json (per alert: covering rule, rules checked / missing / broken).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from evals.triage_smoke import load_golden
from sentinel.agents.enrich import K, enrich_alert
from sentinel.validation.coverage import check_coverage

ROOT = Path(__file__).parent.parent
OUT = ROOT / "results" / "coverage.json"


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.coverage")
    p.add_argument("--k", type=int, default=K, help=f"Sigma rules retrieved per alert ({K})")
    args = p.parse_args(argv)

    labels, alerts = load_golden()
    attacks = [lab for lab in labels if lab["label"] == "true_positive"]
    rows = []
    for lab in attacks:
        alert = alerts[lab["alert_id"]]
        _, rules = enrich_alert(alert, k=args.k)
        cov = check_coverage(alert.events, [h.id for h in rules])
        if cov.unavailable:
            raise SystemExit(f"cannot measure coverage: {cov.unavailable}")
        rows.append(
            {"alert_id": lab["alert_id"], "technique_ids": lab["technique_ids"]} | asdict(cov)
        )

    covered = [r for r in rows if r["covering_rule_id"]]
    unknown = [r for r in rows if not r["checked"] and not r["covering_rule_id"]]
    summary = {
        "k": args.k,
        "attacks": len(rows),
        "covered": len(covered),
        "coverage": len(covered) / len(rows) if rows else None,
        "no_rule_matched": len(unknown),  # every retrieved rule missing or broken
        "top_covering_rules": Counter(r["covering_rule_id"] for r in covered).most_common(10),
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2) + "\n", "utf-8")
    print(
        f"covered {summary['covered']}/{summary['attacks']} golden attacks "
        f"({summary['coverage']:.0%}) with the top {args.k} retrieved Sigma rules; "
        f"{len(unknown)} had no matchable rule -> {OUT.relative_to(ROOT).as_posix()}"
    )


if __name__ == "__main__":
    main()
