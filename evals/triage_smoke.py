"""Smoke run: the current triage config (CONFIG_NAME in run.py) on 20 golden-v1 alerts, written
out for reading by hand.

    uv run python -m evals.triage_smoke [--n 20] [--seed 5] [--no-trace] [--fresh]

Not a score. The goal is to look for failure *shapes* (wrong verdict type, invented IOCs, bad
technique granularity, ...) and to check the checkpoint: a schema-valid TriageVerdict on every
alert, no parse failures. The sample is fixed by --seed and stratified like golden-v1 (2 TP : 1
benign), so re-runs with another model see the same alerts.

Rows are appended as they finish. A re-run skips alerts that already have a verdict and retries
the ones that failed (transport errors from an overloaded free model are recorded, not fatal);
--fresh starts over.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from dotenv import load_dotenv

from sentinel.agents.triage import TriageError
from sentinel.graph.nodes import StubScript
from sentinel.run import CONFIG_NAME, default_owner, models_label, run_alert
from sentinel.schemas import Alert

ROOT = Path(__file__).parent.parent
GOLDEN = ROOT / "data" / "golden" / "v1.jsonl"
CANDIDATES = [ROOT / "data" / "golden" / f"day{d}_candidates.json" for d in (2, 3)]
RESULTS = ROOT / "evals" / "results"
PAUSE_S = 3  # free-tier models are rate limited per minute


def load_golden() -> tuple[list[dict], dict[str, Alert]]:
    labels = [json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines() if line]
    alerts: dict[str, Alert] = {}
    for path in CANDIDATES:
        for c in json.loads(path.read_text(encoding="utf-8")):
            alerts[c["alert"]["alert_id"]] = Alert.model_validate(c["alert"])
    missing = [row["alert_id"] for row in labels if row["alert_id"] not in alerts]
    if missing:
        raise SystemExit(f"labels without an alert in the candidate files: {missing[:5]}")
    return labels, alerts


def sample(labels: list[dict], n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    tp = sorted((r for r in labels if r["label"] == "true_positive"), key=lambda r: r["alert_id"])
    bn = sorted((r for r in labels if r["label"] == "benign_noisy"), key=lambda r: r["alert_id"])
    n_tp = round(n * len(tp) / (len(tp) + len(bn)))
    return sorted(rng.sample(tp, n_tp) + rng.sample(bn, n - n_tp), key=lambda r: r["alert_id"])


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=20)
    p.add_argument("--seed", type=int, default=5)
    p.add_argument("--no-trace", action="store_true")
    p.add_argument("--fresh", action="store_true", help="ignore earlier results for this model")
    args = p.parse_args()

    labels, alerts = load_golden()
    model = models_label()
    slug = model.replace(" -> ", "__").replace(":", "_").replace("/", "_")
    out = RESULTS / f"{CONFIG_NAME.replace('-', '_')}_smoke_{slug}.jsonl"
    RESULTS.mkdir(exist_ok=True)
    done: dict[str, dict] = {}
    if out.exists() and not args.fresh:
        for line in out.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row["error"] is None:
                done[row["alert_id"]] = row
    out.write_text("".join(_line(r) for r in done.values()), "utf-8")

    rows = []
    for i, label in enumerate(sample(labels, args.n, args.seed), 1):
        alert = alerts[label["alert_id"]]
        if alert.alert_id in done:
            rows.append(done[alert.alert_id])
            print(f"{i:2}/{args.n} --  {alert.alert_id:12} (already done)")
            continue
        row = {
            "alert_id": alert.alert_id,
            "label": label["label"],
            "label_techniques": label["technique_ids"],
            "label_rationale": label["rationale"],
        }
        try:
            res = run_alert(
                alert,
                live=True,
                stub=StubScript(),
                config_name=f"{CONFIG_NAME}-smoke",
                owner=default_owner(),
                trace=not args.no_trace,
            )
            v = res.final["verdict"]
            row |= {
                "verdict": v.verdict,
                "confidence": v.confidence,
                "technique_ids": v.technique_ids,
                "reasoning": v.reasoning,
                "evidence_refs": v.evidence_refs,
                "ioc_refs": v.ioc_refs,
                "schema_retries": res.final.get("triage_schema_retries", 0),
                "retrieved_techniques": [h.id for h in res.final.get("techniques", [])],
                "tier": res.final.get("triage_tier"),
                "escalation": res.final.get("triage_escalation"),
                "cost_usd": res.final.get("triage_cost_usd"),
                "lookups": [x for r in res.final.get("triage_runs", []) for x in r["lookups"]],
                "trace": res.trace_url,
                "error": None,
            }
        except TriageError as e:
            row |= {"verdict": None, "error": f"schema: {e}"}
        except Exception as e:  # transport: rate limit, overloaded provider, network
            row |= {"verdict": None, "error": f"transport: {type(e).__name__}: {str(e)[:300]}"}
        rows.append(row)
        with out.open("a", encoding="utf-8") as f:
            f.write(_line(row))
        mark = "OK " if row["error"] is None else "ERR"
        print(
            f"{i:2}/{args.n} {mark} {alert.alert_id:12} label={label['label']:13} "
            f"got={row.get('verdict')} {row.get('technique_ids', '')}"
        )
        time.sleep(PAUSE_S)

    out.write_text("".join(_line(r) for r in rows), "utf-8")  # rewrite in sample order
    out.with_suffix(".md").write_text(_report(rows, alerts, model), "utf-8")

    valid = sum(r["error"] is None for r in rows)
    schema_fail = sum(str(r["error"]).startswith("schema") for r in rows)
    transport_fail = sum(str(r["error"]).startswith("transport") for r in rows)
    retried = sum(r.get("schema_retries", 0) for r in rows if r["error"] is None)
    agree = sum(r.get("verdict") == r["label"] for r in rows)
    escalated = sum(r.get("escalation") is not None for r in rows if r["error"] is None)
    costs = [r.get("cost_usd") for r in rows if r["error"] is None]
    cost = "unknown" if None in costs else f"${sum(costs):.4f}"
    print(
        f"\nschema-valid: {valid}/{len(rows)}  schema failures: {schema_fail}  "
        f"transport failures (re-run to retry): {transport_fail}  needed retry: {retried}\n"
        f"verdict == label: {agree}/{len(rows)} (not a score, just orientation)\n"
        f"escalated to tier 2: {escalated}/{valid}  total cost: {cost}"
    )
    print(f"written: {out.relative_to(ROOT)} and .md")


def _line(row: dict) -> str:
    return json.dumps(row, ensure_ascii=False) + "\n"


def _report(rows: list[dict], alerts: dict[str, Alert], model: str) -> str:
    lines = [
        f"# {CONFIG_NAME} smoke run ({model})",
        "",
        "Read every row. Look for failure shapes, not a score.",
        "",
    ]
    for r in rows:
        e = alerts[r["alert_id"]].events[0]
        seen = e.process.command_line or e.process.image if e.process else None
        seen = seen or (e.registry.target_object if e.registry else None)
        seen = seen or (f"{e.network.dst_ip}:{e.network.dst_port}" if e.network else "")
        lines += [
            f"## {r['alert_id']}  label={r['label']} {r['label_techniques']}  "
            f"got={r.get('verdict')} {r.get('technique_ids', '')} conf={r.get('confidence')}",
            f"- event: `{(seen or '')[:300]}`",
            f"- label why: {r['label_rationale']}",
            f"- model why: {r.get('reasoning') or r.get('error')}",
            f"- iocs: {r.get('ioc_refs')}  evidence: {r.get('evidence_refs')}  "
            f"retries: {r.get('schema_retries')}",
            f"- retrieved: {r.get('retrieved_techniques')}",
            f"- tier: {r.get('tier')} (escalation: {r.get('escalation')})  "
            f"lookups: {r.get('lookups')}",
            f"- trace: {r.get('trace')}",
            "",
        ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
