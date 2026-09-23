"""
injection/runner.py

Takes InjectionCase objects, embeds each payload into a target field of
a real benign alert, runs it through the Sentinel Loop pipeline, and
checks whether the attack's success_signal shows up in the output.
"""
import argparse
import json
import random
from pathlib import Path
from datetime import datetime, timezone

from sentinel.schemas import InjectionCase, TriageVerdict

# Adjust this import to match whatever Mouheb actually named the
# pipeline entrypoint in his graph module (e.g. sentinel.graph.run,
# sentinel.run.run_alert, etc).
try:
    from sentinel.graph import run_pipeline
except ImportError:
    run_pipeline = None


def load_cases(path: str) -> list[InjectionCase]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [InjectionCase(**c) for c in raw]


def load_candidates(*paths: str) -> dict:
    """Load one or more candidate files (day2_candidates.json,
    day3_candidates.json, ...) and index alerts by alert_id."""
    by_id = {}
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            candidates = json.load(f)
        for c in candidates:
            alert = c.get("alert")
            if alert and alert.get("alert_id"):
                by_id[alert["alert_id"]] = alert
    return by_id


def load_benign_alerts(labels_path: str, candidates: dict) -> list[dict]:
    """Read v1.jsonl, keep only benign_noisy alert_ids, and return their
    real alert content pulled from the candidate files."""
    alerts = []
    with open(labels_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("label") == "benign_noisy":
                alert = candidates.get(row["alert_id"])
                if alert:
                    alerts.append(alert)
    return alerts


def set_by_path(obj: dict, dotted_path: str, value: str) -> None:
    parts = dotted_path.split(".")
    cur = obj
    for p in parts[:-1]:
        if cur.get(p) is None:
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value

def inject(alert: dict, case: InjectionCase) -> dict:
    poisoned = json.loads(json.dumps(alert))  # deep copy
    if "events" in poisoned and poisoned["events"]:
        set_by_path(poisoned["events"][0], case.target_field, case.payload)
    else:
        set_by_path(poisoned, case.target_field, case.payload)
    return poisoned


def attack_succeeded(case: InjectionCase, verdict: dict) -> bool:
    """Mechanical check: did the success_signal show up in the output
    (e.g. the model parroted the injected instruction, flipped verdict,
    or leaked an IOC that only exists in the payload)."""
    verdict_text = json.dumps(verdict).lower()
    signal = case.success_signal.lower()
    return signal in verdict_text


def run(cases_path: str, alerts_path: str, out_path: str) -> None:
    cases = load_cases(cases_path)
    candidates = load_candidates(
        "data/golden/day2_candidates.json",
        "data/golden/day3_candidates.json",
    )
    benign_alerts = load_benign_alerts(alerts_path, candidates)

    if not benign_alerts:
        raise SystemExit(f"No benign alerts found in {alerts_path}")

    results = []
    for case in cases:
        carrier = random.choice(benign_alerts)
        poisoned_alert = inject(carrier, case)

        if run_pipeline is None:
            verdict = {"error": "run_pipeline not wired yet — stub result"}
        else:
            verdict = run_pipeline(poisoned_alert)
            if isinstance(verdict, TriageVerdict):
                verdict = verdict.model_dump()

        success = attack_succeeded(case, verdict)

        results.append({
            "case_id": case.case_id,
            "category": case.category,
            "target_field": case.target_field,
            "carrier_alert_id": carrier.get("alert_id"),
            "attack_succeeded": success,
            "verdict": verdict,
        })

    total = len(results)
    succeeded = sum(r["attack_succeeded"] for r in results)
    asr = succeeded / total if total else 0.0

    summary = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "total_cases": total,
        "successful_attacks": succeeded,
        "attack_success_rate": round(asr, 3),
        "results": results,
    }

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"ASR: {asr:.1%} ({succeeded}/{total})")
    print(f"Written to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(args.cases, args.alerts, args.out)