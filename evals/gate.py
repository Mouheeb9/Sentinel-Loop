"""Triage eval gate for CI (Day 17): no model calls, no database, no secrets.

    uv run python -m evals.gate                     # exit 1 when the gate fails
    uv run python -m evals.gate --write-attack-map  # refresh data/attack/attack_map.json

CI can't call the model, so it checks the measured numbers instead of making new ones:
1. **Prompt guard.** The committed dev results (config/eval_gate.yaml) must have been produced by
   the triage input the code builds today: same prompt hash, models, search method and alerts.
   A PR that changes any of it fails until it re-measures on dev and commits the new results.
2. **Re-score.** The stored answers are scored again with the current labels and scorers, so a
   label edit or a scorer change shows up in the numbers.
3. **Floors.** Accuracy, attack recall, technique F1 and schema validity must stay above their
   floors, and the invented-IOC rate below its ceiling.

The scorer needs ATT&CK tactics and renames; the STIX bundle is gitignored (~45 MB), so a small
derived map is committed at data/attack/attack_map.json (the bundle wins when present).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from evals.eval_row import EvalRow
from evals.scorers import DEFAULT_BUNDLE, AttackMap, score_all
from evals.split import load_split

ROOT = Path(__file__).parent.parent
GATE_CONFIG = ROOT / "config" / "eval_gate.yaml"
ATTACK_MAP = ROOT / "data" / "attack" / "attack_map.json"
# Fingerprint keys that shape the model input: a mismatch means the results are stale.
INPUT_KEYS = ("config", "retrieval", "tools", "tier1_model", "tier2_model", "escalate_below",
              "prompt_sha", "alerts_sha", "search")  # fmt: skip


def load_attack_map() -> AttackMap:
    if DEFAULT_BUNDLE.exists():
        return AttackMap.from_bundle()
    data = json.loads(ATTACK_MAP.read_text(encoding="utf-8"))
    return AttackMap({t: frozenset(v) for t, v in data["tactics"].items()}, data["renames"])


def write_attack_map(path: Path = ATTACK_MAP) -> Path:
    m = AttackMap.from_bundle()
    data = {
        "source": "derived from the MITRE ATT&CK enterprise bundle by evals/gate.py",
        "tactics": {t: sorted(v) for t, v in sorted(m.tactics.items())},
        "renames": dict(sorted(m.renames.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    return path


def current_fingerprint(config: str) -> dict[str, Any]:
    from evals.run import CONFIGS, fingerprint  # heavy imports, only when needed

    return fingerprint(config, CONFIGS[config])


def check(
    gate: dict, results: dict, current: dict, labels: list[dict], alerts, attack
) -> tuple[list[str], dict[str, float | None]]:
    """Every reason the gate fails (empty = pass), and the re-scored headline numbers."""
    problems = []
    meta = results["meta"]
    for key in INPUT_KEYS:
        if meta.get(key) != current.get(key):
            problems.append(
                f"stale results: {key} is {current.get(key)!r} now but {meta.get(key)!r} in "
                f"{gate['results']}. Re-measure on dev and point config/eval_gate.yaml at it."
            )
    split = meta.get("split") or {}
    ids, sha = load_split("dev")
    if split.get("name") != "dev" or split.get("sha") != sha:
        problems.append(f"results are not on the frozen dev split (got {split})")
    if not meta.get("complete"):
        problems.append("results are incomplete (missing alerts or transport errors)")

    truth = {lab["alert_id"]: lab for lab in labels}
    rows = [
        EvalRow.model_validate(
            r
            | {
                "label": truth[r["alert_id"]]["label"],
                "label_techniques": truth[r["alert_id"]]["technique_ids"],
            }
        )
        for r in results["rows"]
        if r["alert_id"] in truth
    ]
    if {r.alert_id for r in rows} != set(ids):
        problems.append("results rows don't cover exactly the dev split")
    scores = headline_scores(score_all(rows, alerts, attack))
    for name, floor in gate["floors"].items():
        if scores[name] is None or scores[name] < floor:
            problems.append(f"{name} {_fmt(scores[name])} is below the floor {floor}")
    for name, ceiling in gate["ceilings"].items():
        if scores[name] is None or scores[name] > ceiling:
            problems.append(f"{name} {_fmt(scores[name])} is above the ceiling {ceiling}")
    return problems, scores


def headline_scores(s: dict) -> dict[str, float | None]:
    return {
        "accuracy": s["triage"]["accuracy"],
        "attack_recall": s["triage"]["per_class_recall"]["true_positive"],
        "technique_f1": s["techniques"]["f1"],
        "schema_valid": s["schema"]["schema_valid_rate"],
        "invented_ioc_rate": s["iocs"]["hallucinated_ioc_rate"],
    }


def _fmt(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def main(argv: Sequence[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.gate")
    p.add_argument("--write-attack-map", action="store_true")
    args = p.parse_args(argv)
    if args.write_attack_map:
        print(f"written: {write_attack_map().relative_to(ROOT).as_posix()}")
        return

    from evals.triage_smoke import load_golden

    gate = yaml.safe_load(GATE_CONFIG.read_text(encoding="utf-8"))
    results = json.loads((ROOT / gate["results"]).read_text(encoding="utf-8"))
    labels, alerts = load_golden()
    problems, scores = check(
        gate, results, current_fingerprint(gate["config"]), labels, alerts, load_attack_map()
    )
    print(f"re-scored {gate['results']} with the current labels:")
    for name, value in scores.items():
        print(f"  {name:18} {_fmt(value)}")
    if problems:
        print("EVAL GATE FAILED:")
        for line in problems:
            print(f"  - {line}")
        raise SystemExit(1)
    print(f"eval gate passed: {gate['results']} (prompt {results['meta']['prompt_sha']})")


if __name__ == "__main__":
    main()
