"""Scorers: eval rows in, numbers out. Pure functions: no model calls, no DB.

Metrics (as defined in docs/labeling-guide.md):
- triage accuracy, three classes, with a confusion matrix
- technique precision / recall / F1 with partial credit (guide section 4)
- hallucinated-IOC rate: an IOC not present anywhere in the input event
- schema validity rate
- cost per alert and p95 latency

Input rows follow the `EvalRow` contract (evals/eval_row.py). An error row (no valid verdict) is
scored as a wrong answer with no techniques and no IOCs: it is never skipped, otherwise a model
that crashes on the hard alerts would look better than one that answers them.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evals.check_labels import TechniqueIndex
from evals.eval_row import EvalRow
from sentinel.retrieval.attack import DEFAULT_BUNDLE, _is_live, _technique_id
from sentinel.schemas import Alert

VERDICTS = ("true_positive", "benign_noisy", "needs_review")
ERROR = "error"  # column of the confusion matrix for rows with no valid verdict


# --- ATT&CK lookups -------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackMap:
    """What the technique scorer needs from ATT&CK: each technique's tactics, and old -> new
    IDs for techniques ATT&CK renumbered (T1562.002 -> T1685.001, ...).

    Built from the STIX bundle in real runs; tests build a small one by hand, so they run
    without the (gitignored) bundle.
    """

    tactics: Mapping[str, frozenset[str]]
    renames: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def from_bundle(cls, bundle_path: Path = DEFAULT_BUNDLE) -> AttackMap:
        objects = json.loads(bundle_path.read_text(encoding="utf-8"))["objects"]
        tactics: dict[str, frozenset[str]] = {}
        for o in objects:
            if o["type"] == "attack-pattern" and _is_live(o) and (tid := _technique_id(o)):
                tactics[tid] = frozenset(p["phase_name"] for p in o.get("kill_chain_phases", []))
        # A revoked ID with exactly one live successor is a rename; split ones stay as they are.
        index = TechniqueIndex(bundle_path)
        renames = {}
        for o in objects:
            if o["type"] == "attack-pattern" and o.get("revoked") and (tid := _technique_id(o)):
                problem = index.problem_for("-", tid)
                if problem and problem.auto_fixable:
                    renames[tid] = problem.successors[0]
        return cls(tactics, renames)

    def canonical(self, technique_id: str) -> str:
        tid = technique_id.strip().upper()
        return self.renames.get(tid, tid)

    def tactics_of(self, technique_id: str) -> frozenset[str]:
        """A sub-technique without its own tactics inherits its parent's."""
        tid = self.canonical(technique_id)
        return self.tactics.get(tid) or self.tactics.get(_parent(tid), frozenset())


def _parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


# --- technique precision / recall -------------------------------------------------------------


def credit(pred: str, gold: str, attack: AttackMap) -> float:
    """Partial credit for one predicted ID against one gold ID (labeling guide section 4).

    1.0 exact, 0.5 same parent technique (either side may be the parent), 0.25 a shared
    tactic, 0.0 otherwise. Both IDs are mapped through ATT&CK renames first.
    """
    p, g = attack.canonical(pred), attack.canonical(gold)
    if p == g:
        return 1.0
    if _parent(p) == _parent(g):
        return 0.5
    if attack.tactics_of(p) & attack.tactics_of(g):
        return 0.25
    return 0.0


def technique_scores(rows: Iterable[EvalRow], attack: AttackMap) -> dict[str, Any]:
    """Macro-averaged over alerts.

    Per alert: recall = mean over gold IDs of the best credit any prediction earns;
    precision = mean over predicted IDs of the best credit against any gold ID.
    - gold and pred both empty (a benign alert, correctly no technique): not scored.
    - gold empty, pred not empty: precision 0 (the techniques were invented).
    - gold not empty, pred empty (or an error row): recall 0, no precision term.
    Precision is averaged over alerts that predicted something, recall over alerts with gold
    techniques. F1 = 2PR / (P + R) of those two averages.
    """
    precisions: list[float] = []
    recalls: list[float] = []
    exact_primary = primary_total = 0
    for row in rows:
        gold, pred = row.label_techniques, (row.technique_ids if row.error is None else [])
        if gold:
            recalls.append(
                sum(max((credit(p, g, attack) for p in pred), default=0.0) for g in gold)
                / len(gold)
            )
            primary_total += 1
            exact_primary += bool(pred) and attack.canonical(pred[0]) == attack.canonical(gold[0])
        if pred:
            precisions.append(
                sum(max((credit(p, g, attack) for g in gold), default=0.0) for p in pred)
                / len(pred)
            )
    precision = sum(precisions) / len(precisions) if precisions else None
    recall = sum(recalls) / len(recalls) if recalls else None
    f1 = None
    if precision is not None and recall is not None:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "primary_exact_rate": exact_primary / primary_total if primary_total else None,
        "alerts_with_gold": len(recalls),
        "alerts_with_pred": len(precisions),
    }


# --- triage accuracy ------------------------------------------------------------------------


def triage_accuracy(rows: Iterable[EvalRow]) -> dict[str, Any]:
    """Three-class accuracy. confusion[label][predicted]; predicted is "error" for error rows.
    The costly cell is confusion["true_positive"]["benign_noisy"]: a missed attack."""
    confusion = {label: {v: 0 for v in (*VERDICTS, ERROR)} for label in VERDICTS}
    for row in rows:
        predicted = row.verdict if row.error is None and row.verdict else ERROR
        confusion[row.label][predicted] += 1
    total = sum(sum(r.values()) for r in confusion.values())
    correct = sum(confusion[v][v] for v in VERDICTS)
    per_class_recall = {
        label: (confusion[label][label] / n if (n := sum(confusion[label].values())) else None)
        for label in VERDICTS
    }
    return {
        "accuracy": correct / total if total else None,
        "n": total,
        "confusion": confusion,
        "per_class_recall": per_class_recall,
        "missed_attacks": confusion["true_positive"]["benign_noisy"],
    }


# --- hallucinated IOCs ----------------------------------------------------------------------


def _normalize(text: str) -> str:
    """Lowercase and forward slashes: the model writes C:/Users/... for C:\\Users\\..."""
    return text.lower().replace("\\", "/")


def _strings(value: Any) -> Iterable[str]:
    """Every string/number leaf of a JSON value (so escaping never hides a match)."""
    if isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


def hallucinated_iocs(ioc_refs: Iterable[str], alert: Alert) -> list[str]:
    """IOCs that appear nowhere in the input alert (its events, raw fields included).
    A set difference after normalizing both sides, not a judgement."""
    haystack = "\n".join(_normalize(s) for s in _strings(alert.model_dump(mode="json")))
    return [ioc for ioc in ioc_refs if ioc.strip() and _normalize(ioc.strip()) not in haystack]


def ioc_scores(rows: Iterable[EvalRow], alerts: Mapping[str, Alert]) -> dict[str, Any]:
    total = invented = alerts_hit = 0
    examples: list[dict[str, Any]] = []
    for row in rows:
        iocs = [i for i in row.ioc_refs if i.strip()] if row.error is None else []
        if not iocs:
            continue
        bad = hallucinated_iocs(iocs, alerts[row.alert_id])
        total += len(iocs)
        invented += len(bad)
        if bad:
            alerts_hit += 1
            examples.append({"alert_id": row.alert_id, "iocs": bad})
    return {
        "hallucinated_ioc_rate": invented / total if total else None,
        "iocs_total": total,
        "iocs_hallucinated": invented,
        "alerts_with_hallucination": alerts_hit,
        "examples": examples[:10],
    }


# --- schema validity, cost, latency ---------------------------------------------------------


def schema_scores(rows: Iterable[EvalRow]) -> dict[str, Any]:
    rows = list(rows)
    valid = [r for r in rows if r.error is None]
    return {
        "schema_valid_rate": len(valid) / len(rows) if rows else None,
        "first_try_rate": sum(r.schema_retries == 0 for r in valid) / len(rows) if rows else None,
        "errors": len(rows) - len(valid),
    }


def p95(values: Iterable[float]) -> float | None:
    """Nearest-rank 95th percentile: the smallest value with >= 95% of values at or below it."""
    ordered = sorted(values)
    if not ordered:
        return None
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def cost_latency_scores(rows: Iterable[EvalRow]) -> dict[str, Any]:
    """Cost is None when no row has a known cost (free models): unknown, not zero."""
    rows = list(rows)
    costs = [r.cost_usd for r in rows if r.cost_usd is not None]
    return {
        "cost_per_alert_usd": sum(costs) / len(costs) if costs else None,
        "cost_known_rows": len(costs),
        "latency_p95_s": p95(r.latency_s for r in rows),
    }


# --- entry point ----------------------------------------------------------------------------


def score_all(
    rows: Iterable[EvalRow | Mapping[str, Any]],
    alerts: Mapping[str, Alert],
    attack: AttackMap | None = None,
) -> dict[str, Any]:
    """Every metric for one config's rows. `alerts` maps alert_id -> input Alert (for IOCs)."""
    parsed = [r if isinstance(r, EvalRow) else EvalRow.model_validate(r) for r in rows]
    attack = attack or AttackMap.from_bundle()
    return {
        "triage": triage_accuracy(parsed),
        "techniques": technique_scores(parsed, attack),
        "iocs": ioc_scores(parsed, alerts),
        "schema": schema_scores(parsed),
        "cost_latency": cost_latency_scores(parsed),
    }
