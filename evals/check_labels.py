"""Check the golden labels' ATT&CK technique IDs against the current ATT&CK release.

    uv run python -m evals.check_labels          # report problems, exit 1 if any
    uv run python -m evals.check_labels --fix    # also rewrite IDs that have ONE clear successor

ATT&CK renumbers, merges and retires techniques between releases; an old ID stays in the data
stamped `revoked` (replaced) or `deprecated` (retired). A label using one would silently never
match a live technique. `--fix` only touches the `technique_ids` array of affected labels and
only when the replacement is unambiguous; everything else is reported for a human to decide.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.retrieval.attack import DEFAULT_BUNDLE, _is_live, _technique_id

LABELS = Path(__file__).resolve().parents[1] / "data" / "golden" / "labels.jsonl"
_TECHNIQUE_IDS_ARRAY = re.compile(r'("technique_ids"\s*:\s*\[)([^\]]*)(\])')


@dataclass(frozen=True)
class Problem:
    alert_id: str
    technique_id: str
    kind: str  # "revoked" | "deprecated" | "unknown"
    successors: tuple[str, ...] = ()

    @property
    def auto_fixable(self) -> bool:
        return self.kind == "revoked" and len(self.successors) == 1

    def message(self) -> str:
        # plain ASCII " - ": Windows consoles often cannot render an em dash
        head = f"alert {self.alert_id} uses {self.technique_id} - "
        if self.kind == "unknown":
            return head + "not a known ATT&CK technique (typo?); fix by hand"
        if self.kind == "deprecated":
            return head + "deprecated, no replacement; relabel by hand"
        if not self.successors:
            return head + "revoked, no replacement found; relabel by hand"
        if len(self.successors) == 1:
            return head + f"revoked, use {self.successors[0]}"
        return head + f"revoked, split into several: {', '.join(self.successors)}; pick one by hand"


class TechniqueIndex:
    """Which technique IDs exist, which are dead, and what replaced the revoked ones."""

    def __init__(self, bundle_path: Path = DEFAULT_BUNDLE) -> None:
        objects: list[dict[str, Any]] = json.loads(bundle_path.read_text(encoding="utf-8"))[
            "objects"
        ]
        self._by_stix = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
        self._by_ext = {}
        for o in self._by_stix.values():
            ext = _technique_id(o)
            if ext:
                self._by_ext[ext] = o
        self._revoked_by: dict[str, list[str]] = defaultdict(list)
        for o in objects:
            if (
                o["type"] == "relationship"
                and o["relationship_type"] == "revoked-by"
                and o["source_ref"] in self._by_stix
                and o["target_ref"] in self._by_stix
            ):
                self._revoked_by[o["source_ref"]].append(o["target_ref"])

    def _live_successors(self, stix_id: str, seen: frozenset[str] = frozenset()) -> list[str]:
        """Follow revoked-by links (a successor may itself have been revoked) to live IDs."""
        found: list[str] = []
        for target in self._revoked_by.get(stix_id, []):
            if target in seen:
                continue
            obj = self._by_stix[target]
            if _is_live(obj):
                found.append(_technique_id(obj))
            else:
                found += self._live_successors(target, seen | {stix_id})
        return sorted(set(found))

    def problem_for(self, alert_id: str, technique_id: str) -> Problem | None:
        obj = self._by_ext.get(technique_id)
        if obj is None:
            return Problem(alert_id, technique_id, "unknown")
        if _is_live(obj):
            return None
        if obj.get("revoked"):
            return Problem(
                alert_id, technique_id, "revoked", tuple(self._live_successors(obj["id"]))
            )
        return Problem(alert_id, technique_id, "deprecated")


def read_labels(labels_path: Path = LABELS) -> list[dict[str, Any]]:
    text = labels_path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def check_labels(labels_path: Path = LABELS, index: TechniqueIndex | None = None) -> list[Problem]:
    index = index or TechniqueIndex()
    problems = []
    for row in read_labels(labels_path):
        for tid in row.get("technique_ids", []):
            problem = index.problem_for(row["alert_id"], tid)
            if problem:
                problems.append(problem)
    return problems


def fix_labels(labels_path: Path, problems: list[Problem]) -> list[Problem]:
    """Rewrite unambiguous revoked IDs in place. Returns the problems that were fixed.

    Works on bytes and touches only the `technique_ids` array of affected lines, so the rest of
    the file (key order, spacing, line endings) is left byte-for-byte alone.
    """
    fixable: dict[str, dict[str, str]] = defaultdict(dict)
    for p in problems:
        if p.auto_fixable:
            fixable[p.alert_id][p.technique_id] = p.successors[0]
    if not fixable:
        return []

    fixed: list[Problem] = []
    out: list[str] = []
    for line in labels_path.read_bytes().decode("utf-8").splitlines(keepends=True):
        row = json.loads(line) if line.strip() else None
        if row and row["alert_id"] in fixable:
            mapping = fixable[row["alert_id"]]
            new_ids = list(dict.fromkeys(mapping.get(t, t) for t in row["technique_ids"]))
            rendered = ", ".join(json.dumps(t) for t in new_ids)
            new_line = _TECHNIQUE_IDS_ARRAY.sub(
                lambda m, r=rendered: m.group(1) + r + m.group(3), line, count=1
            )
            after = json.loads(new_line)
            assert after["technique_ids"] == new_ids  # the rewrite must say what we meant
            assert {k: v for k, v in after.items() if k != "technique_ids"} == {
                k: v for k, v in row.items() if k != "technique_ids"
            }  # ...and nothing else may have changed
            line = new_line
            fixed += [p for p in problems if p.alert_id == row["alert_id"] and p.auto_fixable]
        out.append(line)
    labels_path.write_bytes("".join(out).encode("utf-8"))
    return fixed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", type=Path, default=LABELS)
    ap.add_argument("--fix", action="store_true", help="rewrite IDs with a single clear successor")
    args = ap.parse_args()

    index = TechniqueIndex()
    rows = read_labels(args.labels)
    problems = check_labels(args.labels, index)
    if args.fix:
        for p in fix_labels(args.labels, problems):
            print(f"fixed  alert {p.alert_id}: {p.technique_id} -> {p.successors[0]}")
        problems = check_labels(args.labels, index)

    used = {t for r in rows for t in r.get("technique_ids", [])}
    for p in problems:
        print(p.message())
    print(f"{len(rows)} labels, {len(used)} distinct technique IDs, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
