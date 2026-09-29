"""Turn evals/golden_spec_day3.yaml into candidate alerts and draft labels.

    uv run python -m evals.mine_candidates            # dry run: print what would be written
    uv run python -m evals.mine_candidates --write    # write candidates + append draft labels

The spec names, per capture, the exact event that gets each label and why. Every selector must
match; a technique ID must be live in the current ATT&CK release; no event may be picked twice
or already be in the Day 2 candidates. Anything else aborts, so the output is never a silent
approximation of the spec. Alert IDs are assigned after a seeded shuffle so true positives and
benign alerts are interleaved (no label pattern in the ordering).
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import zipfile
from datetime import date
from pathlib import Path

import yaml

from evals.check_labels import TechniqueIndex
from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.schemas import Alert, Event

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "data" / "raw" / "security-datasets"
GOLDEN = ROOT / "data" / "golden"
SPEC = Path(__file__).parent / "golden_spec_day3.yaml"
FIRST_ID = 41  # alerts 1-40 are the Day 2 batch
SEED = 41
LABELER = "claude-draft"
DETECTION_NAME = "Atomic capture — manual review"  # identical for every alert: no label leak


def load_events(dataset: str) -> list[Event]:
    zf = zipfile.ZipFile(CAPTURES / f"{dataset}.zip")
    events = []
    for line in zf.open(zf.namelist()[0]):
        try:
            event = sysmon_to_event(json.loads(line))
        except Exception:
            continue
        if event:
            events.append(event)
    return events


def kind_of(e: Event) -> str:
    return "network" if e.network else "registry" if e.registry else "process"


def _search(pattern: str, value: str | None) -> bool:
    return bool(re.search(pattern, value or "", re.IGNORECASE))


def matches(e: Event, m: dict[str, str]) -> bool:
    if kind_of(e) != m.get("kind", "process"):
        return False
    p = e.process
    fields = {
        "image": p.image if p else None,
        "cmd": p.command_line if p else None,
        "parent": p.parent.image if p and p.parent else None,
        "dst": f"{e.network.dst_ip}:{e.network.dst_port}" if e.network else None,
        "key": e.registry.target_object if e.registry else None,
        "details": e.registry.details if e.registry else None,
    }
    return all(_search(pattern, fields[f]) for f, pattern in m.items() if f in fields)


def summary(e: Event) -> str:
    parts = [f"host={e.host}", f"user={e.user}"]
    p = e.process
    if p:
        parts.append(f"image={p.image}")
        if p.command_line:
            parts.append(f"cmd={p.command_line!r}")
        if p.parent and p.parent.image:
            parts.append(f"parent={p.parent.image}")
    if e.network:
        parts.append(f"net={e.network.src_ip}->{e.network.dst_ip}:{e.network.dst_port}")
    if e.registry:
        parts.append(f"reg_key={e.registry.target_object}")
        parts.append(f"reg_value={e.registry.details}")
    return " | ".join(parts)


def used_in_day2() -> set[str]:
    rows = json.loads((GOLDEN / "day2_candidates.json").read_text(encoding="utf-8"))
    return {ev["event_id"] for r in rows for ev in r["alert"]["events"]}


def build(spec_path: Path = SPEC) -> list[dict]:
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    index = TechniqueIndex()
    taken = used_in_day2()
    items: list[dict] = []
    errors: list[str] = []
    for ds in spec["datasets"]:
        capture = ds.get("dataset", ds["name"])  # an entry may reuse a capture under another name
        events = load_events(capture)
        for it in ds["items"]:
            hits = [e for e in events if matches(e, it["match"])]
            nth = it.get("nth", 0)
            if len(hits) <= nth:
                errors.append(f"{ds['name']}: no event matches {it['match']} (nth={nth})")
                continue
            event = hits[nth]
            if event.event_id in taken:
                errors.append(f"{ds['name']}: {it['match']} picks an event already used")
                continue
            taken.add(event.event_id)
            techniques = it.get("technique", [])
            for t in techniques:
                if index.problem_for("spec", t):
                    errors.append(f"{ds['name']}: technique {t} is not live in this ATT&CK")
            if (it["label"] == "true_positive") != bool(techniques):
                errors.append(f"{ds['name']}: only true positives carry technique IDs")
            items.append(
                {
                    "dataset": capture,
                    "label": it["label"],
                    "techniques": techniques,
                    "why": it["why"],
                    "event": event,
                    "candidates_matched": len(hits),
                }
            )
    if errors:
        raise SystemExit("spec errors:\n  " + "\n  ".join(errors))
    random.Random(SEED).shuffle(items)
    for i, item in enumerate(items, start=FIRST_ID):
        item["alert_id"] = f"day3-{i:03d}"
    return items


def to_candidate(item: dict) -> dict:
    alert = Alert(
        alert_id=item["alert_id"],
        detection_name=DETECTION_NAME,
        severity="medium",
        events=[item["event"]],
    )
    return {
        "candidate_id": item["alert_id"],
        "kind": "attack_capture" if item["label"] == "true_positive" else "background",
        "source_dataset": f"{item['dataset']}.zip",
        "alert": alert.model_dump(mode="json"),
    }


def to_label_row(item: dict) -> dict:
    return {
        "alert_id": item["alert_id"],
        "label": item["label"],
        "technique_ids": item["techniques"],
        "source_dataset": f"{item['dataset']}.zip",
        "rationale": item["why"],
        "labeler": LABELER,
        "labeled_at": date.today().isoformat(),
    }


def write(items: list[dict]) -> None:
    ordered = sorted(items, key=lambda i: i["alert_id"])
    (GOLDEN / "day3_candidates.json").write_text(
        json.dumps([to_candidate(i) for i in ordered], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md = [
        f"# Day 3 labeling candidates: {len(ordered)} items\n",
        "Draft labels for these are already in `labels.jsonl` (labeler `claude-draft`); "
        "judge each one yourself and overwrite where you disagree.\n",
    ]
    for i in ordered:
        md.append(f"## {i['alert_id']}  (source: {i['dataset']}.zip)\n{summary(i['event'])}\n")
    (GOLDEN / "day3_candidates.md").write_text("\n".join(md), encoding="utf-8")

    labels = GOLDEN / "labels.jsonl"
    kept = [
        ln
        for ln in labels.read_bytes().decode("utf-8").splitlines(keepends=True)
        if ln.strip() and not json.loads(ln)["alert_id"].startswith("day3-")
    ]
    if kept and not kept[-1].endswith("\n"):
        kept[-1] += "\n"
    new = [json.dumps(to_label_row(i), ensure_ascii=False) + "\n" for i in ordered]
    labels.write_bytes("".join(kept + new).encode("utf-8"))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    items = build()
    counts: dict[str, int] = {}
    for i in sorted(items, key=lambda i: i["alert_id"]):
        counts[i["label"]] = counts.get(i["label"], 0) + 1
        tech = ",".join(i["techniques"]) or "-"
        e = i["event"]
        what = (
            (e.process.command_line or e.process.image)
            if e.process and kind_of(e) == "process"
            else summary(e).split(" | ", 2)[-1]
        )
        print(f"{i['alert_id']} {i['label']:13} {tech:18} {i['dataset'][:34]:34} {str(what)[:70]}")
    techniques = {t for i in items for t in i["techniques"]}
    print(f"\n{len(items)} alerts {counts}; {len(techniques)} distinct technique IDs in this batch")
    if args.write:
        write(items)
        print("written: day3_candidates.json/.md and draft rows appended to labels.jsonl")
    else:
        print("dry run only (add --write to persist)")


if __name__ == "__main__":
    main()
