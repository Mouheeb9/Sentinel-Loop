"""Grade a generated Sigma rule: compiles? catches held-out attacks? fires on benign activity?

Owner: Mouadh (Day 12). Change the signature of `validate` only by a PR both of us review, like
`schemas.py`. Where the samples come from, and why, is in data/validation/README.md.

v0 corpus:
- Positives (must fire): golden true_positive alerts labeled with a technique the rule claims
  (a claimed parent covers its sub-techniques), in the rule's log source, never from the capture
  the source alert came from (leakage rule: a rule can't prove itself on its own capture).
  Sibling sub-techniques (rule claims T1218.005, alert is T1218.011) are reported, not required.
- Negatives (must not fire): golden benign_noisy alerts + the hand-checked background events
  (tests/fixtures/sysmon/bg_*.json), in the rule's log source.
- Noise check (reported, not graded): the held-out capture pool (data/validation/), about 10k
  unlabeled Sysmon events. Those captures contain attacks too, so a hit there is not a false
  positive, but hundreds of hits mean the rule is too broad. Skipped when data/raw/ is absent (CI).

v2 (Day 16): when the source alert has a procedure in data/golden/procedures.yaml and the rule
claims its technique, positives = same procedure only (procedure_recall); the technique's other
procedures are reported as sibling_recall, not graded. evidence = low with <=1 positive.

The feedback never quotes event values (they are attacker-written): it names alert ids and rule
fields. The repair loop looks values up through `failed_samples[].event_ref` and quotes them as
untrusted, like rule_gen's self-check does.
"""

from __future__ import annotations

import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.schemas import Alert, Event, FailedSample, ValidationResult
from sentinel.validation import matcher as matcher_module

ROOT = Path(__file__).resolve().parents[3]
GOLDEN_LABELS = ROOT / "data" / "golden" / "v1.1.jsonl"
PROCEDURES = ROOT / "data" / "golden" / "procedures.yaml"  # alert_id -> technique/procedure (v2)
GOLDEN_ALERTS = [ROOT / "data" / "golden" / f"day{d}_candidates.json" for d in (2, 3)]
POOL_LIST = ROOT / "data" / "validation" / "validation_datasets.txt"
CAPTURES = ROOT / "data" / "raw" / "security-datasets"
BACKGROUND = ROOT / "tests" / "fixtures" / "sysmon"  # hand-checked non-attack events (bg_*)
BENIGN = ROOT / "data" / "validation" / "benign"  # v2: hand-checked benign events (*.jsonl)

# Sysmon EventIDs each rule_form category reads (the sysmon pipeline adds the same filter).
CATEGORY_EVENT_IDS = {
    "process_creation": {1},
    "network_connection": {3},
    "registry_set": {13},
    "registry_event": {12, 13, 14},
    "registry_add": {12},
}
# Filtering a rule by process name: the attacker runs from that name and is never seen (RG-3).
NAME_FIELDS = {"Image", "ParentImage", "OriginalFileName"}
# A forward-slash Windows path in a non-path field: Sysmon writes '\', so the value never matches.
SLASH_PATH = re.compile(
    r"(?i)(?:^|[\\/:])(windows|users|appdata|programdata|system32|syswow64|temp|tasks)/"
)
POOL_BROAD = 20  # pool hits from which the feedback calls the rule broad


@dataclass(frozen=True)
class Sample:
    alert_id: str
    label: str
    technique_ids: tuple[str, ...]
    capture: str
    event: Event
    procedure: str | None = None  # from procedures.yaml; None = not grouped yet


@dataclass(frozen=True)
class Corpus:
    golden: list[Sample]
    pool: list[tuple[str, Event]] | None = None  # (capture, event); None = not available
    notes: list[str] = field(default_factory=list)


def validate(rule_yaml: str, source_alert: Alert, technique_ids: list[str]) -> ValidationResult:
    """The rule's ValidationResult against the v0 corpus (see the module docstring)."""
    return grade(rule_yaml, source_alert, technique_ids, default_corpus())


def grade(
    rule_yaml: str, source_alert: Alert, technique_ids: list[str], corpus: Corpus
) -> ValidationResult:
    rule, error = _parse(rule_yaml)
    rule_id = str((rule or {}).get("id") or "unknown")
    if error is None:
        try:
            matcher_module.match(rule_yaml, [])  # compiles, or ValueError
        except ValueError as e:
            error = str(e)
    if error is not None:
        return ValidationResult(
            rule_id=rule_id,
            compiled=False,
            compile_errors=[error],
            true_positives=0,
            false_positives=0,
            fp_rate=0.0,
            feedback=f"does not compile: {error}",
        )

    category = (rule.get("logsource") or {}).get("category")
    event_ids = CATEGORY_EVENT_IDS.get(category)
    claimed = {t.upper() for t in technique_ids}
    source_capture = _source_capture(source_alert, corpus)
    source_events = {e.event_id for e in source_alert.events}

    def usable(s: Sample) -> bool:
        return (
            s.alert_id != source_alert.alert_id
            and s.capture != source_capture
            and s.event.event_id not in source_events
            and (event_ids is None or _eid(s.event) in event_ids)
        )

    held_out = [s for s in corpus.golden if s.label == "true_positive" and usable(s)]
    # v2: when the source alert has a procedure and the rule claims its technique, only the same
    # procedure must fire; other procedures of the technique are siblings (reported, not graded).
    # Otherwise (alert not in golden, or triage claimed another technique) v0: by technique.
    procedure = _source_procedure(source_alert, corpus)
    if procedure and _relation(claimed, (procedure.split("/")[0],)) != "same":
        procedure = None
    if procedure:
        positives = [s for s in held_out if s.procedure == procedure]
        siblings = [
            s
            for s in held_out
            if s.procedure != procedure and _relation(claimed, s.technique_ids) is not None
        ]
    else:
        positives = [s for s in held_out if _relation(claimed, s.technique_ids) == "same"]
        siblings = [s for s in held_out if _relation(claimed, s.technique_ids) == "sibling"]
    benign = [s for s in corpus.golden if s.label == "benign_noisy" and usable(s)]
    same_capture = [
        s
        for s in corpus.golden
        if s.label == "true_positive"
        and s.capture == source_capture
        and s.alert_id != source_alert.alert_id
        and _relation(claimed, s.technique_ids) == "same"
        and (procedure is None or s.procedure == procedure)
    ]

    fired = set(matcher_module.match(rule_yaml, [s.event for s in positives + siblings + benign]))
    hits = [s for s in positives if s.event.event_id in fired]
    misses = [s for s in positives if s.event.event_id not in fired]
    fps = [s for s in benign if s.event.event_id in fired]
    sibling_hits = [s for s in siblings if s.event.event_id in fired]

    failed = [_failed(s, should_fire=True) for s in misses] + [
        _failed(s, should_fire=False) for s in fps
    ]

    target = (
        f"{procedure} (procedure)" if procedure else "/".join(sorted(claimed)) or "no technique"
    )
    evidence = "low" if len(positives) <= 1 else "ok"
    lines = [_tp_line(target, category, positives, hits, misses, same_capture)]
    if evidence == "low":
        lines.append(
            f"evidence: low ({len(positives)} held-out positive): a pass here proves little, "
            "flag for human review"
        )
    lines.append(
        f"benign: fires on {len(fps)}/{len(benign)} benign_noisy events in {category}"
        + (f" ({_ids(fps)}): too broad, tighten the selection" if fps else "")
    )
    if siblings:
        lines.append(
            f"siblings (info, not graded): fires on {len(sibling_hits)}/{len(siblings)} "
            f"attacks of another {'procedure or ' if procedure else ''}sub-technique"
        )
    lines.append(_pool_line(rule_yaml, corpus, source_capture, event_ids, category))
    lines += _lint(rule)
    lines += corpus.notes

    return ValidationResult(
        rule_id=rule_id,
        compiled=True,
        true_positives=len(hits),
        false_positives=len(fps),
        fp_rate=len(fps) / len(benign) if benign else 0.0,
        failed_samples=failed,
        feedback="\n".join(line for line in lines if line),
        evidence=evidence,
        procedure_recall=len(hits) / len(positives) if procedure and positives else None,
        sibling_recall=len(sibling_hits) / len(siblings) if siblings else None,
    )


@cache
def default_corpus() -> Corpus:
    labels = [
        json.loads(line)
        for line in GOLDEN_LABELS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    alerts: dict[str, Alert] = {}
    for path in GOLDEN_ALERTS:
        for c in json.loads(path.read_text(encoding="utf-8")):
            alerts[c["alert"]["alert_id"]] = Alert.model_validate(c["alert"])
    procedures = load_procedures(labels)
    golden = [
        Sample(
            row["alert_id"],
            row["label"],
            tuple(row["technique_ids"]),
            row["source_dataset"],
            e,
            procedures.get(row["alert_id"]),
        )
        for row in labels
        if row["alert_id"] in alerts
        for e in alerts[row["alert_id"]].events
    ]
    seen = {s.event.event_id for s in golden}
    for path in sorted(BACKGROUND.glob("bg_*.json")):  # labeled background events (Day 2)
        e = sysmon_to_event(json.loads(path.read_text(encoding="utf-8")))
        if e and e.event_id not in seen:
            golden.append(Sample(f"bg:{path.stem}", "benign_noisy", (), "background", e))
            seen.add(e.event_id)
    for path in sorted(BENIGN.glob("*.jsonl")):  # v2: {"id", "why", "event"} per line
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line) if line.strip() else None
            e = row and sysmon_to_event(row["event"])
            if e and e.event_id not in seen:
                seen.add(e.event_id)
                golden.append(
                    Sample(f"bg:{row['id']}", "benign_noisy", (), f"benign:{path.stem}", e)
                )
    pool, notes = _load_pool()
    return Corpus(golden=golden, pool=pool, notes=notes)


def load_procedures(labels: list[dict[str, Any]], path: Path = PROCEDURES) -> dict[str, str]:
    """alert_id -> procedure id. Raises ValueError when a row is not a golden true_positive or
    the procedure's technique part is not one of the row's labels (labels win, never this file)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = {r["alert_id"]: r for r in labels}
    bad = []
    for alert_id, proc in raw.items():
        row = rows.get(alert_id)
        technique, _, name = str(proc).partition("/")
        if row is None or row["label"] != "true_positive":
            bad.append(f"{alert_id}: not a golden true_positive")
        elif not name or technique not in row["technique_ids"]:
            bad.append(f"{alert_id}: {proc!r} must be <one of {row['technique_ids']}>/<name>")
    if bad:
        raise ValueError(f"{path.name}: " + "; ".join(bad))
    return {str(k): str(v) for k, v in raw.items()}


def _load_pool() -> tuple[list[tuple[str, Event]] | None, list[str]]:
    names = [n.strip() for n in POOL_LIST.read_text(encoding="utf-8").splitlines() if n.strip()]
    present = [n for n in names if (CAPTURES / n).exists()]
    if not present:
        return None, ["noise check skipped: held-out captures not downloaded (README Setup)"]
    pool: list[tuple[str, Event]] = []
    for name in present:
        with zipfile.ZipFile(CAPTURES / name) as zf:
            for member in zf.namelist():
                if member.startswith("__MACOSX") or not member.endswith(".json"):
                    continue
                for line in zf.read(member).decode("utf-8", errors="replace").splitlines():
                    if line.strip() and (e := sysmon_to_event(json.loads(line))):
                        pool.append((name, e))
    missing = len(names) - len(present)
    return pool, [
        f"noise check used {len(present)}/{len(names)} held-out captures"
    ] if missing else []


def _parse(rule_yaml: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        return None, f"invalid YAML: {e}"
    if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
        return None, "not a Sigma rule: no detection section"
    return rule, None


def _source_capture(alert: Alert, corpus: Corpus) -> str | None:
    """The capture the source alert came from: by alert id, else by any shared event."""
    events = {e.event_id for e in alert.events}
    for s in corpus.golden:
        if s.alert_id == alert.alert_id or s.event.event_id in events:
            return s.capture
    return None


def _source_procedure(alert: Alert, corpus: Corpus) -> str | None:
    """The source alert's procedure (procedures.yaml), by alert id, else by any shared event."""
    events = {e.event_id for e in alert.events}
    for s in corpus.golden:
        if s.procedure and (s.alert_id == alert.alert_id or s.event.event_id in events):
            return s.procedure
    return None


def _eid(e: Event) -> int | None:
    """The Sysmon EventID as an int (exports carry it as a number or a string)."""
    try:
        return int(e.raw.get("EventID"))
    except (TypeError, ValueError):
        return None


def _parent(t: str) -> str:
    return t.upper().split(".")[0]


def _relation(claimed: set[str], gold: tuple[str, ...]) -> str | None:
    """'same' when the alert carries a claimed technique (a claimed parent covers its subs),
    'sibling' when it only shares a parent, else None."""
    for g in (t.upper() for t in gold):
        if g in claimed or _parent(g) in claimed:
            return "same"
    if {_parent(g) for g in gold} & {_parent(c) for c in claimed}:
        return "sibling"
    return None


def _failed(s: Sample, should_fire: bool) -> FailedSample:
    return FailedSample(
        sample_id=s.alert_id,
        should_fire=should_fire,
        did_fire=not should_fire,
        event_ref=f"golden:{s.alert_id}/{s.event.event_id}",
        note=(
            f"held-out {'/'.join(s.technique_ids)} attack, rule did not fire"
            if should_fire
            else "benign_noisy event, rule fired"
        ),
    )


def _ids(samples: list[Sample], limit: int = 5) -> str:
    ids = [s.alert_id for s in samples]
    return ", ".join(ids[:limit]) + (f" +{len(ids) - limit} more" if len(ids) > limit else "")


def _tp_line(techniques, category, positives, hits, misses, same_capture) -> str:
    if not positives:
        gap = (
            f" ({len(same_capture)} more in the source capture, not usable)" if same_capture else ""
        )
        return (
            f"TP unknown: no held-out {techniques} attack in {category} outside the source "
            f"capture{gap} (data gap, not a rule failure)"
        )
    line = f"TP: fires on {len(hits)}/{len(positives)} held-out {techniques} attacks in {category}"
    if misses:
        line += f"; missed {_ids(misses)}: compare their fields with the selection"
    return line


def _pool_line(
    rule_yaml: str,
    corpus: Corpus,
    source_capture: str | None,
    event_ids: set[int] | None,
    category: str | None,
) -> str:
    if corpus.pool is None:
        return ""
    events = [
        e
        for capture, e in corpus.pool
        if capture != source_capture and (event_ids is None or _eid(e) in event_ids)
    ]
    fired = set(matcher_module.match(rule_yaml, events))
    if not fired:
        return f"noise: 0/{len(events)} held-out pool events in {category} fire"
    by_capture = Counter(c for c, e in corpus.pool if e.event_id in fired)
    line = (
        f"noise: fires on {len(fired)}/{len(events)} held-out pool events in {category}, "
        f"{len(by_capture)} captures (unlabeled, may include real attacks)"
    )
    if len(fired) >= POOL_BROAD:
        line += ": likely too broad"
    return line


def lint(rule_yaml: str) -> list[str]:
    """The structure problems of a rule (the `_lint` lines); [] when it doesn't parse."""
    rule, error = _parse(rule_yaml)
    return [] if error else _lint(rule)


def _lint(rule: dict[str, Any]) -> list[str]:
    """Structure problems no sample shows: filter evasion (RG-3) and values that can't match."""
    out = []
    for name, block in rule["detection"].items():
        if name == "condition" or not isinstance(block, dict):
            continue
        for key, values in block.items():
            fld = key.split("|")[0]
            values = values if isinstance(values, list) else [values]
            if name.startswith("filter") and fld in NAME_FIELDS:
                out.append(
                    f"risk: {name} excludes by {fld}: an attacker running from that process name "
                    f"is never detected (RG-3); filter on something the attacker can't choose"
                )
            if fld not in {"Image", "ParentImage", "TargetObject", "CurrentDirectory"}:
                dead = [v for v in values if isinstance(v, str) and SLASH_PATH.search(v)]
                if dead:
                    out.append(
                        f"dead values: {len(dead)} {name}.{fld} value(s) use '/' path separators; "
                        f"Windows logs use '\\', so they never match"
                    )
    return out
