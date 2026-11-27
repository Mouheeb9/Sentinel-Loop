"""Demo recordings: one pipeline run, node by node, saved so the demo page can replay it.

A recording is what `run_alert(on_event=...)` reported, turned into plain JSON:

    {"meta": {name, alert, models, recorded_at, path, outcome},
     "events": [{node, start, end, update}, ...]}

The demo page (app/demo.py) draws a live run from the same events, so a replay shows exactly what
the live run showed, with its real per-node timings.

    uv run python -m sentinel.demo record --alert-id day3-070 --name full-loop
    uv run python -m sentinel.demo record --alert path/to/alert.json --name my-alert
    uv run python -m sentinel.demo list
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel

from sentinel.schemas import Alert

ROOT = Path(__file__).resolve().parents[2]
RECORDINGS = ROOT / "results" / "demo"
# Where --alert-id looks: the golden candidates and the tools eval set (same file schema).
ALERT_SOURCES = (
    ROOT / "data" / "golden" / "day2_candidates.json",
    ROOT / "data" / "golden" / "day3_candidates.json",
    ROOT / "data" / "tools-eval" / "candidates.json",
)


def to_jsonable(x: Any) -> Any:
    """Node updates hold pydantic models (Hit, TriageVerdict, ValidationResult...): plain JSON."""
    if isinstance(x, BaseModel):
        return x.model_dump(mode="json")
    if isinstance(x, dict):
        return {str(k): to_jsonable(v) for k, v in x.items()}
    if isinstance(x, list | tuple | set):
        return [to_jsonable(v) for v in x]
    if isinstance(x, datetime | date):
        return x.isoformat()
    if x is None or isinstance(x, str | int | float | bool):
        return x
    return str(x)


def attach_lookup_answers(event: dict, cache: Any = None) -> dict:
    """Triage records which lookups it made, not what came back. The answer is in tool_cache
    (every lookup goes through it), so read it there for the screen. Best effort: no cache, no
    answer shown."""
    if event.get("node") != "triage":
        return event
    from sentinel.tools import nvd, threatfox
    from sentinel.tools.cache import default_cache

    for run in event.get("update", {}).get("triage_runs") or []:
        for look in run.get("lookups") or []:
            value = next(iter((look.get("args") or {}).values()), "")
            try:
                if look["name"] == nvd.NAME:
                    key = nvd.normalize_cve(value)
                else:
                    key = threatfox.classify(value)[1]
                look["answer"] = (cache or default_cache()).get(
                    look["name"], key, timedelta(days=36500)
                )
            except Exception:  # noqa: BLE001 - display only, never fail a recording
                look["answer"] = None
    return event


def find_alert(alert_id: str, sources: tuple[Path, ...] = ALERT_SOURCES) -> Alert:
    for src in sources:
        if not src.exists():
            continue
        for c in json.loads(src.read_text(encoding="utf-8")):
            if c["alert"]["alert_id"] == alert_id:
                return Alert.model_validate(c["alert"])
    raise SystemExit(f"alert {alert_id} not in {[s.name for s in sources]}")


def record(
    alert: Alert,
    name: str,
    *,
    live: bool = True,
    trace: bool = False,
    on_event: Callable[[dict], None] | None = None,
    stub: Any = None,
) -> dict:
    """Run the pipeline once and return the recording. `on_event` also gets each event (JSON form)
    as it happens, so a caller can draw while recording."""
    from sentinel.graph.nodes import StubScript
    from sentinel.run import default_owner, models_label, run_alert

    events: list[dict] = []

    def keep(ev: dict) -> None:
        ev = to_jsonable(ev)
        if live:
            ev = attach_lookup_answers(ev)
        events.append(ev)
        if on_event:
            on_event(ev)

    res = run_alert(
        alert,
        live=live,
        stub=stub or StubScript(),
        config_name="demo",
        owner=default_owner(),
        trace=trace,
        on_event=keep,
    )
    return {
        "meta": {
            "name": name,
            "alert": alert.model_dump(mode="json"),
            "models": models_label() if live else "stub",
            "recorded_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "path": res.path,
            "outcome": res.final.get("outcome"),
        },
        "events": events,
    }


def save(rec: dict, out_dir: Path = RECORDINGS) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{rec['meta']['name']}.json"
    path.write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load(path: Path) -> dict:
    rec = json.loads(path.read_text(encoding="utf-8"))
    if "meta" not in rec or "events" not in rec:
        raise ValueError(f"{path.name}: not a demo recording")
    return rec


def recordings(out_dir: Path | None = None) -> dict[str, Path]:
    """Saved recordings by name. SENTINEL_DEMO_DIR overrides the folder (tests)."""
    out_dir = out_dir or Path(os.environ.get("SENTINEL_DEMO_DIR") or RECORDINGS)
    return {p.stem: p for p in sorted(out_dir.glob("*.json"))} if out_dir.exists() else {}


# --- what the page draws (pure, so it's tested without Streamlit) ---------------------------

NODES = ("ingest", "enrich", "triage", "route", "rule_gen", "validate", "repair", "output")
# Where the run goes next when there's only one way: lit as "running" during a live run.
NEXT = {"ingest": "enrich", "enrich": "triage", "triage": "route"}
OK, BUSY, BAD, IDLE = "#16a34a", "#f59e0b", "#dc2626", "#9ca3af"


def graph_edges() -> list[tuple[str, str]]:
    """The pipeline's real edges, from the compiled graph (so the drawing can't drift)."""
    from sentinel.graph.build import build_graph

    g = build_graph(live=False).get_graph()
    return [(e.source, e.target) for e in g.edges]


def validation_verdict(update: dict) -> str | None:
    """passed / needs_review / failed for a validate event, None for other events."""
    from sentinel.graph.nodes import rule_verdict
    from sentinel.schemas import ValidationResult

    vals = update.get("validations") or []
    if not vals or update.get("validation_pending"):
        return None
    return rule_verdict(ValidationResult.model_validate(vals[-1]))


def graph_dot(events: list[dict], running: str | None = None, edges=None) -> str:
    """Graphviz DOT for the run so far: finished nodes filled, the running one amber, a failed
    validation red, edges taken drawn thick (with xN when a loop took them more than once)."""
    edges = edges if edges is not None else graph_edges()
    path = ["__start__", *(e["node"] for e in events)]
    if events and events[-1]["node"] == "output":
        path.append("__end__")
    taken: dict[tuple[str, str], int] = {}
    for a, b in zip(path, path[1:], strict=False):
        taken[(a, b)] = taken.get((a, b), 0) + 1
    if running and path:
        taken.setdefault((path[-1], running), 0)  # the edge being travelled now
    color = {e["node"]: OK for e in events}
    for e in events:
        if e["node"] == "validate" and validation_verdict(e["update"]) == "failed":
            color["validate"] = BAD
        elif e["node"] == "validate":
            color["validate"] = OK
    if running:
        color[running] = BUSY
    start = OK if events or running else IDLE
    lines = [
        "digraph G {",
        '  rankdir=LR; bgcolor="transparent"; nodesep=0.35; ranksep=0.45;',
        '  node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=13 '
        'margin="0.18,0.08" penwidth=1.5];',
        '  edge [fontname="Helvetica" fontsize=11];',
        f'  __start__ [label="alert" shape=circle fixedsize=true width=0.6 fontsize=10 '
        f'fillcolor="{start}" fontcolor="white" color="{start}"];',
        f'  __end__ [label="" shape=doublecircle fixedsize=true width=0.3 '
        f'fillcolor="{OK if "__end__" in path else IDLE}" color="{IDLE}"];',
    ]
    for n in NODES:
        c = color.get(n)
        if c:
            lines.append(f'  {n} [fillcolor="{c}" color="{c}" fontcolor="white"];')
        else:
            lines.append(f'  {n} [fillcolor="transparent" color="{IDLE}" fontcolor="{IDLE}"];')
    for a, b in edges:
        if (a, b) in taken:
            n = taken[(a, b)]
            c = BUSY if n == 0 else OK
            label = f' label=" x{n}" fontcolor="{OK}"' if n > 1 else ""
            lines.append(f'  {a} -> {b} [color="{c}" penwidth=2.6{label}];')
        else:
            lines.append(f'  {a} -> {b} [color="{IDLE}" style=dashed penwidth=1];')
    lines.append("}")
    return "\n".join(lines)


def event_rows(alert: dict) -> list[dict]:
    """One row per log event of the alert (all values attacker-controlled: shown as data)."""
    rows = []
    for e in alert.get("events", []):
        p, n = e.get("process") or {}, e.get("network") or {}
        rows.append(
            {
                "time": e.get("timestamp"),
                "host": e.get("host"),
                "user": e.get("user"),
                "process": p.get("image"),
                "command line": p.get("command_line"),
                "parent command line": (p.get("parent") or {}).get("command_line"),
                "network": f"{n.get('dst_ip')}:{n.get('dst_port')}" if n.get("dst_ip") else None,
            }
        )
    return rows


def hit_rows(hits: list[dict]) -> list[dict]:
    return [
        {"rank": i, "id": h["id"], "title": h["title"], "found by": ", ".join(h["matched_by"])}
        for i, h in enumerate(hits, 1)
    ]


def lookup_rows(triage_update: dict) -> list[dict]:
    """Each ThreatFox / NVD lookup and the gist of its answer."""
    rows = []
    for run in triage_update.get("triage_runs") or []:
        for look in run.get("lookups") or []:
            a = look.get("answer") or {}
            value = next(iter((look.get("args") or {}).values()), "")
            if look["name"].startswith("nvd"):
                cvss = a.get("cvss") or {}
                gist = (
                    f"{cvss.get('severity', '?')} {cvss.get('base_score', '')}"
                    + (", known exploited (CISA)" if a.get("cisa_known_exploited") else "")
                    if a.get("found")
                    else "not found"
                )
            elif not a:
                gist = "(answer not recorded)"
            elif a.get("found"):
                hit = (a.get("results") or [{}])[0]
                parts = [hit.get("malware_printable"), hit.get("threat_type")]
                if hit.get("confidence_level") is not None:
                    parts.append(f"confidence {hit['confidence_level']}")
                gist = "listed: " + ", ".join(str(x) for x in parts if x)
            else:
                gist = "not listed"
            rows.append(
                {
                    "tier": run.get("tier"),
                    "tool": "ThreatFox" if look["name"].startswith("threatfox") else "NVD",
                    "looked up": value,
                    "answer": gist,
                }
            )
    return rows


KEY_VAR = "OPENROUTER_API_KEY"
QUOTA_MARKERS = ("per-day", "per day", "401", "User not found", "No auth credentials")


def record_with_key_switch(alert: Alert, name: str, **kw: Any) -> dict:
    """record(), moving OPENROUTER_API_KEY to the next OPENROUTER_API_KEY_<name> (a different
    account) when a key hits its free daily quota or is dead, then recording again from the
    start. Works because chat_model() reads the env var on each call. Same idea as evals.run."""
    names = [KEY_VAR] + sorted(n for n in os.environ if n.startswith(KEY_VAR + "_"))
    keys = list(dict.fromkeys(v for n in names if (v := os.environ.get(n, "").strip())))
    tried = {os.environ.get(KEY_VAR, "").strip()}
    while True:
        try:
            return record(alert, name, **kw)
        except Exception as e:
            nxt = next((k for k in keys if k not in tried), None)
            if not any(m in str(e) for m in QUOTA_MARKERS) or nxt is None:
                raise
            tried.add(nxt)
            os.environ[KEY_VAR] = nxt
            print(f"  key quota hit or dead: switching to key {len(tried)}/{len(keys)}", flush=True)


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    p = argparse.ArgumentParser(prog="python -m sentinel.demo")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("record", help="run one alert live and save the recording")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--alert-id", help="an alert id from the golden or tools eval set")
    src.add_argument("--alert", type=Path, help="an alert JSON file")
    r.add_argument("--name", required=True, help="recording name -> results/demo/<name>.json")
    r.add_argument("--trace", action="store_true", help="also send a Langfuse trace")
    sub.add_parser("list", help="saved recordings")
    args = p.parse_args(argv)

    if args.command == "list":
        for name, path in recordings().items():
            m = load(path)["meta"]
            path_s = " -> ".join(m["path"])
            print(f"{name:24} {m['alert']['alert_id']:12} {m['outcome']:16} {path_s}")
        return
    if args.alert:
        alert = Alert.model_validate_json(args.alert.read_text(encoding="utf-8"))
    else:
        alert = find_alert(args.alert_id)

    def show(ev: dict) -> None:
        print(f"  {ev['node']:9} {ev['end'] - ev['start']:6.1f}s", flush=True)

    rec = record_with_key_switch(alert, args.name, trace=args.trace, on_event=show)
    print(f"{rec['meta']['outcome']}: {' -> '.join(rec['meta']['path'])}")
    print(f"saved {save(rec).relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
