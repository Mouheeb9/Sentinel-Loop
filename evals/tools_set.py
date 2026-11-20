"""The tools eval set (docs/tools-eval-plan.md): alerts where the lookup decides the answer.

Kept out of data/golden/ on purpose: evals.run hashes the golden candidate files into every dev
row's fingerprint, so adding cases there would make every stored dev result stale.

    data/tools-eval/candidates.json   alerts, same schema as data/golden/day*_candidates.json
    data/tools-eval/labels.jsonl      golden label format + "pair" (e.g. "A01") and "group" (A/B/C)
    data/tools-eval/cache.json        the tool_cache rows for these alerts' lookup targets

ThreatFox drops old IOCs, so the answers cached at build time ARE the ground truth: export them
once the live lookups are done, import them on any other machine before a run.

    uv run python -m evals.tools_set check            # files load, pairs complete, targets cached
    uv run python -m evals.tools_set export           # tool_cache (Postgres) -> cache.json
    uv run python -m evals.tools_set import           # cache.json -> tool_cache
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

from sentinel.schemas import Alert
from sentinel.tools import lookup_targets, nvd, threatfox

ROOT = Path(__file__).parent.parent
TOOLS_DIR = ROOT / "data" / "tools-eval"
CANDIDATES = TOOLS_DIR / "candidates.json"
LABELS = TOOLS_DIR / "labels.jsonl"
CACHE = TOOLS_DIR / "cache.json"


def load_tools_set(
    candidates: Path = CANDIDATES, labels_path: Path = LABELS
) -> tuple[list[dict], dict[str, Alert]]:
    if not candidates.exists() or not labels_path.exists():
        raise SystemExit(f"tools set not built yet: need {candidates} and {labels_path}")
    labels = [json.loads(x) for x in labels_path.read_text(encoding="utf-8").splitlines() if x]
    alerts = {
        c["alert"]["alert_id"]: Alert.model_validate(c["alert"])
        for c in json.loads(candidates.read_text(encoding="utf-8"))
    }
    missing = [lab["alert_id"] for lab in labels if lab["alert_id"] not in alerts]
    if missing:
        raise SystemExit(f"labels without an alert in {candidates.name}: {missing[:5]}")
    return labels, alerts


def cache_keys(alert: Alert) -> set[tuple[str, str]]:
    """(tool, key) rows a lookup on this alert can read: each target, and the host of each
    target URL (check_args allows that domain too). Keys normalized the way the tools store them."""
    keys: set[tuple[str, str]] = set()
    for t in lookup_targets(alert):
        if t.upper().startswith("CVE-"):
            keys.add((nvd.NAME, nvd.normalize_cve(t)))
            continue
        keys.add((threatfox.NAME, threatfox.classify(t)[1]))
        if "://" in t and (host := urlsplit(t).hostname):
            try:
                keys.add((threatfox.NAME, threatfox.classify(host)[1]))
            except ValueError:
                pass
    return keys


def problems(labels: list[dict], alerts: dict[str, Alert]) -> list[str]:
    """What is wrong with the set before spending a run on it."""
    out = []
    pairs: dict[str, list[dict]] = {}
    for lab in labels:
        if lab.get("pair"):
            pairs.setdefault(lab["pair"], []).append(lab)
        if not lookup_targets(alerts[lab["alert_id"]]):
            out.append(f"{lab['alert_id']}: no lookup target (tools would never be offered)")
    for p, members in sorted(pairs.items()):
        if len(members) != 2:
            out.append(f"pair {p}: {len(members)} alerts, need 2")
        elif {m["label"] for m in members} != {"true_positive", "benign_noisy"}:
            out.append(
                f"pair {p}: labels {[m['label'] for m in members]}, need one TP + one benign"
            )
    return out


def export_cache(alerts: dict[str, Alert], out: Path = CACHE) -> tuple[int, list[str]]:
    """Write the tool_cache rows these alerts can read. Returns (rows written, keys missing)."""
    from sentinel.tools.cache import PgToolCache

    keys = sorted(set().union(*(cache_keys(a) for a in alerts.values())))
    conn = PgToolCache()._connect()
    rows, missing = [], []
    with conn:
        for tool, key in keys:
            hit = conn.execute(
                "SELECT response, fetched_at FROM tool_cache WHERE tool = %s AND key = %s",
                (tool, key),
            ).fetchone()
            if hit is None:
                missing.append(f"{tool}:{key}")
                continue
            rows.append(
                {"tool": tool, "key": key, "response": hit[0], "fetched_at": hit[1].isoformat()}
            )
    out.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(rows), missing


def import_cache(path: Path = CACHE) -> int:
    """Load cache.json into tool_cache, keeping the original fetched_at."""
    from psycopg.types.json import Jsonb

    from sentinel.tools.cache import PgToolCache

    rows = json.loads(path.read_text(encoding="utf-8"))
    conn = PgToolCache()._connect()
    with conn:
        for r in rows:
            conn.execute(
                """
                INSERT INTO tool_cache (tool, key, response, fetched_at) VALUES (%s, %s, %s, %s)
                ON CONFLICT (tool, key) DO UPDATE
                SET response = EXCLUDED.response, fetched_at = EXCLUDED.fetched_at
                """,
                (r["tool"], r["key"], Jsonb(r["response"]), r["fetched_at"]),
            )
    return len(rows)


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    p = argparse.ArgumentParser(prog="python -m evals.tools_set")
    p.add_argument("command", choices=["check", "export", "import"])
    args = p.parse_args(argv)
    labels, alerts = load_tools_set()
    if args.command == "import":
        print(f"imported {import_cache()} rows from {CACHE.relative_to(ROOT).as_posix()}")
        return
    if args.command == "export":
        n, missing = export_cache(alerts)
        print(f"exported {n} rows to {CACHE.relative_to(ROOT).as_posix()}")
        for m in missing:
            print(f"  not cached (no live lookup yet): {m}")
        return
    issues = problems(labels, alerts)
    print(f"{len(labels)} labels, {len(alerts)} alerts, {len(issues)} problems")
    for i in issues:
        print(f"  {i}")
    if issues:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
