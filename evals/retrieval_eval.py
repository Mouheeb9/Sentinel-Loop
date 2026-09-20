"""Recall@5 of retrieve() on a frozen probe set, hybrid vs vector-only.

    uv run python -m evals.retrieval_eval [--probes evals/retrieval_probes_v2.yaml] [--label NAME]

Scoring rules are pre-registered in each probe file (primary / lenient / mixed). Vector-only is
reported next to hybrid so a lexical leg that makes results *worse* shows up immediately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from sentinel.retrieval import store
from sentinel.retrieval.search import Hit, retrieve

HERE = Path(__file__).parent
DEFAULT_PROBES = HERE / "retrieval_probes.yaml"
K = 5
DEEP = 20  # rank beyond top-5 is reported for diagnosis only; it does not enter recall@5


def _related(returned: str, expected: str) -> bool:
    """Same technique, or one is the parent of the other (T1059 <-> T1059.001)."""
    return (
        returned == expected
        or returned.startswith(expected + ".")
        or expected.startswith(returned + ".")
    )


def _returned_ids(hit: Hit) -> list[str]:
    return [hit.id] if hit.kind == "technique" else hit.technique_ids


def _first_rank(hits: list[Hit], expected: list[str], match) -> int | None:
    for rank, hit in enumerate(hits, start=1):
        if any(match(r, e) for r in _returned_ids(hit) for e in expected):
            return rank
    return None


def _exact(returned: str, expected: str) -> bool:
    return returned == expected


def _run_mode(conn, probes: list[dict], use_lexical: bool) -> dict:
    rows = []
    for p in probes:
        tech = retrieve(p["query"], k=DEEP, kind="technique", conn=conn, use_lexical=use_lexical)
        mixed = retrieve(p["query"], k=DEEP, conn=conn, use_lexical=use_lexical)
        rows.append(
            {
                "id": p["id"],
                "tag": p["tag"],
                "query": p["query"],
                "expected": p["expected"],
                "primary_rank": _first_rank(tech, p["expected"], _exact),
                "lenient_rank": _first_rank(tech, p["expected"], _related),
                "mixed_rank": _first_rank(mixed, p["expected"], _exact),
                "top5_techniques": [h.id for h in tech[:K]],
            }
        )

    def recall(key: str, subset: str | None = None) -> float:
        sel = [r for r in rows if subset is None or r["tag"] == subset]
        return sum(1 for r in sel if r[key] is not None and r[key] <= K) / len(sel)

    return {
        "recall_at_5": {
            "primary": recall("primary_rank"),
            "lenient": recall("lenient_rank"),
            "mixed": recall("mixed_rank"),
        },
        "primary_by_tag": {t: recall("primary_rank", t) for t in sorted({r["tag"] for r in rows})},
        "rows": rows,
    }


def run(probes_path: Path = DEFAULT_PROBES) -> dict:
    probes = yaml.safe_load(probes_path.read_text(encoding="utf-8"))["probes"]
    with store.connect() as conn:
        return {
            "probes_file": probes_path.name,
            "probes_sha256": hashlib.sha256(probes_path.read_bytes()).hexdigest(),
            "k": K,
            "hybrid": _run_mode(conn, probes, use_lexical=True),
            "vector_only": _run_mode(conn, probes, use_lexical=False),
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    ap.add_argument("--label", default=None, help="results are written to results/<label>.json")
    args = ap.parse_args()

    result = run(args.probes)
    print(f"{result['probes_file']}  sha256 {result['probes_sha256']}")
    hyb, vec = result["hybrid"]["rows"], result["vector_only"]["rows"]
    for h, v in zip(hyb, vec, strict=True):
        fmt = lambda r: "HIT " if r["primary_rank"] and r["primary_rank"] <= K else "MISS"  # noqa: E731
        print(
            f"{h['id']} [{h['tag']:9}] hybrid {fmt(h)} rank={h['primary_rank']}"
            f" | vector {fmt(v)} rank={v['primary_rank']} | expected={h['expected']}"
        )
    for mode in ("hybrid", "vector_only"):
        r = result[mode]
        print(f"{mode:12} recall@5 {r['recall_at_5']}  by tag {r['primary_by_tag']}")

    if args.label:
        out = HERE / "results" / f"{args.label}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {out}")


if __name__ == "__main__":
    main()
