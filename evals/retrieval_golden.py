"""Retrieval test, split by question type. No model calls, no quota.

    uv run python -m evals.retrieval_golden                  # current search (BM25 + vector), dev
    uv run python -m evals.retrieval_golden --no-bm25 --label vector-only
    uv run python -m evals.retrieval_golden --no-vector --label bm25-only

Six question types ("tasks"), each scored on its own, because a search setup can be good at one
and bad at another:

    text->attack     a plain-English description -> the right ATT&CK technique   (40 probes)
    text->sigma      the same descriptions -> a Sigma rule about that technique  (40 probes)
    alert->attack    the pipeline's real search text for an alert -> technique   (dev attacks)
    alert->sigma     the same, over Sigma rules (with the pipeline's logsource filter)
    command->attack  only the command line(s) of the alert -> technique
    fields->sigma    the alert written as Sigma field names ("Image: ...", "CommandLine: ...")
                     -> Sigma rules, since rules are written in those field names

The alert tasks use the true_positive alerts of the chosen split and their primary gold
technique. The probe tasks reuse the frozen hand-written probe sets v1 + v2: they are "spent" for
tuning search settings, but still fine for comparing whole setups side by side.

A technique answer is right when it is one of the expected technique IDs. A Sigma rule is right
when it is tagged with the expected technique or the same parent technique (T1003 ~ T1003.001):
a proxy, since no one has labeled which rule "should" come back for each question.

Scores per task, all 0..1, higher is better:
    recall@5, recall@10   a right answer is in the top 5 / top 10
    MRR                   average of 1/rank of the first right answer (0 if not in the top DEEP)
    NDCG@5                how near the top the right answers are within the top 5 (1 = best
                          possible order; several right Sigma rules all count)

Only 20 dev attacks: one alert = 0.05, so gaps under ~0.10 are luck. Tune on dev only;
`--split test` is sealed. Output: results/retrieval/<label>-<split>.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from evals.scorers import AttackMap
from evals.split import SPLITS, load_split
from evals.triage_smoke import GOLDEN, load_golden
from sentinel.agents.enrich import search_plan
from sentinel.retrieval import search, store
from sentinel.retrieval.embed import MODEL_NAME
from sentinel.retrieval.search import retrieve
from sentinel.schemas import Alert

ROOT = Path(__file__).parent.parent
OUT_DIR = ROOT / "results" / "retrieval"
PROBE_FILES = [
    ROOT / "evals" / "retrieval_probes.yaml",
    ROOT / "evals" / "retrieval_probes_v2.yaml",
]
DEEP = 20
TASKS = ("text->attack", "text->sigma", "alert->attack", "alert->sigma", "command->attack",
         "fields->sigma")  # fmt: skip


@dataclass
class Case:
    task: str
    case_id: str
    query: str
    kind: str  # "technique" | "sigma_rule"
    gold: list[str]  # right technique IDs
    platform: str | None = None
    logsource: str | None = None


# --- questions ------------------------------------------------------------------------------


def command_query(alert: Alert) -> str | None:
    lines = [e.process.command_line for e in alert.events if e.process and e.process.command_line]
    return " ".join(lines) or None


def fields_query(alert: Alert) -> str:
    """The event as Sigma field names, the vocabulary Sigma detections are written in."""
    out: list[str] = []
    for e in alert.events:
        p, r, n = e.process, e.registry, e.network
        pairs = [
            ("Image", p and p.image),
            ("CommandLine", p and p.command_line),
            ("ParentImage", p and p.parent and p.parent.image),
            ("ParentCommandLine", p and p.parent and p.parent.command_line),
            ("TargetObject", r and r.target_object),
            ("Details", r and r.details),
            ("DestinationIp", n and n.dst_ip),
            ("DestinationPort", n and n.dst_port),
        ]
        out += [f"{name}: {value}" for name, value in pairs if value]
    return "\n".join(out)


def alert_cases(labels: list[dict], alerts: dict[str, Alert]) -> list[Case]:
    cases = []
    for lab in labels:
        if lab["label"] != "true_positive" or not lab["technique_ids"]:
            continue
        alert, gold = alerts[lab["alert_id"]], [lab["technique_ids"][0]]
        query, platform, logsource = search_plan(alert)
        aid = lab["alert_id"]
        cases += [
            Case("alert->attack", aid, query, "technique", gold, platform),
            Case("alert->sigma", aid, query, "sigma_rule", gold, platform, logsource),
            Case(
                "fields->sigma", aid, fields_query(alert), "sigma_rule", gold, platform, logsource
            ),
        ]
        if cmd := command_query(alert):
            cases.append(Case("command->attack", aid, cmd, "technique", gold, platform))
    return cases


def probe_cases() -> list[Case]:
    cases = []
    for path in PROBE_FILES:
        for p in yaml.safe_load(path.read_text(encoding="utf-8"))["probes"]:
            pid = f"{path.stem}:{p['id']}"
            cases.append(Case("text->attack", pid, p["query"], "technique", p["expected"]))
            cases.append(Case("text->sigma", pid, p["query"], "sigma_rule", p["expected"]))
    return cases


# --- scoring --------------------------------------------------------------------------------


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def relevance(case: Case, answers: list[list[str]], attack: AttackMap) -> list[bool]:
    """One flag per returned hit: is it a right answer? `answers` = each hit's technique IDs
    (a technique hit has one, a Sigma rule hit has its ATT&CK tags)."""
    if case.kind == "technique":
        gold = {attack.canonical(g) for g in case.gold}
        return [any(attack.canonical(t) in gold for t in tags) for tags in answers]
    gold = {_parent(attack.canonical(g)) for g in case.gold}
    return [any(_parent(attack.canonical(t)) in gold for t in tags) for tags in answers]


def ndcg(rels: list[bool], n_relevant: int, k: int = 5) -> float:
    """Binary NDCG@k: a right answer at rank r is worth 1/log2(r+1); divided by the best score
    possible with n_relevant right answers."""
    dcg = sum(1 / math.log2(i + 2) for i, rel in enumerate(rels[:k]) if rel)
    ideal = sum(1 / math.log2(i + 2) for i in range(min(n_relevant, k)))
    return dcg / ideal if ideal else 0.0


def case_scores(rels: list[bool], n_relevant: int) -> dict[str, Any]:
    first = next((i for i, rel in enumerate(rels, start=1) if rel), None)
    return {"first_rank": first, "ndcg5": ndcg(rels, max(n_relevant, 1))}


def summarize(rows: list[dict]) -> dict[str, dict[str, float]]:
    out = {}
    for task in TASKS:
        rs = [r for r in rows if r["task"] == task]
        if not rs:
            continue

        def recall(k: int, rs=rs) -> float:
            return sum(r["first_rank"] is not None and r["first_rank"] <= k for r in rs) / len(rs)

        out[task] = {
            "n": len(rs),
            "recall@5": recall(5),
            "recall@10": recall(10),
            "mrr": sum(1 / r["first_rank"] for r in rs if r["first_rank"]) / len(rs),
            "ndcg@5": sum(r["ndcg5"] for r in rs) / len(rs),
        }
    return out


def _relevant_rule_count(conn, case: Case, attack: AttackMap) -> int:
    """How many Sigma rules in the searched set are right answers (for NDCG's best order)."""
    where, params = search._filters("sigma_rule", case.platform, case.logsource)
    parents = sorted({_parent(attack.canonical(g)) for g in case.gold})
    sql = (
        f"SELECT count(*) FROM chunks WHERE {where} AND EXISTS ("
        "SELECT 1 FROM unnest(technique_ids) t WHERE split_part(t, '.', 1) = ANY(%s))"
    )
    return conn.execute(sql, [*params, parents]).fetchone()[0]


# --- run ------------------------------------------------------------------------------------


def evaluate(
    cases: list[Case],
    attack: AttackMap,
    lexical: bool = False,
    bm25: bool = True,
    vector: bool = True,
) -> list[dict]:
    rows = []
    with store.connect() as conn:
        for case in cases:
            hits = retrieve(
                case.query,
                DEEP,
                logsource=case.logsource,
                platform=case.platform,
                kind=case.kind,
                conn=conn,
                use_lexical=lexical,
                use_bm25=bm25,
                use_vector=vector,
            )
            answers = [[h.id] if h.kind == "technique" else h.technique_ids for h in hits]
            rels = relevance(case, answers, attack)
            n_rel = (
                len(case.gold)
                if case.kind == "technique"
                else _relevant_rule_count(conn, case, attack)
            )
            rows.append(
                asdict(case)
                | case_scores(rels, n_rel)
                | {"n_relevant": n_rel, "top": [h.id for h in hits[:5]]}
            )
    return rows


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.retrieval_golden")
    p.add_argument("--split", choices=SPLITS, default="dev")
    p.add_argument("--unseal-test", action="store_true")
    p.add_argument("--lexical", action="store_true", help="add the old IDF keyword leg")
    p.add_argument("--no-bm25", action="store_true", help="turn the BM25 keyword search off")
    p.add_argument("--no-vector", action="store_true", help="turn the vector search off")
    p.add_argument("--label", default="current", help="experiment name for the output file")
    args = p.parse_args(argv)
    if args.split == "test" and not args.unseal_test:
        p.error("the test split is sealed until Day 13-14: add --unseal-test to run it")

    label_rows, alerts = load_golden()
    ids, split_sha = load_split(args.split)
    wanted = set(ids)
    labels = [lab for lab in label_rows if lab["alert_id"] in wanted]
    cases = probe_cases() + alert_cases(labels, alerts)
    rows = evaluate(
        cases, AttackMap.from_bundle(), args.lexical, not args.no_bm25, not args.no_vector
    )
    summary = summarize(rows)

    with store.connect() as conn:
        chunks = conn.execute("SELECT kind, count(*) FROM chunks GROUP BY kind").fetchall()
    name = args.label
    meta = {
        "label": name,
        "split": {"name": args.split, "sha": split_sha},
        "golden_sha": hashlib.sha256(GOLDEN.read_bytes()).hexdigest()[:12],
        "embedding_model": MODEL_NAME,
        "lexical": args.lexical,
        "bm25": not args.no_bm25,
        "vector": not args.no_vector,
        "index": dict(chunks),
        "deep": DEEP,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{name}-{args.split}.json"
    result = {"meta": meta, "summary": summary, "rows": rows}
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"{name} ({args.split})")
    print(f"  {'task':16} {'n':>3} {'R@5':>5} {'R@10':>5} {'MRR':>5} {'NDCG@5':>6}")
    for task, s in summary.items():
        print(
            f"  {task:16} {s['n']:3} {s['recall@5']:5.2f} {s['recall@10']:5.2f} "
            f"{s['mrr']:5.2f} {s['ndcg@5']:6.2f}"
        )
    print(f"-> {out.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
