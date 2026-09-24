"""Eval runner: golden-v1 through named pipeline configs, scored, with charts.

    uv run python -m evals.run                                  # all 3 configs, all 150 alerts
    uv run python -m evals.run --configs rag-tools --n 30       # stratified sample
    uv run python -m evals.run --score-only                     # rebuild scores + charts, no calls

Configs (the Week 1 baseline):
    single-prompt  no retrieval, no tools: the model and the alert alone
    rag            ATT&CK + Sigma context from pgvector, no tools
    rag-tools      retrieval + NVD/ThreatFox lookups (= triage-v1)
Two-tier routing is the same in all three (SENTINEL_TRIAGE_MODEL / SENTINEL_ESCALATION_MODEL).

Outputs, per config:
    results/<config>.rows.jsonl   one line per alert as it finishes (resume point)
    results/<config>.json         meta + scores (evals.scorers.score_all) + rows + details
    results/charts/baseline.png   every config side by side

Reproducibility: every run records the models, a prompt hash (system prompt + answer schema +
offered tool schemas + retrieval k), the git SHA (and whether the tree was dirty), the golden
file's hash and timestamps. The first line of the rows file is that fingerprint; a re-run with a
different fingerprint starts over instead of mixing two setups into one number.

Resuming: a re-run keeps finished rows (valid verdicts AND schema errors, which are real
outcomes) and retries transport errors. The run stops early on a provider's daily quota, or after
MAX_TRANSPORT_STREAK transport errors in a row, rather than burning retries on 150 alerts. A
results file with transport errors left is marked complete=false: its scores count those rows as
wrong (scorers never skip a row), so don't quote it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from evals.eval_row import EvalRow
from evals.scorers import AttackMap, score_all
from evals.triage_smoke import GOLDEN, load_golden, sample
from sentinel.agents.enrich import K
from sentinel.agents.routing import escalate_below
from sentinel.agents.triage import CONTEXT_TEXT_CHARS, SYSTEM_PROMPT, TriageError
from sentinel.graph.nodes import PipelineOptions, StubScript
from sentinel.llm import escalation_model_name, triage_model_name
from sentinel.run import default_owner, run_alert
from sentinel.schemas import Alert, TriageVerdict
from sentinel.tools import ALLOWED_TOOLS

ROOT = Path(__file__).parent.parent
RESULTS = ROOT / "results"
CHARTS = RESULTS / "charts"

CONFIGS: dict[str, PipelineOptions] = {
    "single-prompt": PipelineOptions(retrieval=False, tools=False),
    "rag": PipelineOptions(retrieval=True, tools=False),
    "rag-tools": PipelineOptions(retrieval=True, tools=True),
}
PAUSE_S = 3  # free-tier models are rate limited per minute
MAX_TRANSPORT_STREAK = 3
DAILY_QUOTA_MARKERS = ("per-day", "per day")


# --- fingerprint ----------------------------------------------------------------------------


def prompt_hash(options: PipelineOptions) -> str:
    """Everything that shapes what the model is asked, hashed. Changes when the prompt, the
    answer schema, the offered tools or the amount of retrieved context change."""
    tools = (
        {n: t.args_schema.model_json_schema() for n, t in sorted(ALLOWED_TOOLS.items())}
        if options.tools
        else {}
    )
    material = {
        "system": SYSTEM_PROMPT,
        "answer_schema": TriageVerdict.model_json_schema(),
        "tools": tools,
        "retrieval_k": K if options.retrieval else 0,
        "context_chars": CONTEXT_TEXT_CHARS,
    }
    return _sha(json.dumps(material, sort_keys=True))[:12]


def git_state() -> dict[str, Any]:
    def git(*args: str) -> str:
        out = subprocess.run(["git", *args], capture_output=True, text=True, cwd=ROOT)
        return out.stdout.strip()

    return {
        "git_sha": git("rev-parse", "HEAD") or None,
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
    }


def fingerprint(config: str, options: PipelineOptions) -> dict[str, Any]:
    """What must match for two rows to belong to the same run."""
    return {
        "config": config,
        "retrieval": options.retrieval,
        "tools": options.tools,
        "tier1_model": triage_model_name(),
        "tier2_model": escalation_model_name(),
        "escalate_below": escalate_below(),
        "prompt_sha": prompt_hash(options),
        "golden_sha": _sha(GOLDEN.read_bytes())[:12],
        "tool_cache": os.environ.get("SENTINEL_TOOL_CACHE") or "ttl",
    }


def _sha(data: str | bytes) -> str:
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


# --- one alert ------------------------------------------------------------------------------


def eval_one(
    config: str, options: PipelineOptions, label: dict, alert: Alert, *, trace: bool
) -> tuple[EvalRow, dict[str, Any]]:
    """Run one alert. Returns the scorer row and the details a human reads failures with."""
    base = {
        "config": config,
        "alert_id": alert.alert_id,
        "label": label["label"],
        "label_techniques": label["technique_ids"],
    }
    detail: dict[str, Any] = {"label_rationale": label.get("rationale")}
    start = time.perf_counter()
    try:
        res = run_alert(
            alert,
            live=True,
            stub=StubScript(),
            config_name=f"eval-{config}",
            owner=default_owner(),
            trace=trace,
            pipeline=options,
        )
    except TriageError as e:
        return EvalRow(**base, error=f"schema: {e}", latency_s=_since(start)), detail
    except Exception as e:  # rate limit, overloaded provider, network, DB down
        error = f"transport: {type(e).__name__}: {str(e)[:300]}"
        return EvalRow(**base, error=error, latency_s=_since(start)), detail

    f = res.final
    v: TriageVerdict = f["verdict"]
    row = EvalRow(
        **base,
        verdict=v.verdict,
        confidence=v.confidence,
        technique_ids=v.technique_ids,
        ioc_refs=v.ioc_refs,
        evidence_refs=v.evidence_refs,
        schema_retries=f.get("triage_schema_retries", 0),
        cost_usd=f.get("triage_cost_usd"),
        latency_s=_since(start),
        tier=f.get("triage_tier"),
        trace=res.trace_url,
    )
    detail |= {
        "reasoning": v.reasoning,
        "retrieved_techniques": [h.id for h in f.get("techniques", [])],
        "retrieved_rules": [h.id for h in f.get("sigma_rules", [])],
        "escalation": f.get("triage_escalation"),
        "lookups": [x for r in f.get("triage_runs", []) for x in r["lookups"]],
        "tokens": sum(r["input_tokens"] + r["output_tokens"] for r in f.get("triage_runs", [])),
    }
    return row, detail


def _since(start: float) -> float:
    return round(time.perf_counter() - start, 2)


# --- one config -----------------------------------------------------------------------------


def rows_path(config: str) -> Path:
    return RESULTS / f"{config}.rows.jsonl"


def load_rows(config: str, fp: dict, fresh: bool) -> dict[str, dict]:
    """Earlier lines of this run, by alert_id, when the fingerprint matches; else nothing."""
    path = rows_path(config)
    if fresh or not path.exists():
        return {}
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]
    if not lines or lines[0].get("fingerprint") != fp:
        print(f"[{config}] setup changed since the last run: starting over")
        return {}
    return {x["row"]["alert_id"]: x for x in lines[1:]}


def run_config(
    config: str, labels: list[dict], alerts: dict[str, Alert], *, trace: bool, fresh: bool
) -> bool:
    """Returns False when the run stopped early (quota / transport streak)."""
    options = CONFIGS[config]
    fp = fingerprint(config, options)
    done = load_rows(config, fp, fresh)
    keep = {a: x for a, x in done.items() if not x["row"]["error"] or _is_schema(x["row"])}

    RESULTS.mkdir(exist_ok=True)
    path = rows_path(config)
    path.write_text(
        _line({"fingerprint": fp}) + "".join(_line(x) for x in keep.values()), encoding="utf-8"
    )

    streak = 0
    todo = [lab for lab in labels if lab["alert_id"] not in keep]
    print(f"[{config}] {len(keep)} done, {len(todo)} to run  (prompt {fp['prompt_sha']})")
    for i, label in enumerate(todo, 1):
        row, detail = eval_one(config, options, label, alerts[label["alert_id"]], trace=trace)
        detail |= git_state() | {"at": _now()}
        with path.open("a", encoding="utf-8") as f:
            f.write(_line({"row": row.model_dump(mode="json"), "detail": detail}))
        ok = "OK " if row.error is None else "ERR"
        print(
            f"[{config}] {i:3}/{len(todo)} {ok} {row.alert_id:12} label={row.label:13} "
            f"got={row.verdict} {row.technique_ids or ''} {row.latency_s}s"
        )
        if row.error and row.error.startswith("transport"):
            streak += 1
            if any(m in row.error for m in DAILY_QUOTA_MARKERS):
                print(f"[{config}] daily quota hit: stopping, re-run tomorrow to resume")
                return False
            if streak >= MAX_TRANSPORT_STREAK:
                print(f"[{config}] {streak} transport errors in a row: stopping")
                return False
        else:
            streak = 0
        time.sleep(PAUSE_S)
    return True


def _is_schema(row: dict) -> bool:
    return str(row.get("error")).startswith("schema")


def _line(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False) + "\n"


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --- scoring --------------------------------------------------------------------------------


def write_results(
    config: str, labels: list[dict], alerts: dict[str, Alert], attack: AttackMap
) -> dict | None:
    """results/<config>.json from the rows file. Only the alerts in `labels` count."""
    path = rows_path(config)
    if not path.exists():
        return None
    lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]
    fp, by_id = lines[0]["fingerprint"], {x["row"]["alert_id"]: x for x in lines[1:]}
    wanted = [lab["alert_id"] for lab in labels]
    entries = [by_id[a] for a in wanted if a in by_id]
    rows = [EvalRow.model_validate(x["row"]) for x in entries]
    if not rows:
        return None
    transport = sum(str(r.error).startswith("transport") for r in rows)
    shas = sorted({x["detail"].get("git_sha") for x in entries if x["detail"].get("git_sha")})
    stamps = sorted(x["detail"]["at"] for x in entries if "at" in x["detail"])
    meta = fp | {
        "git_shas": shas,  # more than one = code changed mid-run
        "git_dirty": any(x["detail"].get("git_dirty") for x in entries),
        "started_at": stamps[0] if stamps else None,
        "finished_at": stamps[-1] if stamps else None,
        "alerts_planned": len(wanted),
        "alerts_run": len(rows),
        "transport_errors": transport,
        "complete": len(rows) == len(wanted) and transport == 0,
    }
    result = {
        "meta": meta,
        "scores": score_all(rows, alerts, attack),
        "rows": [r.model_dump(mode="json") for r in rows],
        "details": {x["row"]["alert_id"]: x["detail"] for x in entries},
    }
    out = RESULTS / f"{config}.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return result


def headline(result: dict) -> dict[str, float | None]:
    s = result["scores"]
    return {
        "triage accuracy": s["triage"]["accuracy"],
        "technique F1": s["techniques"]["f1"],
        "schema-valid rate": s["schema"]["schema_valid_rate"],
        "hallucinated-IOC rate (lower = better)": s["iocs"]["hallucinated_ioc_rate"],
    }


# --- chart ----------------------------------------------------------------------------------

# Reference categorical palette slots 1-3 (light mode): one fixed hue per config.
CONFIG_COLORS = {"single-prompt": "#2a78d6", "rag": "#eb6834", "rag-tools": "#1baf7a"}
INK, INK_MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def render_chart(results: dict[str, dict], out: Path) -> Path:
    """Small multiples: one panel per headline metric, one bar per config, value on each bar.
    One scale per panel (all are rates in 0..1), so no panel needs a second axis."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    configs = [c for c in CONFIGS if c in results]
    metrics = list(headline(next(iter(results.values()))))
    fig, axes = plt.subplots(1, len(metrics), figsize=(3.2 * len(metrics), 3.6), sharey=True)
    for ax, metric in zip(axes, metrics, strict=True):
        values = [headline(results[c])[metric] for c in configs]
        xs = range(len(configs))
        heights = [v or 0 for v in values]
        ax.bar(xs, heights, width=0.62, color=[CONFIG_COLORS[c] for c in configs])
        for x, v in zip(xs, values, strict=True):
            text = "n/a" if v is None else f"{v:.2f}"
            ax.text(x, (v or 0) + 0.02, text, ha="center", va="bottom", fontsize=9, color=INK)
        ax.set_title(metric, fontsize=10, color=INK)
        ax.set_xticks(list(xs), configs, fontsize=8, color=INK_MUTED)
        ax.set_ylim(0, 1.1)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        for side in ("top", "right", "left"):
            ax.spines[side].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.tick_params(axis="y", colors=INK_MUTED, labelsize=8, length=0)
        ax.tick_params(axis="x", length=0)
    meta = next(iter(results.values()))["meta"]
    n = {c: results[c]["meta"]["alerts_run"] for c in configs}
    fig.suptitle(
        f"Triage baseline on golden-v1 (n={', '.join(str(v) for v in n.values())})  "
        f"model: {meta['tier1_model'].split(':', 1)[-1]}"
        + ("  [INCOMPLETE]" if not all(results[c]["meta"]["complete"] for c in configs) else ""),
        fontsize=10,
        color=INK,
    )
    fig.tight_layout()
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=150, facecolor="white")
    plt.close(fig)
    return out


# --- CLI ------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    load_dotenv()
    os.environ.setdefault("SENTINEL_TOOL_CACHE", "frozen")  # lookups can't move between runs

    p = argparse.ArgumentParser(prog="python -m evals.run")
    p.add_argument("--configs", nargs="+", choices=list(CONFIGS), default=list(CONFIGS))
    p.add_argument("--n", type=int, default=None, help="stratified sample size (default: all)")
    p.add_argument("--seed", type=int, default=5)
    p.add_argument("--no-trace", action="store_true")
    p.add_argument("--fresh", action="store_true", help="drop earlier rows for these configs")
    p.add_argument("--score-only", action="store_true", help="no model calls; rescore + chart")
    args = p.parse_args(argv)

    labels, alerts = load_golden()
    if args.n:
        labels = sample(labels, args.n, args.seed)
    labels = sorted(labels, key=lambda r: r["alert_id"])

    stopped = False
    if not args.score_only:
        for config in args.configs:
            if not run_config(config, labels, alerts, trace=not args.no_trace, fresh=args.fresh):
                stopped = True
                break  # same quota for every config: no point starting the next one

    attack = AttackMap.from_bundle()
    results = {}
    for config in CONFIGS:
        if (r := write_results(config, labels, alerts, attack)) is not None:
            results[config] = r
    if not results:
        print("no results yet")
        return

    print(f"\n{'config':14} {'n':>4} {'acc':>5} {'F1':>5} {'valid':>5} {'IOC!':>5}  complete")
    for config, r in results.items():
        h = headline(r)
        cells = " ".join("  n/a" if v is None else f"{v:5.2f}" for v in h.values())
        print(f"{config:14} {r['meta']['alerts_run']:4} {cells}  {r['meta']['complete']}")
    chart = render_chart(results, CHARTS / "baseline.png")
    print(f"written: results/<config>.json, {chart.relative_to(ROOT).as_posix()}")
    if stopped:
        print("run stopped early: re-run the same command to resume")


if __name__ == "__main__":
    main()
