"""Run one alert through the pipeline.

    uv run python -m sentinel.run --alert tests/fixtures/alerts/day2-001.json
    uv run python -m sentinel.run --alert ... --stub --verdict benign_noisy   # all nodes fake

By default enrich and triage are real (Postgres + the model in SENTINEL_TRIAGE_MODEL); the later
nodes are still stubs, steered by --covered / --passes. --stub makes every node fake.
Traces go to Langfuse when LANGFUSE_* keys are set in .env (see .env.example).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from sentinel.graph.build import build_graph
from sentinel.graph.nodes import StubScript
from sentinel.llm import triage_model_name
from sentinel.schemas import Alert
from sentinel.tracing import trace_run


@dataclass
class RunResult:
    final: dict
    path: list[str]
    trace_url: str | None


def default_owner() -> str:
    # Two people share one machine; the per-session git identity says who is running this.
    if owner := os.environ.get("SENTINEL_OWNER"):
        return owner
    try:
        name = subprocess.run(
            ["git", "config", "user.name"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        name = ""
    return name or "unknown"


def run_alert(
    alert: Alert,
    *,
    live: bool,
    stub: StubScript,
    config_name: str,
    owner: str,
    trace: bool = True,
) -> RunResult:
    graph = build_graph(live=live)
    path: list[str] = []
    final: dict = {}
    model = triage_model_name() if live else "stub"
    with trace_run(alert, config_name=config_name, owner=owner, model=model, enabled=trace) as tr:
        config = {
            "configurable": {"stub": stub},
            "callbacks": tr.callbacks,
            "run_name": "sentinel-pipeline",
        }
        try:
            for mode, chunk in graph.stream(
                {"alert": alert}, config, stream_mode=["updates", "values"]
            ):
                if mode == "updates":
                    path.extend(chunk)
                else:
                    final = chunk
        finally:
            tr.finish(final)
    return RunResult(final=final, path=path, trace_url=tr.url)


def main(argv: list[str] | None = None) -> dict:
    load_dotenv()  # before any Langfuse client or model is created

    p = argparse.ArgumentParser(prog="python -m sentinel.run")
    p.add_argument("--alert", required=True, type=Path, help="Alert JSON file")
    p.add_argument("--stub", action="store_true", help="fake every node (no DB, no model)")
    p.add_argument("--config-name", default=None, help="Langfuse tag; default triage-v0 / stub")
    p.add_argument("--owner", default=None, help="default: SENTINEL_OWNER or git user.name")
    p.add_argument("--no-trace", action="store_true", help="never send a Langfuse trace")
    p.add_argument(
        "--verdict",
        default="true_positive",
        choices=["true_positive", "benign_noisy", "needs_review"],
        help="stub triage verdict (only with --stub)",
    )
    p.add_argument(
        "--covered", default=None, metavar="RULE_ID", help="stub: existing rule covers it"
    )
    p.add_argument("--passes", default="T", help="stub: validation results in order, e.g. FFT")
    args = p.parse_args(argv)

    alert = Alert.model_validate_json(args.alert.read_text(encoding="utf-8"))
    stub = StubScript(
        verdict=args.verdict,
        covering_rule_id=args.covered,
        validation_passes=tuple(c.upper() == "T" for c in args.passes) or (True,),
    )
    result = run_alert(
        alert,
        live=not args.stub,
        stub=stub,
        config_name=args.config_name or ("stub" if args.stub else "triage-v0"),
        owner=args.owner or default_owner(),
        trace=not args.no_trace,
    )

    final = result.final
    verdict = final["verdict"]
    # ASCII only: the Windows console can't print some characters.
    print(f"alert:     {alert.alert_id}")
    print(f"path:      {' -> '.join(result.path)}")
    print(f"verdict:   {verdict.verdict} (confidence {verdict.confidence})")
    print(f"techniques:{' ' + ', '.join(verdict.technique_ids) if verdict.technique_ids else ' -'}")
    print(f"reasoning: {verdict.reasoning.encode('ascii', 'replace').decode()}")
    print(f"outcome:   {final['outcome']}  (validations: {len(final.get('validations', []))})")
    print(f"trace:     {result.trace_url or 'off (no LANGFUSE keys, or --no-trace)'}")
    print(json.dumps({"outcome": final["outcome"]}))
    return final


if __name__ == "__main__":
    main()
