"""Run one alert through the pipeline.

    uv run python -m sentinel.run --alert tests/fixtures/alerts/day2-001.json
    uv run python -m sentinel.run --alert ... --passes FFT      # force the repair loop

Nodes are stubs on Day 4; --verdict / --covered / --passes pick which path the stubs take.
Traces go to Langfuse when LANGFUSE_* keys are set in .env (see .env.example).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from sentinel.graph.build import build_graph
from sentinel.graph.nodes import StubScript
from sentinel.schemas import Alert
from sentinel.tracing import trace_run


def _default_owner() -> str:
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


def main(argv: list[str] | None = None) -> dict:
    load_dotenv()  # before any Langfuse client is created

    p = argparse.ArgumentParser(prog="python -m sentinel.run")
    p.add_argument("--alert", required=True, type=Path, help="Alert JSON file")
    p.add_argument("--config-name", default="stub", help="tag for comparing runs in Langfuse")
    p.add_argument("--owner", default=None, help="default: SENTINEL_OWNER or git user.name")
    p.add_argument("--no-trace", action="store_true", help="never send a Langfuse trace")
    p.add_argument(
        "--verdict",
        default="true_positive",
        choices=["true_positive", "benign_noisy", "needs_review"],
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

    graph = build_graph()
    path: list[str] = []
    final: dict = {}
    with trace_run(
        alert,
        config_name=args.config_name,
        owner=args.owner or _default_owner(),
        enabled=not args.no_trace,
    ) as trace:
        config = {
            "configurable": {"stub": stub},
            "callbacks": trace.callbacks,
            "run_name": "sentinel-pipeline",
        }
        for mode, chunk in graph.stream(
            {"alert": alert}, config, stream_mode=["updates", "values"]
        ):
            if mode == "updates":
                path.extend(chunk)
            else:
                final = chunk
        trace.finish(final)

    verdict = final["verdict"]
    # ASCII only: the Windows console can't print some characters.
    print(f"alert:    {alert.alert_id}")
    print(f"path:     {' -> '.join(path)}")
    print(f"verdict:  {verdict.verdict} (confidence {verdict.confidence})")
    print(f"outcome:  {final['outcome']}  (validations: {len(final.get('validations', []))})")
    print(f"trace:    {trace.url or 'off (no LANGFUSE keys, or --no-trace)'}")
    print(json.dumps({"outcome": final["outcome"]}))
    return final


if __name__ == "__main__":
    main()
