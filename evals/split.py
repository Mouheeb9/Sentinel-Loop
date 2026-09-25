"""Freeze the golden set into a dev split and a sealed test split.

    uv run python -m evals.split            # writes data/golden/split-v1.json, never overwrites
    uv run python -m evals.split --check    # verifies the committed file still matches its hash

dev   = the 30 alerts the Week 1 baseline runs on (`--n 30 --seed 5`), so looking at its failures
        is allowed. Every tuning decision is made on dev.
test  = 30 fresh alerts, stratified like dev, drawn from the other 120. Nobody reads them, and
        they are run once, on Day 13-14, to report the final number.

The split stores alert IDs only; the truth is always read from the current golden file, so a
label fix (golden-v1.1) changes the scores, never which alerts are in which split. The file's
content sha256 is recorded next to it (split-v1.sha256) and in every results/*.json that uses it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from evals.triage_smoke import GOLDEN, load_golden, sample

ROOT = Path(__file__).parent.parent
SPLIT = ROOT / "data" / "golden" / "split-v1.json"
SPLITS = ("dev", "test")
DEV_N, DEV_SEED = 30, 5  # the baseline's sample: do not change
TEST_N, TEST_SEED = 30, 14


def build(labels: list[dict]) -> dict:
    dev = sample(labels, DEV_N, DEV_SEED)
    dev_ids = {r["alert_id"] for r in dev}
    rest = [r for r in labels if r["alert_id"] not in dev_ids]
    test = sample(rest, TEST_N, TEST_SEED)
    return {
        "version": "split-v1",
        "golden_sha": hashlib.sha256(GOLDEN.read_bytes()).hexdigest()[:12],
        "dev": {"n": DEV_N, "seed": DEV_SEED, "alert_ids": sorted(dev_ids)},
        "test": {"n": TEST_N, "seed": TEST_SEED, "alert_ids": sorted(r["alert_id"] for r in test)},
    }


def sha_path(path: Path = SPLIT) -> Path:
    return path.with_suffix(".sha256")


def file_sha(path: Path = SPLIT) -> str:
    """Hash of the content, not the bytes: git's CRLF conversion on Windows can't change it."""
    canonical = json.dumps(json.loads(path.read_text(encoding="utf-8")), sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_split(name: str, path: Path = SPLIT) -> tuple[list[str], str]:
    """Alert IDs of one split, and the split file's sha (checked against the recorded one)."""
    if name not in SPLITS:
        raise ValueError(f"unknown split {name!r}")
    sha = file_sha(path)
    recorded = sha_path(path).read_text(encoding="utf-8").split()[0]
    if sha != recorded:
        raise SystemExit(
            f"{path.name} changed since it was frozen (sha {sha[:12]} != {recorded[:12]})"
        )
    return json.loads(path.read_text(encoding="utf-8"))[name]["alert_ids"], sha[:12]


def write(split: dict, path: Path = SPLIT) -> str:
    if path.exists():
        raise SystemExit(f"{path.name} already exists: a frozen split is never regenerated")
    path.write_text(json.dumps(split, indent=2) + "\n", encoding="utf-8")
    sha = file_sha(path)
    sha_path(path).write_text(f"{sha}  {path.name}\n", encoding="utf-8")
    return sha


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.split")
    p.add_argument("--check", action="store_true", help="verify the frozen file's hash")
    args = p.parse_args(argv)
    if args.check:
        for name in SPLITS:
            ids, sha = load_split(name)
            print(f"{name}: {len(ids)} alerts  (split sha {sha})")
        return
    labels, _ = load_golden()
    sha = write(build(labels))
    print(f"written {SPLIT.relative_to(ROOT).as_posix()}  sha {sha[:12]}")


if __name__ == "__main__":
    main()
