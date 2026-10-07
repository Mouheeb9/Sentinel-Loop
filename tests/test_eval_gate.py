"""Triage eval gate: passes on the committed results, fails on stale input, drops and gaps."""

from __future__ import annotations

import copy
import json

import pytest
import yaml

from evals import gate
from evals.scorers import DEFAULT_BUNDLE, AttackMap
from evals.triage_smoke import load_golden


@pytest.fixture(scope="module")
def ctx():
    cfg = yaml.safe_load(gate.GATE_CONFIG.read_text(encoding="utf-8"))
    results = json.loads((gate.ROOT / cfg["results"]).read_text(encoding="utf-8"))
    labels, alerts = load_golden()
    return cfg, results, gate.current_fingerprint(cfg["config"]), labels, alerts


def _check(ctx, results=None, current=None):
    cfg, res, cur, labels, alerts = ctx
    problems, _ = gate.check(
        cfg, results or res, current or cur, labels, alerts, gate.load_attack_map()
    )
    return problems


def test_committed_results_pass_the_gate(ctx):
    assert _check(ctx) == []


def test_a_prompt_change_without_a_new_dev_run_fails(ctx):
    current = ctx[2] | {"prompt_sha": "000000000000"}
    problems = _check(ctx, current=current)
    assert any("stale results: prompt_sha" in p for p in problems)


def test_a_score_drop_fails(ctx):
    results = copy.deepcopy(ctx[1])
    attacks = [r for r in results["rows"] if r["label"] == "true_positive"]
    for r in attacks[:6]:  # 6 missed attacks: recall and accuracy fall below their floors
        r["verdict"] = "benign_noisy"
    problems = _check(ctx, results=results)
    assert any(p.startswith("attack_recall") for p in problems)
    assert any(p.startswith("accuracy") for p in problems)


def test_incomplete_or_wrong_split_fails(ctx):
    results = copy.deepcopy(ctx[1])
    results["meta"]["complete"] = False
    results["meta"]["split"] = {"name": "test", "sha": "x"}
    results["rows"] = results["rows"][:-1]
    problems = _check(ctx, results=results)
    assert any("incomplete" in p for p in problems)
    assert any("frozen dev split" in p for p in problems)
    assert any("cover exactly" in p for p in problems)


def test_committed_attack_map_loads_without_the_bundle(monkeypatch):
    monkeypatch.setattr(gate, "DEFAULT_BUNDLE", gate.ROOT / "no-such-bundle.json")
    m = gate.load_attack_map()
    assert m.tactics and m.canonical("T1562.002") == "T1685.001"  # a known renumbering


@pytest.mark.skipif(not DEFAULT_BUNDLE.exists(), reason="ATT&CK bundle not downloaded")
def test_committed_attack_map_matches_the_bundle(monkeypatch):
    monkeypatch.setattr(gate, "DEFAULT_BUNDLE", gate.ROOT / "no-such-bundle.json")
    committed, live = gate.load_attack_map(), AttackMap.from_bundle()
    assert dict(committed.tactics) == dict(live.tactics)
    assert dict(committed.renames) == dict(live.renames)
