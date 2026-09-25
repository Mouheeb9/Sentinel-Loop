"""The frozen dev/test split: disjoint, stratified, tamper-evident, dev = the baseline sample."""

from __future__ import annotations

import json

import pytest

from evals import run as ev
from evals import split as sp
from evals.triage_smoke import load_golden, sample


def test_committed_split_matches_its_hash():
    for name in sp.SPLITS:
        ids, sha = sp.load_split(name)
        assert len(ids) == 30 and len(sha) == 12


def test_dev_is_the_baseline_sample_and_test_is_disjoint():
    labels, _ = load_golden()
    dev, _ = sp.load_split("dev")
    test, _ = sp.load_split("test")
    assert dev == sorted(r["alert_id"] for r in sample(labels, 30, 5))
    assert not set(dev) & set(test)


def test_both_splits_are_stratified():
    labels = {r["alert_id"]: r["label"] for r in load_golden()[0]}
    for name in sp.SPLITS:
        ids, _ = sp.load_split(name)
        assert sum(labels[i] == "true_positive" for i in ids) == 20


def test_edited_split_is_refused(tmp_path):
    path = tmp_path / "split-v1.json"
    sp.write({"dev": {"alert_ids": ["a"]}, "test": {"alert_ids": ["b"]}}, path)
    assert sp.load_split("dev", path)[0] == ["a"]
    path.write_text(json.dumps({"dev": {"alert_ids": ["b"]}, "test": {"alert_ids": ["a"]}}))
    with pytest.raises(SystemExit, match="changed since it was frozen"):
        sp.load_split("dev", path)


def test_line_endings_do_not_change_the_hash(tmp_path):
    path = tmp_path / "split-v1.json"
    sp.write({"dev": {"alert_ids": ["a"]}, "test": {"alert_ids": ["b"]}}, path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert sp.load_split("test", path)[0] == ["b"]


def test_frozen_split_is_never_overwritten(tmp_path):
    path = tmp_path / "split-v1.json"
    sp.write({"dev": {"alert_ids": []}, "test": {"alert_ids": []}}, path)
    with pytest.raises(SystemExit, match="never regenerated"):
        sp.write({"dev": {"alert_ids": []}, "test": {"alert_ids": []}}, path)


def test_test_split_is_sealed(capsys):
    with pytest.raises(SystemExit):
        ev.main(["--split", "test", "--score-only"])
    assert "sealed" in capsys.readouterr().err


def test_split_and_n_are_exclusive():
    with pytest.raises(SystemExit):
        ev.main(["--split", "dev", "--n", "30", "--score-only"])
