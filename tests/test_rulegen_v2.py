"""Rule generation fixes from gold-v2-base (2026-11-27): repair history, list debris, duplicate
selections, dead '/' paths in CommandLine."""

from __future__ import annotations

import copy

from sentinel.agents.repair import build_repair_context, score
from sentinel.agents.rule_form import RuleDraft
from sentinel.agents.rule_gen import fix_slashes, generate_rule, render
from sentinel.graph import nodes
from tests.test_repair import EVENTS, RULE, _state, _v
from tests.test_rule_gen import VALID, VERDICT, ScriptedModel, _alert, _call


def test_score_is_counts_only():
    assert score(_v(1, missed=3, fp=2)) == "caught 1/4 held-out repeats, fired on 2 benign events"
    assert score(_v(0)) == "no repeats to test, fired on 0 benign events"


def test_history_lists_every_version_with_its_score():
    vals = [_v(4, fp=5), _v(0, missed=4)]
    ctx = build_repair_context(RULE, vals[-1], 3, 3, EVENTS.get, [RULE, RULE], vals)
    assert [(n, g) for n, _, g in ctx.history] == [
        (1, "caught 4/4 held-out repeats, fired on 5 benign events"),
        (2, "caught 0/4 held-out repeats, fired on 0 benign events"),
    ]
    assert ctx.history[0][1].startswith("detection:")
    # one version only: nothing to compare, no history section
    assert build_repair_context(RULE, vals[0], 2, 3, EVENTS.get, [RULE], vals[:1]).history == ()


def test_repair_prompt_shows_the_history():
    model = ScriptedModel(replies=[_call(VALID)], seen=[])
    state = _state(
        attempts=2, rule_versions=[RULE, RULE], validations=[_v(4, fp=5), _v(0, missed=4)]
    )
    nodes.repair_live(state, {"configurable": {"rulegen_model": model, "event_lookup": EVENTS.get}})
    prompt = model.seen[0][1].content
    assert "### Every version so far and how it scored" in prompt
    assert "Version 1: caught 4/4 held-out repeats, fired on 5 benign events" in prompt
    assert 'path="version_1"' in prompt  # rule values are untrusted


def test_list_debris_gets_the_retry():
    bad = copy.deepcopy(VALID)
    bad["selections"][0]["items"][1]["values"] = ["comsvcs', 'MiniDump']}"]
    model = ScriptedModel(replies=[_call(bad), _call(VALID)], seen=[])
    r = generate_rule(_alert(), VERDICT, [], model)
    assert r.schema_retries == 1
    assert "several values written as one string" in model.seen[1][-1].content


def test_duplicate_selections_are_dropped():
    args = copy.deepcopy(VALID)
    args["selections"] = args["selections"] * 3
    draft = RuleDraft.model_validate(args)
    assert len(draft.selections) == 1
    assert render(draft) == RULE


def test_slash_windows_path_in_commandline_is_converted():
    args = copy.deepcopy(VALID)
    args["selections"][0]["items"].append(
        {"field": "CommandLine", "match": "contains", "values": ["AppData/Roaming/", "/c"]}
    )
    draft = fix_slashes(RuleDraft.model_validate(args), _alert().events)
    assert draft.selections[0].items[2].values == ["AppData\\Roaming\\", "/c"]


def test_ioc_check_collapses_doubled_backslashes():
    """day3-157's log holds the path as typed, with a doubled backslash; the model writes one."""
    from sentinel.refs import missing_iocs

    alert = _alert()
    alert.events[0].raw["CommandLine"] = "cmd /c x.exe C:" + "\\" * 2 + "programdata\\calc.xll"
    assert missing_iocs([r"C:\programdata\calc.xll"], alert) == []
    assert missing_iocs([r"C:\programdata\other.xll"], alert) == [r"C:\programdata\other.xll"]
