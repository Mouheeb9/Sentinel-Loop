"""Wires the nodes into the graph.

    ingest -> enrich -> triage -> route --(new threat)--> rule_gen --(rule)--> validate
               route --(benign / needs_review / covered)--> output
               rule_gen --(no rule: failed / skipped)--> output
               validate --(passed, needs review, unvalidated, or fail at the last attempt)--> output
               validate --(fail, attempts < max_attempts, not stalled)--> repair
               repair --(new rule)--> validate;  repair --(no valid rule)--> output

The conditional edges below are the only branching logic; nodes never pick their successor.
"""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, START, StateGraph

from sentinel.graph import nodes
from sentinel.graph.state import MAX_ATTEMPTS, SentinelState

# Safety net, not a proof: LangGraph counts supersteps, not our node names. The longest legal
# path (11 nodes: 3 validations, 2 repairs) was measured to need a limit of 12 on langgraph
# 1.2.11. 25 leaves a wide margin, and a runaway loop raises GraphRecursionError instead of
# spinning. The path tests (give_up uses this limit) are what prove the legal paths fit.
RECURSION_LIMIT = 25


def after_route(state: SentinelState) -> Literal["rule_gen", "output"]:
    if state["verdict"].verdict != "true_positive":
        return "output"
    if state.get("covering_rule_id"):
        return "output"
    return "rule_gen"


def after_rule_gen(state: SentinelState) -> Literal["validate", "output"]:
    """No rule to validate when generation failed or was switched off."""
    return "validate" if state.get("draft_rule") else "output"


def after_validate(state: SentinelState) -> Literal["repair", "output"]:
    if state.get("validation_pending"):  # no validator yet: nothing to repair against
        return "output"
    if nodes.rule_verdict(state["validations"][-1]) != "failed":  # passed, or needs a human
        return "output"
    if state.get("attempts", 0) >= state.get("max_attempts", MAX_ATTEMPTS):
        return "output"
    if nodes.stalled(state["validations"]):
        return "output"
    return "repair"


def after_repair(state: SentinelState) -> Literal["validate", "output"]:
    return "output" if state.get("repair_failed") else "validate"


LIVE_NODES = ("enrich", "triage", "route", "rule_gen", "validate", "repair")


def build_graph(live: bool = False):
    """live=False: every node is a stub (tests). live=True: LIVE_NODES run for real."""
    g = StateGraph(SentinelState)
    for name in ("ingest", "enrich", "triage", "route", "rule_gen", "validate", "repair", "output"):
        impl = (
            getattr(nodes, f"{name}_live") if live and name in LIVE_NODES else getattr(nodes, name)
        )
        g.add_node(name, impl)

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "enrich")
    g.add_edge("enrich", "triage")
    g.add_edge("triage", "route")
    g.add_conditional_edges("route", after_route)
    g.add_conditional_edges("rule_gen", after_rule_gen)
    g.add_conditional_edges("validate", after_validate)
    g.add_conditional_edges("repair", after_repair)
    g.add_edge("output", END)

    return g.compile().with_config(recursion_limit=RECURSION_LIMIT)
