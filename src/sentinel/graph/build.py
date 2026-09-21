"""Wires the nodes into the graph.

    ingest -> enrich -> triage -> route --(new threat)--> rule_gen -> validate --(pass)--> output
                                     \\--(benign / needs_review / covered)--> output      |
                                                                  repair <--(fail, attempts < 3)
                                                                  (fail at 3rd attempt) --> output

The two conditional edges below are the only branching logic; nodes never pick their successor.
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


def after_validate(state: SentinelState) -> Literal["repair", "output"]:
    if nodes.rule_passed(state["validations"][-1]):
        return "output"
    if state.get("attempts", 0) >= MAX_ATTEMPTS:
        return "output"
    return "repair"


def build_graph():
    g = StateGraph(SentinelState)
    for name in ("ingest", "enrich", "triage", "route", "rule_gen", "validate", "repair", "output"):
        g.add_node(name, getattr(nodes, name))

    g.add_edge(START, "ingest")
    g.add_edge("ingest", "enrich")
    g.add_edge("enrich", "triage")
    g.add_edge("triage", "route")
    g.add_conditional_edges("route", after_route)
    g.add_edge("rule_gen", "validate")
    g.add_conditional_edges("validate", after_validate)
    g.add_edge("repair", "validate")
    g.add_edge("output", END)

    return g.compile().with_config(recursion_limit=RECURSION_LIMIT)
