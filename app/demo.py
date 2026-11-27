"""Sentinel Loop demo: watch one alert travel through the pipeline, node by node.

    uv run --group dashboard streamlit run app/demo.py                 # replay recordings only
    DEMO_LIVE=1 uv run --group dashboard streamlit run app/demo.py     # + run alerts for real

Replay plays a recording (results/demo/, made with `python -m sentinel.demo record`) with its real
per-node timings, sped up: no model, no database. Live runs the real pipeline on the alert in the
editor (models + Postgres) and never opens a pull request.

Untrusted values (event fields, model reasoning, rule YAML, validator feedback) are shown with
st.code / st.dataframe only, never st.markdown or HTML (ADR 0004): visitors write the alert.
"""

from __future__ import annotations

import json
import os
import time

import streamlit as st

from sentinel import demo

LIVE_ALLOWED = os.environ.get("DEMO_LIVE") == "1"
MAX_ALERT_BYTES, MAX_EVENTS = 20_000, 5
SPEEDS = {"1x": 1, "2x": 2, "5x": 5, "20x": 20}
TITLES = {
    "ingest": "Ingest: the alert as logged",
    "enrich": "Enrich: what ATT&CK and SigmaHQ search found",
    "triage": "Triage: the model's verdict",
    "route": "Route: does a rule already catch it?",
    "rule_gen": "Rule generation: a new Sigma rule",
    "validate": "Validate: run the rule on labeled logs",
    "repair": "Repair: fix the rule from the validator's report",
    "output": "Output",
}
OUTCOMES = {
    "benign": "Benign: closed, nothing to write.",
    "needs_review": "Needs review: sent to an analyst.",
    "covered": "Real threat, already caught by an existing rule.",
}

st.set_page_config(page_title="Sentinel Loop demo", page_icon=":material/radar:", layout="wide")


@st.cache_data(ttl=3600)
def edges() -> list[tuple[str, str]]:
    return demo.graph_edges()


def dataframe(rows: list[dict], alt: str) -> None:
    if rows:
        st.dataframe(rows, hide_index=True, alt=alt)


def render_event(ev: dict, alert: dict, n_validations: int) -> None:
    """One node's panel. Values from the alert or a model only via st.code / st.dataframe."""
    node, u = ev["node"], ev["update"]
    if node == "ingest":
        dataframe(demo.event_rows(alert), "Log events in the alert")
        st.caption("Fields an attacker can write (treated as data, never as instructions):")
        st.code(", ".join(sorted({f for e in alert["events"] for f in e["untrusted_fields"]})))
    elif node == "enrich":
        left, right = st.columns(2)
        with left:
            st.caption("ATT&CK techniques")
            dataframe(demo.hit_rows(u.get("techniques") or []), "Top ATT&CK techniques")
        with right:
            st.caption("Existing SigmaHQ rules")
            dataframe(demo.hit_rows(u.get("sigma_rules") or []), "Top Sigma rules")
    elif node == "triage":
        v = u.get("verdict") or {}
        with st.container(horizontal=True):
            st.metric("Verdict", v.get("verdict", "?"), border=True)
            st.metric("Confidence", f"{v.get('confidence', 0):.2f}", border=True)
            tier = u.get("triage_tier")
            st.metric("Model tier", "escalated" if tier == 2 else "first", border=True)
            cost = u.get("triage_cost_usd")
            st.metric("Cost", "free" if not cost else f"${cost:.4f}", border=True)
        if u.get("triage_escalation"):
            st.caption("Why it escalated to the bigger model:")
            st.code(u["triage_escalation"], wrap_lines=True)
        looks = demo.lookup_rows(u)
        if looks:
            st.caption("Threat-intel lookups")
            dataframe(looks, "ThreatFox and NVD lookups")
        st.caption("ATT&CK techniques / IOCs")
        st.code(
            f"techniques: {', '.join(v.get('technique_ids') or []) or '-'}\n"
            f"iocs:       {', '.join(v.get('ioc_refs') or []) or '-'}",
            wrap_lines=True,
        )
        st.caption("Reasoning (model-written)")
        st.code(v.get("reasoning", ""), language=None, wrap_lines=True)
    elif node == "route":
        cov = u.get("covering_rule_id")
        if cov:
            st.success(
                "An existing SigmaHQ rule already fires on this alert.", icon=":material/check:"
            )
            st.code(cov)
        elif "coverage" in u:
            st.warning("No existing rule fires on this alert: write one.", icon=":material/edit:")
        else:
            st.info("Not a confirmed threat: no rule needed.", icon=":material/do_not_disturb_on:")
    elif node in ("rule_gen", "repair"):
        info = u.get("rulegen") or ((u.get("repairs") or [{}])[-1])
        if info.get("error"):
            st.error("The model gave no valid rule.", icon=":material/error:")
            st.code(info["error"], wrap_lines=True)
        else:
            if node == "repair":
                st.caption(f"Attempt {u.get('attempts', '?')}")
            st.code(u.get("draft_rule", ""), language="yaml")
    elif node == "validate":
        val = (u.get("validations") or [{}])[-1]
        verdict = demo.validation_verdict(u)
        held_out = val.get("true_positives", 0) + sum(
            1 for f in val.get("failed_samples", []) if f.get("should_fire")
        )
        with st.container(horizontal=True):
            st.metric("Rule version", n_validations, border=True)
            st.metric("Result", verdict or "pending", border=True)
            st.metric(
                "Repeats of the attack caught",
                f"{val.get('true_positives', 0)} / {held_out}",
                border=True,
            )
            st.metric("Benign events hit", val.get("false_positives", 0), border=True)
        if val.get("feedback"):
            st.caption("Validator report (what repair reads)")
            st.code(val["feedback"], wrap_lines=True)
    elif node == "output":
        outcome = u.get("outcome", "?")
        text = OUTCOMES.get(outcome, f"Outcome: {outcome}")
        if u.get("best_attempt"):
            text += f" Kept rule version {u['best_attempt']}."
        st.success(text, icon=":material/flag:")
        if outcome not in OUTCOMES:
            st.caption("In production this opens a pull request; CI's rule gate decides the merge.")


class View:
    """The graph slot and the panels, redrawn as events arrive (replay or live)."""

    def __init__(self, alert: dict) -> None:
        self.alert = alert
        self.events: list[dict] = []
        self.graph = st.empty()
        self.status = st.empty()
        self.panels = st.container()
        self.draw()

    def draw(self, running: str | None = None) -> None:
        self.graph.graphviz_chart(
            demo.graph_dot(self.events, running, edges()),
            width="stretch",
            alt="Sentinel Loop pipeline graph, nodes lit as the alert passes",
        )

    def add(self, ev: dict) -> None:
        self.events.append(ev)
        n_val = sum(1 for e in self.events if e["node"] == "validate")
        with self.panels:
            label = f"{len(self.events)}. {TITLES.get(ev['node'], ev['node'])}"
            label += f"  ({ev['end'] - ev['start']:.1f} s)"
            with st.expander(label, expanded=True):
                render_event(ev, self.alert, n_val)


def replay(rec: dict, speed: float, cap: float, animate: bool) -> None:
    view = View(rec["meta"]["alert"])
    for ev in rec["events"]:
        if animate:
            view.draw(running=ev["node"])
            took = ev["end"] - ev["start"]
            view.status.caption(f"{ev['node']} running... (took {took:.1f} s for real)")
            time.sleep(min(took / speed, cap))
        view.add(ev)
    view.draw()
    view.status.caption(f"Done: {' -> '.join(rec['meta']['path'])}")


def parse_alert(text: str):
    from sentinel.schemas import Alert

    if len(text.encode("utf-8")) > MAX_ALERT_BYTES:
        raise ValueError(f"alert is over {MAX_ALERT_BYTES // 1000} KB")
    alert = Alert.model_validate_json(text)
    if len(alert.events) > MAX_EVENTS:
        raise ValueError(f"at most {MAX_EVENTS} events per alert")
    return alert


def run_live(alert) -> None:
    view = View(alert.model_dump(mode="json"))
    view.draw(running="ingest")
    view.status.caption("ingest running...")

    def on_event(ev: dict) -> None:
        view.add(ev)
        nxt = demo.NEXT.get(ev["node"])
        view.draw(running=nxt)
        view.status.caption(f"{nxt} running..." if nxt else "running...")

    try:
        rec = demo.record(alert, "live", on_event=on_event)
    except Exception as e:  # noqa: BLE001 - show the failure, keep the page up
        st.error("The run failed.", icon=":material/error:")
        st.code(f"{type(e).__name__}: {e}"[:2000], wrap_lines=True)
        return
    view.draw()
    view.status.caption(f"Done: {' -> '.join(rec['meta']['path'])}")
    st.session_state["last_live"] = rec


# --- page ------------------------------------------------------------------------------------

st.title("Watch an alert travel through Sentinel Loop")
st.caption(
    "Triage with ATT&CK retrieval and threat-intel lookups, then, for a real threat no rule "
    "catches, a Sigma rule written, validated on labeled logs and repaired."
)

recs = demo.recordings()
with st.sidebar:
    modes = ["Replay", "Live"] if LIVE_ALLOWED else ["Replay"]
    mode = st.segmented_control("Mode", modes, default="Replay", required=True)

if mode == "Replay":
    if not recs:
        st.info(
            "No recordings yet: `uv run python -m sentinel.demo record ...`", icon=":material/info:"
        )
        st.stop()
    with st.sidebar:
        name = st.selectbox("Recording", list(recs))
        speed = SPEEDS[st.segmented_control("Speed", list(SPEEDS), default="5x", required=True)]
        cap = st.slider("Longest wait per node (s)", 0.5, 10.0, 3.0, 0.5)
        play = st.button("Play", icon=":material/play_arrow:", type="primary", width="stretch")
    rec = demo.load(recs[name])
    st.caption(f"Recorded {rec['meta']['recorded_at']} with {rec['meta']['models']}")
    replay(rec, speed, cap, animate=play)
else:
    with st.sidebar:
        start = st.selectbox("Start from", list(recs) or ["(no recordings)"])
    seed = json.dumps(demo.load(recs[start])["meta"]["alert"], indent=2) if start in recs else ""
    text = st.text_area(
        "Alert JSON (edit anything, e.g. swap the IP)", seed, height=260, key=f"a-{start}"
    )
    go = st.button("Run for real", icon=":material/bolt:", type="primary")
    if go:
        try:
            alert = parse_alert(text)
        except Exception as e:  # noqa: BLE001 - pydantic or size error, shown to the visitor
            st.error("That alert doesn't fit the schema.", icon=":material/error:")
            st.code(str(e)[:2000], wrap_lines=True)
        else:
            run_live(alert)
    elif "last_live" in st.session_state:
        replay(st.session_state["last_live"], 1, 0, animate=False)
