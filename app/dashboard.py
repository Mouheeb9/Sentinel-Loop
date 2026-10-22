"""Sentinel Loop dashboard (read-only, ADR 0004): stored results, no model calls, no database.

    uv run --group dashboard streamlit run app/dashboard.py

Untrusted values (event fields, rule YAML, model reasoning, validator feedback) are shown with
st.code / st.dataframe only, never st.markdown or HTML: they come from attacker-written logs.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from sentinel.dashboard_data import (
    attempts,
    injection_runs,
    load_rows,
    loop_runs,
    loop_summary,
    trace_url,
)

st.set_page_config(page_title="Sentinel Loop", layout="wide")
st.title("Sentinel Loop")
st.caption("alert -> triage -> rule generation -> validation -> repair -> pull request")

loop_tab, injection_tab = st.tabs(["The loop", "Prompt injection"])

with loop_tab:
    runs = loop_runs()
    if not runs:
        st.info("No loop results in results/.")
        st.stop()
    run = st.selectbox(
        "Run", list(runs), index=list(runs).index("e2e-v1-ultra") if "e2e-v1-ultra" in runs else 0
    )
    rows = load_rows(runs[run])
    s = loop_summary(rows)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", s["alerts"])
    c2.metric("Rules generated", s["rules"])
    c3.metric("Passed first try", s["pass_first_try"])
    c4.metric("Passed after repair", s["pass_after_repair"])

    table = pd.DataFrame(
        [
            {
                "alert": r["alert_id"],
                "outcome": r.get("outcome"),
                "verdict": r.get("verdict"),
                "triage techniques": ", ".join(r.get("triage_techniques") or []),
                "label techniques": ", ".join(r.get("label_techniques") or []),
                "attempts": len(r.get("attempt_passes") or []),
            }
            for r in rows
        ]
    )
    st.dataframe(table, hide_index=True, width="stretch")

    alert = st.selectbox("Alert", [r["alert_id"] for r in rows])
    row = next(r for r in rows if r["alert_id"] == alert)
    left, right = st.columns(2)
    with left:
        st.subheader("Triage")
        st.dataframe(
            pd.DataFrame(
                [
                    {"field": "verdict", "value": str(row.get("verdict"))},
                    {
                        "field": "triage techniques",
                        "value": ", ".join(row.get("triage_techniques") or []),
                    },
                    {
                        "field": "label",
                        "value": f"{row.get('label')} {row.get('label_techniques')}",
                    },
                    {"field": "outcome", "value": str(row.get("outcome"))},
                ]
            ),
            hide_index=True,
            width="stretch",
        )
        if url := trace_url(row):
            st.link_button("Langfuse trace", url)
        st.subheader("Repair attempts")
        st.dataframe(pd.DataFrame(attempts(row)), hide_index=True, width="stretch")
    with right:
        st.subheader("Generated rule (model-written, untrusted)")
        st.code(row.get("rule_yaml") or "(no rule)", language="yaml")
        st.subheader("Validator report")
        st.code((row.get("validation") or {}).get("feedback") or "(not validated)", language="text")

with injection_tab:
    runs = injection_runs()
    if not runs:
        st.info("No injection results in results/.")
        st.stop()
    name = st.selectbox("Injection run", list(runs), index=len(runs) - 1)
    data = runs[name]
    totals = data["totals"] or {}
    c1, c2, c3 = st.columns(3)
    c1.metric("Attack success rate", f"{totals.get('asr', 0):.0%}" if "asr" in totals else "-")
    c2.metric("Cases counted", totals.get("counted", "-"))
    c3.metric("Successes", totals.get("success", "-"))
    st.caption(f"models: {data['models']}")
    if data["by_category"]:
        st.dataframe(
            pd.DataFrame([{"category": k, **v} for k, v in data["by_category"].items()]),
            hide_index=True,
            width="stretch",
        )
