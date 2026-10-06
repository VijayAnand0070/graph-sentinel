"""Streamlit analyst console consuming only GraphSentinel's public API."""

from __future__ import annotations

import os
from importlib import import_module

from graphsentinel.dashboard.client import DashboardApiClient


def main() -> None:
    try:
        st = import_module("streamlit")
    except ImportError as error:
        raise RuntimeError(
            'Install dashboard dependencies with: pip install -e ".[dashboard]"'
        ) from error

    st.set_page_config(page_title="GraphSentinel", page_icon="🛡️", layout="wide")
    st.title("GraphSentinel")
    st.caption("Temporal lateral-movement detection and evidence-grounded investigation")
    base_url = st.sidebar.text_input(
        "API URL", value=os.getenv("GRAPHSENTINEL_API_URL", "http://127.0.0.1:8000")
    )
    minimum_risk = st.sidebar.slider("Minimum risk", 0.0, 1.0, 0.5, 0.01)
    limit = st.sidebar.number_input("Alert limit", 1, 1_000, 100)
    client = DashboardApiClient(base_url)
    try:
        health = client.health()
        metrics = client.metrics()
        alerts = client.alerts(minimum_risk=minimum_risk, limit=int(limit))
    except RuntimeError as error:
        st.error(str(error))
        st.stop()

    st.sidebar.success(f"API {health['version']} available")
    st.sidebar.write("Frozen model:", "loaded" if health["model_loaded"] else "not loaded")
    overview, queue, investigation, model_tab = st.tabs(
        ["Overview", "Alert queue", "Investigation", "Model & operations"]
    )
    repository = metrics["repository"]
    runtime = metrics["runtime"]
    with overview:
        columns = st.columns(4)
        columns[0].metric("Scored events", repository["scored_events"])
        columns[1].metric("Alerts", repository["alerts"])
        columns[2].metric("Suspicious paths", repository["paths"])
        columns[3].metric("Alert rate", f"{repository['alert_rate']:.2%}")
        st.subheader("Runtime")
        st.json(runtime)

    with queue:
        if not alerts:
            st.info("No alerts match the current filter.")
        else:
            st.dataframe(
                [
                    {
                        "alert_id": alert["alert_id"],
                        "timestamp": alert["timestamp"],
                        "risk": alert["risk"],
                        "status": alert["status"],
                        "user": alert["evidence"]["event"]["user"],
                        "source": alert["evidence"]["event"]["source_host"],
                        "destination": alert["evidence"]["event"]["destination_host"],
                    }
                    for alert in alerts
                ],
                use_container_width=True,
                hide_index=True,
            )

    with investigation:
        if alerts:
            selected_id = st.selectbox("Alert", [alert["alert_id"] for alert in alerts])
            selected = next(alert for alert in alerts if alert["alert_id"] == selected_id)
            st.subheader("Evidence bundle")
            st.json(selected["evidence"])
            path_id = selected["evidence"].get("path_id")
            if path_id:
                st.subheader("Suspicious path")
                st.json(client.path(path_id))
            if st.button("Generate evidence-grounded triage", type="primary"):
                selected = client.triage(selected_id)
            if selected.get("triage"):
                st.subheader("Triage report")
                st.json(selected["triage"])
        else:
            st.info("Select a lower risk threshold or replay events to investigate alerts.")

    with model_tab:
        st.json(metrics)
        if health["model_loaded"]:
            st.subheader("Frozen checkpoint provenance")
            st.json(client.model())
        else:
            st.warning("No frozen checkpoint is loaded; external TGN components are required.")


if __name__ == "__main__":
    main()
