
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


# ==============================
# Page Configuration
# ==============================

st.set_page_config(
    page_title="Secure AI Assistant",
    page_icon="🛡️",
    layout="wide"
)


# ==============================
# Database Connection
# ==============================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "secure_ai.db"


def load_security_logs():

    if not DATABASE_PATH.exists():
        st.error(f"Database not found: {DATABASE_PATH}")
        return pd.DataFrame()

    try:
        connection = sqlite3.connect(DATABASE_PATH)

        query = """
            SELECT
                id,
                user_id,
                event_type,
                description,
                is_attack,
                created_at
            FROM security_logs
            ORDER BY created_at DESC
        """

        df = pd.read_sql_query(query, connection)
        connection.close()

        return df

    except Exception as error:
        st.error(f"Database Error: {error}")
        return pd.DataFrame()


# ==============================
# Load Data
# ==============================

df = load_security_logs()


# ==============================
# Dashboard Header
# ==============================

st.title("🛡️ Secure AI Assistant")
st.subheader("Security Monitoring Dashboard")

st.markdown(
    "Monitor security events, detect attacks, "
    "and track AI assistant activity."
)

st.divider()


if df.empty:

    st.warning("No security logs found in the database.")

else:

    # ==============================
    # Data Preparation
    # ==============================

    df["is_attack"] = pd.to_numeric(
        df["is_attack"], errors="coerce"
    ).fillna(0)

    df["created_at"] = pd.to_datetime(
        df["created_at"], errors="coerce"
    )

    total_events = len(df)

    detected_attacks = int(
        (df["is_attack"] == 1).sum()
    )

    normal_events = total_events - detected_attacks

    successful_chats = int(
        (df["event_type"] == "SECURE_CHAT_COMPLETED").sum()
    )

    # ==============================
    # Security Metrics
    # ==============================

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Events", total_events)

    col2.metric("Detected Attacks", detected_attacks)

    col3.metric("Normal Events", normal_events)

    col4.metric("Successful AI Chats", successful_chats)

    st.divider()

    # ==============================
    # Charts
    # ==============================

    st.subheader("Security Analytics")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        st.markdown("#### Events by Type")

        event_counts = (
            df["event_type"]
            .value_counts()
            .reset_index()
        )

        event_counts.columns = ["Event Type", "Count"]

        fig_events = px.bar(
            event_counts,
            x="Event Type",
            y="Count",
            color="Event Type",
            title="Security Events Distribution"
        )

        fig_events.update_layout(
            showlegend=False,
            xaxis_title="Event Type",
            yaxis_title="Number of Events"
        )

        st.plotly_chart(
            fig_events,
            use_container_width=True
        )

    with chart_col2:

        st.markdown("#### Attack vs Normal Events")

        status_df = pd.DataFrame({
            "Status": ["Attacks", "Normal Events"],
            "Count": [detected_attacks, normal_events]
        })

        fig_status = px.pie(
            status_df,
            names="Status",
            values="Count",
            hole=0.45,
            title="Security Status Distribution"
        )

        st.plotly_chart(
            fig_status,
            use_container_width=True
        )

    # ==============================
    # Events Timeline
    # ==============================

    st.divider()

    st.subheader("Security Events Timeline")

    timeline_df = df.dropna(
        subset=["created_at"]
    ).copy()

    if not timeline_df.empty:

        timeline_df["Date"] = (
            timeline_df["created_at"].dt.date
        )

        daily_events = (
            timeline_df.groupby("Date")
            .size()
            .reset_index(name="Events")
        )

        fig_timeline = px.line(
            daily_events,
            x="Date",
            y="Events",
            markers=True,
            title="Security Events Over Time"
        )

        st.plotly_chart(
            fig_timeline,
            use_container_width=True
        )

    # ==============================
    # Security Logs Table
    # ==============================

    st.divider()

    st.subheader("Security Logs")

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:

        event_options = ["All"] + sorted(
            df["event_type"].dropna().unique().tolist()
        )

        selected_event = st.selectbox(
            "Filter by Event Type",
            event_options
        )

    with filter_col2:

        selected_status = st.selectbox(
            "Filter by Security Status",
            ["All", "Attacks", "Normal Events"]
        )

    filtered_df = df.copy()

    if selected_event != "All":

        filtered_df = filtered_df[
            filtered_df["event_type"] == selected_event
        ]

    if selected_status == "Attacks":

        filtered_df = filtered_df[
            filtered_df["is_attack"] == 1
        ]

    elif selected_status == "Normal Events":

        filtered_df = filtered_df[
            filtered_df["is_attack"] == 0
        ]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        f"Showing {len(filtered_df)} of {total_events} security events."
    )
