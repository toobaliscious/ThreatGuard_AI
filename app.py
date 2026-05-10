import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from datetime import datetime

# PAGE CONFIG
st.set_page_config(
    page_title="ThreatGuard AI SOC Dashboard",
    layout="wide"
)

# TITLE
st.title("🛡️ ThreatGuard AI")
st.subheader("AI-Powered SOC Threat Detection Dashboard")

st.markdown("---")

# SIDEBAR
st.sidebar.title("⚙️ SOC Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Log CSV File",
    type=["csv"]
)

# SAMPLE DATA OPTION
use_sample = st.sidebar.checkbox(
    "Use Sample SOC Logs",
    value=True
)

# LOAD DATA
if uploaded_file is not None:

    logs = pd.read_csv(uploaded_file)

elif use_sample:

    sample_data = {
        'username': [
            'admin', 'ahmed', 'fatima', 'root',
            'guest', 'admin', 'ali', 'admin',
            'sara', 'root', 'admin', 'guest'
        ],

        'ip_address': [
            '192.168.1.5', '10.0.0.2', '172.16.0.4',
            '192.168.1.5', '10.0.0.8', '45.33.21.1',
            '172.16.0.9', '185.220.101.5',
            '10.0.0.3', '192.168.1.5',
            '203.0.113.1', '10.0.0.8'
        ],

        'failed_logins': [
            1, 0, 2, 15, 0, 18,
            1, 22, 0, 17, 25, 1
        ],

        'login_frequency': [
            2, 1, 3, 24, 1, 30,
            2, 35, 1, 28, 40, 2
        ],

        'timestamp': [
            '2026-05-10 10:00',
            '2026-05-10 10:05',
            '2026-05-10 10:10',
            '2026-05-10 10:12',
            '2026-05-10 10:15',
            '2026-05-10 10:20',
            '2026-05-10 10:22',
            '2026-05-10 10:25',
)