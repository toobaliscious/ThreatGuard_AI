import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

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
            '2026-05-10 10:28',
            '2026-05-10 10:30',
            '2026-05-10 10:35',
            '2026-05-10 10:40'
        ]
    }

    logs = pd.DataFrame(sample_data)

else:

    st.warning("Please upload a CSV file or enable sample logs.")
    st.stop()

# AI FEATURES
features = logs[[
    'failed_logins',
    'login_frequency'
]]

# AI MODEL
model = IsolationForest(
    contamination=0.2,
    random_state=42
)

logs['anomaly'] = model.fit_predict(features)

# DETECT THREATS
threats = logs[
    logs['anomaly'] == -1
].copy()

# THREAT SEVERITY
severity = []

for value in threats['failed_logins']:

    if value >= 20:
        severity.append("CRITICAL")

    elif value >= 15:
        severity.append("HIGH")

    else:
        severity.append("MEDIUM")

threats['severity'] = severity

# DASHBOARD METRICS
st.markdown("## 📊 SOC Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Logs",
    len(logs)
)

col2.metric(
    "Threats Detected",
    len(threats)
)

col3.metric(
    "Critical Threats",
    len(
        threats[
            threats['severity'] == "CRITICAL"
        ]
    )
)

col4.metric(
    "SOC Status",
    "ACTIVE"
)

st.markdown("---")

# FILTERS
st.sidebar.markdown("## 🔍 Threat Filters")

severity_filter = st.sidebar.multiselect(
    "Select Severity",
    options=["CRITICAL", "HIGH", "MEDIUM"],
    default=["CRITICAL", "HIGH", "MEDIUM"]
)

filtered_threats = threats[
    threats['severity'].isin(severity_filter)
]

# LOGIN ACTIVITY
st.markdown("## 📁 Login Activity")

st.dataframe(logs)

# THREAT ALERTS
st.markdown("## 🚨 Threat Detection Alerts")

st.dataframe(filtered_threats)

# GRAPH
st.markdown("## 📈 Threat Visualization")

fig, ax = plt.subplots(figsize=(10, 6))

scatter = ax.scatter(
    logs['failed_logins'],
    logs['login_frequency'],
    c=logs['anomaly']
)

ax.set_xlabel("Failed Logins")

ax.set_ylabel("Login Frequency")

ax.set_title("ThreatGuard AI Detection Graph")

st.pyplot(fig)

# SUSPICIOUS IP ANALYSIS
st.markdown("## 🌐 Suspicious IP Addresses")

ip_counts = threats['ip_address'].value_counts()

st.bar_chart(ip_counts)

# THREAT ANALYSIS
st.markdown("## 🧠 SOC Threat Analysis")

for index, row in filtered_threats.iterrows():

    if row['severity'] == "CRITICAL":

        st.error(
            f"🚨 CRITICAL ALERT | User: {row['username']} | IP: {row['ip_address']} | Failed Logins: {row['failed_logins']}"
        )

    elif row['severity'] == "HIGH":

        st.warning(
            f"⚠️ HIGH ALERT | User: {row['username']} | IP: {row['ip_address']} | Failed Logins: {row['failed_logins']}"
        )

    else:

        st.info(
            f"ℹ️ MEDIUM ALERT | User: {row['username']} | IP: {row['ip_address']}"
        )

# DOWNLOAD REPORT
csv = filtered_threats.to_csv(index=False).encode('utf-8')

st.download_button(
    label="📥 Download Threat Report",
    data=csv,
    file_name='threat_report.csv',
    mime='text/csv'
)

# FOOTER
st.markdown("---")

st.success(
    "🛡️ ThreatGuard AI is actively monitoring suspicious login activity."
)