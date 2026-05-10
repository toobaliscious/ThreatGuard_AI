import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# =========================
# PAGE CONFIG (UI SETUP)
# =========================
st.set_page_config(
    page_title="ThreatGuard AI SOC Engine",
    layout="wide"
)

st.title("🛡️ ThreatGuard AI SOC Engine")
st.subheader("Real-Time Log Analysis (CSV + Event Viewer Compatible)")

st.markdown("---")

# =========================
# SIDEBAR CONTROLS
# =========================
st.sidebar.title("⚙️ SOC Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Log File (CSV / Event Export)",
    type=["csv"]
)

use_sample = st.sidebar.checkbox(
    "Use Sample Logs",
    value=True
)

# =========================
# LOAD DATA
# =========================

if uploaded_file is not None:
    # Load user uploaded file
    logs = pd.read_csv(uploaded_file)

elif use_sample:
    # Sample SOC-like dataset (for demo)
    logs = pd.DataFrame({
        "username": ["admin","ali","sara","root","guest","admin","user1","admin"],
        "ip": ["192.168.1.1","10.0.0.2","10.0.0.3","192.168.1.1","8.8.8.8","192.168.1.1","10.0.0.4","192.168.1.1"],
        "event_id": [4625,4624,4624,4625,4624,4625,4624,4625],  # Windows event simulation
        "failed_logins": [1,0,0,1,0,1,0,1],
        "login_frequency": [2,1,1,3,1,4,1,5]
    })

else:
    st.warning("Please upload a file or enable sample logs.")
    st.stop()

# =========================
# NORMALIZE COLUMN NAMES
# =========================
# Makes column names consistent (important for real-world logs)
logs.columns = [
    c.strip().lower().replace(" ", "_") for c in logs.columns
]

# =========================
# EVENT VIEWER DETECTION
# =========================
# Detect Windows Event Viewer logs automatically

if "event_id" in logs.columns:

    st.info("Windows Event Viewer logs detected → converting to SOC features")

    # Convert Windows Security Event ID 4625 → failed login
    logs["failed_logins"] = logs["event_id"].apply(
        lambda x: 1 if str(x) == "4625" else 0
    )

    # If username exists, calculate login frequency per user
    if "username" in logs.columns:
        logs["login_frequency"] = logs.groupby("username")["event_id"].transform("count")
    else:
        logs["login_frequency"] = logs["failed_logins"]

# =========================
# SAFETY CHECK (IMPORTANT)
# =========================
required_cols = ["failed_logins", "login_frequency"]

missing = [col for col in required_cols if col not in logs.columns]

if missing:
    st.error(f"Missing required columns: {missing}")
    st.stop()

# =========================
# AI MODEL (ANOMALY DETECTION)
# =========================
# Isolation Forest detects unusual patterns

features = logs[required_cols]

model = IsolationForest(
    contamination=0.15,
    random_state=42
)

logs["anomaly"] = model.fit_predict(features)

# =========================
# THREAT EXTRACTION
# =========================
threats = logs[logs["anomaly"] == -1].copy()

# =========================
# DASHBOARD METRICS
# =========================
st.markdown("## 📊 SOC Dashboard Overview")

col1, col2, col3 = st.columns(3)

col1.metric("Total Logs", len(logs))
col2.metric("Threats Detected", len(threats))
col3.metric("SOC Status", "ACTIVE")

st.markdown("---")

# =========================
# LOG TABLE
# =========================
st.markdown("## 📁 All Logs")

st.dataframe(logs)

# =========================
# THREAT TABLE
# =========================
st.markdown("## 🚨 Detected Threats")

if len(threats) == 0:
    st.success("No threats detected 🎉")
else:
    st.dataframe(threats)

# =========================
# VISUALIZATION
# =========================
st.markdown("## 📈 Anomaly Detection Graph")

fig, ax = plt.subplots()

ax.scatter(
    logs["failed_logins"],
    logs["login_frequency"],
    c=logs["anomaly"]
)

ax.set_xlabel("Failed Logins")
ax.set_ylabel("Login Frequency")
ax.set_title("ThreatGuard AI - SOC Detection Graph")

st.pyplot(fig)

# =========================
# ALERT SYSTEM
# =========================
st.markdown("## 🚨 SOC Alerts")

if len(threats) > 0:

    for _, row in threats.iterrows():
        st.error(
            f"Suspicious Activity → "
            f"User: {row.get('username','N/A')} | "
            f"IP: {row.get('ip','N/A')} | "
            f"Failed Logins: {row['failed_logins']}"
        )

# =========================
# DOWNLOAD REPORT
# =========================
csv = threats.to_csv(index=False).encode("utf-8")

st.download_button(
    "📥 Download Threat Report",
    data=csv,
    file_name="soc_threat_report.csv",
    mime="text/csv"
)

# =========================
# FOOTER
# =========================
st.markdown("---")

st.success("🛡️ ThreatGuard AI SOC Engine Running Successfully")