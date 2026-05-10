import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="ThreatGuard Enterprise SOC",
    layout="wide"
)

st.title("🛡️ ThreatGuard AI — Enterprise SOC Engine")
st.subheader("Multi-Log SIEM | Attack Detection | SOC Dashboard")

st.markdown("---")

# =========================================================
# SIDEBAR
# =========================================================
st.sidebar.title("⚙️ SOC Controls")

file = st.sidebar.file_uploader(
    "Upload Logs (CSV / Event Viewer / Generic)",
    type=["csv"]
)

use_sample = st.sidebar.checkbox("Use Sample Data", True)

# =========================================================
# LOAD DATA
# =========================================================
if file:
    logs = pd.read_csv(file)

elif use_sample:
    logs = pd.DataFrame({
        "event_id": ["4625","4625","4624","4634","4625","4625","4624","4625"],
        "username": ["admin","root","ali","guest","admin","root","user1","admin"],
        "ip_address": ["192.168.1.1","192.168.1.1","10.0.0.2","8.8.8.8","192.168.1.1","192.168.1.1","10.0.0.3","192.168.1.1"],
        "message": [
            "failed login","failed login","login success","logout",
            "failed login","failed login","login success","failed login"
        ]
    })
else:
    st.stop()

# =========================================================
# NORMALIZATION ENGINE
# =========================================================
logs.columns = [c.lower().strip().replace(" ", "_") for c in logs.columns]

st.info("🔄 Normalizing logs for SIEM processing...")

# =========================================================
# LOG PARSER (MULTI-SOURCE SUPPORT)
# =========================================================

# --- Event Viewer Detection ---
if "event_id" in logs.columns:

    logs["event_id"] = logs["event_id"].astype(str)

    logs["failed_logins"] = logs["event_id"].apply(
        lambda x: 1 if x in ["4625", "529", "4771"] else 0
    )

# --- Generic Log Detection ---
elif "message" in logs.columns:

    logs["failed_logins"] = logs["message"].astype(str).str.lower().apply(
        lambda x: 1 if "fail" in x or "invalid" in x else 0
    )

else:
    logs["failed_logins"] = 0

# =========================================================
# FEATURE ENGINEERING (SIEM ENRICHMENT)
# =========================================================

if "username" in logs.columns:
    logs["login_frequency"] = logs.groupby("username")["username"].transform("count")
else:
    logs["login_frequency"] = logs["failed_logins"].cumsum()

# IP anomaly (simple heuristic)
if "ip_address" in logs.columns:
    logs["repeated_ip"] = logs["ip_address"].duplicated(keep=False).astype(int)
else:
    logs["repeated_ip"] = 0

# =========================================================
# AI ANOMALY DETECTION
# =========================================================

features = logs[["failed_logins", "login_frequency"]]

if features.nunique().min() > 1:

    model = IsolationForest(contamination=0.2, random_state=42)
    logs["anomaly"] = model.fit_predict(features)

else:
    logs["anomaly"] = logs["failed_logins"].apply(lambda x: -1 if x == 1 else 1)

# =========================================================
# ATTACK DETECTION ENGINE (RULE-BASED SOC LOGIC)
# =========================================================

def detect_attack(row):

    if row["failed_logins"] >= 1 and row.get("repeated_ip", 0) == 1:
        return "BRUTE FORCE ATTACK"

    elif row["failed_logins"] >= 1:
        return "SUSPICIOUS LOGIN"

    elif row.get("repeated_ip", 0) == 1:
        return "RECON ACTIVITY"

    else:
        return "NORMAL"

logs["attack_type"] = logs.apply(detect_attack, axis=1)

threats = logs[logs["anomaly"] == -1]

# =========================================================
# DASHBOARD METRICS
# =========================================================

st.markdown("## 📊 SOC Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Logs", len(logs))
col2.metric("Threats", len(threats))
col3.metric("Attack Types", logs["attack_type"].nunique())
col4.metric("SOC Status", "ACTIVE")

st.markdown("---")

# =========================================================
# LOG VIEW
# =========================================================

st.markdown("## 📁 Raw Logs (Normalized)")

st.dataframe(logs)

# =========================================================
# THREATS
# =========================================================

st.markdown("## 🚨 Threat Intelligence")

st.dataframe(threats)

# =========================================================
# ATTACK DISTRIBUTION
# =========================================================

st.markdown("## 🎯 Attack Classification")

st.bar_chart(logs["attack_type"].value_counts())

# =========================================================
# AI GRAPH
# =========================================================

st.markdown("## 📈 AI Anomaly Map")

fig, ax = plt.subplots()

ax.scatter(
    logs["failed_logins"],
    logs["login_frequency"],
    c=logs["anomaly"]
)

ax.set_xlabel("Failed Logins")
ax.set_ylabel("Login Frequency")
ax.set_title("SOC AI Detection Engine")

st.pyplot(fig)

# =========================================================
# IP ANALYSIS
# =========================================================

if "ip_address" in logs.columns:
    st.markdown("## 🌐 IP Intelligence")
    st.bar_chart(logs["ip_address"].value_counts())

# =========================================================
# ALERT ENGINE
# =========================================================

st.markdown("## 🚨 SOC Alerts")

for _, row in threats.iterrows():

    st.error(
        f"🚨 {row['attack_type']} | "
        f"User: {row.get('username','N/A')} | "
        f"IP: {row.get('ip_address','N/A')} | "
        f"Failed Logins: {row['failed_logins']}"
    )

# =========================================================
# REPORT EXPORT (SIEM FEATURE)
# =========================================================

csv = logs.to_csv(index=False).encode("utf-8")

st.download_button(
    "📥 Download SOC Incident Report",
    data=csv,
    file_name="soc_incident_report.csv",
    mime="text/csv"
)

st.markdown("---")

st.success("🛡️ Enterprise SOC Engine Running — Multi-log detection active")