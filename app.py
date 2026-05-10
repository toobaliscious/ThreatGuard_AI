import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import random

st.set_page_config(page_title="ThreatGuard AI", layout="wide")

st.title("🛡️ ThreatGuard AI")
st.subheader("AI-Powered Cybersecurity Threat Detection Dashboard")

# Generate sample logs
data = []

# Normal activity
for i in range(200):
    failed_logins = random.randint(0, 3)
    login_frequency = random.randint(1, 5)

    data.append([failed_logins, login_frequency])

# Suspicious activity
for i in range(15):
    failed_logins = random.randint(10, 20)
    login_frequency = random.randint(15, 30)

    data.append([failed_logins, login_frequency])

logs = pd.DataFrame(
    data,
    columns=["failed_logins", "login_frequency"]
)

# AI model
model = IsolationForest(contamination=0.07)

logs['anomaly'] = model.fit_predict(logs)

# Threats
threats = logs[logs['anomaly'] == -1]

# Metrics
col1, col2, col3 = st.columns(3)

col1.metric("Total Logs", len(logs))
col2.metric("Threats Detected", len(threats))
col3.metric("AI Status", "Active")

st.divider()

# Show logs
st.write("## 📊 Login Activity")
st.dataframe(logs)

# Threat alerts
st.write("## 🚨 Threat Alerts")
st.dataframe(threats)

# Visualization
st.write("## 📈 Threat Visualization")

fig, ax = plt.subplots()

scatter = ax.scatter(
    logs['failed_logins'],
    logs['login_frequency'],
    c=logs['anomaly']
)

ax.set_xlabel("Failed Logins")
ax.set_ylabel("Login Frequency")
ax.set_title("Threat Detection Graph")

st.pyplot(fig)

st.success("ThreatGuard AI is actively monitoring suspicious behavior.")