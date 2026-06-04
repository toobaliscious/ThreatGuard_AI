# 🛡️ ThreatGuard AI – Enterprise SOC Detection Engine

An AI-powered Security Operations Center (SOC) dashboard that analyzes security logs, detects suspicious activities, identifies potential attacks, and provides real-time threat monitoring through an interactive web interface.

## 🚀 Live Demo

🔗 **Deployment:https://threatguardai-dnpqgesoq95z88xp95tuub.streamlit.app/

---

## 📌 Project Overview

ThreatGuard AI simulates core Security Information and Event Management (SIEM) capabilities by combining:

* Multi-source log ingestion
* Log normalization
* Threat detection
* AI-based anomaly detection
* Attack classification
* Security visualization
* Incident reporting

The platform enables security analysts, students, and cybersecurity enthusiasts to upload logs and instantly identify suspicious behavior through automated analysis.

---

## ✨ Features

### 📂 Multi-Log Processing

* CSV log ingestion
* Windows Event Viewer log support
* Generic security log support
* Automatic log normalization

### 🤖 AI-Powered Anomaly Detection

* Isolation Forest Machine Learning model
* Behavioral anomaly identification
* Suspicious activity detection
* Threat prioritization

### 🚨 Attack Detection

Detects:

* Brute Force Attacks
* Suspicious Login Attempts
* Reconnaissance Activity
* Normal Events

### 📊 SOC Dashboard

Provides:

* Total log statistics
* Threat metrics
* Attack classifications
* Security monitoring overview

### 🌐 IP Intelligence

* Repeated IP detection
* Source analysis
* Network activity monitoring

### 📈 Security Visualizations

* Attack distribution charts
* AI anomaly mapping
* IP activity graphs
* Threat analytics

### 📥 Incident Reporting

* Downloadable CSV reports
* Investigation-ready exports
* Security event documentation

---

## 🏗️ System Architecture

```text
Log Upload
     │
     ▼
Log Normalization
     │
     ▼
Feature Engineering
     │
     ▼
AI Anomaly Detection
(Isolation Forest)
     │
     ▼
Attack Classification
     │
     ▼
SOC Dashboard & Alerts
     │
     ▼
Incident Report Export
```

---

## 🛠️ Technologies Used

| Technology       | Purpose               |
| ---------------- | --------------------- |
| Python           | Backend Development   |
| Streamlit        | Interactive Dashboard |
| Pandas           | Data Processing       |
| Scikit-Learn     | Machine Learning      |
| Isolation Forest | Anomaly Detection     |
| Matplotlib       | Data Visualization    |

---

## 📦 Requirements

Install dependencies using:

```bash
pip install -r requirements.txt
```

### requirements.txt

```txt
streamlit
pandas
scikit-learn
matplotlib
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/toobaliscious/ThreatGuard_AI
```

```bash
cd threatguard-ai
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Application

```bash
streamlit run app.py
```

---

## 📁 Expected Log Format

Example CSV:

```csv
event_id,username,ip_address,message
4625,admin,192.168.1.1,failed login
4624,user1,10.0.0.2,login success
4634,guest,8.8.8.8,logout
```

Supported fields:

* event_id
* username
* ip_address
* message

---

## 🧠 Detection Logic

### Failed Login Detection

Windows Security Events:

| Event ID | Description                     |
| -------- | ------------------------------- |
| 4625     | Failed Logon                    |
| 529      | Failed Logon                    |
| 4771     | Kerberos Authentication Failure |

### Attack Classification Rules

| Condition                  | Classification     |
| -------------------------- | ------------------ |
| Failed login + repeated IP | Brute Force Attack |
| Failed login               | Suspicious Login   |
| Repeated IP                | Recon Activity     |
| None                       | Normal             |

---

## 📸 Dashboard Components

* SOC Overview Metrics
* Raw Log Viewer
* Threat Intelligence Panel
* Attack Distribution Chart
* AI Anomaly Visualization
* IP Intelligence Dashboard
* Security Alert Center
* Incident Report Export

---

## 🎯 Learning Objectives

This project demonstrates:

* Security Operations Center (SOC) concepts
* SIEM workflows
* Log analysis techniques
* Threat detection methodologies
* Machine Learning in cybersecurity
* Security event visualization
* Incident response fundamentals

---

## 🔮 Future Enhancements

* Real-time log streaming
* Wazuh integration
* Splunk integration
* GeoIP threat intelligence
* MITRE ATT&CK mapping
* Email alerting
* User authentication
* Cloud deployment
* Threat severity scoring
* Advanced ML detection models

---

## 👩‍💻 Author

**Tooba Aziz Ghazi**

Cybersecurity Enthusiast | SOC Analyst Aspirant | AI & Security Learner

GitHub: https://github.com/toobaliscious

LinkedIn: https://www.linkedin.com/in/tooba-aziz-ghazi-804a7b389/

---

## 📄 License

This project is intended for educational, research, and cybersecurity learning purposes.
