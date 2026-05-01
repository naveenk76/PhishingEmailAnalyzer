# 🔐 SOC Toolkit Pro (SIEM + Phishing Analyzer)

A Python-based **SOC (Security Operations Center) Toolkit** that combines a Mini SIEM system with a Phishing Email Analyzer in a unified dashboard.
This project simulates real-world security workflows including log monitoring, threat detection, alerting, and email analysis.

---

## 🚀 Features

### 🔹 SIEM Module

* 📥 Log ingestion from file
* 🧠 Brute-force detection using regex
* ⚠️ Real-time alert generation
* 🗄️ SQLite database for persistent storage
* 📊 Alert monitoring dashboard

### 🔹 Phishing Analyzer Module

* 🔍 URL extraction from email content
* ⚠️ Detection of IP-based and shortened URLs
* 🧠 Keyword-based phishing detection
* 📨 Basic header analysis (spoofing indicators)
* 📊 Risk scoring system (Low / Medium / High)

### 🔹 Dashboard

* 🖥️ PyQt6-based GUI
* 📑 Tab-based interface (SIEM + Phishing)
* 🔄 Real-time updates
* 🎯 Analyst-friendly output

---

## 🛠️ Tech Stack

* **Python 3**
* **PyQt6** – GUI framework
* **SQLite3** – Database
* **Regex (re module)** – Log and email parsing
* **Multithreading (QThread)** – Real-time monitoring

---

## 📦 Installation

```bash
git clone https://github.com/your-username/soc-toolkit-pro.git
cd soc-toolkit-pro
pip install PyQt6
```

---

## ▶️ Usage

```bash
python main.py
```

### 🧪 SIEM Module

1. Ensure `sample_logs.txt` exists in the same folder
2. Open **SIEM tab**
3. Monitor alerts in real time

### 📧 Phishing Module

1. Open **Phishing tab**
2. Paste email content
3. (Optional) Paste email headers
4. Click **Analyze Email**

---

## 📄 Sample Log File

Create `sample_logs.txt`:

```text
Failed password for invalid user admin from 192.168.1.10
Failed password for invalid user root from 192.168.1.10
Failed password for invalid user admin from 192.168.1.10
Failed password for invalid user test from 192.168.1.10
Failed password for invalid user root from 192.168.1.10
Failed password for invalid user guest from 192.168.1.10
```

---

## 🧪 Example Phishing Input

```text
Urgent! Verify your account now:
http://192.168.1.10/login
```

### Output:

```
⚠️ IP URL detected
⚠️ Suspicious keyword: urgent
⚠️ Suspicious keyword: verify

Risk: 🔴 HIGH
```

---

## 🧠 How It Works

### SIEM Flow

1. Reads logs from file
2. Detects repeated failed logins
3. Generates alerts
4. Stores alerts in SQLite
5. Displays in dashboard

### Phishing Flow

1. Extracts URLs from email
2. Analyzes domain patterns
3. Detects suspicious keywords
4. Evaluates headers
5. Calculates risk score

---

## 📁 Project Structure

```bash
main.py
sample_logs.txt
soc.db (auto-created)
```

---

## ⚠️ Limitations

* Uses simulated logs (not real-time system logs)
* Basic rule-based detection (no ML)
* Limited header analysis
* No external threat intelligence APIs

---

## 🔐 Ethical Use

This project is intended for:

* Learning cybersecurity concepts
* Demonstrating SOC workflows
* Portfolio and educational use

🚫 Do not use on systems without proper authorization.

---

## 🚀 Future Improvements

* 📊 Charts & visual analytics
* 🌐 Web dashboard (Flask/Django)
* 🔗 VirusTotal API integration
* 🧠 Advanced detection rules engine
* 📁 Email file (.eml) support
* 🔄 Multi-source log ingestion

---

## 💼 Resume Description

> Developed a SOC Toolkit integrating SIEM log monitoring and phishing email analysis with real-time detection, SQLite storage, and a PyQt6-based dashboard for security operations.

---

## 👨‍💻 Author

**Naveen Kumar**
Aspiring SOC Analyst | Python Developer
