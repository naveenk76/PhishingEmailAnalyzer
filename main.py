import sys
import re
import sqlite3
import time
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QLabel, QLineEdit, QHBoxLayout, QTabWidget
)
from PyQt6.QtCore import QThread, pyqtSignal

# CONFIG 
LOG_FILE = "sample_log.txt"
FAILED_THRESHOLD = 5

SUSPICIOUS_KEYWORDS = ["urgent", "verify", "login", "password", "bank", "account"]
SHORTENERS = ["bit.ly", "tinyurl.com"]

# DATABASE 
def init_db():
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            type TEXT,
            attempts INTEGER,
            severity TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

def insert_alert(alert):
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (ip, type, attempts, severity, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (alert["ip"], alert["type"], alert["attempts"], alert["severity"], alert["time"]))
    conn.commit()
    conn.close()

def fetch_alerts():
    conn = sqlite3.connect("soc.db")
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows

#  SIEM DETECTION 
FAILED_PATTERN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

def analyze_logs():
    failed = defaultdict(int)

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                match = FAILED_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    failed[ip] += 1
    except:
        return []

    alerts = []
    for ip, count in failed.items():
        if count >= FAILED_THRESHOLD:
            alerts.append({
                "ip": ip,
                "type": "Brute Force",
                "attempts": count,
                "severity": "High",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

    return alerts

# THREAD 
class MonitorThread(QThread):
    alert_signal = pyqtSignal(dict)

    def run(self):
        seen = set()
        while True:
            alerts = analyze_logs()
            for alert in alerts:
                key = (alert["ip"], alert["attempts"])
                if key not in seen:
                    seen.add(key)
                    insert_alert(alert)
                    self.alert_signal.emit(alert)
            time.sleep(5)

# PHISHING 
def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text)

def is_ip_url(url):
    return re.match(r'https?://\d+\.\d+\.\d+\.\d+', url)

def analyze_email(email, headers):
    findings = []
    score = 0

    urls = extract_urls(email)

    for url in urls:
        domain = urlparse(url).netloc

        if is_ip_url(url):
            findings.append(f"⚠️ IP URL → {url}")
            score += 3

        if any(s in domain for s in SHORTENERS):
            findings.append(f"⚠️ Shortened URL → {url}")
            score += 2

    for word in SUSPICIOUS_KEYWORDS:
        if word in email.lower():
            findings.append(f"⚠️ Keyword → {word}")
            score += 1

    if "spoof" in headers.lower():
        findings.append("⚠️ Spoofed header suspected")
        score += 3

    if "received:" not in headers.lower():
        findings.append("⚠️ Missing Received header")
        score += 2

    return findings, score

def risk(score):
    if score >= 7:
        return "🔴 HIGH", "#ff1a1a"
    elif score >= 4:
        return "🟠 MEDIUM", "#ffa500"
    else:
        return "🟢 LOW", "#4dff88"

# GUI 
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 SOC Toolkit Pro")
        self.setGeometry(200, 200, 1000, 650)
        self.setStyleSheet(self.style())

        self.tabs = QTabWidget()
        self.siem_tab()
        self.phishing_tab()

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.setLayout(layout)

        self.start_monitor()

    # ---------- SIEM TAB ---------- #
    def siem_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.stats = QLabel("Total Alerts: 0")
        layout.addWidget(self.stats)

        btn = QPushButton("Refresh")
        btn.clicked.connect(self.load_alerts)
        layout.addWidget(btn)

        self.alert_output = QTextEdit()
        layout.addWidget(self.alert_output)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "SIEM")

    # ---------- PHISHING TAB ---------- #
    def phishing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.email = QTextEdit()
        self.email.setPlaceholderText("Paste email content...")
        layout.addWidget(self.email)

        self.headers = QTextEdit()
        self.headers.setPlaceholderText("Paste headers...")
        layout.addWidget(self.headers)

        btn = QPushButton("Analyze Email")
        btn.clicked.connect(self.run_phishing)
        layout.addWidget(btn)

        self.result = QLabel("Risk:")
        layout.addWidget(self.result)

        self.phish_output = QTextEdit()
        layout.addWidget(self.phish_output)

        tab.setLayout(layout)
        self.tabs.addTab(tab, "Phishing")

    def start_monitor(self):
        self.thread = MonitorThread()
        self.thread.alert_signal.connect(self.display_alert)
        self.thread.start()

    def display_alert(self, alert):
        self.alert_output.append(f"[{alert['severity']}] {alert['ip']} ({alert['attempts']})")
        self.update_stats()

    def load_alerts(self):
        self.alert_output.clear()
        rows = fetch_alerts()
        for row in rows:
            _, ip, typ, attempts, severity, ts = row
            self.alert_output.append(f"[{severity}] {ip} ({attempts}) @ {ts}")
        self.update_stats()

    def update_stats(self):
        rows = fetch_alerts()
        self.stats.setText(f"Total Alerts: {len(rows)}")

    def run_phishing(self):
        findings, score = analyze_email(
            self.email.toPlainText(),
            self.headers.toPlainText()
        )

        r, color = risk(score)
        self.result.setText(f"Risk: {r}")
        self.result.setStyleSheet(f"color:{color}; font-size:16px;")

        self.phish_output.clear()
        if findings:
            for f in findings:
                self.phish_output.append(f)
        else:
            self.phish_output.setText("✅ No major threats")

    def style(self):
        return """
        QWidget { background:#0f172a; color:#e2e8f0; font-family:Segoe UI; }
        QPushButton { background:#2563eb; padding:8px; border-radius:6px; }
        QPushButton:hover { background:#1d4ed8; }
        QTextEdit { background:#020617; border-radius:6px; }
        """

# RUN 
if __name__ == "__main__":
    init_db()
    app = QApplication(sys.argv)
    win = App()
    win.show()
    sys.exit(app.exec())
