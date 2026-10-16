"""
simulate_attack.py
--------------------
For testing/demo purposes only, on your own machine.

Feeds synthetic "attack-shaped" events directly into the detection
functions (bypassing real network capture) so you can see alerts appear
on the dashboard without needing an actual attacker or a tool like nmap.

Run this AFTER sniffer.py is already running (so the database exists and
is being written to), then refresh the dashboard to see the alerts.

Usage:
    python simulate_attack.py
"""

import sqlite3
import datetime
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "ids_logs.db")


def insert_alert(src_ip, dst_ip, protocol, status, dst_port, confidence, reason):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO alerts
           (timestamp, src_ip, dst_ip, protocol, status, dst_port, confidence, alert_reason)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, dst_ip, protocol, status, dst_port, confidence, reason,
        ),
    )
    conn.commit()
    conn.close()


def main():
    if not os.path.exists(DB_PATH):
        print("[!] ids_logs.db not found. Start sniffer.py first (even for a few seconds)")
        print("    so the database and table get created, then run this script.")
        return

    print("[*] Simulating a rule-based detection: port scan...")
    insert_alert(
        "203.0.113.50", "192.168.1.10", "TCP", "Malicious", 0, 100,
        "Port scan against 192.168.1.10: 60 unique ports in 5s (SIMULATED)",
    )
    time.sleep(0.5)

    print("[*] Simulating a rule-based detection: NULL scan...")
    insert_alert(
        "203.0.113.99", "192.168.1.10", "TCP", "Malicious", 443, 99,
        "NULL scan (SIMULATED)",
    )
    time.sleep(0.5)

    print("[*] Simulating an ML-based detection: Random Forest flagged flow...")
    insert_alert(
        "198.51.100.23", "192.168.1.10", "TCP", "Malicious", 0, 97,
        "ML model (RandomForest) flagged this flow, confidence 97.0% (SIMULATED)",
    )

    print("\n[+] Done. Refresh http://127.0.0.1:5000 to see these alerts.")
    print("[+] These are simulated rows for demo purposes, not real detections.")


if __name__ == "__main__":
    main()
