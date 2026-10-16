from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime
import os
import sqlite3
import threading
import queue
import time
from collections import defaultdict

import ml_detector
from flow_tracker import FlowTracker

print("[*] Initializing IDS (Hybrid: Rule-Based + ML)...")

# Load the trained Random Forest model. This is the piece that was never
# wired in before - train_model.py produced the .pkl files but nothing
# loaded them for live traffic.
try:
    ml_detector.load()
    ML_ENABLED = True
except FileNotFoundError as e:
    print(f"[!] {e}")
    print("[!] Continuing with rule-based detection only.")
    ML_ENABLED = False

flow_tracker = FlowTracker()
ML_CONFIDENCE_THRESHOLD = 70  # only trust an ML "Malicious" verdict above this

# --- Optimization Settings ---
BATCH_SIZE = 50
MAX_QUEUE_SIZE = 5000
packet_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
db_queue = queue.Queue()

# --- VERY Strict Scan Detection Settings ---
SCAN_THRESHOLD = 50          # Need 50+ ports to be considered a scan (was 15)
TIME_WINDOW = 5              # Seconds (shorter window = more accurate)
BLOCK_TTL = 300              # Temporary suppression instead of permanent blocking
connection_history = defaultdict(list)
blocked_ips = {}
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ids_logs.db')

# --- Whitelist - Never flag these ---
WHITELIST = {
    '1.1.1.1', '1.0.0.1',           # Cloudflare DNS
    '8.8.8.8', '8.8.4.4',           # Google DNS
    '9.9.9.9',                      # Quad9 DNS
    '255.255.255.255',              # Broadcast
    '239.255.255.250',              # Multicast
    '127.0.0.1',                    # Localhost
    '0.0.0.0',                      # Null
}

# --- Database Setup ---
def setup_database():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       timestamp TEXT, 
                       src_ip TEXT, 
                       dst_ip TEXT, 
                       protocol TEXT, 
                       status TEXT)''')

    existing_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()
    }
    migrations = {
        'dst_port': 'ALTER TABLE alerts ADD COLUMN dst_port INTEGER DEFAULT 0',
        'confidence': 'ALTER TABLE alerts ADD COLUMN confidence INTEGER DEFAULT 0',
        'alert_reason': "ALTER TABLE alerts ADD COLUMN alert_reason TEXT DEFAULT ''",
    }

    for column, statement in migrations.items():
        if column not in existing_columns:
            cursor.execute(statement)

    conn.commit()
    return conn

# --- Thread 1: Packet Sniffer (Producer) ---
def capture_packets(packet):
    if IP in packet:
        try:
            packet_queue.put_nowait(packet)
        except queue.Full:
            pass

# --- Strict Rule-Based Detection ---
def cleanup_tracking_state(current_time):
    """Drop stale flow history and expired temporary blocks."""
    expired_keys = []
    for flow_key, events in connection_history.items():
        recent_events = [event for event in events if current_time - event[0] < TIME_WINDOW]
        if recent_events:
            connection_history[flow_key] = recent_events
        else:
            expired_keys.append(flow_key)

    for flow_key in expired_keys:
        del connection_history[flow_key]

    expired_blocks = [ip for ip, expiry in blocked_ips.items() if expiry <= current_time]
    for ip in expired_blocks:
        del blocked_ips[ip]


def detect_attack(src_ip, dst_ip, dst_port, protocol, flags_info):
    """Only detect REAL attacks - extremely strict to avoid false positives."""
    global connection_history, blocked_ips
    
    # Skip whitelisted IPs
    if src_ip in WHITELIST or dst_ip in WHITELIST:
        return [], 0
    
    # Skip private IP ranges (local network traffic)
    if src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.16.'):
        # Only check for very specific attack patterns on local network
        pass
    
    current_time = time.time()
    cleanup_tracking_state(current_time)

    # Track per source/destination/protocol flow to reduce broad false positives.
    flow_key = (src_ip, dst_ip, protocol)
    connection_history[flow_key].append((current_time, dst_port, flags_info))

    recent_connections = connection_history.get(flow_key, [])
    unique_ports = {event[1] for event in recent_connections if event[1]}
    syn_only_count = sum(1 for event in recent_connections if event[2] == "SYN")
    
    alerts = []
    confidence = 0
    
    # Rule 1: MASSIVE Port Scan (50+ unique ports in 5 seconds)
    if len(unique_ports) >= SCAN_THRESHOLD:
        alerts.append(
            f"Port scan against {dst_ip}: {len(unique_ports)} unique ports in {TIME_WINDOW}s"
        )
        blocked_ips[src_ip] = current_time + BLOCK_TTL
        confidence = 95

    # Many SYN-only attempts to the same destination within the window is suspicious.
    if protocol == "TCP" and syn_only_count >= SCAN_THRESHOLD:
        alerts.append(
            f"SYN sweep against {dst_ip}: {syn_only_count} connection attempts in {TIME_WINDOW}s"
        )
        blocked_ips[src_ip] = current_time + BLOCK_TTL
        confidence = max(confidence, 96)
    
    # Rule 2: NULL Scan (no flags - definite attack)
    if protocol == "TCP" and flags_info == "NULL":
        alerts.append("NULL scan")
        confidence = 99
    
    # Rule 3: XMAS Scan (FIN+PSH+URG - definite attack)
    if protocol == "TCP" and flags_info == "XMAS":
        alerts.append("XMAS scan")
        confidence = 99
    
    # Rule 4: FIN Scan (only FIN flag - suspicious)
    if protocol == "TCP" and flags_info == "FIN":
        alerts.append("FIN scan")
        confidence = 90
    
    # Rule 5: Blocked IP continuing
    if src_ip in blocked_ips:
        remaining_seconds = int(max(0, blocked_ips[src_ip] - current_time))
        alerts.append(f"Repeated traffic from temporarily blocked source ({remaining_seconds}s left)")
        confidence = 100

    return alerts, confidence

def score_ready_flows():
    """Pull any flows the tracker considers complete and run them through
    the trained Random Forest. Returns a list of db-ready alert tuples."""
    if not ML_ENABLED:
        return []

    records = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for (src_ip, dst_ip, protocol), feature_dict in flow_tracker.pop_ready_flows():
        label, confidence = ml_detector.score(feature_dict)
        if label == "Malicious" and confidence >= ML_CONFIDENCE_THRESHOLD:
            status = "Malicious"
            reason = f"ML model (RandomForest) flagged this flow, confidence {confidence}%"
            print(f"[!] ML DETECTED: {src_ip} -> {dst_ip} ({protocol}) | {reason}")
        else:
            status = "Normal"
            reason = ""
        records.append((timestamp, src_ip, dst_ip, protocol, status, 0, int(confidence), reason))
    return records


# --- Thread 2: Packet Processor ---
def process_packets():
    normal_count = 0
    malicious_count = 0
    
    while True:
        batch = []
        packet_metadata = []
        
        while len(batch) < BATCH_SIZE:
            try:
                pkt = packet_queue.get(timeout=1)
                batch.append(pkt)
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other"
                dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                
                # Get TCP flags
                flags_info = "normal"
                if TCP in pkt:
                    flags = str(pkt[TCP].flags)
                    if flags == "" or flags == "0":
                        flags_info = "NULL"
                    elif "F" in flags and "P" in flags and "U" in flags:
                        flags_info = "XMAS"
                    elif flags == "F":
                        flags_info = "FIN"
                    elif "S" in flags and "A" not in flags:
                        flags_info = "SYN"
                
                packet_metadata.append((src_ip, dst_ip, protocol, dst_port, flags_info))

                # Feed the flow tracker so the ML model has aggregated
                # flow-level stats to score once this flow is "ready".
                pkt_len = len(pkt)
                ttl = pkt[IP].ttl if IP in pkt else 0
                win = pkt[TCP].window if TCP in pkt else 0
                flow_tracker.update(src_ip, dst_ip, protocol, pkt_len, ttl, win, direction="fwd")

            except queue.Empty:
                break
        
        if not batch:
            continue

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db_records = []
        
        for i in range(len(batch)):
            src_ip, dst_ip, protocol, dst_port, flags_info = packet_metadata[i]
            
            # Check detection (fast, per-packet rules: scans, malformed flags)
            alerts, confidence = detect_attack(src_ip, dst_ip, dst_port, protocol, flags_info)
            
            # Only flag if HIGH confidence (90%+)
            if alerts and confidence >= 90:
                status = "Malicious"
                malicious_count += 1
                alert_reason = "; ".join(alerts)
                for alert in alerts:
                    print(f"[!] ATTACK DETECTED: {src_ip} -> {dst_ip}:{dst_port} | {alert} | Confidence: {confidence}%")
            else:
                status = "Normal"
                normal_count += 1
                alert_reason = ""
            
            db_records.append((timestamp, src_ip, dst_ip, protocol, status, dst_port, confidence, alert_reason))

        # Any flows that have gathered enough packets (or gone idle) get
        # scored by the Random Forest model here, separate from the
        # per-packet rules above.
        db_records.extend(score_ready_flows())

        db_queue.put(db_records)
        
        # Print summary every 100 packets
        if (normal_count + malicious_count) % 100 == 0:
            print(f"[*] Stats | Normal: {normal_count} | Malicious: {malicious_count}")

# --- Thread 3: Database Writer ---
def database_worker():
    conn = setup_database()
    cursor = conn.cursor()
    
    while True:
        try:
            records = db_queue.get()
            if records is None:
                break
            
            cursor.executemany(
                '''INSERT INTO alerts
                   (timestamp, src_ip, dst_ip, protocol, status, dst_port, confidence, alert_reason)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                records,
            )
            conn.commit()
            
        except Exception as e:
            print(f"[!] Database Error: {e}")
            
    conn.close()

# --- Main Execution ---
if __name__ == "__main__":
    print(f"[*] Rule-based: {SCAN_THRESHOLD}+ ports in {TIME_WINDOW}s, NULL/XMAS/FIN scans (90%+ confidence)")
    print(f"[*] Temporary block TTL: {BLOCK_TTL}s")
    print("[*] Whitelisted: DNS (1.1.1.1, 8.8.8.8), Multicast, Broadcast")
    print(f"[*] ML-based: Random Forest scores each flow once it has enough packets ({ML_CONFIDENCE_THRESHOLD}%+ confidence)")
    print(f"[*] ML model loaded: {ML_ENABLED}\n")
    
    db_thread = threading.Thread(target=database_worker, daemon=True)
    db_thread.start()
    
    processor_thread = threading.Thread(target=process_packets, daemon=True)
    processor_thread.start()
    
    print("[*] Starting Packet Sniffer... (Press Ctrl+C to stop)")
    print("[*] Test with: nmap -sN -p 1-100 <this_pc_ip> (NULL scan)")
    print("[*] Test with: nmap -sX -p 1-100 <this_pc_ip> (XMAS scan)")
    print("[*] Normal traffic will NOT be flagged\n")
    
    try:
        sniff(prn=capture_packets, store=0) 
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        db_queue.put(None)
        time.sleep(1)
        print("[+] System offline.")
