# 🛡️ IDS with AI

> **Hybrid Intrusion Detection System for Real-Time Network Threat Detection — Rule-Based + Machine Learning**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Dataset](#-dataset)
- [Model Performance](#-model-performance)
- [Known Limitations](#-known-limitations)
- [Project Structure](#-project-structure)
- [Author](#-author)

---

## 🎯 About

**IDS with AI** is a hybrid **Intrusion Detection System** that combines
fast **rule-based detection** with a trained **Random Forest** machine
learning model to flag malicious network activity in real time.

Built on the **UNSW-NB15** dataset, the model performs **binary
classification**: distinguishing **Normal** traffic from **Malicious**
traffic. It does not currently identify *which type* of attack occurred
(see [Known Limitations](#-known-limitations)).

### 🔥 Key Highlights

| Aspect | Details |
|--------|---------|
| 🧠 **ML Model** | Random Forest Classifier (binary: Normal/Malicious) |
| 📏 **Rule Engine** | Port-scan threshold, NULL/XMAS/FIN TCP flag detection |
| 📊 **Dataset** | UNSW-NB15 (42 features) |
| ⚡ **Processing** | Real-time packet capture + flow aggregation |
| 🌐 **Dashboard** | Auto-refreshing web UI (Flask) |
| 💾 **Storage** | SQLite database logging |

---

## ✨ Features

```
✅ Hybrid Detection          → Rule-based engine + Random Forest ML model, run together
✅ Real-time Monitoring      → Live network packet capture using Scapy
✅ Flow Aggregation          → Groups packets into flows so the ML model gets the
                                connection-level features it was trained on
✅ Web Dashboard             → Auto-refreshing UI with search, filters, and confidence bands
✅ Threat Alerts             → Visual Malicious/Normal badges with the reason for each flag
✅ Persistent Logging        → SQLite database for historical analysis
✅ Binary Classification     → Normal (0) vs Malicious (1) detection
✅ Demo Mode                 → simulate_attack.py shows alerts without needing a real attacker
```

---

## 🏗️ Architecture

```
┌──────────────┐    ┌───────────────┐    ┌──────────────────┐    ┌──────────────┐
│   Network    │───▶│  sniffer.py   │───▶│  flow_tracker.py  │───▶│ ml_detector.py│
│   Traffic    │    │ (rule engine) │    │ (groups packets   │    │ (loads model, │
└──────────────┘    └───────┬───────┘    │  into flows)      │    │  scores flow) │
                             │            └──────────────────┘    └──────┬───────┘
                             │  per-packet alerts                        │ flow verdict
                             ▼                                           ▼
                        ┌─────────────────────────────────────────────────┐
                        │              ids_logs.db (SQLite)                │
                        └───────────────────────┬───────────────────────────┘
                                                 ▼
                        ┌──────────────┐   ┌──────────────┐
                        │   app.py     │──▶│  Web Browser  │
                        │ (Flask)      │   │  Dashboard    │
                        └──────────────┘   └──────────────┘
```

Detection happens in two independent layers that both write to the same
database:

1. **Rule engine** (in `sniffer.py`) — fires instantly per packet for
   known attack signatures (port scans, NULL/XMAS/FIN scans).
2. **ML model** (`flow_tracker.py` + `ml_detector.py`) — groups packets
   belonging to the same `(src_ip, dst_ip, protocol)` flow, builds a
   feature row shaped like the training data, and asks the trained
   Random Forest to classify it once the flow has enough packets.

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- **Windows only:** [Npcap](https://npcap.com/#download) (install with
  "WinPcap API-compatible Mode" checked) — required for Scapy to capture
  live packets.

### Step 1: Clone the repository

```bash
git clone https://github.com/meghaInfosec/IDS-with-AI.git
cd IDS-with-AI
```

### Step 2: Create a virtual environment and install dependencies

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

pip install -r requirements.txt
```

### Step 3: Train the model (optional — pre-trained files are included)

```bash
python train_model.py
```

This reads `UNSW_NB15_training-set.csv` and produces:
- `ids_rf_model.pkl` → trained Random Forest model
- `ids_scaler.pkl` → feature scaler
- `ids_model_config.pkl` → feature names/order the model expects

---

## 🚀 Usage

### 1️⃣ Start the sniffer (needs admin/root — live packet capture requires it)

```bash
# Windows: run CMD "as Administrator"
python sniffer.py

# Linux/Mac
sudo python3 sniffer.py
```

Confirm `[*] ML model loaded: True` appears in the output — this means
both the rule engine and the ML model are active.

### 2️⃣ Launch the dashboard (separate terminal, while sniffer.py keeps running)

```bash
python app.py
```

### 3️⃣ Open the dashboard

```
http://127.0.0.1:5000
```

### 4️⃣ (Optional) See a Malicious alert without a real attacker

```bash
python simulate_attack.py
```

Refresh the dashboard — simulated Malicious rows appear (clearly labeled
`SIMULATED` in the reason text), including one routed through the actual
ML model so you can see both detection paths in action.

To trigger a **real** rule-based detection safely, scan your own machine
only:
```bash
nmap -sN -p 1-100 127.0.0.1      # NULL scan
nmap -sX -p 1-100 127.0.0.1      # XMAS scan
```

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| 📊 **Live Statistics** | Real-time threat counts and totals |
| 📋 **Detection Logs** | Recent network activity table, searchable and filterable |
| 🔎 **Filters** | By status, protocol, and minimum confidence |
| 🏷️ **Status Badges** | Color-coded Normal/Malicious indicators |
| 📝 **Alert Reason** | Shows whether a rule or the ML model flagged each row, and why |

---

## 📁 Dataset

### UNSW-NB15 Details

| Property | Value |
|----------|-------|
| **Name** | UNSW-NB15 |
| **Type** | Network Intrusion Detection |
| **Classes used by this model** | Binary (Normal/Malicious) |
| **Features** | 42 network traffic features |
| **Source** | University of New South Wales |

> **Note:** The full UNSW-NB15 dataset also ships an `attack_cat` column
> that labels *which* attack family a malicious row belongs to (Fuzzers,
> Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode,
> Worms). **This project drops that column during training**, so the
> model only learns Normal-vs-Malicious — it cannot currently tell you
> which of those 9 categories a detected attack falls into. Turning this
> into a multi-class classifier (training on `attack_cat` instead of the
> binary `label`) is a natural next step; see Known Limitations.

### Possible datasets for future extension

- **CSE-CIC-IDS2018** — modern traffic, 80+ flow features, covers Brute
  Force, DoS/DDoS, Heartbleed, Botnet, Infiltration, Web Attacks.
- **ToN-IoT** — IoT/IIoT telemetry + network + OS logs, covers DoS/DDoS,
  Ransomware, Backdoor, Injection, XSS, Scanning, MitM.
- **BoT-IoT** — focused on botnet behavior, covers DDoS/DoS, OS
  Fingerprinting, Service Discovery, Keylogging, Data Exfiltration.

---

## 📈 Model Performance

These numbers are from an actual run of `train_model.py` on this
project's dataset, not estimates:

```
┌────────────────────────────────────────────────────────────┐
│                  Model Evaluation Results                  │
├────────────────────────────────────────────────────────────┤
│  Metric                               │  Score              │
├────────────────────────────────────────┼─────────────────────┤
│  Accuracy (train/test split)          │  97.59%             │
│  Accuracy (full held-out test CSV,    │  90.25%             │
│   175,341 rows never trained on)      │                     │
│  Precision (Normal / Malicious)       │  0.97 / 0.98        │
│  Recall (Normal / Malicious)          │  0.98 / 0.97        │
│  F1-score (Normal / Malicious)        │  0.97 / 0.98        │
└────────────────────────────────────────────────────────────┘
```

These scores come from clean, pre-labeled CSV rows. **Live accuracy on
real packet captures will be lower** — see Known Limitations below for
why.

---

## ⚠️ Known Limitations

Worth knowing, and good talking points if this project comes up in an
interview:

1. **Binary classification only.** The model distinguishes
   Normal/Malicious; it does not identify the attack category, even
   though the dataset supports it (the `attack_cat` column is dropped
   during training).
2. **Live flow features are incomplete.** `flow_tracker.py` can only
   derive about half of the 42 trained features from raw packets alone
   (duration, packet/byte counts, TTL, window size). Features that need
   deep packet inspection or longer history — service type, HTTP-specific
   fields, counts of recent connections to the same host — default to 0
   rather than being guessed. This is why live accuracy is lower than the
   90%+ seen on the clean test CSV.
3. **Flow scoring has latency.** The ML path waits for a flow to gather
   enough packets (or go idle) before scoring it, so it's not as
   instantaneous as the per-packet rule engine.
4. **SQLite is single-machine.** Fine for a demo/portfolio project; a
   production deployment would want a proper database and a WSGI server
   instead of Flask's development server.

---

## 📂 Project Structure

```
IDS-with-AI/
│
├── 📄 train_model.py          # Trains the Random Forest (binary: Normal/Malicious)
├── 📄 flow_tracker.py         # Groups live packets into flows for the ML model
├── 📄 ml_detector.py          # Loads the trained model and scores a flow
├── 📄 sniffer.py              # Packet capture + rule engine + ML scoring (hybrid)
├── 📄 app.py                  # Flask dashboard
├── 📄 simulate_attack.py      # Demo script — injects sample alerts, no real attacker needed
├── 📄 test_capture.py         # Standalone check that Scapy can see your network interface
├── 📄 requirements.txt        # Python dependencies
│
├── 📁 templates/
│   └── 📄 index.html          # Dashboard UI
│
├── 🔧 .gitignore
│
└── 📦 Generated at runtime
    ├── ids_rf_model.pkl       # Trained model
    ├── ids_scaler.pkl         # Feature scaler
    ├── ids_model_config.pkl   # Feature names/order
    └── ids_logs.db            # Detection logs (SQLite)
```

---

## 📄 License

This project is licensed under the **MIT License** — see the
[LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

| | |
|---|---|
| **GitHub** | [@meghaInfosec](https://github.com/meghaInfosec) |
| **Email** | meghaiiitainfosec@gmail.com |

---

<div align="center">

### 🛡️ Built for learning real-world network security + applied ML

[⬆ Back to Top](#-ids-with-ai)

</div>
