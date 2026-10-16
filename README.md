# 🛡️ IDS with AI

> **AI-Driven Intrusion Detection System for Real-Time Network Threat Detection**

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
- [Screenshots](#-screenshots)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [Author](#-author)

---

## 🎯 About

**IDS with AI** is an intelligent **Intrusion Detection System** that leverages **Machine Learning** to detect and alert malicious network activities in real-time. 

Built with the renowned **UNSW-NB15** dataset, this system employs a **Random Forest classifier** to achieve high-accuracy detection of network intrusions, distinguishing between **Normal** and **Malicious** traffic patterns.

### 🔥 Key Highlights

| Aspect | Details |
|--------|---------|
| 🧠 **AI Model** | Random Forest Classifier |
| 📊 **Dataset** | UNSW-NB15 (42 features) |
| ⚡ **Processing** | Real-time packet analysis |
| 🌐 **Dashboard** | Auto-refreshing web UI |
| 💾 **Storage** | SQLite database logging |

---

## ✨ Features

```
✅ AI-Powered Detection     → Random Forest ML model with ~85-90% accuracy
✅ Real-time Monitoring      → Live network packet capture using Scapy  
✅ Web Dashboard             → Beautiful, responsive UI with auto-refresh
✅ Threat Alerts             → Instant visual notifications for malicious activity
✅ Persistent Logging        → SQLite database for historical analysis
✅ Binary Classification     → Normal (0) vs Malicious (1) detection
✅ Modular Design            → Easy to extend with additional models
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         IDS with AI Architecture                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐         │
│   │   Network    │─────▶│   AI Sniffer │─────▶│   SQLite     │         │
│   │   Traffic    │      │  (Scapy+ML)  │      │   Database   │         │
│   └──────────────┘      └──────────────┘      └──────┬───────┘         │
│                                                      │                  │
│                                                      ▼                  │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐         │
│   │   Web        │◀─────│    Flask     │◀─────│  Detection   │         │
│   │   Browser    │      │    Server    │      │     Logs     │         │
│   └──────────────┘      └──────────────┘      └──────────────┘         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- Git
- pip (Python package manager)

### Step 1: Clone Repository

```bash
git clone https://github.com/shamanthwick/IDS-With-AI.git
cd IDS-With-AI
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Download Dataset

Download the UNSW-NB15 training dataset:
- Search for `UNSW_NB15_training-set.csv` online
- Place it in the project root folder

### Step 4: Train AI Model

```bash
python train_model.py
```

This generates:
- `ids_rf_model.pkl` → Trained Random Forest model
- `ids_scaler.pkl` → Feature scaler

---

## 🚀 Usage

### 1️⃣ Start Network Sniffer

```bash
python sniffer.py
```

### 2️⃣ Launch Web Dashboard

Open a new terminal:

```bash
python app.py
```

### 3️⃣ Access Dashboard

Open browser and navigate to:

```
http://127.0.0.1:5000
```

---

## 📊 Dashboard Features

| Feature | Description |
|---------|-------------|
| 📊 **Live Statistics** | Real-time threat counts and totals |
| 📋 **Detection Logs** | Recent network activity table |
| 🔄 **Auto-Refresh** | Updates every 3 seconds |
| 🏷️ **Status Badges** | Color-coded Normal/Malicious indicators |
| 🎨 **Dark Theme** | Modern, eye-friendly UI |

---

## 📁 Dataset

### UNSW-NB15 Details

| Property | Value |
|----------|-------|
| **Name** | UNSW-NB15 |
| **Type** | Network Intrusion Detection |
| **Classes** | Binary (Normal/Malicious) |
| **Features** | 42 network traffic features |
| **Source** | University of New South Wales |

### Attack Categories Covered

- 🖥️ Fuzzers
- 🔍 Analysis
- 🚪 Backdoors
- 💥 DoS (Denial of Service)
- 🎯 Exploits
- 🔀 Generic
- 📡 Reconnaissance
- 💉 Shellcode
- 🐛 Worms

---

## 🚀 Additional Datasets & Future Improvements

To enhance the robustness of this IDS, future iterations can incorporate more modern and diverse datasets:

### 1. CSE-CIC-IDS2018
A large-scale dataset created by the Canadian Institute for Cybersecurity (CIC) representing modern network traffic environments.
- **Key Features:**
    - Capture period of 10 days with realistic background traffic.
    - Extensive feature set (80+ network flow features).
    - Large volume of data (terabytes of raw traffic).
- **Types of Attacks:** Brute Force, DoS, DDoS, Heartbleed, Botnet, Infiltration, and Web Attacks.
- **Why it's Modern:** It captures much newer attack vectors and more complex network topologies compared to UNSW-NB15.

### 2. ToN-IoT
A heterogeneous dataset collecting data from Telemetry, Operating Systems, and Network (ToN) sensors in an IoT/IIoT environment.
- **Key Features:**
    - Multi-layered data including Network traffic, IoT telemetry, and OS logs.
    - Realistic Industrial IoT (IIoT) environment simulation.
    - High-dimensional and diverse feature sets.
- **Types of Attacks:** DoS, DDoS, Ransomware, Backdoor, Injection, XSS, Scanning, and MitM.
- **Why it's Modern:** Specifically designed for the IoT era, addressing vulnerabilities in smart devices that traditional datasets like UNSW-NB15 overlook.

### 3. BoT-IoT
A dataset created in a realistic network environment specifically to capture various botnet attack scenarios.
- **Key Features:**
    - High-density Botnet-specific traffic patterns.
    - Includes 5% sub-sampled versions for efficient research and training.
    - Detailed per-packet and per-flow statistical metrics.
- **Types of Attacks:** DDoS, DoS, OS Fingerprinting, Service Discovery, Keylogging, and Data Exfiltration.
- **Why it's Modern:** Provides a much more specialized and deep focus on botnet behaviors, which have evolved significantly since the release of earlier datasets.

---

## 📈 Model Performance

```
┌────────────────────────────────────────────────────┐
│              Model Evaluation Results              │
├────────────────────────────────────────────────────┤
│  Metric       │  Score                             │
├───────────────┼────────────────────────────────────┤
│  Accuracy     │  ~85-90%                           │
│  Precision    │  ~85%                              │
│  Recall       │  ~85%                              │
│  F1-Score     │  ~85%                              │
└────────────────────────────────────────────────────┘

*Results may vary based on training data and network conditions
```

---

## 📂 Project Structure

```
IDS-With-AI/
│
├── 📄 train_model.py          # AI model training script
├── 📄 sniffer.py              # Network packet sniffer
├── 📄 app.py                  # Flask web server
├── 📄 requirements.txt        # Python dependencies
├── 📄 README.md               # Project documentation
│
├── 📁 templates/
│   └── 📄 index.html          # Dashboard UI
│
├── 🔧 .gitignore              # Git ignore rules
│
└── 📦 Generated Files (not in repo)
    ├── ids_rf_model.pkl       # Trained model
    ├── ids_scaler.pkl         # Feature scaler
    └── ids_logs.db            # Detection logs
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. 🍴 **Fork** the repository
2. 🌿 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. 🚀 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🔄 Open a **Pull Request**

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

| | |
|---|---|
| **GitHub** | [@shamanthwick](https://github.com/shamanthwick) |
| **Email** | shamantharsingh@gmail.com |

---

## 🙏 Acknowledgments

- 🎓 **UNSW-NB15** Dataset creators
- 🔧 **Scapy** developers
- 🤖 **Scikit-learn** team
- 🌐 **Flask** community

---

<div align="center">

### 🛡️ Made with ❤️ for Network Security

**If you find this project useful, please ⭐ star this repository!**

[⬆ Back to Top](#-ids-with-ai)

</div>
