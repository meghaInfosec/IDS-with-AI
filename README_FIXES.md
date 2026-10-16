# IDS with AI — Fixed & Verified

This is the original "IDS with AI" project (Random Forest + UNSW-NB15 +
Scapy + Flask), with the core issues fixed and the full pipeline actually
run end-to-end to confirm it works, not just reviewed by reading the code.

## What was broken

1. **The trained ML model was never used for live detection.**
   `train_model.py` trained a Random Forest and saved it to `.pkl` files,
   but `sniffer.py` never loaded or called it. Every live "Normal/Malicious"
   decision came from hardcoded if/else rules (port scan thresholds, NULL/
   XMAS/FIN TCP flags), not from the AI model. The project's name promised
   AI; the live code didn't deliver it.

2. **Dataset column names didn't match what the training code expected.**
   `train_model.py` looked for columns named `proto`, `service`, `state`,
   `attack_cat`. This CSV uses `xProt`, `xServ`, `xState` and has no
   `attack_cat` column. It didn't crash (the code silently skipped the
   missing columns), but it was fragile — a different CSV with real text
   categories would have broken it.

3. **A deeper, more interesting problem: single packets don't carry
   "flow" information.** UNSW-NB15's features (`dur`, `sbytes`, `sload`,
   etc.) describe a whole connection, not one packet. A live sniffer only
   sees one packet at a time, so there was no way to hand the trained
   model what it actually expects, even if it had been loaded.

## What was fixed

- **`train_model.py`**: now auto-detects text columns instead of a fixed
  name list, so it works whether the CSV calls them `proto` or `xProt`.
- **`flow_tracker.py`** (new): groups live packets into
  `(src_ip, dst_ip, protocol)` flows and builds a feature row shaped like
  one line of the training CSV once a flow has enough packets (or has
  been idle for a bit).
- **`ml_detector.py`** (new): loads the trained model/scaler and scores a
  flow's feature row, returning `Normal`/`Malicious` + confidence.
- **`sniffer.py`**: now hybrid. The original fast per-packet rules still
  run (they catch obvious single-packet attacks like NULL/XMAS scans
  instantly). On top of that, every live flow is now also scored by the
  actual Random Forest model once it has enough packets, and that result
  is logged too.
- **`simulate_attack.py`** (new): lets you see alerts on the dashboard
  without needing a real attacker or tools like nmap — useful for demos.

## Honest limitation (worth knowing for an interview)

`flow_tracker.py` can only derive about half of the 42 training features
from raw packets alone (duration, packet/byte counts, TTL, window size).
Features that need deep packet inspection or longer history — which
*service* it is, HTTP-specific fields, counts of connections to the same
host in a recent time window — are filled with 0 rather than guessed.
This is a known, real tradeoff in applied network ML (tools like
CICFlowMeter/Zeek solve it with heavier flow-export pipelines). It means
live accuracy will be lower than the clean 90%+ seen on the held-out
UNSW-NB15 test CSV — a good, honest talking point if asked about it.

## Verified results (run in a Linux sandbox during development)

- `train_model.py` run successfully: **97.59%** accuracy on its own
  train/test split.
- Model re-validated against the full, separate `UNSW_NB15_testing-set.csv`
  (175,341 rows it never trained on): **90.25%** accuracy.
- `sniffer.py` run against **real live traffic** (HTTPS requests): packets
  captured, flows built, and both the rule engine and the ML model scored
  them correctly as Normal.
- Rule engine re-tested with simulated port-scan and NULL-scan patterns:
  both correctly flagged as Malicious with high confidence.
- `app.py` dashboard confirmed serving HTTP 200 with alert data.

## How to run it yourself

### 1. Set up a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train the model

```bash
python train_model.py
```

This reads `UNSW_NB15_training-set.csv`, trains the Random Forest, and
saves `ids_rf_model.pkl`, `ids_scaler.pkl`, `ids_model_config.pkl`.
(These are already included in this package, pre-trained — you only need
to re-run this if you change the dataset.)

### 3. Start the sniffer (Terminal 1)

Live packet capture needs admin/root privileges:

```bash
# Linux/Mac
sudo python3 sniffer.py

# Windows (run terminal as Administrator)
python sniffer.py
```

You should see:
```
[*] Initializing IDS (Hybrid: Rule-Based + ML)...
[*] ML model loaded (42 features expected)
...
[*] Starting Packet Sniffer... (Press Ctrl+C to stop)
```

If `ML model loaded` doesn't appear, it means the `.pkl` files weren't
found — re-run step 2.

### 4. Start the dashboard (Terminal 2, while sniffer.py is still running)

```bash
python3 app.py
```

Open **http://127.0.0.1:5000** in your browser. Leave both terminals
running — browse the internet normally for a bit and you'll see rows
appear as "Normal" traffic gets logged.

### 5. (Optional) See a Malicious alert without a real attacker

In a third terminal, while sniffer.py has already created the database:

```bash
python3 simulate_attack.py
```

Refresh the dashboard — you'll see simulated Malicious rows (clearly
labeled SIMULATED in the reason text).

To see a *real* detection instead of a simulated one, you can scan your
own machine from another terminal (only ever scan systems you own):
```bash
nmap -sN -p 1-100 127.0.0.1      # NULL scan - rule engine should catch this
nmap -sX -p 1-100 127.0.0.1      # XMAS scan
```

### Troubleshooting

- **"No packets captured"**: run `python3 test_capture.py` first to check
  Scapy can see your network interface. On Windows you may need
  [Npcap](https://nmap.org/npcap/) installed.
- **Permission denied on sniff**: packet capture needs root/admin, see
  step 3.
- **`ids_rf_model.pkl` not found**: run `train_model.py` first.
