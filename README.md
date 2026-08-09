# RANZER - Ransomware Analyzer & Endpoint Protection System

> Capstone Project | Group C | Victoria University

RANZER is a lightweight, real-time, signature-free **Endpoint Protection System (EPS)** that detects ransomware by monitoring the **act of encryption** - not known malware signatures. It combines Shannon entropy analysis, honey file deception, and process behaviour tracking into a unified hybrid detection engine.

---

## How It Works

```
File Modified / Created
        │
        ▼
  File Watcher (watchdog)
        │
    ┌───┴─────────────────────┐
    ▼                         ▼
Entropy Monitor         Honey File Engine
(Shannon entropy)       (decoy file traps)
    │                         │
    └──────────┬──────────────┘
               ▼
      Process Behaviour Tracker
      (/proc/pid/io - who did this?)
               ▼
      Threat Correlator
      (decay-weighted multi-signal scoring)
               ▼
      Alert Handler
      (log + notify + GUI + export)
```

Instead of relying on known malware signatures, RANZER watches **what files are doing**:

- **Entropy spike** on a modified file → file may be getting encrypted
- **Honey file touched** → ransomware walked into a decoy trap
- **Process writing 100 KB/s+ to monitored directories** → mass encryption behaviour
- **Same PID triggers multiple engines** → cross-signal score bonus, action recommended

---

## Project Structure

```
Ranzer/
├── ranzer/
│   ├── __init__.py
│   ├── __main__.py               ← python3 -m ranzer entry point
│   ├── cli.py                    ← Command line interface
│   ├── core/
│   │   ├── engine.py             ← Main orchestrator (RanzerEngine + RanzerConfig)
│   │   ├── entropy_monitor.py    ← Shannon entropy analysis
│   │   ├── honey_file_engine.py  ← Decoy file deployment & detection
│   │   ├── process_tracker.py    ← Process I/O monitoring via /proc
│   │   ├── threat_correlator.py  ← Multi-signal threat scoring
│   │   ├── alert_handler.py      ← Logging, notifications, export
│   │   └── file_watcher.py       ← Real-time filesystem listener (watchdog)
│   └── gui/
│       ├── __init__.py           ← Asset path resolver (_gui_resource)
│       ├── app.py                ← GUI entry point
│       ├── landing.py            ← Welcome / mode selection screen
│       ├── main_window.py        ← Main application window
│       ├── setup_window.py       ← Directory & config setup
│       ├── theme.py              ← Colours, fonts, logo loader
│       ├── logo.png
│       ├── image.png
│       └── views/
│           ├── dashboard.py      ← Live stats & alert preview
│           ├── alerts.py         ← Full alert table + search + export
│           ├── actions.py        ← Detected processes & manual termination
│           └── home.py
├── packaging/
│   ├── ranzer.desktop            ← Linux desktop entry (app menu icon)
│   └── debian/
│       ├── control               ← .deb package metadata
│       ├── postinst              ← Post-install: permissions + chattr +i protection
│       └── prerm                 ← Pre-remove: strips immutable flag for clean uninstall
├── ranzer.spec                   ← PyInstaller bundle spec
├── build_deb.sh                  ← One-command .deb builder
├── simulate_ransomware.py        ← High-entropy file simulation (safe testing)
├── simulate_risk_low.py          ← High write-rate, low entropy simulation
└── requirements.txt
```

---

## Requirements

- **OS:** Linux (Ubuntu / Debian / Kali recommended)
- **Python:** 3.10+
- **Dependencies:** `watchdog`, `psutil`, `Pillow`

---

## Installation

### Option A - Install the .deb package (recommended)

```bash
git clone https://github.com/RIVIRU05/Ranzer.git
cd Ranzer
bash install.sh
```

That's it. The script builds and installs everything automatically.

Launch from your **application menu** (search "RANZER"), or from the terminal:

```bash
ranzer gui
```

Uninstall:

```bash
sudo dpkg -r ranzer
```

---

### Option B - Run from source (development)

```bash
git clone https://github.com/RIVIRU05/Ranzer.git
cd Ranzer

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# GUI
python3 -m ranzer gui

# CLI
python3 -m ranzer start --dirs ~/Documents
```

---

## CLI Reference

```bash
# Launch GUI
ranzer gui

# Start monitoring (comma-separated directories)
ranzer start --dirs /home/user/Documents,/home/user/Desktop

# Start with custom entropy threshold (default 7.5, range 6.0–8.0)
ranzer start --dirs ~/Documents --threshold 7.2

# Start with auto-terminate enabled
ranzer start --dirs ~/Documents --auto-terminate

# Start without honey files
ranzer start --dirs ~/Documents --no-honeyfiles

# Check if RANZER is running
ranzer status

# View last 20 alerts
ranzer log

# View only HIGH and CRITICAL alerts
ranzer log --severity HIGH

# Scan a single file for entropy
ranzer scan --file /path/to/suspicious.bin

# Export alerts
ranzer export --format json --output alerts.json
ranzer export --format csv  --output alerts.csv
ranzer export --format txt  --output alerts.txt
```

---

## Self-Protection

When installed via `.deb`, RANZER applies `chattr +i` (immutable flag) to every file in `/opt/ranzer/` during installation. This means:

- **User-space ransomware** (running as the logged-in user) cannot modify, rename, or delete any RANZER file.
- Even root-owned processes cannot touch the files without first explicitly running `chattr -i` - which real ransomware does not do.
- The `prerm` script automatically removes the flag when you uninstall cleanly via `dpkg -r ranzer`.

---

## GUI Overview

| View | What it shows |
|---|---|
| **Dashboard** | Live threat score, alert counts, last 5 events |
| **Alerts** | Full alert log with search, severity filter, and export |
| **System Actions** | Detected malicious processes with live CPU/status and manual terminate |

Threat popups appear automatically:
- **HIGH** - bottom-right corner notification, auto-dismisses after 12 s
- **CRITICAL** - centred modal, requires manual dismissal

---

## Detection Engines

### 1. Entropy Monitor
Calculates Shannon entropy (0–8 bits/byte) on every file write. Encrypted or compressed data scores near 8.0. Skips known high-entropy formats (`.zip`, `.jpg`, `.mp4`, etc.) to avoid false positives. Threshold default: **7.5**.

### 2. Honey File Engine
Deploys realistic decoy files (`credentials.txt`, `financial_report_2024.docx`, `passwords_backup.txt`, etc.) into monitored directories. Any modification, deletion, or rename fires an immediate HIGH/CRITICAL alert. Decoys are invisible to regular users and blend in with real documents.

### 3. Process Behaviour Tracker
Reads `/proc/[pid]/io` every 0.5 s to measure the kernel-level `wchar` (write syscall bytes) for every running process. Flags processes sustaining **100 KB/s+** write rates to monitored directories. Maintains a large whitelist of interactive apps (file managers, editors, browsers, system daemons) to prevent false positives.

### 4. File Watcher
Watchdog-based real-time event listener. Counts **new file creations** per directory per 5-second window. Ten or more new files in 5 s triggers a rapid-write PID scan. Entropy checks run on every file modification.

### 5. Threat Correlator
Combines signals from all engines into a decay-weighted score. Signals lose weight over a 30 s window. A PID appearing in multiple engine types gets a cross-signal bonus. Thresholds:

| Level | Score | Action |
|---|---|---|
| LOW | 20–39 | MONITOR |
| MEDIUM | 40–64 | ALERT |
| HIGH | 65–89 | ALERT + popup |
| CRITICAL | 90+ | TERMINATE (if auto-terminate enabled) |

### 6. Alert Handler
Routes all events to:
- Dated log file: `logs/ranzer_events_YYYY-MM-DD.log`
- Desktop notifications via `notify-send` (CLI mode)
- GUI event queue (GUI mode)
- In-memory ring buffer (last 500 events, exportable)

Escalation is gated - each severity level fires at most once per session (MEDIUM → HIGH → CRITICAL), preventing notification spam.

---

## Log Files

| File | Contents |
|---|---|
| `logs/ranzer_YYYY-MM-DD.log` | Full engine log - startup, scans, debug |
| `logs/ranzer_events_YYYY-MM-DD.log` | Detection events - one JSON object per line |
| `logs/ranzer_latest.log` | Symlink → today's log for easy tailing |
| `.ranzer_honey_state.json` | Honey file registry (auto-created on start) |

```bash
# Watch alerts appear live
tail -f logs/ranzer_events_latest.log

# Pretty-print the last alert
tail -1 logs/ranzer_events_latest.log | python3 -m json.tool
```

---

## Testing (Safe Simulation)

> Never test with real ransomware outside an isolated VM.

```bash
# Trigger entropy detection - writes a random (high-entropy) file
python3 simulate_ransomware.py

# Trigger low-risk / write-rate detection only
python3 simulate_risk_low.py

# Manually trigger a honey file alert
echo "TAMPERED" >> ~/Desktop/ranzer_test/credentials.txt

# One-shot entropy scan of any file
ranzer scan --file /path/to/file.bin
```

---

## Roadmap

- [x] Core detection engines (entropy, honey files, process I/O, threat correlator)
- [x] CLI interface (`start`, `status`, `log`, `scan`, `export`, `gui`)
- [x] Tkinter GUI (Dashboard, Alerts, System Actions, threat popups)
- [x] Dated log files with daily rotation
- [x] Auto-terminate on CRITICAL with process whitelist
- [x] .deb package + desktop app (installable via `dpkg -i`)
- [x] Self-protection via `chattr +i` immutable flag
- [ ] Windows port (separate module - in progress)
- [ ] Remote admin mode (monitor machines over network)
- [ ] Email / SMS alert integration
- [ ] Scheduled scan reports

---

## Team

| Name | Student ID |
|---|---|
| V.A. Riviru Eren - Project Lead | s8170544 |
| P.H. Movindi Amasha | s8170573 |
| M.N.R. Marasingha | s8170623 |
| R.M.T.D. Moragolla | s8170624 |

**Victoria University**
<img width="120" height="62" alt="Victoria University" src="https://github.com/user-attachments/assets/b9c555f6-ea69-4655-ba9e-118d6e05ebc4" />
