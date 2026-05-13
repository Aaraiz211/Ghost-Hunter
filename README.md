# 👻 Ghost-Hunter v3.0 — Autonomous SOC Engine

<div align="center">

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-3.0-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=for-the-badge&logo=windows)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

**An autonomous Python-based Security Operations Centre (SOC) engine that independently discovers, triages, maps, and blocks cyber threats — with zero command-line interaction.**

*Developed by **Aaraiz Tahir** | BS Cybersecurity | Air University, Islamabad*
*Dual-Course Project: Cyber Threat Intelligence & Network Security*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [What's New in v3.0](#-whats-new-in-v30)
- [How It Works](#-how-it-works)
- [IoC Discovery Modules](#-ioc-discovery-modules)
- [CTI Triage Pipeline](#-cti-triage-pipeline)
- [Risk Scoring Algorithm](#-risk-scoring-algorithm)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Shodan Integration](#-shodan-integration)
- [Auto Network Range Detection](#-auto-network-range-detection)
- [Network Security Features](#-network-security-features)
- [GUI Interface](#-gui-interface)
- [Languages & Technologies](#-languages--technologies)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Test Results](#-test-results)
- [Limitations](#-limitations)
- [License](#-license)

---

## 🔍 Overview

Ghost-Hunter v3.0 is a Python-based **Autonomous SOC Engine** that automates the initial triage phase of incident response. In modern SOC environments, analysts are overwhelmed by alert fatigue from manually cross-referencing Indicators of Compromise (IoCs) across multiple threat intelligence platforms. Ghost-Hunter eliminates this by:

1. **Autonomously discovering** its own IoCs from four independent attack surfaces
2. **Triaging** every discovered IoC through three threat intelligence platforms simultaneously
3. **Scoring** each IoC using a composite weighted algorithm (0–100)
4. **Mapping** confirmed threats to MITRE ATT&CK techniques automatically
5. **Enriching** malicious IPs with Shodan infrastructure intelligence and CVE data
6. **Blocking** all confirmed malicious IPs via Windows Firewall automatically
7. **Reporting** every finding in a professional timestamped HTML report

All of this runs through a professional dark-themed GUI. No terminal, no manual commands, no analyst fatigue.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🤖 **Autonomous IoC Discovery** | Finds threats from 4 sources without any manual input |
| ⚡ **Async Concurrent APIs** | AbuseIPDB + VirusTotal fire simultaneously — 33% faster per IoC |
| 🔍 **Shodan Integration** | Deep infrastructure intel + CVE data for malicious IPs |
| 🎯 **MITRE ATT&CK Mapping** | Auto-maps findings to 21 technique IDs across 5 tactics |
| 🌐 **Auto Network Detection** | Calculates subnet range automatically from your NIC |
| 🛡️ **Auto Firewall Blocking** | Applies Windows Firewall rules for confirmed threats |
| 📊 **Nmap Port Scanning** | Service-version scan on all malicious IPs |
| 📦 **SHA-256 Hash Scanning** | Checks Downloads folder files against 70+ AV engines |
| 📋 **Event Log Monitoring** | Detects brute-force attacker IPs from Windows Security logs |
| 🎨 **Professional Dark GUI** | CustomTkinter interface with real-time stats and live console |
| 📄 **Timestamped Reports** | Unique HTML report per scan — never overwrites previous ones |
| 🔁 **Autonomous Scheduling** | Repeats full scan cycle every N minutes automatically |

---

## 🆕 What's New in v3.0

### Upgrade 1 — Shodan Integration
Queries Shodan's internet-wide scanner database for every confirmed MALICIOUS IP. Returns organization, ISP, country, open ports, running services, and known CVEs — giving analysts immediate patch-level context.

```
[SHODAN] Querying 193.163.125.138...
   Shodan: 3 ports | Russia | Evil Corp ISP | 2 CVE(s)
      CVE: CVE-2019-0708
      CVE: CVE-2021-34527
```

### Upgrade 2 — MITRE ATT&CK Mapping
Automatically maps detected ports, risk scores, and OTX pulse counts to MITRE ATT&CK technique IDs. Results appear in the GUI table's MITRE column and a full summary table in the HTML report.

```
[MITRE] 3 technique(s) mapped:
   T1021.001 | Remote Desktop Protocol (RDP) | Lateral Movement
   T1583     | Acquire Infrastructure        | Resource Development
   T1203     | Exploitation for Client Exec  | Execution
```

### Upgrade 3 — Async Concurrent API Calls
Replaces the old sequential `requests` library with `asyncio` + `aiohttp`. AbuseIPDB and VirusTotal now fire simultaneously instead of one after the other.

```
Before v3.0:  AbuseIPDB (10s) → VirusTotal (10s) → OTX (10s) = 30s per IoC
After  v3.0:  AbuseIPDB ──┐
                           ├── resolve together (~10s) → OTX (10s) = 20s per IoC
              VirusTotal ──┘
```

### Upgrade 4 — Auto Network Range Detection
The Network Range field is now auto-filled on startup. Ghost-Hunter reads your active NIC's IP and subnet mask, performs a bitwise AND, and calculates the CIDR notation automatically.

```
IPv4: 10.135.139.108  +  Mask: 255.255.248.0
         ↓ bitwise AND
Network: 10.135.136.0/21  ← auto-filled in the GUI field
```

---

## ⚙️ How It Works

```
┌──────────────────────────────────────────────────────────┐
│               AUTONOMOUS SCAN CYCLE                       │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  Module 1       Module 2       Module 3      Module 4    │
│  Network Host   Endpoint       File Hash     Event Log   │
│  Discovery      Connections    Scanner       Monitor     │
│  (Nmap -sn)     (psutil)       (SHA-256)     (Win32)     │
│       └──────────────┴──────────────┴────────────┘       │
│                         ↓ deduplicate                     │
│                    [ IoC List ]                           │
│                         ↓                                 │
│         ┌───────────────────────────┐                    │
│         │      TRIAGE PIPELINE      │                    │
│         │  [ASYNC] AbuseIPDB ──┐    │                    │
│         │  [ASYNC] VirusTotal ─┘─→ Score                 │
│         │  [SYNC]  OTX              │                    │
│         └───────────────────────────┘                    │
│                    ↓ score > 30                           │
│         Nmap Scan + Shodan + MITRE Mapping               │
│                         ↓                                 │
│         Windows Firewall Block Rule Applied              │
│                         ↓                                 │
│         HTML Report Saved (timestamped)                  │
│                         ↓                                 │
│         Wait N minutes → Repeat                          │
└──────────────────────────────────────────────────────────┘
```

---

## 🔎 IoC Discovery Modules

### Module 1 — Network Host Discovery
Uses Nmap's ping scan (`-sn`) to send ICMP echo requests to every IP in the configured subnet. Any device that responds is added as an IoC. Scans the **entire network** — all devices on the same Wi-Fi or LAN.

```python
nm.scan(hosts='10.135.136.0/21', arguments='-sn')
# Pings all 2046 IPs — discovers routers, laptops, servers, unknown devices
```

### Module 2 — Endpoint Connection Scanner
Reads the OS active connection table (same as `netstat -n`) and extracts all established connections to external IPs, identifying the process name for each connection.

```python
for c in psutil.net_connections(kind='inet'):
    if c.status == 'ESTABLISHED' and not c.raddr.ip.startswith(private):
        suspicious_ips.add(c.raddr.ip)
# Example: unknown.exe → 185.220.101.5:4444 → MALICIOUS (Metasploit C2)
```

### Module 3 — File System Hash Scanner
Walks the Downloads folder, computes SHA-256 fingerprints of every file, and checks them against VirusTotal's 70+ engine database. Immune to filename manipulation — a renamed malware file still produces the same hash.

```python
sha256 = hashlib.sha256()
for chunk in iter(lambda: f.read(8192), b''):
    sha256.update(chunk)
file_hash = sha256.hexdigest()  # submitted to VirusTotal
```

### Module 4 — Windows Event Log Monitor
Reads Windows Security Event Log for **Event ID 4625** (Failed Logon). Extracts source IPs of brute-force attackers automatically without needing to open Event Viewer.

```python
if event.EventID == 4625:  # Failed logon
    ips = re.findall(IP_REGEX, str(event.StringInserts))
# Example: 185.156.73.1 → 4,847 failed RDP logins → MALICIOUS → AUTO-BLOCKED
```

---

## 🧠 CTI Triage Pipeline

Every discovered IoC passes through three threat intelligence platforms:

| Platform | API Endpoint | What It Returns |
|---|---|---|
| **AbuseIPDB** | `GET /api/v2/check` | Community abuse confidence score (0–100%) |
| **VirusTotal** | `GET /api/v3/ip_addresses/{ip}` or `/files/{hash}` | Results from 70+ AV engines |
| **AlienVault OTX** | `get_indicator_details_full()` | Community threat intelligence pulse count |

AbuseIPDB and VirusTotal are queried **concurrently** via `asyncio.gather()`. OTX runs after both resolve with 3-retry logic and 10-second backoff for rate limiting.

---

## 📐 Risk Scoring Algorithm

```
Risk Score = (AbuseIPDB × 0.333) + ((VT_Malicious / VT_Total) × 100 × 0.333) + (33.3 if OTX_Pulses > 0 else 0)
```

| Source | Weight | Max Points | Scoring Logic |
|---|---|---|---|
| AbuseIPDB | 33.3% | 33.3 pts | `abuseConfidenceScore × 0.333` |
| VirusTotal | 33.3% | 33.3 pts | `(malicious / total_engines) × 100 × 0.333` |
| AlienVault OTX | 33.3% | 33.3 pts | `33.3 if pulse_count > 0 else 0` |
| **Total** | **100%** | **~99.9 pts** | Sum of all three |

**Score > 30** triggers MALICIOUS verdict → Nmap scan + Shodan query + MITRE mapping + Firewall block

---

## 🎯 MITRE ATT&CK Mapping

Ghost-Hunter maps findings to ATT&CK techniques from three evidence sources:

**Port-based mapping (21 ports):**

| Port | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| 22 | T1021.004 | Remote Services: SSH | Lateral Movement |
| 3389 | T1021.001 | Remote Desktop Protocol | Lateral Movement |
| 4444 | T1571 | Non-Standard Port (Metasploit C2) | Command & Control |
| 445 | T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| 9050 | T1090.003 | Tor SOCKS Proxy | Command & Control |
| 53 | T1071.004 | DNS Application Layer Protocol | Command & Control |
| 80/443 | T1071.001 | Web Protocols HTTP/HTTPS | Command & Control |

**Score-based:** Score > 70 → T1583 | Score > 30 → T1071

**OTX-based:** Pulses > 10 → T1588 | Pulses > 0 → T1203

---

## 🌍 Shodan Integration

Called automatically for every MALICIOUS IP (score > 30). Returns:

- **Organization** — who owns the IP range
- **ISP** — hosting provider
- **Country & City** — geographic location
- **Open Ports** — historically observed open ports from internet-wide scans
- **CVEs** — known vulnerabilities from NVD database cross-referenced with service versions
- **Service Banners** — product names and version strings per port

Requires `SHODAN_KEY` in `.env` file. Free key available at [account.shodan.io](https://account.shodan.io).

---

## 🌐 Auto Network Range Detection

Ghost-Hunter automatically detects your active network interface and calculates the correct subnet using Python's `ipaddress` module:

```python
net = ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
# 10.135.139.108 AND 255.255.248.0 = 10.135.136.0/21
```

Smart filtering skips VMware, VirtualBox, Bluetooth, loopback, and disconnected interfaces. A green **Auto** button in the GUI lets you re-detect at any time.

---

## 🛡️ Network Security Features

### Automatic Firewall Blocking
```bash
netsh advfirewall firewall add rule name="GhostHunter_BLOCK_193.163.125.138" dir=in action=block remoteip=193.163.125.138
```
Rules are applied immediately, cleaned up between cycles, and saved to timestamped `.txt` files for audit trail. Requires Administrator mode.

### Port Scanning
Runs on confirmed MALICIOUS IPs only using `nmap -sV --open -p 1-1024`. Detects service names and version strings which feed into MITRE ATT&CK mapping.

### Live Traffic Capture (Mode 3)
Scapy captures 100 live packets from the NIC and extracts all unique external IPs from packet headers for triage. Requires Npcap on Windows.

---

## 🖥️ GUI Interface

The GUI is built with CustomTkinter and includes:

- **Title bar** — tool name, v3.0 badge, live IDLE/RUNNING status
- **5 stat cards** — Total IoCs, Malicious, Clean, MITRE Hits, Status (all real-time)
- **Triage results table** — 6 columns: Artifact, Score, OTX, Ports, MITRE, Status
- **Configuration panel** — Scan Mode, Network Range + Auto button, IoC File, Interval, Shodan status, Async APIs status
- **START/STOP buttons** — background thread execution
- **Open Report button** — 3-step fallback to always open most recent report
- **Live console** — color-coded logs (green=success, yellow=warning, red=danger)

---

## 🧰 Languages & Technologies

| Component | Technology | Purpose |
|---|---|---|
| Core Engine | Python 3.x | All backend logic |
| GUI Framework | CustomTkinter | Dark-theme desktop interface |
| Async HTTP | asyncio + aiohttp | Concurrent API calls |
| Network Scanning | python-nmap + Nmap | Host discovery & port scanning |
| Packet Capture | Scapy + Npcap | Live traffic analysis |
| Process Monitor | psutil | Endpoint connection inspection |
| File Hashing | hashlib (stdlib) | SHA-256 fingerprinting |
| Subnet Detection | ipaddress (stdlib) | CIDR calculation |
| Event Logs | pywin32 | Windows Security log parsing |
| Threat Intel | requests + aiohttp | AbuseIPDB, VT, OTX API calls |
| Shodan | shodan SDK | Infrastructure intelligence |
| OTX | OTXv2 SDK | AlienVault threat intel |
| Scheduling | schedule | Autonomous repeat cycles |
| Config | python-dotenv | Secure API key management |
| Reports | HTML + CSS (generated) | Triage report output |

> GitHub shows 100% Python because the HTML/CSS in reports is generated as Python string output, not a separate file.

---

## 📦 Installation

See **[USAGE.md](USAGE.md)** for complete step-by-step setup instructions.

**Quick start:**
```bash
git clone https://github.com/Aaraiz211/Ghost-Hunter.git
cd Ghost-Hunter
pip install -r requirements.txt
# Add your API keys to a .env file
python Ghost-Hunter-v3.py
```

**Requirements:**
- Python 3.8+
- [Nmap](https://nmap.org/download) installed on system PATH
- [Npcap](https://npcap.com) — for Live Traffic Capture mode only
- Windows OS — for Event Log and Firewall features
- Administrator mode — for Nmap scanning, Firewall rules, and Event Log reading

---

## ⚙️ Configuration

Create a `.env` file in the project root:

```env
ABUSEIPDB_KEY=your_abuseipdb_api_key
VT_KEY=your_virustotal_api_key
OTX_KEY=your_alienvault_otx_api_key
SHODAN_KEY=your_shodan_api_key
```

| API | Sign Up Link | Free Tier Limit |
|---|---|---|
| AbuseIPDB | [abuseipdb.com/register](https://www.abuseipdb.com/register) | 1,000 checks/day |
| VirusTotal | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | 500 requests/day |
| AlienVault OTX | [otx.alienvault.com/api](https://otx.alienvault.com/api) | Unlimited |
| Shodan | [account.shodan.io/register](https://account.shodan.io/register) | 1 query/second |

---

## 🚀 Usage

Run as Administrator in PowerShell:
```powershell
cd "D:\Path\To\Ghost-Hunter"
python Ghost-Hunter-v3.py
```

Three operating modes are available via the dropdown in the GUI:

| Mode | How IoCs are collected |
|---|---|
| 🤖 Autonomous SOC | All 4 discovery modules run automatically |
| 📄 Manual IoC File | Reads your `iocs.txt` (one IP or SHA-256 hash per line) |
| 📡 Live Traffic Capture | Captures 100 live packets from NIC via Scapy |

---

## 📁 Project Structure

```
Ghost-Hunter/
├── Ghost-Hunter-v3.py          ← Main application (v3.0)
├── Ghost-Hunter.py             ← Legacy v2.0
├── requirements.txt            ← Python dependencies
├── iocs.txt                    ← Manual IoC input file
├── .env                        ← API keys (NOT in GitHub)
├── .gitignore                  ← Excludes .env and reports
├── README.md                   ← This file
├── USAGE.md                    ← Setup and usage guide
├── triage_report_latest.html   ← Most recent scan report
└── triage_report_YYYYMMDD_HHMMSS.html  ← Timestamped reports
```

---

## 🧪 Test Results

### Manual Mode — 6 Known IoCs

| Artifact | Risk Score | OTX Pulses | Verdict |
|---|---|---|---|
| 8.8.8.8 | 0.0/100 | 0 | ✅ CLEAN |
| 27.79.45.17 | 68.05/100 | 2 | 🚨 MALICIOUS |
| 24d004a104da...f07 | 0/100 | 0 | ✅ CLEAN |
| 1.1.1.1 | 0.0/100 | 0 | ✅ CLEAN |
| 193.163.125.138 | 69.5/100 | 50 | 🚨 MALICIOUS |
| 45.130.147.168 | 0.0/100 | 0 | ✅ CLEAN |

**Detection accuracy: 100%** — Both malicious IPs correctly identified. Firewall rules applied automatically for both.

### Autonomous Mode — Air University Wi-Fi (10.135.136.0/21)

- 12 live devices discovered via ping scan
- 3 external IPs from active endpoint connections
- 17 file hashes from Downloads folder
- 0 brute-force IPs from event logs
- **Total: 17 unique IoCs — all CLEAN** (correct for internal university infrastructure)

---

## ⚠️ Limitations

- OTX scoring is binary — 1 pulse and 50 pulses both contribute the same 33.3 points
- Private/internal IPs (10.x, 192.168.x) return no data from public threat intel APIs
- Free API tier rate limits restrict throughput for very large IoC volumes
- Only local Windows Firewall is controlled — not router or network-level firewall
- Domain names and URLs not yet supported as IoC types
- Live Traffic Capture requires Npcap installed on Windows

---

## 🔮 Planned Future Enhancements

- [ ] Graduated OTX scoring weighted by pulse count magnitude
- [ ] Domain, URL, and email IoC type support
- [ ] CVE severity scoring from NVD for detected open ports
- [ ] STIX 2.1 export for SIEM ingestion (Splunk, ELK, Sentinel)
- [ ] Known-device whitelist to filter trusted infrastructure
- [ ] MikroTik/pfSense REST API for network-level blocking
- [ ] GeoIP world map visualization in HTML report

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [AbuseIPDB](https://www.abuseipdb.com) — IP abuse intelligence database
- [VirusTotal](https://www.virustotal.com) — Multi-engine malware analysis
- [AlienVault OTX](https://otx.alienvault.com) — Open threat exchange community
- [Shodan](https://www.shodan.io) — Internet-wide infrastructure scanner
- [MITRE ATT&CK](https://attack.mitre.org) — Adversary tactic and technique framework
- [Nmap](https://nmap.org) — Network exploration and security scanner
- [Scapy](https://scapy.net) — Python packet manipulation library

---

<div align="center">
<b>Ghost-Hunter v3.0</b> — Autonomous SOC Engine<br>
Aaraiz Tahir | BS Cybersecurity | Air University, Islamabad<br>
<i>Cyber Threat Intelligence × Network Security</i>
</div>
