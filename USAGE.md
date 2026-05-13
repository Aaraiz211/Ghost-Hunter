# 📖 Ghost-Hunter v3.0 — User Manual & Setup Guide

> Complete step-by-step guide to install, configure, and operate Ghost-Hunter v3.0

---

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Step 1 — Clone the Repository](#-step-1--clone-the-repository)
- [Step 2 — Install Python Dependencies](#-step-2--install-python-dependencies)
- [Step 3 — Install Nmap](#-step-3--install-nmap)
- [Step 4 — Install Npcap (Optional)](#-step-4--install-npcap-optional)
- [Step 5 — Get Your API Keys](#-step-5--get-your-api-keys)
- [Step 6 — Create the .env File](#-step-6--create-the-env-file)
- [Step 7 — Find Your Network Range](#-step-7--find-your-network-range)
- [Step 8 — Run as Administrator](#-step-8--run-as-administrator)
- [Using the GUI](#-using-the-gui)
- [Operating Modes](#-operating-modes)
- [Mode 1 — Autonomous SOC](#-mode-1--autonomous-soc)
- [Mode 2 — Manual IoC File](#-mode-2--manual-ioc-file)
- [Mode 3 — Live Traffic Capture](#-mode-3--live-traffic-capture)
- [Reading the Triage Results](#-reading-the-triage-results)
- [Understanding the HTML Report](#-understanding-the-html-report)
- [Understanding Firewall Rules](#-understanding-firewall-rules)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)

---

## Prerequisites

Before installing Ghost-Hunter, make sure you have the following:

| Requirement | Version | Check Command |
|---|---|---|
| Python | 3.8 or higher | `python --version` |
| pip | Latest | `pip --version` |
| Nmap | Any recent version | `nmap --version` |
| Windows OS | 10 or 11 | — |
| Administrator access | Required | Right-click PowerShell |
| Npcap | Latest (optional) | Only needed for Mode 3 |

---

## Step 1 — Clone the Repository

Open PowerShell and run:

```powershell
git clone https://github.com/Aaraiz211/Ghost-Hunter.git
cd Ghost-Hunter
```

Or download the ZIP from GitHub and extract it to a folder of your choice such as:
```
D:\Certifications, Licencing and Projects\Ghost-Hunter\
```

---

## Step 2 — Install Python Dependencies

Run this command in the same folder as `requirements.txt`:

```powershell
pip install -r requirements.txt
```

This installs all required libraries:

```
requests          # HTTP client for API calls
OTXv2             # AlienVault OTX threat intel SDK
python-dotenv     # Load API keys securely from .env
aiohttp           # Async concurrent HTTP (Upgrade 3)
shodan            # Shodan infrastructure intelligence (Upgrade 1)
python-nmap       # Python wrapper around Nmap binary
scapy             # Live packet capture and analysis
psutil            # Process and network connection monitoring
schedule          # In-process autonomous scheduling
pywin32           # Windows Security Event Log access
customtkinter     # Modern dark-theme GUI framework
```

> **Note:** You may see yellow `WARNING: Cache entry deserialization failed` messages during install. These are harmless pip cache warnings and are not errors. Installation continues normally and completes successfully.

---

## Step 3 — Install Nmap

Ghost-Hunter requires Nmap to be installed on your system for network host discovery and port scanning. Python-nmap is just a wrapper — the actual Nmap binary must be present.

1. Go to **[nmap.org/download](https://nmap.org/download)**
2. Download the **Windows installer** (`.exe` file)
3. Run the installer — on the options page, ensure **"Add Nmap to PATH"** is checked
4. Complete the installation
5. Verify by opening a new PowerShell window and running:

```powershell
nmap --version
```

Expected output:
```
Nmap version 7.94 ( https://nmap.org )
```

If `nmap --version` gives an error, reinstall Nmap and make sure the PATH option is checked.

---

## Step 4 — Install Npcap (Optional)

Npcap is only required if you plan to use **Mode 3 (Live Traffic Capture)**. If you only use Autonomous SOC or Manual IoC File modes, skip this step.

1. Go to **[npcap.com](https://npcap.com/#download)**
2. Download the latest Npcap installer
3. During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
4. Complete the installation
5. Restart your computer if prompted

---

## Step 5 — Get Your API Keys

Ghost-Hunter uses four threat intelligence APIs. All provide free tiers.

### AbuseIPDB
1. Go to **[abuseipdb.com/register](https://www.abuseipdb.com/register)**
2. Create a free account and verify your email
3. Navigate to **My Account → API**
4. Copy your API key

**Free tier:** 1,000 IP checks per day

---

### VirusTotal
1. Go to **[virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)**
2. Create a free account and verify your email
3. Click your profile picture → **API Key**
4. Copy the displayed API key

**Free tier:** 500 requests per day, 4 requests per minute

---

### AlienVault OTX
1. Go to **[otx.alienvault.com](https://otx.alienvault.com)**
2. Click **Sign Up** and create a free account
3. After login, click your username → **Settings**
4. Navigate to the **API Integration** section
5. Copy your OTX Key

**Free tier:** Unlimited requests (rate limiting applies under heavy use)

---

### Shodan
1. Go to **[account.shodan.io/register](https://account.shodan.io/register)**
2. Create a free account
3. Go to **[account.shodan.io](https://account.shodan.io)**
4. Your API Key is displayed on the dashboard — copy it

**Free tier:** 1 query per second, basic host lookup included

> **Shodan is optional.** If you skip it, the tool shows `✗ Add SHODAN_KEY to .env` in the GUI but all other features work normally. Shodan only activates for confirmed MALICIOUS IPs anyway.

---

## Step 6 — Create the .env File

In your Ghost-Hunter project folder, create a new text file named exactly `.env` with no other extension.

**In PowerShell:**
```powershell
New-Item .env -ItemType File
notepad .env
```

Paste the following and fill in your keys:

```env
ABUSEIPDB_KEY=your_abuseipdb_key_here
VT_KEY=your_virustotal_key_here
OTX_KEY=your_alienvault_otx_key_here
SHODAN_KEY=your_shodan_key_here
```

Save and close Notepad.

**Example with real key format:**
```env
ABUSEIPDB_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
VT_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
OTX_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
SHODAN_KEY=a1B2c3D4e5F6a1B2
```

> **Security warning:** Never commit the `.env` file to GitHub. It is already listed in `.gitignore` to prevent accidental exposure.

---

## Step 7 — Find Your Network Range

Ghost-Hunter v3.0 detects your network range **automatically** when it starts. The Network Range field will be pre-filled with your correct subnet. You can also click the green **Auto** button at any time.

To verify or find it manually, open PowerShell and run:

```powershell
ipconfig
```

Look for your active network adapter:
```
Wireless LAN adapter Wi-Fi:
   IPv4 Address  . . . : 10.135.139.108
   Subnet Mask . . . . : 255.255.248.0
   Default Gateway . . : 10.135.136.1
```

**How the subnet is calculated:**
```
IP Address:   10.135.139.108   =  00001010.10000111.10001011.01101100
Subnet Mask:  255.255.248.0    =  11111111.11111111.11111000.00000000
                                   AND operation (both bits must be 1)
Network:      10.135.136.0/21  =  00001010.10000111.10001000.00000000
```

The `/21` means 21 bits are the network portion (8+8+5+0 = 21 ones in the mask). This gives 2046 usable host addresses — all of which Ghost-Hunter will scan in Autonomous mode.

---

## Step 8 — Run as Administrator

Ghost-Hunter requires Administrator privileges for Nmap scanning, Windows Firewall rule creation, and Windows Security Event Log reading.

```powershell
# Right-click on PowerShell in the Start menu → Run as Administrator
cd "D:\Certifications, Licencing and Projects\Ghost-Hunter"
python Ghost-Hunter-v3.py
```

The Ghost-Hunter v3.0 dark GUI window will open with:
- The v3.0 blue badge in the title bar
- 5 stat cards showing zeros
- Network Range pre-filled automatically
- Shodan status showing green (Configured) if your key is set
- Async APIs showing green (Enabled concurrent)

---

## Using the GUI

The GUI has two main panels:

**Left panel — Triage Results Table**
Shows every analyzed IoC with 6 columns:
- Artifact, Score, OTX, Ports, MITRE, Status

**Right panel — Configuration and Console**
Contains all controls and a live log of everything the tool is doing.

**Top stat cards (real-time):**
- **TOTAL IOCs** — unique IoCs triaged this cycle
- **MALICIOUS** — confirmed threats found
- **CLEAN** — safe artifacts
- **MITRE HITS** — total ATT&CK technique IDs mapped
- **STATUS** — current operation phase

---

## Operating Modes

Select your mode from the **Scan Mode** dropdown:

| Mode | IoC Source | Best For |
|---|---|---|
| Autonomous SOC | 4 automatic modules | Regular continuous monitoring |
| Manual IoC File | Your `iocs.txt` file | Investigating specific suspected IoCs |
| Live Traffic Capture | Live packet sniffing | Real-time traffic analysis |

---

## Mode 1 — Autonomous SOC

The primary mode. Ghost-Hunter discovers its own IoCs, triages all of them, blocks threats, saves a report, and repeats automatically.

**Steps:**
1. Select **Autonomous SOC** in the dropdown (it is the default)
2. Check the Network Range field — click **Auto** if needed
3. Set **Interval (min)** to your preferred repeat frequency (default: 30)
4. Click **START SCAN**
5. Watch the Live Console for real-time progress
6. Click **STOP** when done or let it run continuously

**What Ghost-Hunter does automatically:**
- Pings every IP in your subnet to find live devices
- Checks all active outbound connections on your machine
- Hashes all files in your Downloads folder
- Reads Windows Security Event Log for failed logins
- Triages every discovered IoC through AbuseIPDB, VirusTotal, OTX simultaneously
- Queries Shodan for any MALICIOUS IP
- Maps findings to MITRE ATT&CK techniques
- Applies Windows Firewall block rules for MALICIOUS IPs
- Saves a timestamped HTML report
- Waits the configured interval then repeats

---

## Mode 2 — Manual IoC File

Use this mode when you have specific IPs or file hashes to investigate.

**Prepare your iocs.txt file:**

Open `iocs.txt` in the Ghost-Hunter folder and add one IoC per line:

```
# Example iocs.txt
8.8.8.8
193.163.125.138
27.79.45.17
1.1.1.1
45.130.147.168
24d004a104da70002166a6a23405786358c9710f220f862ca858034c44e99f07
```

Supported formats:
- IPv4 addresses (e.g. `193.163.125.138`)
- SHA-256 hashes (64 hexadecimal characters)
- Lines starting with `#` are treated as comments and ignored
- Blank lines are ignored

**Steps:**
1. Edit your `iocs.txt` file with the IoCs you want to investigate
2. Select **Manual IoC File** from the dropdown
3. The **IoC File** field becomes active — enter the full path:
   ```
   D:\Certifications, Licencing and Projects\Ghost-Hunter\iocs.txt
   ```
4. Click **START SCAN**

---

## Mode 3 — Live Traffic Capture

Captures live network packets and triages the external IPs your machine communicates with in real time.

**Requirements:**
- Npcap must be installed (see Step 4)
- Must run as Administrator
- Some active network traffic helps (open a browser, etc.)

**Steps:**
1. Select **Live Traffic Capture** from the dropdown
2. Click **START SCAN**
3. Ghost-Hunter captures 100 packets from your NIC
4. All unique external IPs are extracted and triaged

The capture takes about 30-60 seconds depending on your network activity.

---

## Reading the Triage Results

Each row in the results table represents one analyzed IoC:

| Column | Meaning |
|---|---|
| **Artifact** | The IP address or SHA-256 hash being analyzed |
| **Score** | Composite risk score out of 100 |
| **OTX** | Number of AlienVault OTX threat intelligence pulses |
| **Ports** | Open ports from Nmap scan (only for MALICIOUS IPs) |
| **MITRE** | MITRE ATT&CK technique IDs mapped from evidence |
| **Status** | CLEAN (green) or MALICIOUS (red) |

**Score interpretation:**
| Score Range | Meaning | Action Taken |
|---|---|---|
| 0 – 30 | CLEAN / No known threat | No action |
| 31 – 60 | MALICIOUS / Moderate threat | Blocked + reported |
| 61 – 99 | MALICIOUS / High confidence threat | Blocked + Shodan + MITRE |

---

## Understanding the HTML Report

After each scan, click **Open Report** to view the results in your browser.

The report includes:
- **Header** — developer info, timestamp, and v3.0 feature highlights
- **Summary cards** — Total IoCs, Malicious, Clean, MITRE hits (color coded)
- **Triage table** — every IoC with all scores, ports, MITRE techniques
- **Shodan boxes** — for MALICIOUS IPs: organization, country, CVEs, open ports
- **MITRE ATT&CK summary table** — all technique IDs detected in this scan

Reports are saved with unique timestamps — previous reports are never overwritten:
```
triage_report_20260510_172950.html   ← permanent timestamped copy
triage_report_latest.html            ← always the most recent scan
```

The **Open Report** button uses a three-step fallback:
1. Current session report (stored in memory)
2. `triage_report_latest.html` in the project folder
3. Most recently dated timestamped file in the folder

---

## Understanding Firewall Rules

Ghost-Hunter automatically creates Windows Firewall inbound block rules for every MALICIOUS IP:

```
GhostHunter_BLOCK_193.163.125.138
GhostHunter_BLOCK_27.79.45.17
```

Rules are saved to audit files:
```
firewall_rules_20260510_172950.txt   ← timestamped copy
firewall_rules_latest.txt            ← most recent
```

To view a specific rule:
```powershell
netsh advfirewall firewall show rule name="GhostHunter_BLOCK_193.163.125.138"
```

To manually remove a rule:
```powershell
netsh advfirewall firewall delete rule name="GhostHunter_BLOCK_193.163.125.138"
```

To see all Ghost-Hunter rules at once:
```powershell
netsh advfirewall firewall show rule name=all | findstr "GhostHunter"
```

> Ghost-Hunter automatically removes all previous `GhostHunter_BLOCK_*` rules at the start of each new scan cycle and re-applies only the current ones. This prevents stale rules from accumulating.

---

## Troubleshooting

### OTX keeps retrying
```
OTX busy, retrying (1/3)...
OTX busy, retrying (2/3)...
OTX failed after 3 attempts.
```
**This is normal** under heavy use. OTX rate limiting is temporary. The tool continues with a partial score for that IoC and resumes on the next one.

---

### Nmap not found
```
Network discovery error: [Errno 2] No such file or directory: 'nmap'
```
Install Nmap from [nmap.org/download](https://nmap.org/download) and ensure "Add to PATH" is checked during installation. Restart PowerShell after installing.

---

### Event logs skipped
```
Skipping event logs (pywin32 not available).
```
Run:
```powershell
pip install pywin32
python -m pywin32_postinstall -install
```

---

### Firewall access denied
```
Failed to block 193.163.125.138: Access is denied.
```
You are not running as Administrator. Right-click PowerShell → Run as Administrator.

---

### Live capture fails
```
Capture error: Sniffing on interface failed.
```
Install Npcap from [npcap.com](https://npcap.com/#download) with WinPcap-compatible mode enabled.

---

### Shodan shows not configured
```
Shodan: ✗ Add SHODAN_KEY to .env
```
Add `SHODAN_KEY=your_key` to your `.env` file and restart the tool.

---

### GUI opens but network range is wrong
Click the green **Auto** button next to the Network Range field. If it still shows the wrong subnet, run `ipconfig` in PowerShell and manually enter the correct range in the format `10.135.136.0/21`.

---

## FAQ

**Q: Why do all internal IPs score 0/100 in Autonomous mode?**

Internal private IPs (10.x.x.x, 192.168.x.x) are not tracked by public threat intelligence databases. AbuseIPDB and OTX have no data on them so they score 0. This is correct behavior. The value of network scanning is detecting rogue or unexpected devices, not generating threat scores from internal addresses.

---

**Q: Can I scan a specific folder instead of Downloads?**

Yes — modify the `scan_directory_for_hashes()` call in `run_full_scan_cycle()` and pass your desired folder path as the `scan_directory` parameter.

---

**Q: Does Ghost-Hunter block outbound traffic too?**

Currently only inbound block rules (`dir=in`) are applied. To add outbound blocking, duplicate the firewall rule generation with `dir=out` in the `generate_firewall_rules()` function.

---

**Q: How do I stop Ghost-Hunter from scanning certain devices?**

Add a whitelist check in `discover_network_hosts()` to skip known-good IPs such as your router or trusted servers before adding them to the IoC list.

---

**Q: Why is there a 3-second pause between each IoC?**

The `time.sleep(3)` cooldown prevents hitting API rate limits on the free tiers of AbuseIPDB and VirusTotal. Removing it may cause 429 rate-limit errors from the APIs.

---

**Q: Can I run Ghost-Hunter automatically at Windows startup?**

Use Windows Task Scheduler. Create a task that runs `python Ghost-Hunter-v3.py` with the "Run with highest privileges" option checked and trigger set to "At startup".

---

<div align="center">

**Still having issues?** Open an issue on [GitHub](https://github.com/Aaraiz211/Ghost-Hunter/issues)

---

**Ghost-Hunter v3.0** — Autonomous SOC Engine
Aaraiz Tahir | BS Cybersecurity | Air University, Islamabad

</div>
