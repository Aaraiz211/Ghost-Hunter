import os
import asyncio
import aiohttp
import ipaddress
import re
import time
import hashlib
import threading
import subprocess
import platform
import requests
import nmap
import psutil
import schedule
import customtkinter as ctk
from tkinter import ttk
import tkinter as tk
from scapy.all import sniff, IP
from datetime import datetime
from OTXv2 import OTXv2, IndicatorTypes
from dotenv import load_dotenv

# Windows Event Log
try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# Shodan (pip install shodan)
try:
    import shodan as _shodan_lib
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# --- Load API Keys ---
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_KEY") or "YOUR_ACTUAL_ABUSEIPDB_KEY"
VT_API_KEY        = os.getenv("VT_KEY")         or "YOUR_ACTUAL_VT_KEY"
OTX_API_KEY       = os.getenv("OTX_KEY")        or "YOUR_ACTUAL_OTX_KEY"
SHODAN_API_KEY    = os.getenv("SHODAN_KEY")      or "YOUR_ACTUAL_SHODAN_KEY"

# --- Theme ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")




# ==============================================================================
#  UPGRADE 2 — MITRE ATT&CK MAPPING
# ==============================================================================

MITRE_PORT_MAP = {
    21:   ("T1021.004", "Remote Services: FTP",               "Lateral Movement"),
    22:   ("T1021.004", "Remote Services: SSH",               "Lateral Movement"),
    23:   ("T1021",     "Remote Services: Telnet",            "Lateral Movement"),
    25:   ("T1566",     "Phishing via SMTP",                  "Initial Access"),
    53:   ("T1071.004", "DNS Application Layer Protocol",     "Command & Control"),
    80:   ("T1071.001", "Web Protocols: HTTP",                "Command & Control"),
    135:  ("T1021.003", "DCOM Remote Services",               "Lateral Movement"),
    139:  ("T1021.002", "SMB / Windows Admin Shares",         "Lateral Movement"),
    443:  ("T1071.001", "Web Protocols: HTTPS",               "Command & Control"),
    445:  ("T1021.002", "SMB / Windows Admin Shares",         "Lateral Movement"),
    1433: ("T1190",     "Exploit Public-Facing App: MSSQL",   "Initial Access"),
    3306: ("T1190",     "Exploit Public-Facing DB: MySQL",    "Initial Access"),
    3389: ("T1021.001", "Remote Desktop Protocol (RDP)",      "Lateral Movement"),
    4444: ("T1571",     "Non-Standard Port (Metasploit C2)",  "Command & Control"),
    4445: ("T1571",     "Non-Standard Port (Backdoor)",       "Command & Control"),
    5900: ("T1021.005", "VNC Remote Desktop",                 "Lateral Movement"),
    6667: ("T1071",     "IRC C2 Channel",                     "Command & Control"),
    8080: ("T1071.001", "Web Proxy: HTTP Alt Port",           "Command & Control"),
    8443: ("T1071.001", "Web Proxy: HTTPS Alt Port",          "Command & Control"),
    9001: ("T1090.003", "Tor Network Proxy",                  "Command & Control"),
    9050: ("T1090.003", "Tor SOCKS Proxy",                    "Command & Control"),
}

def map_mitre_techniques(ports, score, otx_count):
    """Map detected ports / scores / OTX pulses to MITRE ATT&CK techniques."""
    techniques = {}
    for p in ports:
        pnum = p.get("port", 0)
        if pnum in MITRE_PORT_MAP:
            tid, name, tactic = MITRE_PORT_MAP[pnum]
            techniques[tid] = {"id": tid, "name": name,
                                "tactic": tactic, "source": f"Port {pnum}"}
    if score > 70:
        techniques["T1583"] = {"id": "T1583", "name": "Acquire Infrastructure",
            "tactic": "Resource Development",
            "source": f"High risk score ({score}/100)"}
    if score > 30:
        techniques["T1071"] = {"id": "T1071",
            "name": "Application Layer Protocol", "tactic": "Command & Control",
            "source": "Malicious score threshold exceeded"}
    if otx_count > 10:
        techniques["T1588"] = {"id": "T1588", "name": "Obtain Capabilities",
            "tactic": "Resource Development",
            "source": f"OTX: {otx_count} threat intelligence pulses"}
    if otx_count > 0:
        techniques["T1203"] = {"id": "T1203",
            "name": "Exploitation for Client Execution", "tactic": "Execution",
            "source": "OTX: Known malicious indicator"}
    return list(techniques.values())


# ==============================================================================
#  UPGRADE 3 — ASYNC API CALLS
#  AbuseIPDB + VirusTotal fired concurrently via aiohttp (5-10x faster)
#  OTX stays synchronous (SDK limitation) but runs immediately after both resolve
# ==============================================================================

async def _async_abuseipdb(session, ip, key):
    try:
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": key},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                return (await r.json()).get("data", {})
    except Exception:
        pass
    return None

async def _async_vt_ip(session, ip, key):
    try:
        async with session.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                return ((await r.json())
                        .get("data", {}).get("attributes", {})
                        .get("last_analysis_stats", {}))
    except Exception:
        pass
    return None

async def _async_vt_hash(session, h, key):
    try:
        async with session.get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": key},
            timeout=aiohttp.ClientTimeout(total=15)
        ) as r:
            if r.status == 200:
                return ((await r.json())
                        .get("data", {}).get("attributes", {})
                        .get("last_analysis_stats", {}))
    except Exception:
        pass
    return None

async def _gather_ip(ip, abuse_key, vt_key):
    async with aiohttp.ClientSession() as s:
        return await asyncio.gather(
            _async_abuseipdb(s, ip, abuse_key),
            _async_vt_ip(s, ip, vt_key)
        )

async def _gather_hash(h, vt_key):
    async with aiohttp.ClientSession() as s:
        return None, await _async_vt_hash(s, h, vt_key)

def run_async_intel(ioc):
    """Blocking wrapper — runs async concurrent API fetch in a new event loop."""
    is_ip = "." in ioc
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            _gather_ip(ioc, ABUSEIPDB_API_KEY, VT_API_KEY) if is_ip
            else _gather_hash(ioc, VT_API_KEY)
        )
        loop.close()
        return result
    except Exception:
        return None, None



# ==============================================================================
#  AUTO NETWORK RANGE DETECTION
# ==============================================================================

def auto_detect_network_range():
    """Detect active network interface and calculate subnet range e.g. 10.135.136.0/21."""
    SKIP_P = ("127.", "169.254.", "0.")
    SKIP_N = ("vmware", "vbox", "virtual", "loopback", "bluetooth", "vmnet", "vethernet")
    best   = None
    try:
        stats = psutil.net_if_stats()
        for iface, addrs in psutil.net_if_addrs().items():
            if iface in stats and not stats[iface].isup:
                continue
            if any(s in iface.lower() for s in SKIP_N):
                continue
            for addr in addrs:
                if addr.family != 2:
                    continue
                ip, mask = addr.address or "", addr.netmask or ""
                if not ip or not mask:
                    continue
                if any(ip.startswith(p) for p in SKIP_P):
                    continue
                if mask == "255.255.255.255":
                    continue
                try:
                    net      = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    cidr_str = str(net)
                    if best is None:
                        best = cidr_str
                    elif not ip.startswith("192.168.") and best.startswith("192.168."):
                        best = cidr_str
                except Exception:
                    continue
    except Exception:
        pass
    return best or "192.168.1.0/24"
# =============================================================
#  BACKEND ENGINE  (Ghost-Hunter v3.0)
# =============================================================

class GhostHunter:
    def __init__(self, log_callback=None, table_callback=None,
                 status_callback=None, stats_callback=None):
        self.headers_abuseipdb = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
        self.headers_vt        = {'x-apikey': VT_API_KEY}
        self.otx               = OTXv2(OTX_API_KEY)
        self.results_log       = []
        self.running           = False
        self.latest_report     = None

        # UPGRADE 1 — Shodan
        if SHODAN_AVAILABLE and SHODAN_API_KEY != "YOUR_ACTUAL_SHODAN_KEY":
            try:
                self.shodan_api = _shodan_lib.Shodan(SHODAN_API_KEY)
            except Exception:
                self.shodan_api = None
        else:
            self.shodan_api = None
        self.log_callback      = log_callback    or print
        self.table_callback    = table_callback  or (lambda *a: None)
        self.status_callback   = status_callback or (lambda *a: None)
        self.stats_callback    = stats_callback  or (lambda *a: None)

    def log(self, message, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_callback(f"[{ts}] {message}", tag)


    # ------------------------------------------------------------------ #
    #  UPGRADE 1 — SHODAN                                                  #
    # ------------------------------------------------------------------ #

    def query_shodan(self, ip):
        """Query Shodan for infrastructure details on a confirmed malicious IP."""
        if not self.shodan_api:
            self.log("   Shodan: not configured — add SHODAN_KEY to .env", "warning")
            return {}
        self.log(f"   [SHODAN] Querying {ip}...", "info")
        try:
            host = self.shodan_api.host(ip)
            result = {
                "org":        host.get("org", "Unknown"),
                "isp":        host.get("isp", "Unknown"),
                "country":    host.get("country_name", "Unknown"),
                "city":       host.get("city", "Unknown"),
                "os":         host.get("os", "Unknown"),
                "open_ports": host.get("ports", []),
                "hostnames":  host.get("hostnames", []),
                "vulns":      list(host.get("vulns", {}).keys()),
                "tags":       host.get("tags", []),
                "last_update":host.get("last_update", "Unknown"),
                "services":   [],
            }
            for item in host.get("data", []):
                result["services"].append({
                    "port":    item.get("port", 0),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                })
            self.log(
                f"   Shodan: {len(result['open_ports'])} ports | "
                f"{result['country']} | {result['org']} | "
                f"{len(result['vulns'])} CVE(s)",
                "danger" if result["vulns"] else "warning"
            )
            for cve in result["vulns"][:5]:
                self.log(f"      CVE: {cve}", "danger")
            return result
        except Exception as e:
            if "No information available" in str(e):
                self.log(f"   Shodan: No data for {ip}", "info")
            else:
                self.log(f"   Shodan error: {e}", "error")
        return {}

    # ------------------------------------------------------------------ #
    #  UPGRADE 3 — ASYNC INTEL                                            #
    # ------------------------------------------------------------------ #

    def query_intel_async(self, ioc):
        """Fire AbuseIPDB + VirusTotal concurrently via aiohttp."""
        self.log("   [ASYNC] AbuseIPDB + VirusTotal firing concurrently...", "info")
        a_data, v_data = run_async_intel(ioc)
        if a_data:
            sc = a_data.get("abuseConfidenceScore", 0)
            self.log(f"   AbuseIPDB: {sc}% confidence",
                     "danger" if sc > 50 else "info")
        if v_data:
            fl = v_data.get("malicious", 0)
            self.log(f"   VirusTotal: {fl} engines flagged",
                     "danger" if fl > 0 else "info")
        return a_data, v_data

    # ------------------------------------------------------------------ #
    #  CTI ENGINE                                                          #
    # ------------------------------------------------------------------ #

    def import_iocs(self, file_path):
        if not os.path.exists(file_path):
            self.log(f"Error: File '{file_path}' not found.", "error")
            return []
        with open(file_path, 'r') as f:
            iocs = [line.strip() for line in f if line.strip()]
        self.log(f"Ingested {len(iocs)} IOCs from file.", "success")
        return iocs

    def query_abuseipdb(self, ip):
        try:
            r = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=self.headers_abuseipdb,
                params={'ipAddress': ip, 'maxAgeInDays': '90'},
                timeout=10)
            if r.status_code == 200:
                data  = r.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                self.log(f"   AbuseIPDB: {score}% confidence",
                         "danger" if score > 50 else "info")
                return data
        except Exception:
            pass
        return None

    def query_virustotal(self, resource):
        is_ip = "." in resource
        url   = (f'https://www.virustotal.com/api/v3/ip_addresses/{resource}'
                 if is_ip else
                 f'https://www.virustotal.com/api/v3/files/{resource}')
        try:
            r = requests.get(url, headers=self.headers_vt, timeout=10)
            if r.status_code == 200:
                stats   = (r.json().get('data', {})
                           .get('attributes', {})
                           .get('last_analysis_stats', {}))
                flagged = stats.get('malicious', 0)
                self.log(f"   VirusTotal: {flagged} engines flagged",
                         "danger" if flagged > 0 else "info")
                return stats
        except Exception:
            pass
        return None

    def query_alienvault(self, resource):
        for attempt in range(3):
            try:
                is_ip    = "." in resource
                ioc_type = IndicatorTypes.IPv4 if is_ip else IndicatorTypes.FILE_HASH_SHA256
                result   = self.otx.get_indicator_details_full(ioc_type, resource)
                count    = (result.get('general', {})
                            .get('pulse_info', {})
                            .get('count', 0))
                self.log(f"   OTX: {count} pulses",
                         "warning" if count > 0 else "info")
                return count
            except Exception:
                if attempt < 2:
                    self.log(f"   OTX busy, retrying ({attempt+1}/3)...", "warning")
                    time.sleep(10)
        self.log("   OTX failed after 3 attempts.", "error")
        return 0

    def calculate_threat_score(self, abuse=None, vt=None, otx=0):
        score = 0
        if abuse:
            score += abuse.get('abuseConfidenceScore', 0) * 0.333
        if vt:
            mal   = vt.get('malicious', 0)
            total = sum(vt.values())
            if total > 0:
                score += (mal / total) * 100 * 0.333
        if otx > 0:
            score += 33.3
        return round(score, 2)

    # ------------------------------------------------------------------ #
    #  NETWORK SECURITY                                                    #
    # ------------------------------------------------------------------ #

    def scan_ports(self, ip):
        self.log(f"   Port scanning {ip}...", "info")
        ports = []
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, '1-1024', arguments='-sV --open')
            if ip not in nm.all_hosts():
                self.log(f"   Nmap: No response from {ip}", "warning")
                return ports
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    s = nm[ip][proto][port]
                    ports.append({'port': port, 'state': s['state'],
                                  'service': s['name'], 'version': s['version']})
                    self.log(f"      {port}/tcp  {s['name']}  {s['version']}", "warning")
        except Exception as e:
            self.log(f"   Port scan error: {e}", "error")
        if not ports:
            self.log(f"   No open ports on {ip}", "info")
        return ports

    def capture_and_triage(self, interface=None, packet_count=100):
        self.log(f"Capturing {packet_count} packets...", "info")
        captured = set()
        private  = ("192.168.", "10.", "172.", "127.", "0.", "255.")

        def process(pkt):
            if IP in pkt:
                for a in (pkt[IP].src, pkt[IP].dst):
                    if not a.startswith(private):
                        captured.add(a)
        try:
            sniff(iface=interface, prn=process, count=packet_count, store=False)
        except Exception as e:
            self.log(f"Capture error: {e}", "error")
        self.log(f"Captured {len(captured)} external IPs.", "success")
        return list(captured)

    def clear_old_firewall_rules(self):
        """Remove previously added Ghost-Hunter firewall rules before applying new ones."""
        self.log("Clearing old Ghost-Hunter firewall rules...", "warning")
        try:
            result = subprocess.run(
                'netsh advfirewall firewall show rule name=all',
                shell=True, capture_output=True, text=True)
            old_names = re.findall(r'GhostHunter_BLOCK_[\d\.]+', result.stdout)
            for name in old_names:
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{name}"',
                    shell=True, capture_output=True)
                self.log(f"   Removed: {name}", "info")
            self.log(f"Cleared {len(old_names)} old rule(s).", "success")
        except Exception as e:
            self.log(f"Cleanup error: {e}", "error")

    def generate_firewall_rules(self):
        malicious = [i['ioc'] for i in self.results_log
                     if i['score'] > 30 and "." in i['ioc']]
        if not malicious:
            self.log("No malicious IPs — no firewall rules needed.", "info")
            return

        os_type = platform.system()
        rules   = []
        self.log(f"Generating {os_type} firewall rules for "
                 f"{len(malicious)} malicious IP(s)...", "warning")

        for ip in malicious:
            rule = (f'netsh advfirewall firewall add rule '
                    f'name="GhostHunter_BLOCK_{ip}" '
                    f'dir=in action=block remoteip={ip}'
                    if os_type == "Windows" else
                    f'iptables -A INPUT -s {ip} -j DROP')
            rules.append((ip, rule))
            self.log(f"   [FW] {rule}", "danger")

        # Save to file
        ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        fw_file = f"firewall_rules_{ts_str}.txt"
        with open(fw_file, "w") as f:
            f.write(f"# Ghost-Hunter Firewall Rules\n"
                    f"# Generated: {datetime.now()}\n\n")
            f.write("\n".join(r for _, r in rules))
        # Also keep a "latest" copy
        with open("firewall_rules_latest.txt", "w") as f:
            f.write(f"# Ghost-Hunter Firewall Rules\n"
                    f"# Generated: {datetime.now()}\n\n")
            f.write("\n".join(r for _, r in rules))
        self.log(f"Firewall rules saved: {fw_file}", "success")

        # Auto-apply rules to Windows Firewall
        self.log("Applying rules to Windows Firewall...", "warning")
        applied = 0
        failed  = 0
        for ip, rule in rules:
            try:
                result = subprocess.run(rule, shell=True,
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    self.log(f"   BLOCKED: {ip}", "success")
                    applied += 1
                else:
                    self.log(f"   Failed to block {ip}: {result.stderr.strip()}", "error")
                    failed += 1
            except Exception as e:
                self.log(f"   Error blocking {ip}: {e}", "error")
                failed += 1
        self.log(f"Firewall update: {applied} blocked, {failed} failed.", "success")

    # ------------------------------------------------------------------ #
    #  AUTONOMOUS SOC MODULES                                             #
    # ------------------------------------------------------------------ #

    def discover_network_hosts(self, network_range):
        self.log(f"Discovering hosts on {network_range}...", "info")
        self.status_callback("Scanning Network...")
        found = []
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network_range, arguments='-sn')
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    hn = nm[host].hostname() or "Unknown"
                    self.log(f"   Live: {host} ({hn})", "success")
                    found.append(host)
            self.log(f"Found {len(found)} host(s).", "success")
        except Exception as e:
            self.log(f"Network discovery error: {e}", "error")
        return found

    def scan_endpoint_connections(self):
        self.log("Scanning endpoint connections...", "info")
        self.status_callback("Scanning Endpoint...")
        ips     = set()
        private = ("192.168.", "10.", "172.", "127.", "0.0")
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.raddr and c.status == 'ESTABLISHED':
                    ip = c.raddr.ip
                    if not ip.startswith(private):
                        try:
                            name = psutil.Process(c.pid).name()
                        except Exception:
                            name = "Unknown"
                        self.log(f"   {name} -> {ip}:{c.raddr.port}", "info")
                        ips.add(ip)
        except Exception as e:
            self.log(f"Endpoint scan error: {e}", "error")
        self.log(f"Found {len(ips)} external connection(s).", "success")
        return list(ips)

    def scan_directory_for_hashes(self, directory=None):
        if not directory:
            directory = os.path.join(os.path.expanduser("~"), "Downloads")
        self.log(f"Hashing files in: {directory}", "info")
        self.status_callback("Hashing Files...")
        hashes = []
        if not os.path.exists(directory):
            self.log(f"Directory not found: {directory}", "error")
            return hashes
        for root, _, files in os.walk(directory):
            for fname in files:
                try:
                    h = hashlib.sha256()
                    with open(os.path.join(root, fname), 'rb') as f:
                        for chunk in iter(lambda: f.read(8192), b''):
                            h.update(chunk)
                    fh = h.hexdigest()
                    self.log(f"   {fname} -> {fh[:20]}...", "info")
                    hashes.append(fh)
                except (PermissionError, OSError):
                    pass
        self.log(f"Hashed {len(hashes)} file(s).", "success")
        return hashes

    def scan_event_logs(self):
        ips = set()
        if not WIN32_AVAILABLE:
            self.log("Skipping event logs (pywin32 not available).", "warning")
            return list(ips)
        self.log("Reading Windows Security event logs...", "info")
        self.status_callback("Reading Event Logs...")
        try:
            hand   = win32evtlog.OpenEventLog(None, "Security")
            flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                      win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events:
                if event.EventID == 4625:
                    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                                         str(event.StringInserts)):
                        if not ip.startswith(("127.", "0.", "192.168.", "10.")):
                            ips.add(ip)
                            self.log(f"   Failed login from: {ip}", "danger")
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            self.log(f"Event log error: {e}", "error")
        self.log(f"Found {len(ips)} brute-force IP(s).", "success")
        return list(ips)

    # ------------------------------------------------------------------ #
    #  TRIAGE PIPELINE                                                     #
    # ------------------------------------------------------------------ #

    def triage_ioc(self, ioc):
        self.log(f"Triaging: {ioc}", "info")
        self.status_callback(f"Triaging {ioc[:25]}...")
        is_ip  = "." in ioc

        # UPGRADE 3: Concurrent async API calls
        a_data, v_data = self.query_intel_async(ioc)

        # OTX: synchronous with retry logic
        o_cnt  = self.query_alienvault(ioc)
        score  = self.calculate_threat_score(a_data, v_data, o_cnt)
        ports  = self.scan_ports(ioc) if score > 30 and is_ip else []

        # UPGRADE 1: Shodan enrichment for malicious IPs
        shodan_data = {}
        if score > 30 and is_ip:
            shodan_data = self.query_shodan(ioc)

        # UPGRADE 2: MITRE ATT&CK mapping
        mitre = map_mitre_techniques(ports, score, o_cnt)
        if mitre:
            self.log(f"   [MITRE] {len(mitre)} technique(s) mapped:", "warning")
            for t in mitre:
                self.log(f"      {t['id']} | {t['name']} | {t['tactic']}", "danger")

        self.results_log.append({'ioc': ioc, 'score': score,
                                  'otx_count': o_cnt, 'ports': ports,
                                  'shodan': shodan_data, 'mitre': mitre})

        status    = "MALICIOUS" if score > 30 else "CLEAN"
        ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in ports) or "N/A"
        mitre_str = " | ".join(t["id"] for t in mitre) or "N/A"
        self.table_callback(ioc, str(score), str(o_cnt), ports_str, mitre_str, status)

        total     = len(self.results_log)
        malicious = sum(1 for r in self.results_log if r['score'] > 30)
        self.stats_callback(total, malicious, total - malicious)

        self.log(f"Score: {score}/100  |  {status}",
                 "danger" if score > 30 else "success")
        self.log("Cooling down 3s...", "info")
        time.sleep(3)

    def run_full_scan_cycle(self, network_range="192.168.1.0/24",
                             scan_directory=None):
        self.results_log = []
        self.log("=" * 52, "info")
        self.log("  AUTONOMOUS SCAN CYCLE STARTED", "success")
        self.log("=" * 52, "info")

        # Clear old firewall rules before new scan
        if platform.system() == "Windows":
            self.clear_old_firewall_rules()

        all_iocs = list(set(
            self.discover_network_hosts(network_range) +
            self.scan_endpoint_connections()           +
            self.scan_directory_for_hashes(scan_directory) +
            self.scan_event_logs()
        ))

        if not all_iocs:
            self.log("No IoCs discovered this cycle.", "warning")
            self.status_callback("Idle")
            return

        self.log(f"Total IoCs to triage: {len(all_iocs)}", "success")
        self.status_callback("Triaging IoCs...")

        for ioc in all_iocs:
            if not self.running:
                break
            self.triage_ioc(ioc)

        self.generate_html_report()
        self.generate_firewall_rules()
        self.log("Scan cycle complete!", "success")
        self.status_callback("Scan Complete")

    # ------------------------------------------------------------------ #
    #  HTML REPORT  (timestamped — never overwrites previous reports)     #
    # ------------------------------------------------------------------ #

    def generate_html_report(self):
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mal = sum(1 for i in self.results_log if i['score'] > 30)
        cln = len(self.results_log) - mal

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Ghost-Hunter Triage Report</title>
  <style>
    body        {{ font-family:'Segoe UI',sans-serif; margin:40px; background:#f0f2f5; }}
    h1          {{ color:#2c3e50; }}
    .dev        {{ color:#555; font-size:.9em; margin-bottom:10px; }}
    .summary    {{ display:flex; gap:20px; margin:20px 0; }}
    .card       {{ padding:15px 30px; border-radius:8px; color:white;
                   font-size:1.1em; font-weight:bold; }}
    .blue       {{ background:#2980b9; }}
    .red        {{ background:#e74c3c; }}
    .green      {{ background:#2ecc71; }}
    table       {{ width:100%; border-collapse:collapse; background:white;
                   border-radius:8px; overflow:hidden; margin-top:20px; }}
    th, td      {{ padding:15px; border:1px solid #ddd; text-align:left; }}
    th          {{ background:#2c3e50; color:white; }}
    tr:hover    {{ background:#f5f5f5; }}
    .mal        {{ background:#e74c3c; color:white; padding:4px 10px;
                   border-radius:4px; font-weight:bold; }}
    .cln        {{ background:#2ecc71; color:white; padding:4px 10px;
                   border-radius:4px; }}
    .pt         {{ background:#eaf0fb; border:1px solid #aac; border-radius:3px;
                   padding:1px 6px; margin:2px; font-family:monospace;
                   font-size:.85em; display:inline-block; }}
    .footer     {{ margin-top:20px; font-size:.8em; color:#666; }}
  </style>
</head>
<body>
  <h1>Ghost-Hunter Triage Report</h1>
  <div class="dev">
    <strong>SOC Intelligence Triage Engine</strong> | Air University Project<br>
    <strong>Developer:</strong> Aaraiz Tahir &nbsp;|&nbsp;
    <strong>BS Cybersecurity</strong> &nbsp;|&nbsp;
    <strong>Generated on:</strong> {ts}
  </div>

  <div class="summary">
    <div class="card blue">Total IoCs: {len(self.results_log)}</div>
    <div class="card red">Malicious: {mal}</div>
    <div class="card green">Clean: {cln}</div>
  </div>

  <table>
    <tr>
      <th>Artifact</th>
      <th>Risk Score</th>
      <th>OTX Pulses</th>
      <th>Open Ports</th>
      <th>Status</th>
    </tr>"""

        for item in self.results_log:
            s   = "MALICIOUS" if item['score'] > 30 else "CLEAN/UNKNOWN"
            c   = "mal"       if item['score'] > 30 else "cln"
            pts = (" ".join(
                      f"<span class='pt'>{p['port']}/{p['service']}</span>"
                      for p in item['ports'])
                   or "N/A")
            html += f"""
    <tr>
      <td><strong>{item['ioc']}</strong></td>
      <td>{item['score']}/100</td>
      <td>{item['otx_count']}</td>
      <td>{pts}</td>
      <td><span class='{c}'>{s}</span></td>
    </tr>"""

        html += """
  </table>
  <p class="footer">Passive OSINT + Network Security Triage Utility
  &nbsp;|&nbsp; Ghost-Hunter Autonomous SOC</p>
</body>
</html>"""

        # Save with unique timestamp — never overwrites old reports
        ts_str      = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"triage_report_{ts_str}.html"
        with open(report_name, "w") as f:
            f.write(html)

        # Always keep a "latest" copy so the button always finds the newest one
        with open("triage_report_latest.html", "w") as f:
            f.write(html)

        self.latest_report = report_name
        self.log(f"Report saved: {report_name}", "success")
        self.log("Latest copy: triage_report_latest.html", "success")


# =============================================================
#  GUI
# =============================================================

class GhostHunterGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Ghost-Hunter — Autonomous SOC Engine  v3.0")
        self.geometry("1420x790")
        self.minsize(1100, 660)
        self.configure(fg_color="#0d1117")
        self.hunter     = None
        self.is_running = False
        self._build_ui()

    # ------------------------------------------------------------------ #
    #  UI CONSTRUCTION                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        # Title bar
        bar = ctk.CTkFrame(self, fg_color="#161b22", corner_radius=0, height=58)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="  GHOST-HUNTER",
                     font=ctk.CTkFont("Consolas", 22, "bold"),
                     text_color="#58a6ff").pack(side="left", padx=16, pady=10)
        ctk.CTkLabel(bar,
                     text="Autonomous SOC Engine  |  Aaraiz Tahir  |  Air University",
                     font=ctk.CTkFont("Consolas", 11),
                     text_color="#8b949e").pack(side="left")
        ctk.CTkLabel(bar, text=" v3.0 ",
                     font=ctk.CTkFont("Consolas", 10, "bold"),
                     text_color="#0d1117", fg_color="#1f6feb",
                     corner_radius=6).pack(side="left", padx=8)

        self.status_lbl = ctk.CTkLabel(bar, text="  IDLE",
                                        font=ctk.CTkFont("Consolas", 12, "bold"),
                                        text_color="#3fb950")
        self.status_lbl.pack(side="right", padx=20)

        # Stats bar
        sbar = ctk.CTkFrame(self, fg_color="#0d1117", height=78)
        sbar.pack(fill="x", padx=14, pady=(10, 0))
        sbar.pack_propagate(False)
        self.s_total = self._card(sbar, "TOTAL IOCs",  "0",    "#58a6ff")
        self.s_mal   = self._card(sbar, "MALICIOUS",   "0",    "#f85149")
        self.s_clean = self._card(sbar, "CLEAN",       "0",    "#3fb950")
        self.s_mitre = self._card(sbar, "MITRE HITS",  "0",    "#a371f7")
        self.s_stat  = self._card(sbar, "STATUS",      "IDLE", "#d29922")

        # Body
        body = ctk.CTkFrame(self, fg_color="#0d1117")
        body.pack(fill="both", expand=True, padx=14, pady=10)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color="#161b22", corner_radius=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self._build_table(left)

        right = ctk.CTkFrame(body, fg_color="#161b22", corner_radius=10)
        right.grid(row=0, column=1, sticky="nsew")
        self._build_controls(right)

    def _card(self, parent, label, value, color):
        f = ctk.CTkFrame(parent, fg_color="#161b22", corner_radius=8, width=155)
        f.pack(side="left", padx=6, pady=5, fill="y")
        f.pack_propagate(False)
        ctk.CTkLabel(f, text=label,
                     font=ctk.CTkFont("Consolas", 9, "bold"),
                     text_color="#8b949e").pack(pady=(8, 0))
        v = ctk.CTkLabel(f, text=value,
                          font=ctk.CTkFont("Consolas", 22, "bold"),
                          text_color=color)
        v.pack()
        return v

    def _build_table(self, parent):
        ctk.CTkLabel(parent, text="  TRIAGE RESULTS",
                     font=ctk.CTkFont("Consolas", 13, "bold"),
                     text_color="#58a6ff").pack(anchor="w", padx=14, pady=(12, 5))

        sty = ttk.Style()
        sty.theme_use("clam")
        sty.configure("G.Treeview",
                       background="#0d1117", foreground="#c9d1d9",
                       rowheight=30, fieldbackground="#0d1117",
                       borderwidth=0, font=("Consolas", 10))
        sty.configure("G.Treeview.Heading",
                       background="#21262d", foreground="#58a6ff",
                       font=("Consolas", 10, "bold"), borderwidth=0)
        sty.map("G.Treeview",
                background=[("selected", "#1f6feb")],
                foreground=[("selected", "white")])

        self.tree = ttk.Treeview(
            parent,
            columns=("Artifact", "Score", "OTX", "Ports", "MITRE", "Status"),
            show="headings", style="G.Treeview")

        for col, w, anchor in [
            ("Artifact", 220, "w"), ("Score",  80, "center"),
            ("OTX",       55, "center"), ("Ports", 100, "w"),
            ("MITRE",    145, "w"),  ("Status", 85, "center"),
        ]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=anchor, minwidth=60)

        self.tree.tag_configure("malicious", foreground="#f85149",
                                 font=("Consolas", 10, "bold"))
        self.tree.tag_configure("clean", foreground="#3fb950")

        sb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True,
                       padx=(10, 0), pady=(0, 10))
        sb.pack(side="right", fill="y", pady=(0, 10), padx=(0, 5))

    def _build_controls(self, parent):
        # Section label
        ctk.CTkLabel(parent, text="  CONFIGURATION",
                     font=ctk.CTkFont("Consolas", 13, "bold"),
                     text_color="#58a6ff").pack(anchor="w", padx=14, pady=(12, 5))

        cfg = ctk.CTkFrame(parent, fg_color="#0d1117", corner_radius=8)
        cfg.pack(fill="x", padx=10, pady=5)

        def lbl(text, row):
            ctk.CTkLabel(cfg, text=text,
                         font=ctk.CTkFont("Consolas", 11),
                         text_color="#8b949e").grid(
                             row=row, column=0, padx=10, pady=8, sticky="w")

        lbl("Scan Mode", 0)
        self.mode_var = ctk.StringVar(value="Autonomous SOC")
        ctk.CTkOptionMenu(
            cfg,
            values=["Autonomous SOC", "Manual IoC File", "Live Traffic Capture"],
            variable=self.mode_var,
            font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", button_color="#1f6feb",
            width=210,
            command=self._on_mode
        ).grid(row=0, column=1, padx=10, pady=8)

        lbl("Network Range", 1)
        net_frame = ctk.CTkFrame(cfg, fg_color="transparent")
        net_frame.grid(row=1, column=1, padx=10, pady=8, sticky="w")
        self.net_entry = ctk.CTkEntry(
            net_frame, font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", width=152,
            placeholder_text="e.g. 10.135.136.0/21")
        self.net_entry.pack(side="left")
        ctk.CTkButton(
            net_frame, text="Auto",
            font=ctk.CTkFont("Consolas", 10, "bold"),
            fg_color="#238636", hover_color="#2ea043",
            width=48, height=28, corner_radius=6,
            command=self._auto_detect_range
        ).pack(side="left", padx=(6, 0))
        detected = auto_detect_network_range()
        self.net_entry.insert(0, detected)

        lbl("IoC File", 2)
        self.ioc_entry = ctk.CTkEntry(
            cfg, font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", width=210,
            placeholder_text="iocs.txt", state="disabled")
        self.ioc_entry.grid(row=2, column=1, padx=10, pady=8)

        lbl("Interval (min)", 3)
        self.int_entry = ctk.CTkEntry(
            cfg, font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", width=210)
        self.int_entry.grid(row=3, column=1, padx=10, pady=8)
        self.int_entry.insert(0, "30")

        lbl("Shodan", 4)
        shodan_ok  = (SHODAN_AVAILABLE and
                      SHODAN_API_KEY != "YOUR_ACTUAL_SHODAN_KEY")
        shodan_txt = "\u2713  Configured" if shodan_ok else "\u2717  Add SHODAN_KEY to .env"
        shodan_clr = "#3fb950" if shodan_ok else "#f85149"
        ctk.CTkLabel(cfg, text=shodan_txt,
                     font=ctk.CTkFont("Consolas", 11),
                     text_color=shodan_clr).grid(
                         row=4, column=1, padx=10, pady=6, sticky="w")

        lbl("Async APIs", 5)
        ctk.CTkLabel(cfg, text="\u2713  Enabled (concurrent)",
                     font=ctk.CTkFont("Consolas", 11),
                     text_color="#3fb950").grid(
                         row=5, column=1, padx=10, pady=6, sticky="w")

        # Buttons row 1
        bf1 = ctk.CTkFrame(parent, fg_color="transparent")
        bf1.pack(fill="x", padx=10, pady=(6, 3))

        self.start_btn = ctk.CTkButton(
            bf1, text="  START SCAN",
            font=ctk.CTkFont("Consolas", 13, "bold"),
            fg_color="#1f6feb", hover_color="#388bfd",
            height=42, corner_radius=8,
            command=self._start)
        self.start_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))

        self.stop_btn = ctk.CTkButton(
            bf1, text="  STOP",
            font=ctk.CTkFont("Consolas", 13, "bold"),
            fg_color="#21262d", hover_color="#f85149",
            text_color="#f85149", height=42,
            corner_radius=8, state="disabled",
            command=self._stop)
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        # Buttons row 2
        bf2 = ctk.CTkFrame(parent, fg_color="transparent")
        bf2.pack(fill="x", padx=10, pady=(0, 8))

        ctk.CTkButton(
            bf2, text="Open Report",
            font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", hover_color="#30363d",
            height=34, corner_radius=8,
            command=self._open_report
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))

        ctk.CTkButton(
            bf2, text="Clear All",
            font=ctk.CTkFont("Consolas", 11),
            fg_color="#21262d", hover_color="#30363d",
            height=34, corner_radius=8,
            command=self._clear
        ).pack(side="left", expand=True, fill="x", padx=(4, 0))

        # Console
        ctk.CTkLabel(parent, text="  LIVE CONSOLE",
                     font=ctk.CTkFont("Consolas", 13, "bold"),
                     text_color="#58a6ff").pack(anchor="w", padx=14, pady=(8, 4))

        self.console = tk.Text(
            parent, bg="#0d1117", fg="#c9d1d9",
            font=("Consolas", 10), relief="flat", bd=0,
            insertbackground="white",
            selectbackground="#1f6feb",
            state="disabled", wrap="word")
        self.console.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        for tag, color in [
            ("info",    "#c9d1d9"),
            ("success", "#3fb950"),
            ("warning", "#d29922"),
            ("danger",  "#f85149"),
            ("error",   "#f85149"),
        ]:
            self.console.tag_config(tag, foreground=color)

    # ------------------------------------------------------------------ #
    #  GUI CALLBACKS                                                       #
    # ------------------------------------------------------------------ #

    def _on_mode(self, mode):
        self.net_entry.configure(
            state="normal" if mode == "Autonomous SOC" else "disabled")
        self.ioc_entry.configure(
            state="normal" if mode == "Manual IoC File" else "disabled")

    def _auto_detect_range(self):
        """Auto-detect active network interface and fill Network Range."""
        detected = auto_detect_network_range()
        self.net_entry.configure(state="normal")
        self.net_entry.delete(0, "end")
        self.net_entry.insert(0, detected)
        self._log(f"[AUTO] Network range detected: {detected}", "success")

    def _log(self, msg, tag="info"):
        def _w():
            self.console.configure(state="normal")
            self.console.insert("end", msg + "\n", tag)
            self.console.see("end")
            self.console.configure(state="disabled")
        self.after(0, _w)

    def _add_row(self, ioc, score, otx, ports, mitre, status):
        def _w():
            tag = "malicious" if status == "MALICIOUS" else "clean"
            self.tree.insert("", "end",
                              values=(ioc, f"{score}/100", otx, ports, mitre, status),
                              tags=(tag,))
            self.tree.yview_moveto(1.0)
            if mitre and mitre != "N/A":
                try:
                    n = int(self.s_mitre.cget("text")) + len(mitre.split("|"))
                except ValueError:
                    n = 1
                self.s_mitre.configure(text=str(n))
        self.after(0, _w)

    def _set_status(self, text):
        def _w():
            self.status_lbl.configure(text=f"  {text.upper()}")
            self.s_stat.configure(text=text[:12])
        self.after(0, _w)

    def _set_stats(self, total, mal, clean):
        def _w():
            self.s_total.configure(text=str(total))
            self.s_mal.configure(text=str(mal))
            self.s_clean.configure(text=str(clean))
        self.after(0, _w)

    # ------------------------------------------------------------------ #
    #  SCAN CONTROL                                                        #
    # ------------------------------------------------------------------ #

    def _start(self):
        if self.is_running:
            return
        self.is_running = True
        self.start_btn.configure(state="disabled", text="  SCANNING...")
        self.stop_btn.configure(state="normal")
        self._set_status("Running")
        self.status_lbl.configure(text_color="#d29922")

        self.hunter = GhostHunter(
            log_callback    = self._log,
            table_callback  = self._add_row,
            status_callback = self._set_status,
            stats_callback  = self._set_stats,
        )
        self.hunter.running = True
        mode = self.mode_var.get()

        def _run():
            try:
                if mode == "Autonomous SOC":
                    net = self.net_entry.get() or "192.168.1.0/24"
                    try:
                        mins = int(self.int_entry.get())
                    except ValueError:
                        mins = 30
                    self.hunter.run_full_scan_cycle(network_range=net)
                    schedule.every(mins).minutes.do(
                        self.hunter.run_full_scan_cycle, network_range=net)
                    while self.hunter.running:
                        schedule.run_pending()
                        time.sleep(1)

                elif mode == "Manual IoC File":
                    iocs = self.hunter.import_iocs(
                        self.ioc_entry.get() or "iocs.txt")
                    for ioc in iocs:
                        if not self.hunter.running:
                            break
                        self.hunter.triage_ioc(ioc)
                    self.hunter.generate_html_report()
                    self.hunter.generate_firewall_rules()

                elif mode == "Live Traffic Capture":
                    ips = self.hunter.capture_and_triage(packet_count=100)
                    for ioc in ips:
                        if not self.hunter.running:
                            break
                        self.hunter.triage_ioc(ioc)
                    self.hunter.generate_html_report()
                    self.hunter.generate_firewall_rules()

            except Exception as e:
                self._log(f"Scan error: {e}", "error")
            finally:
                self.after(0, self._done)

        threading.Thread(target=_run, daemon=True).start()

    def _stop(self):
        if self.hunter:
            self.hunter.running = False
        schedule.clear()
        self._log("Scan stopped by user.", "warning")
        self._done()

    def _done(self):
        self.is_running = False
        self.start_btn.configure(state="normal", text="  START SCAN")
        self.stop_btn.configure(state="disabled")
        self.status_lbl.configure(text="  IDLE", text_color="#3fb950")
        self._set_status("Idle")

    # ------------------------------------------------------------------ #
    #  OPEN REPORT  — always opens the most recent scan's report          #
    # ------------------------------------------------------------------ #

    def _open_report(self):
        report = None

        # 1. Check if current hunter has a report from this session
        if self.hunter and self.hunter.latest_report:
            if os.path.exists(self.hunter.latest_report):
                report = self.hunter.latest_report

        # 2. Fall back to the "latest" symlink file
        if not report and os.path.exists("triage_report_latest.html"):
            report = "triage_report_latest.html"

        # 3. Fall back to scanning folder for most recent timestamped report
        if not report:
            candidates = sorted([
                f for f in os.listdir(".")
                if f.startswith("triage_report_") and f.endswith(".html")
            ])
            if candidates:
                report = candidates[-1]

        if report:
            self._log(f"Opening report: {report}", "info")
            if platform.system() == "Windows":
                os.startfile(report)
            else:
                subprocess.run(["xdg-open", report])
        else:
            self._log("No report found. Run a scan first.", "warning")

    def _clear(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")
        for w in (self.s_total, self.s_mal, self.s_clean, self.s_mitre):
            w.configure(text="0")
        if self.hunter:
            self.hunter.results_log = []


# =============================================================
#  ENTRY POINT
# =============================================================

if __name__ == "__main__":
    app = GhostHunterGUI()
    app.mainloop()
