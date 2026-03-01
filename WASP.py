#!/usr/bin/env python3

from scapy.all import sniff, Dot11, Dot11Elt, RadioTap
import time, os, sys, signal, threading, subprocess, re
from collections import defaultdict, deque
import configparser

# ================= DEFAULT CONFIG =================
WINDOW_SECONDS = 5
SRC_THRESHOLD = 10
BSSID_THRESHOLD = 20
PROBE_THRESHOLD = 30
AUTH_THRESHOLD = 20
HIDDEN_BEACON_THRESHOLD = 15
CHANNEL_THRESHOLD = 4

SHOW_AWARENESS = True
USE_COLOUR = True
# ================================================

# ---------- LOAD CONFIG (silent if missing) ----------

def load_config():
    global WINDOW_SECONDS, SRC_THRESHOLD, BSSID_THRESHOLD
    global PROBE_THRESHOLD, AUTH_THRESHOLD
    global HIDDEN_BEACON_THRESHOLD, CHANNEL_THRESHOLD
    global SHOW_AWARENESS, USE_COLOUR

    cfg = configparser.ConfigParser()
    cfg.read(["./wasp.conf", "/etc/wasp.conf"])

    if "general" in cfg:
        WINDOW_SECONDS = cfg.getint("general", "window_seconds", fallback=WINDOW_SECONDS)

    if "thresholds" in cfg:
        SRC_THRESHOLD = cfg.getint("thresholds", "deauth_src", fallback=SRC_THRESHOLD)
        BSSID_THRESHOLD = cfg.getint("thresholds", "deauth_bssid", fallback=BSSID_THRESHOLD)
        PROBE_THRESHOLD = cfg.getint("thresholds", "probe", fallback=PROBE_THRESHOLD)
        AUTH_THRESHOLD = cfg.getint("thresholds", "auth", fallback=AUTH_THRESHOLD)
        HIDDEN_BEACON_THRESHOLD = cfg.getint("thresholds", "hidden_ssid", fallback=HIDDEN_BEACON_THRESHOLD)
        CHANNEL_THRESHOLD = cfg.getint("thresholds", "channel_hop", fallback=CHANNEL_THRESHOLD)

    if "ui" in cfg:
        SHOW_AWARENESS = cfg.getboolean("ui", "show_awareness", fallback=SHOW_AWARENESS)
        USE_COLOUR = cfg.getboolean("ui", "use_colour", fallback=USE_COLOUR)

load_config()

# ============== ANSI COLOURS ==============
RESET="\033[0m"; WHITE="\033[37m"; GREEN="\033[92m"
YELLOW="\033[93m"; RED="\033[91m"; CYAN="\033[96m"; BOLD="\033[1m"

if not USE_COLOUR:
    RESET=WHITE=GREEN=YELLOW=RED=CYAN=BOLD=""
# =========================================

# 802.11 subtypes
DEAUTH = 0x0c
DISASSOC = 0x0a
PROBE = 0x04
BEACON = 0x08
AUTH = 0x0b

# ============== GLOBAL STATE ==============
MODE = None
TARGET_BSSID = None
TARGET_SSID = None

BASE_INTERFACE = None
SNIFF_INTERFACE = None
RUNNING = True
START_TIME = time.time()

# Alert counters
src_alerts = 0
bssid_alerts = 0
probe_alerts = 0
auth_alerts = 0
hidden_ssid_alerts = 0
channel_alerts = 0

# Detection trackers
src_tracker = defaultdict(deque)
bssid_tracker = defaultdict(deque)
probe_tracker = defaultdict(deque)
auth_tracker = defaultdict(deque)
hidden_tracker = defaultdict(deque)
channel_tracker = defaultdict(deque)

# Awareness trackers
ssid_bssid_map = defaultdict(set)
ssid_awareness_printed = set()

mac_roles = defaultdict(set)
mac_channels = defaultdict(set)
mac_role_printed = set()
mac_channel_printed = set()
# =========================================


# ---------- DIAGNOSTICS ----------

def auto_diagnostics():
    print(f"{BOLD}{CYAN}[*] Running pre-flight diagnostics...{RESET}")

    if os.geteuid() != 0:
        print(f"{RED}[!] Must run as root (sudo){RESET}")
        sys.exit(1)
    print(f"{GREEN}[✓] Running as root{RESET}")

    try:
        nm = subprocess.run(
            ["systemctl", "is-active", "NetworkManager"],
            capture_output=True, text=True
        )
        if nm.stdout.strip() == "active":
            print(f"{YELLOW}[!] NetworkManager is running (may interfere){RESET}")
    except Exception:
        pass

    try:
        iw = subprocess.check_output(["iw", "list"], text=True)
        if "monitor" not in iw:
            print(f"{RED}[!] Adapter does not support monitor mode{RESET}")
            sys.exit(1)
        print(f"{GREEN}[✓] Monitor mode supported{RESET}")
    except Exception:
        pass

    print(f"{GREEN}[*] Diagnostics complete{RESET}")
    print("-" * 70)


# ---------- INTERFACE ----------

def select_interface():
    out = subprocess.check_output(["iw", "dev"], text=True)
    interfaces = []

    for line in out.splitlines():
        m = re.search(r"Interface (\w+)", line)
        if m:
            interfaces.append(m.group(1))

    if not interfaces:
        print(f"{RED}[!] No wireless interfaces found{RESET}")
        sys.exit(1)

    print("\nAvailable Wi-Fi interfaces:\n")
    for i, iface in enumerate(interfaces, 1):
        print(f"[{i}] {iface}")

    while True:
        c = input("\nSelect interface to use: ").strip()
        if c.isdigit() and 1 <= int(c) <= len(interfaces):
            return interfaces[int(c) - 1]


def enable_monitor_mode():
    global SNIFF_INTERFACE

    iw_out = subprocess.check_output(["iw", "dev"], text=True)
    if "type monitor" not in iw_out:
        print(f"{YELLOW}[!] {BASE_INTERFACE} not in monitor mode{RESET}")
        if input("Enable monitor mode? (y/n): ").lower() == "y":
            subprocess.check_call(["ip", "link", "set", BASE_INTERFACE, "down"])
            subprocess.check_call(["iw", "dev", BASE_INTERFACE, "set", "type", "monitor"])
            subprocess.check_call(["ip", "link", "set", BASE_INTERFACE, "up"])
        else:
            sys.exit(0)

    SNIFF_INTERFACE = BASE_INTERFACE
    print(f"{GREEN}[*] Using capture interface: {SNIFF_INTERFACE}{RESET}")


# ---------- MODE / HELP ----------

def select_mode():
    global MODE, TARGET_BSSID, TARGET_SSID

    while True:
        print("\nSelect operating mode:")
        print("1) Monitor all networks")
        print("2) Monitor a specific BSSID")
        print("3) Monitor a specific SSID")
        c = input("> ").strip()

        if c == "1":
            MODE = "ALL"
            TARGET_BSSID = TARGET_SSID = None
            break
        if c == "2":
            MODE = "BSSID"
            TARGET_BSSID = input("Enter BSSID: ").lower()
            break
        if c == "3":
            MODE = "SSID"
            TARGET_SSID = input("Enter SSID: ")
            break

    print("-" * 70)
    print(f"{GREEN}[*] Monitoring active:{RESET}")
    print(f"{WHITE}    Mode: {MODE}{RESET}")
    print(f"{WHITE}    Passive detection & awareness enabled{RESET}")
    print(f"{WHITE}    s=status • m=mode • h=help • q=quit{RESET}")
    print("-" * 70)


def show_help():
    print(f"""
{BOLD}{CYAN}[HELP] WASP — Wireless Auditing & Security Platform{RESET}

 Controls:
   s → show status
   m → change monitoring mode
   h → show this help screen
   q → quit cleanly

 Passive Wi-Fi intrusion detection and awareness tool.
 No packets are injected.
""")


# ---------- STATUS ----------

def show_status():
    up = int(time.time() - START_TIME)
    h, m, s = up // 3600, (up % 3600) // 60, up % 60

    def row(label, value):
        print(f" {label:<27} : {value}")

    print(f"\n{BOLD}{CYAN}[STATUS]{RESET}")
    row("Mode", MODE)
    row("Deauth SRC alerts", src_alerts)
    row("Deauth BSSID alerts", bssid_alerts)
    row("Probe alerts", probe_alerts)
    row("Auth flood alerts", auth_alerts)
    row("Hidden SSID alerts", hidden_ssid_alerts)
    row("Channel hop alerts", channel_alerts)
    row("Uptime", f"{h:02}:{m:02}:{s:02}")
    print("-" * 70)


# ---------- SESSION SUMMARY ----------

def print_session_summary():
    up = int(time.time() - START_TIME)
    h, m, s = up // 3600, (up % 3600) // 60, up % 60

    print(f"\n{BOLD}==================== SESSION SUMMARY ===================={RESET}")
    print(f"   {'Interface':<27} : {BASE_INTERFACE}")
    print(f"   {'Mode':<27} : {MODE}")
    print(f"   {'Runtime':<27} : {h:02}:{m:02}:{s:02}")

    print("\n ------------------ Alerts Triggered ------------------")
    print(f"   {'Deauth SRC floods':<27} : {src_alerts}")
    print(f"   {'Deauth BSSID floods':<27} : {bssid_alerts}")
    print(f"   {'Probe floods':<27} : {probe_alerts}")
    print(f"   {'Auth floods':<27} : {auth_alerts}")
    print(f"   {'Hidden SSID anomalies':<27} : {hidden_ssid_alerts}")
    print(f"   {'Channel hop anomalies':<27} : {channel_alerts}")
    print(f"{BOLD}========================================================{RESET}")


def clean_exit():
    global RUNNING
    print(f"\n{CYAN}[*] Exiting WASP cleanly in 4 seconds...{RESET}")
    RUNNING = False
    print_session_summary()
    time.sleep(4)
    sys.exit(0)


signal.signal(signal.SIGINT, lambda *_: clean_exit())
signal.signal(signal.SIGTERM, lambda *_: clean_exit())


# ---------- PACKET HANDLER ----------

def extract_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0 and elt.info:
            return elt.info.decode(errors="ignore")
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def is_hidden_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            return elt.info == b""
        elt = elt.payload.getlayer(Dot11Elt)
    return False


def extract_channel(pkt):
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        if hasattr(rt, "ChannelFrequency"):
            return rt.ChannelFrequency
    return None


def handle_packet(pkt):
    global src_alerts, bssid_alerts, probe_alerts
    global auth_alerts, hidden_ssid_alerts, channel_alerts

    if not pkt.haslayer(Dot11):
        return

    d = pkt[Dot11]
    now = time.time()
    src = d.addr2
    bssid = d.addr3

    # Awareness — SSID ↔ BSSID
    if SHOW_AWARENESS and d.subtype == BEACON and bssid:
        ssid = extract_ssid(pkt)
        if ssid:
            ssid_bssid_map[ssid].add(bssid)
            mac_roles[bssid].add("AP")
            if len(ssid_bssid_map[ssid]) >= 2 and ssid not in ssid_awareness_printed:
                ssid_awareness_printed.add(ssid)
                print(f"{YELLOW}{BOLD}[?] Multiple BSSIDs advertising SSID \"{ssid}\"{RESET}")

    # Awareness — MAC roles
    if SHOW_AWARENESS and src and d.subtype in (PROBE, AUTH):
        mac_roles[src].add("CLIENT")
        if len(mac_roles[src]) >= 2 and src not in mac_role_printed:
            mac_role_printed.add(src)
            print(f"{YELLOW}{BOLD}[?] MAC acting as AP and CLIENT: {src}{RESET}")

    # Awareness — MAC channels
    ch = extract_channel(pkt)
    if SHOW_AWARENESS and src and ch:
        mac_channels[src].add(ch)
        if len(mac_channels[src]) >= 2 and src not in mac_channel_printed:
            mac_channel_printed.add(src)
            print(f"{YELLOW}{BOLD}[?] MAC observed on multiple channels: {src}{RESET}")

    # Mode filtering
    if MODE == "BSSID" and bssid and bssid.lower() != TARGET_BSSID:
        return
    if MODE == "SSID":
        ssid = extract_ssid(pkt)
        if ssid != TARGET_SSID:
            return

    # Detections
    if d.subtype in (DEAUTH, DISASSOC) and src and bssid:
        src_tracker[src].append(now)
        bssid_tracker[bssid].append(now)
        src_tracker[src] = deque(t for t in src_tracker[src] if now - t <= WINDOW_SECONDS)
        bssid_tracker[bssid] = deque(t for t in bssid_tracker[bssid] if now - t <= WINDOW_SECONDS)
        if len(src_tracker[src]) >= SRC_THRESHOLD:
            src_alerts += 1
        if len(bssid_tracker[bssid]) >= BSSID_THRESHOLD:
            bssid_alerts += 1

    elif d.subtype == PROBE and src:
        probe_tracker[src].append(now)
        probe_tracker[src] = deque(t for t in probe_tracker[src] if now - t <= WINDOW_SECONDS)
        if len(probe_tracker[src]) >= PROBE_THRESHOLD:
            probe_alerts += 1

    elif d.subtype == AUTH and src:
        auth_tracker[src].append(now)
        auth_tracker[src] = deque(t for t in auth_tracker[src] if now - t <= WINDOW_SECONDS)
        if len(auth_tracker[src]) >= AUTH_THRESHOLD:
            auth_alerts += 1

    elif d.subtype == BEACON and bssid and is_hidden_ssid(pkt):
        hidden_tracker[bssid].append(now)
        hidden_tracker[bssid] = deque(t for t in hidden_tracker[bssid] if now - t <= WINDOW_SECONDS)
        if len(hidden_tracker[bssid]) >= HIDDEN_BEACON_THRESHOLD:
            hidden_ssid_alerts += 1

    if src and ch:
        channel_tracker[src].append((now, ch))
        channel_tracker[src] = deque((t, c) for t, c in channel_tracker[src] if now - t <= WINDOW_SECONDS)
        if len({c for _, c in channel_tracker[src]}) >= CHANNEL_THRESHOLD:
            channel_alerts += 1


# ---------- INPUT THREAD ----------

def input_listener():
    while RUNNING:
        try:
            c = input().strip().lower()
        except EOFError:
            continue

        if c == "s":
            show_status()
        elif c == "m":
            select_mode()
        elif c == "h":
            show_help()
        elif c == "q":
            clean_exit()


# ---------- STARTUP ----------

os.system("clear")
print(f"""{BOLD}{CYAN}
██╗    ██╗ █████╗ ███████╗██████╗
██║    ██║██╔══██╗██╔════╝██╔══██╗
██║ █╗ ██║███████║███████╗██████╔╝
██║███╗██║██╔══██║╚════██║██╔═══╝
╚███╔███╔╝██║  ██║███████║██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝
{RESET}""")

print(f"{BOLD}{CYAN}WASP — Wireless Auditing & Security Platform{RESET}")
print(f"{CYAN}Passive Wi-Fi Intrusion Detection (WIDS){RESET}")
print("-" * 70)

auto_diagnostics()
BASE_INTERFACE = select_interface()
enable_monitor_mode()
select_mode()

threading.Thread(target=input_listener, daemon=True).start()

sniff(
    iface=SNIFF_INTERFACE,
    prn=handle_packet,
    store=False,
    stop_filter=lambda _: not RUNNING
)
