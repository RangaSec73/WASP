#!/usr/bin/env python3

from scapy.all import sniff, Dot11, Dot11Elt, RadioTap
import time, os, sys, signal, threading, subprocess, re
from collections import defaultdict, deque
import configparser
from datetime import datetime

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

recent_alerts = deque(maxlen=10)

def print_event(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {message}"
    recent_alerts.append(line)
    print(line)

# ---------- LOAD CONFIG ----------

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

src_alerts = 0
bssid_alerts = 0
probe_alerts = 0
auth_alerts = 0
hidden_ssid_alerts = 0
channel_alerts = 0

src_tracker = defaultdict(deque)
bssid_tracker = defaultdict(deque)
probe_tracker = defaultdict(deque)
auth_tracker = defaultdict(deque)
hidden_tracker = defaultdict(deque)
channel_tracker = defaultdict(deque)

alert_cooldown = defaultdict(float)
ALERT_COOLDOWN = 30

ssid_bssid_map = defaultdict(set)
ssid_awareness_printed = set()

mac_roles = defaultdict(set)
mac_channels = defaultdict(set)
mac_role_printed = set()
mac_channel_printed = set()
rf_device_counter = defaultdict(int)

# ---------- HELPER FUNCTIONS ----------

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
    print(f"\n{CYAN}[*] Exiting WASP cleanly...{RESET}")
    RUNNING = False
    print_session_summary()
    time.sleep(2)
    sys.exit(0)

signal.signal(signal.SIGINT, lambda *_: clean_exit())
signal.signal(signal.SIGTERM, lambda *_: clean_exit())

# ---------- VM DETECTION ----------

def is_virtual_machine():
    try:
        with open("/sys/class/dmi/id/product_name", "r") as f:
            product = f.read().lower()

        vm_indicators = ["virtualbox","vmware","kvm","qemu","hyper-v","xen"]
        return any(v in product for v in vm_indicators)
    except:
        return False

def show_vm_advisory():
    print(f"""{YELLOW}{BOLD}
┌─ Environment Notice ──────────────────────────────────────────┐
│ Virtual machine detected                                     │
│ Some USB Wi-Fi adapters may behave unreliably in monitor     │
│ mode when used inside virtualization environments.           │
└─────────────────────────────────────────────────────────────┘
{RESET}""")

# ---------- DIAGNOSTICS ----------

def auto_diagnostics():
    print(f"{BOLD}{CYAN}[*] Running pre-flight diagnostics...{RESET}")

    if os.geteuid() != 0:
        print(f"{RED}[!] Must run as root (sudo){RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Running as root{RESET}")

    try:
        iw = subprocess.check_output(["iw","list"], text=True)
        if "monitor" not in iw:
            print(f"{RED}[!] Adapter does not support monitor mode{RESET}")
            sys.exit(1)
        print(f"{GREEN}[✓] Monitor mode supported{RESET}")
    except:
        pass

    print(f"{GREEN}[*] Diagnostics complete{RESET}")
    print("-"*70)

# ---------- INTERFACE ----------

def select_interface():
    out = subprocess.check_output(["iw","dev"], text=True)
    interfaces=[]

    for line in out.splitlines():
        m=re.search(r"Interface (\w+)", line)
        if m:
            interfaces.append(m.group(1))

    print("\nAvailable Wi-Fi interfaces:\n")

    for i,iface in enumerate(interfaces,1):
        print(f"[{i}] {iface}")

    while True:
        c=input("\nSelect interface to use: ").strip()
        if c.isdigit() and 1<=int(c)<=len(interfaces):
            return interfaces[int(c)-1]

def enable_monitor_mode():
    global SNIFF_INTERFACE
    SNIFF_INTERFACE = BASE_INTERFACE
    print(f"{GREEN}[*] Using capture interface: {SNIFF_INTERFACE}{RESET}")

# ---------- MODE ----------

def select_mode():
    global MODE,TARGET_BSSID,TARGET_SSID

    while True:
        print("\nSelect operating mode:")
        print("1) Monitor all networks")
        print("2) Monitor a specific BSSID")
        print("3) Monitor a specific SSID")
        print("h) Help")
        print("q) Quit")

        c=input("> ").strip().lower()

        if c=="q":
            clean_exit()

        if c=="1":
            MODE="ALL"
            break

        if c=="2":
            MODE="BSSID"
            TARGET_BSSID=input("Enter BSSID: ").lower()
            break

        if c=="3":
            MODE="SSID"
            TARGET_SSID=input("Enter SSID: ")
            break

# ---------- STATUS ----------

def show_status():

    up = int(time.time() - START_TIME)
    h, m, s = up // 3600, (up % 3600) // 60, up % 60

    print(f"\n{BOLD}{CYAN}====================== STATUS ======================{RESET}")

    print(f"   {'Interface':<27} : {BASE_INTERFACE}")
    print(f"   {'Mode':<27} : {MODE}")
    print(f"   {'Runtime':<27} : {h:02}:{m:02}:{s:02}")

    print("\n ------------------ Current Alerts ------------------")

    print(f"   {'Deauth SRC floods':<27} : {src_alerts}")
    print(f"   {'Deauth BSSID floods':<27} : {bssid_alerts}")
    print(f"   {'Probe floods':<27} : {probe_alerts}")
    print(f"   {'Auth floods':<27} : {auth_alerts}")
    print(f"   {'Hidden SSID anomalies':<27} : {hidden_ssid_alerts}")
    print(f"   {'Channel hop anomalies':<27} : {channel_alerts}")

    print(f"{BOLD}====================================================={RESET}")

# ---------- TOP RF DEVICES ----------

def show_top_devices():

    print(f"\n{BOLD}{CYAN}=================== TOP RF DEVICES ==================={RESET}")

    if not rf_device_counter:
        print("   No RF devices observed yet.")
        print(f"{BOLD}======================================================{RESET}")
        return

    top = sorted(rf_device_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    print("\n   {:<20} {}".format("MAC Address", "Frames Seen"))
    print("   -----------------------------------------------")

    for mac, count in top:
        print(f"   {mac:<20} {count}")

    print(f"\n{BOLD}======================================================{RESET}")

# ---------- LAST ALERTS ----------

def show_last_alerts():

    print(f"\n{BOLD}{CYAN}==================== LAST ALERTS ===================={RESET}")

    if not recent_alerts:
        print("   No alerts recorded yet.")
        print(f"{BOLD}====================================================={RESET}")
        return

    for alert in recent_alerts:
        print(f"   {alert}")

    print(f"{BOLD}====================================================={RESET}")

# ---------- PACKET HANDLER ----------

def handle_packet(pkt):

    global src_alerts, bssid_alerts, probe_alerts
    global auth_alerts, hidden_ssid_alerts, channel_alerts

    if not pkt.haslayer(Dot11):
        return

    d = pkt[Dot11]
    now = time.time()

    src = d.addr2
    bssid = d.addr3

    if src:
        rf_device_counter[src] += 1

    if d.subtype in (DEAUTH, DISASSOC) and src and bssid:

        src_tracker[src].append(now)
        bssid_tracker[bssid].append(now)

        src_tracker[src] = deque(t for t in src_tracker[src] if now - t <= WINDOW_SECONDS)
        bssid_tracker[bssid] = deque(t for t in bssid_tracker[bssid] if now - t <= WINDOW_SECONDS)

        if len(src_tracker[src]) == SRC_THRESHOLD:
            if now - alert_cooldown[src] > ALERT_COOLDOWN:
                src_alerts += 1
                print_event(f"{RED}[DEAUTH SRC FLOOD]{RESET} {src}")
                alert_cooldown[src] = now

        if len(bssid_tracker[bssid]) == BSSID_THRESHOLD:
            if now - alert_cooldown[bssid] > ALERT_COOLDOWN:
                bssid_alerts += 1
                print_event(f"{RED}[DEAUTH BSSID FLOOD]{RESET} {bssid}")
                alert_cooldown[bssid] = now

    elif d.subtype == PROBE and src:

        probe_tracker[src].append(now)
        probe_tracker[src] = deque(t for t in probe_tracker[src] if now - t <= WINDOW_SECONDS)

        if len(probe_tracker[src]) == PROBE_THRESHOLD:
            if now - alert_cooldown[src] > ALERT_COOLDOWN:
                probe_alerts += 1
                print_event(f"{YELLOW}[PROBE FLOOD]{RESET} {src}")
                alert_cooldown[src] = now

    elif d.subtype == AUTH and src:

        auth_tracker[src].append(now)
        auth_tracker[src] = deque(t for t in auth_tracker[src] if now - t <= WINDOW_SECONDS)

        if len(auth_tracker[src]) == AUTH_THRESHOLD:
            if now - alert_cooldown[src] > ALERT_COOLDOWN:
                auth_alerts += 1
                print_event(f"{RED}[AUTH FLOOD]{RESET} {src}")
                alert_cooldown[src] = now

    elif d.subtype == BEACON and bssid and is_hidden_ssid(pkt):

        hidden_tracker[bssid].append(now)
        hidden_tracker[bssid] = deque(t for t in hidden_tracker[bssid] if now - t <= WINDOW_SECONDS)

        if len(hidden_tracker[bssid]) == HIDDEN_BEACON_THRESHOLD:
            if now - alert_cooldown[bssid] > ALERT_COOLDOWN:
                hidden_ssid_alerts += 1
                print_event(f"{YELLOW}[HIDDEN SSID ANOMALY]{RESET} {bssid}")
                alert_cooldown[bssid] = now

    ch = extract_channel(pkt)

    if src and ch:

        channel_tracker[src].append((now, ch))
        channel_tracker[src] = deque((t, c) for t, c in channel_tracker[src] if now - t <= WINDOW_SECONDS)

        unique_channels = {c for _, c in channel_tracker[src]}

        if len(unique_channels) >= CHANNEL_THRESHOLD:
            if now - alert_cooldown[src] > ALERT_COOLDOWN:
                channel_alerts += 1
                print_event(f"{YELLOW}[CHANNEL HOP ANOMALY]{RESET} {src}")
                alert_cooldown[src] = now

# ---------- INPUT THREAD ----------

def input_listener():
    while RUNNING:
        try:
            c=input().strip().lower()
        except EOFError:
            continue

        if c=="s":
            show_status()
        elif c=="t":
            show_top_devices()
        elif c=="l":
            show_last_alerts()
        elif c=="m":
            select_mode()
        elif c=="q":
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

print(f"{BOLD}{CYAN}WASP v1.2 — Wireless Auditing & Security Platform{RESET}")
print(f"{CYAN}Passive Wi-Fi Intrusion Detection (WIDS){RESET}")
print("-"*70)

if is_virtual_machine():
    show_vm_advisory()

auto_diagnostics()

# ---------- MONITORING PANEL ----------

BASE_INTERFACE = select_interface()
enable_monitor_mode()

select_mode()

print("-" * 70)
print(f"{CYAN}[*] Monitoring active:{RESET}")
print(f"{WHITE}    Mode: {MODE}{RESET}")
print(f"{WHITE}    Passive detection & awareness enabled{RESET}")
print(f"{WHITE}    s=status • t=top devices • l=last alerts • m=mode • q=quit{RESET}")
print("-" * 70)

threading.Thread(target=input_listener,daemon=True).start()

sniff(
    iface=SNIFF_INTERFACE,
    prn=handle_packet,
    store=False,
    stop_filter=lambda _: not RUNNING
)
