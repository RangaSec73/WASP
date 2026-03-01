# WASP — Wireless Auditing & Security Platform
Passive Wi-Fi Intrusion Detection System (WIDS)

Overview
--------
WASP is a passive Wi-Fi intrusion detection and awareness tool designed to monitor
IEEE 802.11 management traffic and identify suspicious or abusive behaviour on
wireless networks.

WASP does not inject traffic, does not interfere with networks, and does not
attempt mitigation. It is intended for defensive monitoring, learning, and
authorised security auditing.

What WASP Is (and Is Not)
------------------------
WASP is:
- A passive WIDS
- A monitoring and awareness tool
- Designed for learning, auditing, and defensive analysis
- Safe to run on live networks (read-only)

WASP is not:
- An attack tool
- A packet injection framework
- A mitigation or blocking system
- A replacement for enterprise IDS/IPS platforms

Features
--------
Detection (Alerts):
- Deauthentication / Disassociation floods (SRC and BSSID)
- Probe request floods
- Authentication floods
- Hidden SSID beacon anomalies
- Channel hopping anomalies

Awareness (Non-Alerting):
- Multiple BSSIDs advertising the same SSID
- MAC addresses acting as both AP and client
- MAC addresses observed on multiple channels

Requirements
------------
- Linux
- Python 3
- Scapy
- Root privileges (sudo)
- Wireless adapter with monitor mode support

Installation
------------
sudo apt install python3-scapy iw
sudo python3 WASP.py

Usage
-----
Startup flow:
1. Pre-flight diagnostics
2. Interface selection
3. Monitor mode enablement
4. Mode selection (ALL / BSSID / SSID)
5. Monitoring begins

Runtime controls:
s - status
m - change mode
h - help
q - quit cleanly

Configuration (wasp.conf)
-------------------------
Optional configuration file for tuning thresholds and UI behaviour.
If missing, defaults are used silently.

Location:
- ./wasp.conf
- /etc/wasp.conf

Important:
Monitoring mode selection is always interactive and not configurable.

Virtual Machines & Hardware
---------------------------
Wi-Fi monitor mode inside virtual machines is often unreliable.
Bare-metal or dual-boot Linux installations are recommended.

Legal & Ethical Use
-------------------
Use only on wireless networks you own or are explicitly authorised to test.
You are solely responsible for lawful and ethical operation.

Disclaimer
----------
This software is provided "as is", without warranty of any kind.
The author assumes no responsibility for misuse, damage, or legal
consequences resulting from the use of this tool.

License
-------
MIT License. See the LICENSE file for details.

Author
------
Ranga (RangaSec73)

Project Status
--------------
Version 1.0 — stable
Feature-complete passive WIDS.
