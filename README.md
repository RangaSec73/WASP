# WASP

**Wireless Auditing & Security Platform**

Passive Wi-Fi Intrusion Detection System (WIDS)

![Python](https://img.shields.io/badge/python-3.x-blue)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

WASP is a passive Wi-Fi intrusion detection and awareness tool designed to monitor IEEE 802.11 management traffic and identify suspicious or abusive behaviour on wireless networks.

WASP operates entirely in **read-only passive mode**. It does not inject traffic, does not interfere with wireless networks, and does not attempt mitigation.

The tool is designed for defensive monitoring, learning, and authorised wireless security auditing.

---

## Topics

wifi-security • wireless-ids • wids • network-security • cybersecurity • python-security-tool

## What WASP Is (and Is Not)

### WASP is:

* A passive WIDS (Wireless Intrusion Detection System)
* A monitoring and awareness tool
* Designed for learning, auditing, and defensive analysis
* Safe to run on live networks (read-only monitoring)

### WASP is not:

* An attack tool
* A packet injection framework
* A mitigation or blocking system
* A replacement for enterprise IDS/IPS platforms

---

## Features

### Detection (Alerts)

WASP detects common wireless abuse patterns using sliding-window thresholds:

* Deauthentication / Disassociation floods (SRC and BSSID)
* Probe request floods
* Authentication floods
* Hidden SSID beacon anomalies
* Channel hopping anomalies

---

## Operator Console

Version **1.2** introduces an interactive monitoring console.

Runtime controls:

**s → Status panel**
Displays current runtime statistics and alert counters.

**t → Top RF devices**
Shows the most active transmitting MAC addresses observed on the air.

**l → Last alerts**
Displays the most recent IDS alerts generated during the session.

**m → Change monitoring mode**
Allows switching between ALL / BSSID / SSID monitoring modes.

**q → Quit cleanly**
Stops monitoring and displays a session summary.

---

## Session Reporting

When WASP exits cleanly it displays a session summary including:

* Runtime duration
* Interface used
* Monitoring mode
* Alert counters

This provides a quick overview of observed wireless activity.

---

## Awareness (Non-Alerting Observations)

WASP also tracks certain wireless behaviours for situational awareness:

* Multiple BSSIDs advertising the same SSID
* MAC addresses acting as both AP and client
* MAC addresses observed across multiple channels

These are informational observations and do not generate alerts.

---

## Requirements

* Linux
* Python 3
* Scapy
* Root privileges (sudo)
* Wireless adapter with monitor mode support

Install dependencies:

```
sudo apt install python3-scapy iw
```

Run WASP:

```
sudo python3 WASP.py
```

---

## Startup Flow

1. Pre-flight diagnostics
2. Interface selection
3. Monitor mode enablement
4. Mode selection (ALL / BSSID / SSID)
5. Monitoring begins

---

## Configuration (wasp.conf)

Optional configuration file for tuning detection thresholds and UI behaviour.

If the configuration file is not present, WASP runs with safe default values.

Search locations:

```
./wasp.conf
/etc/wasp.conf
```

Monitoring mode selection is always interactive.

---

## Virtual Machines & Hardware

WASP can run inside virtual machines; however, Wi-Fi monitor mode under virtualization is often unreliable due to hardware passthrough limitations.

Some USB Wi-Fi adapters — especially dual-band chipsets such as **MT7612U** and **RTL8812AU** — may behave unpredictably in monitor mode inside VMs.

For VM testing, **2.4 GHz adapters such as RTL8187L-based devices are recommended.**

When WASP detects that it is running inside a virtual machine, it will display an informational advisory notice at startup.

---

## Project Structure

```
WASP/
│
├── WASP.py        # Main IDS sensor
├── wasp.conf      # Optional configuration file
├── README.md      # Project documentation
└── LICENSE        # MIT license
```

---

## Legal & Ethical Use

Use only on wireless networks you own or are explicitly authorised to test.

You are solely responsible for lawful and ethical operation.

---

## Disclaimer

This software is provided **“as is”**, without warranty of any kind.

The author assumes no responsibility for misuse, damage, or legal consequences resulting from the use of this tool.

---

## License

MIT License.

---

## Author

**Ranga (RangaSec73)**

---

## Project Status

**Version 1.2 — stable**

Major additions in this release:

* Interactive monitoring console
* Status panel
* Top RF device visibility
* Alert history viewer
* Alert cooldown system
* Improved terminal output formatting
