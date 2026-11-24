"""
MARSAD | مَــرصــــد  -  detection engine
=======================================

Non-blocking ``scapy.AsyncSniffer(store=False)`` capture with three
multi-tier detectors (Low / Medium / High):

    Port Scanning   distinct TCP SYN destination ports per source IP   (5.0 s window)
    SYN Flood       TCP SYN packets to one (src_ip, dst_port)          (2.0 s window)
    ARP Spoofing    IP -> MAC conflicts seen in ARP replies           (10.0 s window)

``sniffer_state`` is the dictionary shared with the Streamlit UI.
"""

import time
from collections import defaultdict, deque

from scapy.all import AsyncSniffer, IP, TCP, ARP, get_working_ifaces

from database import init_db, insert_alert

# --------------------------------------------------------------------------
# In-memory tracking structures (sliding windows)
# --------------------------------------------------------------------------
port_scan_tracker = defaultdict(deque)       # src_ip -> deque[(timestamp, dst_port)]
syn_flood_tracker = defaultdict(deque)       # (src_ip, dst_port) -> deque[timestamp]
arp_table = {}                               # ip_address -> baseline_mac_address
arp_conflict_tracker = defaultdict(deque)    # src_ip -> deque[timestamp]
alert_cooldown = {}                          # (src_ip, attack_type) -> (last_time, last_severity_rank)

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}

# Shared runtime state with Streamlit UI
sniffer_state = {
    "instance": None,
    "packets_inspected": 0,
    "current_iface": "Default (Auto)",
    "error": None,
    # Extra telemetry (additive - the UI may ignore these keys)
    "started_at": None,
    "alerts_raised": 0,
    "analysis_errors": 0,
    "last_analysis_error": None,
}

# --- Multi-Tier Thresholds ---
PORT_SCAN_WINDOW = 5.0
PORT_SCAN_LOW = 6          # 6 - 12 distinct ports / 5s
PORT_SCAN_MEDIUM = 13      # 13 - 20 distinct ports / 5s
PORT_SCAN_HIGH = 21        # >= 21 distinct ports / 5s

SYN_FLOOD_WINDOW = 2.0
SYN_FLOOD_LOW = 15         # 15 - 30 SYN packets / 2s
SYN_FLOOD_MEDIUM = 31      # 31 - 50 SYN packets / 2s
SYN_FLOOD_HIGH = 51        # >= 51 SYN packets / 2s

ARP_CONFLICT_WINDOW = 10.0
COOLDOWN_SECONDS = 5.0

# Housekeeping for long-running sensors
GC_INTERVAL = 30.0
COOLDOWN_RETENTION = 60.0
_last_gc = 0.0

TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_ACK = 0x10


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _is_pure_syn(flags):
    """True for a connection-opening SYN (SYN set, no ACK / RST / FIN)."""
    try:
        value = int(flags)
    except (TypeError, ValueError):
        return flags == "S"
    return (value & (TCP_SYN | TCP_ACK | TCP_RST | TCP_FIN)) == TCP_SYN


def _prune_timestamps(window_queue, now, window):
    """Drop timestamps older than ``window`` seconds from the left."""
    while window_queue and (now - window_queue[0]) > window:
        window_queue.popleft()


def _prune_port_events(window_queue, now, window):
    """Drop (timestamp, port) events older than ``window`` seconds from the left."""
    while window_queue and (now - window_queue[0][0]) > window:
        window_queue.popleft()


def reset_trackers():
    """Forget all sliding windows, the ARP baseline and the alert cooldowns."""
    port_scan_tracker.clear()
    syn_flood_tracker.clear()
    arp_table.clear()
    arp_conflict_tracker.clear()
    alert_cooldown.clear()


def _collect_garbage(now):
    """Evict idle tracker entries so memory stays flat on long captures."""
    global _last_gc
    if (now - _last_gc) < GC_INTERVAL:
        return
    _last_gc = now

    for key in list(port_scan_tracker.keys()):
        events = port_scan_tracker[key]
        if not events or (now - events[-1][0]) > PORT_SCAN_WINDOW:
            del port_scan_tracker[key]

    for key in list(syn_flood_tracker.keys()):
        events = syn_flood_tracker[key]
        if not events or (now - events[-1]) > SYN_FLOOD_WINDOW:
            del syn_flood_tracker[key]

    for key in list(arp_conflict_tracker.keys()):
        events = arp_conflict_tracker[key]
        if not events or (now - events[-1]) > ARP_CONFLICT_WINDOW:
            del arp_conflict_tracker[key]

    for key in list(alert_cooldown.keys()):
        if (now - alert_cooldown[key][0]) > COOLDOWN_RETENTION:
            del alert_cooldown[key]


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------
def trigger_real_alert(attack_type, src_ip, severity, details):
    """Log alert with smart cooldown that allows immediate escalation from Low -> Medium -> High."""
    now = time.time()
    key = (src_ip, attack_type)
    new_rank = SEVERITY_RANK.get(severity, 1)
    previous = alert_cooldown.get(key)

    if previous is not None:
        last_time, last_rank = previous
        if (now - last_time) < COOLDOWN_SECONDS and new_rank <= last_rank:
            return False

    alert_cooldown[key] = (now, new_rank)
    print(f"[!] MARSAD ALERT [{attack_type} | {severity}] from {src_ip}: {details}")

    try:
        insert_alert(attack_type, src_ip, severity, details, mode="live")
    except Exception as exc:  # database locked / disk problem: keep sniffing, retry next time
        if previous is not None:
            alert_cooldown[key] = previous
        else:
            alert_cooldown.pop(key, None)
        print(f"[x] MARSAD could not store alert: {exc}")
        return False

    sniffer_state["alerts_raised"] += 1
    return True


# --------------------------------------------------------------------------
# Packet analysis
# --------------------------------------------------------------------------
def _inspect_arp(packet, now):
    arp = packet[ARP]
    op = arp.op
    src_ip = arp.psrc
    src_mac = arp.hwsrc

    if not src_ip or src_ip == "0.0.0.0" or not src_mac:
        return
    src_mac = str(src_mac).lower()

    # Baseline discovery works from both ARP Requests (op=1) and Replies (op=2).
    if src_ip not in arp_table:
        arp_table[src_ip] = src_mac
        return

    # Only an ARP Reply that contradicts the learned mapping is a conflict.
    if op == 2 and arp_table[src_ip] != src_mac:
        old_mac = arp_table[src_ip]
        conflicts = arp_conflict_tracker[src_ip]
        conflicts.append(now)
        _prune_timestamps(conflicts, now, ARP_CONFLICT_WINDOW)
        conflict_count = len(conflicts)
        is_gateway = src_ip.endswith(".1") or src_ip.endswith(".254")

        if is_gateway or conflict_count >= 4:
            severity = "High"
            tier_label = "Critical Gateway/MitM ARP Poisoning"
        elif conflict_count >= 2:
            severity = "Medium"
            tier_label = f"Repeated ARP Conflict ({conflict_count}x/10s)"
        else:
            severity = "Low"
            tier_label = "Initial MAC Mapping Anomaly"

        details = f"{tier_label} for {src_ip}: MAC changed from {old_mac} to {src_mac}"
        trigger_real_alert("ARP Spoofing", src_ip, severity, details)


def _inspect_tcp(packet, now):
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    if not _is_pure_syn(packet[TCP].flags):
        return

    # Rule A: Port Scanning (Distinct Destination Ports in 5s)
    scan_events = port_scan_tracker[src_ip]
    scan_events.append((now, dst_port))
    _prune_port_events(scan_events, now, PORT_SCAN_WINDOW)
    unique_ports = len({port for (_, port) in scan_events})

    if unique_ports >= PORT_SCAN_LOW:
        if unique_ports >= PORT_SCAN_HIGH:
            severity = "High"
            tier_label = "Aggressive Port Sweep (>20 ports)"
            scan_events.clear()
        elif unique_ports >= PORT_SCAN_MEDIUM:
            severity = "Medium"
            tier_label = "Moderate Port Scan (13-20 ports)"
        else:
            severity = "Low"
            tier_label = "Light Reconnaissance Probe (6-12 ports)"

        details = f"{tier_label}: Probed {unique_ports} distinct TCP ports within {PORT_SCAN_WINDOW}s"
        trigger_real_alert("Port Scanning", src_ip, severity, details)

        # A Medium/High sweep already explains the SYN burst: suppress overlap.
        if unique_ports >= PORT_SCAN_MEDIUM:
            return

    # Rule B: SYN Flood (Rapid SYN Burst to Same Port in 2s)
    target_key = (src_ip, dst_port)
    flood_events = syn_flood_tracker[target_key]
    flood_events.append(now)
    _prune_timestamps(flood_events, now, SYN_FLOOD_WINDOW)
    syn_count = len(flood_events)

    if syn_count >= SYN_FLOOD_LOW:
        if syn_count >= SYN_FLOOD_HIGH:
            severity = "High"
            tier_label = "Critical DoS SYN Flood (>50 SYN/2s)"
            flood_events.clear()
        elif syn_count >= SYN_FLOOD_MEDIUM:
            severity = "Medium"
            tier_label = "Moderate SYN Flood (31-50 SYN/2s)"
        else:
            severity = "Low"
            tier_label = "Suspicious SYN Burst (15-30 SYN/2s)"

        details = f"{tier_label}: {syn_count} SYN packets to port {dst_port} within {SYN_FLOOD_WINDOW}s"
        trigger_real_alert("SYN Flood", src_ip, severity, details)


def analyze_packet(packet):
    """
    Scapy ``prn`` callback.  An exception escaping from here would terminate
    the whole capture thread, so every packet is analysed defensively.
    """
    now = time.time()
    sniffer_state["packets_inspected"] += 1

    try:
        _collect_garbage(now)

        # 1. ARP Spoofing Detection (Low / Medium / High)
        if packet.haslayer(ARP):
            _inspect_arp(packet, now)

        # 2. Port Scanning & SYN Flood Detection (Low / Medium / High)
        if packet.haslayer(IP) and packet.haslayer(TCP):
            _inspect_tcp(packet, now)
    except Exception as exc:
        sniffer_state["analysis_errors"] += 1
        sniffer_state["last_analysis_error"] = repr(exc)


# --------------------------------------------------------------------------
# Capture lifecycle
# --------------------------------------------------------------------------
def get_available_interfaces():
    ifaces = {"Default (Auto)": None}
    try:
        for iface in get_working_ifaces():
            desc = getattr(iface, "description", "")
            name = getattr(iface, "name", str(iface))
            label = f"{name} - {desc}" if desc and desc != name else name
            ifaces[label] = iface
    except Exception:
        pass
    return ifaces


def is_sniffer_active():
    inst = sniffer_state["instance"]
    return bool(inst is not None and getattr(inst, "running", False))


def stop_sniffer():
    """Stop the running capture thread (safe to call at any time)."""
    inst = sniffer_state["instance"]
    if inst is not None and getattr(inst, "running", False):
        try:
            inst.stop()
        except Exception:
            pass
    sniffer_state["instance"] = None


def _explain_capture_error(error):
    """Turn raw Scapy / OS errors into an actionable one-liner."""
    text = str(error) if str(error) else type(error).__name__
    lowered = text.lower()
    if isinstance(error, PermissionError) or "permission" in lowered or "not permitted" in lowered:
        return f"{text} - run MARSAD as Administrator (Windows) or with root privileges (Linux/macOS)."
    if "winpcap" in lowered or "npcap" in lowered or "layer 2" in lowered or "libpcap" in lowered:
        return f"{text} - install Npcap (WinPcap API-compatible mode) / libpcap and restart."
    return text


def start_or_restart_sniffer(iface_label="Default (Auto)"):
    init_db(mode="live")
    ifaces_map = get_available_interfaces()
    target_iface = ifaces_map.get(iface_label, None)
    iface_changed = iface_label != sniffer_state["current_iface"]

    stop_sniffer()
    if iface_changed:
        # A different network means a different ARP baseline: never mix them.
        reset_trackers()

    sniffer_state["error"] = None
    # Record the requested adapter even if binding fails, so the UI never
    # loops trying to restart on an adapter that cannot be opened.
    sniffer_state["current_iface"] = iface_label

    sniffer = None
    try:
        sniffer = AsyncSniffer(iface=target_iface, prn=analyze_packet, store=False)
        sniffer.start()

        deadline = time.time() + 2.0
        while time.time() < deadline and not getattr(sniffer, "running", False):
            thread = getattr(sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                break
            time.sleep(0.1)

        if getattr(sniffer, "running", False):
            sniffer_state["instance"] = sniffer
            sniffer_state["started_at"] = time.time()
        else:
            failure = getattr(sniffer, "exception", None)
            sniffer_state["instance"] = None
            sniffer_state["error"] = (
                _explain_capture_error(failure)
                if failure is not None
                else "Sniffer failed to bind to selected adapter."
            )
    except Exception as exc:
        sniffer_state["instance"] = None
        sniffer_state["error"] = _explain_capture_error(exc)
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass