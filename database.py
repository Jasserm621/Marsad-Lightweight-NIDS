"""
MARSAD | مَــرصــــد  -  storage layer
=====================================

Two fully isolated SQLite databases back the platform:

    nids_live.db   mode="live"   alerts raised by the real packet sniffer
    nids_demo.db   mode="demo"   simulated telemetry for presentations

Both share the same academic schema (``timestamp`` is a real DATETIME column,
written as ``YYYY-MM-DD HH:MM:SS``).

The public API used by ``sniffer.py`` and ``app.py`` is unchanged:
``init_db``, ``insert_alert``, ``clear_alerts``, ``seed_random_alerts`` and
``get_db_name``.  ``fetch_alerts``, ``get_db_path`` and ``ALERT_COLUMNS`` are
new helpers so the UI no longer has to open SQLite connections by itself.
"""

import random
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

LIVE_DB = "nids_live.db"
DEMO_DB = "nids_demo.db"

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
ALERT_COLUMNS = ("id", "timestamp", "attack_type", "source_ip", "severity", "details")

# The sniffer thread writes while the Streamlit thread reads / clears.
# SQLite serialises writers anyway; the lock avoids needless "database is
# locked" retries between the two threads of this process.
_write_lock = threading.Lock()

_SCHEMA = """
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        attack_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        severity TEXT NOT NULL,
        details TEXT NOT NULL
    )
"""


# --------------------------------------------------------------------------
# Paths & connections
# --------------------------------------------------------------------------
def get_db_name(mode="live"):
    """File name of the database that belongs to ``mode``."""
    return DEMO_DB if mode == "demo" else LIVE_DB


def get_db_path(mode="live"):
    """Absolute path of the database, independent of the working directory."""
    return str(BASE_DIR / get_db_name(mode))


def _ensure_schema(conn):
    """Create the alerts table (and a timestamp index) when missing."""
    conn.execute(_SCHEMA)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")


@contextmanager
def _connect(mode="live"):
    """Open a short-lived connection that commits on success and always closes."""
    conn = sqlite3.connect(get_db_path(mode), timeout=10)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def init_db(mode="live"):
    """Initialize SQLite alert schema with DATETIME type."""
    with _write_lock:
        with _connect(mode) as conn:
            try:
                # WAL lets the dashboard read while the sniffer is writing.
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            _ensure_schema(conn)


def insert_alert(attack_type, source_ip, severity, details, mode="live", timestamp=None):
    """Insert a verified intrusion alert into SQLite storage."""
    stamp = timestamp or datetime.now().strftime(TIMESTAMP_FORMAT)
    with _write_lock:
        with _connect(mode) as conn:
            _ensure_schema(conn)
            conn.execute(
                """
                INSERT INTO alerts (timestamp, attack_type, source_ip, severity, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (stamp, attack_type, source_ip, severity, details),
            )


def fetch_alerts(mode="live", limit=None):
    """Return alerts newest-first as a list of tuples ordered like ALERT_COLUMNS."""
    query = (
        "SELECT id, timestamp, attack_type, source_ip, severity, details "
        "FROM alerts ORDER BY id DESC"
    )
    params = ()
    if limit:
        query += " LIMIT ?"
        params = (int(limit),)
    with _connect(mode) as conn:
        _ensure_schema(conn)
        return conn.execute(query, params).fetchall()


def clear_alerts(mode="live"):
    """Delete every alert of one mode and restart its event numbering at 1."""
    with _write_lock:
        with _connect(mode) as conn:
            _ensure_schema(conn)
            conn.execute("DELETE FROM alerts")
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name = 'alerts'")
            except sqlite3.OperationalError:
                pass


# --------------------------------------------------------------------------
# Demo telemetry
# --------------------------------------------------------------------------
def seed_random_alerts(count=None):
    """Generate 1 to 3 realistic alerts covering Low, Medium, and High for all 3 attacks."""
    count = count if count else random.randint(1, 3)
    attack_types = ["Port Scanning", "SYN Flood", "ARP Spoofing"]
    severities = ["Low", "Medium", "High"]

    for _ in range(count):
        attack = random.choice(attack_types)
        severity = random.choice(severities)
        random_ip = f"192.168.10.{random.randint(11, 240)}"

        if attack == "Port Scanning":
            if severity == "Low":
                ports = random.randint(6, 12)
                tier_desc = "Low reconnaissance probe (6-12 ports/5s)"
            elif severity == "Medium":
                ports = random.randint(13, 20)
                tier_desc = "Moderate service scan (13-20 ports/5s)"
            else:
                ports = random.randint(21, 65)
                tier_desc = "Aggressive port sweep (>20 ports/5s)"
            details = f"{tier_desc}: Probed {ports} distinct TCP ports within 5.0s"

        elif attack == "SYN Flood":
            port = random.choice([80, 443, 22, 8080])
            if severity == "Low":
                pkts = random.randint(15, 30)
                tier_desc = "Suspicious SYN burst (15-30 SYN/2s)"
            elif severity == "Medium":
                pkts = random.randint(31, 50)
                tier_desc = "Moderate SYN flood (31-50 SYN/2s)"
            else:
                pkts = random.randint(55, 240)
                tier_desc = "Critical DoS SYN flood (>50 SYN/2s)"
            details = f"{tier_desc}: {pkts} TCP SYN packets to port {port} within 2.0s"

        else:  # ARP Spoofing
            old_mac = f"00:50:56:c0:00:{random.randint(10, 99)}"
            new_mac = f"08:00:27:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}"
            if severity == "Low":
                target_ip = f"192.168.10.{random.randint(15, 90)}"
                details = f"Single MAC anomaly for host {target_ip}: {old_mac} -> {new_mac}"
            elif severity == "Medium":
                target_ip = f"192.168.10.{random.randint(15, 90)}"
                conflicts = random.randint(2, 3)
                details = f"Repeated ARP poisoning ({conflicts}x/10s) for {target_ip}: {old_mac} -> {new_mac}"
            else:
                target_ip = "192.168.10.1"
                details = f"Critical Gateway MitM ARP spoofing on {target_ip}: {old_mac} -> {new_mac}"

        insert_alert(attack, random_ip, severity, details, mode="demo")