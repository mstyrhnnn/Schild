"""
SCHILD Memory — Persistent storage for threat data, IOCs, and system state.

Extends guard_agent's GuardMemory with:
- IOC store (indicators of compromise)
- Threat graph (entity relationships)
- Hunt result persistence
- Baseline profile storage
"""

import sqlite3
import json
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any


class SchildMemory:
    """
    Persistent memory store for SCHILD.
    Uses SQLite for local storage; no external DB dependency.
    """

    def __init__(self, db_path: str = "schild_memory.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()  # DONE: TASK-01
        self._init_schema()

    # ─────────────────────────────────────────────────────────────────────────
    # Schema
    # ─────────────────────────────────────────────────────────────────────────

    def _init_schema(self):
        with self._lock:  # DONE: FIX-02 — consistent lock usage
            c = self._conn.cursor()

            # Events log
            c.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT    NOT NULL,
                    message    TEXT    NOT NULL,
                    level      TEXT    DEFAULT 'info',
                    hostname   TEXT,
                    timestamp  TEXT    NOT NULL
                )
            """)

            # Asset inventory snapshots
            c.execute("""
                CREATE TABLE IF NOT EXISTS asset_inventory (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    data      TEXT    NOT NULL,
                    timestamp TEXT    NOT NULL
                )
            """)

            # Vulnerability scan results
            c.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT    NOT NULL,
                    data      TEXT    NOT NULL,
                    timestamp TEXT    NOT NULL
                )
            """)

            # Alerts
            c.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    title     TEXT    NOT NULL,
                    message   TEXT    NOT NULL,
                    severity  TEXT    DEFAULT 'medium',
                    hostname  TEXT,
                    timestamp TEXT    NOT NULL
                )
            """)

            # IOC store — Indicators of Compromise
            c.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type    TEXT    NOT NULL,    -- ip | domain | hash | url | process
                    value       TEXT    NOT NULL,
                    source      TEXT,               -- virustotal | shodan | manual | schild
                    threat_name TEXT,
                    confidence  REAL    DEFAULT 0.0, -- 0.0 - 1.0
                    tags        TEXT,               -- JSON list
                    first_seen  TEXT    NOT NULL,
                    last_seen   TEXT    NOT NULL,
                    UNIQUE(ioc_type, value)
                )
            """)

            # Threat hunt results
            c.execute("""
                CREATE TABLE IF NOT EXISTS hunt_results (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    hypothesis   TEXT    NOT NULL,
                    findings     TEXT    NOT NULL,   -- JSON
                    verdict      TEXT    DEFAULT 'inconclusive', -- clean | suspicious | compromised
                    mitre_tactic TEXT,
                    mitre_tech   TEXT,
                    timestamp    TEXT    NOT NULL
                )
            """)

            # Behavioral baseline snapshots
            c.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric    TEXT    NOT NULL,      -- cpu | memory | net_conn | process_count
                    stats     TEXT    NOT NULL,      -- JSON {mean, std, min, max, samples}
                    timestamp TEXT    NOT NULL
                )
            """)

            self._conn.commit()

    # ─────────────────────────────────────────────────────────────────────────
    # Events
    # ─────────────────────────────────────────────────────────────────────────

    def save_event(self, event_type: str, message: str, level: str = "info",
                   hostname: str = "") -> int:
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO events (event_type, message, level, hostname, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (event_type, message, level, hostname, datetime.now().isoformat()),
            )
            self._conn.commit()
            return c.lastrowid

    def get_recent_summary(self, limit: int = 10) -> str:
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT timestamp, level, event_type, message FROM events "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        if not rows:
            return "No recent events."
        lines = [f"[{r[0][:19]}] [{r[1].upper()}] {r[2]}: {r[3][:100]}" for r in reversed(rows)]
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    # Assets & Scans
    # ─────────────────────────────────────────────────────────────────────────

    def save_asset_inventory(self, assets: dict):
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO asset_inventory (data, timestamp) VALUES (?, ?)",
                (json.dumps(assets), datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_latest_asset_inventory(self) -> Optional[dict]:
        c = self._conn.cursor()
        row = c.execute(
            "SELECT data FROM asset_inventory ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def save_scan_result(self, scan_type: str, data: dict):
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO scan_results (scan_type, data, timestamp) VALUES (?, ?, ?)",
                (scan_type, json.dumps(data), datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_latest_scan_result(self, scan_type: str) -> Optional[dict]:
        c = self._conn.cursor()
        row = c.execute(
            "SELECT data FROM scan_results WHERE scan_type = ? ORDER BY id DESC LIMIT 1",
            (scan_type,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def save_vulnerabilities(self, vulns: list):
        self.save_scan_result("vulnerability_assessment", {"vulnerabilities": vulns})

    # ─────────────────────────────────────────────────────────────────────────
    # Alerts
    # ─────────────────────────────────────────────────────────────────────────

    def save_alert(self, title: str, message: str, severity: str = "medium",
                   hostname: str = "") -> int:
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO alerts (title, message, severity, hostname, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (title, message, severity, hostname, datetime.now().isoformat()),
            )
            self._conn.commit()
            lastrowid = c.lastrowid
        self.save_event("ALERT", f"[{severity.upper()}] {title}: {message}", "warning", hostname)
        return lastrowid

    def get_recent_alerts(self, limit: int = 20) -> List[dict]:
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT title, message, severity, hostname, timestamp "
            "FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"title": r[0], "message": r[1], "severity": r[2],
             "hostname": r[3], "timestamp": r[4]}
            for r in rows
        ]

    # ─────────────────────────────────────────────────────────────────────────
    # IOCs
    # ─────────────────────────────────────────────────────────────────────────

    def upsert_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str = "schild",
        threat_name: str = "",
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
    ) -> int:
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            now = datetime.now().isoformat()
            tags_json = json.dumps(tags or [])
            c.execute(
                """INSERT INTO iocs (ioc_type, value, source, threat_name, confidence, tags, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, value) DO UPDATE SET
                     last_seen = ?,
                     confidence = MAX(confidence, ?),
                     source = ?,
                     threat_name = COALESCE(NULLIF(?, ''), threat_name)
                """,
                (ioc_type, value, source, threat_name, confidence, tags_json, now, now,
                 now, confidence, source, threat_name),
            )
            self._conn.commit()
            return c.lastrowid

    def lookup_ioc(self, value: str) -> Optional[dict]:
        c = self._conn.cursor()
        row = c.execute(
            "SELECT ioc_type, value, source, threat_name, confidence, tags, first_seen, last_seen "
            "FROM iocs WHERE value = ?",
            (value,),
        ).fetchone()
        if not row:
            return None
        return {
            "ioc_type": row[0], "value": row[1], "source": row[2],
            "threat_name": row[3], "confidence": row[4],
            "tags": json.loads(row[5] or "[]"),
            "first_seen": row[6], "last_seen": row[7],
        }

    def get_iocs(self, ioc_type: Optional[str] = None, limit: int = 100) -> List[dict]:
        c = self._conn.cursor()
        if ioc_type:
            rows = c.execute(
                "SELECT ioc_type, value, source, threat_name, confidence, last_seen "
                "FROM iocs WHERE ioc_type = ? ORDER BY confidence DESC LIMIT ?",
                (ioc_type, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT ioc_type, value, source, threat_name, confidence, last_seen "
                "FROM iocs ORDER BY confidence DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {"ioc_type": r[0], "value": r[1], "source": r[2],
             "threat_name": r[3], "confidence": r[4], "last_seen": r[5]}
            for r in rows
        ]

    # ─────────────────────────────────────────────────────────────────────────
    # Hunt Results
    # ─────────────────────────────────────────────────────────────────────────

    def save_hunt_result(
        self,
        hypothesis: str,
        findings: dict,
        verdict: str = "inconclusive",
        mitre_tactic: str = "",
        mitre_tech: str = "",
    ):
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO hunt_results (hypothesis, findings, verdict, mitre_tactic, mitre_tech, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (hypothesis, json.dumps(findings), verdict, mitre_tactic, mitre_tech,
                 datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_hunt_results(self, limit: int = 20) -> List[dict]:
        c = self._conn.cursor()
        rows = c.execute(
            "SELECT hypothesis, verdict, mitre_tactic, mitre_tech, timestamp "
            "FROM hunt_results ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"hypothesis": r[0], "verdict": r[1], "mitre_tactic": r[2],
             "mitre_tech": r[3], "timestamp": r[4]}
            for r in rows
        ]

    # ─────────────────────────────────────────────────────────────────────────
    # Baselines
    # ─────────────────────────────────────────────────────────────────────────

    def save_baseline(self, metric: str, stats: dict):
        with self._lock:  # DONE: TASK-01
            c = self._conn.cursor()
            c.execute(
                "INSERT INTO baselines (metric, stats, timestamp) VALUES (?, ?, ?)",
                (metric, json.dumps(stats), datetime.now().isoformat()),
            )
            self._conn.commit()

    def get_latest_baseline(self, metric: str) -> Optional[dict]:
        c = self._conn.cursor()
        row = c.execute(
            "SELECT stats FROM baselines WHERE metric = ? ORDER BY id DESC LIMIT 1",
            (metric,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    # DONE: TASK-07
    def backup(self, backup_dir: str = "schild_backups") -> str:
        """
        Create a timestamped backup of the SQLite database.
        Uses sqlite3's native backup API for consistency (safe during live writes).
        Returns the path of the created backup file.
        """
        from pathlib import Path
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = str(Path(backup_dir) / f"schild_memory_{ts}.db")
        with self._lock:
            backup_conn = sqlite3.connect(backup_path)
            self._conn.backup(backup_conn)
            backup_conn.close()
        return backup_path

    def close(self):
        self._conn.close()
