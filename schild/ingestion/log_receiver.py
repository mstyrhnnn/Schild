"""
SCHILD Log Ingestion Layer

Provides:
  - SyslogReceiver    — UDP syslog server (RFC 3164)
  - LogFileWatcher    — Tails log files using watchdog
  - LogIngestionManager — Orchestrates all ingestion sources

DONE: TASK-08
"""

import os
import re
import socket
import threading
from datetime import datetime
from typing import Callable, Optional, Dict, List

try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from schild.ingestion.packet_capture import PacketMirrorCapture
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from schild.core.memory import SchildMemory


# ─────────────────────────────────────────────────────────────────────────────
# RFC 3164 Syslog Receiver
# ─────────────────────────────────────────────────────────────────────────────

# Syslog severity mapping (RFC 5424 §6.2.1)
_SYSLOG_SEVERITY = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# RFC 3164 pattern: <priority>timestamp hostname process: message
_RFC3164_RE = re.compile(
    r"<(\d{1,3})>"                     # priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                        # hostname
    r"(\S+?):\s+"                      # process
    r"(.*)",                           # message
)


class SyslogReceiver:
    """
    UDP syslog server that parses RFC 3164 messages and
    routes them to a callback.
    """

    def __init__(
        self,
        callback: Callable[[dict], None],
        host: str = "0.0.0.0",
        port: int = 5140,
    ):
        self.callback = callback
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)  # allow periodic stop checks
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        print(f"  Syslog receiver listening on {self.host}:{self.port}")

    def stop(self):
        self._stop_event.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=3)

    def _listen(self):
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
                line = data.decode("utf-8", errors="replace").strip()
                event = self._parse(line)
                if event:
                    self.callback(event)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue

    @staticmethod
    def _parse(line: str) -> Optional[dict]:
        m = _RFC3164_RE.match(line)
        if not m:
            # Fallback: treat as raw message
            return {
                "hostname": "unknown",
                "process": "syslog",
                "message": line,
                "severity": "info",
                "timestamp": datetime.now().isoformat(),
            }
        priority = int(m.group(1))
        severity = _SYSLOG_SEVERITY.get(priority % 8, "info")
        return {
            "hostname": m.group(3),
            "process": m.group(4),
            "message": m.group(5),
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Log File Watcher
# ─────────────────────────────────────────────────────────────────────────────

# Apache Combined Log Format regex
_APACHE_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+"       # IP
    r"\S+\s+\S+\s+"                   # ident, authuser
    r"\[.*?\]\s+"                     # timestamp
    r'"(\w+)\s+(\S+)\s+\S+"\s+'      # method, path
    r"(\d{3})\s+"                     # status
    r"(\S+)"                          # size
)


class _LogFileHandler(FileSystemEventHandler):
    """Watchdog handler that tails a specific file on modification."""

    def __init__(self, log_path: str, callback: Callable[[dict], None]):
        super().__init__()
        self.log_path = os.path.abspath(log_path)
        self.callback = callback
        self._position = self._get_file_size()

    def _get_file_size(self) -> int:
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def on_modified(self, event):
        if os.path.abspath(event.src_path) != self.log_path:
            return
        try:
            with open(self.log_path, "r", errors="replace") as f:
                f.seek(self._position)
                new_lines = f.readlines()
                self._position = f.tell()
            for line in new_lines:
                line = line.strip()
                if not line:
                    continue
                event_data = self._parse_line(line)
                if event_data:
                    self.callback(event_data)
        except Exception:
            pass

    def _parse_line(self, line: str) -> Optional[dict]:
        """Try Apache Combined format first, then generic fallback."""
        m = _APACHE_RE.match(line)
        if m:
            status = int(m.group(4))
            return {
                "hostname": "logfile",
                "process": "apache",
                "message": f"{m.group(2)} {m.group(3)} {m.group(4)}",
                "severity": "warning" if status >= 400 else "info",
                "ip": m.group(1),
                "method": m.group(2),
                "path": m.group(3),
                "status": status,
                "timestamp": datetime.now().isoformat(),
            }
        # Generic fallback
        return {
            "hostname": "logfile",
            "process": "logwatcher",
            "message": line[:500],
            "severity": "info",
            "timestamp": datetime.now().isoformat(),
        }


class LogFileWatcher:
    """Watches a single log file for new lines using watchdog."""

    def __init__(self, log_path: str, callback: Callable[[dict], None]):
        self.log_path = os.path.abspath(log_path)
        self.callback = callback
        self._observer: Optional[object] = None
        self._handler: Optional[_LogFileHandler] = None

    def start(self):
        if not HAS_WATCHDOG:
            print(f"  Warning: watchdog not installed, cannot watch {self.log_path}")
            return
        watch_dir = os.path.dirname(self.log_path) or "."
        self._handler = _LogFileHandler(self.log_path, self.callback)
        self._observer = Observer()
        self._observer.schedule(self._handler, watch_dir, recursive=False)
        self._observer.daemon = True
        self._observer.start()
        print(f"  Watching log file: {self.log_path}")

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)


# ─────────────────────────────────────────────────────────────────────────────
# Log Ingestion Manager
# ─────────────────────────────────────────────────────────────────────────────

class LogIngestionManager:
    """
    Orchestrates all log ingestion sources.
    Routes incoming events to SchildMemory and optionally raises alerts.
    """

    _ALERT_SEVERITIES = frozenset(["error", "critical", "emergency", "alert"])

    def __init__(
        self,
        memory: SchildMemory,
        alert_callback: Optional[Callable] = None,
    ):
        self.memory = memory
        self.alert_callback = alert_callback
        self._watchers: List[LogFileWatcher] = []
        self._syslog: Optional[SyslogReceiver] = None
        self._mirror_captures: List["PacketMirrorCapture"] = []

    def add_file_watcher(self, log_path: str):
        watcher = LogFileWatcher(log_path, self._on_event)
        watcher.start()
        self._watchers.append(watcher)

    def start_syslog(self, host: str = "0.0.0.0", port: int = 5140):
        self._syslog = SyslogReceiver(
            callback=self._on_event,
            host=host,
            port=port,
        )
        self._syslog.start()

    def start_port_mirror(
        self,
        interface: str,
        bpf_filter: str = "",
        promisc: bool = True,
    ) -> "PacketMirrorCapture":
        """
        Start passive packet capture on a SPAN/mirrored interface.

        Parameters
        ----------
        interface : str
            Network interface receiving mirrored traffic (e.g. "eth1").
        bpf_filter : str
            Optional BPF filter string, e.g. "tcp port 80" or "not port 22".
        promisc : bool
            Enable promiscuous mode (required for mirrored traffic).

        Returns
        -------
        PacketMirrorCapture
            The running capture instance (can be used to call stop() or get_stats()).

        Raises
        ------
        ImportError
            If scapy is not installed.
        """
        if not HAS_SCAPY:
            raise ImportError(
                "scapy is required for port mirroring.\n"
                "Install with: pip install scapy"
            )
        cap = PacketMirrorCapture(
            interface=interface,
            callback=self._on_event,
            bpf_filter=bpf_filter,
            promisc=promisc,
        )
        cap.start()
        self._mirror_captures.append(cap)
        return cap

    def stop_all(self):
        for w in self._watchers:
            w.stop()
        self._watchers.clear()
        if self._syslog:
            self._syslog.stop()
            self._syslog = None
        for cap in self._mirror_captures:
            cap.stop()
        self._mirror_captures.clear()

    def _on_event(self, event: dict):
        """Route an ingested event to memory and optionally fire an alert."""
        event_type = event.get("process", "ingestion").upper()
        message = event.get("message", "")
        level = event.get("severity", "info")
        hostname = event.get("hostname", "unknown")

        self.memory.save_event(event_type, message, level=level, hostname=hostname)

        if level in self._ALERT_SEVERITIES and self.alert_callback:
            self.alert_callback(
                title=f"Ingested {level.upper()} from {hostname}",
                message=message[:300],
                severity=level,
            )
