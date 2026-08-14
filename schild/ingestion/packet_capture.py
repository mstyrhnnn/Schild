"""
SCHILD Packet Capture / Port Mirroring Ingestion

Receives mirrored (SPAN) traffic from a network interface and converts
raw packets into SCHILD log events that feed into the normal ingestion
pipeline (memory, alerts, threat hunting).

Requirements:
    pip install scapy
    Run as root or with CAP_NET_RAW capability:
        sudo setcap cap_net_raw+eip $(which python3)

Architecture context:
    DMZ (DVWA / Web server / client)
        --> switch SPAN / port mirror
            --> this machine's capture interface (e.g. eth1)
                --> PacketMirrorCapture
                    --> LogIngestionManager._on_event
                        --> SchildMemory / alerts / threat hunting

Usage:
    from schild.ingestion.packet_capture import PacketMirrorCapture

    cap = PacketMirrorCapture(
        interface="eth1",           # NIC receiving mirrored traffic
        callback=ingestion._on_event,
        bpf_filter="ip",            # optional BPF filter string
        snap_len=1518,
        promisc=True,
    )
    cap.start()
    # ...
    cap.stop()
"""

import threading
from datetime import datetime
from typing import Callable, Dict, List, Optional

try:
    from scapy.all import (  # type: ignore
        AsyncSniffer,
        Packet,
        IP, IPv6,
        TCP, UDP, ICMP, ICMPv6EchoRequest,
        Raw,
        ARP,
        DNS, DNSQR, DNSRR,
        HTTPRequest, HTTPResponse,  # requires scapy[basic] or scapy-http
    )
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


# ---------------------------------------------------------------------------
# Protocol / port helpers
# ---------------------------------------------------------------------------

_TCP_PORT_NAMES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

_UDP_PORT_NAMES: Dict[int, str] = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client",
    69: "tftp", 123: "ntp", 161: "snmp", 162: "snmptrap",
    514: "syslog", 5140: "schild-syslog",
}

_HIGH_RISK_PORTS = frozenset({
    21, 22, 23, 25, 53, 445, 3389,       # common attack surfaces
    4444, 4445, 5555, 6666, 1337, 31337,  # common reverse shell ports
})

_SUSPICIOUS_PAYLOADS = [
    b"/bin/sh", b"/bin/bash", b"cmd.exe",
    b"wget ", b"curl ", b"chmod ", b"base64",
    b"eval(", b"exec(", b"system(",
    b"SELECT ", b"UNION ", b"DROP TABLE",  # SQLi patterns
    b"<script", b"javascript:", b"onerror=",  # XSS patterns
]


def _service_name(proto: str, port: int) -> str:
    if proto == "tcp":
        return _TCP_PORT_NAMES.get(port, f"tcp/{port}")
    if proto == "udp":
        return _UDP_PORT_NAMES.get(port, f"udp/{port}")
    return proto


def _check_payload(payload: bytes) -> Optional[str]:
    """Returns a suspicious pattern string if found in payload, else None."""
    payload_lower = payload.lower()
    for pattern in _SUSPICIOUS_PAYLOADS:
        if pattern.lower() in payload_lower:
            return pattern.decode("utf-8", errors="replace")
    return None


# ---------------------------------------------------------------------------
# Core Capture Class
# ---------------------------------------------------------------------------

class PacketMirrorCapture:
    """
    Passively captures packets arriving on a mirrored (SPAN) interface
    and converts them to SCHILD log events.

    Parameters
    ----------
    interface : str
        Network interface name receiving the mirrored traffic (e.g. "eth1").
        Must be set to promiscuous mode or this class will do it automatically.
    callback : Callable[[dict], None]
        Function to receive parsed packet events.  Typically
        LogIngestionManager._on_event.
    bpf_filter : str
        BPF (Berkeley Packet Filter) expression to pre-filter captured traffic.
        Examples:
            "ip"                     — IPv4 only
            "tcp port 80"            — HTTP only
            "not port 22"            — exclude SSH
            "host 192.168.1.0/24"   — specific subnet
        Default: "" (capture everything)
    snap_len : int
        Maximum bytes to capture per packet (default 1518 = standard Ethernet MTU).
    promisc : bool
        Enable promiscuous mode on the interface (required for mirrored traffic).
    max_payload_bytes : int
        How many bytes of raw payload to inspect for suspicious patterns.
    """

    def __init__(
        self,
        interface: str,
        callback: Callable[[dict], None],
        bpf_filter: str = "",
        snap_len: int = 1518,
        promisc: bool = True,
        max_payload_bytes: int = 512,
    ):
        if not _HAS_SCAPY:
            raise ImportError(
                "scapy is required for port mirroring capture.\n"
                "Install with: pip install scapy"
            )

        self.interface = interface
        self.callback = callback
        self.bpf_filter = bpf_filter
        self.snap_len = snap_len
        self.promisc = promisc
        self.max_payload_bytes = max_payload_bytes

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._lock = threading.Lock()

        # Live statistics
        self.stats: Dict[str, int] = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "other": 0,
            "suspicious": 0,
            "alerts_fired": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Start background packet capture on the configured interface."""
        with self._lock:
            if self._running:
                return
            kwargs = dict(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                promisc=self.promisc,
            )
            if self.bpf_filter:
                kwargs["filter"] = self.bpf_filter

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self._running = True
            print(
                f"  [PacketMirrorCapture] listening on {self.interface}"
                + (f" (filter: {self.bpf_filter})" if self.bpf_filter else "")
            )

    def stop(self):
        """Stop the background capture."""
        with self._lock:
            if not self._running:
                return
            if self._sniffer:
                self._sniffer.stop()
                self._sniffer = None
            self._running = False
            print(
                f"  [PacketMirrorCapture] stopped."
                f" Total captured: {self.stats['total']}"
                f" | Suspicious: {self.stats['suspicious']}"
            )

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)

    # ------------------------------------------------------------------
    # Packet Processing
    # ------------------------------------------------------------------

    def _process_packet(self, pkt: "Packet"):
        """Scapy callback — called for every captured packet."""
        self.stats["total"] += 1
        try:
            event = self._parse_packet(pkt)
            if event:
                self.callback(event)
        except Exception:
            pass  # never crash the capture thread

    def _parse_packet(self, pkt: "Packet") -> Optional[dict]:
        """
        Extract a normalized event dict from a raw packet.
        Returns None for packets we intentionally ignore (e.g. plain ARP replies).
        """
        ts = datetime.now().isoformat()
        event: Dict = {
            "hostname":  "mirror",
            "process":   "packet_capture",
            "severity":  "info",
            "timestamp": ts,
            "message":   "",
            # Extended fields (not required by LogIngestionManager)
            "src_ip":    None,
            "dst_ip":    None,
            "src_port":  None,
            "dst_port":  None,
            "proto":     "unknown",
            "service":   "unknown",
            "flags":     [],
            "payload_snippet": "",
            "suspicious_pattern": None,
        }

        # ── ARP ───────────────────────────────────────────────────────
        if ARP in pkt:
            self.stats["arp"] += 1
            arp = pkt[ARP]
            op = "who-has" if arp.op == 1 else "is-at"
            event["proto"] = "arp"
            event["service"] = "arp"
            event["src_ip"] = arp.psrc
            event["dst_ip"] = arp.pdst
            event["message"] = (
                f"ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}"
            )
            # ARP spoofing: unsolicited reply
            if arp.op == 2:
                event["severity"] = "warning"
                event["message"] += " [unsolicited ARP reply — possible spoofing]"
                self.stats["suspicious"] += 1
                event["suspicious_pattern"] = "arp_spoof"
            return event

        # ── IPv4 ──────────────────────────────────────────────────────
        if IP in pkt:
            ip = pkt[IP]
            event["src_ip"] = ip.src
            event["dst_ip"] = ip.dst
            return self._parse_ip_payload(pkt, ip, event)

        # ── IPv6 ──────────────────────────────────────────────────────
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            event["src_ip"] = ip6.src
            event["dst_ip"] = ip6.dst
            return self._parse_ip_payload(pkt, ip6, event)

        # ── Unknown / non-IP ──────────────────────────────────────────
        self.stats["other"] += 1
        return None  # skip

    def _parse_ip_payload(self, pkt: "Packet", ip, event: dict) -> dict:
        """Dispatch to TCP / UDP / ICMP parsers."""
        # ── TCP ───────────────────────────────────────────────────────
        if TCP in pkt:
            self.stats["tcp"] += 1
            tcp = pkt[TCP]
            event["proto"] = "tcp"
            event["src_port"] = tcp.sport
            event["dst_port"] = tcp.dport
            event["service"] = _service_name("tcp", tcp.dport)
            flags = self._tcp_flags(tcp.flags)
            event["flags"] = flags

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            snippet = payload[: self.max_payload_bytes]

            suspicious = _check_payload(snippet)
            if suspicious:
                self.stats["suspicious"] += 1
                event["severity"] = "error"
                event["suspicious_pattern"] = suspicious
                event["payload_snippet"] = snippet.decode("utf-8", errors="replace")

            # High-risk destination port
            if tcp.dport in _HIGH_RISK_PORTS and event["severity"] == "info":
                event["severity"] = "warning"

            event["message"] = (
                f"TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                f" [{','.join(flags)}] svc={event['service']}"
                + (f" SUSPICIOUS:{suspicious}" if suspicious else "")
            )
            return event

        # ── UDP ───────────────────────────────────────────────────────
        if UDP in pkt:
            self.stats["udp"] += 1
            udp = pkt[UDP]
            event["proto"] = "udp"
            event["src_port"] = udp.sport
            event["dst_port"] = udp.dport
            event["service"] = _service_name("udp", udp.dport)

            # Parse DNS queries/responses
            if DNS in pkt:
                dns_info = self._parse_dns(pkt[DNS])
                event["message"] = (
                    f"DNS {ip.src} -> {ip.dst}: {dns_info}"
                )
                return event

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            suspicious = _check_payload(payload[: self.max_payload_bytes])
            if suspicious:
                self.stats["suspicious"] += 1
                event["severity"] = "error"
                event["suspicious_pattern"] = suspicious

            event["message"] = (
                f"UDP {ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
                f" svc={event['service']}"
                + (f" SUSPICIOUS:{suspicious}" if suspicious else "")
            )
            return event

        # ── ICMP ──────────────────────────────────────────────────────
        if ICMP in pkt:
            self.stats["icmp"] += 1
            icmp = pkt[ICMP]
            event["proto"] = "icmp"
            event["service"] = "icmp"
            type_names = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request",
                          11: "time-exceeded", 5: "redirect"}
            type_str = type_names.get(icmp.type, f"type{icmp.type}")
            event["message"] = (
                f"ICMP {ip.src} -> {ip.dst} [{type_str}]"
            )
            # ICMP redirect can indicate MITM
            if icmp.type == 5:
                event["severity"] = "warning"
                event["suspicious_pattern"] = "icmp_redirect"
                self.stats["suspicious"] += 1
            return event

        # ── Other IP protocol ─────────────────────────────────────────
        self.stats["other"] += 1
        proto_num = getattr(ip, "proto", "?")
        event["message"] = f"IP proto={proto_num} {ip.src} -> {ip.dst}"
        return event

    @staticmethod
    def _tcp_flags(flags_int: int) -> List[str]:
        """Decode TCP flags integer to list of flag names."""
        flag_map = {
            0x001: "FIN", 0x002: "SYN", 0x004: "RST",
            0x008: "PSH", 0x010: "ACK", 0x020: "URG",
            0x040: "ECE", 0x080: "CWR",
        }
        return [name for bit, name in flag_map.items() if flags_int & bit]

    @staticmethod
    def _parse_dns(dns) -> str:
        """Extract a human-readable summary from a DNS packet."""
        try:
            if dns.qr == 0:  # Query
                qname = dns.qd.qname.decode("utf-8", errors="replace") if dns.qd else "?"
                return f"query {qname}"
            else:  # Response
                answers = []
                ans = dns.an
                while ans:
                    if hasattr(ans, "rdata"):
                        answers.append(str(ans.rdata))
                    ans = ans.payload if hasattr(ans, "payload") else None
                return f"response [{', '.join(answers[:3])}]"
        except Exception:
            return "dns (parse error)"
