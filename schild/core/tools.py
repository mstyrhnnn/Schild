import subprocess
import logging
import json
import os
import shlex
import hashlib
import requests
from typing import Dict, Optional, Any
from abc import ABC, abstractmethod

try:
    from duckduckgo_search import DDGS  # type: ignore
    HAS_DDG = True
except ImportError:
    HAS_DDG = False

try:
    from bs4 import BeautifulSoup  # type: ignore
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

from schild.core.config import (
    VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY,
    TOOL_TIMEOUT, COLORS,
)
from schild.utils.executor import is_dangerous_command  # DONE: TASK-03

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Base Tool
# ─────────────────────────────────────────────────────────────────────────────

class Tool(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(self, *args, **kwargs) -> str:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Shell Tool
# ─────────────────────────────────────────────────────────────────────────────

class ShellTool(Tool):
    """Safe shell command execution for investigation (read-preferred)."""

    def __init__(self):
        super().__init__(
            "shell_tool",
            "Execute a Linux shell command for investigation. Args: command (str)"
        )

    def execute(self, command: str = None, cmd: str = None, **kwargs) -> str:
        final = command or cmd or kwargs.get("command") or kwargs.get("cmd")
        if not final:
            return "Error: Missing 'command' argument."

        # DONE: TASK-03 — use regex-based check
        if is_dangerous_command(final):
            return f"Error: Blocked — contains dangerous pattern."

        try:
            result = subprocess.run(
                final, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=TOOL_TIMEOUT,
            )
            out = result.stdout if result.returncode == 0 else result.stderr
            if not out.strip():
                return "(Command completed with no output)"

            # Smart tail for large output
            if len(out) > 4000:
                return f"{out[:800]}\n\n... [Truncated — {len(out)} bytes total] ...\n\n{out[-2000:]}"
            return out
        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {TOOL_TIMEOUT}s."
        except Exception as e:
            return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Tool
# ─────────────────────────────────────────────────────────────────────────────

class RemediationTool(Tool):
    """Apply active defense actions (block, isolate, kill)."""

    # Removed old dangerous block list array, now handled by is_dangerous_command

    def __init__(self):
        super().__init__(
            "remediation_tool",
            "Apply active defense. Args: action (block_ip|kill_process|isolate_service), target (ip|pid|service)"
        )

    def execute(self, action: str = None, target: str = None,
                command: str = None, cmd: str = None, **kwargs) -> str:
        if command or cmd:
            return self._run(command or cmd)

        if not action or not target:
            return "Error: Requires action (block_ip|kill_process|isolate_service) and target."

        if action == "block_ip":
            return self._block_ip(target)
        elif action == "kill_process":
            return self._kill_process(target)
        elif action == "isolate_service":
            return self._isolate_service(target)
        return f"Error: Unknown action '{action}'."

    def _block_ip(self, ip: str) -> str:
        import ipaddress
        if ip.startswith(("127.", "10.", "192.168.")):
            return f"Error: Refusing to block private/local IP {ip}."
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"Error: Invalid IP address '{ip}'."
        return self._run(f"ufw deny from {shlex.quote(ip)} to any")

    def _kill_process(self, pid: str) -> str:
        if not str(pid).isdigit():
            return "Error: Target must be a numeric PID."
        return self._run(f"kill -9 {shlex.quote(str(pid))}")

    def _isolate_service(self, service: str) -> str:
        whitelist = ["nginx", "apache2", "mysql", "postgresql", "mariadb", "docker", "redis"]
        if service not in whitelist:
            return f"Error: Service '{service}' not in whitelist {whitelist}."
        return self._run(f"systemctl stop {shlex.quote(service)}")

    # DONE: FIX-01
    def _run(self, cmd: str) -> str:
        # FIX-01 — gunakan regex guard yang sama dengan ShellTool
        if is_dangerous_command(cmd):
            logger.warning(f"SCHILD REMEDIATION BLOCKED (dangerous pattern): {cmd[:100]}")
            return "Error: Blocked — command matches dangerous pattern."
        logger.info(f"SCHILD REMEDIATION: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=60,
            )
            out = result.stdout if result.returncode == 0 else result.stderr
            return out.strip() or "(Remediation applied — no output)"
        except Exception as e:
            return f"Error: {e}"



# ─────────────────────────────────────────────────────────────────────────────
# Sidecar Tool — Remote Host Mitigation
# ─────────────────────────────────────────────────────────────────────────────

class SidecarTool(Tool):
    """
    Execute mitigation actions on a remote host via SCHILD sidecar agent.
    The sidecar must be running on the target host (see schild/sidecar/server.py).

    Actions: block_ip, unblock_ip, kill_process, stop_service, restart_service, get_status
    """

    # DONE: TASK-11.5

    def __init__(self, sidecar_url: str, secret: str, host_name: str = "remote"):
        """
        Args:
            sidecar_url: URL sidecar server, misal "http://10.0.0.5:8421"
            secret:      Shared secret (SCHILD_SIDECAR_SECRET)
            host_name:   Label untuk logging, misal "dvwa", "webserver-1"
        """
        super().__init__(
            name=f"sidecar_{host_name}",
            description=(
                f"Execute mitigation on remote host '{host_name}' via SCHILD sidecar. "
                f"Args: action (block_ip|unblock_ip|kill_process|stop_service|restart_service|get_status), "
                f"params (dict). "
                f"Example: action='block_ip', params={{'ip':'1.2.3.4'}}"
            ),
        )
        self.host_name = host_name

        # Lazy import agar tidak crash jika sidecar module belum terinstall
        try:
            from schild.sidecar.client import SidecarClient
            self._client = SidecarClient(base_url=sidecar_url, secret=secret)
        except ImportError as e:
            self._client = None
            logger.warning(f"SidecarTool: could not import client — {e}")

    def execute(
        self,
        action: str = "get_status",
        params: dict = None,
        # Terima variasi nama argument dari AI
        target: str = None,
        ip: str = None,
        pid: str = None,
        service: str = None,
        **kwargs,
    ) -> str:
        if self._client is None:
            return "Error: SidecarTool client not initialized (check import errors)."

        # Normalisasi params dari berbagai format yang mungkin dikirim AI
        if params is None:
            params = {}
        if ip:
            params["ip"] = ip
        if pid:
            params["pid"] = pid
        if service:
            params["service"] = service
        if target and not params:
            # Coba deteksi tipe target otomatis
            import re, ipaddress
            try:
                ipaddress.ip_address(target)
                params["ip"] = target
            except ValueError:
                if target.isdigit():
                    params["pid"] = target
                else:
                    params["service"] = target

        logger.info(f"SidecarTool [{self.host_name}] action={action} params={params}")
        result = self._client.execute(action=action, params=params)

        status = "✓" if result.get("success") else "✗"
        return (
            f"[Sidecar: {self.host_name}] {status} {action}\n"
            f"Output: {result.get('output', '(no output)')}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Web Search Tool
# ─────────────────────────────────────────────────────────────────────────────

class WebSearchTool(Tool):
    def __init__(self):
        super().__init__(
            "web_search",
            "Search the internet for CVEs, techniques, or threat info. Args: query (str)"
        )

    def execute(self, query: str) -> str:
        if not HAS_DDG:
            return "Error: duckduckgo-search not installed."
        try:
            results = DDGS().text(query, max_results=5)
            if not results:
                return "No results found."
            lines = []
            for i, r in enumerate(results, 1):
                lines.append(f"{i}. {r.get('title','')}\n   {r.get('href','')}\n   {r.get('body','')[:200]}\n")
            return "\n".join(lines)
        except Exception as e:
            return f"Search error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Threat Intel Tool (VirusTotal + AbuseIPDB)
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelTool(Tool):
    """
    IOC enrichment via external threat intelligence APIs.
    Supports: VirusTotal (IP/hash/domain), AbuseIPDB (IP reputation).
    """

    def __init__(self):
        super().__init__(
            "threat_intel",
            "Lookup an IP, domain, or file hash in threat intel APIs. "
            "Args: ioc_type (ip|hash|domain), value (str)"
        )

    def execute(self, ioc_type: str, value: str) -> str:
        results = []

        if ioc_type == "ip":
            vt = self._virustotal_ip(value)
            abuse = self._abuseipdb(value)
            if vt:
                results.append(f"[VirusTotal] {vt}")
            if abuse:
                results.append(f"[AbuseIPDB] {abuse}")

        elif ioc_type == "hash":
            vt = self._virustotal_hash(value)
            if vt:
                results.append(f"[VirusTotal] {vt}")

        elif ioc_type == "domain":
            vt = self._virustotal_domain(value)
            if vt:
                results.append(f"[VirusTotal] {vt}")

        else:
            return f"Error: Unknown ioc_type '{ioc_type}'. Use: ip | hash | domain"

        return "\n".join(results) if results else "No threat intel API keys configured. Set VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY."

    def _virustotal_ip(self, ip: str) -> Optional[str]:
        if not VIRUSTOTAL_API_KEY:
            return None
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                reputation = data.get("reputation", "N/A")
                country = data.get("country", "N/A")
                return (
                    f"IP: {ip} | Country: {country} | Reputation: {reputation} | "
                    f"Malicious detections: {malicious}/{total}"
                )
        except Exception as e:
            return f"VT error: {e}"
        return None

    def _virustotal_hash(self, hash_val: str) -> Optional[str]:
        if not VIRUSTOTAL_API_KEY:
            return None
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{hash_val}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                name = data.get("meaningful_name", "Unknown")
                return f"File: {name} | Hash: {hash_val[:16]}... | Malicious: {malicious}/{total}"
        except Exception as e:
            return f"VT error: {e}"
        return None

    def _virustotal_domain(self, domain: str) -> Optional[str]:
        if not VIRUSTOTAL_API_KEY:
            return None
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                cats = list((data.get("categories") or {}).values())[:3]
                return f"Domain: {domain} | Malicious: {malicious}/{total} | Categories: {cats}"
        except Exception as e:
            return f"VT error: {e}"
        return None

    def _abuseipdb(self, ip: str) -> Optional[str]:
        if not ABUSEIPDB_API_KEY:
            return None
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "N/A")
                isp = data.get("isp", "N/A")
                return (
                    f"IP: {ip} | Country: {country} | ISP: {isp} | "
                    f"Abuse Score: {score}% | Reports: {reports}"
                )
        except Exception as e:
            return f"AbuseIPDB error: {e}"
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Network Forensic Tool
# ─────────────────────────────────────────────────────────────────────────────

class NetworkForensicTool(Tool):
    """Deep network inspection for threat hunting."""

    def __init__(self):
        super().__init__(
            "network_forensic",
            "Deep network inspection. Args: action (connections|listeners|dns_cache|arp_table|traffic_summary)"
        )

    def execute(self, action: str = "connections") -> str:
        cmds = {
            "connections": "ss -tnp state established 2>/dev/null | head -40",
            "listeners":   "ss -tlnp 2>/dev/null",
            "dns_cache":   "systemd-resolve --statistics 2>/dev/null || cat /etc/hosts",
            "arp_table":   "arp -n 2>/dev/null || ip neigh show 2>/dev/null",
            "traffic_summary": (
                "ss -s 2>/dev/null; echo '---'; "
                "cat /proc/net/dev 2>/dev/null | awk 'NR>2 {print $1, \"rx:\", $2, \"tx:\", $10}'"
            ),
            "routing":     "ip route show 2>/dev/null",
        }
        cmd = cmds.get(action)
        if not cmd:
            return f"Error: Unknown action '{action}'. Options: {list(cmds.keys())}"
        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=TOOL_TIMEOUT,
            )
            return result.stdout.strip() or "(No output)"
        except Exception as e:
            return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# File Forensic Tool
# ─────────────────────────────────────────────────────────────────────────────

class FileForensicTool(Tool):
    """File integrity checks and malware indicators."""

    def __init__(self):
        super().__init__(
            "file_forensic",
            "File forensics. Args: action (suid_scan|world_writable|recent_modified|hash_file|hidden_files), "
            "path (optional, default=/)"
        )

    def execute(self, action: str = "suid_scan", path: str = "/", target: str = None) -> str:
        target = target or path

        if action == "suid_scan":
            cmd = f"find {shlex.quote(target)} -perm -4000 -type f 2>/dev/null | head -30"
        elif action == "world_writable":
            cmd = f"find {shlex.quote(target)} -perm -0002 -not -type l 2>/dev/null | head -30"
        elif action == "recent_modified":
            cmd = f"find {shlex.quote(target)} -mtime -1 -type f 2>/dev/null | grep -v proc | head -40"
        elif action == "hidden_files":
            cmd = (
                f"find {shlex.quote(target)} -name '.*' -type f 2>/dev/null | "
                "grep -v '.git' | head -40"
            )
        elif action == "hash_file":
            if not os.path.isfile(target):
                return f"Error: File not found: {target}"
            cmd = f"sha256sum {shlex.quote(target)}"
        else:
            return f"Error: Unknown action '{action}'."

        try:
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=TOOL_TIMEOUT,
            )
            return result.stdout.strip() or "(No results — this may mean the system is clean)"
        except Exception as e:
            return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Web Scraper Tool
# ─────────────────────────────────────────────────────────────────────────────

class WebScraperTool(Tool):
    def __init__(self):
        super().__init__(
            "web_scraper",
            "Scrape text from a URL. Args: url (str)"
        )

    def execute(self, url: str) -> str:
        if not HAS_BS4:
            return "Error: beautifulsoup4 not installed."
        try:
            headers = {"User-Agent": "Mozilla/5.0 (SCHILD Security Scanner)"}
            r = requests.get(url, headers=headers, timeout=15)
            r.raise_for_status()
            soup = BeautifulSoup(r.content, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            text = " ".join(soup.get_text(separator="\n").split())
            return text[:3000] + "..." if len(text) > 3000 else text
        except Exception as e:
            return f"Error scraping {url}: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool Registry
# ─────────────────────────────────────────────────────────────────────────────

class ToolRegistry:
    """Registry to manage and retrieve SCHILD tools."""

    def __init__(self):
        self.tools: Dict[str, Tool] = {}
        self._register_defaults()

    def _register_defaults(self):
        for tool in [
            ShellTool(),
            RemediationTool(),
            WebSearchTool(),
            WebScraperTool(),
            ThreatIntelTool(),
            NetworkForensicTool(),
            FileForensicTool(),
        ]:
            self.register(tool)

    def register(self, tool: Tool):
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Tool]:
        return self.tools.get(name)

    def list_tools(self) -> str:
        return "\n".join(
            f"  - {t.name}: {t.description}" for t in self.tools.values()
        )
