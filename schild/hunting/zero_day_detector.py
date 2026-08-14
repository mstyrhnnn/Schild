import subprocess
import re
import os
import json
from datetime import datetime
from typing import List, Dict, Optional

from schild.core.config import COLORS, ANALYST_TIMEOUT
from schild.core.memory import SchildMemory
from schild.ai.provider import AIProviderBase, ModelTier


# Behavioral patterns that commonly indicate zero-day / novel exploitation
SUSPICIOUS_PATTERNS = {
    "shell_from_service": {
        "description": "Shell spawned by service process (web server, DB, etc.)",
        "severity": "critical",
        "mitre": "T1059",
        "detect": lambda ps_tree: _detect_shell_from_service(ps_tree),
    },
    "unexpected_network_from_process": {
        "description": "Non-network process making external connections",
        "severity": "high",
        "mitre": "T1071",
        "detect": lambda net_proc: _detect_unexpected_network(net_proc),
    },
    "memory_only_execution": {
        "description": "Processes running from deleted files or /proc/mem",
        "severity": "critical",
        "mitre": "T1055",
        "detect": lambda proc: _detect_memonly_execution(proc),
    },
    "suid_abuse": {
        "description": "Non-standard SUID binary executed recently",
        "severity": "high",
        "mitre": "T1548.001",
        "detect": lambda suid: _detect_suid_abuse(suid),
    },
    "tmp_executable": {
        "description": "Executable files in /tmp, /var/tmp, /dev/shm",
        "severity": "high",
        "mitre": "T1059",
        "detect": lambda tmp: _detect_tmp_executables(tmp),
    },
}


class ZeroDayDetector:
    """
    Zero-day behavioral detector.

    Collects behavioral snapshots of the running system, applies
    pattern matching for known exploit behaviors, and uses AI to
    analyze suspicious patterns in context.
    """

    def __init__(
        self,
        provider: AIProviderBase,
        memory: SchildMemory,
    ):
        self.provider = provider
        self.memory = memory

    def scan(self) -> List[Dict]:
        """
        Run a full behavioral scan for zero-day indicators.
        Returns list of findings.
        """
        print(f"\n{COLORS['hunt']}{'' * 60}{COLORS['reset']}")
        print(f"{COLORS['hunt']}🔬 SCHILD Zero-Day Behavioral Scan{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'' * 60}{COLORS['reset']}\n")

        # Collect behavioral data
        behavioral_data = self._collect_behavioral_snapshot()

        findings = []
        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            print(f"{COLORS['info']}  Checking: {pattern['description']}...{COLORS['reset']}", end=" ")
            try:
                relevant_data = behavioral_data.get(pattern_name, "")
                detected = pattern["detect"](relevant_data)
                if detected:
                    print(f"{COLORS['warning']}️  Detected{COLORS['reset']}")
                    finding = {
                        "pattern": pattern_name,
                        "description": pattern["description"],
                        "severity": pattern["severity"],
                        "mitre": pattern["mitre"],
                        "evidence": detected,
                        "timestamp": datetime.now().isoformat(),
                    }
                    findings.append(finding)
                    self.memory.save_event(
                        "ZERO_DAY_INDICATOR",
                        f"[{pattern['severity'].upper()}] {pattern['description']}: {str(detected)[:200]}",
                        level="warning",
                    )
                else:
                    print(f"{COLORS['success']} Clean{COLORS['reset']}")
            except Exception as e:
                print(f"{COLORS['error']}Error: {e}{COLORS['reset']}")

        if findings:
            print(f"\n{COLORS['critical']}️  {len(findings)} zero-day indicators found!{COLORS['reset']}")
            self._ai_analysis(findings, behavioral_data)
        else:
            print(f"\n{COLORS['success']} No zero-day behavioral indicators detected.{COLORS['reset']}")

        return findings

    # ─────────────────────────────────────────────────────────────────────────

    def _collect_behavioral_snapshot(self) -> Dict[str, str]:
        """Collect raw behavioral data from system."""
        data = {}

        cmds = {
            "shell_from_service":       "ps auxf 2>/dev/null",
            "unexpected_network_from_process": "ss -tnp state established 2>/dev/null",
            "memory_only_execution":    "ls -la /proc/*/exe 2>/dev/null | grep -v '^l'",
            "suid_abuse":               "find / -perm -4000 -type f 2>/dev/null 2>&1 | head -30",
            "tmp_executable":           "find /tmp /var/tmp /dev/shm -executable -type f 2>/dev/null",
        }

        for key, cmd in cmds.items():
            try:
                r = subprocess.run(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=15,
                )
                data[key] = r.stdout.strip()
            except Exception:
                data[key] = ""

        return data

    # ─────────────────────────────────────────────────────────────────────────

    def _ai_analysis(self, findings: List[Dict], behavioral_data: Dict[str, str]):
        """Use AI to correlate findings and provide threat assessment."""
        findings_summary = "\n".join([
            f"- [{f['severity'].upper()}] {f['description']} (MITRE: {f['mitre']}): {f['evidence'][:200]}"
            for f in findings
        ])

        sys_prompt = """You are SCHILD, an expert in zero-day threat analysis.
Analyze these behavioral anomalies and determine:
1. Whether these represent an active attack
2. The likely attack vector and threat actor TTPs
3. Immediate containment recommendations

Be concise and technical. Focus on actionable intelligence."""

        prompt = f"""Zero-Day Behavioral Findings:
{findings_summary}

Provide:
1. Threat Assessment (1-2 sentences)
2. Likely Attack Vector
3. MITRE ATT&CK Chain
4. Immediate Actions (top 3)"""

        print(f"\n{COLORS['analysis']} AI Threat Assessment:{COLORS['reset']}")
        try:
            response = self.provider.complete(
                prompt, system_prompt=sys_prompt,
                tier=ModelTier.ANALYST, timeout=ANALYST_TIMEOUT,
            )
            print(f"{COLORS['warning']}{response}{COLORS['reset']}")
            self.memory.save_event(
                "ZERO_DAY_AI_ANALYSIS",
                response[:500],
                level="warning",
            )
        except Exception as e:
            print(f"{COLORS['error']}AI analysis failed: {e}{COLORS['reset']}")


# ─────────────────────────────────────────────────────────────────────────────
# Pattern Detectors
# ─────────────────────────────────────────────────────────────────────────────

_SERVICE_PARENTS = [
    "nginx", "apache2", "httpd", "php-fpm", "node", "python",
    "ruby", "java", "tomcat", "mysqld", "postgres", "redis",
]

def _detect_shell_from_service(ps_tree: str) -> Optional[str]:
    """Detect shell (bash/sh/zsh) spawned by a service process."""
    if not ps_tree:
        return None
    lines = ps_tree.splitlines()
    for i, line in enumerate(lines):
        is_shell = re.search(r"\b(bash|sh|zsh|dash|ksh)\b", line)
        if is_shell:
            # Look at parent (line above in tree)
            for j in range(max(0, i - 3), i):
                if any(svc in lines[j].lower() for svc in _SERVICE_PARENTS):
                    return f"Shell spawned from service: {line.strip()[:200]}"
    return None

# DONE: TASK-05 — Self-reference filter
_SELF_FILTER = frozenset([
    "schild", "openai", "anthropic", "googleapis",
    "gemini", "ollama", "127.0.0.1", "localhost",
])

def _detect_unexpected_network(net_proc: str) -> Optional[str]:
    """Detect non-network processes making connections."""
    if not net_proc:
        return None
    suspicious = []
    for line in net_proc.splitlines():
        # DONE: TASK-05 — skip SCHILD self-references
        if any(kw in line.lower() for kw in _SELF_FILTER):
            continue
        for proc in ["python", "perl", "ruby", "php", "bash", "sh ", "nc ", "ncat", "socat"]:
            if proc in line and ("ESTABLISHED" in line or ":" in line):
                suspicious.append(line.strip()[:200])
    return "\n".join(suspicious[:5]) if suspicious else None

def _detect_memonly_execution(proc_data: str) -> Optional[str]:
    """Detect processes running from deleted executables."""
    if not proc_data:
        return None
    deleted = [l for l in proc_data.splitlines() if "(deleted)" in l]
    return "\n".join(deleted[:5]) if deleted else None

def _detect_suid_abuse(suid_data: str) -> Optional[str]:
    """Detect non-standard SUID binaries."""
    if not suid_data:
        return None
    known_suid = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
        "/usr/bin/chfn", "/bin/ping", "/bin/mount", "/bin/umount",
        "/usr/bin/pkexec", "/usr/bin/crontab",
    }
    unexpected = []
    for line in suid_data.splitlines():
        parts = line.strip().split()
        if parts:
            binary = parts[-1]
            if binary not in known_suid and not binary.startswith("/snap/"):
                unexpected.append(binary)
    return "\n".join(unexpected[:10]) if unexpected else None

def _detect_tmp_executables(tmp_data: str) -> Optional[str]:
    """Detect executables in temp directories (common malware drop location)."""
    if not tmp_data:
        return None
    files = [l.strip() for l in tmp_data.splitlines() if l.strip()]
    return "\n".join(files[:10]) if files else None
