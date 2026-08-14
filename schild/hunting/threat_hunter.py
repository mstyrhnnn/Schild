import subprocess
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Callable

from schild.core.config import (
    DEFAULT_HUNT_HYPOTHESES, COLORS, DefenseMode, ANALYST_TIMEOUT,
)
from schild.core.memory import SchildMemory
from schild.ai.provider import AIProviderBase, ModelTier


# ─────────────────────────────────────────────────────────────────────────────
# Evidence collector — maps hypothesis indicators to shell commands
# ─────────────────────────────────────────────────────────────────────────────

HUNT_COMMANDS: Dict[str, List[str]] = {
    "H-001": [  # Lateral Movement via SSH
        r"grep -i 'Accepted\|Failed\|Invalid' /var/log/auth.log 2>/dev/null | tail -30",
        "cat ~/.ssh/authorized_keys 2>/dev/null; find /home -name authorized_keys 2>/dev/null",
        "ss -tnp state established 2>/dev/null | grep ':22'",
    ],
    "H-002": [  # Persistence via Cron/Systemd
        "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null; ls /var/spool/cron/ 2>/dev/null",
        "systemctl list-units --type=service --state=running 2>/dev/null | grep -v 'systemd'",
        "find /etc/systemd/system /usr/local/lib/systemd/system -name '*.service' -newer /etc/passwd 2>/dev/null",
    ],
    "H-003": [  # C2 Beaconing
        "ss -tnp state established 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20",
        "lsof -i -n -P 2>/dev/null | grep -v LISTEN | head -30",
        "ps aux --no-headers 2>/dev/null | awk '{print $1,$2,$11}' | grep -vE 'systemd|kernel|bash' | head -30",
    ],
    "H-004": [  # Credential Dumping
        "ls -la /etc/shadow /etc/passwd /etc/sudoers 2>/dev/null",
        r"find / -name '*.py' -o -name '*.sh' 2>/dev/null | xargs grep -l 'shadow\|passwd\|credential' 2>/dev/null | head -10",
        r"grep -r 'SecretAccessKey\|PRIVATE KEY\|password' /tmp /var/tmp /dev/shm 2>/dev/null | head -10",
    ],
    "H-005": [  # Data Exfiltration
        "find /tmp /var/tmp /dev/shm -type f -size +1M 2>/dev/null",
        "ss -tnp state established 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -rn | head -10",
        "cat /proc/net/dev 2>/dev/null | awk 'NR>2 {print $1, \"TX:\", $10}'",
    ],
    "H-006": [  # Log Clearing
        "ls -la /var/log/ 2>/dev/null",
        "find /var/log -name '*.log' -empty 2>/dev/null",
        "cat ~/.bash_history 2>/dev/null | grep -iE 'truncate|shred|history|>/var/log' | tail -20",
    ],
    "H-007": [  # Privilege Escalation
        "find / -perm -4000 -type f 2>/dev/null | head -20",
        "sudo -l 2>/dev/null; grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null",
        "last 2>/dev/null | head -20; lastb 2>/dev/null | head -10",
    ],
    "H-008": [  # Zero-Day Exploit Behavior
        "ps auxf 2>/dev/null | head -50",
        "find /tmp /var/tmp /dev/shm -executable -type f 2>/dev/null",
        r"ls -la /proc/*/exe 2>/dev/null | grep -v '/usr\|/bin\|/lib\|/sbin\|/opt' | head -20",
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# ThreatHunter
# ─────────────────────────────────────────────────────────────────────────────

class ThreatHunter:
    """
    Proactive threat hunter using MITRE ATT&CK hypotheses.

    For each hypothesis:
      1. Collect evidence via shell commands
      2. Analyze with AI analyst model
      3. Generate verdict + MITRE mapping
      4. Persist to SchildMemory
    """

    def __init__(
        self,
        provider: AIProviderBase,
        memory: SchildMemory,
        defense_mode: DefenseMode = DefenseMode.HUNT,
        hypotheses: Optional[List[Dict]] = None,
    ):
        self.provider = provider
        self.memory = memory
        self.defense_mode = defense_mode
        self.hypotheses = hypotheses or DEFAULT_HUNT_HYPOTHESES

    # ─────────────────────────────────────────────────────────────────────────

    def hunt_all(self) -> List[Dict]:
        """Run all configured hunt hypotheses. Returns list of results."""
        print(f"\n{COLORS['hunt']}{'' * 60}{COLORS['reset']}")
        print(f"{COLORS['hunt']} SCHILD Proactive Threat Hunt — {len(self.hypotheses)} hypotheses{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'' * 60}{COLORS['reset']}\n")

        all_results = []
        for hyp in self.hypotheses:
            result = self.hunt_hypothesis(hyp)
            all_results.append(result)

        # Summary
        compromised = [r for r in all_results if r["verdict"] == "compromised"]
        suspicious  = [r for r in all_results if r["verdict"] == "suspicious"]
        clean       = [r for r in all_results if r["verdict"] == "clean"]

        print(f"\n{COLORS['hunt']}{'' * 60}{COLORS['reset']}")
        print(f"{COLORS['hunt']}📊 Hunt Summary:{COLORS['reset']}")
        print(f"{COLORS['error']}  Compromised : {len(compromised)}{COLORS['reset']}")
        print(f"{COLORS['warning']}  Suspicious  : {len(suspicious)}{COLORS['reset']}")
        print(f"{COLORS['success']}  Clean       : {len(clean)}{COLORS['reset']}")

        if compromised:
            print(f"\n{COLORS['critical']}️  CRITICAL — Active threats detected:{COLORS['reset']}")
            for r in compromised:
                print(f"{COLORS['critical']}  → {r['hypothesis']} [{r.get('mitre_tech','')}]{COLORS['reset']}")

        return all_results

    # ─────────────────────────────────────────────────────────────────────────

    def hunt_hypothesis(self, hypothesis: Dict) -> Dict:
        """Run a single hunt hypothesis. Returns result dict."""
        hid   = hypothesis.get("id", "H-???")
        name  = hypothesis.get("name", "Unknown Hunt")
        tactic = hypothesis.get("tactic", "")
        tech   = hypothesis.get("technique", "")
        desc   = hypothesis.get("description", "")

        print(f"\n{COLORS['hunt']} [{hid}] {name}{COLORS['reset']}")
        print(f"{COLORS['info']}  MITRE: {tactic} / {tech} — {desc}{COLORS['reset']}")

        # 1. Collect evidence
        evidence = self._collect_evidence(hid)

        # 2. AI analysis
        verdict, analysis, recommendations = self._analyze_evidence(
            hypothesis, evidence
        )

        # 3. Verdict display
        color = {
            "compromised": COLORS["critical"],
            "suspicious":  COLORS["warning"],
            "clean":       COLORS["success"],
        }.get(verdict, COLORS["info"])
        verdict_icon = {"compromised": "", "suspicious": "️", "clean": ""}.get(verdict, "❓")
        print(f"{color}  {verdict_icon} Verdict: {verdict.upper()}{COLORS['reset']}")
        if verdict != "clean":
            print(f"{COLORS['analysis']}  Analysis: {analysis[:300]}{COLORS['reset']}")

        # 4. Persist
        result = {
            "id": hid,
            "hypothesis": name,
            "verdict": verdict,
            "analysis": analysis,
            "recommendations": recommendations,
            "mitre_tactic": tactic,
            "mitre_tech": tech,
            "timestamp": datetime.now().isoformat(),
        }
        self.memory.save_hunt_result(
            hypothesis=name,
            findings={"evidence_summary": evidence[:500], "analysis": analysis, "recommendations": recommendations},
            verdict=verdict,
            mitre_tactic=tactic,
            mitre_tech=tech,
        )
        self.memory.save_event(
            "HUNT",
            f"[{hid}] {name} → {verdict.upper()}",
            level="warning" if verdict != "clean" else "info",
        )

        return result

    # ─────────────────────────────────────────────────────────────────────────

    def _collect_evidence(self, hypothesis_id: str) -> str:
        """Run evidence-collection commands for a given hypothesis."""
        commands = HUNT_COMMANDS.get(hypothesis_id, [])
        evidence_parts = []

        for cmd in commands:
            try:
                result = subprocess.run(
                    cmd, shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=15,
                )
                out = result.stdout.strip()
                if out:
                    evidence_parts.append(f"$ {cmd}\n{out[:500]}")
            except Exception as e:
                evidence_parts.append(f"$ {cmd}\nError: {e}")

        return "\n\n".join(evidence_parts) if evidence_parts else "(No evidence collected)"

    # ─────────────────────────────────────────────────────────────────────────

    def _analyze_evidence(
        self, hypothesis: Dict, evidence: str
    ):
        """Send evidence to AI analyst for verdict."""
        sys_prompt = """You are SCHILD, an elite threat hunter and incident responder.
Analyze the collected system evidence for the given threat hypothesis.

VERDICT OPTIONS:
- compromised: Clear evidence of active threat / attacker presence
- suspicious: Anomalies found, could be threat, needs further investigation
- clean: No indicators of compromise found for this hypothesis

Return ONLY valid JSON:
{
  "verdict": "compromised|suspicious|clean",
  "analysis": "Technical explanation of findings (2-3 sentences)",
  "iocs": ["list of specific IOCs found: IPs, hashes, filenames, etc."],
  "recommendations": ["specific action 1", "specific action 2"]
}"""

        prompt = f"""Threat Hunt Hypothesis:
ID: {hypothesis.get('id')}
Name: {hypothesis.get('name')}
MITRE: {hypothesis.get('tactic')} / {hypothesis.get('technique')}
Description: {hypothesis.get('description')}

Collected Evidence:
{evidence}

Analyze and return JSON verdict:"""

        try:
            raw = self.provider.complete(
                prompt, system_prompt=sys_prompt,
                tier=ModelTier.ANALYST, timeout=ANALYST_TIMEOUT,
            )
            # Extract JSON
            import re
            m = re.search(r"\{[\s\S]*\}", raw)
            if m:
                import json as _json
                data = _json.loads(m.group(0))
                verdict = data.get("verdict", "inconclusive")
                analysis = data.get("analysis", "")
                recommendations = data.get("recommendations", [])

                # Save IOCs to memory
                for ioc in data.get("iocs", []):
                    if ioc:
                        ioc_type = "ip" if _looks_like_ip(ioc) else "file" if "/" in ioc else "indicator"
                        self.memory.upsert_ioc(
                            ioc_type=ioc_type, value=ioc,
                            source="schild_hunt",
                            threat_name=hypothesis.get("name", ""),
                            confidence=0.7 if verdict == "compromised" else 0.4,
                            tags=[hypothesis.get("technique", "")],
                        )

                return verdict, analysis, recommendations
        except Exception as e:
            pass

        return "inconclusive", "AI analysis failed — review evidence manually.", []


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value.strip()))
