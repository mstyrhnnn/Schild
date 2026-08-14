import subprocess
import shlex
from datetime import datetime
from typing import Dict, List, Optional

from schild.core.config import DefenseMode, COLORS
from schild.core.memory import SchildMemory


class ResponseAction:
    """Represents a single defensive action."""

    def __init__(
        self,
        action_type: str,   # block_ip | kill_process | isolate_service | alert | harden
        target: str,
        reason: str,
        severity: str = "medium",
        mitre_tech: str = "",
    ):
        self.action_type = action_type
        self.target = target
        self.reason = reason
        self.severity = severity
        self.mitre_tech = mitre_tech
        self.executed = False
        self.result = ""
        self.timestamp = datetime.now().isoformat()


class ResponseOrchestrator:
    """
    Autonomous defense response engine.
    Translates threat findings into defensive actions.
    """

    def __init__(self, memory: SchildMemory, defense_mode: DefenseMode):
        self.memory = memory
        self.defense_mode = defense_mode
        # DONE: TASK-11.6
        self._sidecar_registry = None   # diset dari agent via set_sidecar_registry()

    def set_sidecar_registry(self, registry) -> None:
        """
        Inject SidecarRegistry. Dipanggil dari SchildAgent setelah sidecar dikonfigurasi.
        Registry bisa None jika tidak ada sidecar yang dikonfigurasi.
        """
        # DONE: TASK-11.6
        self._sidecar_registry = registry

    # ─────────────────────────────────────────────────────────────────────────

    def respond_to_findings(self, findings: List[Dict]) -> List[ResponseAction]:
        """
        Process a list of threat findings and execute appropriate responses.
        Returns list of ResponseAction objects (executed or proposed).
        """
        if not findings:
            return []

        actions = self._plan_actions(findings)
        results = []

        print(f"\n{COLORS['hunt']}{'' * 60}{COLORS['reset']}")
        print(f"{COLORS['hunt']}  SCHILD Response Orchestrator — Mode: {self.defense_mode.value.upper()}{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'' * 60}{COLORS['reset']}\n")

        for action in actions:
            result = self._execute_action(action)
            results.append(result)

        return results

    # ─────────────────────────────────────────────────────────────────────────

    def _plan_actions(self, findings: List[Dict]) -> List[ResponseAction]:
        """Map threat findings to response actions."""
        actions = []

        for finding in findings:
            severity = finding.get("severity", "medium")
            verdict  = finding.get("verdict", "inconclusive")
            pattern  = finding.get("pattern", "")
            evidence = str(finding.get("evidence", ""))
            mitre    = finding.get("mitre", "")

            # Always log
            actions.append(ResponseAction(
                action_type="alert",
                target="memory",
                reason=f"{finding.get('description', 'Unknown threat')}: {evidence[:200]}",
                severity=severity,
                mitre_tech=mitre,
            ))

            # Extract IPs from evidence and block them (if CONTAIN/ELIMINATE)
            import re
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', evidence)
            for ip in ips:
                if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                    actions.append(ResponseAction(
                        action_type="block_ip",
                        target=ip,
                        reason=f"IOC found in: {finding.get('description', '')}",
                        severity=severity,
                        mitre_tech=mitre,
                    ))

            # Kill malicious processes in /tmp or /dev/shm
            if pattern in ("tmp_executable", "memory_only_execution"):
                pids = re.findall(r'\bpid=(\d+)\b', evidence)
                for pid in pids:
                    actions.append(ResponseAction(
                        action_type="kill_process",
                        target=pid,
                        reason=f"Suspicious executable: {evidence[:100]}",
                        severity=severity,
                        mitre_tech=mitre,
                    ))

        return actions

    # ─────────────────────────────────────────────────────────────────────────

    def _execute_action(self, action: ResponseAction) -> ResponseAction:
        """Execute or log a single response action based on defense mode."""

        if action.action_type == "alert":
            self.memory.save_alert(
                title="SCHILD Threat Response",
                message=action.reason[:500],
                severity=action.severity,
            )
            action.executed = True
            action.result = "Alert saved to memory."
            return action

        # For actions that modify the system:
        color = COLORS["critical"] if action.severity == "critical" else COLORS["warning"]
        print(f"{color}  [{action.action_type.upper()}] Target: {action.target}{COLORS['reset']}")
        print(f"{COLORS['info']}  Reason: {action.reason[:120]}{COLORS['reset']}")

        if self.defense_mode == DefenseMode.OBSERVE:
            print(f"{COLORS['info']}  → OBSERVE mode: logged only, not executed.{COLORS['reset']}")
            action.result = "OBSERVE mode: no action taken."
            return action

        if self.defense_mode == DefenseMode.HUNT:
            print(f"{COLORS['info']}  → HUNT mode: proposed action (not executed).{COLORS['reset']}")
            action.result = "HUNT mode: proposed only."
            return action

        if self.defense_mode == DefenseMode.CONTAIN:
            # Auto-execute for IP blocks, ask for kills
            if action.action_type == "block_ip":
                action.result = self._block_ip(action.target)
                action.executed = True
            elif action.action_type == "kill_process":
                conf = input(f"{COLORS['warning']}  Kill PID {action.target}? (y/n): {COLORS['reset']}").strip().lower()
                if conf == "y":
                    action.result = self._kill_process(action.target)
                    action.executed = True
                else:
                    action.result = "Denied by operator."
            elif action.action_type == "isolate_service":
                conf = input(f"{COLORS['warning']}  Isolate {action.target}? (y/n): {COLORS['reset']}").strip().lower()
                if conf == "y":
                    action.result = self._isolate_service(action.target)
                    action.executed = True
                else:
                    action.result = "Denied by operator."

        elif self.defense_mode == DefenseMode.ELIMINATE:
            # Fully autonomous
            if action.action_type == "block_ip":
                action.result = self._block_ip(action.target)
            elif action.action_type == "kill_process":
                action.result = self._kill_process(action.target)
            elif action.action_type == "isolate_service":
                action.result = self._isolate_service(action.target)
            action.executed = True

        status = f"{COLORS['success']}{COLORS['reset']}" if action.executed else f"{COLORS['warning']}⏳{COLORS['reset']}"
        print(f"  {status} Result: {action.result[:100]}")

        self.memory.save_event(
            "RESPONSE_ACTION",
            f"[{action.action_type.upper()}] target={action.target} executed={action.executed}: {action.result[:200]}",
            level="info" if action.executed else "warning",
        )

        return action

    # ─────────────────────────────────────────────────────────────────────────
    # Low-level executors
    # ─────────────────────────────────────────────────────────────────────────

    def _block_ip(self, ip: str) -> str:
        # DONE: TASK-11.6 — coba remote sidecar jika ada
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"Invalid IP: {ip}"

        results = ["[local] "]

        # Eksekusi lokal seperti sebelumnya
        try:
            result = subprocess.run(
                f"ufw deny from {shlex.quote(ip)} to any",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            results[0] += result.stdout.strip() or result.stderr.strip() or "Blocked (ufw)."
        except Exception as e:
            results[0] += f"Error: {e}"

        # Eksekusi ke semua sidecar yang terdaftar
        if self._sidecar_registry:
            for host_name in self._sidecar_registry.list_hosts():
                client = self._sidecar_registry.get(host_name)
                if client:
                    res = client.execute("block_ip", {"ip": ip})
                    status = "✓" if res.get("success") else "✗"
                    results.append(f"[sidecar:{host_name}] {status} {res.get('output','')}")

        return "\n".join(results)

    def _kill_process(self, pid: str) -> str:
        # DONE: TASK-11.6
        if not str(pid).isdigit():
            return f"Invalid PID: {pid}"

        results = []

        # Lokal
        try:
            result = subprocess.run(
                f"kill -9 {shlex.quote(str(pid))}",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            results.append(f"[local] {result.stdout.strip() or 'Process killed.'}")
        except Exception as e:
            results.append(f"[local] Error: {e}")

        # Sidecar
        if self._sidecar_registry:
            for host_name in self._sidecar_registry.list_hosts():
                client = self._sidecar_registry.get(host_name)
                if client:
                    res = client.execute("kill_process", {"pid": pid})
                    status = "✓" if res.get("success") else "✗"
                    results.append(f"[sidecar:{host_name}] {status} {res.get('output','')}")

        return "\n".join(results)

    def _isolate_service(self, service: str) -> str:
        # DONE: TASK-11.6
        whitelist = ["nginx", "apache2", "mysql", "postgresql", "mariadb", "docker", "redis"]
        if service not in whitelist:
            return f"Service '{service}' not in isolation whitelist."

        results = []

        # Lokal
        try:
            result = subprocess.run(
                f"systemctl stop {shlex.quote(service)}",
                shell=True, capture_output=True, text=True, timeout=15,
            )
            results.append(f"[local] {result.stdout.strip() or f'Service {service} stopped.'}")
        except Exception as e:
            results.append(f"[local] Error: {e}")

        # Sidecar
        if self._sidecar_registry:
            for host_name in self._sidecar_registry.list_hosts():
                client = self._sidecar_registry.get(host_name)
                if client:
                    res = client.execute("stop_service", {"service": service})
                    status = "✓" if res.get("success") else "✗"
                    results.append(f"[sidecar:{host_name}] {status} {res.get('output','')}")

        return "\n".join(results)
