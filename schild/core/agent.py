

import os
import subprocess
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Callable

# Load .env if available
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except ImportError:
    pass

from schild.core.config import (
    DefenseMode, DEFAULT_DEFENSE_MODE, COLORS,
    DEFAULT_DB_PATH, DEFAULT_AI_PROVIDER, AIProvider,
    MAX_HUNT_STEPS, ANALYST_TIMEOUT, TRIAGE_TIMEOUT,
)
from schild.core.memory import SchildMemory
from schild.core.tools import ToolRegistry
from schild.ai.provider import create_provider, verify_provider, AIProviderBase, ModelTier
from schild.ai.router import plan_action, generate_memory_answer
from schild.ai.investigator import run_investigation_loop
from schild.hunting.threat_hunter import ThreatHunter
from schild.hunting.zero_day_detector import ZeroDayDetector
from schild.hunting.ioc_enricher import IOCEnricher
from schild.ml.baseline_profiler import BaselineProfiler
from schild.ml.anomaly_detector import AnomalyDetector
from schild.response.orchestrator import ResponseOrchestrator
from schild.utils.executor import execute_command
from schild.utils.logger import log_event
from schild.utils.alerts import create_alert


class SchildAgent:
    """
    SCHILD — Autonomous Engine for Guardian & Intelligent Security.

    Core capabilities:
    - API-key based AI (OpenAI / Anthropic / Gemini)
    - Proactive threat hunting (MITRE ATT&CK hypotheses)
    - Zero-day behavioral detection
    - ML anomaly detection (statistical + Isolation Forest)
    - IOC enrichment (VirusTotal, AbuseIPDB, Shodan)
    - Autonomous response (OBSERVE / HUNT / CONTAIN / ELIMINATE)
    """

    COLORS = COLORS

    def __init__(
        self,
        defense_mode: DefenseMode = DEFAULT_DEFENSE_MODE,
        db_path: str = DEFAULT_DB_PATH,
        ai_provider: Optional[AIProvider] = None,
        api_key: Optional[str] = None,
    ):
        self.defense_mode = defense_mode
        self.history: List[Dict] = []
        self.alerts: List[Dict] = []
        self._logs: List[Dict] = []  # DONE: TASK-02
        self.vulnerabilities: List[Dict] = []

        # ── Core systems ──────────────────────────────────────────────────────
        self.memory = SchildMemory(db_path=db_path)
        print(f"{COLORS['success']} Memory store initialized{COLORS['reset']}")

        self.tool_registry = ToolRegistry()
        print(f"{COLORS['success']} SOAR tools registered ({len(self.tool_registry.tools)} tools){COLORS['reset']}")

        # ── AI Provider ───────────────────────────────────────────────────────
        chosen_provider = ai_provider or DEFAULT_AI_PROVIDER
        self.provider: AIProviderBase = create_provider(chosen_provider, api_key)
        self._provider_ok = verify_provider(self.provider)

        # ── Hunting & Detection ───────────────────────────────────────────────
        self.threat_hunter = ThreatHunter(
            provider=self.provider,
            memory=self.memory,
            defense_mode=defense_mode,
        )
        self.zero_day_detector = ZeroDayDetector(
            provider=self.provider,
            memory=self.memory,
        )
        self.ioc_enricher = IOCEnricher(memory=self.memory)
        self.baseline_profiler = BaselineProfiler(memory=self.memory)
        self.anomaly_detector = AnomalyDetector(
            memory=self.memory,
            profiler=self.baseline_profiler,
        )
        self.response_orchestrator = ResponseOrchestrator(
            memory=self.memory,
            defense_mode=defense_mode,
        )
        print(f"{COLORS['success']} Threat hunting engine ready{COLORS['reset']}")
        print(f"{COLORS['success']}  Log buffer initialized{COLORS['reset']}")  # DONE: TASK-02

        # ── Log Ingestion Layer ───────────────────────────────────────────────
        # DONE: FIX-03 — graceful fallback jika watchdog tidak tersedia
        try:
            from schild.ingestion.log_receiver import LogIngestionManager
            self.ingestion = LogIngestionManager(
                memory=self.memory,
                alert_callback=self._alert,
            )
            print(f"{COLORS['success']}  Log ingestion layer ready{COLORS['reset']}")
        except ImportError:
            self.ingestion = None
            print(
                f"{COLORS['warning']}  Log ingestion unavailable "
                f"(run: pip install watchdog){COLORS['reset']}"
            )

        # ── Webhook Notifier ──────────────────────────────────────────────────
        # DONE: TASK-10
        try:
            from schild.notifications.webhook import WebhookNotifier
            self.notifier = WebhookNotifier()
            if self.notifier.enabled:
                print(f"{COLORS['success']}  Webhook notifier active{COLORS['reset']}")
        except ImportError:
            self.notifier = None
            print(f"{COLORS['warning']}  Webhook notifier unavailable{COLORS['reset']}")

        # ── Sidecar Registry ───────────────────────────────────────────────────────────────────────────────
        # DONE: TASK-11.7
        try:
            from schild.sidecar.client import SidecarRegistry
            self._sidecar_registry = SidecarRegistry()
            # Inject ke response orchestrator
            self.response_orchestrator.set_sidecar_registry(self._sidecar_registry)
            print(f"{COLORS['success']}  Sidecar registry ready (0 hosts){COLORS['reset']}")
        except ImportError:
            self._sidecar_registry = None
            print(f"{COLORS['warning']}  Sidecar not available (fastapi/requests missing){COLORS['reset']}")

        # ── System context ────────────────────────────────────────────────────
        self.work_dir = subprocess.getoutput("pwd")
        self.system_context = self._get_system_context()
        self.asset_inventory: Dict = {}

        # ── Monitoring thread ─────────────────────────────────────────────────
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None
        self._monitor_stop = threading.Event()

        # ── MITRE data for context injection ──────────────────────────────────
        self._mitre_data = self._load_mitre_data()

        self.memory.save_event(
            "AGENT_START",
            f"SCHILD started — mode={defense_mode.value}, provider={self.provider.provider_name}",
            level="info",
        )

    # ─────────────────────────────────────────────────────────────────────────
    # System Context
    # ─────────────────────────────────────────────────────────────────────────

    def _get_system_context(self) -> Dict:
        return {
            "os": subprocess.getoutput("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2 2>/dev/null || uname -s"),
            "hostname": subprocess.getoutput("hostname"),
            "kernel": subprocess.getoutput("uname -r"),
            "uptime": subprocess.getoutput("uptime -p 2>/dev/null || uptime"),
            "cpu_cores": os.cpu_count() or 1,
            "memory_total": subprocess.getoutput("free -h | awk '/Mem:/ {print $2}' 2>/dev/null || echo 'N/A'"),
            "network_ips": subprocess.getoutput("ip -brief address 2>/dev/null | awk '{print $1,$3}'"),
            "work_dir": self.work_dir,
        }

    def _load_mitre_data(self) -> Optional[Dict]:
        """Load MITRE ATT&CK data from local file."""
        try:
            data_path = Path(__file__).parent.parent / "intel" / "data" / "attack_techniques.json"
            if data_path.exists():
                with open(data_path) as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Core helpers
    # ─────────────────────────────────────────────────────────────────────────

    def execute(self, command: str) -> str:
        return execute_command(command=command, work_dir=self.work_dir,
                               history=self.history, logger_func=self._log)

    def _log(self, message: str, level: str = "info"):
        log_event(
            message=message, level=level,
            hostname=self.system_context.get("hostname", "unknown"),
            logs_list=self._logs,  # DONE: TASK-02
        )
        self.memory.save_event("LOG", message, level=level)

    def _alert(self, title: str, message: str, severity: str = "medium"):
        alert = create_alert(
            title=title, message=message, severity=severity,
            hostname=self.system_context.get("hostname", "unknown"),
            alerts_list=self.alerts,
            memory=self.memory,
            notifier=self.notifier,  # DONE: TASK-10
        )
        return alert

    # DONE: TASK-08
    def start_syslog_ingestion(self, host: str = "0.0.0.0", port: int = 5140):
        # DONE: FIX-03
        if self.ingestion is None:
            print(f"{COLORS['warning']}  Log ingestion not available.{COLORS['reset']}")
            return
        self.ingestion.start_syslog(host=host, port=port)

    def watch_log_file(self, path: str):
        # DONE: FIX-03
        if self.ingestion is None:
            print(f"{COLORS['warning']}  Log ingestion not available.{COLORS['reset']}")
            return
        self.ingestion.add_file_watcher(path)

    def start_port_mirror(
        self,
        interface: str,
        bpf_filter: str = "",
        promisc: bool = True,
    ):
        """
        Start passive packet capture on a SPAN / port-mirrored interface.

        Requires scapy and root / CAP_NET_RAW privileges.

        Parameters
        ----------
        interface : str
            NIC receiving mirrored traffic, e.g. "eth1".
        bpf_filter : str
            Optional BPF filter, e.g. "tcp port 80" or "not port 22".
        promisc : bool
            Enable promiscuous mode (default True — required for SPAN).
        """
        if self.ingestion is None:
            print(f"{COLORS['warning']}  Log ingestion not available.{COLORS['reset']}")
            return
        try:
            cap = self.ingestion.start_port_mirror(
                interface=interface,
                bpf_filter=bpf_filter,
                promisc=promisc,
            )
            print(
                f"{COLORS['success']}  Port mirror capture started "
                f"on {interface}"
                + (f" (filter: {bpf_filter})" if bpf_filter else "")
                + f"{COLORS['reset']}"
            )
            self.memory.save_event(
                "PORT_MIRROR",
                f"Packet capture started on {interface} filter='{bpf_filter}'",
                level="info",
            )
            return cap
        except ImportError as e:
            print(f"{COLORS['error']}  {e}{COLORS['reset']}")
        except PermissionError:
            print(
                f"{COLORS['error']}  Permission denied — run as root or grant CAP_NET_RAW:\n"
                f"    sudo setcap cap_net_raw+eip $(which python3){COLORS['reset']}"
            )

    def stop_all_ingestion(self):
        """Stop all ingestion sources: file watchers, syslog, port mirrors."""
        if self.ingestion is None:
            return
        self.ingestion.stop_all()
        print(f"{COLORS['info']}  All ingestion sources stopped.{COLORS['reset']}")

    # DONE: TASK-09
    def start_scheduled_hunt(self, interval_minutes: int = 360):
        """
        Start a background scheduler that runs a full threat hunt every N minutes.
        Default: every 6 hours.
        """
        from apscheduler.schedulers.background import BackgroundScheduler
        self._scheduler = BackgroundScheduler()
        self._scheduler.add_job(
            func=self.hunt,
            trigger="interval",
            minutes=interval_minutes,
            id="scheduled_hunt",
            replace_existing=True,
        )
        self._scheduler.start()
        print(
            f"{COLORS['success']}  Scheduled hunt every {interval_minutes}min{COLORS['reset']}"
        )

    def register_sidecar(self, name: str, url: str, secret: str) -> bool:
        """
        Register a remote host sidecar.

        Args:
            name:   Label host, misal "dvwa", "webserver-1"
            url:    URL sidecar, misal "http://10.0.0.5:8421"
            secret: Shared secret

        Returns:
            True jika sidecar bisa dijangkau, False jika tidak
        """
        # DONE: TASK-11.7
        if self._sidecar_registry is None:
            print(f"{COLORS['warning']}  Sidecar registry not initialized.{COLORS['reset']}")
            return False

        client = self._sidecar_registry.register(name=name, base_url=url, secret=secret)

        # Ping untuk verifikasi koneksi
        alive = client.is_alive()
        status_color = COLORS["success"] if alive else COLORS["warning"]
        status_text  = "reachable" if alive else "UNREACHABLE (registered anyway)"
        print(f"{status_color}  Sidecar '{name}' at {url} — {status_text}{COLORS['reset']}")

        # Register SidecarTool ke ToolRegistry agar agent bisa pakai di ReAct loop
        from schild.core.tools import SidecarTool
        self.tool_registry.register(SidecarTool(
            sidecar_url=url,
            secret=secret,
            host_name=name,
        ))

        return alive

    def ping_sidecars(self) -> dict:
        """Ping semua registered sidecar dan return status."""
        # DONE: TASK-11.7
        if self._sidecar_registry is None:
            return {}
        return self._sidecar_registry.ping_all()

    # ─────────────────────────────────────────────────────────────────────────
    # Asset Discovery
    # ─────────────────────────────────────────────────────────────────────────

    def discover_assets(self) -> Dict:
        print(f"\n{COLORS['analysis']} Discovering assets...{COLORS['reset']}")
        assets = {
            "hostname": self.system_context.get("hostname", "unknown"),
            "os": self.system_context.get("os", "unknown"),
            "kernel": self.system_context.get("kernel", "unknown"),
            "network_interfaces": [],
            "installed_services": [],
            "open_ports": [],
            "users": [],
            "timestamp": datetime.now().isoformat(),
        }
        try:
            assets["network_interfaces"] = [
                l for l in subprocess.getoutput("ip -brief address 2>/dev/null || ifconfig").split("\n") if l.strip()
            ]
            assets["installed_services"] = [
                s.strip() for s in subprocess.getoutput(
                    "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | head -25"
                ).split("\n") if s.strip()
            ]
            assets["open_ports"] = [
                p.strip() for p in subprocess.getoutput(
                    "ss -tuln 2>/dev/null | grep LISTEN | head -25 || netstat -tuln 2>/dev/null | grep LISTEN | head -25"
                ).split("\n") if p.strip()
            ]
            assets["users"] = [
                u.strip() for u in subprocess.getoutput("getent passwd | cut -d: -f1 | head -20").split("\n") if u.strip()
            ]
            self.memory.save_asset_inventory(assets)
            self.asset_inventory = assets
            print(f"{COLORS['success']} Discovered {len(assets['installed_services'])} services, "
                  f"{len(assets['open_ports'])} open ports{COLORS['reset']}")
        except Exception as e:
            self._log(f"Asset discovery error: {e}", level="error")
        return assets

    # ─────────────────────────────────────────────────────────────────────────
    # Threat Hunting
    # ─────────────────────────────────────────────────────────────────────────

    def hunt(self, hypothesis_id: Optional[str] = None) -> List[Dict]:
        """Run threat hunt (all or specific hypothesis)."""
        if hypothesis_id:
            from schild.core.config import DEFAULT_HUNT_HYPOTHESES
            hyp = next((h for h in DEFAULT_HUNT_HYPOTHESES if h["id"] == hypothesis_id), None)
            if not hyp:
                print(f"{COLORS['error']}Hypothesis '{hypothesis_id}' not found.{COLORS['reset']}")
                return []
            results = [self.threat_hunter.hunt_hypothesis(hyp)]
        else:
            results = self.threat_hunter.hunt_all()

        # Auto-respond if in CONTAIN/ELIMINATE mode
        if self.defense_mode in (DefenseMode.CONTAIN, DefenseMode.ELIMINATE):
            threats = [r for r in results if r["verdict"] in ("compromised", "suspicious")]
            if threats:
                self.response_orchestrator.respond_to_findings(threats)

        return results

    def zero_day_scan(self) -> List[Dict]:
        """Run zero-day behavioral scan."""
        findings = self.zero_day_detector.scan()
        if findings and self.defense_mode in (DefenseMode.CONTAIN, DefenseMode.ELIMINATE):
            self.response_orchestrator.respond_to_findings(findings)
        return findings

    def anomaly_scan(self) -> List[Dict]:
        """Run statistical anomaly detection."""
        return self.anomaly_detector.detect()

    def enrich_ioc(self, ioc_type: str, value: str) -> Dict:
        """Enrich a single IOC."""
        print(f"{COLORS['ioc']} Enriching IOC: [{ioc_type}] {value}{COLORS['reset']}")
        return self.ioc_enricher.enrich(ioc_type, value)

    def build_baseline(self, samples: int = 20):
        """Build behavioral baseline for anomaly detection."""
        return self.baseline_profiler.build_baseline(num_samples=samples)

    # ─────────────────────────────────────────────────────────────────────────
    # Continuous Monitoring
    # ─────────────────────────────────────────────────────────────────────────

    def start_monitoring(self, interval: int = 60):
        if self._monitoring_active:
            print(f"{COLORS['warning']}Monitoring already active.{COLORS['reset']}")
            return
        self._monitoring_active = True
        self._monitor_stop.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, args=(interval,), daemon=True
        )
        self._monitoring_thread.start()
        print(f"{COLORS['success']} Continuous monitoring started (interval: {interval}s){COLORS['reset']}")
        self._log("Monitoring started", level="info")

    def stop_monitoring(self):
        self._monitoring_active = False
        self._monitor_stop.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        print(f"{COLORS['info']}Monitoring stopped.{COLORS['reset']}")

    def _monitoring_loop(self, interval: int):
        while not self._monitor_stop.is_set():
            try:
                anomalies = self.anomaly_detector.detect()
                if anomalies:
                    severity = max(
                        (a.get("severity", "medium") for a in anomalies),
                        key=lambda s: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(s, 0),
                        default="medium",
                    )
                    self._alert(
                        "Behavioral Anomaly Detected",
                        f"{len(anomalies)} metric anomalies: "
                        + ", ".join(a["metric"] for a in anomalies[:3]),
                        severity=severity,
                    )
                    if self.defense_mode in (DefenseMode.CONTAIN, DefenseMode.ELIMINATE):
                        self.response_orchestrator.respond_to_findings(anomalies)
            except Exception as e:
                self._log(f"Monitoring loop error: {e}", level="error")
            self._monitor_stop.wait(interval)

    # ─────────────────────────────────────────────────────────────────────────
    # Chat / Investigation Mode
    # ─────────────────────────────────────────────────────────────────────────

    def chat_mode(self):
        print(f"\n{COLORS['hunt']} SCHILD AI Mode — {self.provider.provider_name.upper()}{COLORS['reset']}")
        print(f"{COLORS['info']}Type 'exit' to return to CLI.{COLORS['reset']}\n")

        while True:
            user_msg = input(f"{COLORS['command']}You: {COLORS['reset']}").strip()
            if not user_msg:
                continue
            if user_msg.lower() in ("exit", "quit"):
                break

            print(f"{COLORS['output']}[Routing...]{COLORS['reset']}", end="\r")

            planned = plan_action(
                provider=self.provider,
                user_msg=user_msg,
                memory_hint=self.memory.get_recent_summary(limit=3),
                timeout=TRIAGE_TIMEOUT,
            )
            action = (planned or {}).get("action", "INVESTIGATE")

            if action == "CHAT":
                msg = str((planned or {}).get("message", "")).strip()
                if not msg:
                    msg = self.provider.complete(
                        user_msg,
                        system_prompt="You are SCHILD, an autonomous threat defense system. Respond briefly.",
                        tier=ModelTier.TRIAGE,
                        timeout=TRIAGE_TIMEOUT,
                    ).strip()
                print(f"{COLORS['success']}SCHILD: {msg}{COLORS['reset']}\n")
                continue

            if action == "ANSWER_MEMORY":
                print(f"{COLORS['analysis']}Reading memory...{COLORS['reset']}")
                ans = generate_memory_answer(
                    provider=self.provider,
                    memory=self.memory,
                    user_msg=user_msg,
                    asset_inventory=self.asset_inventory,
                    vulnerabilities=self.vulnerabilities,
                    alerts=self.alerts,
                    iocs=self.memory.get_iocs(limit=20),
                )
                print(f"{COLORS['success']}SCHILD: {ans}{COLORS['reset']}\n")
                continue

            if action == "HUNT":
                self.hunt()
                continue

            if action == "CONTAIN":
                target = str((planned or {}).get("target", "")).strip()
                method = str((planned or {}).get("method", "")).strip()
                if target and method:
                    from schild.response.orchestrator import ResponseAction
                    ra = ResponseAction(
                        action_type=method.replace("block_ip", "block_ip")
                                         .replace("kill_process", "kill_process"),
                        target=target,
                        reason=f"Operator-requested containment: {user_msg}",
                        severity="high",
                    )
                    self.response_orchestrator._execute_action(ra)
                continue

            if action == "RUN_CMD":
                cmd = str((planned or {}).get("command", "")).strip()
                if cmd:
                    print(f"{COLORS['warning']} {cmd}{COLORS['reset']}")
                    out = self.execute(cmd)
                    print(f"{COLORS['output']}{out}{COLORS['reset']}\n")
                continue

            # Default: INVESTIGATE
            run_investigation_loop(
                user_msg=user_msg,
                provider=self.provider,
                execute_cmd=self.execute,
                memory_summary=self.memory.get_recent_summary,
                tool_registry=self.tool_registry,
                mitre_data=self._mitre_data,
                defense_mode=self.defense_mode,
                max_steps=MAX_HUNT_STEPS,
                timeout=ANALYST_TIMEOUT,
            )
            print()

    def single_prompt(self, user_msg: str):
        print(f"\n{COLORS['hunt']} SCHILD AI Mode — {self.provider.provider_name.upper()}{COLORS['reset']}")
        print(f"{COLORS['command']}Prompt: {user_msg}{COLORS['reset']}\n")
        
        planned = plan_action(
            provider=self.provider,
            user_msg=user_msg,
            memory_hint=self.memory.get_recent_summary(limit=3),
            timeout=TRIAGE_TIMEOUT,
        )
        action = (planned or {}).get("action", "INVESTIGATE")

        if action == "CHAT":
            msg = str((planned or {}).get("message", "")).strip()
            if not msg:
                msg = self.provider.complete(
                    user_msg,
                    system_prompt="You are SCHILD, an autonomous threat defense system. Respond briefly.",
                    tier=ModelTier.TRIAGE,
                    timeout=TRIAGE_TIMEOUT,
                ).strip()
            print(f"{COLORS['success']}SCHILD: {msg}{COLORS['reset']}\n")
            return
            
        if action == "ANSWER_MEMORY":
            ans = generate_memory_answer(
                provider=self.provider,
                memory=self.memory,
                user_msg=user_msg,
                asset_inventory=self.asset_inventory,
                vulnerabilities=self.vulnerabilities,
                alerts=self.alerts,
                iocs=self.memory.get_iocs(limit=20),
            )
            print(f"{COLORS['success']}SCHILD: {ans}{COLORS['reset']}\n")
            return
            
        if action == "HUNT":
            self.hunt()
            return
            
        if action == "RUN_CMD":
            cmd = str((planned or {}).get("command", "")).strip()
            if cmd:
                print(f"{COLORS['warning']} {cmd}{COLORS['reset']}")
                out = self.execute(cmd)
                print(f"{COLORS['output']}{out}{COLORS['reset']}\n")
            return

        # Default: INVESTIGATE
        run_investigation_loop(
            user_msg=user_msg,
            provider=self.provider,
            execute_cmd=self.execute,
            memory_summary=self.memory.get_recent_summary,
            tool_registry=self.tool_registry,
            mitre_data=self._mitre_data,
            defense_mode=self.defense_mode,
            max_steps=MAX_HUNT_STEPS,
            timeout=ANALYST_TIMEOUT,
        )
        print()

    # ─────────────────────────────────────────────────────────────────────────
    # CLI Entry
    # ─────────────────────────────────────────────────────────────────────────

    def run(self):
        self._print_banner()

        while True:
            try:
                user_input = input(
                    f"{COLORS['hunt']}SCHILD[{self.defense_mode.value}]➜ "
                    f"{self.work_dir} $ {COLORS['reset']}"
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print(f"\n{COLORS['info']}Exiting SCHILD...{COLORS['reset']}")
                break

            if not user_input:
                continue

            cmd = user_input.lower()

            if cmd in ("exit", "quit"):
                if self._monitoring_active:
                    self.stop_monitoring()
                break
            elif cmd == "help":
                self._print_banner()
            elif cmd == "schild hunt":
                self.hunt()
            elif cmd.startswith("schild hunt "):
                hyp_id = user_input.split(" ", 2)[2].upper()
                self.hunt(hypothesis_id=hyp_id)
            elif cmd == "schild zeroday":
                self.zero_day_scan()
            elif cmd == "schild anomaly":
                self.anomaly_scan()
            elif cmd == "schild assets":
                self.discover_assets()
                print(json.dumps(self.asset_inventory, indent=2))
            elif cmd == "schild baseline build":
                self.build_baseline()
            elif cmd == "schild ml train":
                print(f"{COLORS['info']}Starting Full ML Training Pipeline...{COLORS['reset']}")
                self.anomaly_detector.train(n_samples=40)
            elif cmd == "schild ml retrain":
                self.anomaly_detector.retrain(n_samples=40)
            elif cmd == "schild ml update":
                print(f"{COLORS['info']}Starting ML Online Update...{COLORS['reset']}")
                self.anomaly_detector.update_online(n_new=10)
            elif cmd == "schild monitor start":
                interval = input("Interval (seconds, default 60): ").strip()
                self.start_monitoring(int(interval) if interval.isdigit() else 60)
            elif cmd == "schild monitor stop":
                self.stop_monitoring()
            elif cmd == "schild alerts":
                alerts = self.memory.get_recent_alerts(limit=20)
                for a in alerts:
                    color = COLORS["error"] if a["severity"] in ("high", "critical") else COLORS["warning"]
                    print(f"{color}[{a['severity'].upper()}] {a['title']}: {a['message'][:80]}{COLORS['reset']}")
            elif cmd == "schild iocs":
                iocs = self.memory.get_iocs(limit=30)
                for ioc in iocs:
                    print(f"  [{ioc['ioc_type']}] {ioc['value']} — conf={ioc['confidence']:.2f} — {ioc.get('threat_name','')}")
            elif cmd == "schild hunts":
                results = self.memory.get_hunt_results(limit=20)
                for r in results:
                    icon = "" if r["verdict"] == "compromised" else "️" if r["verdict"] == "suspicious" else ""
                    print(f"  {icon} [{r['timestamp'][:10]}] {r['hypothesis']} → {r['verdict'].upper()}")
            elif cmd.startswith("enrich "):
                parts = user_input.split(" ", 2)
                if len(parts) == 3:
                    self.enrich_ioc(parts[1], parts[2])
                else:
                    print("Usage: enrich ip|domain|hash <value>")
            elif cmd == "chat":
                self.chat_mode()
            elif cmd == "log":
                print(self.memory.get_recent_summary(limit=20))
            elif cmd.startswith("schild mirror start "):
                parts = user_input.split()
                # schild mirror start <iface> [filter ...]
                if len(parts) >= 4:
                    iface = parts[3]
                    bpf = " ".join(parts[4:]) if len(parts) > 4 else ""
                    self.start_port_mirror(interface=iface, bpf_filter=bpf)
                else:
                    print("Usage: schild mirror start <interface> [bpf_filter]")
            elif cmd == "schild mirror stop":
                self.stop_all_ingestion()
            elif cmd.startswith("schild mirror stats"):
                if self.ingestion and self.ingestion._mirror_captures:
                    for i, cap in enumerate(self.ingestion._mirror_captures):
                        s = cap.get_stats()
                        print(f"  Capture[{i}] iface={cap.interface}: {s}")
                else:
                    print("  No active port mirror captures.")
            else:
                out = self.execute(user_input)
                print(f"{COLORS['output']}{out}{COLORS['reset']}", end="")

    def _print_banner(self):
        mode_color = {
            DefenseMode.OBSERVE:   COLORS["info"],
            DefenseMode.HUNT:      COLORS["analysis"],
            DefenseMode.CONTAIN:   COLORS["warning"],
            DefenseMode.ELIMINATE: COLORS["critical"],
        }.get(self.defense_mode, COLORS["info"])

        print(f"\n{COLORS['hunt']}{'═' * 64}{COLORS['reset']}")
        print(f"{COLORS['hunt']}  SCHILD — Autonomous Defense & AI-Driven Threat Hunting{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'═' * 64}{COLORS['reset']}")
        print(f"  Provider  : {self.provider.provider_name.upper()} "
              f"({self.provider.triage_model} / {self.provider.analyst_model})")
        print(f"  Mode      : {mode_color}{self.defense_mode.value.upper()}{COLORS['reset']}")
        print(f"  Hostname  : {self.system_context.get('hostname','?')}")
        print(f"  OS        : {self.system_context.get('os','?')}")
        print(f"\n{COLORS['hunt']}  Hunting Commands:{COLORS['reset']}")
        print("    schild hunt              — Run all MITRE ATT&CK hunt hypotheses")
        print("    schild hunt H-001        — Run specific hypothesis")
        print("    schild zeroday           — Zero-day behavioral scan")
        print("    schild anomaly           — Anomaly detection vs baseline (Stat + ML)")
        print("    schild ml train          — Train all ML anomaly models")
        print("    schild ml update         — Incremental online update for ML models")
        print("    schild ml retrain        — Retrain all ML models from scratch")
        print("    schild baseline build    — Build statistical baseline")
        print("    schild assets            — Asset discovery")
        print("    schild monitor start     — Start continuous monitoring")
        print("    schild monitor stop      — Stop monitoring")
        print("    schild alerts            — View recent alerts")
        print("    schild iocs              — View tracked IOCs")
        print("    schild hunts             — View hunt history")
        print(f"\n{COLORS['hunt']}  Log Ingestion Commands:{COLORS['reset']}")
        print("    schild mirror start <iface> [filter] — Start port mirror capture")
        print("    schild mirror stop               — Stop all ingestion sources")
        print("    schild mirror stats              — Show capture statistics")
        print("    enrich ip|domain|hash X — Enrich an IOC")
        print("    chat                    — AI threat hunting chat")
        print("    log                     — View event log")
        print("    exit                    — Quit SCHILD")
        print(f"{COLORS['hunt']}{'=' * 64}{COLORS['reset']}\n")
