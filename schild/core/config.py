import os
from enum import Enum
from typing import Optional



class DefenseMode(Enum):
    OBSERVE   = "observe"    # Log-only; no automated actions
    HUNT      = "hunt"       # Proactive hunting; no auto-remediation
    CONTAIN   = "contain"    # Auto-isolate threats; confirm kills
    ELIMINATE = "eliminate"  # Fully autonomous response

class AIProvider(Enum):
    OPENAI    = "openai"
    ANTHROPIC = "anthropic"
    GEMINI    = "gemini"
    OLLAMA    = "ollama"


DEFAULT_AI_PROVIDER = AIProvider(
    os.getenv("SCHILD_AI_PROVIDER", "openai")
)

TRIAGE_MODEL = os.getenv("SCHILD_TRIAGE_MODEL", "gpt-4o-mini")

ANALYST_MODEL = os.getenv("SCHILD_ANALYST_MODEL", "gpt-4o")

ANTHROPIC_TRIAGE_MODEL  = os.getenv("SCHILD_ANTHROPIC_TRIAGE_MODEL",  "claude-haiku-4-5")
ANTHROPIC_ANALYST_MODEL = os.getenv("SCHILD_ANTHROPIC_ANALYST_MODEL", "claude-sonnet-4-5")
GEMINI_TRIAGE_MODEL     = os.getenv("SCHILD_GEMINI_TRIAGE_MODEL",     "gemini-1.5-flash")
GEMINI_ANALYST_MODEL    = os.getenv("SCHILD_GEMINI_ANALYST_MODEL",    "gemini-1.5-pro")
OLLAMA_TRIAGE_MODEL     = os.getenv("SCHILD_OLLAMA_TRIAGE_MODEL",     "llama3")
OLLAMA_ANALYST_MODEL    = os.getenv("SCHILD_OLLAMA_ANALYST_MODEL",    "llama3")
OLLAMA_BASE_URL         = os.getenv("OLLAMA_BASE_URL",                 "http://localhost:11434")


# ─────────────────────────────────────────────────────────────────────────────
# API Keys (from environment)
# ─────────────────────────────────────────────────────────────────────────────

OPENAI_API_KEY:    Optional[str] = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL:   Optional[str] = os.getenv("OPENAI_BASE_URL")
ANTHROPIC_API_KEY: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
GEMINI_API_KEY:    Optional[str] = os.getenv("GEMINI_API_KEY")
# Ollama tidak butuh API key (local), tapi bisa di-override jika pakai server remote
OLLAMA_API_KEY:    Optional[str] = os.getenv("OLLAMA_API_KEY")

# Threat Intel APIs
VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY:     Optional[str] = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY:  Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
NVD_API_KEY:        Optional[str] = os.getenv("NVD_API_KEY")  # NIST NVD feed


# ─────────────────────────────────────────────────────────────────────────────
# Runtime Settings
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_DEFENSE_MODE = DefenseMode(
    os.getenv("SCHILD_DEFENSE_MODE", "hunt")
)

DEFAULT_DB_PATH = os.getenv("SCHILD_DB_PATH", "schild_memory.db")

# Timeouts (seconds)
TRIAGE_TIMEOUT  = int(os.getenv("SCHILD_TRIAGE_TIMEOUT",  "30"))
ANALYST_TIMEOUT = int(os.getenv("SCHILD_ANALYST_TIMEOUT", "120"))
TOOL_TIMEOUT    = int(os.getenv("SCHILD_TOOL_TIMEOUT",     "30"))

# Investigation loop
MAX_HUNT_STEPS = int(os.getenv("SCHILD_MAX_HUNT_STEPS", "8"))

# Anomaly detection
ANOMALY_ZSCORE_THRESHOLD  = float(os.getenv("SCHILD_ANOMALY_ZSCORE",      "3.0"))
BASELINE_SAMPLE_INTERVAL  = int(os.getenv("SCHILD_BASELINE_INTERVAL",     "60"))   # seconds
BASELINE_WARMUP_SAMPLES   = int(os.getenv("SCHILD_BASELINE_WARMUP",       "20"))

# Memory limits
MAX_LOGS_IN_MEMORY    = 2000
MAX_HISTORY_ITEMS     = 200
MAX_IOC_ENTRIES       = 10000
REFLECTION_INTERVAL_HOURS = 2

# API Backend
API_HOST   = os.getenv("SCHILD_API_HOST", "0.0.0.0")
API_PORT   = int(os.getenv("SCHILD_API_PORT", "8420"))
API_SECRET = os.getenv("SCHILD_API_SECRET", "")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Color Palette
# ─────────────────────────────────────────────────────────────────────────────

COLORS = {
    "command":  "\033[33m",    # Yellow
    "output":   "\033[90m",    # Dark gray
    "analysis": "\033[36m",    # Cyan
    "error":    "\033[31m",    # Red
    "reset":    "\033[0m",
    "chat":     "\033[34m",    # Blue
    "warning":  "\033[33m",    # Yellow warning
    "success":  "\033[32m",    # Green
    "info":     "\033[35m",    # Magenta
    "critical": "\033[1;31m",  # Bold red
    "hunt":     "\033[1;36m",  # Bold cyan — hunting activity
    "ioc":      "\033[1;33m",  # Bold yellow — IOC hits
}


# ─────────────────────────────────────────────────────────────────────────────
# Command Safety
# ─────────────────────────────────────────────────────────────────────────────

# DONE: FIX-04
# Dangerous command detection dipindah ke schild/utils/executor.py
# menggunakan regex pattern (DANGEROUS_PATTERNS) — lebih akurat dari substring match.
# Lihat: is_dangerous_command() di executor.py


# ─────────────────────────────────────────────────────────────────────────────
# Threat Hunting Hypotheses (MITRE ATT&CK aligned)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Sidecar Remote Agent Config
# ─────────────────────────────────────────────────────────────────────────────

# DONE: TASK-11.1
SIDECAR_TIMEOUT = 15          # detik — timeout request ke sidecar
SIDECAR_PORT    = 8421        # port default sidecar (non-root)

# Actions yang diizinkan sidecar — JANGAN ubah tanpa update server.py juga
SIDECAR_ALLOWED_ACTIONS = frozenset([
    "block_ip",
    "unblock_ip",
    "kill_process",
    "stop_service",
    "restart_service",
    "get_status",
])


DEFAULT_HUNT_HYPOTHESES = [
    {
        "id": "H-001",
        "name": "Lateral Movement via SSH",
        "tactic": "TA0008",
        "technique": "T1021.004",
        "description": "Detect unusual SSH connections between internal hosts",
        "indicators": ["ssh", "authorized_keys", "known_hosts", "/.ssh/"],
    },
    {
        "id": "H-002",
        "name": "Persistence via Cron/Systemd",
        "tactic": "TA0003",
        "technique": "T1053",
        "description": "Detect unauthorized scheduled tasks or systemd units",
        "indicators": ["crontab", "/etc/cron", "systemd", ".service", ".timer"],
    },
    {
        "id": "H-003",
        "name": "Command & Control Beaconing",
        "tactic": "TA0011",
        "technique": "T1071",
        "description": "Detect periodic outbound connections suggesting C2",
        "indicators": ["netstat", "ss", "curl", "wget", "/tmp"],
    },
    {
        "id": "H-004",
        "name": "Credential Dumping",
        "tactic": "TA0006",
        "technique": "T1003",
        "description": "Detect access to credential stores (/etc/shadow, SAM)",
        "indicators": ["/etc/shadow", "/etc/passwd", "mimikatz", "secretsdump"],
    },
    {
        "id": "H-005",
        "name": "Data Exfiltration",
        "tactic": "TA0010",
        "technique": "T1041",
        "description": "Detect large outbound data transfers or suspicious archives",
        "indicators": ["tar", "zip", "scp", "rsync", "large upload"],
    },
    {
        "id": "H-006",
        "name": "Defense Evasion — Log Clearing",
        "tactic": "TA0005",
        "technique": "T1070",
        "description": "Detect clearing or tampering with system logs",
        "indicators": ["truncate", "/var/log", "shred", "history -c"],
    },
    {
        "id": "H-007",
        "name": "Privilege Escalation",
        "tactic": "TA0004",
        "technique": "T1068",
        "description": "Detect exploitation of SUID binaries or sudo misconfig",
        "indicators": ["suid", "sudo", "setuid", "/etc/sudoers", "pkexec"],
    },
    {
        "id": "H-008",
        "name": "Zero-Day Exploit Behavior",
        "tactic": "TA0002",
        "technique": "T1059",
        "description": "Detect anomalous process spawning from unexpected parents",
        "indicators": ["unexpected_child", "shell_from_service", "memory_injection"],
    },
]
