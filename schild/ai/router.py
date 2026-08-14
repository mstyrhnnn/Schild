import json
import re
from typing import Dict, Any, Optional

from schild.ai.provider import AIProviderBase, ModelTier
from schild.core.config import TRIAGE_TIMEOUT, COLORS


# Quick heuristic prefixes that skip full LLM roundtrip
_CMD_PREFIXES = (
    "run ", "exec ", "cat ", "ls ", "grep ",
    "systemctl ", "journalctl ", "ps ", "ss ",
)

_HUNT_KEYWORDS = (
    "hunt", "threat hunt", "zero-day", "zeroday",
    "lateral movement", "persistence", "c2 ", "command and control",
    "exfiltration", "privilege escalation", "ioc",
)

_CONTAIN_KEYWORDS = (
    "block ip", "isolate", "kill process", "quarantine",
    "ban", "terminate", "stop service",
)


def plan_action(
    provider: AIProviderBase,
    user_msg: str,
    memory_hint: str = "",
    timeout: int = TRIAGE_TIMEOUT,
) -> Dict[str, Any]:
    """
    Classify intent and return a routing decision.

    Returns dict:
      {"action": "HUNT"}
      {"action": "INVESTIGATE"}
      {"action": "RUN_CMD", "command": "..."}
      {"action": "ANSWER_MEMORY"}
      {"action": "CONTAIN", "target": "...", "method": "..."}
      {"action": "CHAT", "message": "..."}
    """
    lower = user_msg.lower().strip()

    # ── Fast-path heuristics (no LLM) ───────────────────────────────────────
    if lower.startswith(("run ", "exec ")):
        parts = user_msg.split(" ", 1)
        if len(parts) > 1:
            return {"action": "RUN_CMD", "command": parts[1].strip()}

    if any(kw in lower for kw in _HUNT_KEYWORDS):
        return {"action": "HUNT"}

    if any(kw in lower for kw in _CONTAIN_KEYWORDS):
        return {"action": "CONTAIN"}

    # ── LLM classification (triage model — fast) ─────────────────────────────
    sys_prompt = """You are SCHILD — an autonomous threat hunting & defense system router.
Classify the user request into exactly ONE of these actions:

1) CHAT          — greeting / small talk, no security action needed
2) ANSWER_MEMORY — can be answered from cached system data
3) RUN_CMD       — single read-only Linux command answers the question
4) INVESTIGATE   — requires multi-step iterative investigation
5) HUNT          — proactive threat hunting across the system
6) CONTAIN       — user wants to block/isolate/kill a specific threat

Rules:
- Output ONLY valid JSON, no markdown, no explanation.
- Default to INVESTIGATE if unclear.
- HUNT is for proactive "find threats" requests, not reactive ones.
- CONTAIN requires a clear target (IP / process / service).

JSON schema (choose ONE):
{"action":"CHAT","message":"..."} 
{"action":"ANSWER_MEMORY"}
{"action":"RUN_CMD","command":"..."}
{"action":"INVESTIGATE"}
{"action":"HUNT"}
{"action":"CONTAIN","target":"...","method":"block_ip|kill_process|isolate_service"}"""

    prompt = user_msg
    if memory_hint:
        prompt = f"User: {user_msg}\n\nContext:\n{memory_hint}\n\nReturn JSON:"

    try:
        raw = provider.complete(
            prompt, system_prompt=sys_prompt,
            tier=ModelTier.TRIAGE, timeout=timeout,
        )
    except Exception:
        return {"action": "INVESTIGATE"}

    # Extract JSON
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        up = (raw or "").upper()
        for key in ("HUNT", "CONTAIN", "INVESTIGATE", "ANSWER_MEMORY", "RUN_CMD", "CHAT"):
            if key in up:
                return {"action": key}
        return {"action": "INVESTIGATE"}

    try:
        obj = json.loads(m.group(0))
    except Exception:
        return {"action": "INVESTIGATE"}

    action = str(obj.get("action", "")).strip().upper()
    valid = ("CHAT", "ANSWER_MEMORY", "RUN_CMD", "INVESTIGATE", "HUNT", "CONTAIN")
    if action not in valid:
        return {"action": "INVESTIGATE"}

    if action == "RUN_CMD":
        return {"action": "RUN_CMD", "command": str(obj.get("command", "")).strip()}
    if action == "CHAT":
        return {"action": "CHAT", "message": str(obj.get("message", "")).strip()}
    if action == "CONTAIN":
        return {
            "action": "CONTAIN",
            "target": str(obj.get("target", "")).strip(),
            "method": str(obj.get("method", "")).strip(),
        }

    return {"action": action}


def generate_memory_answer(
    provider: AIProviderBase,
    memory,              # SchildMemory instance
    user_msg: str,
    asset_inventory: Optional[dict] = None,
    vulnerabilities: Optional[list] = None,
    alerts: Optional[list] = None,
    iocs: Optional[list] = None,
    timeout: int = TRIAGE_TIMEOUT,
) -> str:
    """Answer directly from cached SCHILD memory — no new system commands."""

    assets = asset_inventory or (memory.get_latest_asset_inventory() if hasattr(memory, "get_latest_asset_inventory") else None)
    context_parts = []

    if assets:
        context_parts.append(
            f"Assets: hostname={assets.get('hostname')}, "
            f"services={len(assets.get('installed_services', []))}, "
            f"open_ports={len(assets.get('open_ports', []))}"
        )

    if vulnerabilities:
        vuln_sum = f"Vulnerabilities: {len(vulnerabilities)} found. "
        for v in vulnerabilities[:5]:
            vuln_sum += f"[{str(v.get('severity','?')).upper()}] {str(v.get('description',''))[:80]}; "
        context_parts.append(vuln_sum)

    if alerts:
        context_parts.append(f"Active Alerts: {len(alerts)}")
        for a in alerts[-3:]:
            context_parts.append(f"  → [{a.get('severity','?').upper()}] {a.get('title','')}: {a.get('message','')[:80]}")

    if iocs:
        context_parts.append(f"Tracked IOCs: {len(iocs)}")

    recent = memory.get_recent_summary(limit=5) if hasattr(memory, "get_recent_summary") else ""
    if recent:
        context_parts.append(f"Recent Events:\n{recent}")

    context_str = "\n".join(context_parts) if context_parts else "No data in memory."

    sys_prompt = (
        "You are SCHILD, an autonomous threat defense system. "
        "Answer briefly and directly using ONLY the data provided below. "
        "If data is not available, tell the user which SCHILD command to run. "
        "Answer in the same language as the question."
    )
    prompt = f"""User Question: {user_msg}

SCHILD Memory:
{context_str}

Answer briefly:"""

    try:
        response = provider.complete(prompt, system_prompt=sys_prompt,
                                     tier=ModelTier.TRIAGE, timeout=timeout)
        return response.strip()
    except Exception as e:
        if vulnerabilities is not None:
            return f"Found {len(vulnerabilities)} vulnerabilities in memory."
        return "No data available. Run 'schild hunt' or 'schild scan' first."
