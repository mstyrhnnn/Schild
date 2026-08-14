import re
import json
from typing import Optional, Callable, Dict

from schild.ai.provider import AIProviderBase, ModelTier
from schild.core.config import COLORS, DefenseMode, MAX_HUNT_STEPS, ANALYST_TIMEOUT

try:
    import json_repair  # type: ignore
except ImportError:
    json_repair = None


# ─────────────────────────────────────────────────────────────────────────────
# Streaming Output Renderer
# ─────────────────────────────────────────────────────────────────────────────

class ThreatStreamRenderer:
    """
    Renders LLM streaming output with visual distinction:
    - THOUGHT → boxed cyan thinking process
    - ACTION  → suppressed (raw JSON hidden from user)
    - FINAL   → green conclusion
    """

    def __init__(self):
        self.buffer = ""
        self.in_thought_box = False
        self.box_width = 88
        self.line_buffer = ""
        self.has_started_thought = False
        self.box_border = "─" * (self.box_width - 2)
        self.suppress_output = False

    # DONE: TASK-04
    def reset(self) -> None:
        self.buffer = ""
        self.in_thought_box = False
        self.line_buffer = ""
        self.has_started_thought = False
        self.suppress_output = False

    def _open_box(self):
        if not self.in_thought_box:
            print(f"{COLORS['hunt']}┌{self.box_border}┐{COLORS['reset']}")
            print(f"{COLORS['hunt']}│  Threat Analysis:{' ' * (self.box_width - 22)}│{COLORS['reset']}")
            print(f"{COLORS['hunt']}├{self.box_border}┤{COLORS['reset']}")
            self.in_thought_box = True

    def _close_box(self):
        if self.in_thought_box:
            if self.line_buffer:
                self._print_box_line(self.line_buffer)
                self.line_buffer = ""
            print(f"{COLORS['hunt']}└{self.box_border}┘{COLORS['reset']}")
            self.in_thought_box = False

    def _print_box_line(self, text: str):
        text = text[:self.box_width - 4]
        padding = " " * (self.box_width - 4 - len(text))
        print(f"{COLORS['hunt']}│ {text}{padding} │{COLORS['reset']}")

    def _process_box_content(self, text: str):
        for char in text:
            if char == "\n":
                self._print_box_line(self.line_buffer)
                self.line_buffer = ""
            else:
                self.line_buffer += char
                if len(self.line_buffer) >= (self.box_width - 4):
                    self._print_box_line(self.line_buffer)
                    self.line_buffer = ""

    def process_token(self, token: str):
        self.buffer += token

        if not self.has_started_thought:
            if "THOUGHT:" in self.buffer:
                self.has_started_thought = True
                self._open_box()
                self.buffer = self.buffer.split("THOUGHT:", 1)[1]
            elif "ACTION:" in self.buffer or self.buffer.lstrip().startswith("{"):
                self.suppress_output = True
            elif "FINAL ANSWER:" in self.buffer:
                self.suppress_output = False

        if self.in_thought_box:
            end_markers = ["ACTION:", "FINAL ANSWER:", "{"]
            for marker in end_markers:
                if marker in self.buffer:
                    if marker == "{" and "ACTION" in self.buffer:
                        continue
                    parts = self.buffer.split(marker, 1)
                    self._process_box_content(parts[0])
                    self._close_box()
                    if "FINAL ANSWER:" in marker:
                        self.suppress_output = False
                        print(f"\n{parts[1]}", end="", flush=True)
                    else:
                        self.suppress_output = True
                    self.buffer = ""
                    return
            self._process_box_content(self.buffer)
            self.buffer = ""
        else:
            if "ACTION:" in self.buffer or (
                self.buffer.strip().startswith("{") and not self.has_started_thought
            ):
                self.suppress_output = True
            if not self.suppress_output:
                print(token, end="", flush=True)
                self.buffer = ""


# ─────────────────────────────────────────────────────────────────────────────
# Security Context Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_security_context(user_msg: str, mitre_data: Optional[dict] = None) -> str:
    """Inject MITRE ATT&CK context relevant to the user's request."""
    if not mitre_data:
        return ""

    lower = user_msg.lower()
    relevant = []

    techniques = mitre_data.get("techniques", {})
    for t_id, tech in techniques.items():
        t_name = tech.get("name", "").lower()
        # Simple keyword matching based on ID or long words in the name
        keywords = [t_id.lower()] + [w for w in t_name.split() if len(w) > 4]
        
        if any(kw in lower for kw in keywords):
            relevant.append(
                f"  [{t_id}] {tech.get('name','')}: {tech.get('description','')[:100]}"
            )

    if not relevant:
        return ""

    lines = "\n".join(relevant[:5])
    return f"\n MITRE ATT&CK Context:\n{lines}\n"


# ─────────────────────────────────────────────────────────────────────────────
# Main Investigation / Hunt Loop
# ─────────────────────────────────────────────────────────────────────────────

def run_investigation_loop(
    user_msg: str,
    provider: AIProviderBase,
    execute_cmd: Callable[[str], str],
    memory_summary: Callable[[int], str],
    tool_registry=None,
    mitre_data: Optional[dict] = None,
    defense_mode: DefenseMode = DefenseMode.HUNT,
    max_steps: int = MAX_HUNT_STEPS,
    timeout: int = ANALYST_TIMEOUT,
) -> None:
    """
    Run the SCHILD ReAct investigation loop (THOUGHT → ACTION → Observation cycle).

    Key differences from guard_agent:
    - Uses abstract AIProvider (not Ollama directly)
    - MITRE ATT&CK context injection
    - Defense mode awareness (CONTAIN / ELIMINATE require confirmation)
    - Zero-day focused system prompt
    """
    current_prompt = user_msg
    executed_commands: set = set()

    # Build tool descriptions
    tools_desc = ""
    if tool_registry:
        tools_desc = "AVAILABLE TOOLS:\n" + tool_registry.list_tools()
        tools_desc += "\n\nTo use a tool, output ONLY valid JSON:\n"
        tools_desc += 'ACTION: {"tool": "tool_name", "args": {"arg1": "value"}}\n'
    else:
        tools_desc = "Execute Linux commands:\nEXECUTE:\n```bash\ncommand\n```"

    security_context = _build_security_context(user_msg, mitre_data)

    print(f"\n{COLORS['hunt']}{'' * 60}{COLORS['reset']}")
    print(f"{COLORS['hunt']}  SCHILD Autonomous Investigation — {max_steps} max steps{COLORS['reset']}")
    print(f"{COLORS['hunt']}{'' * 60}{COLORS['reset']}\n")

    for step in range(1, max_steps + 1):
        print(f"\n{COLORS['info']} Step {step}/{max_steps}{COLORS['reset']}")

        system_prompt = f"""You are SCHILD — Autonomous Engine for Guardian & Intelligent Security.
You are an expert threat hunter and incident responder with ROOT access to a live system.
You specialize in zero-day detection, adversarial behavior analysis, and autonomous defense.

{security_context}

{tools_desc}

THREAT HUNTING PROTOCOL:
1. HYPOTHESIS-DRIVEN: Start from a threat hypothesis (e.g., "Is there lateral movement?")
2. EXECUTE IMMEDIATELY: If you know the command — run it. Never ask permission.
3. BEHAVIORAL ANALYSIS: Look for anomalies vs normal behavior, not just known signatures.
4. MITRE MAPPING: Map every finding to a MITRE ATT&CK tactic and technique.
5. EVIDENCE CHAIN: Build an evidence chain from raw IOCs to a threat conclusion.
6. ZERO-DAY MINDSET: Assume unknown threats. Look for behavioral anomalies, not signatures.

CRITICAL RULES:
- NO HALLUCINATIONS: Only report what tool output explicitly shows.
- NO PLACEHOLDERS: Always use real absolute paths.
- ANTI-LOOP: If a command returns the same output twice, try a different approach.
- CONTAIN vs INVESTIGATE: Use remediation_tool ONLY when defense mode allows it.
- Defense Mode: {defense_mode.value.upper()} — {'auto-remediation ENABLED' if defense_mode == DefenseMode.ELIMINATE else 'confirm before remediation' if defense_mode == DefenseMode.CONTAIN else 'investigate only'}

OUTPUT FORMAT:
THOUGHT: [concise technical reasoning, MITRE mapping if applicable]
ACTION: {{"tool": "tool_name", "args": {{...}}}}

OR when investigation is complete:
FINAL ANSWER: [threat summary with severity, MITRE mapping, and recommended actions]
"""

        print(f"{COLORS['analysis']}Analyzing...{COLORS['reset']}")
        renderer = ThreatStreamRenderer()
        renderer.reset()  # DONE: TASK-04 — safety reset

        try:
            response = provider.stream(
                current_prompt,
                system_prompt=system_prompt,
                tier=ModelTier.ANALYST,
                timeout=timeout,
                callback=renderer.process_token,
            )
            renderer._close_box()
        except Exception as e:
            print(f"{COLORS['error']}Provider error: {e}{COLORS['reset']}")
            renderer._close_box()  # DONE: TASK-04 — cleanly close any open box
            break

        if not response:
            print(f"{COLORS['error']}No response from AI provider.{COLORS['reset']}")
            break

        # ── Final Answer ─────────────────────────────────────────────────────
        if "FINAL ANSWER:" in response:
            final = response.split("FINAL ANSWER:", 1)[-1].strip()
            print(f"\n{COLORS['success']}{'' * 60}{COLORS['reset']}")
            print(f"{COLORS['success']} SCHILD Conclusion:{COLORS['reset']}")
            print(f"{COLORS['success']}{final}{COLORS['reset']}")
            print(f"{COLORS['success']}{'' * 60}{COLORS['reset']}")
            break

        # ── Parse Action ──────────────────────────────────────────────────────
        tool_executed = False

        if tool_registry:
            json_str = _extract_json_block(response)
            if json_str:
                result = _execute_tool_action_with_prompt(
                    json_str, tool_registry, executed_commands,
                    defense_mode,
                )
                if result is not None:
                    tool_executed, current_prompt = result
            elif "ACTION:" in response:
                print(f"{COLORS['error']}ACTION detected but no JSON found.{COLORS['reset']}")
                current_prompt = 'Error: Output ONLY valid JSON after ACTION:. Example: {"tool": "shell_tool", "args": {"command": "ls"}}'
                tool_executed = True

        # ── Legacy EXECUTE fallback ───────────────────────────────────────────
        if not tool_executed:
            match = re.search(r"EXECUTE:.*?```(?:bash)?\s*(.*?)\s*```", response, re.DOTALL)
            if match:
                cmd = match.group(1).strip()
                print(f"{COLORS['warning']} Command: {cmd}{COLORS['reset']}")
                output = execute_cmd(cmd)
                print(f"{COLORS['output']}{output[:600]}{COLORS['reset']}")
                current_prompt = f"Command Output:\n{output}\n\nNext step?"
                tool_executed = True

        if not tool_executed:
            print(f"{COLORS['chat']}AI: {response[:300]}{COLORS['reset']}")
            current_prompt = (
                'Proceed with next investigation step. '
                'Use ACTION: {"tool": "...", "args": {...}} or FINAL ANSWER:'
            )

    else:
        # Loop finished without breaking (no FINAL ANSWER generated)
        print(f"\n{COLORS['info']} Max steps reached. Generating final conclusion...{COLORS['reset']}")
        final_prompt = current_prompt + "\n\nCRITICAL INSTRUCTION: You have reached the maximum number of investigation steps. DO NOT output any THOUGHT or ACTION blocks. You must immediately provide a concise summary of the security status of the system based ONLY on the evidence gathered so far. Start your response directly with the summary."
        
        try:
            response = provider.complete(
                final_prompt,
                system_prompt=system_prompt,
                tier=ModelTier.ANALYST,
                timeout=timeout,
            )
            if "FINAL ANSWER:" in response:
                final = response.split("FINAL ANSWER:", 1)[-1].strip()
            else:
                final = response.strip()
                
            print(f"\n{COLORS['success']}{'' * 60}{COLORS['reset']}")
            print(f"{COLORS['success']} SCHILD Conclusion:{COLORS['reset']}")
            print(f"{COLORS['success']}{final}{COLORS['reset']}")
            print(f"{COLORS['success']}{'' * 60}{COLORS['reset']}")
        except Exception as e:
            print(f"{COLORS['error']}Failed to generate final conclusion: {e}{COLORS['reset']}")


def _extract_json_block(text: str) -> Optional[str]:
    """Extract the first complete JSON object from text."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _execute_tool_action_with_prompt(
    json_str: str,
    tool_registry,
    executed_commands: set,
    defense_mode: DefenseMode,
) -> Optional[tuple]:
    """
    Execute a tool action parsed from JSON string.
    Returns (tool_executed: bool, next_prompt: str) or None on parse failure.
    """
    try:
        action_data = json.loads(json_str)
    except json.JSONDecodeError:
        if json_repair:
            try:
                action_data = json_repair.repair_json(json_str, return_objects=True)
            except Exception:
                return None
        else:
            return None

    tool_name = action_data.get("tool", "")
    tool_args = action_data.get("args") or {}

    # Auto-correct bare shell commands mistaken as tool names
    shell_aliases = ["ps", "ls", "grep", "netstat", "cat", "find", "whoami", "id",
                     "ss", "last", "lastb", "awk", "sed"]
    if tool_name in shell_aliases and not tool_registry.get_tool(tool_name):
        arg_val = tool_args.get("pid") or tool_args.get("args") or ""
        tool_args = {"command": f"{tool_name} {arg_val}".strip()}
        tool_name = "shell_tool"
        print(f"{COLORS['warning']}↩  Auto-corrected → shell_tool{COLORS['reset']}")

    # Loop prevention
    sig = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
    if sig in executed_commands:
        print(f"{COLORS['warning']}  Loop prevented: duplicate command skipped.{COLORS['reset']}")
        return True, (
            f"Tool Output ({tool_name}):\n"
            "Error: This exact command was already executed. Use a DIFFERENT approach.\n"
            "Next step?"
        )
    executed_commands.add(sig)

    # Remediation guard
    if tool_name == "remediation_tool":
        if defense_mode == DefenseMode.OBSERVE:
            return True, (
                f"Tool Output ({tool_name}):\n"
                "Blocked: OBSERVE mode — remediation is disabled.\n"
                "Next step?"
            )
        if defense_mode in (DefenseMode.HUNT, DefenseMode.CONTAIN):
            print(f"{COLORS['critical']}️  SCHILD wants to execute remediation: {tool_args}{COLORS['reset']}")
            conf = input(f"{COLORS['warning']}Allow? (y/n): {COLORS['reset']}").lower().strip()
            if conf != "y":
                print(f"{COLORS['error']}Remediation denied by operator.{COLORS['reset']}")
                return True, (
                    f"Tool Output ({tool_name}):\n"
                    "Error: Operator denied this remediation.\n"
                    "Next step?"
                )

    # Execute tool
    tool = tool_registry.get_tool(tool_name)
    if not tool:
        print(f"{COLORS['error']}Tool '{tool_name}' not found.{COLORS['reset']}")
        return True, (
            f"Error: Tool '{tool_name}' not found. "
            f"Available: {tool_registry.list_tools()}"
        )

    print(f"{COLORS['ioc']} Tool: {tool_name} {tool_args}{COLORS['reset']}")
    try:
        output = tool.execute(**tool_args)
    except TypeError as e:
        output = f"Tool argument error: {e}"
    except Exception as e:
        output = f"Tool execution error: {e}"

    # Output filtering (hide self-references)
    if tool_name == "shell_tool":
        cmd_lower = tool_args.get("command", "").lower()
        if any(kw in cmd_lower for kw in ("ps", "netstat", "top", "ss")):
            lines = output.splitlines()
            output = "\n".join(
                l for l in lines
                if "schild" not in l.lower() and "openai" not in l.lower()
                and "anthropic" not in l.lower() and "googleapis" not in l.lower()  # DONE: TASK-05
            ) or "(filtered)"

    print(f"{COLORS['output']}{output[:600]}{COLORS['reset']}")

    next_hint = ""
    if "Error" in output and "Permission" in output:
        next_hint = "\nPERMISSION ERROR: Try with sudo or check if you have root."
    elif not output.strip():
        next_hint = "\nEMPTY RESULT: No matches found — this is valid. Try a different angle."

    return True, f"Tool Output ({tool_name}):\n{output}\n{next_hint}\nNext step?"


def _execute_tool_action(json_str, tool_registry, executed_commands, defense_mode, current_prompt, callback):
    """Shim — use _execute_tool_action_with_prompt instead."""
    result = _execute_tool_action_with_prompt(json_str, tool_registry, executed_commands, defense_mode)
    return result is not None and result[0]
