"""
Safe command execution utilities
"""

import re
import subprocess
from datetime import datetime
from typing import Dict, List

from schild.core.config import TOOL_TIMEOUT as COMMAND_EXECUTION_TIMEOUT, COLORS

# DONE: TASK-03 — Regex-based dangerous command detection
DANGEROUS_PATTERNS = [
    r'\brm\s+-rf\b',
    r'\bmkfs\b',
    r'\bdd\s+if=/dev/zero\b',
    r':\(\)\s*\{',           # fork bomb
    r'\bchmod\s+[0-7]*7[0-7]*\s+/',
    r'>\s*/dev/sd[a-z]',
    r'\b(shutdown|reboot|halt|poweroff)\b',
    r'\bsystemctl\s+(stop|disable|mask)\b',
]


def is_dangerous_command(command: str) -> bool:
    """
    Check if command contains dangerous patterns using regex.
    
    Args:
        command: Command string to check
        
    Returns:
        True if command is potentially dangerous
    """
    return any(re.search(p, command, re.IGNORECASE) for p in DANGEROUS_PATTERNS)


def execute_command(command: str, work_dir: str, history: List[Dict], logger_func=None) -> str:
    """
    Execute shell command safely with confirmation for dangerous commands.
    
    Args:
        command: Command to execute
        work_dir: Working directory
        history: Command history list to update
        logger_func: Optional logging function
        
    Returns:
        Command output or error message
    """
    try:
        # Check for dangerous commands
        if is_dangerous_command(command):
            confirm = input(f"{COLORS['warning']}WARNING: Dangerous command. Confirm? [y/N] {COLORS['reset']}")
            if confirm.lower() != 'y':
                return "Command cancelled\n"
        
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=COMMAND_EXECUTION_TIMEOUT,
            cwd=work_dir
        )
        
        output = result.stdout if result.returncode == 0 else result.stderr
        output = output if output.endswith('\n') else output + '\n'
        
        history.append({
            "command": command,
            "output": output,
            "success": result.returncode == 0,
            "timestamp": datetime.now().isoformat()
        })
        
        if logger_func:
            logger_func(f"Command executed: {command[:50]}", level="info")
        
        return output
    
    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {COMMAND_EXECUTION_TIMEOUT} seconds\n"
        history.append({
            "command": command,
            "output": error_msg,
            "success": False,
            "timestamp": datetime.now().isoformat()
        })
        return error_msg
    
    except Exception as e:
        error_msg = f"Error: {str(e)}\n"
        history.append({
            "command": command,
            "output": error_msg,
            "success": False,
            "timestamp": datetime.now().isoformat()
        })
        return error_msg
