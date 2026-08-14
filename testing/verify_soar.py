import sys
import os
import subprocess
import time
from unittest.mock import MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from guard_agent.core.agent import GuardAgent
from guard_agent.core.tools import ToolRegistry

def test_soar_wiring():
    print("Testing SOAR Wiring (Smart Scan)...")
    
    agent = GuardAgent()
    
    # Mock LLM to simulate the new "Smart" behavior
    # Step 1: LLM should request system_scan
    mock_responses = [
        # Step 1 Response
"""THOUGHT: I should start with a system situation report using shell commands.
ACTION: {"tool": "shell_tool", "args": {"command": "w"}}""",
        
        # Step 2 Response (Action based on scan)
"""THOUGHT: I see a suspicious process. Let's check logs.
ACTION: {"tool": "shell_tool", "args": {"command": "grep 'Failed password' /var/log/auth.log | tail"}}"""
    ]

    
    agent.ollama.get_response = MagicMock(side_effect=mock_responses)
    
    try:
        from guard_agent.ai.investigator import run_investigation_loop
        print("Running loop...")
        run_investigation_loop(
            user_msg="Check suspicious activity",
            ollama_get_response=agent.get_ollama_response,
            execute_cmd=agent.execute,
            memory_summary=lambda x: "",
            max_steps=2,
            tool_registry=agent.tool_registry
        )
        print(" Loop finished. LLM correctly called detailed tools.")
        
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    test_soar_wiring()
