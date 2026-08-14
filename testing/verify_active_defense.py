import sys
import os
from unittest.mock import MagicMock, patch

# Adjust path to import guard_agent
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from guard_agent.core.tools import RemediationTool
from guard_agent.knowledge.security_knowledge import SecurityKnowledge
from guard_agent.core.config import GuardLevel, GUARD_LEVEL

def test_remediation_whitelist():
    print("\n--- Testing RemediationTool Safety & Whitelist ---")
    tool = RemediationTool()
    
    # Test 1: Block Local IP (Should Fail)
    res = tool.execute(action="block_ip", target="127.0.0.1")
    if "Safety Triggered" in res:
        print("PASS: Block Local IP prevented.")
    else:
        print(f"FAIL: Block Local IP allowed! Output: {res}")
        return False

    # Test 2: Block Private IP (Should Fail)
    res = tool.execute(action="block_ip", target="192.168.1.5")
    if "Safety Triggered" in res:
         print("PASS: Block Private IP prevented.")
    else:
         print(f"FAIL: Block Private IP allowed! Output: {res}")
         return False

    # Test 3: Isolate Critical Service (Should Fail)
    res = tool.execute(action="isolate_service", target="ssh")
    if "not in whitelist" in res:
         print("PASS: Isolate Critical Service (ssh) prevented.")
    else:
         print(f"FAIL: Isolate Critical Service (ssh) allowed! Output: {res}")
         return False

    # Test 4: Isolate Valid Service (Should Pass/Mocked)
    # We mock subprocess to allow "success"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        
        res = tool.execute(action="isolate_service", target="nginx")
        if "Remediation applied successfully" in res and mock_run.called:
             print("PASS: Isolate Valid Service (nginx) allowed.")
        else:
             print(f"FAIL: Isolate Valid Service failed. Output: {res}")
             return False
             
    return True

def test_playbooks():
    print("\n--- Testing Security Playbooks ---")
    sk = SecurityKnowledge()
    
    # Test T1110 (Brute Force) -> Should have Block Attacker
    pb = sk.get_playbook("T1110")
    has_block = any(step.get("tool") == "remediation_tool" and step["args"].get("action") == "block_ip" for step in pb)
    
    if has_block:
        print("PASS: T1110 Playbook contains active 'block_ip' step.")
    else:
        print("FAIL: T1110 Playbook missing active defense step.")
        return False
        
    return True

if __name__ == "__main__":
    t1 = test_remediation_whitelist()
    t2 = test_playbooks()
    
    if t1 and t2:
        print("\nALL ACTIVE DEFENSE CHECKS PASSED.")
    else:
        print("\nSOME CHECKS FAILED.")
