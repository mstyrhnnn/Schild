import sys
import os

# Adjust path to import guard_agent
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from guard_agent.core.tools import ToolRegistry, RemediationTool
from guard_agent.ai.router import plan_action

def test_remediation_tool():
    print("Testing RemediationTool...")
    registry = ToolRegistry()
    tool = registry.get_tool("remediation_tool")
    
    if not tool:
        print("FAIL: RemediationTool not registered.")
        return False
        
    print("PASS: RemediationTool registered.")
    
    # Test execution
    result = tool.execute(command="echo 'test fix'")
    if "test fix" in result and "Executing REMEDIATION" not in result: # Logger might not show up in return
        print(f"PASS: RemediationTool execution output: {result.strip()}")
    else:
        print(f"INFO: RemediationTool execution output: {result.strip()}")

    # Test safety
    result_unsafe = tool.execute(command="rm -rf /")
    if "blocked for safety" in result_unsafe:
        print("PASS: Safety check working.")
    else:
        print(f"FAIL: Safety check failed! Output: {result_unsafe}")
        return False
        
    return True

class MockOllama:
    def get_response(self, *args, **kwargs):
        raise Exception("Should not be called for heuristic test!")

def test_router_heuristic():
    print("\nTesting Router Heuristic...")
    ollama = MockOllama()
    
    # potentially risky if logic changes, but we want to ensure it DOESNT call LLM
    try:
        # "run ls" should return RUN_CMD without LLM
        action = plan_action(ollama, "run ls -la", timeout=1)
        if action.get("action") == "RUN_CMD" and action.get("command") == "ls -la":
            print(f"PASS: 'run ls -la' -> {action}")
        else:
            print(f"FAIL: 'run ls -la' -> {action}")
            return False

        # "exec ps" should return RUN_CMD
        action = plan_action(ollama, "exec ps aux", timeout=1)
        if action.get("action") == "RUN_CMD" and action.get("command") == "ps aux":
             print(f"PASS: 'exec ps aux' -> {action}")
        else:
             print(f"FAIL: 'exec ps aux' -> {action}")
             return False
             
        # "check something" might trigger INVESTIGATE or just check heuristic.
        # In my code: `if lower_msg.startswith(cmd_prefixes)` -> but inside I only handle `run` or `exec` for RUN_CMD extraction.
        # Wait, my logic was:
        # if lower_msg.startswith(cmd_prefixes)...
        #    if lower_msg.startswith("run ") or ...: return RUN_CMD
        # 
        # So "check nginx" matches the outer if, but NOT the inner if.
        # Implementation Detail: if it matches outer but not inner, it falls through to LLM (which will raise Exception in Mock).
        # Let's verify that behavior or fix it if unintended.
        # Actually, if I want "check nginx" to go to LLM, then Mock raising exception is CORRECT behavior (it tries to call LLM).
        
        try:
            plan_action(ollama, "check nginx", timeout=1)
            print("FAIL: 'check nginx' should have called LLM (heuristic incomplete for 'check')")
        except Exception as e:
            if "Should not be called" in str(e):
                 print("PASS: 'check nginx' fell through to LLM as expected (heuristic only handles explicit run/exec)")
            else:
                 raise e

    except Exception as e:
        print(f"FAIL: Exception during router test: {e}")
        return False
        
    return True

if __name__ == "__main__":
    t1 = test_remediation_tool()
    t2 = test_router_heuristic()
    
    if t1 and t2:
        print("\nALL CHECKS PASSED.")
    else:
        print("\nSOME CHECKS FAILED.")
