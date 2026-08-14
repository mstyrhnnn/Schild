
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from guard_agent.core.tools import RemediationTool, ToolRegistry
from guard_agent.knowledge.security_knowledge import SecurityKnowledge

class TestSecurityFixes(unittest.TestCase):
    
    def setUp(self):
        self.tool = RemediationTool()
        # Mock _run_root_cmd to prevent actual execution
        self.tool._run_root_cmd = MagicMock(return_value="Mock Success")

    def test_remediation_tool_block_ip_injection(self):
        """Test that command injection is prevented in block_ip action."""
        # Attempt injection: valid-looking start but with malicious append
        target = "1.2.3.4; rm -rf /"
        
        # This should fail validation because it's not a valid IP
        result = self.tool.execute(action="block_ip", target=target)
        
        print(f"\n[Test block_ip injection] Target: '{target}' -> Result: '{result}'")
        self.assertIn("Error", result)
        self.assertIn("Invalid IP", result)
        self.tool._run_root_cmd.assert_not_called()

    def test_remediation_tool_valid_ip(self):
        """Test that valid IP works."""
        target = "192.168.1.100" 
        # Note: Local IPs are blocked by safety check, so use a public one for "success" path test or expect safety error
        # Let's use a public IP to test the success path
        target_public = "8.8.8.8"
        
        result = self.tool.execute(action="block_ip", target=target_public)
        print(f"\n[Test block_ip valid] Target: '{target_public}' -> Result: '{result}'")
        
        self.assertEqual(result, "Mock Success")
        # Verify shlex.quote was used (arg passed to _run_root_cmd)
        call_args = self.tool._run_root_cmd.call_args[0][0]
        self.assertIn("ufw deny from 8.8.8.8 to any", call_args)

    def test_remediation_tool_isolate_service_injection(self):
        """Test that command injection is prevented in isolate_service."""
        target = "nginx; rm -rf /"
        result = self.tool.execute(action="isolate_service", target=target)
        
        print(f"\n[Test isolate_service injection] Target: '{target}' -> Result: '{result}'")
        self.assertIn("Error", result)
        self.assertIn("not in whitelist", result)
        self.tool._run_root_cmd.assert_not_called()

    def test_security_knowledge_playbooks_valid_tools(self):
        """Verify that all tools in playbooks actually exist in ToolRegistry."""
        kb = SecurityKnowledge()
        registry = ToolRegistry()
        
        # Techniques we modified
        techniques = ["T1110", "T1053"]
        
        for tech_id in techniques:
            playbook = kb.get_playbook(tech_id)
            print(f"\n[Test Playbook {tech_id}] Steps: {len(playbook)}")
            for step in playbook:
                tool_name = step.get("tool")
                print(f"  - Step: {step.get('name')}, Tool: {tool_name}")
                
                # Check if tool is registered
                tool_instance = registry.get_tool(tool_name)
                if not tool_instance:
                    self.fail(f"Playbook {tech_id} uses unknown tool: '{tool_name}'")
                else:
                    print(f"    -> OK (Found {tool_instance.name})")

if __name__ == '__main__':
    unittest.main()
