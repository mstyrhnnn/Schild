
import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from guard_agent.ai.investigator import run_investigation_loop
from guard_agent.core.tools import ToolRegistry, ShellTool

class TestInvestigatorLogic(unittest.TestCase):
    
    def test_output_filtering(self):
        """Test that 'ollama' processes are filtered from shell_tool output in run_investigation_loop."""
        
        # We need to capture the print output or mock the internals. 
        # Since the logic is inside the loop and modifies 'output' variable before printing/prompting,
        # it's hard to test without refactoring or deep mocking.
        # However, we can mock the tool execution and check what happens *after* in the prompt or print.
        
        # Let's mock the entire ToolRegistry and a ShellTool
        mock_registry = MagicMock(spec=ToolRegistry)
        mock_tool = MagicMock()
        mock_registry.get_tool.return_value = mock_tool
        
        # The tool returns output containing 'ollama'
        mock_tool.execute.return_value = "root 123 0.1 ollama runner\nroot 456 0.0 other_process"
        
        # We also need to mock ollama_get_response to break the loop after 1 step
        # It needs to return a valid JSON action 

        mock_llm = MagicMock(side_effect=[
            'ACTION: {"tool": "shell_tool", "args": {"command": "ps aux"}}',
            'FINAL ANSWER: Done'
        ])
        
        # We need to capture stdout to verify the filtering
        from io import StringIO
        captured_output = StringIO()
        sys.stdout = captured_output
        
        try:
            run_investigation_loop(
                user_msg="Check processes",
                ollama_get_response=mock_llm,
                execute_cmd=MagicMock(),
                memory_summary=MagicMock(),
                max_steps=1,
                tool_registry=mock_registry
            )
        finally:
            sys.stdout = sys.__stdout__
            
        output_str = captured_output.getvalue()
        
        print("\nCaptured Output Fragment:")
        print(output_str[:500])
        
        # Check if 'ollama' is present in the "Tool Output" section implicitly printed
        # Wait, the code prints `COLORS['output'] + output + ...`
        # If filtering works, "ollama runner" should NOT be in the printed output lines corresponding to the tool result.
        # Note: 'ollama' might appear in the "AI wants to execute..." or debug lines, 
        # but we are looking for the tool output block.
        # The tool output mock was: "root 123 0.1 ollama runner\nroot 456 0.0 other_process"
        
        self.assertNotIn("ollama runner", output_str, "Filtering failed: 'ollama runner' found in output.")
        self.assertIn("other_process", output_str, "Filtering too aggressive: 'other_process' missing.")

if __name__ == '__main__':
    unittest.main()
