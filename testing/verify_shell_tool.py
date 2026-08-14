import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from guard_agent.core.tools import ShellTool

class TestShellTool(unittest.TestCase):
    def test_safe_command(self):
        tool = ShellTool()
        result = tool.execute("echo 'hello world'")
        self.assertEqual(result.strip(), "hello world")

    def test_dangerous_command(self):
        tool = ShellTool()
        result = tool.execute("rm -rf /")
        self.assertIn("blocked for safety", result)

    def test_pipe_command(self):
        tool = ShellTool()
        result = tool.execute("echo 'hello' | tr 'a-z' 'A-Z'")
        self.assertEqual(result.strip(), "HELLO")

if __name__ == '__main__':
    unittest.main()
