
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from guard_agent.core.tools import WebSearchTool

class TestWebSearch(unittest.TestCase):
    @patch('guard_agent.core.tools.requests.get')
    def test_search_execution(self, mock_get):
        # Mock SearXNG response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "title": "CVE-2023-1234 Detail",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                    "content": "This is a critical vulnerability."
                },
                {
                    "title": "Exploit DB",
                    "url": "https://exploit-db.com/123",
                    "content": "PoC available."
                }
            ]
        }
        mock_get.return_value = mock_response

        tool = WebSearchTool()
        result = tool.execute("CVE-2023-1234")
        
        print("Search Result:\n", result)
        
        self.assertIn("CVE-2023-1234 Detail", result)
        self.assertIn("Exploit DB", result)
        self.assertIn("https://nvd.nist.gov", result)

if __name__ == '__main__':
    unittest.main()
