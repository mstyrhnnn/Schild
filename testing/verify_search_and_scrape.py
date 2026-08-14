import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from guard_agent.core.tools import WebSearchTool, WebScraperTool

class TestWebTools(unittest.TestCase):
    @patch('guard_agent.core.tools.requests.get')
    def test_search_execution(self, mock_get):
        # Mock SearXNG response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"title": f"Result {i}", "url": f"http://test.com/{i}", "content": "test"} 
                for i in range(1, 10) # Return more than 5 to test limit
            ]
        }
        mock_get.return_value = mock_response

        tool = WebSearchTool()
        result = tool.execute("CVE-2023-1234")
        
        print("Search Result:\n", result)
        
        # Check if domain restriction is applied in the query
        # access call args to verify
        # args, kwargs = mock_get.call_args
        # self.assertIn("site:attack.mitre.org", kwargs['params']['q'])
        
        # Check limit of 5
        self.assertIn("5. Result 5", result)
        self.assertNotIn("6. Result 6", result)

    @patch('guard_agent.core.tools.requests.get')
    def test_scraper_execution(self, mock_get):
        # Mock HTML response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body><h1>Test Header</h1><p>Test content.</p><script>bad()</script></body></html>"
        mock_get.return_value = mock_response

        tool = WebScraperTool()
        result = tool.execute("http://example.com")

        print("Scraper Result:\n", result)

        self.assertIn("Test Header", result)
        self.assertIn("Test content", result)
        self.assertNotIn("bad()", result)

if __name__ == '__main__':
    unittest.main()
