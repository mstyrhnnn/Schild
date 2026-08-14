import requests
import os

def test_search():
    instances = [
        "https://searx.aicamp.cn/search",
        "https://search.mdosch.de/search",
        "https://searx.prvcy.eu/search",
        "https://s.zhaocloud.net/search",
        "https://search.inetol.net/search"
    ]
    
    query = "linux check failed logins"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    print("Testing SearXNG Instances...")
    
    for url in instances:
        print(f"\n--- Testing {url} ---")
        try:
            res = requests.get(url, params={"q": query, "format": "json"}, headers=headers, timeout=5)
            print(f"Status: {res.status_code}")
            if res.status_code == 200:
                print("SUCCESS! Found working instance.")
                try:
                    data = res.json()
                    print(f"Results found: {len(data.get('results', []))}")
                    break
                except:
                    print("Error parsing JSON")
            else:
                print("Failed")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_search()

