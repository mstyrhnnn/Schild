#!/usr/bin/env python3
"""
Test script untuk memverifikasi GUARD Agent installation
"""

import sys
import subprocess
import requests
import json

def test_ollama_connection(url="http://localhost:11434"):
    """Test koneksi ke Ollama"""
    print("Testing Ollama connection...")
    try:
        response = requests.get(f"{url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            print(f"✓ Ollama connected. Found {len(models)} models")
            if models:
                print(f"  Available models: {', '.join([m.get('name', '') for m in models[:5]])}")
            return True
        else:
            print(f"✗ Ollama returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Cannot connect to Ollama: {str(e)}")
        print("  Make sure Ollama is running: ollama serve")
        return False

def test_ollama_model(model="llama3.2:3b", url="http://localhost:11434"):
    """Test apakah model tersedia"""
    print(f"Testing model: {model}...")
    try:
        response = requests.get(f"{url}/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]
            if model in model_names:
                print(f"✓ Model {model} is available")
                return True
            else:
                print(f"✗ Model {model} not found")
                print(f"  Pull it with: ollama pull {model}")
                return False
    except Exception as e:
        print(f"✗ Error checking model: {str(e)}")
        return False

def test_ollama_generate(model="llama3.2:3b", url="http://localhost:11434"):
    """Test generate response dari Ollama"""
    print(f"Testing Ollama generate with {model}...")
    print("  Note: First request may take longer as model loads into memory...")
    try:
        payload = {
            "model": model,
            "prompt": "Say 'GUARD Agent test successful' if you can read this.",
            "stream": False
        }
        # Increase timeout to 120 seconds to account for model loading time
        response = requests.post(f"{url}/api/generate", json=payload, timeout=120)
        if response.status_code == 200:
            result = response.json().get("response", "")
            print(f"✓ Ollama generate works")
            print(f"  Response: {result[:100]}...")
            return True
        else:
            print(f"✗ Generate failed: {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        print(f"✗ Generate timeout: Model may be loading. Try again in a moment.")
        print(f"  You can test manually: curl -X POST {url}/api/generate -d '{{\"model\":\"{model}\",\"prompt\":\"test\"}}'")
        return False
    except Exception as e:
        print(f"✗ Generate error: {str(e)}")
        return False

def test_python_dependencies():
    """Test Python dependencies"""
    print("Testing Python dependencies...")
    try:
        import requests
        print("✓ requests module available")
        return True
    except ImportError:
        print("✗ requests module not found")
        print("  Install with: pip install requests")
        return False

def test_guard_agent_import():
    """Test import GuardAgent"""
    print("Testing GUARD Agent import...")
    try:
        # Try to import the agent
        sys.path.insert(0, '.')
        from AgentLinux import GuardAgent, GuardLevel
        print("✓ GuardAgent class imported successfully")
        return True
    except Exception as e:
        print(f"✗ Import error: {str(e)}")
        return False

def test_system_commands():
    """Test system commands yang digunakan agent"""
    print("Testing system commands...")
    commands = {
        "hostname": "hostname",
        "ip": "ip -brief address 2>/dev/null || ifconfig",
        "services": "systemctl list-units --type=service --state=running --no-legend 2>/dev/null | head -5",
        "ports": "ss -tuln 2>/dev/null | head -5 || netstat -tuln 2>/dev/null | head -5"
    }
    
    all_ok = True
    for name, cmd in commands.items():
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or result.stdout.strip():
                print(f"✓ {name} command works")
            else:
                print(f"⚠ {name} command returned no output (may be normal)")
        except Exception as e:
            print(f"✗ {name} command failed: {str(e)}")
            all_ok = False
    
    return all_ok

def main():
    print("=" * 60)
    print("GUARD Agent Test Suite")
    print("=" * 60)
    print()
    
    results = []
    
    # Test 1: Python dependencies
    results.append(("Python Dependencies", test_python_dependencies()))
    print()
    
    # Test 2: GuardAgent import
    results.append(("GuardAgent Import", test_guard_agent_import()))
    print()
    
    # Test 3: System commands
    results.append(("System Commands", test_system_commands()))
    print()
    
    # Test 4: Ollama connection
    results.append(("Ollama Connection", test_ollama_connection()))
    print()
    
    # Test 5: Model availability
    model = "llama3.2:3b"
    results.append(("Ollama Model", test_ollama_model(model)))
    print()
    
    # Test 6: Ollama generate (only if model available)
    if results[-1][1]:  # If model test passed
        results.append(("Ollama Generate", test_ollama_generate(model)))
        print()
    
    # Summary
    print("=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {test_name}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed! GUARD Agent is ready to use.")
        print("\nTo start GUARD Agent:")
        print("  python3 AgentLinux.py --level level1")
        return 0
    else:
        print("\n⚠ Some tests failed. Please fix the issues above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

