import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guard_agent.integrations.ollama_client import OllamaClient

def verify_model():
    model_name = "qwen2.5-coder:7b"
    print(f"Testing model: {model_name}")
    
    client = OllamaClient(model=model_name)
    
    # 1. Verify Connection
    print("\n[1] Verifying connection...")
    if client.verify_connection():
        print("Success: Connection verified and model found.")
    else:
        print("Failed: Connection or model check failed.")
        
    # 2. Test Generation
    print("\n[2] Testing generation...")
    response = client.get_response("Say hello", stream=False, timeout=30)
    print(f"Response: {response}")

if __name__ == "__main__":
    verify_model()
