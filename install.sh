#!/bin/bash

# GUARD Agent Installation Script
# Script untuk menginstall dan setup GUARD Agent di sistem Linux

set -e

echo "=========================================="
echo "GUARD Agent Installation Script"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${YELLOW}Warning: Running as root. Some commands may need sudo.${NC}"
fi

# Step 1: Check Python
echo "[1/6] Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}✗ Python3 not found. Please install Python 3.7+${NC}"
    exit 1
fi

# Step 2: Setup Virtual Environment
echo "[2/6] Setting up Python virtual environment..."
VENV_DIR="venv"

# Check if venv already exists
if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}⚠ Virtual environment already exists${NC}"
    read -p "Recreate virtual environment? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        python3 -m venv "$VENV_DIR"
        echo -e "${GREEN}✓ Virtual environment recreated${NC}"
    fi
else
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"
echo -e "${GREEN}✓ Virtual environment activated${NC}"

# Upgrade pip inside venv
pip install --upgrade pip -q
echo -e "${GREEN}✓ pip upgraded${NC}"

# Step 3: Install Python dependencies
echo "[3/6] Installing Python dependencies..."
pip install -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 4: Check Ollama
echo "[4/6] Checking Ollama installation..."
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}✓ Ollama found${NC}"
    
    # Check if Ollama service is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Ollama service is running${NC}"
    else
        echo -e "${YELLOW}⚠ Ollama service not running. Starting...${NC}"
        ollama serve > /dev/null 2>&1 &
        sleep 2
    fi
    
    # Check for recommended models
    echo "Checking for recommended models..."
    MODELS=$(ollama list 2>/dev/null | grep -E "baronllm|llama3.2:3b|qwen2.5:7b" || echo "")
    
    if [ -z "$MODELS" ]; then
        echo -e "${YELLOW}⚠ No recommended models found.${NC}"
        read -p "Pull default model (qwen2.5-coder:7b)? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Pulling qwen2.5-coder:7b (this may take a while)..."
            ollama pull qwen2.5-coder:7b
        fi
    else
        echo -e "${GREEN}✓ Found recommended models${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Ollama not found${NC}"
    read -p "Install Ollama? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Installing Ollama..."
        curl -fsSL https://ollama.com/install.sh | sh
        
        # Pull default model
        echo "Pulling default model (qwen2.5-coder:7b)..."
        ollama pull qwen2.5-coder:7b
    else
        echo -e "${RED}✗ Ollama is required for GUARD Agent${NC}"
        exit 1
    fi
fi

# Step 5: Create systemd service (optional)
echo "[5/6] Creating systemd service (optional)..."
read -p "Create systemd service for auto-start? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/guard-agent.service"
    AGENT_PATH=$(pwd)
    USER=$(whoami)
    
    sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=GUARD Agent - Linux Security Monitoring
After=network.target ollama.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$AGENT_PATH
ExecStart=$AGENT_PATH/venv/bin/python $AGENT_PATH/guard_agent/cli/main.py chat
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}✓ Service file created at $SERVICE_FILE${NC}"
    echo "To enable: sudo systemctl enable guard-agent"
    echo "To start: sudo systemctl start guard-agent"
fi

# Step 6: Create config file
echo "[6/6] Creating configuration..."
read -p "GUARD Level (level1/level2/level3, default: level1): " GUARD_LEVEL
GUARD_LEVEL=${GUARD_LEVEL:-level1}
read -p "Ollama model (default: qwen2.5-coder:7b): " OLLAMA_MODEL
OLLAMA_MODEL=${OLLAMA_MODEL:-qwen2.5-coder:7b}

CONFIG_FILE="guard_config.json"
cat > $CONFIG_FILE <<EOF
{
  "ollama_model": "$OLLAMA_MODEL",
  "ollama_url": "http://localhost:11434",
  "guard_level": "$GUARD_LEVEL"
}
EOF

echo -e "${GREEN}✓ Configuration saved to $CONFIG_FILE${NC}"

# Summary
echo ""
echo "=========================================="
echo -e "${GREEN}Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Virtual environment created at: $(pwd)/venv"
echo ""
echo "To run GUARD Agent:"
echo "  # Option 1: Activate venv first"
echo "  source venv/bin/activate"
echo "  python3 guard_agent/cli/main.py chat"
echo ""
echo "  # Option 2: Use venv Python directly"
echo "  ./venv/bin/python3 guard_agent/cli/main.py chat"
echo ""
echo "Or use the config file (if implemented in main):"
echo "  ./venv/bin/python3 guard_agent/cli/main.py chat --config $CONFIG_FILE"
echo ""
echo ""

