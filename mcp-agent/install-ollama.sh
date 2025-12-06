#!/bin/bash

#====================================================================
#  Install Ollama for FREE AI-powered bug bounty
#====================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     Installing Ollama (FREE Local AI)                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if already installed
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}[+] Ollama is already installed!${NC}"
    ollama --version
else
    echo -e "${YELLOW}[*] Installing Ollama...${NC}"
    curl -fsSL https://ollama.com/install.sh | sh
    echo -e "${GREEN}[+] Ollama installed!${NC}"
fi

# Start Ollama service
echo -e "${YELLOW}[*] Starting Ollama service...${NC}"
if pgrep -x "ollama" > /dev/null; then
    echo -e "${GREEN}[+] Ollama is already running${NC}"
else
    ollama serve &
    sleep 3
    echo -e "${GREEN}[+] Ollama started${NC}"
fi

# Pull a model
echo ""
echo -e "${YELLOW}[*] Pulling llama3.2 model (this may take a few minutes)...${NC}"
echo -e "${BLUE}    This is a ~2GB download, but it's FREE and runs locally!${NC}"
echo ""

ollama pull llama3.2

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[+] Setup complete!${NC}"
echo ""
echo -e "${YELLOW}To run the FREE AI agent:${NC}"
echo -e "  ${BLUE}cd /home/hitarth/HackTools/mcp-agent${NC}"
echo -e "  ${BLUE}npm run start:free${NC}"
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
