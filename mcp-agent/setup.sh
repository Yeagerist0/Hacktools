#!/bin/bash

#====================================================================
#  HackStrike MCP Agent Setup Script
#====================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

echo -e "${RED}"
cat << "EOF"
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
EOF
echo -e "${NC}"
echo -e "${BLUE}    MCP Agent Setup${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check Node.js
info "Checking Node.js..."
if ! command -v node &> /dev/null; then
    error "Node.js is not installed!"
    echo "Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    error "Node.js version 18+ required (found: $(node -v))"
    exit 1
fi
log "Node.js $(node -v) ✓"

# Check npm
if ! command -v npm &> /dev/null; then
    error "npm is not installed!"
    exit 1
fi
log "npm $(npm -v) ✓"

# Install dependencies
info "Installing dependencies..."
npm install

# Build TypeScript
info "Building TypeScript..."
npm run build

log "Build complete!"

# Create .env if not exists
if [ ! -f ".env" ]; then
    info "Creating .env file..."
    cp .env.example .env
    warn "Please edit .env and add your Anthropic API key"
fi

# Setup Claude Desktop config
CLAUDE_CONFIG_DIR="$HOME/.config/claude"
if [ -d "$CLAUDE_CONFIG_DIR" ] || [ -d "$HOME/Library/Application Support/Claude" ]; then
    info "Claude Desktop detected"
    
    if [ -d "$HOME/Library/Application Support/Claude" ]; then
        CLAUDE_CONFIG_DIR="$HOME/Library/Application Support/Claude"
    fi
    
    echo ""
    echo -e "${YELLOW}To use with Claude Desktop, add this to your claude_desktop_config.json:${NC}"
    echo ""
    cat << EOF
{
  "mcpServers": {
    "hackstrike": {
      "command": "node",
      "args": ["$SCRIPT_DIR/dist/server.js"],
      "env": {
        "HACKTOOLS_DIR": "$(dirname "$SCRIPT_DIR")"
      }
    }
  }
}
EOF
    echo ""
fi

# Make CLI executable
chmod +x dist/cli.js 2>/dev/null || true

echo ""
log "Setup complete!"
echo ""
echo -e "${GREEN}Usage:${NC}"
echo ""
echo "  ${BLUE}CLI Agent:${NC}"
echo "    npm start"
echo "    # or"
echo "    node dist/cli.js"
echo ""
echo "  ${BLUE}MCP Server only:${NC}"
echo "    npm run server"
echo ""
echo "  ${BLUE}Development mode:${NC}"
echo "    npm run dev"
echo ""
echo -e "${YELLOW}Note: Make sure to set your ANTHROPIC_API_KEY in .env or environment${NC}"
echo ""
