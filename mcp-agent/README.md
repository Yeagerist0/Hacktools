# 🤖 HackStrike MCP Agent

An AI-powered bug bounty assistant that connects Claude to your security tools via the Model Context Protocol (MCP).

## Features

- 🎯 **Natural Language Interface**: Talk to the AI in plain English
- 🔧 **20+ Security Tools**: Subdomain enumeration, port scanning, vulnerability scanning, and more
- 🔌 **MCP Integration**: Works with Claude Desktop or as a standalone CLI
- 📊 **Automated Workflows**: Full reconnaissance and vulnerability assessment pipelines
- 📝 **Report Generation**: Automatic Markdown/JSON reports

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Claude AI     │────▶│   MCP Server    │────▶│  Security Tools │
│  (Your Brain)   │◀────│  (hackstrike)   │◀────│  (subfinder,    │
└─────────────────┘     └─────────────────┘     │   nuclei, etc.) │
                                                └─────────────────┘
```

## Prerequisites

- **Node.js 18+** - [Download](https://nodejs.org/)
- **Anthropic API Key** - [Get one here](https://console.anthropic.com/)
- **Security Tools** (install what you need):
  - Subdomain: `subfinder`, `amass`, `assetfinder`, `findomain`
  - Live hosts: `httpx`, `httprobe`
  - Ports: `nmap`, `naabu`
  - URLs: `gau`, `waybackurls`, `katana`, `hakrawler`
  - Vulns: `nuclei`, `dalfox`, `sqlmap`
  - Fuzzing: `ffuf`, `feroxbuster`
  - Other: `wafw00f`, `whatweb`, `arjun`

## Quick Start

### 1. Setup

```bash
cd mcp-agent
chmod +x setup.sh
./setup.sh
```

### 2. Configure API Key

```bash
# Option 1: Edit .env file
nano .env
# Add: ANTHROPIC_API_KEY=your_key_here

# Option 2: Environment variable
export ANTHROPIC_API_KEY=your_key_here
```

### 3. Run the CLI Agent

```bash
npm start
```

## Usage

### CLI Agent

The CLI provides an interactive chat interface:

```
hackstrike> scan example.com for vulnerabilities
🤖 I'll help you scan example.com. Let me start with reconnaissance...

⚡ Running: set_target
   ✓ Target set to example.com

⚡ Running: subdomain_enum
   ✓ Found 127 unique subdomains

⚡ Running: live_host_detection
   ✓ Found 45 live hosts

⚡ Running: vulnerability_scan
   🔥 Found 3 potential vulnerabilities!

🤖 I found some interesting results...
```

### Example Commands

```
hackstrike> find all subdomains of target.com
hackstrike> check target.com for XSS vulnerabilities
hackstrike> scan the ports of 192.168.1.1
hackstrike> look for exposed secrets on example.com
hackstrike> test https://example.com/page?id=1 for SQL injection
hackstrike> generate a report of all findings
hackstrike> help
```

### Claude Desktop Integration

Add the MCP server to Claude Desktop by editing your config file:

**Linux**: `~/.config/claude/claude_desktop_config.json`
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "hackstrike": {
      "command": "node",
      "args": ["/path/to/HackTools/mcp-agent/dist/server.js"],
      "env": {
        "HACKTOOLS_DIR": "/path/to/HackTools"
      }
    }
  }
}
```

Restart Claude Desktop, and you'll see the hackstrike tools available!

## Available Tools

| Tool | Description |
|------|-------------|
| `set_target` | Set the target domain for scanning |
| `get_target` | Get current target and output directory |
| `subdomain_enum` | Enumerate subdomains |
| `live_host_detection` | Find live/responsive hosts |
| `port_scan` | Scan for open ports |
| `url_collection` | Collect URLs from various sources |
| `vulnerability_scan` | Run Nuclei vulnerability scanner |
| `xss_scan` | Test for XSS with Dalfox |
| `sqli_scan` | Test for SQL injection with SQLMap |
| `directory_fuzz` | Fuzz for hidden directories |
| `tech_detect` | Detect technologies and frameworks |
| `waf_detect` | Detect Web Application Firewalls |
| `secret_scan` | Find exposed secrets and API keys |
| `param_discovery` | Discover hidden parameters |
| `cors_check` | Check for CORS misconfigurations |
| `subdomain_takeover` | Check for subdomain takeovers |
| `read_results` | Read scan result files |
| `list_results` | List all result files |
| `run_custom_command` | Run custom shell commands |
| `generate_report` | Generate a summary report |

## Project Structure

```
mcp-agent/
├── src/
│   ├── server.ts      # MCP server with bug bounty tools
│   └── cli.ts         # Interactive CLI agent
├── dist/              # Compiled JavaScript
├── package.json
├── tsconfig.json
├── setup.sh
├── .env.example
└── README.md
```

## Development

```bash
# Development mode with hot reload
npm run dev

# Run MCP server only (for debugging)
npm run server:dev

# Build for production
npm run build
```

## Output Structure

Results are saved in `HackTools/results/<target>_<timestamp>/`:

```
example.com_20241130_120000/
├── subdomains/
│   ├── subfinder.txt
│   ├── amass.txt
│   └── all_subdomains.txt
├── urls/
│   ├── gau.txt
│   ├── wayback.txt
│   ├── all_urls.txt
│   └── params_urls.txt
├── ports/
│   └── port_scan.txt
├── vulns/
│   ├── nuclei_results.txt
│   └── xss_results.txt
├── secrets/
├── params/
└── reports/
    └── report.md
```

## Security Notice

⚠️ **IMPORTANT**: Only use this tool on targets you have explicit authorization to test. Unauthorized scanning is illegal and unethical.

## Troubleshooting

### API Key Issues
```bash
# Check if key is set
echo $ANTHROPIC_API_KEY

# Set temporarily for testing
ANTHROPIC_API_KEY=your_key npm start
```

### Tool Not Found
Make sure security tools are in your PATH:
```bash
which subfinder nuclei httpx
```

### MCP Connection Issues
```bash
# Test the server standalone
node dist/server.js

# Check for Node.js version
node --version  # Should be 18+
```

## Contributing

PRs welcome! Please follow the existing code style and add tests for new features.

## License

MIT License - See LICENSE file for details.

---

Made with ❤️ for the bug bounty community
