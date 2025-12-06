#!/usr/bin/env node
/**
 * HackStrike AI Agent CLI
 * Interactive CLI that connects Claude to bug bounty tools via MCP
 */

import Anthropic from "@anthropic-ai/sdk";
import { spawn, ChildProcess } from "child_process";
import * as readline from "readline";
import * as path from "path";
import * as fs from "fs";

// ANSI Colors
const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
};

const c = colors;

// Configuration
const CONFIG_DIR = path.join(process.env.HOME || "~", ".hackstrike");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

interface Config {
  anthropic_api_key?: string;
  model?: string;
  hacktools_dir?: string;
}

interface MCPMessage {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: any;
  result?: any;
  error?: any;
}

interface Tool {
  name: string;
  description: string;
  inputSchema: any;
}

// MCP Client for communicating with the server
class MCPClient {
  private process: ChildProcess | null = null;
  private messageId = 0;
  private pendingRequests: Map<number, { resolve: Function; reject: Function }> = new Map();
  private buffer = "";

  async connect(serverPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.process = spawn("node", [serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      this.process.stdout?.on("data", (data: Buffer) => {
        this.buffer += data.toString();
        this.processBuffer();
      });

      this.process.stderr?.on("data", (data: Buffer) => {
        // Server logs go to stderr
        const msg = data.toString().trim();
        if (msg && !msg.includes("running")) {
          console.error(`${c.dim}[MCP] ${msg}${c.reset}`);
        }
      });

      this.process.on("error", (err) => {
        reject(err);
      });

      this.process.on("exit", (code) => {
        if (code !== 0) {
          console.error(`${c.red}MCP server exited with code ${code}${c.reset}`);
        }
      });

      // Initialize the connection
      setTimeout(async () => {
        try {
          await this.initialize();
          resolve();
        } catch (err) {
          reject(err);
        }
      }, 500);
    });
  }

  private processBuffer() {
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.trim()) {
        try {
          const message: MCPMessage = JSON.parse(line);
          if (message.id !== undefined && this.pendingRequests.has(message.id)) {
            const { resolve, reject } = this.pendingRequests.get(message.id)!;
            this.pendingRequests.delete(message.id);
            if (message.error) {
              reject(new Error(message.error.message));
            } else {
              resolve(message.result);
            }
          }
        } catch (e) {
          // Ignore non-JSON lines
        }
      }
    }
  }

  private async sendRequest(method: string, params: any = {}): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = ++this.messageId;
      const message: MCPMessage = {
        jsonrpc: "2.0",
        id,
        method,
        params,
      };

      this.pendingRequests.set(id, { resolve, reject });
      this.process?.stdin?.write(JSON.stringify(message) + "\n");

      // Timeout after 5 minutes for long-running operations
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error("Request timed out"));
        }
      }, 300000);
    });
  }

  private async initialize(): Promise<void> {
    await this.sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: {
        name: "hackstrike-cli",
        version: "1.0.0",
      },
    });
    await this.sendRequest("notifications/initialized", {});
  }

  async listTools(): Promise<Tool[]> {
    const result = await this.sendRequest("tools/list", {});
    return result.tools || [];
  }

  async callTool(name: string, args: any): Promise<any> {
    const result = await this.sendRequest("tools/call", {
      name,
      arguments: args,
    });
    return result;
  }

  disconnect() {
    this.process?.kill();
    this.process = null;
  }
}

// Load or create configuration
function loadConfig(): Config {
  try {
    if (!fs.existsSync(CONFIG_DIR)) {
      fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }
    if (fs.existsSync(CONFIG_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
    }
  } catch (e) {
    // Ignore
  }
  return {};
}

function saveConfig(config: Config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

// Banner
function printBanner() {
  console.log(`${c.red}
    ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
    ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
    ███████║███████║██║     █████╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
    ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
    ██║  ██║██║  ██║╚██████╗██║  ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
  console.log(`${c.white}              🤖 AI-Powered Bug Bounty Agent ${c.yellow}v1.0${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
  console.log();
}

// AI Agent class
class HackStrikeAgent {
  private anthropic: Anthropic;
  private mcpClient: MCPClient;
  private tools: Tool[] = [];
  private conversationHistory: Array<{ role: "user" | "assistant"; content: string | any[] }> = [];
  private model: string;

  constructor(apiKey: string, model: string = "claude-sonnet-4-20250514") {
    this.anthropic = new Anthropic({ apiKey });
    this.mcpClient = new MCPClient();
    this.model = model;
  }

  async initialize(): Promise<void> {
    // Find the server path
    const serverPath = path.join(__dirname, "server.js");
    
    console.log(`${c.blue}[*] Starting MCP server...${c.reset}`);
    await this.mcpClient.connect(serverPath);
    
    console.log(`${c.blue}[*] Loading tools...${c.reset}`);
    this.tools = await this.mcpClient.listTools();
    console.log(`${c.green}[+] Loaded ${this.tools.length} bug bounty tools${c.reset}`);
  }

  private formatToolsForClaude(): Anthropic.Tool[] {
    return this.tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.inputSchema as Anthropic.Tool.InputSchema,
    }));
  }

  private getSystemPrompt(): string {
    return `You are HackStrike AI, an expert bug bounty hunter and penetration tester assistant. 
You help security researchers find vulnerabilities in web applications.

Your capabilities include:
- Subdomain enumeration and discovery
- Live host detection
- Port scanning
- URL collection and crawling
- Vulnerability scanning with Nuclei
- XSS and SQL injection testing
- Directory fuzzing
- Technology and WAF detection
- Secret and API key discovery
- Parameter discovery
- CORS misconfiguration detection
- Subdomain takeover detection
- Report generation

IMPORTANT GUIDELINES:
1. Always set a target first using set_target before running scans
2. Be methodical - start with reconnaissance before active scanning
3. Explain what you're doing and why
4. Highlight important findings prominently
5. Suggest next steps based on results
6. Only test targets you have authorization to test
7. Be efficient - don't run redundant scans

When the user asks you to scan a target, follow this general workflow:
1. Set the target
2. Enumerate subdomains
3. Find live hosts
4. Collect URLs
5. Detect technologies and WAF
6. Run vulnerability scans
7. Test for specific vulnerabilities based on findings
8. Generate a report

Always be helpful, thorough, and explain your reasoning.`;
  }

  async processUserInput(userInput: string): Promise<void> {
    this.conversationHistory.push({ role: "user", content: userInput });

    console.log(`${c.magenta}🤖 Thinking...${c.reset}`);

    try {
      let response = await this.anthropic.messages.create({
        model: this.model,
        max_tokens: 4096,
        system: this.getSystemPrompt(),
        tools: this.formatToolsForClaude(),
        messages: this.conversationHistory,
      });

      // Process response and handle tool calls
      while (response.stop_reason === "tool_use") {
        const assistantMessage = response.content;
        this.conversationHistory.push({ role: "assistant", content: assistantMessage });

        const toolResults: any[] = [];

        for (const block of assistantMessage) {
          if (block.type === "text") {
            console.log(`\n${c.cyan}🤖 ${block.text}${c.reset}`);
          } else if (block.type === "tool_use") {
            console.log(`\n${c.green}⚡ Running: ${c.bold}${block.name}${c.reset}`);
            if (Object.keys(block.input as object).length > 0) {
              console.log(`${c.dim}   Args: ${JSON.stringify(block.input)}${c.reset}`);
            }

            try {
              const result = await this.mcpClient.callTool(block.name, block.input);
              
              // Parse and display the result
              let resultText = "";
              if (result.content && result.content[0] && result.content[0].text) {
                resultText = result.content[0].text;
                const parsed = JSON.parse(resultText);
                
                // Pretty print key information
                if (parsed.message) {
                  console.log(`${c.green}   ✓ ${parsed.message}${c.reset}`);
                }
                if (parsed.error) {
                  console.log(`${c.red}   ✗ ${parsed.error}${c.reset}`);
                }
                if (parsed.total_findings && parsed.total_findings > 0) {
                  console.log(`${c.red}   🔥 Found ${parsed.total_findings} potential vulnerabilities!${c.reset}`);
                }
                if (parsed.vulnerable === true) {
                  console.log(`${c.red}   ⚠️  VULNERABILITY DETECTED!${c.reset}`);
                }
              }

              toolResults.push({
                type: "tool_result",
                tool_use_id: block.id,
                content: resultText || JSON.stringify(result),
              });
            } catch (error: any) {
              console.log(`${c.red}   ✗ Error: ${error.message}${c.reset}`);
              toolResults.push({
                type: "tool_result",
                tool_use_id: block.id,
                content: JSON.stringify({ error: error.message }),
                is_error: true,
              });
            }
          }
        }

        // Continue the conversation with tool results
        this.conversationHistory.push({ role: "user", content: toolResults });

        response = await this.anthropic.messages.create({
          model: this.model,
          max_tokens: 4096,
          system: this.getSystemPrompt(),
          tools: this.formatToolsForClaude(),
          messages: this.conversationHistory,
        });
      }

      // Print final response
      for (const block of response.content) {
        if (block.type === "text") {
          console.log(`\n${c.cyan}🤖 ${block.text}${c.reset}`);
        }
      }

      this.conversationHistory.push({ role: "assistant", content: response.content });
    } catch (error: any) {
      console.error(`${c.red}Error: ${error.message}${c.reset}`);
      // Remove the failed user message
      this.conversationHistory.pop();
    }
  }

  disconnect() {
    this.mcpClient.disconnect();
  }
}

// Main function
async function main() {
  printBanner();

  // Load configuration
  let config = loadConfig();

  // Check for API key
  let apiKey = process.env.ANTHROPIC_API_KEY || config.anthropic_api_key;

  if (!apiKey) {
    console.log(`${c.yellow}⚠️  Anthropic API key not found.${c.reset}`);
    console.log(`${c.white}Please enter your Anthropic API key:${c.reset}`);

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    apiKey = await new Promise<string>((resolve) => {
      rl.question(`${c.cyan}API Key: ${c.reset}`, (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    });

    if (!apiKey) {
      console.error(`${c.red}API key is required.${c.reset}`);
      process.exit(1);
    }

    // Save for future use
    config.anthropic_api_key = apiKey;
    saveConfig(config);
    console.log(`${c.green}[+] API key saved to ${CONFIG_FILE}${c.reset}`);
  }

  // Initialize agent
  const agent = new HackStrikeAgent(apiKey, config.model);

  try {
    await agent.initialize();
  } catch (error: any) {
    console.error(`${c.red}Failed to initialize agent: ${error.message}${c.reset}`);
    process.exit(1);
  }

  console.log(`\n${c.green}[+] HackStrike AI Agent ready!${c.reset}`);
  console.log(`${c.dim}Type your commands in natural language. Type 'exit' to quit.${c.reset}`);
  console.log(`${c.dim}Example: "Find all subdomains of example.com and scan for vulnerabilities"${c.reset}\n`);

  // Start interactive loop
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    rl.question(`${c.magenta}hackstrike>${c.reset} `, async (input) => {
      const trimmed = input.trim();

      if (!trimmed) {
        prompt();
        return;
      }

      if (trimmed.toLowerCase() === "exit" || trimmed.toLowerCase() === "quit") {
        console.log(`${c.cyan}🤖 Goodbye! Happy hunting!${c.reset}`);
        agent.disconnect();
        rl.close();
        process.exit(0);
      }

      if (trimmed.toLowerCase() === "clear") {
        console.clear();
        printBanner();
        prompt();
        return;
      }

      if (trimmed.toLowerCase() === "help") {
        console.log(`
${c.cyan}Available Commands:${c.reset}
  ${c.white}Natural language queries:${c.reset}
    - "Scan example.com for vulnerabilities"
    - "Find all subdomains of target.com"
    - "Check for XSS on https://example.com/page?id=1"
    - "Run a full reconnaissance on example.com"
    - "Generate a report of findings"

  ${c.white}System commands:${c.reset}
    - ${c.green}help${c.reset}  - Show this help
    - ${c.green}clear${c.reset} - Clear the screen
    - ${c.green}exit${c.reset}  - Exit the program
`);
        prompt();
        return;
      }

      await agent.processUserInput(trimmed);
      prompt();
    });
  };

  prompt();
}

main().catch(console.error);
