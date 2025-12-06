#!/usr/bin/env node
/**
 * HackStrike AI Agent CLI - Ollama Version (FREE)
 * Uses local Ollama models instead of Claude API
 */

import { spawn, ChildProcess } from "child_process";
import * as readline from "readline";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

interface OllamaResponse {
  model: string;
  message: {
    role: string;
    content: string;
    tool_calls?: Array<{
      function: {
        name: string;
        arguments: string;
      };
    }>;
  };
  done: boolean;
}

// MCP Client
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
        const msg = data.toString().trim();
        if (msg && !msg.includes("running")) {
          console.error(`${c.dim}[MCP] ${msg}${c.reset}`);
        }
      });

      this.process.on("error", reject);
      this.process.on("exit", (code) => {
        if (code !== 0) {
          console.error(`${c.red}MCP server exited with code ${code}${c.reset}`);
        }
      });

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
        } catch (e) {}
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
      clientInfo: { name: "hackstrike-cli", version: "1.0.0" },
    });
    await this.sendRequest("notifications/initialized", {});
  }

  async listTools(): Promise<Tool[]> {
    const result = await this.sendRequest("tools/list", {});
    return result.tools || [];
  }

  async callTool(name: string, args: any): Promise<any> {
    return await this.sendRequest("tools/call", { name, arguments: args });
  }

  disconnect() {
    this.process?.kill();
    this.process = null;
  }
}

// Ollama API Client
class OllamaClient {
  private baseUrl: string;
  private model: string;

  constructor(model: string = "llama3.2", baseUrl: string = "http://localhost:11434") {
    this.model = model;
    this.baseUrl = baseUrl;
  }

  async chat(messages: any[], tools?: any[]): Promise<OllamaResponse> {
    const response = await fetch(`${this.baseUrl}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: this.model,
        messages,
        tools,
        stream: false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Ollama error: ${response.statusText}`);
    }

    return await response.json() as OllamaResponse;
  }

  async isAvailable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      return response.ok;
    } catch {
      return false;
    }
  }

  async listModels(): Promise<string[]> {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      const data = await response.json() as { models: Array<{ name: string }> };
      return data.models?.map((m) => m.name) || [];
    } catch {
      return [];
    }
  }
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
  console.log(`${c.white}         🤖 AI Bug Bounty Agent ${c.yellow}(Ollama - FREE)${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
  console.log();
}

// Agent
class HackStrikeAgent {
  private ollama: OllamaClient;
  private mcpClient: MCPClient;
  private tools: Tool[] = [];
  private conversationHistory: any[] = [];

  constructor(model: string = "llama3.2") {
    this.ollama = new OllamaClient(model);
    this.mcpClient = new MCPClient();
  }

  async initialize(): Promise<void> {
    // Check Ollama
    console.log(`${c.blue}[*] Checking Ollama...${c.reset}`);
    if (!(await this.ollama.isAvailable())) {
      throw new Error("Ollama is not running. Start it with: ollama serve");
    }

    const models = await this.ollama.listModels();
    console.log(`${c.green}[+] Ollama available with models: ${models.join(", ") || "none"}${c.reset}`);

    if (models.length === 0) {
      console.log(`${c.yellow}[!] No models found. Pull one with: ollama pull llama3.2${c.reset}`);
    }

    // Start MCP server
    const serverPath = path.join(__dirname, "server.js");
    console.log(`${c.blue}[*] Starting MCP server...${c.reset}`);
    await this.mcpClient.connect(serverPath);

    console.log(`${c.blue}[*] Loading tools...${c.reset}`);
    this.tools = await this.mcpClient.listTools();
    console.log(`${c.green}[+] Loaded ${this.tools.length} bug bounty tools${c.reset}`);
  }

  private formatToolsForOllama(): any[] {
    return this.tools.map((tool) => ({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema,
      },
    }));
  }

  private getSystemPrompt(): string {
    return `You are HackStrike AI, an expert bug bounty hunter assistant.
You help security researchers find vulnerabilities in web applications.

You have access to these tools:
${this.tools.map((t) => `- ${t.name}: ${t.description}`).join("\n")}

IMPORTANT:
1. Always set a target first using set_target before running scans
2. Be methodical - start with reconnaissance before active scanning
3. When you need to use a tool, respond with a JSON tool call in this exact format:
   {"tool": "tool_name", "args": {"param1": "value1"}}
4. Only test authorized targets
5. Explain what you're doing

When the user asks to scan something, call the appropriate tools.`;
  }

  async processUserInput(userInput: string): Promise<void> {
    this.conversationHistory.push({ role: "user", content: userInput });

    console.log(`${c.magenta}🤖 Thinking...${c.reset}`);

    try {
      const messages = [
        { role: "system", content: this.getSystemPrompt() },
        ...this.conversationHistory,
      ];

      let response = await this.ollama.chat(messages, this.formatToolsForOllama());
      let content = response.message.content;

      // Check for tool calls in the response
      const toolCallMatch = content.match(/\{"tool":\s*"([^"]+)",\s*"args":\s*(\{[^}]+\})\}/);
      
      if (toolCallMatch || response.message.tool_calls?.length) {
        // Handle tool call
        let toolName: string;
        let toolArgs: any;

        if (response.message.tool_calls?.length) {
          const tc = response.message.tool_calls[0];
          toolName = tc.function.name;
          toolArgs = JSON.parse(tc.function.arguments);
        } else if (toolCallMatch) {
          toolName = toolCallMatch[1];
          toolArgs = JSON.parse(toolCallMatch[2]);
        } else {
          console.log(`\n${c.cyan}🤖 ${content}${c.reset}`);
          this.conversationHistory.push({ role: "assistant", content });
          return;
        }

        console.log(`\n${c.green}⚡ Running: ${c.bold}${toolName}${c.reset}`);
        if (Object.keys(toolArgs).length > 0) {
          console.log(`${c.dim}   Args: ${JSON.stringify(toolArgs)}${c.reset}`);
        }

        try {
          const result = await this.mcpClient.callTool(toolName, toolArgs);
          let resultText = "";
          
          if (result.content?.[0]?.text) {
            resultText = result.content[0].text;
            const parsed = JSON.parse(resultText);
            
            if (parsed.message) {
              console.log(`${c.green}   ✓ ${parsed.message}${c.reset}`);
            }
            if (parsed.error) {
              console.log(`${c.red}   ✗ ${parsed.error}${c.reset}`);
            }
            if (parsed.total_findings > 0) {
              console.log(`${c.red}   🔥 Found ${parsed.total_findings} potential vulnerabilities!${c.reset}`);
            }
          }

          // Add tool result to conversation and get AI's interpretation
          this.conversationHistory.push({ 
            role: "assistant", 
            content: `I called ${toolName} and got: ${resultText}` 
          });

          // Get follow-up response
          const followUp = await this.ollama.chat([
            { role: "system", content: this.getSystemPrompt() },
            ...this.conversationHistory,
            { role: "user", content: "Summarize what you found and suggest next steps." }
          ]);

          console.log(`\n${c.cyan}🤖 ${followUp.message.content}${c.reset}`);
          this.conversationHistory.push({ role: "assistant", content: followUp.message.content });

        } catch (error: any) {
          console.log(`${c.red}   ✗ Error: ${error.message}${c.reset}`);
        }
      } else {
        console.log(`\n${c.cyan}🤖 ${content}${c.reset}`);
        this.conversationHistory.push({ role: "assistant", content });
      }
    } catch (error: any) {
      console.error(`${c.red}Error: ${error.message}${c.reset}`);
      this.conversationHistory.pop();
    }
  }

  disconnect() {
    this.mcpClient.disconnect();
  }
}

// Main
async function main() {
  printBanner();

  const model = process.env.OLLAMA_MODEL || "llama3.2";
  const agent = new HackStrikeAgent(model);

  try {
    await agent.initialize();
  } catch (error: any) {
    console.error(`${c.red}Failed to initialize: ${error.message}${c.reset}`);
    console.log(`
${c.yellow}To fix this:${c.reset}
  1. Install Ollama: ${c.cyan}curl -fsSL https://ollama.com/install.sh | sh${c.reset}
  2. Start Ollama: ${c.cyan}ollama serve${c.reset}
  3. Pull a model: ${c.cyan}ollama pull llama3.2${c.reset}
  4. Run this agent again
`);
    process.exit(1);
  }

  console.log(`\n${c.green}[+] HackStrike AI Agent ready! (Using Ollama - FREE)${c.reset}`);
  console.log(`${c.dim}Type your commands. Type 'exit' to quit.${c.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    rl.question(`${c.magenta}hackstrike>${c.reset} `, async (input) => {
      const trimmed = input.trim();

      if (!trimmed) { prompt(); return; }

      if (["exit", "quit"].includes(trimmed.toLowerCase())) {
        console.log(`${c.cyan}🤖 Goodbye!${c.reset}`);
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
${c.cyan}Examples:${c.reset}
  - "Set target to example.com"
  - "Find subdomains"
  - "Scan for vulnerabilities"
  - "Check for XSS"
  - "Generate report"

${c.cyan}Commands:${c.reset}
  help  - Show this help
  clear - Clear screen
  exit  - Exit
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
