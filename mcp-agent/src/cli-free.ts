#!/usr/bin/env node
/**
 * HackStrike AI Agent - Simple FREE Version
 * Uses Ollama for AI + direct tool execution
 */

import { exec } from "child_process";
import { promisify } from "util";
import * as readline from "readline";
import * as path from "path";
import * as fs from "fs/promises";
import { fileURLToPath } from "url";

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Colors
const c = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
};

// Config
const HACKTOOLS_DIR = path.resolve(__dirname, "../..");
const RESULTS_DIR = path.join(HACKTOOLS_DIR, "results");

// State
let currentTarget: string | null = null;
let outputDir: string | null = null;

// Helper functions
async function runCommand(cmd: string, timeout = 120000): Promise<string> {
  try {
    const { stdout } = await execAsync(cmd, { timeout, maxBuffer: 50 * 1024 * 1024 });
    return stdout.trim();
  } catch (e: any) {
    return e.stdout?.trim() || "";
  }
}

async function toolExists(tool: string): Promise<boolean> {
  try {
    await execAsync(`which ${tool}`);
    return true;
  } catch {
    return false;
  }
}

// Ollama Chat
async function askOllama(prompt: string, systemPrompt?: string): Promise<string> {
  const messages = [];
  if (systemPrompt) {
    messages.push({ role: "system", content: systemPrompt });
  }
  messages.push({ role: "user", content: prompt });

  try {
    const response = await fetch("http://localhost:11434/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || "llama3.2",
        messages,
        stream: false,
      }),
    });

    if (!response.ok) throw new Error("Ollama not responding");
    const data = await response.json() as any;
    return data.message?.content || "";
  } catch (e: any) {
    throw new Error(`Ollama error: ${e.message}. Is Ollama running? Try: ollama serve`);
  }
}

// Tool implementations
const tools: Record<string, (args: any) => Promise<any>> = {
  async set_target({ target }: { target: string }) {
    currentTarget = target.replace(/^https?:\/\//, "").replace(/\/$/, "");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
    outputDir = path.join(RESULTS_DIR, `${currentTarget}_${timestamp}`);
    
    await fs.mkdir(path.join(outputDir, "subdomains"), { recursive: true });
    await fs.mkdir(path.join(outputDir, "urls"), { recursive: true });
    await fs.mkdir(path.join(outputDir, "vulns"), { recursive: true });
    await fs.mkdir(path.join(outputDir, "ports"), { recursive: true });
    
    return { success: true, target: currentTarget, output_dir: outputDir };
  },

  async subdomain_enum({ target }: { target?: string }) {
    const t = target || currentTarget;
    if (!t) return { error: "No target set" };

    const results: string[] = [];
    console.log(`${c.dim}   Running subdomain enumeration...${c.reset}`);

    if (await toolExists("subfinder")) {
      console.log(`${c.dim}   - subfinder...${c.reset}`);
      const out = await runCommand(`subfinder -d ${t} -silent 2>/dev/null`);
      if (out) results.push(...out.split("\n"));
    }

    if (await toolExists("assetfinder")) {
      console.log(`${c.dim}   - assetfinder...${c.reset}`);
      const out = await runCommand(`assetfinder --subs-only ${t} 2>/dev/null`);
      if (out) results.push(...out.split("\n"));
    }

    const unique = [...new Set(results.filter(Boolean))];
    
    if (outputDir) {
      await fs.writeFile(path.join(outputDir, "subdomains", "all.txt"), unique.join("\n"));
    }

    return { 
      total: unique.length, 
      subdomains: unique.slice(0, 20),
      saved_to: outputDir ? path.join(outputDir, "subdomains", "all.txt") : null
    };
  },

  async port_scan({ target, ports }: { target?: string; ports?: string }) {
    const t = target || currentTarget;
    if (!t) return { error: "No target set" };

    const portSpec = ports || "21,22,80,443,8080,8443,3306,5432";
    console.log(`${c.dim}   Scanning ports ${portSpec}...${c.reset}`);

    let results: string[] = [];

    if (await toolExists("naabu")) {
      const out = await runCommand(`naabu -host ${t} -p ${portSpec} -silent 2>/dev/null`, 180000);
      if (out) results = out.split("\n").filter(Boolean);
    } else if (await toolExists("nmap")) {
      const out = await runCommand(`nmap -p ${portSpec} ${t} --open -oG - 2>/dev/null | grep "/open"`, 180000);
      const matches = out.match(/(\d+)\/open/g) || [];
      results = matches.map(m => `${t}:${m.replace("/open", "")}`);
    }

    if (outputDir) {
      await fs.writeFile(path.join(outputDir, "ports", "open.txt"), results.join("\n"));
    }

    return { open_ports: results };
  },

  async vuln_scan({ target, severity }: { target?: string; severity?: string }) {
    const t = target || currentTarget;
    if (!t) return { error: "No target set" };

    if (!(await toolExists("nuclei"))) {
      return { error: "nuclei not installed" };
    }

    const sev = severity || "medium,high,critical";
    console.log(`${c.dim}   Running nuclei (${sev})...${c.reset}`);

    const out = await runCommand(
      `nuclei -u https://${t} -severity ${sev} -silent 2>/dev/null`,
      300000
    );

    const findings = out.split("\n").filter(Boolean);

    if (outputDir) {
      await fs.writeFile(path.join(outputDir, "vulns", "nuclei.txt"), findings.join("\n"));
    }

    return { 
      total_findings: findings.length, 
      findings: findings.slice(0, 10),
      saved_to: outputDir ? path.join(outputDir, "vulns", "nuclei.txt") : null
    };
  },

  async url_collect({ target }: { target?: string }) {
    const t = target || currentTarget;
    if (!t) return { error: "No target set" };

    const results: string[] = [];
    console.log(`${c.dim}   Collecting URLs...${c.reset}`);

    if (await toolExists("gau")) {
      console.log(`${c.dim}   - gau...${c.reset}`);
      const out = await runCommand(`gau ${t} --threads 2 2>/dev/null | head -500`, 120000);
      if (out) results.push(...out.split("\n"));
    }

    if (await toolExists("waybackurls")) {
      console.log(`${c.dim}   - waybackurls...${c.reset}`);
      const out = await runCommand(`echo "${t}" | waybackurls 2>/dev/null | head -500`, 120000);
      if (out) results.push(...out.split("\n"));
    }

    const unique = [...new Set(results.filter(Boolean))];
    const withParams = unique.filter(u => u.includes("?") || u.includes("="));

    if (outputDir) {
      await fs.writeFile(path.join(outputDir, "urls", "all.txt"), unique.join("\n"));
      await fs.writeFile(path.join(outputDir, "urls", "params.txt"), withParams.join("\n"));
    }

    return { 
      total_urls: unique.length,
      with_params: withParams.length,
      sample: unique.slice(0, 10)
    };
  },

  async tech_detect({ target }: { target?: string }) {
    const t = target || currentTarget;
    if (!t) return { error: "No target set" };

    const url = t.startsWith("http") ? t : `https://${t}`;
    
    if (await toolExists("httpx")) {
      const out = await runCommand(`echo "${url}" | httpx -silent -tech-detect -status-code -title 2>/dev/null`);
      return { result: out };
    }

    return { error: "httpx not installed" };
  },

  async live_hosts({ file }: { file?: string }) {
    if (!outputDir) return { error: "No target set" };
    
    const subsFile = file || path.join(outputDir, "subdomains", "all.txt");
    
    try {
      await fs.access(subsFile);
    } catch {
      return { error: "No subdomains file found. Run subdomain_enum first." };
    }

    if (!(await toolExists("httpx"))) {
      return { error: "httpx not installed" };
    }

    console.log(`${c.dim}   Checking live hosts...${c.reset}`);
    const out = await runCommand(`cat "${subsFile}" | httpx -silent 2>/dev/null`, 180000);
    const live = out.split("\n").filter(Boolean);

    await fs.writeFile(path.join(outputDir, "urls", "live.txt"), live.join("\n"));

    return { live_hosts: live.length, hosts: live.slice(0, 20) };
  },

  async help() {
    return {
      available_tools: [
        "set_target - Set target domain",
        "subdomain_enum - Find subdomains",
        "live_hosts - Check which hosts are alive",
        "port_scan - Scan for open ports",
        "url_collect - Gather URLs",
        "vuln_scan - Run vulnerability scan",
        "tech_detect - Detect technologies",
      ]
    };
  }
};

// Parse AI response for tool calls
function parseToolCall(response: string): { tool: string; args: any } | null {
  // Look for JSON tool calls
  const jsonMatch = response.match(/```json\s*(\{[\s\S]*?\})\s*```/) ||
                    response.match(/\{"tool":\s*"([^"]+)"[^}]*\}/) ||
                    response.match(/TOOL:\s*(\w+)(?:\s+ARGS:\s*(\{[^}]+\}))?/i);

  if (jsonMatch) {
    try {
      if (jsonMatch[0].includes('"tool"')) {
        const parsed = JSON.parse(jsonMatch[0]);
        return { tool: parsed.tool, args: parsed.args || {} };
      }
    } catch {}
  }

  // Look for natural language tool mentions
  const toolMentions: Record<string, string> = {
    "set target": "set_target",
    "subdomain": "subdomain_enum",
    "find subdomain": "subdomain_enum",
    "enumerate subdomain": "subdomain_enum",
    "port scan": "port_scan",
    "scan port": "port_scan",
    "vulnerability": "vuln_scan",
    "vuln scan": "vuln_scan",
    "nuclei": "vuln_scan",
    "collect url": "url_collect",
    "gather url": "url_collect",
    "find url": "url_collect",
    "tech": "tech_detect",
    "technology": "tech_detect",
    "live host": "live_hosts",
    "check live": "live_hosts",
  };

  const lower = response.toLowerCase();
  for (const [phrase, tool] of Object.entries(toolMentions)) {
    if (lower.includes(phrase)) {
      return { tool, args: {} };
    }
  }

  return null;
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
  console.log(`${c.bold}         🤖 AI Bug Bounty Agent ${c.yellow}(FREE - Ollama)${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
  console.log();
}

const SYSTEM_PROMPT = `You are HackStrike AI, an expert bug bounty assistant. You help users find vulnerabilities.

You have these tools available:
- set_target: Set the target domain (MUST be called first)
- subdomain_enum: Find subdomains
- live_hosts: Check which hosts respond
- port_scan: Find open ports
- url_collect: Gather URLs from archives
- vuln_scan: Run Nuclei vulnerability scanner
- tech_detect: Detect technologies

When the user wants to scan something:
1. First call set_target with the domain
2. Then run appropriate scans

To use a tool, respond with: TOOL: tool_name

Be concise and helpful. Explain what you're doing.`;

// Main agent loop
async function processInput(input: string): Promise<void> {
  // Check for direct tool commands
  const directToolMatch = input.match(/^(set_target|subdomain_enum|port_scan|vuln_scan|url_collect|tech_detect|live_hosts|help)\s*(.*)?$/i);
  
  if (directToolMatch) {
    const toolName = directToolMatch[1].toLowerCase();
    const argStr = directToolMatch[2]?.trim();
    
    let args: any = {};
    if (argStr) {
      if (toolName === "set_target") {
        args = { target: argStr };
      } else {
        try {
          args = JSON.parse(argStr);
        } catch {
          args = { target: argStr };
        }
      }
    }

    return await executeTool(toolName, args);
  }

  // Extract target from natural language
  const targetMatch = input.match(/(?:scan|test|check|target|on|for)\s+([a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,})/i);
  
  // Quick commands without AI
  const lowerInput = input.toLowerCase();
  
  if (lowerInput.includes("scan") && targetMatch && !currentTarget) {
    // Auto set target and run scan
    console.log(`${c.green}⚡ Setting target: ${targetMatch[1]}${c.reset}`);
    await executeTool("set_target", { target: targetMatch[1] });
    
    if (lowerInput.includes("full") || lowerInput.includes("everything") || lowerInput.includes("vulnerabilit")) {
      console.log(`\n${c.green}⚡ Running full scan...${c.reset}`);
      await executeTool("subdomain_enum", {});
      await executeTool("live_hosts", {});
      await executeTool("url_collect", {});
      await executeTool("vuln_scan", {});
      return;
    }
  }

  // Use AI for complex queries
  console.log(`${c.magenta}🤖 Thinking...${c.reset}`);
  
  try {
    const contextInfo = currentTarget 
      ? `Current target: ${currentTarget}\nOutput directory: ${outputDir}` 
      : "No target set yet.";
    
    const response = await askOllama(
      `${contextInfo}\n\nUser request: ${input}\n\nWhat tool should I use? Respond with TOOL: tool_name or give advice.`,
      SYSTEM_PROMPT
    );

    console.log(`\n${c.cyan}🤖 ${response}${c.reset}\n`);

    // Check if AI suggested a tool
    const toolCall = parseToolCall(response);
    if (toolCall && tools[toolCall.tool]) {
      // Add target from user input if detected
      if (targetMatch && !toolCall.args.target) {
        toolCall.args.target = targetMatch[1];
      }
      await executeTool(toolCall.tool, toolCall.args);
    }
  } catch (e: any) {
    console.error(`${c.red}Error: ${e.message}${c.reset}`);
  }
}

async function executeTool(name: string, args: any): Promise<void> {
  const tool = tools[name];
  if (!tool) {
    console.log(`${c.red}Unknown tool: ${name}${c.reset}`);
    return;
  }

  console.log(`${c.green}⚡ Running: ${c.bold}${name}${c.reset}`);
  
  try {
    const result = await tool(args);
    
    if (result.error) {
      console.log(`${c.red}   ✗ ${result.error}${c.reset}`);
    } else {
      // Pretty print results
      if (result.success) console.log(`${c.green}   ✓ Success${c.reset}`);
      if (result.target) console.log(`${c.green}   Target: ${result.target}${c.reset}`);
      if (result.total !== undefined) console.log(`${c.green}   Found: ${result.total} items${c.reset}`);
      if (result.total_findings !== undefined) {
        if (result.total_findings > 0) {
          console.log(`${c.red}   🔥 Found ${result.total_findings} vulnerabilities!${c.reset}`);
        } else {
          console.log(`${c.green}   ✓ No vulnerabilities found${c.reset}`);
        }
      }
      if (result.live_hosts !== undefined) console.log(`${c.green}   Live hosts: ${result.live_hosts}${c.reset}`);
      if (result.total_urls !== undefined) console.log(`${c.green}   URLs: ${result.total_urls} (${result.with_params} with params)${c.reset}`);
      if (result.open_ports?.length) console.log(`${c.green}   Open ports: ${result.open_ports.join(", ")}${c.reset}`);
      if (result.saved_to) console.log(`${c.dim}   Saved to: ${result.saved_to}${c.reset}`);
      
      // Show samples
      if (result.subdomains?.length) {
        console.log(`${c.dim}   Sample: ${result.subdomains.slice(0, 5).join(", ")}...${c.reset}`);
      }
      if (result.findings?.length) {
        console.log(`${c.yellow}   Findings:${c.reset}`);
        result.findings.slice(0, 5).forEach((f: string) => console.log(`${c.red}     🔥 ${f}${c.reset}`));
      }
    }
  } catch (e: any) {
    console.log(`${c.red}   ✗ Error: ${e.message}${c.reset}`);
  }
}

// Main
async function main() {
  printBanner();

  // Check Ollama
  try {
    const response = await fetch("http://localhost:11434/api/tags");
    if (!response.ok) throw new Error();
    console.log(`${c.green}[+] Ollama connected${c.reset}`);
  } catch {
    console.log(`${c.yellow}[!] Ollama not running - AI features disabled${c.reset}`);
    console.log(`${c.dim}    Start with: ollama serve${c.reset}`);
    console.log(`${c.dim}    You can still use direct tool commands${c.reset}`);
  }

  console.log(`${c.green}[+] Ready!${c.reset}`);
  console.log(`${c.dim}Commands: set_target <domain>, subdomain_enum, port_scan, vuln_scan, url_collect, help${c.reset}`);
  console.log(`${c.dim}Or use natural language: "scan example.com for vulnerabilities"${c.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    const targetInfo = currentTarget ? `${c.green}[${currentTarget}]${c.reset} ` : "";
    rl.question(`${targetInfo}${c.magenta}hackstrike>${c.reset} `, async (input) => {
      const trimmed = input.trim();
      
      if (!trimmed) { prompt(); return; }
      if (["exit", "quit", "q"].includes(trimmed.toLowerCase())) {
        console.log(`${c.cyan}Goodbye! Happy hunting! 🎯${c.reset}`);
        process.exit(0);
      }
      if (trimmed.toLowerCase() === "clear") {
        console.clear();
        printBanner();
        prompt();
        return;
      }

      await processInput(trimmed);
      console.log();
      prompt();
    });
  };

  prompt();
}

main().catch(console.error);
