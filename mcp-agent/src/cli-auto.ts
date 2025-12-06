#!/usr/bin/env node
/**
 * HackStrike AI Agent - Autonomous FREE Version
 * Automatically runs full scan workflow after setting target
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

// Helpers
async function runCommand(cmd: string, timeout = 180000): Promise<string> {
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

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Ollama
async function askOllama(prompt: string): Promise<string> {
  try {
    const response = await fetch("http://localhost:11434/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || "llama3.2",
        messages: [
          { role: "system", content: "You are a bug bounty expert. Be very concise. Give actionable advice." },
          { role: "user", content: prompt }
        ],
        stream: false,
      }),
    });
    if (!response.ok) return "";
    const data = await response.json() as any;
    return data.message?.content || "";
  } catch {
    return "";
  }
}

// ============================================
// TOOLS
// ============================================

async function setTarget(target: string): Promise<boolean> {
  currentTarget = target.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
  outputDir = path.join(RESULTS_DIR, `${currentTarget}_${timestamp}`);
  
  await fs.mkdir(path.join(outputDir, "subdomains"), { recursive: true });
  await fs.mkdir(path.join(outputDir, "urls"), { recursive: true });
  await fs.mkdir(path.join(outputDir, "vulns"), { recursive: true });
  await fs.mkdir(path.join(outputDir, "ports"), { recursive: true });
  await fs.mkdir(path.join(outputDir, "reports"), { recursive: true });
  
  console.log(`${c.green}   ✓ Target: ${currentTarget}${c.reset}`);
  console.log(`${c.dim}   Output: ${outputDir}${c.reset}`);
  return true;
}

async function subdomainEnum(): Promise<string[]> {
  if (!currentTarget || !outputDir) return [];
  
  const results: string[] = [];
  
  if (await toolExists("subfinder")) {
    process.stdout.write(`${c.dim}   [subfinder] ${c.reset}`);
    const out = await runCommand(`subfinder -d ${currentTarget} -silent 2>/dev/null`, 120000);
    if (out) {
      const subs = out.split("\n").filter(Boolean);
      results.push(...subs);
      console.log(`${c.green}${subs.length} found${c.reset}`);
    } else {
      console.log(`${c.yellow}0 found${c.reset}`);
    }
  }

  if (await toolExists("assetfinder")) {
    process.stdout.write(`${c.dim}   [assetfinder] ${c.reset}`);
    const out = await runCommand(`assetfinder --subs-only ${currentTarget} 2>/dev/null`, 60000);
    if (out) {
      const subs = out.split("\n").filter(Boolean);
      results.push(...subs);
      console.log(`${c.green}${subs.length} found${c.reset}`);
    } else {
      console.log(`${c.yellow}0 found${c.reset}`);
    }
  }

  if (await toolExists("findomain")) {
    process.stdout.write(`${c.dim}   [findomain] ${c.reset}`);
    const out = await runCommand(`findomain -t ${currentTarget} -q 2>/dev/null`, 60000);
    if (out) {
      const subs = out.split("\n").filter(Boolean);
      results.push(...subs);
      console.log(`${c.green}${subs.length} found${c.reset}`);
    } else {
      console.log(`${c.yellow}0 found${c.reset}`);
    }
  }

  const unique = [...new Set(results)].filter(s => s.includes(currentTarget!));
  await fs.writeFile(path.join(outputDir, "subdomains", "all.txt"), unique.join("\n"));
  
  return unique;
}

async function liveHostCheck(subdomains: string[]): Promise<string[]> {
  if (!outputDir || subdomains.length === 0) return [];
  
  if (!(await toolExists("httpx"))) {
    console.log(`${c.yellow}   httpx not installed, skipping${c.reset}`);
    return subdomains.slice(0, 10).map(s => `https://${s}`);
  }

  const subsFile = path.join(outputDir, "subdomains", "all.txt");
  const out = await runCommand(`cat "${subsFile}" | httpx -silent -threads 50 2>/dev/null`, 180000);
  const live = out.split("\n").filter(Boolean);
  
  await fs.writeFile(path.join(outputDir, "urls", "live.txt"), live.join("\n"));
  return live;
}

async function urlCollection(): Promise<string[]> {
  if (!currentTarget || !outputDir) return [];
  
  const results: string[] = [];

  if (await toolExists("gau")) {
    process.stdout.write(`${c.dim}   [gau] ${c.reset}`);
    const out = await runCommand(`gau ${currentTarget} --threads 3 2>/dev/null | head -1000`, 120000);
    if (out) {
      const urls = out.split("\n").filter(Boolean);
      results.push(...urls);
      console.log(`${c.green}${urls.length} URLs${c.reset}`);
    } else {
      console.log(`${c.yellow}0 URLs${c.reset}`);
    }
  }

  if (await toolExists("waybackurls")) {
    process.stdout.write(`${c.dim}   [waybackurls] ${c.reset}`);
    const out = await runCommand(`echo "${currentTarget}" | waybackurls 2>/dev/null | head -1000`, 120000);
    if (out) {
      const urls = out.split("\n").filter(Boolean);
      results.push(...urls);
      console.log(`${c.green}${urls.length} URLs${c.reset}`);
    } else {
      console.log(`${c.yellow}0 URLs${c.reset}`);
    }
  }

  const unique = [...new Set(results)];
  const withParams = unique.filter(u => u.includes("="));
  
  await fs.writeFile(path.join(outputDir, "urls", "all.txt"), unique.join("\n"));
  await fs.writeFile(path.join(outputDir, "urls", "params.txt"), withParams.join("\n"));
  
  return unique;
}

async function portScan(hosts: string[]): Promise<string[]> {
  if (!currentTarget || !outputDir) return [];
  
  const target = hosts[0]?.replace(/^https?:\/\//, "") || currentTarget;
  const ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443";
  
  let results: string[] = [];

  if (await toolExists("naabu")) {
    const out = await runCommand(`naabu -host ${target} -p ${ports} -silent 2>/dev/null`, 120000);
    results = out.split("\n").filter(Boolean);
  } else if (await toolExists("nmap")) {
    const out = await runCommand(`nmap -p ${ports} ${target} --open -oG - 2>/dev/null`, 180000);
    const matches = out.match(/(\d+)\/open/g) || [];
    results = matches.map(m => `${target}:${m.replace("/open", "")}`);
  }

  if (results.length > 0) {
    await fs.writeFile(path.join(outputDir, "ports", "open.txt"), results.join("\n"));
  }
  
  return results;
}

async function vulnScan(liveHosts: string[]): Promise<string[]> {
  if (!currentTarget || !outputDir) return [];
  
  if (!(await toolExists("nuclei"))) {
    console.log(`${c.yellow}   nuclei not installed${c.reset}`);
    return [];
  }

  // Scan main target and a few live hosts
  const targets = [`https://${currentTarget}`, ...liveHosts.slice(0, 5)];
  const targetFile = path.join(outputDir, "vulns", "targets.txt");
  await fs.writeFile(targetFile, targets.join("\n"));

  const out = await runCommand(
    `nuclei -l "${targetFile}" -severity medium,high,critical -silent -rate-limit 100 2>/dev/null`,
    600000
  );
  
  const findings = out.split("\n").filter(Boolean);
  
  if (findings.length > 0) {
    await fs.writeFile(path.join(outputDir, "vulns", "nuclei.txt"), findings.join("\n"));
  }
  
  return findings;
}

async function techDetect(): Promise<string> {
  if (!currentTarget) return "";
  
  if (!(await toolExists("httpx"))) return "";
  
  const out = await runCommand(
    `echo "https://${currentTarget}" | httpx -silent -tech-detect -status-code -title 2>/dev/null`,
    30000
  );
  
  return out;
}

async function generateReport(
  subdomains: string[],
  liveHosts: string[],
  urls: string[],
  ports: string[],
  vulns: string[],
  tech: string
): Promise<void> {
  if (!outputDir || !currentTarget) return;

  const report = `# Bug Bounty Report: ${currentTarget}

**Date:** ${new Date().toISOString()}
**Output Directory:** ${outputDir}

## Summary

| Category | Count |
|----------|-------|
| Subdomains | ${subdomains.length} |
| Live Hosts | ${liveHosts.length} |
| URLs Collected | ${urls.length} |
| Open Ports | ${ports.length} |
| Vulnerabilities | ${vulns.length} |

## Technology Stack
\`\`\`
${tech || "Not detected"}
\`\`\`

## Subdomains (${subdomains.length})
${subdomains.slice(0, 30).map(s => `- ${s}`).join("\n")}
${subdomains.length > 30 ? `\n... and ${subdomains.length - 30} more` : ""}

## Live Hosts (${liveHosts.length})
${liveHosts.slice(0, 20).map(h => `- ${h}`).join("\n")}
${liveHosts.length > 20 ? `\n... and ${liveHosts.length - 20} more` : ""}

## Open Ports
${ports.length > 0 ? ports.map(p => `- ${p}`).join("\n") : "No open ports found"}

## Vulnerabilities (${vulns.length})
${vulns.length > 0 ? vulns.map(v => `- 🔥 ${v}`).join("\n") : "No vulnerabilities found"}

## URLs with Parameters
${urls.filter(u => u.includes("=")).slice(0, 20).map(u => `- ${u}`).join("\n")}

---
*Generated by HackStrike AI Agent*
`;

  await fs.writeFile(path.join(outputDir, "reports", "report.md"), report);
}

// ============================================
// AUTONOMOUS SCAN
// ============================================

async function runFullScan(target: string): Promise<void> {
  console.log(`\n${c.cyan}╔════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  ${c.bold}🎯 AUTONOMOUS BUG BOUNTY SCAN${c.reset}`);
  console.log(`${c.cyan}╚════════════════════════════════════════════════════════════════╝${c.reset}\n`);

  // Phase 1: Set Target
  console.log(`${c.yellow}▶ PHASE 1: Setting Target${c.reset}`);
  await setTarget(target);
  
  // Phase 2: Subdomain Enumeration
  console.log(`\n${c.yellow}▶ PHASE 2: Subdomain Enumeration${c.reset}`);
  const subdomains = await subdomainEnum();
  console.log(`${c.green}   ✓ Total unique subdomains: ${subdomains.length}${c.reset}`);

  // Phase 3: Live Host Detection
  console.log(`\n${c.yellow}▶ PHASE 3: Live Host Detection${c.reset}`);
  const liveHosts = await liveHostCheck(subdomains);
  console.log(`${c.green}   ✓ Live hosts: ${liveHosts.length}${c.reset}`);

  // Phase 4: Technology Detection
  console.log(`\n${c.yellow}▶ PHASE 4: Technology Detection${c.reset}`);
  const tech = await techDetect();
  if (tech) {
    console.log(`${c.green}   ✓ ${tech}${c.reset}`);
  } else {
    console.log(`${c.dim}   No tech detected${c.reset}`);
  }

  // Phase 5: URL Collection
  console.log(`\n${c.yellow}▶ PHASE 5: URL Collection${c.reset}`);
  const urls = await urlCollection();
  const paramsUrls = urls.filter(u => u.includes("="));
  console.log(`${c.green}   ✓ Total URLs: ${urls.length} (${paramsUrls.length} with parameters)${c.reset}`);

  // Phase 6: Port Scanning
  console.log(`\n${c.yellow}▶ PHASE 6: Port Scanning${c.reset}`);
  const ports = await portScan(liveHosts);
  if (ports.length > 0) {
    console.log(`${c.green}   ✓ Open ports: ${ports.join(", ")}${c.reset}`);
  } else {
    console.log(`${c.dim}   No open ports found${c.reset}`);
  }

  // Phase 7: Vulnerability Scanning
  console.log(`\n${c.yellow}▶ PHASE 7: Vulnerability Scanning${c.reset}`);
  console.log(`${c.dim}   Running nuclei (this may take a while)...${c.reset}`);
  const vulns = await vulnScan(liveHosts);
  if (vulns.length > 0) {
    console.log(`${c.red}   🔥 FOUND ${vulns.length} VULNERABILITIES!${c.reset}`);
    vulns.forEach(v => console.log(`${c.red}      → ${v}${c.reset}`));
  } else {
    console.log(`${c.green}   ✓ No critical vulnerabilities found${c.reset}`);
  }

  // Phase 8: Generate Report
  console.log(`\n${c.yellow}▶ PHASE 8: Generating Report${c.reset}`);
  await generateReport(subdomains, liveHosts, urls, ports, vulns, tech);
  console.log(`${c.green}   ✓ Report saved to ${outputDir}/reports/report.md${c.reset}`);

  // Summary
  console.log(`\n${c.cyan}╔════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  ${c.bold}📊 SCAN COMPLETE${c.reset}`);
  console.log(`${c.cyan}╚════════════════════════════════════════════════════════════════╝${c.reset}`);
  console.log(`
   ${c.bold}Target:${c.reset}          ${currentTarget}
   ${c.bold}Subdomains:${c.reset}      ${subdomains.length}
   ${c.bold}Live Hosts:${c.reset}      ${liveHosts.length}
   ${c.bold}URLs:${c.reset}            ${urls.length}
   ${c.bold}Open Ports:${c.reset}      ${ports.length}
   ${c.bold}Vulnerabilities:${c.reset} ${vulns.length > 0 ? c.red + vulns.length + c.reset : "0"}
   ${c.bold}Results:${c.reset}         ${outputDir}
`);

  // AI Analysis
  if (vulns.length > 0 || paramsUrls.length > 10) {
    console.log(`${c.magenta}🤖 AI Analysis:${c.reset}`);
    const analysis = await askOllama(
      `I found ${vulns.length} vulnerabilities and ${paramsUrls.length} URLs with parameters on ${currentTarget}. ` +
      `Vulnerabilities: ${vulns.slice(0, 5).join(", ")}. ` +
      `What should I test next? Be very brief.`
    );
    if (analysis) {
      console.log(`${c.cyan}   ${analysis}${c.reset}`);
    }
  }
}

// Quick scans
async function runQuickRecon(target: string): Promise<void> {
  console.log(`\n${c.cyan}🔍 Quick Recon: ${target}${c.reset}\n`);
  
  await setTarget(target);
  
  console.log(`${c.yellow}▶ Subdomains${c.reset}`);
  const subs = await subdomainEnum();
  console.log(`${c.green}   ✓ Found ${subs.length} subdomains${c.reset}`);
  
  console.log(`\n${c.yellow}▶ Technology${c.reset}`);
  const tech = await techDetect();
  console.log(`${c.green}   ${tech || "Unknown"}${c.reset}`);
  
  console.log(`\n${c.dim}Results saved to: ${outputDir}${c.reset}`);
}

async function runVulnOnly(target: string): Promise<void> {
  console.log(`\n${c.cyan}🔥 Vulnerability Scan: ${target}${c.reset}\n`);
  
  await setTarget(target);
  
  console.log(`${c.dim}Running nuclei...${c.reset}`);
  const vulns = await vulnScan([`https://${target}`]);
  
  if (vulns.length > 0) {
    console.log(`\n${c.red}🔥 Found ${vulns.length} vulnerabilities:${c.reset}`);
    vulns.forEach(v => console.log(`${c.red}   → ${v}${c.reset}`));
  } else {
    console.log(`\n${c.green}✓ No vulnerabilities found${c.reset}`);
  }
}

// ============================================
// MAIN
// ============================================

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
  console.log(`${c.bold}         🤖 AUTONOMOUS Bug Bounty Agent ${c.yellow}(FREE)${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
}

function printHelp() {
  console.log(`
${c.cyan}Usage:${c.reset}
  ${c.green}scan <domain>${c.reset}       Full autonomous scan (subdomains, urls, vulns, etc.)
  ${c.green}recon <domain>${c.reset}      Quick reconnaissance only
  ${c.green}vulns <domain>${c.reset}      Vulnerability scan only
  ${c.green}help${c.reset}                Show this help
  ${c.green}exit${c.reset}                Exit

${c.cyan}Examples:${c.reset}
  scan example.com
  recon hackerone.com
  vulns bugcrowd.com
`);
}

async function main() {
  printBanner();
  
  // Check tools
  const tools = ["subfinder", "httpx", "nuclei", "gau"];
  const available = await Promise.all(tools.map(async t => ({ name: t, installed: await toolExists(t) })));
  const installed = available.filter(t => t.installed).map(t => t.name);
  const missing = available.filter(t => !t.installed).map(t => t.name);
  
  console.log(`\n${c.green}[+] Tools available: ${installed.join(", ") || "none"}${c.reset}`);
  if (missing.length) {
    console.log(`${c.yellow}[!] Missing: ${missing.join(", ")}${c.reset}`);
  }
  
  // Check for command line arguments
  const args = process.argv.slice(2);
  if (args.length >= 2) {
    const [cmd, target] = args;
    if (cmd === "scan") {
      await runFullScan(target);
      process.exit(0);
    } else if (cmd === "recon") {
      await runQuickRecon(target);
      process.exit(0);
    } else if (cmd === "vulns") {
      await runVulnOnly(target);
      process.exit(0);
    }
  }

  console.log(`\n${c.dim}Type 'help' for commands or 'scan <domain>' to start${c.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const prompt = () => {
    const targetInfo = currentTarget ? `${c.green}[${currentTarget}]${c.reset} ` : "";
    rl.question(`${targetInfo}${c.magenta}hackstrike>${c.reset} `, async (input) => {
      const trimmed = input.trim();
      
      if (!trimmed) { prompt(); return; }
      
      const [cmd, ...rest] = trimmed.split(/\s+/);
      const target = rest.join(" ");
      
      switch (cmd.toLowerCase()) {
        case "exit":
        case "quit":
        case "q":
          console.log(`${c.cyan}Goodbye! 🎯${c.reset}`);
          process.exit(0);
          
        case "help":
        case "h":
        case "?":
          printHelp();
          break;
          
        case "clear":
          console.clear();
          printBanner();
          break;
          
        case "scan":
          if (!target) {
            console.log(`${c.red}Usage: scan <domain>${c.reset}`);
          } else {
            await runFullScan(target);
          }
          break;
          
        case "recon":
          if (!target) {
            console.log(`${c.red}Usage: recon <domain>${c.reset}`);
          } else {
            await runQuickRecon(target);
          }
          break;
          
        case "vulns":
        case "vuln":
          if (!target) {
            console.log(`${c.red}Usage: vulns <domain>${c.reset}`);
          } else {
            await runVulnOnly(target);
          }
          break;
          
        default:
          // Try to parse as "scan domain.com" without explicit command
          const domainMatch = trimmed.match(/^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$/);
          if (domainMatch) {
            await runFullScan(trimmed);
          } else if (trimmed.toLowerCase().includes("scan")) {
            const domain = trimmed.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/);
            if (domain) {
              await runFullScan(domain[0]);
            } else {
              console.log(`${c.red}Could not find domain. Usage: scan <domain>${c.reset}`);
            }
          } else {
            console.log(`${c.yellow}Unknown command. Type 'help' for usage.${c.reset}`);
          }
      }
      
      prompt();
    });
  };

  prompt();
}

main().catch(console.error);
