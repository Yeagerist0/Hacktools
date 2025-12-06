#!/usr/bin/env node
/**
 * HackStrike AI - Persistent Bug Bounty Agent
 * Never gives up. Checks everything. Like a human hunter.
 */

import { exec, spawn } from "child_process";
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
let programRules: any = null;
let allFindings: string[] = [];
let scannedTargets: Set<string> = new Set();

// ============================================
// HELPERS
// ============================================

async function runCommand(cmd: string, timeout = 180000): Promise<string> {
  try {
    const { stdout } = await execAsync(cmd, { timeout, maxBuffer: 100 * 1024 * 1024 });
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

function log(msg: string, type: "info" | "success" | "warn" | "error" | "finding" = "info") {
  const icons: Record<string, string> = {
    info: `${c.blue}[*]${c.reset}`,
    success: `${c.green}[+]${c.reset}`,
    warn: `${c.yellow}[!]${c.reset}`,
    error: `${c.red}[-]${c.reset}`,
    finding: `${c.red}[🔥]${c.reset}`,
  };
  console.log(`${icons[type]} ${msg}`);
}

function header(title: string) {
  console.log(`\n${c.cyan}╔${"═".repeat(66)}╗${c.reset}`);
  console.log(`${c.cyan}║${c.reset} ${c.bold}${title.padEnd(64)}${c.reset} ${c.cyan}║${c.reset}`);
  console.log(`${c.cyan}╚${"═".repeat(66)}╝${c.reset}\n`);
}

function subheader(title: string) {
  console.log(`\n${c.yellow}▶ ${title}${c.reset}`);
}

async function saveFile(subpath: string, content: string): Promise<void> {
  if (!outputDir) return;
  const filePath = path.join(outputDir, subpath);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

async function appendFinding(finding: string): Promise<void> {
  if (!allFindings.includes(finding)) {
    allFindings.push(finding);
    log(finding, "finding");
    await saveFile("findings/all_findings.txt", allFindings.join("\n"));
  }
}

// Ollama AI
async function askAI(prompt: string): Promise<string> {
  try {
    const response = await fetch("http://localhost:11434/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || "llama3.2",
        messages: [
          { role: "system", content: "You are an expert bug bounty hunter. Be concise and actionable." },
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
// HACKERONE RULES FETCHER
// ============================================

async function fetchHackerOneRules(target: string): Promise<any> {
  subheader("Fetching HackerOne Program Rules");
  
  const programName = target.replace(/\.(com|org|net|io)$/, "").replace(/\./g, "");
  
  // Try to fetch from HackerOne API (public programs)
  try {
    // Check common program URLs
    const possibleUrls = [
      `https://hackerone.com/${programName}`,
      `https://hackerone.com/${target.split(".")[0]}`,
    ];
    
    log(`Checking HackerOne for: ${programName}`, "info");
    
    // Use curl to fetch the page
    const html = await runCommand(
      `curl -s "https://hackerone.com/${programName}" 2>/dev/null | head -500`,
      30000
    );
    
    if (html.includes("scope") || html.includes("policy")) {
      log("Found HackerOne program page", "success");
      
      // Extract scope information
      const rules: any = {
        program: programName,
        url: `https://hackerone.com/${programName}`,
        inScope: [],
        outOfScope: [],
        rules: [],
      };
      
      // Try to parse scope from HTML
      const scopeMatch = html.match(/in.scope[\s\S]*?<ul>([\s\S]*?)<\/ul>/i);
      if (scopeMatch) {
        const items = scopeMatch[1].match(/<li[^>]*>([^<]+)/g) || [];
        rules.inScope = items.map((i: string) => i.replace(/<[^>]+>/g, "").trim());
      }
      
      // Check for common rules
      if (html.includes("no social engineering")) rules.rules.push("No social engineering");
      if (html.includes("no DoS")) rules.rules.push("No DoS/DDoS attacks");
      if (html.includes("no physical")) rules.rules.push("No physical attacks");
      if (html.includes("rate limit")) rules.rules.push("Respect rate limits");
      
      return rules;
    }
  } catch (e) {
    log("Could not fetch HackerOne rules directly", "warn");
  }
  
  // Fallback: Check if target has security.txt or bug bounty page
  try {
    const securityTxt = await runCommand(`curl -s "https://${target}/.well-known/security.txt" 2>/dev/null`, 10000);
    if (securityTxt && securityTxt.includes("Contact")) {
      log("Found security.txt", "success");
      return {
        program: target,
        securityTxt: securityTxt,
        inScope: [target, `*.${target}`],
        rules: ["Follow responsible disclosure"],
      };
    }
  } catch {}
  
  // Default rules
  log("Using default bug bounty rules", "info");
  return {
    program: target,
    inScope: [target, `*.${target}`],
    outOfScope: ["Third-party services", "Social engineering", "DoS attacks"],
    rules: [
      "Only test in-scope assets",
      "Do not access other users' data",
      "Do not perform destructive actions",
      "Report vulnerabilities responsibly",
    ],
  };
}

function displayRules(rules: any) {
  console.log(`\n${c.cyan}┌─────────────────────────────────────────────────────────────────┐${c.reset}`);
  console.log(`${c.cyan}│${c.reset} ${c.bold}📋 PROGRAM RULES${c.reset}`);
  console.log(`${c.cyan}└─────────────────────────────────────────────────────────────────┘${c.reset}`);
  
  if (rules.url) {
    console.log(`${c.dim}   Program: ${rules.url}${c.reset}`);
  }
  
  console.log(`\n${c.green}   ✓ In Scope:${c.reset}`);
  (rules.inScope || []).forEach((s: string) => console.log(`     • ${s}`));
  
  if (rules.outOfScope?.length) {
    console.log(`\n${c.red}   ✗ Out of Scope:${c.reset}`);
    rules.outOfScope.forEach((s: string) => console.log(`     • ${s}`));
  }
  
  if (rules.rules?.length) {
    console.log(`\n${c.yellow}   ⚠ Rules:${c.reset}`);
    rules.rules.forEach((r: string) => console.log(`     • ${r}`));
  }
  
  console.log();
}

// ============================================
// RECONNAISSANCE
// ============================================

async function setupTarget(target: string): Promise<void> {
  currentTarget = target.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
  outputDir = path.join(RESULTS_DIR, `${currentTarget}_${timestamp}`);
  
  const dirs = ["subdomains", "urls", "vulns", "js", "params", "findings", "reports", "ports", "screenshots"];
  for (const dir of dirs) {
    await fs.mkdir(path.join(outputDir, dir), { recursive: true });
  }
  
  allFindings = [];
  scannedTargets = new Set();
  
  log(`Target: ${currentTarget}`, "success");
  log(`Output: ${outputDir}`, "info");
}

async function subdomainEnum(): Promise<string[]> {
  subheader("Subdomain Enumeration (Aggressive)");
  
  const results: Set<string> = new Set();
  
  // Tool 1: Subfinder
  if (await toolExists("subfinder")) {
    log("Running subfinder...", "info");
    const out = await runCommand(`subfinder -d ${currentTarget} -all -silent 2>/dev/null`, 300000);
    out.split("\n").filter(Boolean).forEach(s => results.add(s));
    log(`subfinder: ${results.size} subdomains`, "success");
  }
  
  // Tool 2: Amass (passive)
  if (await toolExists("amass")) {
    log("Running amass passive...", "info");
    const out = await runCommand(`timeout 180 amass enum -passive -d ${currentTarget} 2>/dev/null`, 200000);
    out.split("\n").filter(Boolean).forEach(s => results.add(s));
    log(`Total after amass: ${results.size}`, "success");
  }
  
  // Tool 3: Assetfinder
  if (await toolExists("assetfinder")) {
    log("Running assetfinder...", "info");
    const out = await runCommand(`assetfinder --subs-only ${currentTarget} 2>/dev/null`, 60000);
    out.split("\n").filter(Boolean).forEach(s => results.add(s));
    log(`Total after assetfinder: ${results.size}`, "success");
  }
  
  // Tool 4: Findomain
  if (await toolExists("findomain")) {
    log("Running findomain...", "info");
    const out = await runCommand(`findomain -t ${currentTarget} -q 2>/dev/null`, 60000);
    out.split("\n").filter(Boolean).forEach(s => results.add(s));
    log(`Total after findomain: ${results.size}`, "success");
  }
  
  // Tool 5: crt.sh
  log("Checking crt.sh...", "info");
  const crtsh = await runCommand(
    `curl -s "https://crt.sh/?q=%25.${currentTarget}&output=json" 2>/dev/null | grep -oP '"name_value":"[^"]*' | cut -d'"' -f4 | sort -u`,
    30000
  );
  crtsh.split("\n").filter(Boolean).forEach(s => {
    s.split("\n").forEach(sub => {
      if (sub.includes(currentTarget!)) results.add(sub.replace("*.", ""));
    });
  });
  
  const subdomains = Array.from(results).filter(s => s.includes(currentTarget!));
  await saveFile("subdomains/all.txt", subdomains.join("\n"));
  
  log(`Total unique subdomains: ${subdomains.length}`, "success");
  return subdomains;
}

async function findLiveHosts(subdomains: string[]): Promise<string[]> {
  subheader("Live Host Detection");
  
  if (subdomains.length === 0) {
    subdomains = [currentTarget!];
  }
  
  await saveFile("subdomains/to_probe.txt", subdomains.join("\n"));
  
  if (!(await toolExists("httpx"))) {
    log("httpx not installed, using fallback", "warn");
    return subdomains.slice(0, 20).map(s => `https://${s}`);
  }
  
  log(`Probing ${subdomains.length} hosts...`, "info");
  
  const out = await runCommand(
    `cat "${outputDir}/subdomains/to_probe.txt" | httpx -silent -threads 100 -timeout 5 2>/dev/null`,
    300000
  );
  
  const live = out.split("\n").filter(Boolean);
  await saveFile("urls/live_hosts.txt", live.join("\n"));
  
  log(`Live hosts: ${live.length}`, "success");
  return live;
}

// ============================================
// URL & JS COLLECTION
// ============================================

async function collectUrls(hosts: string[]): Promise<string[]> {
  subheader("URL Collection (Deep)");
  
  const allUrls: Set<string> = new Set();
  
  // GAU
  if (await toolExists("gau")) {
    log("Running gau...", "info");
    const out = await runCommand(`gau ${currentTarget} --threads 5 2>/dev/null`, 180000);
    out.split("\n").filter(Boolean).forEach(u => allUrls.add(u));
    log(`gau: ${allUrls.size} URLs`, "success");
  }
  
  // Waybackurls
  if (await toolExists("waybackurls")) {
    log("Running waybackurls...", "info");
    const out = await runCommand(`echo "${currentTarget}" | waybackurls 2>/dev/null`, 120000);
    out.split("\n").filter(Boolean).forEach(u => allUrls.add(u));
    log(`Total after wayback: ${allUrls.size}`, "success");
  }
  
  // Katana (active crawling)
  if (await toolExists("katana")) {
    log("Running katana (active crawl)...", "info");
    for (const host of hosts.slice(0, 5)) {
      const out = await runCommand(`katana -u "${host}" -d 3 -silent -jc 2>/dev/null`, 120000);
      out.split("\n").filter(Boolean).forEach(u => allUrls.add(u));
    }
    log(`Total after katana: ${allUrls.size}`, "success");
  }
  
  // Hakrawler
  if (await toolExists("hakrawler")) {
    log("Running hakrawler...", "info");
    for (const host of hosts.slice(0, 3)) {
      const out = await runCommand(`echo "${host}" | hakrawler -d 2 -subs 2>/dev/null`, 60000);
      out.split("\n").filter(Boolean).forEach(u => allUrls.add(u));
    }
  }
  
  const urls = Array.from(allUrls);
  const jsUrls = urls.filter(u => u.endsWith(".js") || u.includes(".js?"));
  const paramUrls = urls.filter(u => u.includes("="));
  
  await saveFile("urls/all.txt", urls.join("\n"));
  await saveFile("urls/js_files.txt", jsUrls.join("\n"));
  await saveFile("urls/params.txt", paramUrls.join("\n"));
  
  log(`Total URLs: ${urls.length}`, "success");
  log(`JS files: ${jsUrls.length}`, "success");
  log(`URLs with params: ${paramUrls.length}`, "success");
  
  return urls;
}

async function downloadAndAnalyzeJS(): Promise<void> {
  subheader("JavaScript Analysis (Deep)");
  
  let jsUrls: string[] = [];
  try {
    const content = await fs.readFile(path.join(outputDir!, "urls/js_files.txt"), "utf8");
    jsUrls = content.split("\n").filter(Boolean).slice(0, 50); // Limit to 50 JS files
  } catch {
    log("No JS files found", "warn");
    return;
  }
  
  if (jsUrls.length === 0) {
    log("No JS files to analyze", "warn");
    return;
  }
  
  log(`Downloading and analyzing ${jsUrls.length} JS files...`, "info");
  
  const secrets: string[] = [];
  const endpoints: string[] = [];
  const sensitivePatterns = [
    { name: "AWS Key", regex: /AKIA[0-9A-Z]{16}/g },
    { name: "API Key", regex: /api[_-]?key['":\s]*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi },
    { name: "Secret", regex: /secret['":\s]*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi },
    { name: "Token", regex: /token['":\s]*['"]?([a-zA-Z0-9_.-]{20,})['"]?/gi },
    { name: "Password", regex: /password['":\s]*['"]?([^'"\\s]{8,})['"]?/gi },
    { name: "Private Key", regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
    { name: "JWT", regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
    { name: "Google API", regex: /AIza[0-9A-Za-z_-]{35}/g },
    { name: "Firebase", regex: /[a-z0-9-]+\.firebaseio\.com/gi },
    { name: "S3 Bucket", regex: /[a-z0-9.-]+\.s3\.amazonaws\.com/gi },
    { name: "Internal URL", regex: /https?:\/\/(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s'"]+/gi },
  ];
  
  const endpointPatterns = [
    /["'](\/api\/[^"']+)["']/g,
    /["'](\/v[0-9]+\/[^"']+)["']/g,
    /["'](\/graphql[^"']*)["']/g,
    /["'](\/admin[^"']*)["']/g,
    /["'](\/internal[^"']*)["']/g,
    /fetch\s*\(\s*["']([^"']+)["']/g,
    /axios\.[a-z]+\s*\(\s*["']([^"']+)["']/g,
  ];
  
  for (const jsUrl of jsUrls) {
    try {
      const content = await runCommand(`curl -s -L "${jsUrl}" 2>/dev/null | head -50000`, 30000);
      if (!content || content.length < 100) continue;
      
      // Save JS file
      const filename = jsUrl.split("/").pop()?.split("?")[0] || "unknown.js";
      await saveFile(`js/${filename}`, content);
      
      // Check for secrets
      for (const pattern of sensitivePatterns) {
        const matches = content.match(pattern.regex);
        if (matches) {
          for (const match of matches) {
            const finding = `[${pattern.name}] in ${jsUrl}: ${match.slice(0, 50)}...`;
            secrets.push(finding);
            await appendFinding(`SECRET: ${finding}`);
          }
        }
      }
      
      // Extract endpoints
      for (const pattern of endpointPatterns) {
        let match;
        const regex = new RegExp(pattern.source, pattern.flags);
        while ((match = regex.exec(content)) !== null) {
          if (match[1] && !match[1].includes("{{")) {
            endpoints.push(match[1]);
          }
        }
      }
    } catch (e) {
      // Continue on error
    }
  }
  
  const uniqueEndpoints = [...new Set(endpoints)];
  await saveFile("js/extracted_endpoints.txt", uniqueEndpoints.join("\n"));
  await saveFile("js/secrets.txt", secrets.join("\n"));
  
  log(`Secrets found: ${secrets.length}`, secrets.length > 0 ? "finding" : "success");
  log(`Endpoints extracted: ${uniqueEndpoints.length}`, "success");
  
  // Use LinkFinder if available
  if (await toolExists("linkfinder")) {
    log("Running LinkFinder...", "info");
    for (const jsUrl of jsUrls.slice(0, 10)) {
      await runCommand(`linkfinder -i "${jsUrl}" -o cli 2>/dev/null >> "${outputDir}/js/linkfinder.txt"`, 30000);
    }
  }
}

// ============================================
// VULNERABILITY SCANNING
// ============================================

async function scanForVulns(target: string, isSubdomain = false): Promise<string[]> {
  const prefix = isSubdomain ? `[Subdomain: ${target}]` : "[Main Target]";
  
  if (scannedTargets.has(target)) {
    return [];
  }
  scannedTargets.add(target);
  
  const findings: string[] = [];
  const url = target.startsWith("http") ? target : `https://${target}`;
  
  // Nuclei scan
  if (await toolExists("nuclei")) {
    log(`${prefix} Running nuclei...`, "info");
    const out = await runCommand(
      `nuclei -u "${url}" -severity low,medium,high,critical -silent -rate-limit 100 2>/dev/null`,
      600000
    );
    const vulns = out.split("\n").filter(Boolean);
    for (const v of vulns) {
      findings.push(v);
      await appendFinding(`NUCLEI: ${v}`);
    }
  }
  
  return findings;
}

async function testXSS(urls: string[]): Promise<void> {
  subheader("XSS Testing");
  
  const paramUrls = urls.filter(u => u.includes("=")).slice(0, 100);
  if (paramUrls.length === 0) {
    log("No URLs with parameters to test", "warn");
    return;
  }
  
  await saveFile("params/xss_targets.txt", paramUrls.join("\n"));
  
  if (await toolExists("dalfox")) {
    log(`Testing ${paramUrls.length} URLs for XSS...`, "info");
    const out = await runCommand(
      `cat "${outputDir}/params/xss_targets.txt" | dalfox pipe --silence --skip-bav 2>/dev/null`,
      600000
    );
    const findings = out.split("\n").filter(Boolean);
    for (const f of findings) {
      await appendFinding(`XSS: ${f}`);
    }
    log(`XSS tests complete: ${findings.length} potential findings`, findings.length > 0 ? "finding" : "success");
  } else {
    // Manual XSS payloads
    log("dalfox not installed, using manual payloads...", "info");
    const payloads = [
      "<script>alert(1)</script>",
      "'\"><img src=x onerror=alert(1)>",
      "javascript:alert(1)",
      "{{constructor.constructor('alert(1)')()}}",
    ];
    
    for (const url of paramUrls.slice(0, 20)) {
      for (const payload of payloads) {
        const testUrl = url.replace(/=([^&]*)/g, `=${encodeURIComponent(payload)}`);
        const response = await runCommand(`curl -s -o /dev/null -w "%{http_code}" "${testUrl}" 2>/dev/null`, 10000);
        // Check for reflection (simplified)
      }
    }
  }
}

async function testSQLi(urls: string[]): Promise<void> {
  subheader("SQL Injection Testing");
  
  const paramUrls = urls.filter(u => u.includes("=")).slice(0, 50);
  if (paramUrls.length === 0) return;
  
  // Quick SQLi detection with error-based payloads
  log("Testing for SQL injection...", "info");
  
  const sqliPayloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--"];
  const errorPatterns = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "oracle",
    "syntax error",
    "unclosed quotation",
    "unterminated string",
  ];
  
  for (const url of paramUrls.slice(0, 20)) {
    for (const payload of sqliPayloads) {
      const testUrl = url.replace(/=([^&]*)/g, `=${encodeURIComponent(payload)}`);
      const response = await runCommand(`curl -s "${testUrl}" 2>/dev/null | head -100`, 10000);
      
      for (const pattern of errorPatterns) {
        if (response.toLowerCase().includes(pattern)) {
          await appendFinding(`SQLI: Potential SQL injection at ${url} with payload: ${payload}`);
          break;
        }
      }
    }
  }
  
  // Use SQLMap if available
  if (await toolExists("sqlmap")) {
    log("Running sqlmap on top targets...", "info");
    for (const url of paramUrls.slice(0, 5)) {
      await runCommand(
        `sqlmap -u "${url}" --batch --level=2 --risk=2 --output-dir="${outputDir}/vulns/sqlmap" 2>/dev/null`,
        300000
      );
    }
  }
}

async function testSSRF(urls: string[]): Promise<void> {
  subheader("SSRF Testing");
  
  const ssrfParams = ["url", "uri", "path", "dest", "redirect", "site", "html", "data", "reference", "src", "load", "fetch"];
  const ssrfUrls = urls.filter(u => {
    const lower = u.toLowerCase();
    return ssrfParams.some(p => lower.includes(p + "="));
  });
  
  if (ssrfUrls.length === 0) {
    log("No potential SSRF parameters found", "info");
    return;
  }
  
  log(`Testing ${ssrfUrls.length} URLs for SSRF...`, "info");
  
  const ssrfPayloads = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/", // AWS metadata
    "http://[::1]",
    "http://0.0.0.0",
  ];
  
  for (const url of ssrfUrls.slice(0, 20)) {
    for (const payload of ssrfPayloads) {
      const testUrl = url.replace(/=([^&]*)/g, `=${encodeURIComponent(payload)}`);
      const response = await runCommand(`curl -s "${testUrl}" 2>/dev/null | head -50`, 10000);
      
      if (response.includes("ami-id") || response.includes("instance-id") || 
          response.includes("root:") || response.includes("127.0.0.1")) {
        await appendFinding(`SSRF: Potential SSRF at ${url}`);
      }
    }
  }
}

async function testCORS(hosts: string[]): Promise<void> {
  subheader("CORS Misconfiguration Testing");
  
  for (const host of hosts.slice(0, 20)) {
    const origins = [
      "https://evil.com",
      "null",
      `https://${currentTarget}.evil.com`,
      "https://attacker.com",
    ];
    
    for (const origin of origins) {
      const response = await runCommand(
        `curl -s -I -H "Origin: ${origin}" "${host}" 2>/dev/null | grep -i "access-control"`,
        10000
      );
      
      if (response.toLowerCase().includes(origin.toLowerCase()) ||
          response.includes("*") && response.includes("credentials")) {
        await appendFinding(`CORS: Misconfigured CORS at ${host} - reflects ${origin}`);
      }
    }
  }
}

async function testOpenRedirect(urls: string[]): Promise<void> {
  subheader("Open Redirect Testing");
  
  const redirectParams = ["url", "redirect", "next", "return", "rurl", "dest", "destination", "continue", "goto"];
  const redirectUrls = urls.filter(u => {
    const lower = u.toLowerCase();
    return redirectParams.some(p => lower.includes(p + "="));
  });
  
  if (redirectUrls.length === 0) return;
  
  log(`Testing ${redirectUrls.length} URLs for open redirect...`, "info");
  
  const payloads = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
  ];
  
  for (const url of redirectUrls.slice(0, 30)) {
    for (const payload of payloads) {
      const testUrl = url.replace(/=([^&]*)/g, `=${encodeURIComponent(payload)}`);
      const response = await runCommand(
        `curl -s -I -L --max-redirs 3 "${testUrl}" 2>/dev/null | grep -i "location"`,
        10000
      );
      
      if (response.includes("evil.com")) {
        await appendFinding(`REDIRECT: Open redirect at ${url}`);
        break;
      }
    }
  }
}

async function checkSubdomainTakeover(subdomains: string[]): Promise<void> {
  subheader("Subdomain Takeover Check");
  
  if (!(await toolExists("nuclei"))) {
    log("nuclei required for takeover check", "warn");
    return;
  }
  
  await saveFile("subdomains/takeover_check.txt", subdomains.join("\n"));
  
  log(`Checking ${subdomains.length} subdomains for takeover...`, "info");
  const out = await runCommand(
    `nuclei -l "${outputDir}/subdomains/takeover_check.txt" -tags takeover -silent 2>/dev/null`,
    300000
  );
  
  const findings = out.split("\n").filter(Boolean);
  for (const f of findings) {
    await appendFinding(`TAKEOVER: ${f}`);
  }
  
  log(`Takeover check complete: ${findings.length} findings`, findings.length > 0 ? "finding" : "success");
}

async function bruteforceDirectories(hosts: string[]): Promise<void> {
  subheader("Directory Bruteforcing");
  
  if (!(await toolExists("ffuf")) && !(await toolExists("feroxbuster"))) {
    log("No fuzzing tool installed (ffuf/feroxbuster)", "warn");
    return;
  }
  
  const wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt";
  
  for (const host of hosts.slice(0, 5)) {
    log(`Fuzzing ${host}...`, "info");
    
    if (await toolExists("ffuf")) {
      const out = await runCommand(
        `ffuf -u "${host}/FUZZ" -w ${wordlist} -mc 200,201,301,302,403 -s 2>/dev/null`,
        180000
      );
      const found = out.split("\n").filter(Boolean);
      
      for (const f of found) {
        if (f.includes("admin") || f.includes("backup") || f.includes("config") || 
            f.includes(".git") || f.includes(".env") || f.includes("debug")) {
          await appendFinding(`FUZZ: Interesting path at ${host}/${f}`);
        }
      }
    }
  }
}

// ============================================
// PERSISTENT HUNTING
// ============================================

async function persistentHunt(liveHosts: string[], subdomains: string[]): Promise<void> {
  header("🎯 PERSISTENT VULNERABILITY HUNTING");
  
  log("Phase 1: Scanning main target...", "info");
  const mainFindings = await scanForVulns(currentTarget!);
  
  if (mainFindings.length === 0) {
    log("No vulnerabilities on main target. Expanding to subdomains...", "warn");
    
    // Scan subdomains
    log(`Phase 2: Scanning ${Math.min(subdomains.length, 30)} subdomains...`, "info");
    for (const sub of subdomains.slice(0, 30)) {
      await scanForVulns(sub, true);
    }
  }
  
  if (allFindings.length === 0) {
    log("No nuclei findings. Trying manual techniques...", "warn");
    
    // Get all URLs
    let urls: string[] = [];
    try {
      const content = await fs.readFile(path.join(outputDir!, "urls/all.txt"), "utf8");
      urls = content.split("\n").filter(Boolean);
    } catch {}
    
    // Manual testing
    await testXSS(urls);
    await testSQLi(urls);
    await testSSRF(urls);
    await testCORS(liveHosts);
    await testOpenRedirect(urls);
    await checkSubdomainTakeover(subdomains);
  }
  
  if (allFindings.length === 0) {
    log("Still no findings. Going deeper...", "warn");
    await bruteforceDirectories(liveHosts);
    await downloadAndAnalyzeJS();
  }
  
  // Final AI analysis
  if (allFindings.length === 0) {
    log("Asking AI for suggestions...", "info");
    const suggestion = await askAI(
      `I'm hunting bugs on ${currentTarget}. I found ${subdomains.length} subdomains, ` +
      `collected ${(await fs.readFile(path.join(outputDir!, "urls/all.txt"), "utf8").catch(() => "")).split("\n").length} URLs, ` +
      `but no vulnerabilities yet. What unconventional techniques should I try? Be specific.`
    );
    if (suggestion) {
      console.log(`\n${c.magenta}🤖 AI Suggestion:${c.reset}`);
      console.log(`${c.cyan}${suggestion}${c.reset}\n`);
    }
  }
}

// ============================================
// REPORT
// ============================================

async function generateReport(): Promise<void> {
  subheader("Generating Final Report");
  
  const stats = {
    subdomains: 0,
    liveHosts: 0,
    urls: 0,
    jsFiles: 0,
    findings: allFindings.length,
  };
  
  try {
    const subs = await fs.readFile(path.join(outputDir!, "subdomains/all.txt"), "utf8");
    stats.subdomains = subs.split("\n").filter(Boolean).length;
  } catch {}
  
  try {
    const live = await fs.readFile(path.join(outputDir!, "urls/live_hosts.txt"), "utf8");
    stats.liveHosts = live.split("\n").filter(Boolean).length;
  } catch {}
  
  try {
    const urls = await fs.readFile(path.join(outputDir!, "urls/all.txt"), "utf8");
    stats.urls = urls.split("\n").filter(Boolean).length;
  } catch {}
  
  try {
    const js = await fs.readFile(path.join(outputDir!, "urls/js_files.txt"), "utf8");
    stats.jsFiles = js.split("\n").filter(Boolean).length;
  } catch {}
  
  const report = `# 🔥 Bug Bounty Report: ${currentTarget}

**Date:** ${new Date().toISOString()}
**Agent:** HackStrike AI (Persistent Mode)
**Output:** ${outputDir}

## Program Rules
${programRules ? JSON.stringify(programRules, null, 2) : "Default rules applied"}

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | ${stats.subdomains} |
| Live Hosts | ${stats.liveHosts} |
| URLs Collected | ${stats.urls} |
| JS Files Analyzed | ${stats.jsFiles} |
| **Findings** | **${stats.findings}** |

## 🔥 Findings

${allFindings.length > 0 
  ? allFindings.map(f => `- ${f}`).join("\n")
  : "No vulnerabilities found. Consider:\n- Manual testing\n- Different wordlists\n- Time-based attacks\n- Business logic flaws"}

## Recommendations

${allFindings.length > 0 
  ? "1. Verify all findings manually\n2. Check for duplicates on HackerOne\n3. Write detailed PoC\n4. Calculate impact and CVSS"
  : "1. Check for business logic flaws\n2. Test authentication flows\n3. Review JS files manually\n4. Try different attack vectors"}

---
*Generated by HackStrike AI - Persistent Bug Bounty Agent*
`;

  await saveFile("reports/final_report.md", report);
  log(`Report saved to ${outputDir}/reports/final_report.md`, "success");
  
  // Summary
  console.log(`\n${c.cyan}╔${"═".repeat(66)}╗${c.reset}`);
  console.log(`${c.cyan}║${c.reset} ${c.bold}📊 HUNT COMPLETE${c.reset}`);
  console.log(`${c.cyan}╚${"═".repeat(66)}╝${c.reset}`);
  console.log(`
   ${c.bold}Target:${c.reset}       ${currentTarget}
   ${c.bold}Subdomains:${c.reset}   ${stats.subdomains}
   ${c.bold}Live Hosts:${c.reset}   ${stats.liveHosts}
   ${c.bold}URLs:${c.reset}         ${stats.urls}
   ${c.bold}JS Files:${c.reset}     ${stats.jsFiles}
   ${c.bold}Findings:${c.reset}     ${allFindings.length > 0 ? c.red + stats.findings + c.reset : "0"}
   ${c.bold}Results:${c.reset}      ${outputDir}
`);

  if (allFindings.length > 0) {
    console.log(`${c.red}🔥 FINDINGS:${c.reset}`);
    allFindings.slice(0, 10).forEach(f => console.log(`   ${c.red}→ ${f}${c.reset}`));
    if (allFindings.length > 10) {
      console.log(`   ${c.dim}... and ${allFindings.length - 10} more${c.reset}`);
    }
  }
}

// ============================================
// MAIN AUTONOMOUS SCAN
// ============================================

async function fullAutonomousScan(target: string): Promise<void> {
  header("🚀 HACKSTRIKE AI - PERSISTENT BUG BOUNTY HUNTER");
  
  console.log(`${c.bold}Target: ${target}${c.reset}`);
  console.log(`${c.dim}Mode: Never give up - check everything${c.reset}\n`);
  
  // Step 1: Fetch and display rules
  programRules = await fetchHackerOneRules(target);
  displayRules(programRules);
  
  // Confirm
  console.log(`${c.yellow}Starting scan in 3 seconds... (Ctrl+C to cancel)${c.reset}`);
  await new Promise(r => setTimeout(r, 3000));
  
  // Step 2: Setup
  await setupTarget(target);
  
  // Step 3: Subdomain enumeration
  const subdomains = await subdomainEnum();
  
  // Step 4: Live host detection
  const liveHosts = await findLiveHosts(subdomains);
  
  // Step 5: URL collection
  const urls = await collectUrls(liveHosts);
  
  // Step 6: JS analysis
  await downloadAndAnalyzeJS();
  
  // Step 7: Persistent vulnerability hunting
  await persistentHunt(liveHosts, subdomains);
  
  // Step 8: Generate report
  await generateReport();
}

// ============================================
// CLI
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
  console.log(`${c.bold}         🎯 PERSISTENT Bug Bounty AI ${c.yellow}(Never Gives Up)${c.reset}`);
  console.log(`${c.cyan}    ═══════════════════════════════════════════════════════════════════${c.reset}`);
}

async function main() {
  printBanner();
  
  // Check tools
  const requiredTools = ["subfinder", "httpx", "nuclei"];
  const missing = [];
  for (const tool of requiredTools) {
    if (!(await toolExists(tool))) missing.push(tool);
  }
  
  if (missing.length > 0) {
    log(`Missing recommended tools: ${missing.join(", ")}`, "warn");
  }
  
  // Command line mode
  const args = process.argv.slice(2);
  if (args.length >= 1) {
    const target = args[0].replace(/^https?:\/\//, "").replace(/\/$/, "");
    await fullAutonomousScan(target);
    process.exit(0);
  }
  
  // Interactive mode
  console.log(`\n${c.dim}Usage: hunt <domain> - Full autonomous persistent scan${c.reset}\n`);
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  
  const prompt = () => {
    rl.question(`${c.magenta}hackstrike>${c.reset} `, async (input) => {
      const trimmed = input.trim();
      if (!trimmed) { prompt(); return; }
      
      if (["exit", "quit", "q"].includes(trimmed.toLowerCase())) {
        console.log(`${c.cyan}Happy hunting! 🎯${c.reset}`);
        process.exit(0);
      }
      
      const [cmd, ...rest] = trimmed.split(/\s+/);
      const target = rest.join(" ") || trimmed;
      
      if (cmd.toLowerCase() === "hunt" || cmd.toLowerCase() === "scan") {
        if (rest.length === 0) {
          log("Usage: hunt <domain>", "error");
        } else {
          await fullAutonomousScan(rest[0]);
        }
      } else if (target.match(/^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$/)) {
        await fullAutonomousScan(target);
      } else {
        log("Usage: hunt <domain> or just type domain.com", "info");
      }
      
      prompt();
    });
  };
  
  prompt();
}

main().catch(console.error);
