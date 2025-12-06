#!/usr/bin/env node
/**
 * HackStrike MCP Server
 * Exposes bug bounty tools as MCP-compatible functions for AI agents
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { exec, spawn } from "child_process";
import { promisify } from "util";
import * as fs from "fs/promises";
import * as path from "path";

const execAsync = promisify(exec);

// Configuration
const HACKTOOLS_DIR = path.resolve(process.env.HACKTOOLS_DIR || "/home/hitarth/HackTools");
const RESULTS_DIR = path.join(HACKTOOLS_DIR, "results");
const WORDLIST_DIR = process.env.WORDLIST_DIR || "/usr/share/seclists";

// Current session state
let currentTarget: string | null = null;
let outputDir: string | null = null;

// Helper function to run commands with timeout
async function runCommand(
  command: string,
  timeout: number = 300000
): Promise<{ stdout: string; stderr: string; success: boolean }> {
  try {
    const { stdout, stderr } = await execAsync(command, {
      timeout,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer
    });
    return { stdout, stderr, success: true };
  } catch (error: any) {
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
      success: false,
    };
  }
}

// Check if a tool is installed
async function isToolInstalled(tool: string): Promise<boolean> {
  try {
    await execAsync(`which ${tool}`);
    return true;
  } catch {
    return false;
  }
}

// Setup output directory for target
async function setupOutputDir(target: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
  const cleanTarget = target.replace(/^https?:\/\//, "").replace(/[\/]/g, "_");
  const dir = path.join(RESULTS_DIR, `${cleanTarget}_${timestamp}`);
  
  await fs.mkdir(dir, { recursive: true });
  await fs.mkdir(path.join(dir, "subdomains"), { recursive: true });
  await fs.mkdir(path.join(dir, "urls"), { recursive: true });
  await fs.mkdir(path.join(dir, "ports"), { recursive: true });
  await fs.mkdir(path.join(dir, "vulns"), { recursive: true });
  await fs.mkdir(path.join(dir, "secrets"), { recursive: true });
  await fs.mkdir(path.join(dir, "params"), { recursive: true });
  await fs.mkdir(path.join(dir, "reports"), { recursive: true });
  
  return dir;
}

// Define all bug bounty tools
const bugBountyTools: Tool[] = [
  {
    name: "set_target",
    description: "Set the target domain or IP for scanning. This must be called before running any scans.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "The target domain (e.g., example.com) or IP address",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "get_target",
    description: "Get the currently set target and output directory",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "subdomain_enum",
    description: "Enumerate subdomains using multiple tools (subfinder, amass, assetfinder). Returns a list of discovered subdomains.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target domain (uses current target if not specified)",
        },
        tools: {
          type: "array",
          items: { type: "string" },
          description: "Specific tools to use: subfinder, amass, assetfinder, findomain. Default: all available",
        },
        passive_only: {
          type: "boolean",
          description: "Only use passive techniques (default: true)",
        },
      },
    },
  },
  {
    name: "live_host_detection",
    description: "Check which hosts are live and responding using httpx or httprobe",
    inputSchema: {
      type: "object",
      properties: {
        hosts_file: {
          type: "string",
          description: "Path to file containing hosts (one per line). Uses subdomain results if not specified.",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 50)",
        },
      },
    },
  },
  {
    name: "port_scan",
    description: "Scan for open ports on target using nmap or naabu",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target host or IP",
        },
        ports: {
          type: "string",
          description: "Port specification (e.g., '80,443', '1-1000', 'top100'). Default: top 1000",
        },
        scan_type: {
          type: "string",
          enum: ["quick", "full", "stealth"],
          description: "Scan type: quick (common ports), full (all ports), stealth (SYN scan)",
        },
      },
    },
  },
  {
    name: "url_collection",
    description: "Collect URLs from various sources using gau, waybackurls, katana, hakrawler",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target domain or URL",
        },
        tools: {
          type: "array",
          items: { type: "string" },
          description: "Tools to use: gau, waybackurls, katana, hakrawler. Default: all available",
        },
        filter_extensions: {
          type: "boolean",
          description: "Filter out static files (images, css, js). Default: true",
        },
      },
    },
  },
  {
    name: "vulnerability_scan",
    description: "Run vulnerability scanning using Nuclei templates",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL or file with URLs",
        },
        severity: {
          type: "array",
          items: { type: "string" },
          description: "Severity levels: info, low, medium, high, critical. Default: medium,high,critical",
        },
        templates: {
          type: "array",
          items: { type: "string" },
          description: "Specific template tags to use (e.g., cve, xss, sqli, lfi)",
        },
        rate_limit: {
          type: "number",
          description: "Requests per second (default: 150)",
        },
      },
    },
  },
  {
    name: "xss_scan",
    description: "Test for Cross-Site Scripting (XSS) vulnerabilities using dalfox",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameters to test",
        },
        urls_file: {
          type: "string",
          description: "File containing URLs to test",
        },
        blind_xss: {
          type: "string",
          description: "Blind XSS callback URL (e.g., your.xss.ht)",
        },
      },
    },
  },
  {
    name: "sqli_scan",
    description: "Test for SQL Injection vulnerabilities using sqlmap",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameters",
        },
        level: {
          type: "number",
          description: "Test level 1-5 (default: 2)",
        },
        risk: {
          type: "number",
          description: "Risk level 1-3 (default: 2)",
        },
        technique: {
          type: "string",
          description: "SQL injection techniques: BEUSTQ (default: all)",
        },
      },
    },
  },
  {
    name: "directory_fuzz",
    description: "Fuzz for hidden directories and files using ffuf or feroxbuster",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to fuzz",
        },
        wordlist: {
          type: "string",
          description: "Wordlist to use (default: common.txt)",
        },
        extensions: {
          type: "string",
          description: "File extensions to try (e.g., 'php,html,js')",
        },
        threads: {
          type: "number",
          description: "Concurrent threads (default: 50)",
        },
        recursive: {
          type: "boolean",
          description: "Enable recursive fuzzing (default: false)",
        },
      },
    },
  },
  {
    name: "tech_detect",
    description: "Detect technologies, frameworks, and CMS used by the target",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL",
        },
      },
    },
  },
  {
    name: "waf_detect",
    description: "Detect Web Application Firewall (WAF) presence",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL",
        },
      },
    },
  },
  {
    name: "secret_scan",
    description: "Scan for exposed secrets, API keys, and sensitive data",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL or directory to scan",
        },
        js_files: {
          type: "boolean",
          description: "Scan JavaScript files for secrets (default: true)",
        },
      },
    },
  },
  {
    name: "param_discovery",
    description: "Discover hidden parameters using Arjun",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL",
        },
        methods: {
          type: "array",
          items: { type: "string" },
          description: "HTTP methods to test: GET, POST, JSON. Default: GET",
        },
      },
    },
  },
  {
    name: "cors_check",
    description: "Check for CORS misconfiguration vulnerabilities",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to check",
        },
      },
    },
  },
  {
    name: "subdomain_takeover",
    description: "Check for subdomain takeover vulnerabilities",
    inputSchema: {
      type: "object",
      properties: {
        subdomains_file: {
          type: "string",
          description: "File containing subdomains to check",
        },
      },
    },
  },
  {
    name: "read_results",
    description: "Read results from a specific scan output file",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Relative path within output directory (e.g., 'subdomains/subfinder.txt')",
        },
        lines: {
          type: "number",
          description: "Number of lines to read (default: 100, use -1 for all)",
        },
      },
    },
  },
  {
    name: "list_results",
    description: "List all result files in the current output directory",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "run_custom_command",
    description: "Run a custom shell command for advanced operations. Use with caution.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "Shell command to execute",
        },
        timeout: {
          type: "number",
          description: "Timeout in seconds (default: 300)",
        },
      },
      required: ["command"],
    },
  },
  {
    name: "generate_report",
    description: "Generate a summary report of all findings",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["markdown", "json", "txt"],
          description: "Output format (default: markdown)",
        },
      },
    },
  },
];

// Tool implementations
async function handleSetTarget(args: { target: string }) {
  const target = args.target.replace(/^https?:\/\//, "").replace(/\/$/, "");
  currentTarget = target;
  outputDir = await setupOutputDir(target);
  
  return {
    success: true,
    target: currentTarget,
    output_directory: outputDir,
    message: `Target set to ${currentTarget}. Output will be saved to ${outputDir}`,
  };
}

async function handleGetTarget() {
  return {
    target: currentTarget,
    output_directory: outputDir,
    message: currentTarget 
      ? `Current target: ${currentTarget}` 
      : "No target set. Use set_target first.",
  };
}

async function handleSubdomainEnum(args: {
  target?: string;
  tools?: string[];
  passive_only?: boolean;
}) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified. Set target first using set_target." };
  }

  const results: Record<string, string[]> = {};
  const allSubdomains: Set<string> = new Set();
  const dir = outputDir || await setupOutputDir(target);

  // Subfinder
  if (!args.tools || args.tools.includes("subfinder")) {
    if (await isToolInstalled("subfinder")) {
      const outFile = path.join(dir, "subdomains", "subfinder.txt");
      const { stdout, success } = await runCommand(
        `subfinder -d ${target} -silent`,
        120000
      );
      if (success && stdout) {
        const subs = stdout.trim().split("\n").filter(Boolean);
        await fs.writeFile(outFile, subs.join("\n"));
        results.subfinder = subs;
        subs.forEach(s => allSubdomains.add(s));
      }
    }
  }

  // Amass (passive)
  if (!args.tools || args.tools.includes("amass")) {
    if (await isToolInstalled("amass")) {
      const outFile = path.join(dir, "subdomains", "amass.txt");
      const { stdout, success } = await runCommand(
        `timeout 180 amass enum -passive -d ${target}`,
        200000
      );
      if (success && stdout) {
        const subs = stdout.trim().split("\n").filter(Boolean);
        await fs.writeFile(outFile, subs.join("\n"));
        results.amass = subs;
        subs.forEach(s => allSubdomains.add(s));
      }
    }
  }

  // Assetfinder
  if (!args.tools || args.tools.includes("assetfinder")) {
    if (await isToolInstalled("assetfinder")) {
      const outFile = path.join(dir, "subdomains", "assetfinder.txt");
      const { stdout, success } = await runCommand(
        `assetfinder --subs-only ${target}`,
        120000
      );
      if (success && stdout) {
        const subs = stdout.trim().split("\n").filter(Boolean);
        await fs.writeFile(outFile, subs.join("\n"));
        results.assetfinder = subs;
        subs.forEach(s => allSubdomains.add(s));
      }
    }
  }

  // Findomain
  if (!args.tools || args.tools.includes("findomain")) {
    if (await isToolInstalled("findomain")) {
      const outFile = path.join(dir, "subdomains", "findomain.txt");
      const { stdout, success } = await runCommand(
        `findomain -t ${target} -q`,
        120000
      );
      if (success && stdout) {
        const subs = stdout.trim().split("\n").filter(Boolean);
        await fs.writeFile(outFile, subs.join("\n"));
        results.findomain = subs;
        subs.forEach(s => allSubdomains.add(s));
      }
    }
  }

  // Save merged results
  const merged = Array.from(allSubdomains).sort();
  await fs.writeFile(path.join(dir, "subdomains", "all_subdomains.txt"), merged.join("\n"));

  return {
    target,
    total_unique: merged.length,
    by_tool: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [k, v.length])
    ),
    subdomains: merged.slice(0, 50), // Return first 50
    output_file: path.join(dir, "subdomains", "all_subdomains.txt"),
    message: `Found ${merged.length} unique subdomains`,
  };
}

async function handleLiveHostDetection(args: {
  hosts_file?: string;
  threads?: number;
}) {
  if (!outputDir && !args.hosts_file) {
    return { error: "No target set and no hosts file specified." };
  }

  const hostsFile = args.hosts_file || path.join(outputDir!, "subdomains", "all_subdomains.txt");
  const threads = args.threads || 50;

  try {
    await fs.access(hostsFile);
  } catch {
    return { error: `Hosts file not found: ${hostsFile}` };
  }

  const outFile = path.join(outputDir!, "urls", "live_hosts.txt");

  if (await isToolInstalled("httpx")) {
    const { stdout, success } = await runCommand(
      `cat "${hostsFile}" | httpx -silent -threads ${threads}`,
      300000
    );
    if (success) {
      const liveHosts = stdout.trim().split("\n").filter(Boolean);
      await fs.writeFile(outFile, liveHosts.join("\n"));
      return {
        total_live: liveHosts.length,
        live_hosts: liveHosts.slice(0, 30),
        output_file: outFile,
        message: `Found ${liveHosts.length} live hosts`,
      };
    }
  }

  return { error: "httpx not installed" };
}

async function handlePortScan(args: {
  target?: string;
  ports?: string;
  scan_type?: "quick" | "full" | "stealth";
}) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  const scanType = args.scan_type || "quick";
  let portSpec = args.ports || "";
  let nmapFlags = "-sT -T4";

  switch (scanType) {
    case "quick":
      portSpec = portSpec || "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443";
      break;
    case "full":
      portSpec = portSpec || "1-65535";
      nmapFlags = "-sT -T4";
      break;
    case "stealth":
      nmapFlags = "-sS -T2";
      portSpec = portSpec || "1-1000";
      break;
  }

  const outFile = path.join(outputDir || RESULTS_DIR, "ports", `${target.replace(/\./g, "_")}_ports.txt`);
  await fs.mkdir(path.dirname(outFile), { recursive: true });

  // Try naabu first (faster)
  if (await isToolInstalled("naabu")) {
    const { stdout, success } = await runCommand(
      `naabu -host ${target} -p ${portSpec} -silent`,
      300000
    );
    if (success) {
      const ports = stdout.trim().split("\n").filter(Boolean);
      await fs.writeFile(outFile, ports.join("\n"));
      return {
        target,
        tool: "naabu",
        open_ports: ports,
        output_file: outFile,
        message: `Found ${ports.length} open ports`,
      };
    }
  }

  // Fallback to nmap
  if (await isToolInstalled("nmap")) {
    const { stdout, success } = await runCommand(
      `nmap ${nmapFlags} -p ${portSpec} ${target} --open -oG -`,
      600000
    );
    if (success) {
      const portMatches = stdout.match(/(\d+)\/open/g) || [];
      const ports = portMatches.map(p => p.replace("/open", ""));
      await fs.writeFile(outFile, ports.join("\n"));
      return {
        target,
        tool: "nmap",
        open_ports: ports,
        output_file: outFile,
        message: `Found ${ports.length} open ports`,
      };
    }
  }

  return { error: "Neither naabu nor nmap installed" };
}

async function handleUrlCollection(args: {
  target?: string;
  tools?: string[];
  filter_extensions?: boolean;
}) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  const results: Record<string, string[]> = {};
  const allUrls: Set<string> = new Set();
  const dir = outputDir || await setupOutputDir(target);
  const filterExt = args.filter_extensions !== false;

  // GAU
  if (!args.tools || args.tools.includes("gau")) {
    if (await isToolInstalled("gau")) {
      const { stdout, success } = await runCommand(
        `gau ${target} --threads 5`,
        180000
      );
      if (success && stdout) {
        let urls = stdout.trim().split("\n").filter(Boolean);
        if (filterExt) {
          urls = urls.filter(u => !/\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|ico)$/i.test(u));
        }
        await fs.writeFile(path.join(dir, "urls", "gau.txt"), urls.join("\n"));
        results.gau = urls;
        urls.forEach(u => allUrls.add(u));
      }
    }
  }

  // Waybackurls
  if (!args.tools || args.tools.includes("waybackurls")) {
    if (await isToolInstalled("waybackurls")) {
      const { stdout, success } = await runCommand(
        `echo "${target}" | waybackurls`,
        180000
      );
      if (success && stdout) {
        let urls = stdout.trim().split("\n").filter(Boolean);
        if (filterExt) {
          urls = urls.filter(u => !/\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|ico)$/i.test(u));
        }
        await fs.writeFile(path.join(dir, "urls", "wayback.txt"), urls.join("\n"));
        results.waybackurls = urls;
        urls.forEach(u => allUrls.add(u));
      }
    }
  }

  // Katana
  if (!args.tools || args.tools.includes("katana")) {
    if (await isToolInstalled("katana")) {
      const { stdout, success } = await runCommand(
        `katana -u https://${target} -silent -d 2`,
        180000
      );
      if (success && stdout) {
        let urls = stdout.trim().split("\n").filter(Boolean);
        await fs.writeFile(path.join(dir, "urls", "katana.txt"), urls.join("\n"));
        results.katana = urls;
        urls.forEach(u => allUrls.add(u));
      }
    }
  }

  // Save merged
  const merged = Array.from(allUrls);
  await fs.writeFile(path.join(dir, "urls", "all_urls.txt"), merged.join("\n"));

  // Find URLs with parameters
  const paramsUrls = merged.filter(u => u.includes("?") || u.includes("="));
  await fs.writeFile(path.join(dir, "urls", "params_urls.txt"), paramsUrls.join("\n"));

  return {
    target,
    total_urls: merged.length,
    urls_with_params: paramsUrls.length,
    by_tool: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [k, v.length])
    ),
    sample_urls: merged.slice(0, 20),
    output_file: path.join(dir, "urls", "all_urls.txt"),
    message: `Collected ${merged.length} URLs (${paramsUrls.length} with parameters)`,
  };
}

async function handleVulnScan(args: {
  target?: string;
  severity?: string[];
  templates?: string[];
  rate_limit?: number;
}) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  if (!(await isToolInstalled("nuclei"))) {
    return { error: "nuclei not installed" };
  }

  const severity = args.severity?.join(",") || "medium,high,critical";
  const rateLimit = args.rate_limit || 150;
  const dir = outputDir || RESULTS_DIR;
  const outFile = path.join(dir, "vulns", "nuclei_results.txt");

  let cmd = `nuclei -u https://${target} -severity ${severity} -rate-limit ${rateLimit} -silent`;
  
  if (args.templates?.length) {
    cmd += ` -tags ${args.templates.join(",")}`;
  }

  const { stdout, stderr, success } = await runCommand(cmd, 600000);
  
  const findings = stdout.trim().split("\n").filter(Boolean);
  await fs.writeFile(outFile, findings.join("\n"));

  return {
    target,
    total_findings: findings.length,
    findings: findings.slice(0, 20),
    output_file: outFile,
    message: success 
      ? `Found ${findings.length} potential vulnerabilities`
      : `Scan completed with warnings: ${stderr}`,
  };
}

async function handleXssScan(args: {
  target?: string;
  urls_file?: string;
  blind_xss?: string;
}) {
  if (!(await isToolInstalled("dalfox"))) {
    return { error: "dalfox not installed. Install with: go install github.com/hahwul/dalfox/v2@latest" };
  }

  const dir = outputDir || RESULTS_DIR;
  const outFile = path.join(dir, "vulns", "xss_results.txt");

  let cmd: string;
  if (args.urls_file) {
    cmd = `dalfox file ${args.urls_file} --silence`;
  } else if (args.target) {
    cmd = `dalfox url "${args.target}" --silence`;
  } else {
    // Use collected URLs with params
    const paramsFile = path.join(dir, "urls", "params_urls.txt");
    try {
      await fs.access(paramsFile);
      cmd = `head -100 "${paramsFile}" | dalfox pipe --silence`;
    } catch {
      return { error: "No target specified and no params URLs file found" };
    }
  }

  if (args.blind_xss) {
    cmd += ` --blind ${args.blind_xss}`;
  }

  const { stdout, success } = await runCommand(cmd, 600000);
  const findings = stdout.trim().split("\n").filter(Boolean);
  await fs.writeFile(outFile, findings.join("\n"));

  return {
    total_findings: findings.length,
    findings: findings.slice(0, 10),
    output_file: outFile,
    message: `XSS scan complete. Found ${findings.length} potential vulnerabilities`,
  };
}

async function handleSqliScan(args: {
  target: string;
  level?: number;
  risk?: number;
  technique?: string;
}) {
  if (!(await isToolInstalled("sqlmap"))) {
    return { error: "sqlmap not installed" };
  }

  const level = args.level || 2;
  const risk = args.risk || 2;
  const technique = args.technique || "BEUSTQ";
  const dir = outputDir || RESULTS_DIR;
  const outDir = path.join(dir, "vulns", "sqlmap");
  
  await fs.mkdir(outDir, { recursive: true });

  const cmd = `sqlmap -u "${args.target}" --level=${level} --risk=${risk} --technique=${technique} --batch --output-dir="${outDir}" --forms --crawl=2`;

  const { stdout, stderr, success } = await runCommand(cmd, 900000);

  return {
    target: args.target,
    output_directory: outDir,
    stdout: stdout.slice(-2000), // Last 2000 chars
    message: success 
      ? "SQLi scan complete. Check output directory for detailed results."
      : `Scan completed with issues: ${stderr.slice(-500)}`,
  };
}

async function handleDirectoryFuzz(args: {
  target?: string;
  wordlist?: string;
  extensions?: string;
  threads?: number;
  recursive?: boolean;
}) {
  const target = args.target || (currentTarget ? `https://${currentTarget}` : null);
  if (!target) {
    return { error: "No target specified" };
  }

  const threads = args.threads || 50;
  const dir = outputDir || RESULTS_DIR;
  const outFile = path.join(dir, "vulns", "fuzz_results.txt");

  // Try ffuf first
  if (await isToolInstalled("ffuf")) {
    const wordlist = args.wordlist || `${WORDLIST_DIR}/Discovery/Web-Content/common.txt`;
    let cmd = `ffuf -u ${target}/FUZZ -w ${wordlist} -t ${threads} -mc 200,201,301,302,403 -o ${outFile} -of json -s`;
    
    if (args.extensions) {
      cmd += ` -e ${args.extensions}`;
    }
    if (args.recursive) {
      cmd += " -recursion -recursion-depth 2";
    }

    const { stdout, success } = await runCommand(cmd, 600000);
    
    try {
      const results = JSON.parse(await fs.readFile(outFile, "utf8"));
      return {
        target,
        tool: "ffuf",
        total_found: results.results?.length || 0,
        findings: results.results?.slice(0, 20).map((r: any) => ({
          url: r.url,
          status: r.status,
          length: r.length,
        })),
        output_file: outFile,
        message: `Found ${results.results?.length || 0} endpoints`,
      };
    } catch {
      return { target, tool: "ffuf", output_file: outFile, message: "Scan complete" };
    }
  }

  // Fallback to feroxbuster
  if (await isToolInstalled("feroxbuster")) {
    const wordlist = args.wordlist || `${WORDLIST_DIR}/Discovery/Web-Content/common.txt`;
    const cmd = `feroxbuster -u ${target} -w ${wordlist} -t ${threads} -o ${outFile} --quiet`;
    
    await runCommand(cmd, 600000);
    return {
      target,
      tool: "feroxbuster",
      output_file: outFile,
      message: "Directory fuzzing complete",
    };
  }

  return { error: "Neither ffuf nor feroxbuster installed" };
}

async function handleTechDetect(args: { target?: string }) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  const url = target.startsWith("http") ? target : `https://${target}`;
  const results: Record<string, any> = {};

  // httpx with tech detection
  if (await isToolInstalled("httpx")) {
    const { stdout, success } = await runCommand(
      `echo "${url}" | httpx -silent -tech-detect -status-code -title -json`,
      60000
    );
    if (success && stdout) {
      try {
        const data = JSON.parse(stdout.trim());
        results.httpx = {
          technologies: data.tech || [],
          status_code: data.status_code,
          title: data.title,
        };
      } catch {}
    }
  }

  // whatweb
  if (await isToolInstalled("whatweb")) {
    const { stdout, success } = await runCommand(
      `whatweb -q "${url}" --log-json=-`,
      60000
    );
    if (success && stdout) {
      try {
        const data = JSON.parse(stdout.trim().split("\n")[0]);
        results.whatweb = data;
      } catch {}
    }
  }

  return {
    target: url,
    technologies: results,
    message: "Technology detection complete",
  };
}

async function handleWafDetect(args: { target?: string }) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  const url = target.startsWith("http") ? target : `https://${target}`;

  if (await isToolInstalled("wafw00f")) {
    const { stdout, success } = await runCommand(`wafw00f "${url}"`, 60000);
    
    const wafMatch = stdout.match(/is behind (.+)/i) || stdout.match(/detected: (.+)/i);
    const wafDetected = wafMatch ? wafMatch[1] : null;
    const noWaf = stdout.includes("No WAF detected");

    return {
      target: url,
      waf_detected: !noWaf,
      waf_name: wafDetected,
      raw_output: stdout,
      message: noWaf ? "No WAF detected" : `WAF detected: ${wafDetected}`,
    };
  }

  return { error: "wafw00f not installed" };
}

async function handleSecretScan(args: {
  target?: string;
  js_files?: boolean;
}) {
  const dir = outputDir || RESULTS_DIR;
  const outFile = path.join(dir, "secrets", "secrets.txt");

  // Use nuclei with exposure templates
  if (await isToolInstalled("nuclei")) {
    const target = args.target || currentTarget;
    if (!target) {
      return { error: "No target specified" };
    }

    const { stdout, success } = await runCommand(
      `nuclei -u https://${target} -tags exposure,token,secret -silent`,
      300000
    );
    
    const findings = stdout.trim().split("\n").filter(Boolean);
    await fs.writeFile(outFile, findings.join("\n"));

    return {
      target,
      total_findings: findings.length,
      findings: findings.slice(0, 20),
      output_file: outFile,
      message: `Found ${findings.length} potential secrets/exposures`,
    };
  }

  return { error: "nuclei not installed" };
}

async function handleParamDiscovery(args: {
  target?: string;
  methods?: string[];
}) {
  const target = args.target || (currentTarget ? `https://${currentTarget}` : null);
  if (!target) {
    return { error: "No target specified" };
  }

  if (!(await isToolInstalled("arjun"))) {
    return { error: "arjun not installed. Install with: pip3 install arjun" };
  }

  const dir = outputDir || RESULTS_DIR;
  const outFile = path.join(dir, "params", "arjun_params.json");
  const methods = args.methods || ["GET"];

  const { stdout, success } = await runCommand(
    `arjun -u "${target}" -m ${methods.join(",")} -oJ "${outFile}"`,
    300000
  );

  try {
    const results = JSON.parse(await fs.readFile(outFile, "utf8"));
    return {
      target,
      parameters: results,
      output_file: outFile,
      message: "Parameter discovery complete",
    };
  } catch {
    return {
      target,
      output_file: outFile,
      raw_output: stdout,
      message: "Parameter discovery complete",
    };
  }
}

async function handleCorsCheck(args: { target?: string }) {
  const target = args.target || currentTarget;
  if (!target) {
    return { error: "No target specified" };
  }

  const url = target.startsWith("http") ? target : `https://${target}`;
  
  // Test CORS with curl
  const origins = [
    "https://evil.com",
    "null",
    `https://${target}.evil.com`,
    "https://subdomain." + target,
  ];

  const results: any[] = [];
  
  for (const origin of origins) {
    const { stdout, success } = await runCommand(
      `curl -s -I -H "Origin: ${origin}" "${url}" | grep -i "access-control"`,
      30000
    );
    
    if (stdout.trim()) {
      results.push({
        origin,
        headers: stdout.trim(),
        vulnerable: stdout.toLowerCase().includes(origin.toLowerCase()),
      });
    }
  }

  const vulnerable = results.some(r => r.vulnerable);

  return {
    target: url,
    vulnerable,
    tests: results,
    message: vulnerable 
      ? "⚠️ CORS misconfiguration detected!" 
      : "No CORS misconfiguration found",
  };
}

async function handleSubdomainTakeover(args: { subdomains_file?: string }) {
  const dir = outputDir;
  const subsFile = args.subdomains_file || (dir ? path.join(dir, "subdomains", "all_subdomains.txt") : null);

  if (!subsFile) {
    return { error: "No subdomains file specified and no target set" };
  }

  try {
    await fs.access(subsFile);
  } catch {
    return { error: `Subdomains file not found: ${subsFile}` };
  }

  // Use nuclei takeover templates
  if (await isToolInstalled("nuclei")) {
    const outFile = path.join(dir || RESULTS_DIR, "vulns", "takeover_results.txt");
    
    const { stdout, success } = await runCommand(
      `nuclei -l "${subsFile}" -tags takeover -silent`,
      600000
    );
    
    const findings = stdout.trim().split("\n").filter(Boolean);
    await fs.writeFile(outFile, findings.join("\n"));

    return {
      total_checked: (await fs.readFile(subsFile, "utf8")).split("\n").length,
      vulnerable: findings.length,
      findings,
      output_file: outFile,
      message: findings.length > 0 
        ? `🔥 Found ${findings.length} potential subdomain takeovers!`
        : "No subdomain takeover vulnerabilities found",
    };
  }

  return { error: "nuclei not installed" };
}

async function handleReadResults(args: { file_path?: string; lines?: number }) {
  if (!outputDir) {
    return { error: "No target set. Set target first to establish output directory." };
  }

  const filePath = args.file_path 
    ? path.join(outputDir, args.file_path)
    : outputDir;

  try {
    const stats = await fs.stat(filePath);
    
    if (stats.isDirectory()) {
      const files = await fs.readdir(filePath, { recursive: true });
      return { 
        type: "directory",
        files: files.slice(0, 100),
        path: filePath,
      };
    }
    
    const content = await fs.readFile(filePath, "utf8");
    const lines = content.split("\n");
    const maxLines = args.lines === -1 ? lines.length : (args.lines || 100);
    
    return {
      type: "file",
      path: filePath,
      total_lines: lines.length,
      content: lines.slice(0, maxLines).join("\n"),
    };
  } catch (error: any) {
    return { error: `Failed to read: ${error.message}` };
  }
}

async function handleListResults() {
  if (!outputDir) {
    return { error: "No target set" };
  }

  const listDir = async (dir: string, prefix = ""): Promise<string[]> => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files: string[] = [];
    
    for (const entry of entries) {
      const fullPath = path.join(prefix, entry.name);
      if (entry.isDirectory()) {
        files.push(`📁 ${fullPath}/`);
        files.push(...await listDir(path.join(dir, entry.name), fullPath));
      } else {
        const stats = await fs.stat(path.join(dir, entry.name));
        files.push(`📄 ${fullPath} (${stats.size} bytes)`);
      }
    }
    return files;
  };

  const files = await listDir(outputDir);
  
  return {
    output_directory: outputDir,
    files,
    message: `Found ${files.length} items in output directory`,
  };
}

async function handleCustomCommand(args: { command: string; timeout?: number }) {
  const timeout = (args.timeout || 300) * 1000;
  const { stdout, stderr, success } = await runCommand(args.command, timeout);
  
  return {
    command: args.command,
    success,
    stdout: stdout.slice(-10000),
    stderr: stderr.slice(-2000),
  };
}

async function handleGenerateReport(args: { format?: string }) {
  if (!outputDir || !currentTarget) {
    return { error: "No target set" };
  }

  const format = args.format || "markdown";
  const reportFile = path.join(outputDir, "reports", `report.${format === "markdown" ? "md" : format}`);
  
  // Gather all results
  const results: Record<string, any> = {};
  
  const readIfExists = async (filePath: string) => {
    try {
      return (await fs.readFile(filePath, "utf8")).trim().split("\n").filter(Boolean);
    } catch {
      return [];
    }
  };

  results.subdomains = await readIfExists(path.join(outputDir, "subdomains", "all_subdomains.txt"));
  results.liveHosts = await readIfExists(path.join(outputDir, "urls", "live_hosts.txt"));
  results.urls = await readIfExists(path.join(outputDir, "urls", "all_urls.txt"));
  results.vulns = await readIfExists(path.join(outputDir, "vulns", "nuclei_results.txt"));
  results.xss = await readIfExists(path.join(outputDir, "vulns", "xss_results.txt"));

  if (format === "markdown") {
    const report = `# Bug Bounty Report: ${currentTarget}
    
**Generated:** ${new Date().toISOString()}
**Output Directory:** ${outputDir}

## Summary

| Category | Count |
|----------|-------|
| Subdomains | ${results.subdomains.length} |
| Live Hosts | ${results.liveHosts.length} |
| URLs Collected | ${results.urls.length} |
| Vulnerabilities | ${results.vulns.length} |
| XSS Findings | ${results.xss.length} |

## Subdomains (${results.subdomains.length})

${results.subdomains.slice(0, 50).map((s: string) => `- ${s}`).join("\n")}
${results.subdomains.length > 50 ? `\n... and ${results.subdomains.length - 50} more` : ""}

## Live Hosts (${results.liveHosts.length})

${results.liveHosts.slice(0, 30).map((h: string) => `- ${h}`).join("\n")}
${results.liveHosts.length > 30 ? `\n... and ${results.liveHosts.length - 30} more` : ""}

## Vulnerabilities (${results.vulns.length})

${results.vulns.length > 0 ? results.vulns.map((v: string) => `- 🔥 ${v}`).join("\n") : "No vulnerabilities found yet."}

## XSS Findings (${results.xss.length})

${results.xss.length > 0 ? results.xss.map((x: string) => `- ⚠️ ${x}`).join("\n") : "No XSS vulnerabilities found."}

---
*Report generated by HackStrike AI Agent*
`;
    
    await fs.writeFile(reportFile, report);
    
    return {
      target: currentTarget,
      report_file: reportFile,
      summary: {
        subdomains: results.subdomains.length,
        live_hosts: results.liveHosts.length,
        urls: results.urls.length,
        vulnerabilities: results.vulns.length,
        xss_findings: results.xss.length,
      },
      message: "Report generated successfully",
    };
  }

  // JSON format
  if (format === "json") {
    await fs.writeFile(reportFile, JSON.stringify({
      target: currentTarget,
      generated: new Date().toISOString(),
      results,
    }, null, 2));
  }

  return {
    target: currentTarget,
    report_file: reportFile,
    message: "Report generated",
  };
}

// Tool router
async function handleToolCall(name: string, args: any): Promise<any> {
  switch (name) {
    case "set_target":
      return handleSetTarget(args);
    case "get_target":
      return handleGetTarget();
    case "subdomain_enum":
      return handleSubdomainEnum(args);
    case "live_host_detection":
      return handleLiveHostDetection(args);
    case "port_scan":
      return handlePortScan(args);
    case "url_collection":
      return handleUrlCollection(args);
    case "vulnerability_scan":
      return handleVulnScan(args);
    case "xss_scan":
      return handleXssScan(args);
    case "sqli_scan":
      return handleSqliScan(args);
    case "directory_fuzz":
      return handleDirectoryFuzz(args);
    case "tech_detect":
      return handleTechDetect(args);
    case "waf_detect":
      return handleWafDetect(args);
    case "secret_scan":
      return handleSecretScan(args);
    case "param_discovery":
      return handleParamDiscovery(args);
    case "cors_check":
      return handleCorsCheck(args);
    case "subdomain_takeover":
      return handleSubdomainTakeover(args);
    case "read_results":
      return handleReadResults(args);
    case "list_results":
      return handleListResults();
    case "run_custom_command":
      return handleCustomCommand(args);
    case "generate_report":
      return handleGenerateReport(args);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// Create and run the MCP server
async function main() {
  const server = new Server(
    {
      name: "hackstrike-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: bugBountyTools,
  }));

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    
    try {
      const result = await handleToolCall(name, args || {});
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: error.message }),
          },
        ],
        isError: true,
      };
    }
  });

  // Start server with stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error("HackStrike MCP Server running...");
}

main().catch(console.error);
