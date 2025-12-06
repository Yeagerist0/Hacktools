#!/usr/bin/env node
/**
 * S3 Bucket Deep Analysis & Exploitation Module
 * Finds misconfigurations, exposed files, and generates POCs
 */

import { execSync, exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as https from 'https';
import * as http from 'http';

interface S3Finding {
  bucket: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  poc: string;
  evidence?: string;
}

interface S3AnalysisResult {
  bucket: string;
  exists: boolean;
  region?: string;
  publicAccess: boolean;
  listable: boolean;
  writable: boolean;
  findings: S3Finding[];
  files: string[];
  sensitiveFiles: string[];
}

const SENSITIVE_PATTERNS = [
  /\.env/i,
  /\.git/i,
  /config\.(json|yaml|yml|xml|ini)/i,
  /credentials/i,
  /password/i,
  /secret/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /backup/i,
  /\.sql$/i,
  /\.db$/i,
  /\.sqlite/i,
  /\.log$/i,
  /\.bak$/i,
  /\.old$/i,
  /\.zip$/i,
  /\.tar/i,
  /\.gz$/i,
  /id_rsa/i,
  /id_dsa/i,
  /authorized_keys/i,
  /aws/i,
  /token/i,
  /api[_-]?key/i,
  /private/i,
  /internal/i,
  /admin/i,
  /phpinfo/i,
  /web\.config/i,
  /\.htaccess/i,
  /\.htpasswd/i,
  /wp-config/i,
  /settings\.py/i,
  /application\.properties/i,
  /database\.yml/i,
];

const S3_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
  'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
  'sa-east-1', 'ca-central-1'
];

export class S3Hunter {
  private outputDir: string;
  private findings: S3Finding[] = [];
  
  constructor(outputDir: string) {
    this.outputDir = outputDir;
    fs.mkdirSync(path.join(outputDir, 's3-analysis'), { recursive: true });
  }

  private log(msg: string) {
    console.log(`[S3-Hunter] ${msg}`);
  }

  private success(msg: string) {
    console.log(`\x1b[32m[+] ${msg}\x1b[0m`);
  }

  private warning(msg: string) {
    console.log(`\x1b[33m[!] ${msg}\x1b[0m`);
  }

  private error(msg: string) {
    console.log(`\x1b[31m[-] ${msg}\x1b[0m`);
  }

  private critical(msg: string) {
    console.log(`\x1b[31m\x1b[1m[CRITICAL] ${msg}\x1b[0m`);
  }

  /**
   * Extract S3 buckets from JavaScript files
   */
  async extractS3FromJS(jsUrl: string): Promise<string[]> {
    const buckets: Set<string> = new Set();
    
    this.log(`Downloading JS file: ${jsUrl}`);
    
    try {
      const content = await this.fetchUrl(jsUrl);
      
      // Various S3 URL patterns
      const patterns = [
        /([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3\.amazonaws\.com/gi,
        /([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3-[a-z0-9\-]+\.amazonaws\.com/gi,
        /s3\.amazonaws\.com\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi,
        /s3-[a-z0-9\-]+\.amazonaws\.com\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi,
        /s3:\/\/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi,
        /arn:aws:s3:::([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])/gi,
        /['"]([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])['"][\s]*[,:][\s]*['"]?s3/gi,
        /bucket[\s]*[=:][\s]*['"]([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])['"]/gi,
      ];

      for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const bucket = match[1].toLowerCase();
          if (bucket && bucket.length >= 3 && bucket.length <= 63) {
            buckets.add(bucket);
          }
        }
      }

      // Save JS content for analysis
      const jsFileName = jsUrl.split('/').pop() || 'script.js';
      fs.writeFileSync(
        path.join(this.outputDir, 's3-analysis', jsFileName),
        content
      );

      this.success(`Found ${buckets.size} S3 bucket(s) in JS file`);
      
    } catch (err) {
      this.error(`Failed to fetch JS: ${err}`);
    }

    return Array.from(buckets);
  }

  /**
   * Check if bucket exists and get region
   */
  async checkBucketExists(bucket: string): Promise<{ exists: boolean; region?: string }> {
    this.log(`Checking if bucket exists: ${bucket}`);
    
    try {
      // Try HEAD request to bucket
      const response = await this.httpHead(`https://${bucket}.s3.amazonaws.com/`);
      
      if (response.statusCode === 200 || response.statusCode === 403 || response.statusCode === 301) {
        // Get region from headers
        const region = response.headers['x-amz-bucket-region'] as string || 'us-east-1';
        this.success(`Bucket EXISTS: ${bucket} (Region: ${region})`);
        return { exists: true, region };
      }
      
      return { exists: false };
    } catch {
      // Try different region endpoints
      for (const region of S3_REGIONS) {
        try {
          const response = await this.httpHead(`https://${bucket}.s3.${region}.amazonaws.com/`);
          if (response.statusCode === 200 || response.statusCode === 403) {
            this.success(`Bucket EXISTS: ${bucket} (Region: ${region})`);
            return { exists: true, region };
          }
        } catch {
          continue;
        }
      }
      return { exists: false };
    }
  }

  /**
   * Check if bucket is publicly listable
   */
  async checkPublicListing(bucket: string, region: string = 'us-east-1'): Promise<{ listable: boolean; files: string[] }> {
    this.log(`Checking public listing for: ${bucket}`);
    
    const files: string[] = [];
    
    try {
      const url = `https://${bucket}.s3.${region}.amazonaws.com/?list-type=2&max-keys=1000`;
      const content = await this.fetchUrl(url);
      
      if (content.includes('<ListBucketResult') || content.includes('<Contents>')) {
        this.critical(`BUCKET IS PUBLICLY LISTABLE: ${bucket}`);
        
        // Parse XML to extract file names
        const keyMatches = content.matchAll(/<Key>([^<]+)<\/Key>/g);
        for (const match of keyMatches) {
          files.push(match[1]);
        }
        
        this.findings.push({
          bucket,
          type: 'Public Listing',
          severity: 'critical',
          description: `S3 bucket ${bucket} allows public listing of objects`,
          poc: `curl "https://${bucket}.s3.${region}.amazonaws.com/?list-type=2"`,
          evidence: `Found ${files.length} files`
        });
        
        return { listable: true, files };
      }
    } catch {
      // Not listable
    }
    
    return { listable: false, files: [] };
  }

  /**
   * Check if bucket allows public write
   */
  async checkPublicWrite(bucket: string, region: string = 'us-east-1'): Promise<boolean> {
    this.log(`Checking public write for: ${bucket}`);
    
    // Use AWS CLI if available
    try {
      const testFile = `security-test-${Date.now()}.txt`;
      const testContent = 'Security test - please delete';
      
      // Try to upload a file
      execSync(
        `echo "${testContent}" | aws s3 cp - s3://${bucket}/${testFile} --no-sign-request 2>/dev/null`,
        { timeout: 10000 }
      );
      
      this.critical(`BUCKET ALLOWS PUBLIC WRITE: ${bucket}`);
      
      // Try to delete the test file
      try {
        execSync(`aws s3 rm s3://${bucket}/${testFile} --no-sign-request 2>/dev/null`, { timeout: 5000 });
      } catch {}
      
      this.findings.push({
        bucket,
        type: 'Public Write',
        severity: 'critical',
        description: `S3 bucket ${bucket} allows unauthenticated write access`,
        poc: `aws s3 cp test.txt s3://${bucket}/test.txt --no-sign-request`,
        evidence: 'Successfully uploaded test file'
      });
      
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check for ACL misconfigurations
   */
  async checkACL(bucket: string, region: string = 'us-east-1'): Promise<void> {
    this.log(`Checking ACL for: ${bucket}`);
    
    try {
      const url = `https://${bucket}.s3.${region}.amazonaws.com/?acl`;
      const content = await this.fetchUrl(url);
      
      if (content.includes('<AccessControlPolicy')) {
        this.warning(`ACL is publicly readable: ${bucket}`);
        
        // Check for dangerous grants
        if (content.includes('AllUsers') || content.includes('AuthenticatedUsers')) {
          this.critical(`Dangerous ACL grants found in: ${bucket}`);
          
          this.findings.push({
            bucket,
            type: 'ACL Misconfiguration',
            severity: 'high',
            description: `S3 bucket ${bucket} has dangerous ACL grants (AllUsers/AuthenticatedUsers)`,
            poc: `curl "https://${bucket}.s3.${region}.amazonaws.com/?acl"`,
            evidence: content.substring(0, 500)
          });
        }
      }
    } catch {}
  }

  /**
   * Check for sensitive files
   */
  async checkSensitiveFiles(bucket: string, files: string[], region: string = 'us-east-1'): Promise<string[]> {
    const sensitiveFiles: string[] = [];
    
    this.log(`Checking ${files.length} files for sensitive content...`);
    
    for (const file of files) {
      for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.test(file)) {
          sensitiveFiles.push(file);
          this.critical(`SENSITIVE FILE FOUND: ${file}`);
          
          // Try to download the file
          try {
            const url = `https://${bucket}.s3.${region}.amazonaws.com/${encodeURIComponent(file)}`;
            const response = await this.httpHead(url);
            
            if (response.statusCode === 200) {
              this.findings.push({
                bucket,
                type: 'Sensitive File Exposure',
                severity: 'critical',
                description: `Sensitive file publicly accessible: ${file}`,
                poc: `curl "https://${bucket}.s3.${region}.amazonaws.com/${encodeURIComponent(file)}"`,
              });
            }
          } catch {}
          break;
        }
      }
    }
    
    return sensitiveFiles;
  }

  /**
   * Brute force common file paths
   */
  async bruteForceFiles(bucket: string, region: string = 'us-east-1'): Promise<string[]> {
    const found: string[] = [];
    
    const commonPaths = [
      '.env',
      '.git/config',
      '.git/HEAD',
      'config.json',
      'config.yaml',
      'config.yml',
      'credentials.json',
      'secrets.json',
      'backup.sql',
      'database.sql',
      'dump.sql',
      'backup.zip',
      'backup.tar.gz',
      'data.csv',
      'users.csv',
      'passwords.txt',
      'id_rsa',
      'id_rsa.pub',
      'aws-credentials',
      '.aws/credentials',
      'wp-config.php',
      'web.config',
      '.htaccess',
      '.htpasswd',
      'phpinfo.php',
      'info.php',
      'test.php',
      'admin/',
      'private/',
      'internal/',
      'dev/',
      'staging/',
      'prod/',
      'logs/',
      'log/',
      'debug.log',
      'error.log',
      'access.log',
      'application.properties',
      'settings.py',
      'local_settings.py',
      'database.yml',
      '.dockerenv',
      'docker-compose.yml',
      'Dockerfile',
      'terraform.tfstate',
      '.terraform/',
      'ansible.cfg',
      'vault.yml',
      'secrets/',
      'keys/',
      'certs/',
      'ssl/',
      'pem/',
    ];

    this.log(`Brute forcing ${commonPaths.length} common paths...`);

    const promises = commonPaths.map(async (filePath) => {
      try {
        const url = `https://${bucket}.s3.${region}.amazonaws.com/${filePath}`;
        const response = await this.httpHead(url);
        
        if (response.statusCode === 200) {
          found.push(filePath);
          this.critical(`FOUND: ${filePath}`);
          
          this.findings.push({
            bucket,
            type: 'Exposed File',
            severity: 'high',
            description: `File publicly accessible: ${filePath}`,
            poc: `curl "https://${bucket}.s3.${region}.amazonaws.com/${filePath}"`,
          });
        }
      } catch {}
    });

    await Promise.all(promises);
    
    return found;
  }

  /**
   * Check for bucket policy
   */
  async checkBucketPolicy(bucket: string, region: string = 'us-east-1'): Promise<void> {
    this.log(`Checking bucket policy for: ${bucket}`);
    
    try {
      const url = `https://${bucket}.s3.${region}.amazonaws.com/?policy`;
      const content = await this.fetchUrl(url);
      
      if (content.includes('{') && content.includes('Statement')) {
        this.warning(`Bucket policy is publicly readable: ${bucket}`);
        
        // Check for dangerous policies
        if (content.includes('"*"') || content.includes('"Principal":"*"')) {
          this.critical(`Dangerous bucket policy found: ${bucket}`);
          
          this.findings.push({
            bucket,
            type: 'Policy Misconfiguration',
            severity: 'high',
            description: `S3 bucket ${bucket} has overly permissive policy`,
            poc: `curl "https://${bucket}.s3.${region}.amazonaws.com/?policy"`,
            evidence: content.substring(0, 500)
          });
        }
        
        // Save policy
        fs.writeFileSync(
          path.join(this.outputDir, 's3-analysis', `${bucket}-policy.json`),
          content
        );
      }
    } catch {}
  }

  /**
   * Full S3 bucket analysis
   */
  async analyzeBucket(bucket: string): Promise<S3AnalysisResult> {
    console.log('\n' + '═'.repeat(70));
    console.log(`🪣 ANALYZING S3 BUCKET: ${bucket}`);
    console.log('═'.repeat(70) + '\n');

    const result: S3AnalysisResult = {
      bucket,
      exists: false,
      publicAccess: false,
      listable: false,
      writable: false,
      findings: [],
      files: [],
      sensitiveFiles: []
    };

    // Check if bucket exists
    const existsCheck = await this.checkBucketExists(bucket);
    result.exists = existsCheck.exists;
    result.region = existsCheck.region;

    if (!result.exists) {
      this.error(`Bucket does not exist or is not accessible: ${bucket}`);
      
      // Check for bucket takeover possibility
      this.findings.push({
        bucket,
        type: 'Potential Bucket Takeover',
        severity: 'medium',
        description: `S3 bucket ${bucket} does not exist - potential subdomain takeover if referenced in application`,
        poc: `aws s3 mb s3://${bucket} --region us-east-1`,
      });
      
      result.findings = this.findings.filter(f => f.bucket === bucket);
      return result;
    }

    const region = result.region || 'us-east-1';

    // Check public listing
    const listingCheck = await this.checkPublicListing(bucket, region);
    result.listable = listingCheck.listable;
    result.files = listingCheck.files;

    if (result.listable) {
      result.publicAccess = true;
      
      // Check for sensitive files in listing
      result.sensitiveFiles = await this.checkSensitiveFiles(bucket, result.files, region);
    }

    // Always brute force common paths
    const bruteForced = await this.bruteForceFiles(bucket, region);
    result.files.push(...bruteForced);

    // Check write access
    result.writable = await this.checkPublicWrite(bucket, region);

    // Check ACL
    await this.checkACL(bucket, region);

    // Check bucket policy
    await this.checkBucketPolicy(bucket, region);

    result.findings = this.findings.filter(f => f.bucket === bucket);
    
    return result;
  }

  /**
   * Generate POC report
   */
  generateReport(results: S3AnalysisResult[]): string {
    let report = `# S3 Bucket Security Analysis Report\n\n`;
    report += `**Generated:** ${new Date().toISOString()}\n\n`;
    report += `---\n\n`;

    let criticalCount = 0;
    let highCount = 0;

    for (const result of results) {
      report += `## Bucket: ${result.bucket}\n\n`;
      report += `- **Exists:** ${result.exists ? '✅ Yes' : '❌ No'}\n`;
      report += `- **Region:** ${result.region || 'Unknown'}\n`;
      report += `- **Publicly Listable:** ${result.listable ? '🚨 YES' : '✅ No'}\n`;
      report += `- **Publicly Writable:** ${result.writable ? '🚨 YES' : '✅ No'}\n`;
      report += `- **Files Found:** ${result.files.length}\n`;
      report += `- **Sensitive Files:** ${result.sensitiveFiles.length}\n\n`;

      if (result.findings.length > 0) {
        report += `### Findings\n\n`;
        
        for (const finding of result.findings) {
          if (finding.severity === 'critical') criticalCount++;
          if (finding.severity === 'high') highCount++;
          
          const severityEmoji = {
            critical: '🔴',
            high: '🟠',
            medium: '🟡',
            low: '🟢',
            info: '🔵'
          }[finding.severity];

          report += `#### ${severityEmoji} ${finding.type} (${finding.severity.toUpperCase()})\n\n`;
          report += `**Description:** ${finding.description}\n\n`;
          report += `**POC:**\n\`\`\`bash\n${finding.poc}\n\`\`\`\n\n`;
          
          if (finding.evidence) {
            report += `**Evidence:**\n\`\`\`\n${finding.evidence}\n\`\`\`\n\n`;
          }
        }
      }

      if (result.sensitiveFiles.length > 0) {
        report += `### Sensitive Files Found\n\n`;
        for (const file of result.sensitiveFiles) {
          report += `- \`${file}\`\n`;
        }
        report += '\n';
      }

      report += `---\n\n`;
    }

    // Summary
    report += `## Summary\n\n`;
    report += `- **Total Buckets Analyzed:** ${results.length}\n`;
    report += `- **Critical Findings:** ${criticalCount}\n`;
    report += `- **High Findings:** ${highCount}\n`;
    report += `- **Total Findings:** ${this.findings.length}\n\n`;

    // Save report
    const reportPath = path.join(this.outputDir, 's3-analysis', 'report.md');
    fs.writeFileSync(reportPath, report);
    this.success(`Report saved to: ${reportPath}`);

    // Also save JSON findings
    const jsonPath = path.join(this.outputDir, 's3-analysis', 'findings.json');
    fs.writeFileSync(jsonPath, JSON.stringify(this.findings, null, 2));

    return report;
  }

  // Helper methods
  private fetchUrl(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      
      const req = client.get(url, { timeout: 15000 }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      });
      
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout'));
      });
    });
  }

  private httpHead(url: string): Promise<http.IncomingMessage> {
    return new Promise((resolve, reject) => {
      const client = url.startsWith('https') ? https : http;
      
      const req = client.request(url, { method: 'HEAD', timeout: 10000 }, (res) => {
        resolve(res);
      });
      
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout'));
      });
      
      req.end();
    });
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log(`
╔══════════════════════════════════════════════════════════════════╗
║              🪣 S3 BUCKET HUNTER - Deep Analysis                 ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  s3-hunter <bucket-name>              Analyze a specific bucket
  s3-hunter --js <url>                 Extract & analyze buckets from JS
  s3-hunter --domain <domain>          Find buckets related to domain
  
Examples:
  s3-hunter airbnb-photos
  s3-hunter --js https://www.airbnb.com/sw-host_v1.js
  s3-hunter --domain airbnb.com
`);
    process.exit(0);
  }

  const outputDir = `/home/hitarth/HackTools/results/s3-analysis-${Date.now()}`;
  fs.mkdirSync(outputDir, { recursive: true });
  
  const hunter = new S3Hunter(outputDir);
  const results: S3AnalysisResult[] = [];

  if (args[0] === '--js' && args[1]) {
    // Extract buckets from JS and analyze them
    const buckets = await hunter.extractS3FromJS(args[1]);
    
    for (const bucket of buckets) {
      const result = await hunter.analyzeBucket(bucket);
      results.push(result);
    }
  } else if (args[0] === '--domain' && args[1]) {
    // Generate possible bucket names for domain
    const domain = args[1].replace(/\./g, '-');
    const baseDomain = args[1].split('.')[0];
    
    const possibleBuckets = [
      domain,
      baseDomain,
      `${baseDomain}-assets`,
      `${baseDomain}-static`,
      `${baseDomain}-images`,
      `${baseDomain}-photos`,
      `${baseDomain}-media`,
      `${baseDomain}-uploads`,
      `${baseDomain}-files`,
      `${baseDomain}-backup`,
      `${baseDomain}-backups`,
      `${baseDomain}-data`,
      `${baseDomain}-dev`,
      `${baseDomain}-staging`,
      `${baseDomain}-prod`,
      `${baseDomain}-production`,
      `${baseDomain}-public`,
      `${baseDomain}-private`,
      `${baseDomain}-logs`,
      `${baseDomain}-cdn`,
      `${baseDomain}-web`,
      `${baseDomain}-api`,
      `${baseDomain}-app`,
      `${baseDomain}-mobile`,
      `${baseDomain}-content`,
      `${baseDomain}-resources`,
    ];
    
    console.log(`Checking ${possibleBuckets.length} potential buckets for ${args[1]}...`);
    
    for (const bucket of possibleBuckets) {
      const result = await hunter.analyzeBucket(bucket);
      results.push(result);
    }
  } else {
    // Single bucket analysis
    const result = await hunter.analyzeBucket(args[0]);
    results.push(result);
  }

  // Generate report
  const report = hunter.generateReport(results);
  
  console.log('\n' + '═'.repeat(70));
  console.log('📋 ANALYSIS COMPLETE');
  console.log('═'.repeat(70));
  console.log(report);
}

main().catch(console.error);
