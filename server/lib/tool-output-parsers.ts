/**
 * Tool Output Parsers Registry
 *
 * Centralized parsing logic for all security tool outputs used in the
 * engagement orchestrator pipeline. Each tool's stdout is parsed into
 * a normalized ParsedFinding[] array.
 *
 * Extracted from engagement-orchestrator.ts to:
 * 1. Enable independent testing of parser logic
 * 2. Reduce orchestrator file size (~730 lines removed)
 * 3. Allow parser reuse in other contexts (e.g., standalone scan imports)
 *
 * Supported tools (30+):
 *   nuclei, nikto, httpx, naabu, gobuster, enum4linux, hydra, dig,
 *   smbclient, ldapsearch, onesixtyone, cloud_enum, s3scanner, trufflehog,
 *   aws, bash, ffuf, sslscan, whatweb, subfinder, feroxbuster, sqlmap,
 *   amass, katana, gospider, waybackurls, gau, curl, wpscan, testssl,
 *   scanforge-discovery
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type ParsedFinding = {
  severity: string; title: string; cve?: string; description?: string; cvss?: number; cwe?: string;
  endpoint?: string; matched_at?: string;
  evidence?: {
    request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string };
    response?: { statusCode?: number; headers?: Record<string, string>; body?: string };
    attackPayload?: string;
    vulnerableParam?: string;
    matchedPattern?: string;
    proofText?: string;
  };
};

/** Minimal asset shape needed by the parser (avoids importing full AssetStatus) */
export interface ParserAssetContext {
  hostname: string;
  ip?: string;
  ports?: Array<{ port: number; service: string; version?: string }>;
}

// ─── Parser Registry ──────────────────────────────────────────────────────────

export function parseToolOutput(
  tool: string,
  stdout: string,
  asset: ParserAssetContext
): ParsedFinding[] {
  const findings: ParsedFinding[] = [];
  if (!stdout || stdout.length < 10) return findings;

  switch (tool) {
    case "nuclei": {
      // Nuclei JSONL output: one JSON object per line (-jsonl flag)
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[')) continue; // skip empty lines and banner
        try {
          const obj = JSON.parse(trimmed);
          if (obj.info?.severity && obj.info?.name) {
            const cve = obj["matched-at"]?.match(/CVE-\d{4}-\d+/)?.[0] ||
                        obj.info?.classification?.cve?.[0] ||
                        obj["template-id"]?.match(/CVE-\d{4}-\d+/)?.[0];
            const matchedAt = obj["matched-at"] || obj.host || '';
            // Extract structured evidence from nuclei output
            const evidence: ParsedFinding['evidence'] = {};
            // Capture the matched URL and curl command as the request
            if (obj["curl-command"]) {
              const curlMatch = obj["curl-command"].match(/curl\s+(?:-[A-Z]+\s+)?['"]?(https?:\/\/[^'"\s]+)/);
              evidence.request = { method: obj.type === 'http' ? 'GET' : undefined, url: matchedAt || curlMatch?.[1] };
            } else if (matchedAt) {
              evidence.request = { url: matchedAt };
            }
            // Capture the response body/extracted data
            if (obj["extracted-results"] && Array.isArray(obj["extracted-results"]) && obj["extracted-results"].length > 0) {
              evidence.proofText = obj["extracted-results"].join('\n');
            }
            if (obj["matcher-name"]) {
              evidence.matchedPattern = obj["matcher-name"];
            }
            // Capture the response if available (nuclei -include-rr flag)
            if (obj.response) {
              const respStr = typeof obj.response === 'string' ? obj.response : '';
              const statusMatch = respStr.match(/^HTTP\/[\d.]+ (\d+)/);
              evidence.response = {
                statusCode: statusMatch ? parseInt(statusMatch[1]) : undefined,
                body: respStr.substring(0, 2000),
              };
            }
            // Capture the request if available
            if (obj.request) {
              const reqStr = typeof obj.request === 'string' ? obj.request : '';
              const methodMatch = reqStr.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/);
              if (methodMatch) {
                evidence.request = { ...evidence.request, method: methodMatch[1], url: methodMatch[2] };
              }
              if (reqStr.length > 0) {
                evidence.request = { ...evidence.request, body: reqStr.substring(0, 1000) };
              }
            }
            // Capture template-id as the matched pattern if no matcher-name
            if (!evidence.matchedPattern && obj["template-id"]) {
              evidence.matchedPattern = obj["template-id"];
            }
            findings.push({
              severity: obj.info.severity,
              title: `[Nuclei] ${obj.info.name}${matchedAt ? ` @ ${matchedAt}` : ''}`,
              cve,
              description: obj.info.description || undefined,
              cvss: obj.info.classification?.['cvss-score'] || obj.info.classification?.['cvss_score'] || undefined,
              cwe: obj.info.classification?.cwe?.[0] || undefined,
              endpoint: matchedAt || undefined,
              matched_at: matchedAt || undefined,
              evidence: Object.keys(evidence).length > 0 ? evidence : undefined,
            });
          }
        } catch { /* not JSON line — nuclei banner or progress output */ }
      }
      break;
    }
    case "nikto": {
      // Nikto text output: parse all finding lines (start with "+")
      // Nikto findings include: OSVDB, CVE, missing headers, misconfigurations, info leaks
      const niktoSkipPatterns = [
        /^\+ Target IP:/i,
        /^\+ Target Hostname:/i,
        /^\+ Target Port:/i,
        /^\+ Start Time:/i,
        /^\+ End Time:/i,
        /^\+ Server:/i,
        /^\+ \d+ host\(s\) tested/i,
        /^\+ \d+ items? checked/i,
        /^\+ No CGI Directories found/i,
        /^\+ ERROR:/i,
      ];
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("+")) continue;
        // Skip informational/meta lines
        if (niktoSkipPatterns.some(p => p.test(trimmed))) continue;

        const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
        const osvdb = trimmed.match(/OSVDB-\d+/)?.[0];
        // Determine severity based on content
        let severity = "info";
        // P2-FIX: "Uncommon header" findings are informational, not vulns.
        // Must check BEFORE the xss pattern because header names like
        // "x-xss-protection" contain "xss" and would false-positive as HIGH.
        if (/uncommon header|retrieved.*header/i.test(trimmed)) severity = "info";
        else if (cve) severity = "high";
        else if (osvdb) severity = "medium";
        else if (/is not present|not set|is not defined|header.*missing|missing.*header/i.test(trimmed)) severity = "low";
        else if (/directory indexing|listing|backup|config/i.test(trimmed)) severity = "medium";
        else if (/injection|xss|rfi|lfi|traversal|upload/i.test(trimmed)) severity = "high";
        else if (/default|sample|test|example/i.test(trimmed)) severity = "low";

        findings.push({
          severity,
          title: `[Nikto] ${trimmed.slice(2, 150).trim()}`,
          cve,
        });
      }
      break;
    }
    case "httpx": {
      // httpx JSON output: comprehensive parsing of all fields
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.tech && Array.isArray(obj.tech)) {
            for (const tech of obj.tech) {
              findings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
            }
          }
          if (obj.cdn_name) findings.push({ severity: "info", title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
          if (obj.webserver) findings.push({ severity: "info", title: `[httpx] Web Server: ${obj.webserver}` });
          if (obj.status_code) findings.push({ severity: "info", title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ''}`.trim() });
          if (obj.tls) {
            if (obj.tls.subject_cn) findings.push({ severity: "info", title: `[httpx] TLS CN: ${obj.tls.subject_cn}` });
            if (obj.tls.subject_org) findings.push({ severity: "info", title: `[httpx] TLS Org: ${obj.tls.subject_org}` });
            if (obj.tls.not_after) findings.push({ severity: "info", title: `[httpx] TLS Expires: ${obj.tls.not_after}` });
          }
          // Enrich asset passiveRecon if available
          if (asset) {
            if (obj.tech && Array.isArray(obj.tech) && asset.passiveRecon) {
              asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), ...obj.tech])];
            }
            if (obj.webserver && asset.passiveRecon) {
              asset.passiveRecon.technologies = [...new Set([...(asset.passiveRecon.technologies || []), obj.webserver])];
            }
          }
        } catch { /* not JSON line */ }
      }
      break;
    }
    case "naabu": {
      // naabu JSON output: port discovery
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.port && typeof obj.port === 'number') {
            findings.push({ severity: "info", title: `[naabu] Port ${obj.port} open on ${obj.host || obj.ip || 'target'}` });
          }
        } catch {
          // Handle plain "host:port" format
          const portMatch = trimmed.match(/:(\d+)$/);
          if (portMatch) {
            findings.push({ severity: "info", title: `[naabu] Port ${portMatch[1]} open` });
          }
        }
      }
      break;
    }
    case "gobuster": {
      // Gobuster: found directories/files
      // Output format: /{path} (Status: 200) [Size: 1234]
      for (const line of stdout.split("\n")) {
        const match = line.match(/\/(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/);
        if (match) {
          const [, path, status, sizeStr] = match;
          const size = sizeStr ? parseInt(sizeStr, 10) : undefined;
          if (["200", "301", "302", "401", "403", "405", "500"].includes(status)) {
            // Severity classification based on status + content size
            let severity: string;
            if (status === "500") {
              severity = "medium"; // Server error — potential vulnerability
            } else if (status === "401" || status === "403") {
              // Large 403/401 responses may indicate real protected content
              severity = size && size > 500 ? "medium" : "low";
            } else if (status === "200" || status === "301" || status === "302") {
              // Sensitive paths get higher severity
              const sensitivePaths = /\.(env|bak|sql|conf|config|log|old|swp|zip|tar|gz|xml|yml|yaml|json|git|svn|htpasswd|htaccess|DS_Store)/i;
              const adminPaths = /\b(admin|dashboard|panel|manager|console|phpmyadmin|wp-admin|cpanel|debug|server-status|server-info)\b/i;
              if (sensitivePaths.test(path)) {
                severity = "high"; // Sensitive file exposure
              } else if (adminPaths.test(path)) {
                severity = "medium"; // Admin panel discovered
              } else {
                severity = "info";
              }
            } else {
              severity = "info";
            }
            const sizeInfo = size !== undefined ? ` [${size}B]` : '';
            findings.push({
              severity,
              title: `[Gobuster] /${path} (${status})${sizeInfo}`,
            });
          }
        }
      }
      break;
    }
    case "enum4linux": {
      // enum4linux: look for shares, users, password policy
      if (stdout.includes("Sharename")) {
        findings.push({ severity: "medium", title: "[enum4linux] SMB shares enumerated" });
      }
      if (stdout.includes("user:")) {
        findings.push({ severity: "medium", title: "[enum4linux] User accounts enumerated via SMB" });
      }
      break;
    }
    case "hydra": {
      // Hydra: successful login — extract username/password and store on asset
      // Hydra output format: [<port>][<service>] host: <host>   login: <user>   password: <pass>
      //
      // FALSE POSITIVE DETECTION (http-get/https-get):
      // Hydra http-get mode tests HTTP Basic Auth. If the server does NOT use
      // HTTP Basic Auth (e.g., SPA behind CloudFront, form-based login), the
      // server returns HTTP 200 for ALL requests regardless of the Authorization
      // header. Hydra interprets every response as "valid credentials."
      //
      // Detection: If Hydra reports 3+ different credential pairs as valid for
      // the same http-get/https-get service, it's almost certainly a false positive
      // (a real server would only accept the correct credentials).
      const httpGetHits: Array<{ line: string; login: string; pass: string; svc: string; port: number }> = [];
      const nonHttpGetHits: Array<{ line: string; login: string; pass: string; svc: string; port: number }> = [];

      for (const line of stdout.split("\n")) {
        if (line.includes("login:") && line.includes("password:")) {
          const loginMatch = line.match(/login:\s*(\S+)/);
          const passMatch = line.match(/password:\s*(\S*)/);
          const svcMatch = line.match(/\[\d+\]\[(\S+)\]/) || line.match(/\[(\S+)\]/);
          const portMatch = line.match(/\[(\d+)\]/);
          const svc = svcMatch?.[1] || 'http';
          const port = portMatch ? parseInt(portMatch[1], 10) : (asset.ports[0]?.port || 80);

          const hit = {
            line: line.trim(),
            login: loginMatch?.[1] || '',
            pass: passMatch?.[1] || '',
            svc,
            port,
          };

          if (svc === 'http-get' || svc === 'https-get') {
            httpGetHits.push(hit);
          } else {
            nonHttpGetHits.push(hit);
          }
        }
      }

      // FP Detection: If Hydra reports 3+ different user:pass combos via http-get/https-get,
      // the server is NOT using HTTP Basic Auth — it returns 200 for everything.
      // Also flag if 2+ hits have DIFFERENT passwords for the same username (impossible for real auth).
      const isHttpGetFalsePositive = httpGetHits.length >= 3 ||
        (httpGetHits.length >= 2 && new Set(httpGetHits.map(h => h.pass)).size >= 2);

      if (isHttpGetFalsePositive && httpGetHits.length > 0) {
        // Downgrade to info — server does not use HTTP Basic Auth
        findings.push({
          severity: "info",
          title: `[Hydra] FALSE POSITIVE: Server returns HTTP 200 for all requests (no HTTP Basic Auth) — ${httpGetHits.length} credentials reported but server ignores Authorization header`,
        });
        // Do NOT add to confirmedCredentials — these are not real
      } else {
        // Genuine http-get/https-get hits (1-2 unique creds = plausible)
        for (const hit of httpGetHits) {
          const scheme = hit.svc === 'https-get' ? 'https' : 'http';
          const targetUrl = `${scheme}://${asset.hostname}:${hit.port}/`;
          findings.push({
            severity: "critical",
            title: `[Hydra] Valid credentials found: ${hit.login}:*** on ${hit.svc}:${hit.port}`,
            description: `Hydra confirmed valid ${hit.svc} credentials for ${asset.hostname}:${hit.port}. Username: ${hit.login}`,
            evidence: {
              request: { method: 'GET', url: targetUrl, headers: { 'Authorization': `Basic ${Buffer.from(`${hit.login}:${hit.pass}`).toString('base64')}` } },
              response: { statusCode: 200 },
              proofText: `[Hydra Raw Output] ${hit.line}\n\n[Verification Command]\ncurl -v -u '${hit.login}:<REDACTED>' ${targetUrl}\n\n[Credential Details]\nUsername: ${hit.login}\nService: ${hit.svc}\nPort: ${hit.port}\nAccess Level: Authenticated\nConfirmed At: ${new Date().toISOString()}`,
            },
          });
          if (asset.confirmedCredentials) {
            asset.confirmedCredentials.push({
              username: hit.login,
              password: hit.pass,
              service: hit.svc,
              port: hit.port,
              protocol: hit.svc.includes('http') ? 'http' : 'unknown',
              accessLevel: 'authenticated',
              source: 'hydra',
              responseSnippet: hit.line.slice(0, 200),
              confirmedAt: Date.now(),
            });
          }
        }
      }

      // Non-http-get hits (SSH, FTP, etc.) — always trust these
      for (const hit of nonHttpGetHits) {
        const verifyCmd = hit.svc === 'ssh'
          ? `ssh -o StrictHostKeyChecking=no ${hit.login}@${asset.hostname} -p ${hit.port} 'whoami && id && hostname'`
          : hit.svc === 'ftp'
            ? `ftp -n ${asset.hostname} ${hit.port} <<< 'user ${hit.login} <REDACTED>\nls\nquit'`
            : `${hit.svc} ${asset.hostname}:${hit.port} -u ${hit.login}`;
        findings.push({
          severity: "critical",
          title: `[Hydra] Valid credentials found: ${hit.login}:*** on ${hit.svc}:${hit.port}`,
          description: `Hydra confirmed valid ${hit.svc} credentials for ${asset.hostname}:${hit.port}. Service: ${hit.svc}, Username: ${hit.login}`,
          evidence: {
            proofText: `[Hydra Raw Output] ${hit.line}\n\n[Verification Command]\n${verifyCmd}\n\n[Credential Details]\nUsername: ${hit.login}\nService: ${hit.svc}\nPort: ${hit.port}\nProtocol: ${hit.svc}\nAccess Level: Authenticated\nConfirmed At: ${new Date().toISOString()}\n\n[Operator Notes]\nThis credential was confirmed by Hydra brute-force. Verify manually using the command above.`,
          },
        });
        if (asset.confirmedCredentials) {
          asset.confirmedCredentials.push({
            username: hit.login,
            password: hit.pass,
            service: hit.svc,
            port: hit.port,
            protocol: hit.svc.includes('http') ? 'http' : (hit.svc || 'unknown'),
            accessLevel: 'authenticated',
            source: 'hydra',
            responseSnippet: hit.line.slice(0, 200),
            confirmedAt: Date.now(),
          });
        }
      }
      break;
    }
    case "dig": {
      if (stdout.includes("XFR size") || stdout.includes("Transfer")) {
        findings.push({ severity: "high", title: "[dig] DNS Zone Transfer successful" });
      }
      break;
    }
    case "smbclient": {
      if (stdout.includes("Sharename") && !stdout.includes("NT_STATUS_ACCESS_DENIED")) {
        findings.push({ severity: "medium", title: "[smbclient] Anonymous SMB share access" });
      }
      break;
    }
    case "ldapsearch": {
      if (stdout.includes("namingContexts") && !stdout.includes("Operations error")) {
        findings.push({ severity: "medium", title: "[ldapsearch] Anonymous LDAP bind successful" });
      }
      break;
    }
    case "onesixtyone": {
      for (const line of stdout.split("\n")) {
        if (line.includes("[") && !line.includes("Scanning")) {
          findings.push({ severity: "high", title: `[onesixtyone] SNMP community string found: ${line.trim().slice(0, 80)}` });
        }
      }
      break;
    }
    // ─── Cloud Storage & Misconfiguration Tool Parsers ─────────────────────
    case "cloud_enum": {
      // cloud_enum outputs discovered cloud resources line by line
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('[*]') || trimmed.startsWith('[-]')) continue;
        // S3 bucket found
        if (trimmed.includes('s3.amazonaws.com') || trimmed.includes('.s3.')) {
          findings.push({ severity: "high", title: `[cloud_enum] S3 Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Azure Blob found
        else if (trimmed.includes('blob.core.windows.net')) {
          findings.push({ severity: "high", title: `[cloud_enum] Azure Blob Container Discovered: ${trimmed.slice(0, 120)}` });
        }
        // GCS bucket found
        else if (trimmed.includes('storage.googleapis.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] GCS Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Firebase
        else if (trimmed.includes('firebaseio.com') || trimmed.includes('firebaseapp.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] Firebase App Discovered: ${trimmed.slice(0, 120)}` });
        }
        // DigitalOcean Spaces
        else if (trimmed.includes('digitaloceanspaces.com')) {
          findings.push({ severity: "high", title: `[cloud_enum] DO Spaces Bucket Discovered: ${trimmed.slice(0, 120)}` });
        }
        // Generic open resource
        else if (trimmed.includes('[OPEN]') || trimmed.includes('OPEN') || trimmed.includes('200')) {
          findings.push({ severity: "critical", title: `[cloud_enum] Open Cloud Resource: ${trimmed.slice(0, 120)}` });
        }
      }
      break;
    }
    case "s3scanner": {
      // s3scanner JSON output: bucket permission results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const bucket = obj.bucket || obj.name || 'unknown';
          if (obj.exists === false) continue; // bucket doesn't exist
          if (obj.public_read || obj.AuthUsers_read) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC READ: s3://${bucket} — data exposure risk` });
          }
          if (obj.public_write || obj.AuthUsers_write) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC WRITE: s3://${bucket} — bucket takeover risk` });
          }
          if (obj.public_read_acp || obj.AuthUsers_read_acp) {
            findings.push({ severity: "high", title: `[s3scanner] ACL Readable: s3://${bucket} — permission enumeration` });
          }
          if (obj.exists && !obj.public_read && !obj.public_write) {
            findings.push({ severity: "info", title: `[s3scanner] Bucket exists (private): s3://${bucket}` });
          }
        } catch {
          // Plain text output fallback
          if (trimmed.includes('READ') || trimmed.includes('ListBucket')) {
            findings.push({ severity: "critical", title: `[s3scanner] Public Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes('WRITE') || trimmed.includes('PutObject')) {
            findings.push({ severity: "critical", title: `[s3scanner] Write Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes('exists') || trimmed.includes('bucket_exists')) {
            findings.push({ severity: "info", title: `[s3scanner] ${trimmed.slice(0, 120)}` });
          }
        }
      }
      break;
    }
    case "trufflehog": {
      // trufflehog JSON output: discovered secrets
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.DetectorName || obj.detector_name) {
            const detector = obj.DetectorName || obj.detector_name || 'Unknown';
            const source = obj.SourceMetadata?.Data?.S3?.bucket || obj.source || 'unknown';
            const verified = obj.Verified || obj.verified ? 'VERIFIED' : 'unverified';
            findings.push({
              severity: obj.Verified || obj.verified ? "critical" : "high",
              title: `[trufflehog] ${verified} Secret (${detector}) in ${source}`,
            });
          }
        } catch { /* not JSON */ }
      }
      break;
    }
    case "aws": {
      // AWS CLI output: s3 ls results, bucket policy, etc.
      if (stdout.includes('NoSuchBucket')) {
        findings.push({ severity: "high", title: `[aws] Subdomain Takeover Candidate: NoSuchBucket response` });
      } else if (stdout.includes('AccessDenied') || stdout.includes('Access Denied')) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but access denied (private)` });
      } else if (stdout.includes('AllAccessDisabled')) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but all access disabled` });
      } else {
        // Successful listing — parse objects
        const objectLines = stdout.split("\n").filter(l => l.trim() && !l.includes('PRE '));
        if (objectLines.length > 0) {
          findings.push({ severity: "critical", title: `[aws] PUBLIC S3 Bucket — ${objectLines.length} objects listed anonymously` });
          // Sample first 5 objects
          for (const line of objectLines.slice(0, 5)) {
            const parts = line.trim().split(/\s+/);
            const filename = parts[parts.length - 1];
            if (filename && filename !== 'None') {
              findings.push({ severity: "high", title: `[aws] Exposed file: ${filename}` });
            }
          }
        }
        // Check for directory prefixes (PRE)
        const prefixes = stdout.split("\n").filter(l => l.includes('PRE '));
        if (prefixes.length > 0) {
          findings.push({ severity: "high", title: `[aws] Public bucket with ${prefixes.length} directories` });
        }
      }
      break;
    }
    case "bash": {
      // Bash commands used for Firebase, curl checks, etc.
      // Firebase Realtime DB open check
      if (stdout.includes('firebaseio.com')) {
        try {
          const obj = JSON.parse(stdout);
          if (obj && Object.keys(obj).length > 0 && !obj.error) {
            findings.push({ severity: "critical", title: `[Firebase] Database publicly readable — ${Object.keys(obj).length} top-level keys exposed` });
          }
        } catch {
          if (!stdout.includes('Permission denied') && !stdout.includes('null') && stdout.length > 5) {
            findings.push({ severity: "high", title: `[Firebase] Possible public database access` });
          }
        }
      }
      // Generic curl checks for cloud misconfigs
      if (stdout.includes('ListBucketResult') || stdout.includes('<Contents>')) {
        findings.push({ severity: "critical", title: `[curl] S3 Bucket Directory Listing Enabled` });
      }
      if (stdout.includes('BlobNotFound') || stdout.includes('ContainerNotFound')) {
        findings.push({ severity: "high", title: `[curl] Azure Blob Subdomain Takeover Candidate` });
      }
      if (stdout.includes('NoSuchBucket')) {
        findings.push({ severity: "high", title: `[curl] S3 Subdomain Takeover Candidate — NoSuchBucket` });
      }
      break;
    }
    case "ffuf": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.results && Array.isArray(obj.results)) {
            for (const r of obj.results) {
              const status = r.status || r.StatusCode;
              const url = r.url || r.Url || '';
              if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
                findings.push({ severity: status === 500 ? "medium" : "info", title: `[ffuf] ${url} (${status}, ${r.length || '?'}B)` });
              }
            }
          }
        } catch {
          const match = trimmed.match(/(https?:\/\/\S+)\s+\[Status:\s*(\d+)/);
          if (match) findings.push({ severity: "info", title: `[ffuf] ${match[1]} (${match[2]})` });
        }
      }
      break;
    }
    case "sslscan": {
      if (stdout.includes('SSLv2') && !stdout.includes('SSLv2 disabled')) findings.push({ severity: "critical", title: "[sslscan] SSLv2 enabled" });
      if (stdout.includes('SSLv3') && !stdout.includes('SSLv3 disabled')) findings.push({ severity: "high", title: "[sslscan] SSLv3 enabled (POODLE)" });
      if (/TLSv1\.0.*enabled/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] TLS 1.0 enabled" });
      if (/Heartbleed.*vulnerable/i.test(stdout)) findings.push({ severity: "critical", title: "[sslscan] Heartbleed", cve: "CVE-2014-0160" });
      if (/RC4|DES|NULL|EXPORT/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Weak cipher suites accepted" });
      if (/self.signed/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] Self-signed certificate" });
      if (/expired/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Expired certificate" });
      break;
    }
    case "whatweb": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('WhatWeb') || trimmed.startsWith('ERROR')) continue;
        const urlMatch = trimmed.match(/^(https?:\/\/\S+)/);
        const url = urlMatch ? urlMatch[1] : '';
        const techMatches = trimmed.match(/\[([^\]]+)\]/g);
        if (techMatches) {
          for (const tech of techMatches) {
            const techName = tech.slice(1, -1);
            if (techName.length > 2 && !techName.match(/^\d{3}$/)) {
              findings.push({ severity: "info", title: `[whatweb] ${techName}${url ? ` @ ${url}` : ''}` });
            }
          }
        }
      }
      break;
    }
    case "subfinder": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.includes('.') && !trimmed.startsWith('[')) {
          findings.push({ severity: "info", title: `[subfinder] Subdomain: ${trimmed}` });
        }
      }
      break;
    }
    case "feroxbuster": {
      // feroxbuster JSON output: recursive directory discovery results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const status = obj.status || obj.status_code;
          const url = obj.url || obj.original_url || '';
          const length = obj.content_length || obj.length || '?';
          if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
            let severity = "info";
            if (status === 500) severity = "medium";
            else if (status === 401 || status === 403) severity = "low";
            else if (/admin|config|backup|\.env|\.git|\.sql|\.bak|upload|dashboard|secret|password/i.test(url)) severity = "medium";
            findings.push({ severity, title: `[feroxbuster] ${url} (${status}, ${length}B)` });
          }
        } catch {
          // Plain text output fallback: "STATUS  LINES  WORDS  CHARS  URL"
          const match = trimmed.match(/(\d{3})\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+(\S+)/);
          if (match) {
            const [, status, url] = match;
            findings.push({ severity: "info", title: `[feroxbuster] ${url} (${status})` });
          }
        }
      }
      break;
    }
    case "sqlmap": {
      // sqlmap output: SQL injection detection and exploitation results
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        // Injection point found
        if (/Parameter.*is vulnerable/i.test(trimmed) || /injectable/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] SQL Injection Confirmed: ${trimmed.slice(0, 150)}` });
        }
        // Database type identified
        else if (/back-end DBMS/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] ${trimmed.slice(0, 150)}` });
        }
        // Data extracted
        else if (/available databases/i.test(trimmed) || /Database:/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Database Enumerated: ${trimmed.slice(0, 150)}` });
        }
        // Tables/columns dumped
        else if (/Table:/i.test(trimmed) || /\d+ entries/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Data Extracted: ${trimmed.slice(0, 150)}` });
        }
        // OS shell or file access
        else if (/os-shell|file-read|file-write/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] OS-level Access: ${trimmed.slice(0, 150)}` });
        }
        // Injection type info
        else if (/Type:\s*(boolean|time|error|UNION|stacked)/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] Injection Type: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "amass": {
      // amass output: subdomain and infrastructure discovery
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('Querying') || trimmed.startsWith('OWASP') || trimmed.startsWith('The enumeration')) continue;
        // JSON output mode
        try {
          const obj = JSON.parse(trimmed);
          if (obj.name) {
            const sources = obj.sources?.join(', ') || '';
            findings.push({ severity: "info", title: `[amass] ${obj.name}${obj.addresses ? ` → ${obj.addresses.map((a: any) => a.ip).join(', ')}` : ''}${sources ? ` (${sources})` : ''}` });
          }
          continue;
        } catch { /* plain text mode */ }
        // Plain text: one subdomain per line
        if (trimmed.includes('.') && !trimmed.includes(' ')) {
          findings.push({ severity: "info", title: `[amass] Subdomain: ${trimmed}` });
        }
        // CIDR/ASN info
        else if (/ASN|CIDR|Netblock/i.test(trimmed)) {
          findings.push({ severity: "info", title: `[amass] Infrastructure: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "katana": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.startsWith('http')) {
          const isInteresting = /admin|login|api|config|backup|upload|dashboard|\.env|\.git/i.test(trimmed);
          if (isInteresting) findings.push({ severity: "medium", title: `[katana] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "gospider": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed.includes('[form]')) findings.push({ severity: "medium", title: `[gospider] Form: ${trimmed.slice(0, 150)}` });
        else if ((trimmed.includes('[javascript]') || trimmed.includes('[linkfinder]')) && /api|token|key|secret|admin/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[gospider] JS endpoint: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "waybackurls":
    case "gau": {
      const toolLabel = tool;
      let totalUrls = 0;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('http')) continue;
        totalUrls++;
        if (/admin|login|api|config|backup|\.env|\.git|\.sql|\.bak|\.zip|password|secret|token/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[${toolLabel}] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      if (totalUrls > 0) findings.push({ severity: "info", title: `[${toolLabel}] ${totalUrls} historical URLs` });
      break;
    }
    case "curl": {
      if (stdout.includes('ListBucketResult') || stdout.includes('<Contents>')) findings.push({ severity: "critical", title: "[curl] S3 Bucket Directory Listing" });
      if (stdout.includes('NoSuchBucket')) findings.push({ severity: "high", title: "[curl] S3 Subdomain Takeover Candidate" });
      if (stdout.includes('BlobNotFound') || stdout.includes('ContainerNotFound')) findings.push({ severity: "high", title: "[curl] Azure Blob Takeover Candidate" });
      const headerLines = stdout.split("\n");
      const serverHeader = headerLines.find(l => /^server:/i.test(l.trim()));
      if (serverHeader) findings.push({ severity: "info", title: `[curl] ${serverHeader.trim()}` });
      break;
    }
    case "wpscan": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.includes('[!]') || trimmed.includes('[+]')) {
          const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
          if (cve || /vulnerability|outdated|insecure/i.test(trimmed)) {
            findings.push({ severity: cve ? "high" : "medium", title: `[wpscan] ${trimmed.slice(0, 150)}`, cve });
          }
        }
      }
      break;
    }
    case "testssl": {
      for (const line of stdout.split("\n")) {
        if (/VULNERABLE/i.test(line)) {
          const cve = line.match(/CVE-\d{4}-\d+/)?.[0];
          findings.push({ severity: cve ? "critical" : "high", title: `[testssl] ${line.trim().slice(0, 150)}`, cve });
        }
      }
      if (/NOT\s+ok/i.test(stdout)) findings.push({ severity: "medium", title: "[testssl] TLS configuration issues" });
      break;
    }
    case "scanforge-discovery": {
      const portRegex = /^(\d+)\/tcp\s+(open|filtered)\s+(\S+)\s*(.*)/;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        const portMatch = trimmed.match(portRegex);
        if (portMatch && portMatch[2] === 'open') {
          findings.push({ severity: "info", title: `[ScanForge] ${portMatch[1]}/tcp ${portMatch[3]}${portMatch[4] ? ' ' + portMatch[4].trim() : ''}` });
        }
        const cveMatch = trimmed.match(/CVE-\d{4}-\d+/g);
        if (cveMatch) {
          for (const cve of cveMatch) {
            findings.push({ severity: "high", title: `[ScanForge] ${cve} — ${trimmed.slice(0, 120)}`, cve });
          }
        }
        if (/VULNERABLE/i.test(trimmed)) findings.push({ severity: "high", title: `[ScanForge] ${trimmed.slice(0, 150)}` });
        if (/message_signing.*disabled/i.test(trimmed)) findings.push({ severity: "medium", title: "[ScanForge] SMB signing disabled" });
        if (/Anonymous FTP login allowed/i.test(trimmed)) findings.push({ severity: "high", title: "[ScanForge] Anonymous FTP login" });
      }
      break;
    }
    default:
      break;
  }

  return findings;
}
