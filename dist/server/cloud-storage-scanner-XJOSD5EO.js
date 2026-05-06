import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-OR6TJBFA.js";
import "./chunk-2NKRUZKV.js";
import "./chunk-5TJ6FS74.js";
import "./chunk-UYX5D64U.js";
import "./chunk-SD56WPOS.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-YQRYZ5JK.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cloud-storage-scanner.ts
function detectCloudAsset(asset) {
  const signatures = [];
  const storageEndpoints = [];
  const cnames = asset.cnames || [];
  if (asset.dnsRecords) {
    const dnsStr = typeof asset.dnsRecords === "string" ? asset.dnsRecords : JSON.stringify(asset.dnsRecords);
    const cnameMatches = dnsStr.match(/CNAME[:\s]+([^\s,"]+)/gi) || [];
    for (const m of cnameMatches) {
      const cname = m.replace(/CNAME[:\s]+/i, "").trim();
      if (cname && !cnames.includes(cname)) cnames.push(cname);
    }
  }
  for (const cname of cnames) {
    for (const cp of CLOUD_CNAME_PATTERNS) {
      if (cp.pattern.test(cname)) {
        signatures.push({
          provider: cp.provider,
          service: cp.service,
          confidence: "high",
          indicators: [`CNAME: ${cname}`]
        });
        if (["S3", "S3-Website", "Blob-Storage", "GCS", "Spaces", "OSS", "Object-Storage"].includes(cp.service)) {
          storageEndpoints.push(cname);
        }
      }
    }
  }
  if (asset.headers) {
    const headerLines = asset.headers.split("\n");
    for (const line of headerLines) {
      const [key, ...valueParts] = line.split(":");
      if (!key) continue;
      const headerKey = key.trim().toLowerCase();
      const headerValue = valueParts.join(":").trim();
      for (const hp of CLOUD_HEADER_PATTERNS) {
        if (headerKey === hp.header.toLowerCase() && hp.pattern.test(headerValue)) {
          if (!signatures.some((s) => s.provider === hp.provider && s.service === hp.service)) {
            signatures.push({
              provider: hp.provider,
              service: hp.service,
              confidence: "high",
              indicators: [`Header: ${key}: ${headerValue}`]
            });
          }
        }
      }
    }
  }
  if (asset.toolResults) {
    for (const tr of asset.toolResults) {
      if (tr.tool === "httpx" && tr.outputPreview) {
        try {
          for (const line of tr.outputPreview.split("\n")) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            try {
              const obj = JSON.parse(trimmed);
              if (obj.cdn_name) {
                const cdnLower = obj.cdn_name.toLowerCase();
                if (cdnLower.includes("cloudfront") || cdnLower.includes("amazon")) {
                  if (!signatures.some((s) => s.provider === "aws")) {
                    signatures.push({ provider: "aws", service: "CloudFront", confidence: "high", indicators: [`CDN: ${obj.cdn_name}`] });
                  }
                } else if (cdnLower.includes("azure") || cdnLower.includes("akamai")) {
                  if (!signatures.some((s) => s.provider === "azure")) {
                    signatures.push({ provider: "azure", service: "CDN", confidence: "medium", indicators: [`CDN: ${obj.cdn_name}`] });
                  }
                } else if (cdnLower.includes("google") || cdnLower.includes("cloud")) {
                  if (!signatures.some((s) => s.provider === "gcp")) {
                    signatures.push({ provider: "gcp", service: "CDN", confidence: "medium", indicators: [`CDN: ${obj.cdn_name}`] });
                  }
                }
              }
              if (obj.tls?.subject_org) {
                const org = obj.tls.subject_org.toLowerCase();
                if (org.includes("amazon") || org.includes("aws")) {
                  if (!signatures.some((s) => s.provider === "aws")) {
                    signatures.push({ provider: "aws", service: "Unknown", confidence: "medium", indicators: [`TLS Org: ${obj.tls.subject_org}`] });
                  }
                }
              }
              if (obj.header) {
                const headerStr = typeof obj.header === "string" ? obj.header : JSON.stringify(obj.header);
                for (const hp of CLOUD_HEADER_PATTERNS) {
                  const headerRegex = new RegExp(`${hp.header}[:\\s]+([^\\n]+)`, "i");
                  const match = headerStr.match(headerRegex);
                  if (match && hp.pattern.test(match[1])) {
                    if (!signatures.some((s) => s.provider === hp.provider && s.service === hp.service)) {
                      signatures.push({ provider: hp.provider, service: hp.service, confidence: "high", indicators: [`httpx header: ${hp.header}`] });
                    }
                  }
                }
              }
            } catch {
            }
          }
        } catch {
        }
      }
    }
  }
  if (asset.technologies) {
    for (const tech of asset.technologies) {
      const techLower = tech.toLowerCase();
      if (techLower.includes("amazon") || techLower.includes("aws") || techLower.includes("s3")) {
        if (!signatures.some((s) => s.provider === "aws")) {
          signatures.push({ provider: "aws", service: "Unknown", confidence: "medium", indicators: [`Tech: ${tech}`] });
        }
      }
      if (techLower.includes("azure") || techLower.includes("microsoft")) {
        if (!signatures.some((s) => s.provider === "azure")) {
          signatures.push({ provider: "azure", service: "Unknown", confidence: "medium", indicators: [`Tech: ${tech}`] });
        }
      }
      if (techLower.includes("google cloud") || techLower.includes("firebase") || techLower.includes("gcp")) {
        if (!signatures.some((s) => s.provider === "gcp")) {
          signatures.push({ provider: "gcp", service: "Unknown", confidence: "medium", indicators: [`Tech: ${tech}`] });
        }
      }
    }
  }
  for (const cp of CLOUD_CNAME_PATTERNS) {
    if (cp.pattern.test(asset.hostname)) {
      if (!signatures.some((s) => s.provider === cp.provider && s.service === cp.service)) {
        signatures.push({ provider: cp.provider, service: cp.service, confidence: "high", indicators: [`Hostname: ${asset.hostname}`] });
        if (["S3", "S3-Website", "Blob-Storage", "GCS", "Spaces", "OSS", "Object-Storage"].includes(cp.service)) {
          storageEndpoints.push(asset.hostname);
        }
      }
    }
  }
  const suggestedScans = generateCloudScanSuggestions(asset.hostname, signatures, storageEndpoints);
  return {
    isCloudHosted: signatures.length > 0,
    signatures,
    suggestedScans,
    storageEndpoints
  };
}
function generateCloudScanSuggestions(hostname, signatures, storageEndpoints) {
  const suggestions = [];
  const providers = new Set(signatures.map((s) => s.provider));
  const services = new Set(signatures.map((s) => s.service));
  const domainParts = hostname.split(".");
  const baseDomain = domainParts.length >= 2 ? domainParts.slice(-2).join(".") : hostname;
  const keyword = domainParts[0].replace(/[^a-zA-Z0-9-]/g, "");
  if (providers.size > 0 || storageEndpoints.length > 0) {
    suggestions.push({
      tool: "cloud_enum",
      command: `cloud_enum -k ${keyword} --disable-gcp --disable-azure -l /tmp/cloud_enum_${keyword}.txt`,
      rationale: `Enumerate cloud resources using keyword "${keyword}" derived from ${hostname}`,
      priority: 1
    });
    if (providers.has("azure")) {
      suggestions.push({
        tool: "cloud_enum",
        command: `cloud_enum -k ${keyword} --disable-aws --disable-gcp -l /tmp/cloud_enum_azure_${keyword}.txt`,
        rationale: `Azure-specific cloud resource enumeration for ${hostname}`,
        priority: 2
      });
    }
    if (providers.has("gcp") || providers.has("firebase")) {
      suggestions.push({
        tool: "cloud_enum",
        command: `cloud_enum -k ${keyword} --disable-aws --disable-azure -l /tmp/cloud_enum_gcp_${keyword}.txt`,
        rationale: `GCP-specific cloud resource enumeration for ${hostname}`,
        priority: 2
      });
    }
  }
  if (services.has("S3") || services.has("S3-Website") || providers.has("aws")) {
    for (const endpoint of storageEndpoints.filter((e) => /s3/i.test(e))) {
      const bucketName = endpoint.split(".s3")[0];
      suggestions.push({
        tool: "s3scanner",
        command: `echo "${bucketName}" | s3scanner scan --json`,
        rationale: `Check S3 bucket "${bucketName}" for public access and listing permissions`,
        priority: 1
      });
    }
    suggestions.push({
      tool: "bash",
      command: `for suffix in "" "-dev" "-staging" "-prod" "-backup" "-assets" "-static" "-media" "-uploads" "-data" "-logs" "-public" "-private" "-internal"; do echo "${keyword}\${suffix}"; done | s3scanner scan --json`,
      rationale: `Brute-force common S3 bucket name variations for "${keyword}"`,
      priority: 2
    });
  }
  if (services.has("Blob-Storage") || providers.has("azure")) {
    for (const endpoint of storageEndpoints.filter((e) => /blob\.core\.windows/i.test(e))) {
      const accountName = endpoint.split(".blob.core")[0];
      suggestions.push({
        tool: "bash",
        command: `for container in "\\$web" "public" "assets" "data" "backup" "uploads" "media" "static" "files" "images" "documents"; do echo "--- Checking ${accountName}/\${container} ---"; curl -s -o /dev/null -w "%{http_code}" "https://${accountName}.blob.core.windows.net/\${container}?restype=container&comp=list" && echo ""; done`,
        rationale: `Enumerate Azure Blob containers for storage account "${accountName}"`,
        priority: 1
      });
    }
  }
  if (services.has("GCS") || providers.has("gcp")) {
    for (const endpoint of storageEndpoints.filter((e) => /storage\.googleapis/i.test(e))) {
      const bucketName = endpoint.split(".storage.googleapis")[0];
      suggestions.push({
        tool: "bash",
        command: `curl -s "https://storage.googleapis.com/${bucketName}" | head -100`,
        rationale: `Check GCS bucket "${bucketName}" for public listing`,
        priority: 1
      });
    }
  }
  if (services.has("Realtime-DB") || providers.has("firebase")) {
    const firebaseProject = keyword;
    suggestions.push({
      tool: "bash",
      command: `echo "=== Firebase DB ===" && curl -s "https://${firebaseProject}-default-rtdb.firebaseio.com/.json" | head -200 && echo "" && echo "=== Firebase Rules ===" && curl -s "https://${firebaseProject}-default-rtdb.firebaseio.com/.settings/rules.json" | head -100`,
      rationale: `Check Firebase Realtime Database for public read access and exposed rules`,
      priority: 1
    });
    suggestions.push({
      tool: "bash",
      command: `curl -s "https://firestore.googleapis.com/v1/projects/${firebaseProject}/databases/(default)/documents" | head -200`,
      rationale: `Check Firestore database for public document access`,
      priority: 2
    });
  }
  if (providers.size > 0) {
    const cloudTags = ["cloud", "s3", "azure", "gcp", "firebase", "bucket", "storage", "misconfig"];
    const tagStr = cloudTags.join(",");
    suggestions.push({
      tool: "nuclei",
      command: `nuclei -u https://${hostname} -tags ${tagStr} -severity critical,high,medium -jsonl -nc -duc -ni -timeout 15 -retries 1`,
      rationale: `Run nuclei cloud-specific templates against ${hostname}`,
      priority: 1
    });
  }
  if (services.has("Spaces") || providers.has("digitalocean")) {
    for (const endpoint of storageEndpoints.filter((e) => /digitaloceanspaces/i.test(e))) {
      suggestions.push({
        tool: "bash",
        command: `curl -s "https://${endpoint}" | head -100`,
        rationale: `Check DigitalOcean Space "${endpoint}" for public listing`,
        priority: 1
      });
    }
  }
  return suggestions.sort((a, b) => a.priority - b.priority);
}
async function executeCloudStorageScan(hostname, suggestions, options = {}) {
  const maxScans = options.maxScans ?? 10;
  const timeoutSeconds = options.timeoutSeconds ?? 120;
  const findings = [];
  const rawResults = [];
  const scansToRun = suggestions.slice(0, maxScans);
  for (const scan of scansToRun) {
    try {
      const startTime = Date.now();
      let result;
      if (scan.tool === "bash" || scan.tool === "sh") {
        result = await executeRawCommand(scan.command, timeoutSeconds);
      } else if (scan.tool === "cloud_enum" || scan.tool === "s3scanner" || scan.tool === "nuclei") {
        result = await executeTool({
          tool: scan.tool,
          args: scan.command.replace(new RegExp(`^${scan.tool}\\s+`), ""),
          timeoutSeconds
        });
      } else {
        result = await executeRawCommand(scan.command, timeoutSeconds);
      }
      const durationMs = Date.now() - startTime;
      rawResults.push({
        tool: scan.tool,
        command: scan.command,
        stdout: result.stdout || "",
        stderr: result.stderr || "",
        exitCode: result.exitCode ?? -1,
        durationMs
      });
      const parsedFindings = parseCloudScanOutput(scan.tool, result.stdout || "", result.stderr || "", hostname);
      findings.push(...parsedFindings);
    } catch (err) {
      rawResults.push({
        tool: scan.tool,
        command: scan.command,
        stdout: "",
        stderr: err.message || "Execution error",
        exitCode: -1,
        durationMs: 0
      });
    }
  }
  return { findings, rawResults };
}
function parseCloudScanOutput(tool, stdout, stderr, hostname) {
  const findings = [];
  const combined = `${stdout}
${stderr}`;
  for (const sig of CLOUD_ERROR_SIGNATURES) {
    if (sig.pattern.test(combined)) {
      findings.push({
        provider: sig.provider,
        service: sig.service,
        resource: hostname,
        misconfigType: sig.misconfigType,
        severity: sig.severity,
        title: `[${sig.provider.toUpperCase()}] ${sig.description}`,
        description: sig.description,
        evidence: combined.slice(0, 500),
        remediationSteps: getRemediationSteps(sig.provider, sig.service, sig.misconfigType),
        complianceFrameworks: getComplianceFrameworks(sig.misconfigType),
        cwe: getCWE(sig.misconfigType)
      });
    }
  }
  switch (tool) {
    case "s3scanner": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.bucket_name) {
            const isPublic = obj.exists === true && (obj.public_acl === true || obj.list_objects === true);
            findings.push({
              provider: "aws",
              service: "S3",
              resource: obj.bucket_name,
              misconfigType: isPublic ? "open_listing" : obj.exists ? "exists_no_list" : "not_found",
              severity: isPublic ? "critical" : "info",
              title: isPublic ? `[AWS] S3 bucket "${obj.bucket_name}" is publicly accessible` : `[AWS] S3 bucket "${obj.bucket_name}" exists (access denied)`,
              description: isPublic ? `S3 bucket allows public listing/access. Objects may contain sensitive data.` : `S3 bucket exists but public access is denied.`,
              evidence: JSON.stringify(obj, null, 2).slice(0, 500),
              remediationSteps: isPublic ? ["Enable S3 Block Public Access at account level", "Review and restrict bucket policy", "Enable S3 access logging", "Enable server-side encryption"] : [],
              complianceFrameworks: isPublic ? ["CIS AWS 2.1.5", "NIST 800-53 AC-3", "PCI DSS 7.1"] : [],
              cwe: isPublic ? "CWE-284" : void 0
            });
          }
        } catch {
        }
      }
      break;
    }
    case "cloud_enum": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("[") || trimmed.startsWith("#")) continue;
        if (/s3\.amazonaws\.com/i.test(trimmed)) {
          findings.push({
            provider: "aws",
            service: "S3",
            resource: trimmed,
            misconfigType: "discovered",
            severity: "medium",
            title: `[AWS] S3 bucket discovered: ${trimmed}`,
            description: `Cloud enumeration found S3 bucket endpoint. Requires further access testing.`,
            evidence: trimmed,
            remediationSteps: ["Verify bucket access controls", "Check for public ACLs"],
            complianceFrameworks: ["CIS AWS 2.1.5"]
          });
        } else if (/blob\.core\.windows\.net/i.test(trimmed)) {
          findings.push({
            provider: "azure",
            service: "Blob-Storage",
            resource: trimmed,
            misconfigType: "discovered",
            severity: "medium",
            title: `[Azure] Blob storage discovered: ${trimmed}`,
            description: `Cloud enumeration found Azure Blob endpoint. Requires further access testing.`,
            evidence: trimmed,
            remediationSteps: ["Verify container access levels", "Check for anonymous access"],
            complianceFrameworks: ["CIS Azure 3.6"]
          });
        } else if (/storage\.googleapis\.com/i.test(trimmed)) {
          findings.push({
            provider: "gcp",
            service: "GCS",
            resource: trimmed,
            misconfigType: "discovered",
            severity: "medium",
            title: `[GCP] GCS bucket discovered: ${trimmed}`,
            description: `Cloud enumeration found GCS bucket endpoint. Requires further access testing.`,
            evidence: trimmed,
            remediationSteps: ["Enable uniform bucket-level access", "Remove allUsers bindings"],
            complianceFrameworks: ["CIS GCP 5.1"]
          });
        }
      }
      break;
    }
    case "nuclei": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.info?.name && obj.info?.severity) {
            const templateId = obj["template-id"] || "";
            const isCloud = /cloud|s3|bucket|azure|gcp|firebase|storage|misconfig/i.test(templateId) || /cloud|s3|bucket|azure|gcp|firebase|storage/i.test(obj.info.name);
            if (isCloud) {
              findings.push({
                provider: detectProviderFromNuclei(templateId, obj.info.name),
                service: "Unknown",
                resource: obj["matched-at"] || hostname,
                misconfigType: "nuclei_detection",
                severity: obj.info.severity,
                title: `[Nuclei] ${obj.info.name}`,
                description: obj.info.description || obj.info.name,
                evidence: JSON.stringify(obj, null, 2).slice(0, 500),
                remediationSteps: obj.info.remediation ? [obj.info.remediation] : [],
                complianceFrameworks: obj.info.classification?.cwe ? [`CWE-${obj.info.classification.cwe}`] : [],
                cwe: obj.info.classification?.cwe?.[0] ? `CWE-${obj.info.classification.cwe[0]}` : void 0
              });
            }
          }
        } catch {
        }
      }
      break;
    }
  }
  const seen = /* @__PURE__ */ new Set();
  return findings.filter((f) => {
    const key = `${f.resource}:${f.misconfigType}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
function detectProviderFromNuclei(templateId, name) {
  const combined = `${templateId} ${name}`.toLowerCase();
  if (combined.includes("aws") || combined.includes("s3")) return "aws";
  if (combined.includes("azure") || combined.includes("blob")) return "azure";
  if (combined.includes("gcp") || combined.includes("gcs") || combined.includes("google")) return "gcp";
  if (combined.includes("firebase")) return "firebase";
  if (combined.includes("digitalocean") || combined.includes("spaces")) return "digitalocean";
  return "unknown";
}
function getRemediationSteps(provider, service, misconfigType) {
  const steps = {
    "aws:S3:open_listing": [
      "Enable S3 Block Public Access at account and bucket level",
      "Review and restrict bucket ACLs \u2014 remove 'AllUsers' and 'AuthenticatedUsers' grants",
      "Update bucket policy to deny public access",
      "Enable S3 access logging and CloudTrail data events",
      "Enable default server-side encryption (SSE-S3 or SSE-KMS)"
    ],
    "aws:S3:takeover_candidate": [
      "Register the S3 bucket name to prevent subdomain takeover",
      "Remove the dangling CNAME record pointing to the non-existent bucket",
      "Implement DNS monitoring for orphaned records"
    ],
    "azure:Blob-Storage:open_listing": [
      "Set container access level to 'Private'",
      "Disable anonymous access at the storage account level",
      "Enable Azure Storage firewalls and virtual network rules",
      "Enable Azure Storage logging and Azure Monitor alerts"
    ],
    "azure:Blob-Storage:takeover_candidate": [
      "Create the Azure Blob container to prevent takeover",
      "Remove the dangling CNAME record"
    ],
    "gcp:GCS:open_listing": [
      "Enable uniform bucket-level access",
      "Remove allUsers and allAuthenticatedUsers IAM bindings",
      "Enable GCS access logging",
      "Apply organization policy constraints for public access prevention"
    ],
    "firebase:Realtime-DB:open_read": [
      "Update Firebase Security Rules to require authentication",
      "Replace '.read: true' with '.read: auth != null'",
      "Implement granular per-path security rules",
      "Enable Firebase App Check for additional protection"
    ],
    "firebase:Realtime-DB:open_write": [
      "CRITICAL: Immediately restrict write access in Firebase Security Rules",
      "Replace '.write: true' with '.write: auth != null'",
      "Implement data validation rules",
      "Enable Firebase App Check",
      "Audit existing data for unauthorized modifications"
    ],
    "digitalocean:Spaces:open_listing": [
      "Update Space ACL to private",
      "Use pre-signed URLs for authorized access",
      "Enable CDN with restricted access if public serving is needed"
    ]
  };
  return steps[`${provider}:${service}:${misconfigType}`] || [
    "Review and restrict access controls for the resource",
    "Enable logging and monitoring",
    "Implement least-privilege access policies"
  ];
}
function getComplianceFrameworks(misconfigType) {
  const frameworks = {
    "open_listing": ["CIS Benchmark", "NIST 800-53 AC-3", "PCI DSS 7.1", "SOC 2 CC6.1", "ISO 27001 A.9.4"],
    "open_read": ["CIS Benchmark", "NIST 800-53 AC-3", "PCI DSS 7.1", "GDPR Art. 32"],
    "open_write": ["CIS Benchmark", "NIST 800-53 AC-3", "PCI DSS 7.1", "GDPR Art. 32", "SOC 2 CC6.1"],
    "takeover_candidate": ["OWASP Top 10 A05:2021", "CWE-284"],
    "discovered": ["CIS Benchmark"]
  };
  return frameworks[misconfigType] || [];
}
function getCWE(misconfigType) {
  const cweMap = {
    "open_listing": "CWE-284",
    "open_read": "CWE-284",
    "open_write": "CWE-284",
    "takeover_candidate": "CWE-840",
    "nuclei_detection": "CWE-16"
  };
  return cweMap[misconfigType];
}
function getCloudDetectionPromptContext() {
  return `
## CLOUD STORAGE & APP MISCONFIGURATION DETECTION

When you detect cloud-hosted assets (via CNAME, headers, or technology fingerprints), you MUST include cloud-specific tools in the activeTools list.

### Cloud Provider Detection Signals:
- AWS: CNAME to *.s3.amazonaws.com, *.cloudfront.net, *.elasticbeanstalk.com; Headers: x-amz-request-id, Server: AmazonS3
- Azure: CNAME to *.blob.core.windows.net, *.azurewebsites.net; Headers: x-ms-request-id, x-ms-version
- GCP: CNAME to *.storage.googleapis.com, *.appspot.com; Headers: x-goog-storage-class, Server: UploadServer
- Firebase: CNAME to *.firebaseio.com, *.firebaseapp.com, *.web.app
- DigitalOcean: CNAME to *.digitaloceanspaces.com

### Cloud Tools Available on Scan Server:
- cloud_enum: Multi-cloud resource discovery by keyword. Usage: cloud_enum -k <keyword> [--disable-aws] [--disable-azure] [--disable-gcp] -l /tmp/output.txt
- s3scanner: S3 bucket permission testing. Usage: echo '<bucket>' | s3scanner scan --json
- trufflehog: Secret scanning in accessible buckets. Usage: trufflehog s3 --bucket <name> --json
- aws (CLI): Direct S3 anonymous access test. Usage: aws s3 ls s3://<bucket> --no-sign-request
- nuclei (cloud tags): Cloud misconfig templates. Usage: nuclei -u <target> -tags cloud,s3,azure,gcp,firebase,bucket,storage,misconfig -severity critical,high,medium -jsonl -nc -duc -ni

### When to Use Cloud Tools:
1. If passive recon shows cloud CNAME/headers \u2192 add cloud_enum with the domain keyword
2. If S3/GCS/Blob endpoints found \u2192 add s3scanner or direct curl checks
3. If Firebase detected \u2192 add Firebase DB/rules check via curl
4. ALWAYS add nuclei with cloud tags when any cloud provider is detected
5. For subdomain takeover candidates (NoSuchBucket, etc.) \u2192 flag as HIGH severity

### Cloud Scan Priority Rules:
- Priority 1: Direct storage endpoint checks (s3scanner, curl to blob/gcs)
- Priority 2: Keyword-based enumeration (cloud_enum)
- Priority 3: Nuclei cloud templates
- Priority 4: Secret scanning (trufflehog) \u2014 only if public access confirmed
`.trim();
}
var CLOUD_CNAME_PATTERNS, CLOUD_HEADER_PATTERNS, CLOUD_ERROR_SIGNATURES, CLOUD_MISCONFIG_KNOWLEDGE_BASE;
var init_cloud_storage_scanner = __esm({
  "server/lib/cloud-storage-scanner.ts"() {
    init_scan_server_executor();
    CLOUD_CNAME_PATTERNS = [
      // AWS
      { pattern: /\.s3\.amazonaws\.com$/i, provider: "aws", service: "S3" },
      { pattern: /\.s3-[\w-]+\.amazonaws\.com$/i, provider: "aws", service: "S3" },
      { pattern: /\.s3\.[\w-]+\.amazonaws\.com$/i, provider: "aws", service: "S3" },
      { pattern: /\.s3-website[-.][\w-]+\.amazonaws\.com$/i, provider: "aws", service: "S3-Website" },
      { pattern: /\.cloudfront\.net$/i, provider: "aws", service: "CloudFront" },
      { pattern: /\.elasticbeanstalk\.com$/i, provider: "aws", service: "ElasticBeanstalk" },
      { pattern: /\.elb\.amazonaws\.com$/i, provider: "aws", service: "ELB" },
      { pattern: /\.execute-api\.[\w-]+\.amazonaws\.com$/i, provider: "aws", service: "API-Gateway" },
      { pattern: /\.lambda\.[\w-]+\.amazonaws\.com$/i, provider: "aws", service: "Lambda" },
      { pattern: /\.rds\.amazonaws\.com$/i, provider: "aws", service: "RDS" },
      // Azure
      { pattern: /\.blob\.core\.windows\.net$/i, provider: "azure", service: "Blob-Storage" },
      { pattern: /\.file\.core\.windows\.net$/i, provider: "azure", service: "File-Storage" },
      { pattern: /\.queue\.core\.windows\.net$/i, provider: "azure", service: "Queue-Storage" },
      { pattern: /\.table\.core\.windows\.net$/i, provider: "azure", service: "Table-Storage" },
      { pattern: /\.azurewebsites\.net$/i, provider: "azure", service: "App-Service" },
      { pattern: /\.azureedge\.net$/i, provider: "azure", service: "CDN" },
      { pattern: /\.azure-api\.net$/i, provider: "azure", service: "API-Management" },
      { pattern: /\.database\.windows\.net$/i, provider: "azure", service: "SQL-Database" },
      { pattern: /\.vault\.azure\.net$/i, provider: "azure", service: "Key-Vault" },
      // GCP
      { pattern: /\.storage\.googleapis\.com$/i, provider: "gcp", service: "GCS" },
      { pattern: /\.appspot\.com$/i, provider: "gcp", service: "App-Engine" },
      { pattern: /\.cloudfunctions\.net$/i, provider: "gcp", service: "Cloud-Functions" },
      { pattern: /\.run\.app$/i, provider: "gcp", service: "Cloud-Run" },
      { pattern: /\.firebaseio\.com$/i, provider: "firebase", service: "Realtime-DB" },
      { pattern: /\.firebaseapp\.com$/i, provider: "firebase", service: "Hosting" },
      { pattern: /\.web\.app$/i, provider: "firebase", service: "Hosting" },
      // DigitalOcean
      { pattern: /\.digitaloceanspaces\.com$/i, provider: "digitalocean", service: "Spaces" },
      { pattern: /\.ondigitalocean\.app$/i, provider: "digitalocean", service: "App-Platform" },
      // Alibaba
      { pattern: /\.oss-[\w-]+\.aliyuncs\.com$/i, provider: "alibaba", service: "OSS" },
      // Oracle
      { pattern: /\.oraclecloud\.com$/i, provider: "oracle", service: "OCI" },
      { pattern: /\.objectstorage\.[\w-]+\.oci\.customer-oci\.com$/i, provider: "oracle", service: "Object-Storage" }
    ];
    CLOUD_HEADER_PATTERNS = [
      { header: "server", pattern: /^AmazonS3$/i, provider: "aws", service: "S3" },
      { header: "x-amz-request-id", pattern: /.+/, provider: "aws", service: "S3" },
      { header: "x-amz-bucket-region", pattern: /.+/, provider: "aws", service: "S3" },
      { header: "x-amz-cf-id", pattern: /.+/, provider: "aws", service: "CloudFront" },
      { header: "x-ms-request-id", pattern: /.+/, provider: "azure", service: "Blob-Storage" },
      { header: "x-ms-version", pattern: /.+/, provider: "azure", service: "Azure-Storage" },
      { header: "x-goog-storage-class", pattern: /.+/, provider: "gcp", service: "GCS" },
      { header: "x-guploader-uploadid", pattern: /.+/, provider: "gcp", service: "GCS" },
      { header: "server", pattern: /^UploadServer$/i, provider: "gcp", service: "GCS" },
      { header: "x-do-spaces-request-id", pattern: /.+/, provider: "digitalocean", service: "Spaces" }
    ];
    CLOUD_ERROR_SIGNATURES = [
      // S3 bucket listing
      { pattern: /<ListBucketResult/i, provider: "aws", service: "S3", misconfigType: "open_listing", severity: "critical", description: "S3 bucket allows public object listing (ListBucket)" },
      { pattern: /AccessDenied.*ListBucket/i, provider: "aws", service: "S3", misconfigType: "exists_no_list", severity: "info", description: "S3 bucket exists but listing denied" },
      { pattern: /NoSuchBucket/i, provider: "aws", service: "S3", misconfigType: "takeover_candidate", severity: "high", description: "S3 bucket does not exist \u2014 potential subdomain takeover" },
      { pattern: /AllAccessDisabled/i, provider: "aws", service: "S3", misconfigType: "disabled", severity: "info", description: "S3 bucket access is fully disabled" },
      // Azure blob
      { pattern: /<EnumerationResults/i, provider: "azure", service: "Blob-Storage", misconfigType: "open_listing", severity: "critical", description: "Azure Blob container allows public listing" },
      { pattern: /BlobNotFound/i, provider: "azure", service: "Blob-Storage", misconfigType: "exists_no_list", severity: "info", description: "Azure Blob container exists but blob not found" },
      { pattern: /ContainerNotFound/i, provider: "azure", service: "Blob-Storage", misconfigType: "takeover_candidate", severity: "high", description: "Azure container does not exist \u2014 potential takeover" },
      { pattern: /PublicAccessNotPermitted/i, provider: "azure", service: "Blob-Storage", misconfigType: "secure", severity: "info", description: "Azure Blob public access is disabled" },
      // GCS
      { pattern: /<ListBucketResult.*storage\.googleapis/i, provider: "gcp", service: "GCS", misconfigType: "open_listing", severity: "critical", description: "GCS bucket allows public object listing" },
      { pattern: /AccessDenied.*storage\.googleapis/i, provider: "gcp", service: "GCS", misconfigType: "exists_no_list", severity: "info", description: "GCS bucket exists but listing denied" },
      { pattern: /NoSuchBucket.*storage\.googleapis/i, provider: "gcp", service: "GCS", misconfigType: "takeover_candidate", severity: "high", description: "GCS bucket does not exist \u2014 potential takeover" },
      // Firebase
      { pattern: /"rules":\s*\{[^}]*"\.read":\s*true/i, provider: "firebase", service: "Realtime-DB", misconfigType: "open_read", severity: "critical", description: "Firebase Realtime DB has public read rules" },
      { pattern: /"rules":\s*\{[^}]*"\.write":\s*true/i, provider: "firebase", service: "Realtime-DB", misconfigType: "open_write", severity: "critical", description: "Firebase Realtime DB has public write rules" },
      { pattern: /Permission denied/i, provider: "firebase", service: "Realtime-DB", misconfigType: "secure", severity: "info", description: "Firebase DB access denied (properly secured)" },
      // DigitalOcean Spaces
      { pattern: /<ListBucketResult.*digitaloceanspaces/i, provider: "digitalocean", service: "Spaces", misconfigType: "open_listing", severity: "critical", description: "DigitalOcean Space allows public listing" }
    ];
    CLOUD_MISCONFIG_KNOWLEDGE_BASE = {
      description: "Cloud storage and application misconfiguration detection patterns",
      recognitionPatterns: {
        dns: {
          description: "CNAME and A record patterns indicating cloud-hosted resources",
          patterns: CLOUD_CNAME_PATTERNS.map((p) => ({
            regex: p.pattern.source,
            provider: p.provider,
            service: p.service
          }))
        },
        headers: {
          description: "HTTP response headers that reveal cloud provider and service",
          patterns: CLOUD_HEADER_PATTERNS.map((p) => ({
            header: p.header,
            regex: p.pattern.source,
            provider: p.provider,
            service: p.service
          }))
        },
        errors: {
          description: "Error responses that reveal cloud storage misconfigurations",
          patterns: CLOUD_ERROR_SIGNATURES.map((p) => ({
            regex: p.pattern.source,
            provider: p.provider,
            service: p.service,
            misconfigType: p.misconfigType,
            severity: p.severity
          }))
        }
      },
      scanTools: {
        cloud_enum: {
          description: "Multi-cloud resource enumerator \u2014 discovers S3 buckets, Azure Blobs, GCS buckets by keyword",
          usage: "cloud_enum -k <keyword> [--disable-aws] [--disable-azure] [--disable-gcp]",
          bestFor: "Initial cloud resource discovery when a domain/keyword is known"
        },
        s3scanner: {
          description: "S3 bucket permission scanner \u2014 checks for public ACLs, listing, and read/write access",
          usage: "echo '<bucket_name>' | s3scanner scan --json",
          bestFor: "Testing specific S3 bucket names for access misconfigurations"
        },
        trufflehog: {
          description: "Secret scanner \u2014 finds exposed credentials in public buckets and repos",
          usage: "trufflehog s3 --bucket <bucket_name> --json",
          bestFor: "Post-discovery scanning of accessible buckets for leaked secrets"
        },
        aws_cli: {
          description: "AWS CLI for direct S3/cloud API interaction",
          usage: "aws s3 ls s3://<bucket> --no-sign-request",
          bestFor: "Direct bucket enumeration without credentials (anonymous access testing)"
        },
        nuclei_cloud: {
          description: "Nuclei templates for cloud misconfigurations",
          usage: "nuclei -u <target> -tags cloud,s3,azure,gcp,firebase,bucket,storage,misconfig",
          bestFor: "Automated cloud misconfiguration detection using community templates"
        }
      },
      commonMisconfigurations: [
        { type: "Public S3 Bucket", severity: "critical", cis: "CIS AWS 2.1.5", description: "S3 bucket with public ACL or bucket policy allowing ListBucket/GetObject" },
        { type: "Azure Blob Anonymous Access", severity: "critical", cis: "CIS Azure 3.6", description: "Azure Blob container with anonymous read access enabled" },
        { type: "GCS allUsers Binding", severity: "critical", cis: "CIS GCP 5.1", description: "GCS bucket with allUsers or allAuthenticatedUsers IAM binding" },
        { type: "Firebase Open Rules", severity: "critical", cis: "N/A", description: "Firebase Realtime DB with .read: true or .write: true rules" },
        { type: "Subdomain Takeover", severity: "high", cis: "N/A", description: "Dangling CNAME pointing to non-existent cloud resource (S3, Azure, etc.)" },
        { type: "Exposed Storage Keys", severity: "critical", cis: "CIS AWS 1.4", description: "Cloud storage access keys or SAS tokens exposed in public resources" },
        { type: "Unencrypted Storage", severity: "medium", cis: "CIS AWS 2.1.1", description: "Cloud storage without server-side encryption enabled" },
        { type: "No Access Logging", severity: "medium", cis: "CIS AWS 2.1.3", description: "Cloud storage without access logging enabled" },
        { type: "Cross-Account Access", severity: "high", cis: "CIS AWS 1.16", description: "Storage bucket policy allowing cross-account access without MFA" },
        { type: "Versioning Disabled", severity: "low", cis: "CIS AWS 2.1.2", description: "S3 bucket without versioning \u2014 no protection against accidental deletion" }
      ]
    };
  }
});
init_cloud_storage_scanner();
export {
  CLOUD_MISCONFIG_KNOWLEDGE_BASE,
  detectCloudAsset,
  executeCloudStorageScan,
  getCloudDetectionPromptContext,
  parseCloudScanOutput
};
