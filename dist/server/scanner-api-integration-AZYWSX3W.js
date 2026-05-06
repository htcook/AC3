import "./chunk-KFQGP6VL.js";

// server/lib/scanner-api-integration.ts
async function fetchWithAuth(url, credentials, options, timeout = 3e4) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    ...options?.headers || {}
  };
  if (credentials.type === "nessus" && credentials.accessKey && credentials.secretKey) {
    headers["X-ApiKeys"] = `accessKey=${credentials.accessKey}; secretKey=${credentials.secretKey}`;
  }
  if (credentials.type === "tenable_io" && credentials.accessKey && credentials.secretKey) {
    headers["X-ApiKeys"] = `accessKey=${credentials.accessKey};secretKey=${credentials.secretKey}`;
  }
  if (credentials.type === "qualys" && credentials.username && credentials.password) {
    headers["Authorization"] = `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64")}`;
  }
  if (credentials.type === "rapid7" && credentials.apiKey) {
    headers["Authorization"] = `Bearer ${credentials.apiKey}`;
  }
  try {
    const res = await fetch(url, {
      ...options,
      headers,
      signal: controller.signal
    });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}
async function validateConnection(credentials) {
  try {
    switch (credentials.type) {
      case "nessus":
        return await validateNessusConnection(credentials);
      case "tenable_io":
        return await validateTenableConnection(credentials);
      case "qualys":
        return await validateQualysConnection(credentials);
      case "rapid7":
        return await validateRapid7Connection(credentials);
      default:
        return { connected: false, scannerType: credentials.type, error: "Unsupported scanner type", timestamp: /* @__PURE__ */ new Date() };
    }
  } catch (err) {
    return { connected: false, scannerType: credentials.type, error: err.message, timestamp: /* @__PURE__ */ new Date() };
  }
}
async function validateNessusConnection(credentials) {
  const url = `${credentials.baseUrl}/server/status`;
  const res = await fetchWithAuth(url, credentials);
  if (!res) return { connected: false, scannerType: "nessus", error: "Connection failed \u2014 check base URL", timestamp: /* @__PURE__ */ new Date() };
  if (res.status === 401 || res.status === 403) return { connected: false, scannerType: "nessus", error: "Authentication failed \u2014 check API keys", timestamp: /* @__PURE__ */ new Date() };
  if (!res.ok) return { connected: false, scannerType: "nessus", error: `HTTP ${res.status}: ${res.statusText}`, timestamp: /* @__PURE__ */ new Date() };
  const data = await res.json().catch(() => ({}));
  return { connected: true, scannerType: "nessus", scannerVersion: data.nessus_ui_version || data.server_version, timestamp: /* @__PURE__ */ new Date() };
}
async function validateTenableConnection(credentials) {
  const url = `${credentials.baseUrl}/server/status`;
  const res = await fetchWithAuth(url, credentials);
  if (!res) return { connected: false, scannerType: "tenable_io", error: "Connection failed", timestamp: /* @__PURE__ */ new Date() };
  if (res.status === 401 || res.status === 403) return { connected: false, scannerType: "tenable_io", error: "Authentication failed", timestamp: /* @__PURE__ */ new Date() };
  if (!res.ok) return { connected: false, scannerType: "tenable_io", error: `HTTP ${res.status}`, timestamp: /* @__PURE__ */ new Date() };
  const data = await res.json().catch(() => ({}));
  return { connected: true, scannerType: "tenable_io", scannerVersion: data.server_version, timestamp: /* @__PURE__ */ new Date() };
}
async function validateQualysConnection(credentials) {
  const url = `${credentials.baseUrl}/api/2.0/fo/scan/?action=list&show_ags=0&show_op=0`;
  const res = await fetchWithAuth(url, credentials, { method: "POST" });
  if (!res) return { connected: false, scannerType: "qualys", error: "Connection failed \u2014 check base URL", timestamp: /* @__PURE__ */ new Date() };
  if (res.status === 401) return { connected: false, scannerType: "qualys", error: "Authentication failed \u2014 check username/password", timestamp: /* @__PURE__ */ new Date() };
  if (!res.ok) return { connected: false, scannerType: "qualys", error: `HTTP ${res.status}`, timestamp: /* @__PURE__ */ new Date() };
  return { connected: true, scannerType: "qualys", timestamp: /* @__PURE__ */ new Date() };
}
async function validateRapid7Connection(credentials) {
  const url = `${credentials.baseUrl}/api/3/administration/info`;
  const res = await fetchWithAuth(url, credentials);
  if (!res) return { connected: false, scannerType: "rapid7", error: "Connection failed", timestamp: /* @__PURE__ */ new Date() };
  if (res.status === 401) return { connected: false, scannerType: "rapid7", error: "Authentication failed \u2014 check API key", timestamp: /* @__PURE__ */ new Date() };
  if (!res.ok) return { connected: false, scannerType: "rapid7", error: `HTTP ${res.status}`, timestamp: /* @__PURE__ */ new Date() };
  const data = await res.json().catch(() => ({}));
  return { connected: true, scannerType: "rapid7", scannerVersion: data.version, timestamp: /* @__PURE__ */ new Date() };
}
async function listRemoteScans(credentials) {
  switch (credentials.type) {
    case "nessus":
    case "tenable_io":
      return await listNessusScans(credentials);
    case "qualys":
      return await listQualysScans(credentials);
    case "rapid7":
      return await listRapid7Scans(credentials);
    default:
      return [];
  }
}
async function listNessusScans(credentials) {
  const url = `${credentials.baseUrl}/scans`;
  const res = await fetchWithAuth(url, credentials);
  if (!res || !res.ok) return [];
  const data = await res.json().catch(() => ({ scans: [] }));
  return (data.scans || []).map((s) => ({
    scanId: String(s.id),
    name: s.name,
    status: s.status,
    startTime: s.last_modification_date ? new Date(s.last_modification_date * 1e3) : void 0,
    hostCount: s.hostcount
  }));
}
async function listQualysScans(credentials) {
  const url = `${credentials.baseUrl}/api/2.0/fo/scan/?action=list&show_ags=0&show_op=0`;
  const res = await fetchWithAuth(url, credentials, { method: "POST" });
  if (!res || !res.ok) return [];
  const text = await res.text();
  const scans = [];
  const scanRegex = /<SCAN>([\s\S]*?)<\/SCAN>/g;
  let match;
  while ((match = scanRegex.exec(text)) !== null) {
    const content = match[1];
    const getTag = (tag) => {
      const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(content);
      return m ? m[1] : void 0;
    };
    scans.push({
      scanId: getTag("REF") || "",
      name: getTag("TITLE") || "Unnamed Scan",
      status: getTag("STATUS")?.toLowerCase() || "unknown",
      startTime: getTag("LAUNCH_DATETIME") ? new Date(getTag("LAUNCH_DATETIME")) : void 0
    });
  }
  return scans;
}
async function listRapid7Scans(credentials) {
  const url = `${credentials.baseUrl}/api/3/scans?page=0&size=50&sort=endTime,DESC`;
  const res = await fetchWithAuth(url, credentials);
  if (!res || !res.ok) return [];
  const data = await res.json().catch(() => ({ resources: [] }));
  return (data.resources || []).map((s) => ({
    scanId: String(s.id),
    name: s.scanName || s.engineName || "Scan",
    status: s.status,
    startTime: s.startTime ? new Date(s.startTime) : void 0,
    endTime: s.endTime ? new Date(s.endTime) : void 0,
    vulnCount: s.vulnerabilities?.total
  }));
}
async function pullScanResults(credentials, scanId) {
  switch (credentials.type) {
    case "nessus":
    case "tenable_io":
      return await pullNessusScanResults(credentials, scanId);
    case "qualys":
      return await pullQualysScanResults(credentials, scanId);
    case "rapid7":
      return await pullRapid7ScanResults(credentials, scanId);
    default:
      return { scannerType: "custom", findings: [], totalHosts: 0, totalVulns: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
  }
}
async function pullNessusScanResults(credentials, scanId) {
  const url = `${credentials.baseUrl}/scans/${scanId}`;
  const res = await fetchWithAuth(url, credentials);
  if (!res || !res.ok) throw new Error(`Failed to pull Nessus scan ${scanId}: ${res?.status || "connection failed"}`);
  const data = await res.json();
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  for (const host of data.hosts || []) {
    const hostName = host.hostname;
    hosts.add(hostName);
    const hostUrl = `${credentials.baseUrl}/scans/${scanId}/hosts/${host.host_id}`;
    const hostRes = await fetchWithAuth(hostUrl, credentials);
    if (!hostRes || !hostRes.ok) continue;
    const hostData = await hostRes.json();
    for (const vuln of hostData.vulnerabilities || []) {
      const severity = mapNessusSeverityFromCount(vuln.severity);
      if (severity === "info") continue;
      findings.push({
        cveId: null,
        // Would need plugin details call for CVE
        title: vuln.plugin_name || "Unknown",
        severity,
        cvssScore: vuln.severity_index || null,
        hostIp: host.host_ip || null,
        hostName,
        port: null,
        protocol: null,
        description: null,
        solution: null,
        pluginId: String(vuln.plugin_id),
        exploitAvailable: false
      });
    }
  }
  return {
    scannerType: "nessus",
    findings,
    totalHosts: hosts.size,
    totalVulns: findings.length,
    ...countSeverities(findings)
  };
}
async function pullQualysScanResults(credentials, scanId) {
  const url = `${credentials.baseUrl}/api/2.0/fo/scan/?action=fetch&scan_ref=${scanId}&output_format=json`;
  const res = await fetchWithAuth(url, credentials, { method: "POST" });
  if (!res || !res.ok) throw new Error(`Failed to pull Qualys scan ${scanId}`);
  const text = await res.text();
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  const hostRegex = /<IP>([\s\S]*?)<\/IP>/g;
  let match;
  while ((match = hostRegex.exec(text)) !== null) {
    hosts.add(match[1]);
  }
  const vulnRegex = /<VULN>([\s\S]*?)<\/VULN>/g;
  while ((match = vulnRegex.exec(text)) !== null) {
    const content = match[1];
    const getTag = (tag) => {
      const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(content);
      return m ? m[1].trim() : null;
    };
    const severityNum = parseInt(getTag("SEVERITY") || "0");
    findings.push({
      cveId: getTag("CVE_ID"),
      title: getTag("TITLE") || "Unknown",
      severity: mapQualysSeverity(severityNum),
      cvssScore: getTag("CVSS_BASE") ? parseFloat(getTag("CVSS_BASE")) : null,
      hostIp: getTag("IP"),
      hostName: getTag("DNS"),
      port: getTag("PORT") ? parseInt(getTag("PORT")) : null,
      protocol: getTag("PROTOCOL"),
      description: getTag("DIAGNOSIS"),
      solution: getTag("SOLUTION"),
      pluginId: getTag("QID"),
      exploitAvailable: getTag("EXPLOITABILITY")?.includes("Exploit") || false
    });
  }
  return {
    scannerType: "qualys",
    findings,
    totalHosts: hosts.size,
    totalVulns: findings.length,
    ...countSeverities(findings)
  };
}
async function pullRapid7ScanResults(credentials, scanId) {
  const assetsUrl = `${credentials.baseUrl}/api/3/scans/${scanId}/assets`;
  const assetsRes = await fetchWithAuth(assetsUrl, credentials);
  if (!assetsRes || !assetsRes.ok) throw new Error(`Failed to pull Rapid7 scan ${scanId}`);
  const assetsData = await assetsRes.json();
  const findings = [];
  const hosts = /* @__PURE__ */ new Set();
  for (const asset of (assetsData.resources || []).slice(0, 100)) {
    const ip = asset.ip || asset.address;
    const hostname = asset.hostName;
    if (ip) hosts.add(ip);
    const vulnUrl = `${credentials.baseUrl}/api/3/assets/${asset.id}/vulnerabilities?page=0&size=500`;
    const vulnRes = await fetchWithAuth(vulnUrl, credentials);
    if (!vulnRes || !vulnRes.ok) continue;
    const vulnData = await vulnRes.json();
    for (const vuln of vulnData.resources || []) {
      findings.push({
        cveId: null,
        title: vuln.title || "Unknown",
        severity: mapRapid7SeverityFromScore(vuln.cvssV3?.score || vuln.cvssV2?.score || 0),
        cvssScore: vuln.cvssV3?.score || vuln.cvssV2?.score || null,
        hostIp: ip,
        hostName: hostname,
        port: vuln.port || null,
        protocol: vuln.protocol || null,
        description: vuln.description || null,
        solution: vuln.solution || null,
        pluginId: vuln.id || null,
        exploitAvailable: vuln.exploits > 0
      });
    }
  }
  return {
    scannerType: "rapid7",
    findings,
    totalHosts: hosts.size,
    totalVulns: findings.length,
    ...countSeverities(findings)
  };
}
function mapNessusSeverityFromCount(severity) {
  switch (severity) {
    case 4:
      return "critical";
    case 3:
      return "high";
    case 2:
      return "medium";
    case 1:
      return "low";
    default:
      return "info";
  }
}
function mapQualysSeverity(severity) {
  if (severity >= 5) return "critical";
  if (severity >= 4) return "high";
  if (severity >= 3) return "medium";
  if (severity >= 2) return "low";
  return "info";
}
function mapRapid7SeverityFromScore(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}
function countSeverities(findings) {
  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        criticalCount++;
        break;
      case "high":
        highCount++;
        break;
      case "medium":
        mediumCount++;
        break;
      case "low":
        lowCount++;
        break;
    }
  }
  return { criticalCount, highCount, mediumCount, lowCount };
}
export {
  listRemoteScans,
  pullScanResults,
  validateConnection
};
