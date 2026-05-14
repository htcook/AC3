import {
  startWapitiScan
} from "./chunk-AW4NQMNA.js";
import {
  startArachniScan
} from "./chunk-L3OGCX4M.js";
import {
  startSMTPAudit
} from "./chunk-LFD3HVVW.js";
import {
  startSNMPAudit
} from "./chunk-PMZC73VF.js";
import {
  startRDPAudit
} from "./chunk-4BAUU3AU.js";
import {
  startDNSAudit
} from "./chunk-5FJ6CZCL.js";
import {
  startHTTPHeaderAudit
} from "./chunk-RA6FSAWH.js";
import {
  startTLSDeepScan
} from "./chunk-C3DI32EJ.js";
import {
  startSSHAudit
} from "./chunk-FVWKA2UI.js";
import {
  startFTPAudit
} from "./chunk-KUD72YPU.js";
import {
  startNiktoScan
} from "./chunk-TJSHTEE3.js";
import "./chunk-EILMWEUF.js";
import "./chunk-5TKYQID2.js";
import "./chunk-CYC4YF3X.js";
import "./chunk-LCJGW2NZ.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-SD56WPOS.js";
import "./chunk-L5VXSJ4F.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-JZVHFV6D.js";
import "./chunk-GN2OC6SU.js";
import "./chunk-IG2G4XDA.js";
import "./chunk-KFQGP6VL.js";

// server/lib/scanners/service-audit-pipeline.ts
var SERVICE_SCANNER_MAP = {
  ssh: { scanners: ["ssh-audit"], description: "SSH security audit" },
  ftp: { scanners: ["ftp-audit"], description: "FTP security audit" },
  http: { scanners: ["nikto", "wapiti"], description: "Web server + injection testing" },
  https: { scanners: ["nikto", "wapiti", "tls-deep-scan"], description: "Web server + injection testing (TLS)" },
  "http-proxy": { scanners: ["nikto"], description: "HTTP proxy audit" },
  "http-alt": { scanners: ["nikto"], description: "Alternate HTTP audit" },
  smtp: { scanners: ["smtp-audit"], description: "SMTP security audit" },
  snmp: { scanners: ["snmp-audit"], description: "SNMP security audit" },
  "ms-wbt-server": { scanners: ["rdp-audit"], description: "RDP security audit" },
  rdp: { scanners: ["rdp-audit"], description: "RDP security audit" },
  dns: { scanners: ["dns-audit"], description: "DNS security audit" },
  domain: { scanners: ["dns-audit"], description: "DNS security audit" }
};
var PORT_SCANNER_MAP = {
  21: { scanners: ["ftp-audit"], description: "FTP audit" },
  22: { scanners: ["ssh-audit"], description: "SSH audit" },
  2222: { scanners: ["ssh-audit"], description: "SSH audit (alt port)" },
  80: { scanners: ["nikto", "wapiti"], description: "HTTP web audit" },
  443: { scanners: ["nikto", "wapiti", "tls-deep-scan"], description: "HTTPS web audit" },
  8080: { scanners: ["nikto"], description: "HTTP alt web audit" },
  8443: { scanners: ["nikto", "tls-deep-scan"], description: "HTTPS alt web audit" },
  3e3: { scanners: ["nikto"], description: "Dev server audit" },
  5e3: { scanners: ["nikto"], description: "Dev server audit" },
  8e3: { scanners: ["nikto"], description: "Dev server audit" },
  8888: { scanners: ["nikto"], description: "Dev server audit" },
  9090: { scanners: ["nikto"], description: "Admin panel audit" },
  25: { scanners: ["smtp-audit"], description: "SMTP audit" },
  465: { scanners: ["smtp-audit", "tls-deep-scan"], description: "SMTPS audit" },
  587: { scanners: ["smtp-audit"], description: "SMTP submission audit" },
  2525: { scanners: ["smtp-audit"], description: "SMTP alt audit" },
  161: { scanners: ["snmp-audit"], description: "SNMP audit" },
  162: { scanners: ["snmp-audit"], description: "SNMP trap audit" },
  3389: { scanners: ["rdp-audit"], description: "RDP audit" },
  3388: { scanners: ["rdp-audit"], description: "RDP alt audit" },
  53: { scanners: ["dns-audit"], description: "DNS audit" },
  5353: { scanners: ["dns-audit"], description: "mDNS audit" }
};
function getScannersForService(service, enabled) {
  const scanners = /* @__PURE__ */ new Set();
  const serviceLower = service.service?.toLowerCase() || "";
  for (const [svcName, mapping] of Object.entries(SERVICE_SCANNER_MAP)) {
    if (serviceLower.includes(svcName)) {
      for (const s of mapping.scanners) scanners.add(s);
    }
  }
  const portMapping = PORT_SCANNER_MAP[service.port];
  if (portMapping) {
    for (const s of portMapping.scanners) scanners.add(s);
  }
  const webPorts = [80, 443, 8080, 8443, 3e3, 5e3, 8e3, 8888, 9090];
  if (webPorts.includes(service.port) || serviceLower.includes("http")) {
    scanners.add("http-header-audit");
  }
  const tlsPorts = [443, 8443, 993, 995, 465, 636, 989, 990];
  if (tlsPorts.includes(service.port) || serviceLower.includes("ssl") || serviceLower.includes("tls")) {
    scanners.add("tls-deep-scan");
  }
  const enabledMap = {
    "ssh-audit": enabled?.ssh !== false,
    "ftp-audit": enabled?.ftp !== false,
    nikto: enabled?.nikto !== false,
    wapiti: enabled?.wapiti !== false,
    arachni: enabled?.arachni !== false,
    "smtp-audit": enabled?.smtp !== false,
    "snmp-audit": enabled?.snmp !== false,
    "rdp-audit": enabled?.rdp !== false,
    "dns-audit": enabled?.dns !== false,
    "http-header-audit": enabled?.httpHeaders !== false,
    "tls-deep-scan": enabled?.tlsDeepScan !== false
  };
  return Array.from(scanners).filter((s) => enabledMap[s] !== false);
}
async function runScanner(scanner, service, config) {
  const timeout = config.timeoutPerAudit || 300;
  const isHttps = service.service?.toLowerCase().includes("https") || service.port === 443 || service.port === 8443;
  const protocol = isHttps ? "https" : "http";
  const targetUrl = `${protocol}://${service.host}:${service.port}`;
  try {
    switch (scanner) {
      case "ssh-audit": {
        const result = await startSSHAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout
        });
        return { scanner, result };
      }
      case "ftp-audit": {
        const result = await startFTPAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout
        });
        return { scanner, result };
      }
      case "nikto": {
        const result = await startNiktoScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          ssl: isHttps,
          port: service.port,
          tuning: config.profile === "quick" ? "1234" : config.profile === "deep" ? "123456789" : "12345"
        });
        return { scanner, result };
      }
      case "wapiti": {
        const result = await startWapitiScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          scope: config.profile === "quick" ? "page" : config.profile === "deep" ? "domain" : "folder",
          maxDepth: config.profile === "quick" ? 2 : config.profile === "deep" ? 10 : 5,
          modules: config.profile === "quick" ? "sql,xss,exec" : void 0
        });
        return { scanner, result };
      }
      case "arachni": {
        const result = await startArachniScan({
          targetUrl,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          maxPages: config.profile === "quick" ? 20 : config.profile === "deep" ? 500 : 100,
          maxDepth: config.profile === "quick" ? 2 : config.profile === "deep" ? 10 : 5
        });
        return { scanner, result };
      }
      case "smtp-audit": {
        const result = await startSMTPAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          domain: service.host
        });
        return { scanner, result };
      }
      case "snmp-audit": {
        const result = await startSNMPAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout
        });
        return { scanner, result };
      }
      case "rdp-audit": {
        const result = await startRDPAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout
        });
        return { scanner, result };
      }
      case "dns-audit": {
        const result = await startDNSAudit({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          domain: service.host
        });
        return { scanner, result };
      }
      case "http-header-audit": {
        const isHttps2 = service.service?.toLowerCase().includes("https") || service.port === 443 || service.port === 8443;
        const result = await startHTTPHeaderAudit({
          host: service.host,
          port: service.port,
          https: isHttps2,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout
        });
        return { scanner, result };
      }
      case "tls-deep-scan": {
        const result = await startTLSDeepScan({
          host: service.host,
          port: service.port,
          engagementId: config.engagementId,
          operatorId: config.operatorId,
          timeoutSeconds: timeout,
          checkDowngrade: config.profile !== "quick",
          checkCVEs: true,
          enumerateCiphers: true,
          checkCertChain: true,
          checkOCSP: config.profile !== "quick"
        });
        return { scanner, result };
      }
      default:
        return { scanner, result: null, error: `Unknown scanner: ${scanner}` };
    }
  } catch (err) {
    return { scanner, result: null, error: err.message };
  }
}
async function runServiceAuditPipeline(services, config) {
  const startTime = Date.now();
  const concurrency = config.concurrency || 3;
  const emit = config.onEvent || (() => {
  });
  const results = {
    ssh: [],
    ftp: [],
    nikto: [],
    wapiti: [],
    arachni: [],
    smtp: [],
    snmp: [],
    rdp: [],
    dns: [],
    httpHeaders: [],
    tlsDeepScan: []
  };
  let auditsTriggered = 0;
  let auditsCompleted = 0;
  let auditsFailed = 0;
  const tasks = [];
  for (const service of services) {
    const scanners = getScannersForService(service, config.enabledScanners);
    for (const scanner of scanners) {
      tasks.push({ service, scanner });
    }
  }
  auditsTriggered = tasks.length;
  console.log(`[ServiceAuditPipeline] ${tasks.length} audits queued for ${services.length} services`);
  const executing = /* @__PURE__ */ new Set();
  for (const task of tasks) {
    const promise = (async () => {
      emit({
        type: "audit_started",
        service: task.service,
        scanner: task.scanner,
        timestamp: Date.now()
      });
      const { scanner, result, error } = await runScanner(task.scanner, task.service, config);
      if (error || !result) {
        auditsFailed++;
        emit({
          type: "audit_error",
          service: task.service,
          scanner,
          error: error || "No result returned",
          timestamp: Date.now()
        });
      } else {
        auditsCompleted++;
        switch (scanner) {
          case "ssh-audit":
            results.ssh.push(result);
            break;
          case "ftp-audit":
            results.ftp.push(result);
            break;
          case "nikto":
            results.nikto.push(result);
            break;
          case "wapiti":
            results.wapiti.push(result);
            break;
          case "arachni":
            results.arachni.push(result);
            break;
          case "smtp-audit":
            results.smtp.push(result);
            break;
          case "snmp-audit":
            results.snmp.push(result);
            break;
          case "rdp-audit":
            results.rdp.push(result);
            break;
          case "dns-audit":
            results.dns.push(result);
            break;
          case "http-header-audit":
            results.httpHeaders.push(result);
            break;
          case "tls-deep-scan":
            results.tlsDeepScan.push(result);
            break;
        }
        emit({
          type: "audit_completed",
          service: task.service,
          scanner,
          result: {
            findingCount: result.findings?.length || 0,
            status: result.status
          },
          timestamp: Date.now()
        });
      }
    })();
    executing.add(promise);
    promise.finally(() => executing.delete(promise));
    if (executing.size >= concurrency) {
      await Promise.race(executing);
    }
  }
  await Promise.allSettled(executing);
  const severitySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let totalFindings = 0;
  const allResults = [
    ...results.ssh.flatMap((r) => r.findings),
    ...results.ftp.flatMap((r) => r.findings),
    ...results.nikto.flatMap((r) => r.findings),
    ...results.wapiti.flatMap((r) => r.findings),
    ...results.arachni.flatMap((r) => r.findings),
    ...results.smtp.flatMap((r) => r.findings),
    ...results.snmp.flatMap((r) => r.findings),
    ...results.rdp.flatMap((r) => r.findings),
    ...results.dns.flatMap((r) => r.findings),
    ...results.httpHeaders.flatMap((r) => r.findings),
    ...results.tlsDeepScan.flatMap((r) => r.findings)
  ];
  for (const finding of allResults) {
    totalFindings++;
    const sev = finding.severity;
    if (sev in severitySummary) severitySummary[sev]++;
  }
  const durationSeconds = (Date.now() - startTime) / 1e3;
  emit({
    type: "pipeline_completed",
    service: services[0] || { host: "unknown", port: 0, service: "unknown" },
    scanner: "pipeline",
    result: { totalFindings, auditsCompleted, auditsFailed },
    timestamp: Date.now()
  });
  console.log(`[ServiceAuditPipeline] Complete: ${auditsCompleted}/${auditsTriggered} audits, ${totalFindings} findings in ${durationSeconds.toFixed(1)}s`);
  return {
    totalServices: services.length,
    auditsTriggered,
    auditsCompleted,
    auditsFailed,
    results,
    totalFindings,
    severitySummary,
    durationSeconds
  };
}
async function autoAuditSSHPorts(hosts, engagementId, operatorId) {
  const sshHosts = hosts.filter((h) => h.port === 22 || h.port === 2222);
  if (sshHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${sshHosts.length} SSH service(s)`);
  const results = [];
  for (const { host, port } of sshHosts) {
    try {
      const result = await startSSHAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] SSH audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditFTPPorts(hosts, engagementId, operatorId) {
  const ftpHosts = hosts.filter((h) => h.port === 21 || h.port === 990);
  if (ftpHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${ftpHosts.length} FTP service(s)`);
  const results = [];
  for (const { host, port } of ftpHosts) {
    try {
      const result = await startFTPAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] FTP audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditSMTPPorts(hosts, engagementId, operatorId) {
  const smtpHosts = hosts.filter((h) => [25, 465, 587, 2525].includes(h.port));
  if (smtpHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${smtpHosts.length} SMTP service(s)`);
  const results = [];
  for (const { host, port } of smtpHosts) {
    try {
      const result = await startSMTPAudit({ host, port, engagementId, operatorId, domain: host });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] SMTP audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditSNMPPorts(hosts, engagementId, operatorId) {
  const snmpHosts = hosts.filter((h) => h.port === 161 || h.port === 162);
  if (snmpHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${snmpHosts.length} SNMP service(s)`);
  const results = [];
  for (const { host, port } of snmpHosts) {
    try {
      const result = await startSNMPAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] SNMP audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditRDPPorts(hosts, engagementId, operatorId) {
  const rdpHosts = hosts.filter((h) => h.port === 3389 || h.port === 3388);
  if (rdpHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${rdpHosts.length} RDP service(s)`);
  const results = [];
  for (const { host, port } of rdpHosts) {
    try {
      const result = await startRDPAudit({ host, port, engagementId, operatorId });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] RDP audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditDNSPorts(hosts, engagementId, operatorId) {
  const dnsHosts = hosts.filter((h) => h.port === 53 || h.port === 5353);
  if (dnsHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${dnsHosts.length} DNS service(s)`);
  const results = [];
  for (const { host, port } of dnsHosts) {
    try {
      const result = await startDNSAudit({ host, port, engagementId, operatorId, domain: host });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] DNS audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditHTTPPorts(hosts, engagementId, operatorId) {
  const httpHosts = hosts.filter((h) => [80, 443, 8080, 8443, 3e3, 5e3, 8e3, 8888, 9090].includes(h.port));
  if (httpHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${httpHosts.length} HTTP service(s) for security headers`);
  const results = [];
  for (const { host, port } of httpHosts) {
    try {
      const isHttps = port === 443 || port === 8443;
      const result = await startHTTPHeaderAudit({ host, port, https: isHttps, engagementId, operatorId });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] HTTP header audit failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
async function autoAuditTLSPorts(hosts, engagementId, operatorId) {
  const tlsHosts = hosts.filter((h) => [443, 8443, 993, 995, 465, 636, 989, 990].includes(h.port));
  if (tlsHosts.length === 0) return [];
  console.log(`[ServiceAuditPipeline] Auto-auditing ${tlsHosts.length} TLS service(s) for deep SSL/TLS analysis`);
  const results = [];
  for (const { host, port } of tlsHosts) {
    try {
      const result = await startTLSDeepScan({
        host,
        port,
        engagementId,
        operatorId,
        checkDowngrade: true,
        checkCVEs: true,
        enumerateCiphers: true,
        checkCertChain: true,
        checkOCSP: true
      });
      results.push(result);
    } catch (err) {
      console.error(`[ServiceAuditPipeline] TLS deep scan failed for ${host}:${port}: ${err.message}`);
    }
  }
  return results;
}
export {
  autoAuditDNSPorts,
  autoAuditFTPPorts,
  autoAuditHTTPPorts,
  autoAuditRDPPorts,
  autoAuditSMTPPorts,
  autoAuditSNMPPorts,
  autoAuditSSHPorts,
  autoAuditTLSPorts,
  runServiceAuditPipeline
};
