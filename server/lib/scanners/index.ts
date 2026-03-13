/**
 * Scanner Modules — Barrel Export
 *
 * All DAST scanners and service audit modules:
 * - Nikto: Web server scanner (6,700+ checks)
 * - Wapiti: Black-box injection tester (SQL, XSS, XXE, SSRF, etc.)
 * - Arachni: Full-featured web app scanner with DOM analysis
 * - SSH Audit: SSH algorithm, CVE, and auth method auditing
 * - FTP Audit: FTP anonymous access, bounce, CVE, and credential testing
 * - Service Audit Pipeline: Auto-triggers appropriate scanners after port discovery
 */

export { startNiktoScan, analyzeNiktoFindings, type NiktoConfig, type NiktoFinding, type NiktoScanResult } from "./nikto-scanner";
export { startWapitiScan, analyzeWapitiFindings, type WapitiConfig, type WapitiFinding, type WapitiScanResult } from "./wapiti-scanner";
export { startArachniScan, analyzeArachniFindings, type ArachniConfig, type ArachniFinding, type ArachniScanResult } from "./arachni-scanner";
export { startSSHAudit, type SSHAuditConfig, type SSHAuditResult, type SSHAuditFinding, type SSHAlgorithm } from "./ssh-audit-scanner";
export { startFTPAudit, type FTPAuditConfig, type FTPAuditResult, type FTPAuditFinding } from "./ftp-audit-scanner";
export {
  runServiceAuditPipeline,
  autoAuditSSHPorts,
  autoAuditFTPPorts,
  type DiscoveredService,
  type ServiceAuditConfig,
  type ServiceAuditPipelineResult,
  type ServiceAuditEvent,
} from "./service-audit-pipeline";
