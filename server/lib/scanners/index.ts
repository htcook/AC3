/**
 * Scanner Modules — Barrel Export
 *
 * All DAST scanners and service audit modules:
 * - Nikto: Web server scanner (6,700+ checks)
 * - Wapiti: Black-box injection tester (SQL, XSS, XXE, SSRF, etc.)
 * - Arachni: Full-featured web app scanner with DOM analysis
 * - SSH Audit: SSH algorithm, CVE, and auth method auditing
 * - FTP Audit: FTP anonymous access, bounce, CVE, and credential testing
 * - SMTP Audit: Open relay, VRFY/EXPN enum, STARTTLS, auth methods, version CVEs
 * - SNMP Audit: Community string brute, v1/v2c weak auth, info disclosure, MIB walk
 * - RDP Audit: NLA check, CredSSP/BlueKeep CVEs, encryption level, NTLMv1 downgrade
 * - DNS Audit: Zone transfer, DNSSEC, recursion, version disclosure, cache poisoning
 * - HTTP Header Audit: Security headers, CORS, cookies, TLS, server disclosure
 * - TLS Deep Scan: Cipher suites, cert chain, OCSP, protocol downgrade, CVEs (Heartbleed, POODLE, etc.)
 * - Service Audit Pipeline: Auto-triggers appropriate scanners after port discovery
 */

export { startNiktoScan, analyzeNiktoFindings, type NiktoConfig, type NiktoFinding, type NiktoScanResult } from "./nikto-scanner";
export { startWapitiScan, analyzeWapitiFindings, type WapitiConfig, type WapitiFinding, type WapitiScanResult } from "./wapiti-scanner";
export { startArachniScan, analyzeArachniFindings, type ArachniConfig, type ArachniFinding, type ArachniScanResult } from "./arachni-scanner";
export { startSSHAudit, type SSHAuditConfig, type SSHAuditResult, type SSHAuditFinding, type SSHAlgorithm } from "./ssh-audit-scanner";
export { startFTPAudit, type FTPAuditConfig, type FTPAuditResult, type FTPAuditFinding } from "./ftp-audit-scanner";
export { startSMTPAudit, type SMTPAuditConfig, type SMTPAuditResult, type SMTPAuditFinding } from "./smtp-audit-scanner";
export { startSNMPAudit, type SNMPAuditConfig, type SNMPAuditResult, type SNMPAuditFinding } from "./snmp-audit-scanner";
export { startRDPAudit, type RDPAuditConfig, type RDPAuditResult, type RDPAuditFinding } from "./rdp-audit-scanner";
export { startDNSAudit, type DNSAuditConfig, type DNSAuditResult, type DNSFinding } from "./dns-audit-scanner";
export { startHTTPHeaderAudit, type HTTPHeaderAuditConfig, type HTTPHeaderAuditResult, type HTTPHeaderFinding, type SecurityHeader, type CookieAudit, type CORSAudit, type TLSInfo } from "./http-header-audit-scanner";
export { startTLSDeepScan, type TLSDeepScanConfig, type TLSDeepScanResult, type TLSProtocol, type TLSCipherSuite, type TLSCertificate, type TLSVulnerability, type TLSFinding } from "./tls-deep-scanner";
export {
  runServiceAuditPipeline,
  autoAuditSSHPorts,
  autoAuditFTPPorts,
  autoAuditSMTPPorts,
  autoAuditSNMPPorts,
  autoAuditRDPPorts,
  autoAuditDNSPorts,
  autoAuditHTTPPorts,
  autoAuditTLSPorts,
  type DiscoveredService,
  type ServiceAuditConfig,
  type ServiceAuditPipelineResult,
  type ServiceAuditEvent,
} from "./service-audit-pipeline";
