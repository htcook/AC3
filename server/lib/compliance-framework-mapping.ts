/**
 * Compliance Framework Mapping Engine
 * 
 * Maps CWE categories, CVE findings, and vulnerability classes to controls across
 * major compliance frameworks: NIST 800-53, CIS Controls v8, PCI-DSS v4.0,
 * ISO 27001:2022, HIPAA Security Rule, and SOC 2 Trust Services Criteria.
 * 
 * Supports both:
 * - Engagement vuln scan findings (CWE-based from Nuclei/ZAP/Burp)
 * - DI scan posture findings (category/CVE-based from LLM analysis)
 */

// ─── Framework Definitions ─────────────────────────────────────────────────────

export type FrameworkId = 'nist_800_53' | 'cis_v8' | 'pci_dss_v4' | 'iso_27001' | 'hipaa' | 'soc2';

export interface FrameworkControl {
  id: string;           // e.g. "SI-10", "6.1", "Req 6.2.4"
  title: string;        // Human-readable control title
  family: string;       // Control family/group
  description: string;  // Brief description
}

export interface FrameworkMapping {
  frameworkId: FrameworkId;
  frameworkName: string;
  controls: FrameworkControl[];
}

export interface VulnFrameworkResult {
  vulnId: string;
  vulnTitle: string;
  cwe?: string;
  cveIds?: string[];
  category?: string;
  severity: string;
  mappings: FrameworkMapping[];
}

export interface FrameworkSummary {
  frameworkId: FrameworkId;
  frameworkName: string;
  totalControlsAffected: number;
  controlsByFamily: Record<string, number>;
  controlDetails: Array<{
    control: FrameworkControl;
    vulnCount: number;
    maxSeverity: string;
    vulnIds: string[];
  }>;
}

export interface ComplianceReport {
  generatedAt: string;
  selectedFrameworks: FrameworkId[];
  totalVulns: number;
  frameworkSummaries: FrameworkSummary[];
  vulnMappings: VulnFrameworkResult[];
}

// ─── Framework Metadata ────────────────────────────────────────────────────────

export const FRAMEWORK_METADATA: Record<FrameworkId, { name: string; version: string; description: string }> = {
  nist_800_53: {
    name: 'NIST SP 800-53',
    version: 'Rev. 5',
    description: 'Security and Privacy Controls for Information Systems and Organizations',
  },
  cis_v8: {
    name: 'CIS Controls',
    version: 'v8.1',
    description: 'Center for Internet Security Critical Security Controls',
  },
  pci_dss_v4: {
    name: 'PCI DSS',
    version: 'v4.0.1',
    description: 'Payment Card Industry Data Security Standard',
  },
  iso_27001: {
    name: 'ISO/IEC 27001',
    version: '2022',
    description: 'Information Security Management Systems — Annex A Controls',
  },
  hipaa: {
    name: 'HIPAA Security Rule',
    version: '45 CFR Part 164',
    description: 'Health Insurance Portability and Accountability Act — Security Standards',
  },
  soc2: {
    name: 'SOC 2',
    version: 'TSC 2017',
    description: 'Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy',
  },
};

// ─── CWE → Framework Control Mappings ──────────────────────────────────────────
// Each CWE maps to relevant controls across all 6 frameworks.
// CWEs are grouped by vulnerability class for maintainability.

interface CweControlMap {
  nist_800_53: string[];
  cis_v8: string[];
  pci_dss_v4: string[];
  iso_27001: string[];
  hipaa: string[];
  soc2: string[];
}

/**
 * Master CWE-to-control mapping table.
 * Covers the top 40+ CWEs encountered in web application and infrastructure scanning.
 */
const CWE_CONTROL_MAP: Record<string, CweControlMap> = {
  // ── Injection Vulnerabilities ──────────────────────────────────────────────
  'CWE-89': { // SQL Injection
    nist_800_53: ['SI-10', 'SI-11', 'SA-11', 'SA-15'],
    cis_v8: ['16.1', '16.2', '16.12'],
    pci_dss_v4: ['6.2.4', '6.3.1', '6.3.2', '11.3.1'],
    iso_27001: ['A.8.26', 'A.8.28', 'A.8.29'],
    hipaa: ['164.312(a)(1)', '164.312(a)(2)(iv)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1', 'CC8.1'],
  },
  'CWE-78': { // OS Command Injection
    nist_800_53: ['SI-10', 'SI-3', 'SA-11', 'CM-7'],
    cis_v8: ['16.1', '16.2', '2.5'],
    pci_dss_v4: ['6.2.4', '6.3.1', '11.3.1'],
    iso_27001: ['A.8.26', 'A.8.28', 'A.8.9'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
  },
  'CWE-77': { // Command Injection
    nist_800_53: ['SI-10', 'SI-3', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
  },
  'CWE-94': { // Code Injection
    nist_800_53: ['SI-10', 'SI-3', 'SA-11', 'SA-15'],
    cis_v8: ['16.1', '16.2', '16.12'],
    pci_dss_v4: ['6.2.4', '6.3.1', '6.3.2'],
    iso_27001: ['A.8.26', 'A.8.28', 'A.8.29'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1', 'CC8.1'],
  },
  'CWE-917': { // Expression Language Injection
    nist_800_53: ['SI-10', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },
  'CWE-90': { // LDAP Injection
    nist_800_53: ['SI-10', 'IA-5', 'SA-11'],
    cis_v8: ['16.1', '16.2', '6.5'],
    pci_dss_v4: ['6.2.4', '6.3.1', '8.3'],
    iso_27001: ['A.8.26', 'A.8.5', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(d)'],
    soc2: ['CC6.1', 'CC6.6'],
  },
  'CWE-611': { // XXE
    nist_800_53: ['SI-10', 'SC-4', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
  },
  'CWE-91': { // XML Injection
    nist_800_53: ['SI-10', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── Cross-Site Scripting ───────────────────────────────────────────────────
  'CWE-79': { // XSS (Reflected, Stored, DOM)
    nist_800_53: ['SI-10', 'SI-11', 'SA-11', 'SC-18'],
    cis_v8: ['16.1', '16.2', '16.5'],
    pci_dss_v4: ['6.2.4', '6.3.1', '6.4.1', '11.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
  },

  // ── Authentication & Session ───────────────────────────────────────────────
  'CWE-287': { // Improper Authentication
    nist_800_53: ['IA-2', 'IA-5', 'IA-8', 'AC-7'],
    cis_v8: ['6.3', '6.4', '6.5'],
    pci_dss_v4: ['8.2.1', '8.3.1', '8.3.6', '8.4.1'],
    iso_27001: ['A.8.5', 'A.5.17', 'A.8.2'],
    hipaa: ['164.312(d)', '164.312(a)(2)(i)'],
    soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
  },
  'CWE-306': { // Missing Authentication for Critical Function
    nist_800_53: ['IA-2', 'AC-3', 'AC-6'],
    cis_v8: ['6.3', '6.4', '6.8'],
    pci_dss_v4: ['7.2.1', '8.2.1', '8.3.1'],
    iso_27001: ['A.8.5', 'A.8.3', 'A.5.15'],
    hipaa: ['164.312(d)', '164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
  },
  'CWE-384': { // Session Fixation
    nist_800_53: ['SC-23', 'IA-2', 'AC-12'],
    cis_v8: ['16.1', '16.8'],
    pci_dss_v4: ['6.2.4', '8.2.2'],
    iso_27001: ['A.8.5', 'A.8.26'],
    hipaa: ['164.312(d)', '164.312(a)(2)(i)'],
    soc2: ['CC6.1', 'CC6.2'],
  },
  'CWE-613': { // Insufficient Session Expiration
    nist_800_53: ['AC-12', 'SC-23', 'IA-11'],
    cis_v8: ['16.8', '6.5'],
    pci_dss_v4: ['8.2.8', '8.6.1'],
    iso_27001: ['A.8.5', 'A.5.17'],
    hipaa: ['164.312(a)(2)(iii)', '164.312(d)'],
    soc2: ['CC6.1', 'CC6.2'],
  },
  'CWE-798': { // Hard-coded Credentials
    nist_800_53: ['IA-5', 'SA-11', 'CM-6'],
    cis_v8: ['16.1', '16.7', '6.5'],
    pci_dss_v4: ['2.2.2', '6.3.1', '8.3.2'],
    iso_27001: ['A.5.17', 'A.8.4', 'A.8.9'],
    hipaa: ['164.312(d)', '164.312(a)(2)(iv)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-522': { // Insufficiently Protected Credentials
    nist_800_53: ['IA-5', 'SC-28', 'SC-13'],
    cis_v8: ['6.5', '16.4'],
    pci_dss_v4: ['8.3.2', '8.3.4', '3.5.1'],
    iso_27001: ['A.5.17', 'A.8.24'],
    hipaa: ['164.312(d)', '164.312(a)(2)(iv)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-307': { // Improper Restriction of Excessive Auth Attempts
    nist_800_53: ['AC-7', 'IA-5', 'SI-4'],
    cis_v8: ['6.3', '6.5'],
    pci_dss_v4: ['8.3.4', '8.3.6'],
    iso_27001: ['A.8.5', 'A.5.17'],
    hipaa: ['164.312(a)(2)(i)', '164.312(d)'],
    soc2: ['CC6.1', 'CC6.2'],
  },

  // ── Authorization & Access Control ─────────────────────────────────────────
  'CWE-862': { // Missing Authorization
    nist_800_53: ['AC-3', 'AC-6', 'AC-2'],
    cis_v8: ['6.8', '5.4', '3.3'],
    pci_dss_v4: ['7.2.1', '7.2.2', '7.2.5'],
    iso_27001: ['A.5.15', 'A.8.3', 'A.5.18'],
    hipaa: ['164.312(a)(1)', '164.312(a)(2)(i)'],
    soc2: ['CC6.1', 'CC6.3'],
  },
  'CWE-863': { // Incorrect Authorization
    nist_800_53: ['AC-3', 'AC-6', 'AC-5'],
    cis_v8: ['6.8', '5.4'],
    pci_dss_v4: ['7.2.1', '7.2.2'],
    iso_27001: ['A.5.15', 'A.8.3'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.3'],
  },
  'CWE-639': { // IDOR
    nist_800_53: ['AC-3', 'AC-4', 'SC-4'],
    cis_v8: ['6.8', '3.3'],
    pci_dss_v4: ['7.2.1', '6.2.4'],
    iso_27001: ['A.5.15', 'A.8.3'],
    hipaa: ['164.312(a)(1)', '164.312(a)(2)(i)'],
    soc2: ['CC6.1', 'CC6.3'],
  },
  'CWE-22': { // Path Traversal
    nist_800_53: ['SI-10', 'AC-3', 'CM-7'],
    cis_v8: ['16.1', '16.2', '3.3'],
    pci_dss_v4: ['6.2.4', '6.3.1', '7.2.1'],
    iso_27001: ['A.8.26', 'A.8.3', 'A.8.9'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── Cryptographic Issues ───────────────────────────────────────────────────
  'CWE-327': { // Use of Broken Crypto Algorithm
    nist_800_53: ['SC-13', 'SC-12', 'IA-7'],
    cis_v8: ['3.10', '3.11'],
    pci_dss_v4: ['4.2.1', '4.2.2', '3.5.1'],
    iso_27001: ['A.8.24', 'A.5.14'],
    hipaa: ['164.312(a)(2)(iv)', '164.312(e)(1)', '164.312(e)(2)(ii)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-295': { // Improper Certificate Validation
    nist_800_53: ['SC-23', 'SC-13', 'IA-5'],
    cis_v8: ['3.10', '12.1'],
    pci_dss_v4: ['4.2.1', '6.2.4'],
    iso_27001: ['A.8.24', 'A.5.14'],
    hipaa: ['164.312(e)(1)', '164.312(e)(2)(ii)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-326': { // Inadequate Encryption Strength
    nist_800_53: ['SC-13', 'SC-12'],
    cis_v8: ['3.10', '3.11'],
    pci_dss_v4: ['4.2.1', '4.2.2'],
    iso_27001: ['A.8.24'],
    hipaa: ['164.312(a)(2)(iv)', '164.312(e)(2)(ii)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-311': { // Missing Encryption of Sensitive Data
    nist_800_53: ['SC-28', 'SC-8', 'SC-13'],
    cis_v8: ['3.10', '3.11', '3.12'],
    pci_dss_v4: ['3.5.1', '4.2.1', '4.2.2'],
    iso_27001: ['A.8.24', 'A.5.14', 'A.8.10'],
    hipaa: ['164.312(a)(2)(iv)', '164.312(e)(1)', '164.312(e)(2)(ii)'],
    soc2: ['CC6.1', 'CC6.7'],
  },

  // ── Information Disclosure ─────────────────────────────────────────────────
  'CWE-200': { // Exposure of Sensitive Information
    nist_800_53: ['SI-11', 'AC-4', 'SC-8'],
    cis_v8: ['3.1', '3.12', '16.1'],
    pci_dss_v4: ['3.3.1', '3.4.1', '6.2.4'],
    iso_27001: ['A.5.12', 'A.8.10', 'A.8.11'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)', '164.310(d)(1)'],
    soc2: ['CC6.1', 'CC6.5', 'CC6.7'],
  },
  'CWE-209': { // Error Message Information Leak
    nist_800_53: ['SI-11', 'SA-11'],
    cis_v8: ['16.1', '16.4'],
    pci_dss_v4: ['6.2.4', '6.5.6'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC7.1'],
  },
  'CWE-532': { // Insertion of Sensitive Info into Log File
    nist_800_53: ['AU-3', 'AU-9', 'SI-11'],
    cis_v8: ['8.2', '8.5', '3.12'],
    pci_dss_v4: ['10.3.1', '10.3.3', '3.3.1'],
    iso_27001: ['A.8.15', 'A.8.10'],
    hipaa: ['164.312(b)', '164.312(a)(1)'],
    soc2: ['CC6.1', 'CC7.2'],
  },

  // ── File Upload & Inclusion ────────────────────────────────────────────────
  'CWE-434': { // Unrestricted File Upload
    nist_800_53: ['SI-10', 'SI-3', 'CM-7', 'SA-11'],
    cis_v8: ['16.1', '16.2', '10.1'],
    pci_dss_v4: ['6.2.4', '6.3.1', '5.2.1'],
    iso_27001: ['A.8.26', 'A.8.7', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC7.1'],
  },
  'CWE-98': { // File Inclusion
    nist_800_53: ['SI-10', 'CM-7', 'SA-11'],
    cis_v8: ['16.1', '16.2', '2.5'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.9', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── SSRF & Request Forgery ─────────────────────────────────────────────────
  'CWE-918': { // SSRF
    nist_800_53: ['SI-10', 'SC-7', 'AC-4'],
    cis_v8: ['16.1', '13.4', '4.8'],
    pci_dss_v4: ['6.2.4', '1.3.1', '1.3.2'],
    iso_27001: ['A.8.26', 'A.8.20', 'A.8.21'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },
  'CWE-352': { // CSRF
    nist_800_53: ['SC-23', 'SI-10', 'SA-11'],
    cis_v8: ['16.1', '16.6'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)', '164.312(d)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── Deserialization ────────────────────────────────────────────────────────
  'CWE-502': { // Deserialization of Untrusted Data
    nist_800_53: ['SI-10', 'SI-3', 'SA-11', 'SA-15'],
    cis_v8: ['16.1', '16.2', '16.12'],
    pci_dss_v4: ['6.2.4', '6.3.1', '6.3.2'],
    iso_27001: ['A.8.26', 'A.8.28', 'A.8.29'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6', 'CC8.1'],
  },

  // ── Configuration & Deployment ─────────────────────────────────────────────
  'CWE-16': { // Configuration
    nist_800_53: ['CM-6', 'CM-7', 'CM-2'],
    cis_v8: ['4.1', '4.8', '2.5'],
    pci_dss_v4: ['2.2.1', '2.2.2', '6.3.2'],
    iso_27001: ['A.8.9', 'A.8.19'],
    hipaa: ['164.312(a)(1)', '164.310(d)(1)'],
    soc2: ['CC6.1', 'CC7.1', 'CC8.1'],
  },
  'CWE-1021': { // Clickjacking
    nist_800_53: ['SI-10', 'SC-18'],
    cis_v8: ['16.1', '16.5'],
    pci_dss_v4: ['6.2.4', '6.4.1'],
    iso_27001: ['A.8.26'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },
  'CWE-693': { // Protection Mechanism Failure
    nist_800_53: ['SC-7', 'SC-8', 'CM-6'],
    cis_v8: ['4.1', '13.1', '13.6'],
    pci_dss_v4: ['1.2.1', '2.2.1', '6.4.1'],
    iso_27001: ['A.8.20', 'A.8.21', 'A.8.9'],
    hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── Denial of Service ──────────────────────────────────────────────────────
  'CWE-400': { // Uncontrolled Resource Consumption
    nist_800_53: ['SC-5', 'SI-10', 'CP-2'],
    cis_v8: ['16.1', '13.8'],
    pci_dss_v4: ['6.2.4', '11.5.1'],
    iso_27001: ['A.8.6', 'A.8.26'],
    hipaa: ['164.312(a)(1)', '164.308(a)(7)(i)'],
    soc2: ['CC6.1', 'A1.1', 'A1.2'],
  },

  // ── Outdated Software ──────────────────────────────────────────────────────
  'CWE-1104': { // Use of Unmaintained Third-Party Components
    nist_800_53: ['SA-22', 'SI-2', 'RA-5', 'CM-8'],
    cis_v8: ['2.1', '2.2', '7.4', '16.11'],
    pci_dss_v4: ['6.3.1', '6.3.2', '6.3.3', '11.3.1'],
    iso_27001: ['A.8.8', 'A.8.19', 'A.5.19'],
    hipaa: ['164.312(a)(1)', '164.308(a)(5)(ii)(B)'],
    soc2: ['CC6.1', 'CC7.1', 'CC8.1'],
  },
  'CWE-937': { // Using Components with Known Vulns
    nist_800_53: ['SI-2', 'RA-5', 'SA-22', 'CM-8'],
    cis_v8: ['7.1', '7.4', '16.11'],
    pci_dss_v4: ['6.3.1', '6.3.2', '6.3.3'],
    iso_27001: ['A.8.8', 'A.8.19'],
    hipaa: ['164.312(a)(1)', '164.308(a)(1)(ii)(B)'],
    soc2: ['CC6.1', 'CC7.1', 'CC8.1'],
  },

  // ── Race Conditions & Logic ────────────────────────────────────────────────
  'CWE-362': { // Race Condition
    nist_800_53: ['SI-10', 'SA-11', 'SA-15'],
    cis_v8: ['16.1', '16.12'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC8.1'],
  },
  'CWE-841': { // Improper Enforcement of Behavioral Workflow
    nist_800_53: ['AC-3', 'SA-11'],
    cis_v8: ['16.1', '16.12'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.5.15'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC8.1'],
  },

  // ── Open Redirect ──────────────────────────────────────────────────────────
  'CWE-601': { // URL Redirect to Untrusted Site
    nist_800_53: ['SI-10', 'SC-18'],
    cis_v8: ['16.1', '16.5'],
    pci_dss_v4: ['6.2.4'],
    iso_27001: ['A.8.26'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC6.6'],
  },

  // ── Memory Safety ──────────────────────────────────────────────────────────
  'CWE-119': { // Buffer Overflow
    nist_800_53: ['SI-10', 'SI-16', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC8.1'],
  },
  'CWE-125': { // Out-of-bounds Read
    nist_800_53: ['SI-16', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC8.1'],
  },
  'CWE-787': { // Out-of-bounds Write
    nist_800_53: ['SI-16', 'SA-11'],
    cis_v8: ['16.1', '16.2'],
    pci_dss_v4: ['6.2.4', '6.3.1'],
    iso_27001: ['A.8.26', 'A.8.28'],
    hipaa: ['164.312(a)(1)'],
    soc2: ['CC6.1', 'CC8.1'],
  },

  // ── Privilege Escalation ───────────────────────────────────────────────────
  'CWE-269': { // Improper Privilege Management
    nist_800_53: ['AC-6', 'AC-2', 'AC-5'],
    cis_v8: ['5.4', '6.8', '5.3'],
    pci_dss_v4: ['7.2.1', '7.2.2', '7.2.5'],
    iso_27001: ['A.5.15', 'A.5.18', 'A.8.2'],
    hipaa: ['164.312(a)(1)', '164.312(a)(2)(i)'],
    soc2: ['CC6.1', 'CC6.3'],
  },

  // ── Security Headers ───────────────────────────────────────────────────────
  'CWE-1275': { // Sensitive Cookie Without Secure Flag
    nist_800_53: ['SC-23', 'SC-8'],
    cis_v8: ['16.1', '3.10'],
    pci_dss_v4: ['6.2.4', '4.2.1'],
    iso_27001: ['A.8.26', 'A.8.24'],
    hipaa: ['164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
  'CWE-614': { // Sensitive Cookie in HTTPS Without Secure Attribute
    nist_800_53: ['SC-23', 'SC-8'],
    cis_v8: ['16.1', '3.10'],
    pci_dss_v4: ['6.2.4', '4.2.1'],
    iso_27001: ['A.8.26', 'A.8.24'],
    hipaa: ['164.312(e)(1)'],
    soc2: ['CC6.1', 'CC6.7'],
  },
};

// ─── Control Details Database ──────────────────────────────────────────────────

const NIST_800_53_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  'AC-2': { title: 'Account Management', family: 'Access Control', description: 'Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.' },
  'AC-3': { title: 'Access Enforcement', family: 'Access Control', description: 'Enforce approved authorizations for logical access to information and system resources.' },
  'AC-4': { title: 'Information Flow Enforcement', family: 'Access Control', description: 'Enforce approved authorizations for controlling the flow of information within the system and between systems.' },
  'AC-5': { title: 'Separation of Duties', family: 'Access Control', description: 'Separate duties of individuals to reduce risk of malevolent activity.' },
  'AC-6': { title: 'Least Privilege', family: 'Access Control', description: 'Employ the principle of least privilege, allowing only authorized accesses necessary for users.' },
  'AC-7': { title: 'Unsuccessful Logon Attempts', family: 'Access Control', description: 'Enforce a limit of consecutive invalid logon attempts by a user.' },
  'AC-12': { title: 'Session Termination', family: 'Access Control', description: 'Automatically terminate a user session after defined conditions.' },
  'AU-3': { title: 'Content of Audit Records', family: 'Audit and Accountability', description: 'Ensure audit records contain information needed to establish what occurred.' },
  'AU-9': { title: 'Protection of Audit Information', family: 'Audit and Accountability', description: 'Protect audit information and audit logging tools from unauthorized access, modification, and deletion.' },
  'CM-2': { title: 'Baseline Configuration', family: 'Configuration Management', description: 'Develop, document, and maintain a current baseline configuration of the system.' },
  'CM-6': { title: 'Configuration Settings', family: 'Configuration Management', description: 'Establish and document configuration settings for IT products using security configuration checklists.' },
  'CM-7': { title: 'Least Functionality', family: 'Configuration Management', description: 'Configure the system to provide only mission-essential capabilities.' },
  'CM-8': { title: 'System Component Inventory', family: 'Configuration Management', description: 'Develop and document an inventory of system components.' },
  'CP-2': { title: 'Contingency Plan', family: 'Contingency Planning', description: 'Develop a contingency plan for the system that addresses essential missions and business functions.' },
  'IA-2': { title: 'Identification and Authentication', family: 'Identification and Authentication', description: 'Uniquely identify and authenticate organizational users.' },
  'IA-5': { title: 'Authenticator Management', family: 'Identification and Authentication', description: 'Manage system authenticators by verifying identity before distributing initial authenticators.' },
  'IA-7': { title: 'Cryptographic Module Authentication', family: 'Identification and Authentication', description: 'Implement mechanisms for authentication to a cryptographic module.' },
  'IA-8': { title: 'Identification and Authentication (Non-Org Users)', family: 'Identification and Authentication', description: 'Uniquely identify and authenticate non-organizational users.' },
  'IA-11': { title: 'Re-authentication', family: 'Identification and Authentication', description: 'Require users to re-authenticate when defined circumstances or situations require.' },
  'RA-5': { title: 'Vulnerability Monitoring and Scanning', family: 'Risk Assessment', description: 'Monitor and scan for vulnerabilities in the system and hosted applications.' },
  'SA-11': { title: 'Developer Testing and Evaluation', family: 'System and Services Acquisition', description: 'Require developers to create and implement a security and privacy assessment plan.' },
  'SA-15': { title: 'Development Process, Standards, and Tools', family: 'System and Services Acquisition', description: 'Require developers to follow a documented development process.' },
  'SA-22': { title: 'Unsupported System Components', family: 'System and Services Acquisition', description: 'Replace system components when support is no longer available.' },
  'SC-4': { title: 'Information in Shared System Resources', family: 'System and Communications Protection', description: 'Prevent unauthorized and unintended information transfer via shared system resources.' },
  'SC-5': { title: 'Denial-of-Service Protection', family: 'System and Communications Protection', description: 'Protect against or limit the effects of denial-of-service attacks.' },
  'SC-7': { title: 'Boundary Protection', family: 'System and Communications Protection', description: 'Monitor and control communications at the external managed interfaces of the system.' },
  'SC-8': { title: 'Transmission Confidentiality and Integrity', family: 'System and Communications Protection', description: 'Protect the confidentiality and integrity of transmitted information.' },
  'SC-12': { title: 'Cryptographic Key Establishment and Management', family: 'System and Communications Protection', description: 'Establish and manage cryptographic keys when cryptography is employed.' },
  'SC-13': { title: 'Cryptographic Protection', family: 'System and Communications Protection', description: 'Determine the cryptographic uses and implement the required cryptography.' },
  'SC-18': { title: 'Mobile Code', family: 'System and Communications Protection', description: 'Define acceptable and unacceptable mobile code and mobile code technologies.' },
  'SC-23': { title: 'Session Authenticity', family: 'System and Communications Protection', description: 'Protect the authenticity of communications sessions.' },
  'SC-28': { title: 'Protection of Information at Rest', family: 'System and Communications Protection', description: 'Protect the confidentiality and integrity of information at rest.' },
  'SI-2': { title: 'Flaw Remediation', family: 'System and Information Integrity', description: 'Identify, report, and correct system flaws in a timely manner.' },
  'SI-3': { title: 'Malicious Code Protection', family: 'System and Information Integrity', description: 'Implement malicious code protection mechanisms at system entry and exit points.' },
  'SI-4': { title: 'System Monitoring', family: 'System and Information Integrity', description: 'Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections.' },
  'SI-10': { title: 'Information Input Validation', family: 'System and Information Integrity', description: 'Check the validity of information inputs to the system.' },
  'SI-11': { title: 'Error Handling', family: 'System and Information Integrity', description: 'Generate error messages that provide information necessary for corrective actions without revealing sensitive information.' },
  'SI-16': { title: 'Memory Protection', family: 'System and Information Integrity', description: 'Implement security safeguards to protect the system memory from unauthorized code execution.' },
};

const CIS_V8_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  '2.1': { title: 'Establish Software Inventory', family: 'CG 2: Inventory and Control of Software Assets', description: 'Establish and maintain a detailed inventory of all licensed software installed on enterprise assets.' },
  '2.2': { title: 'Ensure Authorized Software', family: 'CG 2: Inventory and Control of Software Assets', description: 'Ensure that only authorized software is installed and can execute on enterprise assets.' },
  '2.5': { title: 'Allowlist Authorized Software', family: 'CG 2: Inventory and Control of Software Assets', description: 'Use technical controls to ensure that only authorized software libraries can load into a system process.' },
  '3.1': { title: 'Establish Data Management Process', family: 'CG 3: Data Protection', description: 'Establish and maintain a data management process.' },
  '3.3': { title: 'Configure Data Access Control Lists', family: 'CG 3: Data Protection', description: 'Configure data access control lists based on a user\'s need to know.' },
  '3.10': { title: 'Encrypt Sensitive Data in Transit', family: 'CG 3: Data Protection', description: 'Encrypt sensitive data in transit using cryptographic protocols.' },
  '3.11': { title: 'Encrypt Sensitive Data at Rest', family: 'CG 3: Data Protection', description: 'Encrypt sensitive data at rest on servers, applications, and databases.' },
  '3.12': { title: 'Segment Data Processing and Storage', family: 'CG 3: Data Protection', description: 'Segment data processing and storage based on the sensitivity of the data.' },
  '4.1': { title: 'Establish Secure Configuration Process', family: 'CG 4: Secure Configuration', description: 'Establish and maintain a secure configuration process for enterprise assets and software.' },
  '4.8': { title: 'Uninstall or Disable Unnecessary Services', family: 'CG 4: Secure Configuration', description: 'Uninstall or disable unnecessary services on enterprise assets and software.' },
  '5.3': { title: 'Disable Dormant Accounts', family: 'CG 5: Account Management', description: 'Delete or disable any dormant accounts after a period of inactivity.' },
  '5.4': { title: 'Restrict Administrator Privileges', family: 'CG 5: Account Management', description: 'Restrict administrator privileges to dedicated administrator accounts on enterprise assets.' },
  '6.3': { title: 'Require MFA for Externally-Exposed Applications', family: 'CG 6: Access Control Management', description: 'Require all externally-exposed enterprise or third-party applications to enforce MFA.' },
  '6.4': { title: 'Require MFA for Remote Network Access', family: 'CG 6: Access Control Management', description: 'Require MFA for remote network access.' },
  '6.5': { title: 'Require MFA for Administrative Access', family: 'CG 6: Access Control Management', description: 'Require MFA for all administrative access accounts.' },
  '6.8': { title: 'Define and Maintain Role-Based Access Control', family: 'CG 6: Access Control Management', description: 'Define and maintain role-based access control for each enterprise asset and software.' },
  '7.1': { title: 'Establish Vulnerability Management Process', family: 'CG 7: Continuous Vulnerability Management', description: 'Establish and maintain a documented vulnerability management process for enterprise assets.' },
  '7.4': { title: 'Perform Automated Application Patch Management', family: 'CG 7: Continuous Vulnerability Management', description: 'Perform application updates on enterprise assets through automated patch management.' },
  '8.2': { title: 'Collect Audit Logs', family: 'CG 8: Audit Log Management', description: 'Collect audit logs. Ensure that logging is enabled for all enterprise assets.' },
  '8.5': { title: 'Collect Detailed Audit Logs', family: 'CG 8: Audit Log Management', description: 'Configure detailed audit logging for enterprise assets containing sensitive data.' },
  '10.1': { title: 'Deploy and Maintain Anti-Malware Software', family: 'CG 10: Malware Defenses', description: 'Deploy and maintain anti-malware software on all enterprise assets.' },
  '12.1': { title: 'Ensure Network Infrastructure is Up-to-Date', family: 'CG 12: Network Infrastructure Management', description: 'Ensure network infrastructure is kept up-to-date.' },
  '13.1': { title: 'Centralize Security Event Alerting', family: 'CG 13: Network Monitoring and Defense', description: 'Centralize security event alerting across enterprise assets.' },
  '13.4': { title: 'Perform Traffic Filtering', family: 'CG 13: Network Monitoring and Defense', description: 'Perform traffic filtering between network segments.' },
  '13.6': { title: 'Collect Network Traffic Flow Logs', family: 'CG 13: Network Monitoring and Defense', description: 'Collect network traffic flow logs and/or network traffic to review and alert upon.' },
  '13.8': { title: 'Deploy Network-Based IDS', family: 'CG 13: Network Monitoring and Defense', description: 'Deploy a network-based intrusion detection solution.' },
  '16.1': { title: 'Establish Secure Application Development Process', family: 'CG 16: Application Software Security', description: 'Establish and maintain a secure application development process.' },
  '16.2': { title: 'Establish Process for Accepting and Addressing Vulnerabilities', family: 'CG 16: Application Software Security', description: 'Establish and maintain a process to accept and address software vulnerabilities.' },
  '16.4': { title: 'Establish and Manage Inventory of Third-Party Components', family: 'CG 16: Application Software Security', description: 'Establish and manage an updated inventory of third-party components used in development.' },
  '16.5': { title: 'Use Up-to-Date and Trusted Third-Party Components', family: 'CG 16: Application Software Security', description: 'Use up-to-date and trusted third-party software components.' },
  '16.6': { title: 'Establish and Maintain a Severity Rating System', family: 'CG 16: Application Software Security', description: 'Establish and maintain a severity rating system and process for application vulnerabilities.' },
  '16.7': { title: 'Use Standard Hardening Configuration Templates', family: 'CG 16: Application Software Security', description: 'Use standard, industry-recommended hardening configuration templates for application infrastructure components.' },
  '16.8': { title: 'Separate Production and Non-Production Systems', family: 'CG 16: Application Software Security', description: 'Maintain separate environments for production, development, and testing.' },
  '16.11': { title: 'Leverage Vetted Modules or Services', family: 'CG 16: Application Software Security', description: 'Leverage vetted modules or services for application security components.' },
  '16.12': { title: 'Implement Code-Level Security Checks', family: 'CG 16: Application Software Security', description: 'Apply static and dynamic analysis tools within the application lifecycle.' },
};

const PCI_DSS_V4_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  '1.2.1': { title: 'Network Security Controls Configuration', family: 'Req 1: Network Security Controls', description: 'Configuration standards for NSCs are defined, implemented, and maintained.' },
  '1.3.1': { title: 'Inbound Traffic Restricted', family: 'Req 1: Network Security Controls', description: 'Inbound traffic to the CDE is restricted to only necessary traffic.' },
  '1.3.2': { title: 'Outbound Traffic Restricted', family: 'Req 1: Network Security Controls', description: 'Outbound traffic from the CDE is restricted to only necessary traffic.' },
  '2.2.1': { title: 'Configuration Standards Developed', family: 'Req 2: Secure Configurations', description: 'Configuration standards are developed, implemented, and maintained for all system components.' },
  '2.2.2': { title: 'Vendor Default Accounts Managed', family: 'Req 2: Secure Configurations', description: 'Vendor default accounts are managed.' },
  '3.3.1': { title: 'SAD Not Retained After Authorization', family: 'Req 3: Protect Stored Account Data', description: 'SAD is not retained after authorization.' },
  '3.4.1': { title: 'PAN Masked When Displayed', family: 'Req 3: Protect Stored Account Data', description: 'PAN is masked when displayed so only authorized personnel can see full PAN.' },
  '3.5.1': { title: 'PAN Secured Wherever Stored', family: 'Req 3: Protect Stored Account Data', description: 'PAN is secured wherever it is stored.' },
  '4.2.1': { title: 'Strong Cryptography for Transmission', family: 'Req 4: Protect Data in Transit', description: 'Strong cryptography is used during transmission of PAN over open, public networks.' },
  '4.2.2': { title: 'PAN Secured with Strong Cryptography', family: 'Req 4: Protect Data in Transit', description: 'PAN is secured with strong cryptography whenever sent via end-user messaging technologies.' },
  '5.2.1': { title: 'Anti-Malware Solution Deployed', family: 'Req 5: Protect Against Malware', description: 'An anti-malware solution is deployed on all system components.' },
  '6.2.4': { title: 'Software Engineering Techniques', family: 'Req 6: Develop Secure Systems', description: 'Software engineering techniques or other methods prevent or mitigate common software attacks.' },
  '6.3.1': { title: 'Security Vulnerabilities Identified and Managed', family: 'Req 6: Develop Secure Systems', description: 'Security vulnerabilities are identified and managed.' },
  '6.3.2': { title: 'Software Inventory Maintained', family: 'Req 6: Develop Secure Systems', description: 'An inventory of bespoke and custom software, and third-party software components is maintained.' },
  '6.3.3': { title: 'Security Patches Installed Timely', family: 'Req 6: Develop Secure Systems', description: 'All security patches/updates are installed within defined timeframes.' },
  '6.4.1': { title: 'Public-Facing Web Apps Protected', family: 'Req 6: Develop Secure Systems', description: 'For public-facing web applications, threats and vulnerabilities are addressed on an ongoing basis.' },
  '6.5.6': { title: 'Change Management Procedures', family: 'Req 6: Develop Secure Systems', description: 'Changes to all system components in the production environment are managed.' },
  '7.2.1': { title: 'Access Control Model Defined', family: 'Req 7: Restrict Access', description: 'An access control model is defined and includes granting access based on business needs.' },
  '7.2.2': { title: 'Access Assigned Based on Job Classification', family: 'Req 7: Restrict Access', description: 'Access is assigned to users based on job classification and function.' },
  '7.2.5': { title: 'Access Assigned and Managed Based on Least Privileges', family: 'Req 7: Restrict Access', description: 'All application and system accounts and related access privileges are assigned and managed based on least privilege.' },
  '8.2.1': { title: 'All Users Assigned Unique ID', family: 'Req 8: Identify Users', description: 'All users are assigned a unique ID before access to system components or cardholder data is allowed.' },
  '8.2.2': { title: 'Group Accounts Managed', family: 'Req 8: Identify Users', description: 'Group, shared, or generic accounts are only used when necessary.' },
  '8.2.8': { title: 'User Sessions Inactive Timeout', family: 'Req 8: Identify Users', description: 'If a user session has been idle for more than 15 minutes, the user is required to re-authenticate.' },
  '8.3': { title: 'Strong Authentication for Users and Admins', family: 'Req 8: Identify Users', description: 'Strong authentication for users and administrators is established and managed.' },
  '8.3.1': { title: 'All User Access Authenticated', family: 'Req 8: Identify Users', description: 'All user access to system components for users and administrators is authenticated.' },
  '8.3.2': { title: 'Strong Cryptography for Authentication', family: 'Req 8: Identify Users', description: 'Strong cryptography is used to render all authentication factors unreadable during transmission and storage.' },
  '8.3.4': { title: 'Invalid Authentication Attempts Limited', family: 'Req 8: Identify Users', description: 'Invalid authentication attempts are limited by locking out the user ID after not more than 10 attempts.' },
  '8.3.6': { title: 'Password Complexity Requirements', family: 'Req 8: Identify Users', description: 'If passwords/passphrases are used as authentication factors, they meet minimum complexity requirements.' },
  '8.4.1': { title: 'MFA for Non-Console Admin Access', family: 'Req 8: Identify Users', description: 'MFA is implemented for all non-console access into the CDE for personnel with administrative access.' },
  '8.6.1': { title: 'System/Application Account Management', family: 'Req 8: Identify Users', description: 'If accounts used by systems or applications can be used for interactive login, they are managed.' },
  '10.3.1': { title: 'Audit Trails Capture User Activities', family: 'Req 10: Log and Monitor', description: 'Audit trails are implemented to link all access to system components to each individual user.' },
  '10.3.3': { title: 'Audit Trails Capture Admin Activities', family: 'Req 10: Log and Monitor', description: 'Audit trails capture all actions taken by any individual with administrative access.' },
  '11.3.1': { title: 'Internal Vulnerability Scans', family: 'Req 11: Test Security', description: 'Internal vulnerability scans are performed at least once every three months.' },
  '11.5.1': { title: 'Intrusion-Detection Techniques', family: 'Req 11: Test Security', description: 'Intrusion-detection and/or intrusion-prevention techniques are used to detect and/or prevent intrusions into the network.' },
};

const ISO_27001_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  'A.5.12': { title: 'Classification of Information', family: 'Organizational Controls', description: 'Information shall be classified according to information security needs of the organization.' },
  'A.5.14': { title: 'Information Transfer', family: 'Organizational Controls', description: 'Information transfer rules, procedures, or agreements shall be in place for all types of transfer.' },
  'A.5.15': { title: 'Access Control', family: 'Organizational Controls', description: 'Rules to control physical and logical access to information shall be established.' },
  'A.5.17': { title: 'Authentication Information', family: 'Organizational Controls', description: 'Allocation and management of authentication information shall be controlled.' },
  'A.5.18': { title: 'Access Rights', family: 'Organizational Controls', description: 'Access rights to information and other associated assets shall be provisioned, reviewed, modified and removed.' },
  'A.5.19': { title: 'Information Security in Supplier Relationships', family: 'Organizational Controls', description: 'Processes and procedures shall be defined to manage information security risks associated with suppliers.' },
  'A.8.2': { title: 'Privileged Access Rights', family: 'Technological Controls', description: 'The allocation and use of privileged access rights shall be restricted and managed.' },
  'A.8.3': { title: 'Information Access Restriction', family: 'Technological Controls', description: 'Access to information and other associated assets shall be restricted in accordance with access control policy.' },
  'A.8.4': { title: 'Access to Source Code', family: 'Technological Controls', description: 'Read and write access to source code, development tools and software libraries shall be appropriately managed.' },
  'A.8.5': { title: 'Secure Authentication', family: 'Technological Controls', description: 'Secure authentication technologies and procedures shall be established and implemented.' },
  'A.8.6': { title: 'Capacity Management', family: 'Technological Controls', description: 'The use of resources shall be monitored and adjusted in line with current and expected capacity requirements.' },
  'A.8.7': { title: 'Protection Against Malware', family: 'Technological Controls', description: 'Protection against malware shall be implemented and supported by appropriate user awareness.' },
  'A.8.8': { title: 'Management of Technical Vulnerabilities', family: 'Technological Controls', description: 'Information about technical vulnerabilities of information systems in use shall be obtained.' },
  'A.8.9': { title: 'Configuration Management', family: 'Technological Controls', description: 'Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.' },
  'A.8.10': { title: 'Information Deletion', family: 'Technological Controls', description: 'Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.' },
  'A.8.11': { title: 'Data Masking', family: 'Technological Controls', description: 'Data masking shall be used in accordance with the access control policy and other related policies.' },
  'A.8.15': { title: 'Logging', family: 'Technological Controls', description: 'Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.' },
  'A.8.19': { title: 'Installation of Software on Operational Systems', family: 'Technological Controls', description: 'Procedures and measures shall be implemented to securely manage software installation on operational systems.' },
  'A.8.20': { title: 'Networks Security', family: 'Technological Controls', description: 'Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.' },
  'A.8.21': { title: 'Security of Network Services', family: 'Technological Controls', description: 'Security mechanisms, service levels, and service requirements of network services shall be identified, implemented and monitored.' },
  'A.8.24': { title: 'Use of Cryptography', family: 'Technological Controls', description: 'Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.' },
  'A.8.26': { title: 'Application Security Requirements', family: 'Technological Controls', description: 'Information security requirements shall be identified, specified and approved when developing or acquiring applications.' },
  'A.8.28': { title: 'Secure Coding', family: 'Technological Controls', description: 'Secure coding principles shall be applied to software development.' },
  'A.8.29': { title: 'Security Testing in Development and Acceptance', family: 'Technological Controls', description: 'Security testing processes shall be defined and implemented in the development lifecycle.' },
};

const HIPAA_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  '164.308(a)(1)(ii)(B)': { title: 'Risk Management', family: 'Administrative Safeguards', description: 'Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level.' },
  '164.308(a)(5)(ii)(B)': { title: 'Protection from Malicious Software', family: 'Administrative Safeguards', description: 'Procedures for guarding against, detecting, and reporting malicious software.' },
  '164.308(a)(7)(i)': { title: 'Contingency Plan', family: 'Administrative Safeguards', description: 'Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI.' },
  '164.310(d)(1)': { title: 'Device and Media Controls', family: 'Physical Safeguards', description: 'Implement policies and procedures that govern the receipt and removal of hardware and electronic media.' },
  '164.312(a)(1)': { title: 'Access Control', family: 'Technical Safeguards', description: 'Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons.' },
  '164.312(a)(2)(i)': { title: 'Unique User Identification', family: 'Technical Safeguards', description: 'Assign a unique name and/or number for identifying and tracking user identity.' },
  '164.312(a)(2)(iii)': { title: 'Automatic Logoff', family: 'Technical Safeguards', description: 'Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.' },
  '164.312(a)(2)(iv)': { title: 'Encryption and Decryption', family: 'Technical Safeguards', description: 'Implement a mechanism to encrypt and decrypt electronic protected health information.' },
  '164.312(b)': { title: 'Audit Controls', family: 'Technical Safeguards', description: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.' },
  '164.312(d)': { title: 'Person or Entity Authentication', family: 'Technical Safeguards', description: 'Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.' },
  '164.312(e)(1)': { title: 'Transmission Security', family: 'Technical Safeguards', description: 'Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.' },
  '164.312(e)(2)(ii)': { title: 'Encryption', family: 'Technical Safeguards', description: 'Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate.' },
};

const SOC2_CONTROLS: Record<string, { title: string; family: string; description: string }> = {
  'CC6.1': { title: 'Logical and Physical Access Controls', family: 'Common Criteria', description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets.' },
  'CC6.2': { title: 'User Authentication', family: 'Common Criteria', description: 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.' },
  'CC6.3': { title: 'Role-Based Access', family: 'Common Criteria', description: 'The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles.' },
  'CC6.5': { title: 'Logical Access Restrictions', family: 'Common Criteria', description: 'The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished.' },
  'CC6.6': { title: 'Security Measures Against Threats', family: 'Common Criteria', description: 'The entity implements logical access security measures to protect against threats from sources outside its system boundaries.' },
  'CC6.7': { title: 'Data Transmission Protection', family: 'Common Criteria', description: 'The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.' },
  'CC7.1': { title: 'Detection and Monitoring', family: 'Common Criteria', description: 'To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.' },
  'CC7.2': { title: 'Anomaly Monitoring', family: 'Common Criteria', description: 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors.' },
  'CC8.1': { title: 'Change Management', family: 'Common Criteria', description: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.' },
  'A1.1': { title: 'Capacity Planning', family: 'Availability', description: 'The entity maintains, monitors, and evaluates current processing capacity and use of system components.' },
  'A1.2': { title: 'Recovery Mechanisms', family: 'Availability', description: 'The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure.' },
};

// ─── Lookup Helper ─────────────────────────────────────────────────────────────

function getControlDetails(frameworkId: FrameworkId, controlId: string): FrameworkControl {
  const controlDbs: Record<FrameworkId, Record<string, { title: string; family: string; description: string }>> = {
    nist_800_53: NIST_800_53_CONTROLS,
    cis_v8: CIS_V8_CONTROLS,
    pci_dss_v4: PCI_DSS_V4_CONTROLS,
    iso_27001: ISO_27001_CONTROLS,
    hipaa: HIPAA_CONTROLS,
    soc2: SOC2_CONTROLS,
  };

  const db = controlDbs[frameworkId];
  const entry = db?.[controlId];
  if (entry) {
    return { id: controlId, title: entry.title, family: entry.family, description: entry.description };
  }
  // Fallback for unmapped controls
  return { id: controlId, title: controlId, family: 'Unknown', description: `Control ${controlId}` };
}

// ─── Category-Based Inference ──────────────────────────────────────────────────
// For DI scan findings that don't have explicit CWEs, infer from category/title.

const CATEGORY_TO_CWE: Record<string, string> = {
  'sql injection': 'CWE-89',
  'sqli': 'CWE-89',
  'cross-site scripting': 'CWE-79',
  'xss': 'CWE-79',
  'reflected xss': 'CWE-79',
  'stored xss': 'CWE-79',
  'dom xss': 'CWE-79',
  'command injection': 'CWE-78',
  'os command injection': 'CWE-78',
  'code injection': 'CWE-94',
  'remote code execution': 'CWE-94',
  'rce': 'CWE-94',
  'xml external entity': 'CWE-611',
  'xxe': 'CWE-611',
  'server-side request forgery': 'CWE-918',
  'ssrf': 'CWE-918',
  'cross-site request forgery': 'CWE-352',
  'csrf': 'CWE-352',
  'path traversal': 'CWE-22',
  'directory traversal': 'CWE-22',
  'local file inclusion': 'CWE-98',
  'remote file inclusion': 'CWE-98',
  'file inclusion': 'CWE-98',
  'file upload': 'CWE-434',
  'unrestricted file upload': 'CWE-434',
  'authentication bypass': 'CWE-287',
  'broken authentication': 'CWE-287',
  'missing authentication': 'CWE-306',
  'session fixation': 'CWE-384',
  'session management': 'CWE-613',
  'insecure deserialization': 'CWE-502',
  'deserialization': 'CWE-502',
  'information disclosure': 'CWE-200',
  'information exposure': 'CWE-200',
  'sensitive data exposure': 'CWE-200',
  'error handling': 'CWE-209',
  'verbose error': 'CWE-209',
  'stack trace': 'CWE-209',
  'hardcoded credentials': 'CWE-798',
  'hardcoded password': 'CWE-798',
  'default credentials': 'CWE-798',
  'weak password': 'CWE-522',
  'credential exposure': 'CWE-522',
  'brute force': 'CWE-307',
  'rate limiting': 'CWE-307',
  'privilege escalation': 'CWE-269',
  'idor': 'CWE-639',
  'insecure direct object reference': 'CWE-639',
  'missing authorization': 'CWE-862',
  'broken access control': 'CWE-862',
  'open redirect': 'CWE-601',
  'url redirect': 'CWE-601',
  'clickjacking': 'CWE-1021',
  'missing security headers': 'CWE-693',
  'security misconfiguration': 'CWE-16',
  'misconfiguration': 'CWE-16',
  'outdated software': 'CWE-1104',
  'outdated component': 'CWE-1104',
  'end of life': 'CWE-1104',
  'known vulnerability': 'CWE-937',
  'vulnerable component': 'CWE-937',
  'buffer overflow': 'CWE-119',
  'denial of service': 'CWE-400',
  'dos': 'CWE-400',
  'ldap injection': 'CWE-90',
  'xml injection': 'CWE-91',
  'expression language injection': 'CWE-917',
  'weak cryptography': 'CWE-327',
  'weak encryption': 'CWE-327',
  'weak cipher': 'CWE-326',
  'ssl/tls': 'CWE-295',
  'certificate': 'CWE-295',
  'missing encryption': 'CWE-311',
  'unencrypted': 'CWE-311',
  'plaintext': 'CWE-311',
  'cookie security': 'CWE-614',
  'insecure cookie': 'CWE-1275',
  'log injection': 'CWE-532',
  'race condition': 'CWE-362',
};

/**
 * Infer CWE from a finding's category and title.
 * Returns the best-matching CWE or undefined if no match.
 */
export function inferCweFromFinding(category: string, title: string): string | undefined {
  const searchText = `${category} ${title}`.toLowerCase();

  // Try exact category match first
  const catLower = category.toLowerCase().trim();
  if (CATEGORY_TO_CWE[catLower]) return CATEGORY_TO_CWE[catLower];

  // Try substring matching on combined text
  for (const [pattern, cwe] of Object.entries(CATEGORY_TO_CWE)) {
    if (searchText.includes(pattern)) return cwe;
  }

  return undefined;
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Map a single vulnerability to compliance framework controls.
 */
export function mapVulnToFrameworks(
  vuln: {
    id: string;
    title: string;
    cwe?: string;
    cveIds?: string[];
    category?: string;
    severity: string;
  },
  selectedFrameworks: FrameworkId[]
): VulnFrameworkResult {
  // Resolve CWE — direct or inferred
  let cwe = vuln.cwe;
  if (!cwe && vuln.category) {
    cwe = inferCweFromFinding(vuln.category, vuln.title);
  }
  if (!cwe) {
    cwe = inferCweFromFinding(vuln.title, '');
  }

  const mappings: FrameworkMapping[] = [];

  if (cwe) {
    // Normalize CWE format
    const normalizedCwe = cwe.startsWith('CWE-') ? cwe : `CWE-${cwe}`;
    const controlMap = CWE_CONTROL_MAP[normalizedCwe];

    if (controlMap) {
      for (const fwId of selectedFrameworks) {
        const controlIds = controlMap[fwId] || [];
        const controls = controlIds.map(id => getControlDetails(fwId, id));
        mappings.push({
          frameworkId: fwId,
          frameworkName: FRAMEWORK_METADATA[fwId].name,
          controls,
        });
      }
    }
  }

  // If no CWE match, provide generic mappings based on severity
  if (mappings.length === 0 || mappings.every(m => m.controls.length === 0)) {
    for (const fwId of selectedFrameworks) {
      if (!mappings.find(m => m.frameworkId === fwId)) {
        // Generic high-level controls for unmapped vulns
        const genericControls = getGenericControls(fwId, vuln.severity);
        mappings.push({
          frameworkId: fwId,
          frameworkName: FRAMEWORK_METADATA[fwId].name,
          controls: genericControls,
        });
      }
    }
  }

  return {
    vulnId: vuln.id,
    vulnTitle: vuln.title,
    cwe,
    cveIds: vuln.cveIds,
    category: vuln.category,
    severity: vuln.severity,
    mappings,
  };
}

/**
 * Generate a full compliance report for a set of vulnerabilities.
 */
export function generateComplianceReport(
  vulns: Array<{
    id: string;
    title: string;
    cwe?: string;
    cveIds?: string[];
    category?: string;
    severity: string;
  }>,
  selectedFrameworks: FrameworkId[]
): ComplianceReport {
  const vulnMappings = vulns.map(v => mapVulnToFrameworks(v, selectedFrameworks));

  // Build framework summaries
  const frameworkSummaries: FrameworkSummary[] = selectedFrameworks.map(fwId => {
    const controlMap = new Map<string, { control: FrameworkControl; vulnIds: Set<string>; maxSeverity: string }>();

    for (const vm of vulnMappings) {
      const fwMapping = vm.mappings.find(m => m.frameworkId === fwId);
      if (!fwMapping) continue;

      for (const ctrl of fwMapping.controls) {
        const existing = controlMap.get(ctrl.id);
        if (existing) {
          existing.vulnIds.add(vm.vulnId);
          existing.maxSeverity = higherSeverity(existing.maxSeverity, vm.severity);
        } else {
          controlMap.set(ctrl.id, {
            control: ctrl,
            vulnIds: new Set([vm.vulnId]),
            maxSeverity: vm.severity,
          });
        }
      }
    }

    const controlDetails = Array.from(controlMap.values())
      .map(({ control, vulnIds, maxSeverity }) => ({
        control,
        vulnCount: vulnIds.size,
        maxSeverity,
        vulnIds: Array.from(vulnIds),
      }))
      .sort((a, b) => severityRank(b.maxSeverity) - severityRank(a.maxSeverity));

    const controlsByFamily: Record<string, number> = {};
    for (const cd of controlDetails) {
      controlsByFamily[cd.control.family] = (controlsByFamily[cd.control.family] || 0) + 1;
    }

    return {
      frameworkId: fwId,
      frameworkName: FRAMEWORK_METADATA[fwId].name,
      totalControlsAffected: controlDetails.length,
      controlsByFamily,
      controlDetails,
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    selectedFrameworks,
    totalVulns: vulns.length,
    frameworkSummaries,
    vulnMappings,
  };
}

/**
 * Get all available frameworks with metadata.
 */
export function getAvailableFrameworks(): Array<{ id: FrameworkId; name: string; version: string; description: string }> {
  return Object.entries(FRAMEWORK_METADATA).map(([id, meta]) => ({
    id: id as FrameworkId,
    ...meta,
  }));
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function severityRank(severity: string): number {
  const s = severity.toLowerCase();
  if (s === 'critical') return 4;
  if (s === 'high') return 3;
  if (s === 'medium') return 2;
  if (s === 'low') return 1;
  if (s === 'info' || s === 'informational') return 0;
  // Numeric severity (0-10 scale from DI scans)
  const n = parseFloat(severity);
  if (!isNaN(n)) {
    if (n >= 9) return 4;
    if (n >= 7) return 3;
    if (n >= 4) return 2;
    if (n >= 1) return 1;
    return 0;
  }
  return 0;
}

function higherSeverity(a: string, b: string): string {
  return severityRank(a) >= severityRank(b) ? a : b;
}

function getGenericControls(fwId: FrameworkId, severity: string): FrameworkControl[] {
  // Provide baseline controls for vulns that don't map to a specific CWE
  const genericMap: Record<FrameworkId, string[]> = {
    nist_800_53: ['RA-5', 'SI-2', 'CM-6'],
    cis_v8: ['7.1', '7.4', '4.1'],
    pci_dss_v4: ['6.3.1', '11.3.1'],
    iso_27001: ['A.8.8', 'A.8.9'],
    hipaa: ['164.312(a)(1)', '164.308(a)(1)(ii)(B)'],
    soc2: ['CC6.1', 'CC7.1'],
  };

  const controlIds = genericMap[fwId] || [];
  return controlIds.map(id => getControlDetails(fwId, id));
}

// ─── Exports for Testing ───────────────────────────────────────────────────────

export const _testing = {
  CWE_CONTROL_MAP,
  CATEGORY_TO_CWE,
  NIST_800_53_CONTROLS,
  CIS_V8_CONTROLS,
  PCI_DSS_V4_CONTROLS,
  ISO_27001_CONTROLS,
  HIPAA_CONTROLS,
  SOC2_CONTROLS,
  severityRank,
  higherSeverity,
  getGenericControls,
  getControlDetails,
};
