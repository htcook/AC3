/**
 * Shared types for all commercial scanner connectors.
 */

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

export type ComplianceFramework =
  | "fedramp_high"
  | "fedramp_moderate"
  | "nist_800_53"
  | "nist_800_171"
  | "cmmc_l2"
  | "cmmc_l3"
  | "dod_stig"
  | "dod_il4"
  | "dod_il5"
  | "pci_dss"
  | "hipaa"
  | "sox";

export interface CommercialScannerConfig {
  /** Unique connector instance ID */
  id: string;
  /** Which scanner platform */
  platform: string;
  /** Display name for this instance */
  name: string;
  /** Base URL for the scanner API */
  baseUrl: string;
  /** Authentication credentials (varies by platform) */
  credentials: Record<string, string>;
  /** Optional: specific scan policies or profiles to use */
  scanPolicy?: string;
  /** Optional: rate limiting (requests per minute) */
  rateLimit?: number;
  /** Optional: proxy configuration */
  proxy?: { host: string; port: number; auth?: { username: string; password: string } };
  /** Whether to verify TLS certificates (disable for self-signed) */
  verifySsl?: boolean;
}

export interface NormalizedFinding {
  /** Unique finding ID from the scanner */
  externalId: string;
  /** Scanner platform that produced this finding */
  source: string;
  /** Finding title */
  title: string;
  /** Detailed description */
  description: string;
  /** Severity level normalized to AC3 scale */
  severity: SeverityLevel;
  /** CVSS score (0-10) if available */
  cvssScore?: number;
  /** CVSS vector string */
  cvssVector?: string;
  /** CVE IDs associated with this finding */
  cveIds: string[];
  /** CWE IDs */
  cweIds: string[];
  /** Affected asset (IP, URL, hostname, etc.) */
  affectedAsset: string;
  /** Affected port if applicable */
  port?: number;
  /** Protocol */
  protocol?: string;
  /** Service/software affected */
  service?: string;
  /** Remediation guidance */
  remediation?: string;
  /** Evidence/proof of vulnerability */
  evidence?: string;
  /** Plugin/check ID from the scanner */
  pluginId?: string;
  /** Compliance frameworks this finding maps to */
  complianceFrameworks: ComplianceFramework[];
  /** NIST 800-53 control families affected */
  nistControls?: string[];
  /** First discovered timestamp (UTC ms) */
  firstSeen: number;
  /** Last seen timestamp (UTC ms) */
  lastSeen: number;
  /** Whether the finding has been verified/confirmed */
  verified: boolean;
  /** Exploit availability */
  exploitAvailable?: boolean;
  /** Raw data from the scanner (for reference) */
  rawData?: Record<string, unknown>;
}

export interface ScanResult {
  /** Scanner platform */
  platform: string;
  /** Scan ID from the platform */
  scanId: string;
  /** Scan status */
  status: ScanStatus;
  /** When the scan started (UTC ms) */
  startedAt: number;
  /** When the scan completed (UTC ms) */
  completedAt?: number;
  /** Total findings count */
  totalFindings: number;
  /** Findings by severity */
  findingsBySeverity: Record<SeverityLevel, number>;
  /** Normalized findings */
  findings: NormalizedFinding[];
  /** Scan metadata */
  metadata?: Record<string, unknown>;
}

export interface ConnectorHealth {
  /** Whether the connector is reachable */
  reachable: boolean;
  /** Whether credentials are valid */
  authenticated: boolean;
  /** API version reported by the scanner */
  apiVersion?: string;
  /** License status if available */
  licenseStatus?: string;
  /** Response latency in ms */
  latencyMs: number;
  /** Error message if unhealthy */
  error?: string;
  /** Last successful check (UTC ms) */
  lastChecked: number;
}

export interface ScanTarget {
  /** Target type */
  type: "ip" | "cidr" | "domain" | "url" | "hostname" | "repository" | "container_image";
  /** Target value */
  value: string;
  /** Optional label */
  label?: string;
}

/**
 * Base interface all commercial scanner connectors must implement.
 */
export interface ICommercialScanner {
  /** Platform identifier */
  readonly platform: string;
  /** Test connectivity and credentials */
  testConnection(): Promise<ConnectorHealth>;
  /** Launch a scan against targets */
  launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }>;
  /** Get scan status */
  getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }>;
  /** Fetch and normalize scan results */
  getResults(scanId: string): Promise<ScanResult>;
  /** List available scan policies/profiles */
  listPolicies?(): Promise<Array<{ id: string; name: string; description?: string }>>;
  /** List assets/targets registered in the platform */
  listAssets?(): Promise<Array<{ id: string; name: string; type: string; lastScan?: number }>>;
  /** Import findings from a specific time range */
  importFindings?(since: number, until?: number): Promise<NormalizedFinding[]>;
}
