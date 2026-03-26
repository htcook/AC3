/**
 * ScanForge Core Types
 *
 * Defines the scan lifecycle, result structures, template schema,
 * and protocol scanner interfaces used throughout the ScanForge engine.
 */

// ─── Scan Lifecycle ────────────────────────────────────────────────────────

export type ScanStatus =
  | "queued"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "cancelled";

export type ScanType =
  | "full"           // All scanners, all protocols
  | "quick"          // Top-20 checks only
  | "web"            // HTTP/HTTPS DAST only
  | "network"        // Port scan + protocol scanners
  | "compliance"     // SCAP/STIG/CIS checks
  | "custom"         // User-selected templates
  | "recon"          // Passive recon only
  | "protocol";      // Single protocol deep scan

export type ScanPriority = "critical" | "high" | "medium" | "low";

export interface ScanTarget {
  /** Primary target (domain, IP, CIDR, URL) */
  value: string;
  /** Target type for routing to correct scanner */
  type: "domain" | "ip" | "cidr" | "url";
  /** Discovered ports from recon phase */
  ports?: number[];
  /** Discovered services mapped to ports */
  services?: Record<number, string>;
  /** Asset criticality for risk scoring */
  criticality?: "critical" | "high" | "medium" | "low";
}

export interface ScanRequest {
  /** Unique scan ID (UUID) */
  id: string;
  /** Engagement ID for audit trail */
  engagementId?: number;
  /** Scan type determines which scanners run */
  type: ScanType;
  /** Priority affects queue ordering */
  priority: ScanPriority;
  /** One or more targets */
  targets: ScanTarget[];
  /** Specific template IDs to run (for custom type) */
  templateIds?: string[];
  /** Specific protocol scanners to run */
  protocols?: string[];
  /** Scanner configuration overrides */
  config?: ScanConfig;
  /** TI enrichment options */
  intelligence?: IntelligenceConfig;
  /** Callback URL for results webhook */
  callbackUrl?: string;
  /** Requester info */
  requestedBy?: string;
  /** Timestamp */
  createdAt: number;
}

export interface ScanConfig {
  /** Max concurrent scanners per target */
  maxConcurrency?: number;
  /** Global timeout in seconds */
  timeoutSeconds?: number;
  /** Per-scanner timeout in seconds */
  scannerTimeoutSeconds?: number;
  /** Rate limit (requests per second) */
  rateLimit?: number;
  /** Follow redirects */
  followRedirects?: boolean;
  /** Max depth for web crawling */
  maxCrawlDepth?: number;
  /** User-Agent string */
  userAgent?: string;
  /** Authentication credentials for DAST */
  auth?: ScanAuth;
  /** Scan mode: passive (no exploitation), active (safe checks), aggressive (full) */
  mode?: "passive" | "active" | "aggressive";
  /** Exclude patterns (regex) */
  excludePatterns?: string[];
}

export interface ScanAuth {
  type: "basic" | "bearer" | "cookie" | "form" | "oauth2";
  credentials: Record<string, string>;
}

export interface IntelligenceConfig {
  /** Use KEV catalog to prioritize known exploited vulns */
  useKEV?: boolean;
  /** Use EPSS scores for probability-based prioritization */
  useEPSS?: boolean;
  /** Use threat actor profiles to select relevant templates */
  useThreatActors?: boolean;
  /** Industry vertical for targeted scanning */
  industry?: string;
  /** Target industry (alias for industry, used by TI engine) */
  targetIndustry?: string;
  /** Specific threat actor IDs to emulate */
  threatActorIds?: string[];
  /** Use DFIR artifacts for detection */
  useDFIR?: boolean;
}

// ─── Scan Results ──────────────────────────────────────────────────────────

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanFinding {
  /** Unique finding ID */
  id: string;
  /** Template or scanner that produced this finding */
  source: string;
  /** Finding title */
  title: string;
  /** Detailed description */
  description: string;
  /** Severity level */
  severity: FindingSeverity;
  /** Confidence level (0-100) */
  confidence: number;
  /** Affected target */
  target: string;
  /** Affected port/service */
  port?: number;
  /** Protocol */
  protocol?: string;
  /** CVE IDs if applicable */
  cves?: string[];
  /** CWE IDs */
  cwes?: string[];
  /** MITRE ATT&CK technique IDs */
  techniqueIds?: string[];
  /** Evidence/proof */
  evidence: FindingEvidence;
  /** Remediation guidance */
  remediation?: string;
  /** References (URLs) */
  references?: string[];
  /** Risk score (composite) */
  riskScore?: RiskScore;
  /** Timestamp */
  foundAt: number;
}

export interface FindingEvidence {
  /** Raw request that triggered the finding */
  request?: string;
  /** Raw response that confirmed the finding */
  response?: string;
  /** Matched pattern or signature */
  matchedPattern?: string;
  /** Screenshot URL if applicable */
  screenshotUrl?: string;
  /** Additional structured data */
  data?: Record<string, any>;
}

export interface RiskScore {
  /** Composite score (0-100) */
  composite: number;
  /** CVSS base score */
  cvss?: number;
  /** EPSS probability (0-1) */
  epss?: number;
  /** EPSS percentile (0-1) */
  epssPercentile?: number;
  /** Is in CISA KEV catalog */
  kevListed?: boolean;
  /** KEV due date */
  kevDueDate?: string;
  /** Known ransomware campaign use */
  ransomwareUse?: boolean;
  /** Threat actor names that exploit this */
  threatActorRelevance?: string[];
  /** Asset criticality multiplier */
  assetCriticality?: number;
  /** Has DFIR precedent */
  dfirPrecedent?: boolean;
  /** DFIR artifact categories matched */
  dfirCategories?: string[];
}

// ─── Scan Job (Queue Item) ─────────────────────────────────────────────────

export interface ScanJob {
  /** Scan request */
  request: ScanRequest;
  /** Current status */
  status: ScanStatus;
  /** Progress (0-100) */
  progress: number;
  /** Scanner currently running */
  currentScanner?: string;
  /** Findings collected so far */
  findings: ScanFinding[];
  /** Scanner results log */
  scannerResults: ScannerResult[];
  /** Start time */
  startedAt?: number;
  /** End time */
  completedAt?: number;
  /** Error message if failed */
  error?: string;
  /** Phase tracking */
  phase?: ScanPhase;
}

export type ScanPhase =
  | "recon"
  | "enumeration"
  | "detection"
  | "verification"
  | "reporting";

export interface ScannerResult {
  /** Scanner name */
  scanner: string;
  /** Status */
  status: "completed" | "failed" | "timeout" | "skipped";
  /** Duration in ms */
  durationMs: number;
  /** Number of findings */
  findingCount: number;
  /** Error if failed */
  error?: string;
}

// ─── Template Schema ───────────────────────────────────────────────────────

export interface ScanTemplate {
  /** Template ID (e.g., "http-missing-hsts") */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description */
  description: string;
  /** Author */
  author: string;
  /** Severity if finding matches */
  severity: FindingSeverity;
  /** Tags for categorization */
  tags: string[];
  /** Protocol this template targets */
  protocol: string;
  /** Matchers to detect the vulnerability */
  matchers: TemplateMatcher[];
  /** Request definition */
  request?: TemplateRequest;
  /** CVE/CWE references */
  references?: {
    cves?: string[];
    cwes?: string[];
    urls?: string[];
  };
  /** Remediation guidance */
  remediation?: string;
  /** MITRE ATT&CK mapping */
  attack?: {
    techniqueIds?: string[];
    tactics?: string[];
  };
  /** TI enrichment metadata */
  intelligence?: {
    /** KEV-related */
    kevRelated?: boolean;
    /** Threat actors known to exploit this */
    threatActors?: string[];
    /** DFIR artifact this detects */
    dfirArtifact?: string;
    /** Industries commonly affected */
    industries?: string[];
    /** TI feeds to check */
    feeds?: string[];
    /** DFIR relevance description */
    dfirRelevance?: string;
  };
}

export interface TemplateRequest {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  /** Raw TCP/UDP payload (hex) */
  rawPayload?: string;
  /** Follow redirects */
  followRedirects?: boolean;
  /** Max redirects */
  maxRedirects?: number;
}

export type MatcherType =
  | "status"     // HTTP status code
  | "header"     // HTTP header value
  | "body"       // Response body content
  | "regex"      // Regex match on response
  | "word"       // Word match on response
  | "binary"     // Binary pattern match
  | "dsl"        // Dynamic expression (e.g., "status_code == 200 && contains(body, 'admin')")
  | "version"    // Version comparison
  | "time"       // Response time threshold
  | "size";      // Response size threshold

export type MatcherCondition = "and" | "or";

export interface TemplateMatcher {
  type: MatcherType;
  /** Condition for combining with other matchers */
  condition?: MatcherCondition;
  /** Values to match against */
  values: string[];
  /** Negate the match */
  negative?: boolean;
  /** Part of response to match (header, body, all) */
  part?: "header" | "body" | "all" | "raw";
}

// ─── Protocol Scanner Interface ────────────────────────────────────────────

export interface ProtocolScanner {
  /** Scanner name */
  name: string;
  /** Protocol this scanner handles */
  protocol: string;
  /** Default port(s) */
  defaultPorts: number[];
  /** Execute the scan */
  scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]>;
  /** Check if the service is running on the target */
  probe(host: string, port: number): Promise<boolean>;
}

// ─── Event Types (WebSocket) ───────────────────────────────────────────────

export type ScanEvent =
  | { type: "scan:queued"; scanId: string; position: number }
  | { type: "scan:started"; scanId: string; phase: ScanPhase }
  | { type: "scan:progress"; scanId: string; progress: number; scanner: string }
  | { type: "scan:finding"; scanId: string; finding: ScanFinding }
  | { type: "scan:scanner_complete"; scanId: string; result: ScannerResult }
  | { type: "scan:phase_change"; scanId: string; phase: ScanPhase }
  | { type: "scan:completed"; scanId: string; summary: ScanSummary }
  | { type: "scan:failed"; scanId: string; error: string }
  | { type: "scan:cancelled"; scanId: string };

export interface ScanSummary {
  scanId: string;
  totalFindings: number;
  bySeverity: Record<FindingSeverity, number>;
  scannersRun: number;
  scannersCompleted: number;
  scannersFailed: number;
  durationMs: number;
  topFindings: ScanFinding[];
}
