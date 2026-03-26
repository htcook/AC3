/**
 * ScanForge Core Types
 *
 * Defines the scan lifecycle, result structures, template schema,
 * and protocol scanner interfaces used throughout the ScanForge engine.
 *
 * Expanded to support:
 *   - Cloud infrastructure (AWS/Azure/GCP)
 *   - IoT devices (MQTT, CoAP, UPnP, Zigbee, BLE)
 *   - ICS/SCADA/OT (Modbus, DNP3, BACnet, EtherNet/IP, OPC UA)
 *   - Container/Kubernetes environments
 *   - Hybrid multi-environment scanning
 *   - LLM-powered context awareness
 *   - Federal compliance evidence (NIST 800-115, FedRAMP, DISA STIG)
 */

// ─── Asset Classification ─────────────────────────────────────────────────

export type AssetEnvironment =
  | "traditional"     // Standard IT infrastructure
  | "cloud"           // AWS/Azure/GCP workloads
  | "iot"             // IoT devices and gateways
  | "ics_ot"          // ICS/SCADA/OT systems
  | "container"       // Docker/Kubernetes
  | "hybrid"          // Multi-environment
  | "unknown";

export type CloudProvider = "aws" | "azure" | "gcp" | "digitalocean" | "unknown";

export interface AssetClassification {
  /** Primary environment type */
  environment: AssetEnvironment;
  /** Cloud provider if applicable */
  cloudProvider?: CloudProvider;
  /** Confidence in classification (0-100) */
  confidence: number;
  /** LLM reasoning for classification */
  reasoning?: string;
  /** Detected technologies/frameworks */
  technologies?: string[];
  /** Industry vertical inference */
  inferredIndustry?: string;
  /** Asset criticality based on context */
  inferredCriticality?: "critical" | "high" | "medium" | "low";
  /** Recommended scan profiles */
  recommendedProfiles?: string[];
  /** Detected compliance frameworks applicable */
  applicableCompliance?: ComplianceFramework[];
}

export type ComplianceFramework =
  | "nist_800_115"    // NIST SP 800-115 Technical Guide to Information Security Testing
  | "nist_800_53"     // NIST SP 800-53 Security and Privacy Controls
  | "fedramp"         // FedRAMP Security Assessment Framework
  | "disa_stig"       // DISA Security Technical Implementation Guide
  | "pci_dss"         // PCI Data Security Standard
  | "hipaa"           // HIPAA Security Rule
  | "cis_benchmark"   // CIS Benchmarks
  | "iec_62443"       // IEC 62443 Industrial Cybersecurity
  | "nerc_cip"        // NERC CIP for power grid
  | "nist_csf";       // NIST Cybersecurity Framework

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
  | "protocol"       // Single protocol deep scan
  | "cloud"          // Cloud infrastructure assessment
  | "iot"            // IoT device scanning
  | "ics_ot"         // ICS/SCADA/OT assessment
  | "container"      // Container/K8s scanning
  | "hybrid";        // Multi-environment comprehensive

export type ScanPriority = "critical" | "high" | "medium" | "low";

export interface ScanTarget {
  /** Primary target (domain, IP, CIDR, URL, cloud ARN, device ID) */
  value: string;
  /** Target type for routing to correct scanner */
  type: "domain" | "ip" | "cidr" | "url" | "cloud_resource" | "iot_device" | "ics_endpoint" | "container";
  /** Discovered ports from recon phase */
  ports?: number[];
  /** Discovered services mapped to ports */
  services?: Record<number, string>;
  /** Asset criticality for risk scoring */
  criticality?: "critical" | "high" | "medium" | "low";
  /** Asset classification from context engine */
  classification?: AssetClassification;
  /** Cloud-specific metadata */
  cloudMeta?: CloudTargetMeta;
  /** IoT-specific metadata */
  iotMeta?: IoTTargetMeta;
  /** ICS/OT-specific metadata */
  icsMeta?: ICSTargetMeta;
  /** Container-specific metadata */
  containerMeta?: ContainerTargetMeta;
}

export interface CloudTargetMeta {
  provider: CloudProvider;
  region?: string;
  accountId?: string;
  resourceType?: string; // e.g., "ec2", "s3", "rds", "lambda"
  resourceArn?: string;
  vpcId?: string;
  securityGroups?: string[];
  tags?: Record<string, string>;
}

export interface IoTTargetMeta {
  deviceType?: string; // e.g., "camera", "sensor", "gateway", "plc"
  manufacturer?: string;
  firmware?: string;
  protocol?: string; // Primary protocol: mqtt, coap, zigbee, ble
  macAddress?: string;
  networkSegment?: string;
}

export interface ICSTargetMeta {
  protocol?: string; // modbus, dnp3, bacnet, ethernetip, opcua
  deviceRole?: "hmi" | "plc" | "rtu" | "scada_server" | "historian" | "engineering_workstation";
  vendor?: string;
  model?: string;
  firmwareVersion?: string;
  safetyLevel?: "sil1" | "sil2" | "sil3" | "sil4";
  zone?: string; // Purdue model zone
  purdueLevel?: 0 | 1 | 2 | 3 | 4 | 5;
}

export interface ContainerTargetMeta {
  runtime?: "docker" | "containerd" | "crio" | "podman";
  orchestrator?: "kubernetes" | "swarm" | "ecs" | "nomad" | "none";
  imageId?: string;
  imageName?: string;
  registryUrl?: string;
  namespace?: string;
  clusterName?: string;
  nodeRole?: "master" | "worker" | "etcd";
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
  /** Context engine override — skip auto-classification */
  skipContextEngine?: boolean;
  /** Compliance frameworks to assess against */
  complianceFrameworks?: ComplianceFramework[];
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
  /** ICS/OT safety mode — prevents disruptive checks */
  icsSafeMode?: boolean;
  /** IoT gentle mode — reduced rate limiting for constrained devices */
  iotGentleMode?: boolean;
  /** Cloud credential profile for authenticated scanning */
  cloudCredentialProfile?: string;
}

export interface ScanAuth {
  type: "basic" | "bearer" | "cookie" | "form" | "oauth2" | "api_key" | "certificate";
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
  /** Use active campaign intelligence */
  useActiveCampaigns?: boolean;
  /** Use LLM context engine for adaptive scanning */
  useLLMContext?: boolean;
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
  /** Asset environment where this was found */
  environment?: AssetEnvironment;
  /** Compliance mapping */
  compliance?: ComplianceMapping[];
  /** LLM-generated enriched narrative */
  enrichedNarrative?: string;
  /** Attack path chain — IDs of related findings */
  attackPathChain?: string[];
  /** Attack path role in the chain */
  attackPathRole?: "initial_access" | "lateral_movement" | "privilege_escalation" | "persistence" | "exfiltration" | "impact";
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
  /** Federal-compliant evidence chain */
  complianceEvidence?: ComplianceEvidence;
}

export interface ComplianceEvidence {
  /** Test procedure ID (e.g., NIST 800-115 section) */
  testProcedureId: string;
  /** Test procedure description */
  testProcedure: string;
  /** Expected result per the control */
  expectedResult: string;
  /** Actual result observed */
  actualResult: string;
  /** Pass/Fail/Not Applicable */
  status: "pass" | "fail" | "not_applicable" | "not_tested";
  /** Timestamp of the test */
  testedAt: number;
  /** Tester/tool identification */
  tester: string;
  /** Raw evidence artifact (hash for integrity) */
  evidenceHash?: string;
  /** Chain of custody reference */
  chainOfCustody?: string;
}

export interface ComplianceMapping {
  /** Framework identifier */
  framework: ComplianceFramework;
  /** Control ID within the framework */
  controlId: string;
  /** Control title */
  controlTitle: string;
  /** Compliance status */
  status: "compliant" | "non_compliant" | "partially_compliant" | "not_applicable";
  /** Mapping confidence */
  confidence: number;
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
  /** Environment-specific risk modifier */
  environmentModifier?: number;
  /** ICS safety impact score */
  icsSafetyImpact?: number;
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
  /** Context engine classification results */
  contextClassification?: AssetClassification[];
  /** Attack paths discovered by correlation engine */
  attackPaths?: AttackPath[];
}

export type ScanPhase =
  | "context"         // LLM context classification (new)
  | "recon"
  | "enumeration"
  | "detection"
  | "verification"
  | "correlation"     // Attack path correlation (new)
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

// ─── Attack Path Correlation ───────────────────────────────────────────────

export interface AttackPath {
  /** Unique path ID */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of the attack path */
  description: string;
  /** Ordered list of finding IDs in the chain */
  findingChain: string[];
  /** MITRE ATT&CK tactics traversed */
  tacticsTraversed: string[];
  /** Overall risk score for the path */
  riskScore: number;
  /** Likelihood of successful exploitation (0-100) */
  exploitability: number;
  /** Potential business impact */
  businessImpact: string;
  /** LLM-generated narrative of the attack path */
  narrative?: string;
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
  /** Environment applicability */
  environments?: AssetEnvironment[];
  /** Compliance framework mapping */
  complianceMapping?: ComplianceMapping[];
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
  | "dsl"        // Dynamic expression
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
  /** Asset environments this scanner applies to */
  environments?: AssetEnvironment[];
  /** Execute the scan */
  scan(target: ScanTarget, config?: ScanConfig): Promise<ScanFinding[]>;
  /** Check if the service is running on the target */
  probe(host: string, port: number): Promise<boolean>;
}

// ─── LLM Context Engine Types ──────────────────────────────────────────────

export interface ContextAnalysis {
  /** Target being analyzed */
  target: string;
  /** Classification result */
  classification: AssetClassification;
  /** Recommended scan type */
  recommendedScanType: ScanType;
  /** Recommended protocol scanners */
  recommendedScanners: string[];
  /** Recommended templates */
  recommendedTemplateIds: string[];
  /** Risk factors identified */
  riskFactors: string[];
  /** LLM reasoning */
  reasoning: string;
  /** Analysis timestamp */
  analyzedAt: number;
}

export interface CorrelationResult {
  /** Attack paths discovered */
  attackPaths: AttackPath[];
  /** Findings that could not be correlated */
  uncorrelatedFindings: string[];
  /** LLM reasoning for correlations */
  reasoning: string;
}

export interface EnrichedNarrative {
  /** Finding ID */
  findingId: string;
  /** Technical narrative */
  technicalNarrative: string;
  /** Executive summary */
  executiveSummary: string;
  /** Recommended remediation steps (prioritized) */
  remediationSteps: string[];
  /** Business impact assessment */
  businessImpact: string;
  /** Compliance implications */
  complianceImplications: string[];
}

// ─── Event Types (WebSocket) ───────────────────────────────────────────────

export type ScanEvent =
  | { type: "scan:queued"; scanId: string; position: number }
  | { type: "scan:started"; scanId: string; phase: ScanPhase }
  | { type: "scan:progress"; scanId: string; progress: number; scanner: string }
  | { type: "scan:finding"; scanId: string; finding: ScanFinding }
  | { type: "scan:scanner_complete"; scanId: string; result: ScannerResult }
  | { type: "scan:phase_change"; scanId: string; phase: ScanPhase }
  | { type: "scan:context_classified"; scanId: string; classification: AssetClassification }
  | { type: "scan:attack_path"; scanId: string; attackPath: AttackPath }
  | { type: "scan:completed"; scanId: string; summary: ScanSummary }
  | { type: "scan:failed"; scanId: string; error: string }
  | { type: "scan:cancelled"; scanId: string };

export interface ScanSummary {
  scanId: string;
  totalFindings: number;
  bySeverity: Record<FindingSeverity, number>;
  byEnvironment?: Record<AssetEnvironment, number>;
  scannersRun: number;
  scannersCompleted: number;
  scannersFailed: number;
  durationMs: number;
  topFindings: ScanFinding[];
  attackPaths?: AttackPath[];
  complianceSummary?: Record<ComplianceFramework, { pass: number; fail: number; total: number }>;
}
