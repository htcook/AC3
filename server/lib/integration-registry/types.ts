/**
 * Integration Registry — Universal Type System
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Defines the complete type system for the AC3 Integration Registry.
 * Every external tool, API, data source, and service is represented
 * as an IntegrationDefinition with a standardized lifecycle:
 * 
 *   1. Registration → LLM auto-discovery → Customer review → Approval → Pipeline wiring
 * 
 * Categories:
 *   - OSINT: Open-source intelligence (Shodan, Censys, crt.sh, etc.)
 *   - EXPLOIT_DB: Exploit databases (ExploitDB, Metasploit modules, Nuclei templates)
 *   - THREAT_INTEL: Threat intelligence feeds (MITRE, AlienVault OTX, ThreatFox)
 *   - SCANNER: Vulnerability scanners (ZAP, Burp Suite, Nuclei, Nikto)
 *   - PENTEST_TOOL: Penetration testing tools (Metasploit, Cobalt Strike, Hydra)
 *   - PHISHING: Phishing simulation (GoPhish, KnowBe4, Proofpoint, Cofense)
 *   - C2: Command & control frameworks (Caldera, Empire, Sliver, Cobalt Strike)
 *   - SIEM_SOAR: Security monitoring (Wazuh, Elastic, Splunk, Cortex XSOAR)
 *   - CLOUD: Cloud security (AWS Inspector, Azure Defender, GCP SCC)
 *   - CREDENTIAL: Credential/breach databases (DeHashed, HIBP, LeakCheck)
 *   - CUSTOM: Customer-defined data sources
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — ENUMS & CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

export type IntegrationCategory =
  | "osint"
  | "exploit_db"
  | "threat_intel"
  | "scanner"
  | "pentest_tool"
  | "phishing"
  | "c2"
  | "siem_soar"
  | "cloud"
  | "credential"
  | "custom";

export type PipelineStage =
  | "recon"              // Phase 1: Domain Recon (passive OSINT)
  | "passive_discovery"  // Phase 2: Passive Discovery & Enumeration
  | "enumeration"        // Phase 5: Active Discovery & Enumeration
  | "vuln_detection"     // Phase 6: Vulnerability Scanning
  | "exploitation"       // Phase 7: Penetration Testing / Exploitation
  | "post_exploit"       // Phase 8: Post-Exploitation
  | "social_engineering" // Phase 6b: Social Engineering / Phishing
  | "reporting"          // Phase 9: Reporting
  | "monitoring"         // Continuous: SIEM/SOAR alert ingestion
  | "enrichment";        // Cross-phase: data enrichment (threat intel, CVE lookup)

export type IntegrationStatus =
  | "proposed"           // LLM classified, awaiting customer review
  | "review"             // Customer is reviewing the proposal
  | "approved"           // Customer approved, ready to wire
  | "active"             // Wired into pipeline and operational
  | "paused"             // Temporarily disabled by customer
  | "rejected"           // Customer rejected the proposal
  | "error"              // Integration has errors (bad API key, unreachable, etc.)
  | "deprecated";        // Replaced or no longer supported

export type LicenseModel =
  | "free"               // No cost, no API key needed
  | "freemium"           // Free tier with limits, paid for more
  | "api_key"            // Requires paid API key
  | "byol"               // Bring Your Own License (commercial tool)
  | "platform_provided"  // AC3 provides the key (customer can override)
  | "custom";            // Custom licensing arrangement

export type AuthMethod =
  | "none"               // No authentication needed
  | "api_key"            // Single API key in header/query
  | "api_key_secret"     // API key + secret pair
  | "basic_auth"         // Username + password
  | "bearer_token"       // Bearer token in Authorization header
  | "oauth2"             // OAuth 2.0 flow
  | "ssh_key"            // SSH key-based access
  | "custom_header"      // Custom header-based auth
  | "certificate";       // Client certificate

export type DataFormat =
  | "json"
  | "xml"
  | "csv"
  | "stix"
  | "openapi"
  | "graphql"
  | "grpc"
  | "raw_text"
  | "html"
  | "binary";

// ═══════════════════════════════════════════════════════════════════════
// §2 — CORE INTEGRATION DEFINITION
// ═══════════════════════════════════════════════════════════════════════

/** Authentication configuration for an integration */
export interface IntegrationAuth {
  method: AuthMethod;
  /** Field names for credentials (e.g., { apiKey: "X-API-Key", apiSecret: "X-API-Secret" }) */
  fields: Record<string, {
    label: string;
    placeholder?: string;
    required: boolean;
    sensitive: boolean;  // Should be masked in UI
    envVar?: string;     // Platform env var that provides default value
  }>;
  /** Where to inject auth (header, query, body) */
  injection: "header" | "query" | "body" | "url_path";
  /** Header name or query param name for the primary key */
  headerName?: string;
  /** Prefix for the value (e.g., "Bearer ", "Token ") */
  valuePrefix?: string;
}

/** How the integration communicates */
export interface IntegrationEndpoint {
  baseUrl: string;
  /** API version path segment (e.g., "/v1", "/api/v2") */
  versionPath?: string;
  /** Response format */
  dataFormat: DataFormat;
  /** Rate limit (requests per minute) */
  rateLimit?: number;
  /** Request timeout in ms */
  timeout?: number;
  /** Health check endpoint (relative to baseUrl) */
  healthCheckPath?: string;
  /** Whether the endpoint supports pagination */
  supportsPagination?: boolean;
  /** OpenAPI/Swagger spec URL if available */
  openApiSpecUrl?: string;
}

/** Describes what data the integration provides and how it maps to AC3 */
export interface IntegrationCapability {
  /** What kind of data this provides */
  dataTypes: string[];  // e.g., ["subdomains", "ip_addresses", "certificates", "vulnerabilities"]
  /** Which pipeline stages this can contribute to */
  pipelineStages: PipelineStage[];
  /** Specific AC3 modules this enhances */
  enhancesModules: string[];  // e.g., ["passive_recon", "vuln_scanning", "exploit_selection"]
  /** Input types this integration accepts */
  inputTypes: string[];  // e.g., ["domain", "ip", "url", "cidr", "email"]
  /** Output observation types (maps to AssetType) */
  outputTypes: string[];  // e.g., ["subdomain", "ip", "vulnerability", "credential"]
  /** Whether this can run in passive-only mode */
  supportsPassiveOnly: boolean;
  /** Whether this requires active probing of the target */
  requiresActiveProbing: boolean;
  /** Estimated execution time range */
  estimatedDurationMs?: { min: number; max: number };
}

/** Value assessment — how much incremental value this integration adds */
export interface IntegrationValueAssessment {
  /** Overall value score (0-100) */
  overallScore: number;
  /** Does this provide unique data not available from existing sources? */
  uniqueDataScore: number;  // 0-100
  /** How reliable/accurate is the data? */
  reliabilityScore: number;  // 0-100
  /** How fresh is the data? */
  freshnessScore: number;  // 0-100
  /** Does this overlap with existing integrations? */
  overlapSources: string[];  // IDs of overlapping integrations
  /** Overlap percentage (0-100) */
  overlapPercent: number;
  /** Human-readable assessment summary */
  summary: string;
  /** Specific value-adds over existing sources */
  valueAdds: string[];
  /** Potential concerns */
  concerns: string[];
  /** Assessed by (llm | admin | system) */
  assessedBy: "llm" | "admin" | "system";
  /** When was this assessment done */
  assessedAt: number;
}

/** LLM auto-discovery result — what the LLM determined about a new API */
export interface AutoDiscoveryResult {
  /** Proposed category */
  category: IntegrationCategory;
  /** Confidence in the classification (0-100) */
  confidence: number;
  /** Proposed pipeline stages */
  pipelineStages: PipelineStage[];
  /** Proposed data types */
  dataTypes: string[];
  /** Proposed input types */
  inputTypes: string[];
  /** Proposed output types */
  outputTypes: string[];
  /** Human-readable description of what the API does */
  description: string;
  /** How the LLM determined this classification */
  reasoning: string;
  /** Suggested integration name */
  suggestedName: string;
  /** Suggested display name */
  suggestedDisplayName: string;
  /** Whether the LLM detected an OpenAPI/Swagger spec */
  hasOpenApiSpec: boolean;
  /** Detected auth method */
  detectedAuthMethod: AuthMethod;
  /** Detected rate limits */
  detectedRateLimit?: number;
  /** Similar existing integrations */
  similarExisting: Array<{ id: string; name: string; overlapPercent: number }>;
  /** Value assessment */
  valueAssessment: IntegrationValueAssessment;
  /** Raw LLM response for debugging */
  rawLlmResponse?: string;
}

/** Customer review/correction of an auto-discovery result */
export interface CustomerReview {
  /** Did the customer approve the proposal? */
  approved: boolean;
  /** Customer-corrected category (if different from LLM proposal) */
  correctedCategory?: IntegrationCategory;
  /** Customer-corrected pipeline stages */
  correctedPipelineStages?: PipelineStage[];
  /** Customer-corrected data types */
  correctedDataTypes?: string[];
  /** Customer notes/feedback */
  notes?: string;
  /** Customer-assigned priority (1=highest, 5=lowest) */
  priority?: number;
  /** Reviewed by (user ID) */
  reviewedBy: string;
  /** When was this reviewed */
  reviewedAt: number;
}

/** The complete integration definition */
export interface IntegrationDefinition {
  /** Unique integration ID (e.g., "shodan", "burp_suite", "custom_threat_feed_123") */
  id: string;
  /** Human-readable name */
  name: string;
  /** Display name for UI */
  displayName: string;
  /** Description of what this integration does */
  description: string;
  /** Category */
  category: IntegrationCategory;
  /** License model */
  licenseModel: LicenseModel;
  /** Current status */
  status: IntegrationStatus;
  /** Authentication configuration */
  auth: IntegrationAuth;
  /** Endpoint configuration */
  endpoint: IntegrationEndpoint;
  /** Capabilities */
  capabilities: IntegrationCapability;
  /** Value assessment */
  valueAssessment?: IntegrationValueAssessment;
  /** Auto-discovery result (for customer-added integrations) */
  autoDiscovery?: AutoDiscoveryResult;
  /** Customer review (for customer-added integrations) */
  customerReview?: CustomerReview;
  /** Pipeline wiring configuration */
  pipelineWiring?: PipelineWiringConfig;
  /** Who added this integration */
  addedBy: "platform" | "customer" | "auto_discovered";
  /** Tenant ID (null = platform-wide, string = tenant-specific) */
  tenantId?: string | null;
  /** Whether the customer can override the platform default key */
  allowCustomerOverride: boolean;
  /** Whether this is a built-in platform integration */
  isBuiltIn: boolean;
  /** Icon URL or icon name */
  icon?: string;
  /** Documentation URL */
  docsUrl?: string;
  /** Tags for search/filter */
  tags: string[];
  /** Created timestamp */
  createdAt: number;
  /** Updated timestamp */
  updatedAt: number;
  /** Last health check timestamp */
  lastHealthCheck?: number;
  /** Last health check result */
  lastHealthStatus?: "healthy" | "degraded" | "unreachable" | "auth_failed" | "unknown";
  /** Error message if status is "error" */
  lastError?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — PIPELINE WIRING
// ═══════════════════════════════════════════════════════════════════════

/** How an integration is wired into the engagement pipeline */
export interface PipelineWiringConfig {
  /** Which pipeline stages this integration participates in */
  stages: PipelineStage[];
  /** Execution priority within each stage (lower = runs first) */
  priority: number;
  /** Whether this runs in parallel with other integrations in the same stage */
  parallel: boolean;
  /** Dependencies — other integration IDs that must complete first */
  dependsOn: string[];
  /** Conditions for when this integration should run */
  conditions: PipelineCondition[];
  /** How to transform the integration's output into AC3's internal format */
  outputMapping: OutputMapping;
  /** Whether to deduplicate against other sources in the same stage */
  deduplicateWith: string[];
  /** Maximum execution time before timeout (ms) */
  maxDurationMs: number;
  /** Whether to continue the pipeline if this integration fails */
  failurePolicy: "continue" | "warn" | "abort";
}

/** Condition for when an integration should run */
export interface PipelineCondition {
  /** Type of condition */
  type: "always" | "if_target_type" | "if_previous_found" | "if_scope_includes" | "if_roe_allows" | "custom";
  /** Condition parameters */
  params: Record<string, any>;
  /** Human-readable description */
  description: string;
}

/** How to map integration output to AC3 internal format */
export interface OutputMapping {
  /** Target AC3 data type */
  targetType: "asset_observation" | "vulnerability" | "exploit_result" | "threat_intel" | "credential" | "report_section";
  /** Field mappings (integration field → AC3 field) */
  fieldMappings: Record<string, string>;
  /** Severity mapping (integration severity → AC3 severity) */
  severityMapping?: Record<string, string>;
  /** Confidence mapping */
  confidenceMapping?: Record<string, number>;
  /** Custom transformation function name (for complex mappings) */
  transformFunction?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — CREDENTIAL MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

/** Stored credentials for an integration (per-tenant) */
export interface IntegrationCredential {
  /** Integration ID */
  integrationId: string;
  /** Tenant ID (null = platform default) */
  tenantId: string | null;
  /** Credential source */
  source: "platform_default" | "customer_provided" | "auto_detected";
  /** Encrypted credential values */
  credentials: Record<string, string>;
  /** Whether the customer is using their own key (vs platform default) */
  isCustomerOverride: boolean;
  /** Last validated timestamp */
  lastValidated?: number;
  /** Validation result */
  validationStatus?: "valid" | "invalid" | "expired" | "rate_limited" | "unknown";
  /** Usage stats */
  usage?: {
    callsToday: number;
    callsThisMonth: number;
    quotaRemaining?: number;
    lastCallAt?: number;
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — FEEDBACK & LEARNING
// ═══════════════════════════════════════════════════════════════════════

/** Feedback record — customer corrections improve future auto-classifications */
export interface ClassificationFeedback {
  /** Auto-discovery result ID */
  discoveryId: string;
  /** Original LLM classification */
  originalCategory: IntegrationCategory;
  /** Original LLM pipeline stages */
  originalStages: PipelineStage[];
  /** Customer-corrected category */
  correctedCategory: IntegrationCategory;
  /** Customer-corrected pipeline stages */
  correctedStages: PipelineStage[];
  /** API characteristics that led to the correction */
  apiCharacteristics: Record<string, any>;
  /** Timestamp */
  createdAt: number;
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — BUILT-IN INTEGRATION CATALOG
// ═══════════════════════════════════════════════════════════════════════

/** Category metadata for UI display */
export const CATEGORY_METADATA: Record<IntegrationCategory, {
  label: string;
  description: string;
  icon: string;
  color: string;
}> = {
  osint: {
    label: "OSINT",
    description: "Open-source intelligence gathering — subdomains, IPs, certificates, tech stacks",
    icon: "Search",
    color: "#3B82F6",
  },
  exploit_db: {
    label: "Exploit Database",
    description: "Exploit databases and vulnerability repositories",
    icon: "Bug",
    color: "#EF4444",
  },
  threat_intel: {
    label: "Threat Intelligence",
    description: "Threat feeds, IOCs, actor profiles, and attack patterns",
    icon: "Shield",
    color: "#F59E0B",
  },
  scanner: {
    label: "Vulnerability Scanner",
    description: "Automated vulnerability scanning tools (DAST, SAST, network)",
    icon: "Radar",
    color: "#8B5CF6",
  },
  pentest_tool: {
    label: "Penetration Testing",
    description: "Exploitation frameworks and penetration testing tools",
    icon: "Crosshair",
    color: "#DC2626",
  },
  phishing: {
    label: "Phishing Simulation",
    description: "Phishing campaign platforms and security awareness training",
    icon: "Mail",
    color: "#F97316",
  },
  c2: {
    label: "Command & Control",
    description: "C2 frameworks for adversary emulation and red team operations",
    icon: "Terminal",
    color: "#7C3AED",
  },
  siem_soar: {
    label: "SIEM / SOAR",
    description: "Security monitoring, alerting, and automated response platforms",
    icon: "Activity",
    color: "#06B6D4",
  },
  cloud: {
    label: "Cloud Security",
    description: "Cloud-native security scanning and compliance tools",
    icon: "Cloud",
    color: "#10B981",
  },
  credential: {
    label: "Credential Intelligence",
    description: "Breach databases, credential leak monitoring, and exposure tracking",
    icon: "Key",
    color: "#EC4899",
  },
  custom: {
    label: "Custom Source",
    description: "Customer-defined data sources and custom API integrations",
    icon: "Plus",
    color: "#6B7280",
  },
};

/** Pipeline stage metadata */
export const PIPELINE_STAGE_METADATA: Record<PipelineStage, {
  label: string;
  description: string;
  phase: string;
  order: number;
}> = {
  recon: { label: "Reconnaissance", description: "Passive OSINT and domain intelligence", phase: "Phase 1", order: 1 },
  passive_discovery: { label: "Passive Discovery", description: "DNS, certs, tech fingerprinting (pre-RoE)", phase: "Phase 2", order: 2 },
  enumeration: { label: "Active Enumeration", description: "Port scanning, service detection, active probing", phase: "Phase 5", order: 3 },
  vuln_detection: { label: "Vulnerability Detection", description: "Automated vulnerability scanning", phase: "Phase 6", order: 4 },
  social_engineering: { label: "Social Engineering", description: "Phishing simulation and awareness testing", phase: "Phase 6b", order: 5 },
  exploitation: { label: "Exploitation", description: "Penetration testing and exploit execution", phase: "Phase 7", order: 6 },
  post_exploit: { label: "Post-Exploitation", description: "Lateral movement, persistence, data exfiltration", phase: "Phase 8", order: 7 },
  reporting: { label: "Reporting", description: "Report generation and evidence compilation", phase: "Phase 9", order: 8 },
  monitoring: { label: "Continuous Monitoring", description: "SIEM/SOAR alert ingestion and detection correlation", phase: "Continuous", order: 9 },
  enrichment: { label: "Data Enrichment", description: "Cross-phase threat intel, CVE lookup, and context enhancement", phase: "Cross-phase", order: 10 },
};
