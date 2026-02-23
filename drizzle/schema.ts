import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, json, boolean, double } from "drizzle-orm/mysql-core";

/**
 * Core user table backing auth flow.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin", "viewer"]).default("viewer").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

/**
 * Caldera server configurations
 */
export const serverConfigs = mysqlTable("server_configs", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  ipAddress: varchar("ipAddress", { length: 45 }).notNull(),
  httpsUrl: varchar("httpsUrl", { length: 512 }),
  httpUrl: varchar("httpUrl", { length: 512 }),
  region: varchar("region", { length: 64 }),
  dropletSize: varchar("dropletSize", { length: 64 }),
  dropletId: varchar("dropletId", { length: 64 }),
  status: mysqlEnum("status", ["online", "offline", "unknown"]).default("unknown").notNull(),
  lastHealthCheck: timestamp("lastHealthCheck"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ServerConfig = typeof serverConfigs.$inferSelect;
export type InsertServerConfig = typeof serverConfigs.$inferInsert;

/**
 * Server credentials (encrypted storage)
 */
export const serverCredentials = mysqlTable("server_credentials", {
  id: int("id").autoincrement().primaryKey(),
  serverId: int("serverId").notNull(),
  credentialType: mysqlEnum("credentialType", ["admin_login", "red_api_key", "blue_api_key", "ssh_key"]).notNull(),
  username: varchar("username", { length: 255 }),
  password: text("password"),
  apiKey: text("apiKey"),
  sshKeyPath: text("sshKeyPath"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type ServerCredential = typeof serverCredentials.$inferSelect;
export type InsertServerCredential = typeof serverCredentials.$inferInsert;

/**
 * SSH keys for MSF server tunnel connections.
 * Stores the key content (encrypted at rest), fingerprint, and metadata.
 */
export const sshKeys = mysqlTable("ssh_keys", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  fingerprint: varchar("fingerprint", { length: 255 }).notNull(),
  publicKey: text("publicKey").notNull(),
  privateKey: text("privateKey").notNull(),
  keyType: mysqlEnum("keyType", ["ed25519", "rsa", "ecdsa"]).default("ed25519").notNull(),
  bitLength: int("bitLength"),
  passphrase: text("passphrase"),
  isDefault: boolean("isDefault").default(false).notNull(),
  associatedServerId: int("associatedServerId"),
  createdBy: varchar("createdBy", { length: 64 }),
  lastUsedAt: timestamp("lastUsedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type SshKey = typeof sshKeys.$inferSelect;
export type InsertSshKey = typeof sshKeys.$inferInsert;

/**
 * Activity logs for audit trail
 */
export const activityLogs = mysqlTable("activity_logs", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId"),
  serverId: int("serverId"),
  action: varchar("action", { length: 255 }).notNull(),
  details: text("details"),
  ipAddress: varchar("ipAddress", { length: 45 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ActivityLog = typeof activityLogs.$inferSelect;
export type InsertActivityLog = typeof activityLogs.$inferInsert;

/**
 * Caldera statistics cache
 */
export const calderaStats = mysqlTable("caldera_stats", {
  id: int("id").autoincrement().primaryKey(),
  serverId: int("serverId").notNull(),
  totalAdversaries: int("totalAdversaries").default(0),
  totalAbilities: int("totalAbilities").default(0),
  activeOperations: int("activeOperations").default(0),
  totalAgents: int("totalAgents").default(0),
  lastUpdated: timestamp("lastUpdated").defaultNow().notNull(),
});

export type CalderaStats = typeof calderaStats.$inferSelect;
export type InsertCalderaStats = typeof calderaStats.$inferInsert;


/**
 * Campaigns for red team exercises
 */
export const campaigns = mysqlTable("campaigns", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  targetEnvironment: varchar("targetEnvironment", { length: 255 }),
  adversaryId: varchar("adversaryId", { length: 255 }),
  adversaryName: varchar("adversaryName", { length: 255 }),
  status: mysqlEnum("status", ["draft", "ready", "active", "paused", "completed"]).default("draft").notNull(),
  serverId: int("serverId"),
  createdBy: int("createdBy"),
  startDate: timestamp("startDate"),
  endDate: timestamp("endDate"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Campaign = typeof campaigns.$inferSelect;
export type InsertCampaign = typeof campaigns.$inferInsert;

/**
 * Agents assigned to campaigns
 */
export const campaignAgents = mysqlTable("campaign_agents", {
  id: int("id").autoincrement().primaryKey(),
  campaignId: int("campaignId").notNull(),
  agentName: varchar("agentName", { length: 255 }).notNull(),
  agentPaw: varchar("agentPaw", { length: 64 }),
  platform: varchar("platform", { length: 64 }),
  hostname: varchar("hostname", { length: 255 }),
  status: mysqlEnum("status", ["pending", "deployed", "active", "inactive"]).default("pending").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CampaignAgent = typeof campaignAgents.$inferSelect;
export type InsertCampaignAgent = typeof campaignAgents.$inferInsert;

/**
 * Abilities assigned to campaigns with execution order
 */
export const campaignAbilities = mysqlTable("campaign_abilities", {
  id: int("id").autoincrement().primaryKey(),
  campaignId: int("campaignId").notNull(),
  abilityId: varchar("abilityId", { length: 255 }).notNull(),
  abilityName: varchar("abilityName", { length: 255 }).notNull(),
  technique: varchar("technique", { length: 32 }),
  tactic: varchar("tactic", { length: 64 }),
  description: text("description"),
  executionOrder: int("executionOrder").default(0),
  status: mysqlEnum("status", ["pending", "running", "completed", "failed", "skipped"]).default("pending").notNull(),
  executedAt: timestamp("executedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CampaignAbility = typeof campaignAbilities.$inferSelect;
export type InsertCampaignAbility = typeof campaignAbilities.$inferInsert;

/**
 * Customer engagements / assessments
 */
export const engagements = mysqlTable("engagements", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  customerName: varchar("customerName", { length: 255 }).notNull(),
  description: text("description"),
  engagementType: mysqlEnum("engagementType", [
    "red_team",
    "phishing",
    "pentest",
    "purple_team",
    "tabletop"
  ]).default("red_team").notNull(),
  status: mysqlEnum("status", [
    "planning",
    "active",
    "paused",
    "completed",
    "archived"
  ]).default("planning").notNull(),
  startDate: timestamp("startDate"),
  endDate: timestamp("endDate"),
  targetDomain: varchar("targetDomain", { length: 255 }),
  targetIpRange: varchar("targetIpRange", { length: 255 }),
  phishingDomain: varchar("phishingDomain", { length: 255 }),
  calderaOperationId: varchar("calderaOperationId", { length: 255 }),
  calderaAdversaryId: varchar("calderaAdversaryId", { length: 255 }),
  gophishCampaignId: int("gophishCampaignId"),
  notes: text("notes"),
  createdBy: int("createdBy"),
  // ROE (Rules of Engagement) fields
  roeStatus: mysqlEnum("roe_status", ["none", "pending", "signed", "expired"]).default("none").notNull(),
  roeSignedDate: timestamp("roe_signed_date"),
  roeExpiryDate: timestamp("roe_expiry_date"),
  roeDocumentUrl: text("roe_document_url"),
  roeScope: json("roe_scope"),
  roeSignerName: varchar("roe_signer_name", { length: 255 }),
  roeSignerEmail: varchar("roe_signer_email", { length: 320 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Engagement = typeof engagements.$inferSelect;
export type InsertEngagement = typeof engagements.$inferInsert;

/**
 * Offensive operations audit log — tracks all Orange/Red tier actions
 */
export const offensiveAuditLog = mysqlTable("offensive_audit_log", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  operatorId: varchar("operator_id", { length: 64 }).notNull(),
  operatorName: varchar("operator_name", { length: 255 }),
  actionType: mysqlEnum("action_type", [
    "active_probe", "msf_check", "msf_auxiliary", "msf_exploit",
    "phishing_launch", "caldera_operation", "payload_delivery", "session_interaction"
  ]).notNull(),
  riskTier: mysqlEnum("risk_tier", ["yellow", "orange", "red"]).notNull(),
  target: varchar("target", { length: 512 }).notNull(),
  targetPort: int("target_port"),
  moduleOrTool: varchar("module_or_tool", { length: 512 }),
  roeStatus: varchar("roe_status", { length: 32 }),
  roeDocumentUrl: text("roe_document_url"),
  actionDetail: json("action_detail"),
  resultStatus: mysqlEnum("result_status", ["success", "failure", "blocked", "pending_approval"]).default("pending_approval").notNull(),
  resultDetail: text("result_detail"),
  ipAddress: varchar("ip_address", { length: 45 }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export type OffensiveAuditLog = typeof offensiveAuditLog.$inferSelect;
export type InsertOffensiveAuditLog = typeof offensiveAuditLog.$inferInsert;

/**
 * Links GoPhish campaigns to engagements for filtering and isolation
 */
export const campaignEngagements = mysqlTable("campaign_engagements", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  gophishCampaignId: int("gophishCampaignId").notNull(),
  gophishCampaignName: varchar("gophishCampaignName", { length: 255 }),
  calderaOperationId: varchar("calderaOperationId", { length: 255 }),
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type CampaignEngagement = typeof campaignEngagements.$inferSelect;
export type InsertCampaignEngagement = typeof campaignEngagements.$inferInsert;

/**
 * OSINT domain reconnaissance results per engagement
 */
export const domainRecon = mysqlTable("domain_recon", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  domain: varchar("domain", { length: 255 }).notNull(),
  // DNS records
  mxRecords: json("mxRecords"),
  spfRecord: text("spfRecord"),
  dmarcRecord: text("dmarcRecord"),
  dkimSelector: text("dkimSelector"),
  nsRecords: json("nsRecords"),
  aRecords: json("aRecords"),
  // Spoofability assessment
  spoofable: boolean("spoofable").default(false),
  spoofScore: int("spoofScore").default(0), // 0-100, higher = easier to spoof
  spoofAnalysis: text("spoofAnalysis"), // LLM-generated analysis
  // Subdomains from crt.sh
  subdomains: json("subdomains"),
  // WHOIS data
  whoisData: json("whoisData"),
  // Tech stack detection
  techStack: json("techStack"),
  // Breach/leak data
  breachData: json("breachData"),
  // Emails discovered
  discoveredEmails: json("discoveredEmails"),
  // Raw scan output
  scanStatus: mysqlEnum("scanStatus", ["pending", "running", "completed", "failed"]).default("pending").notNull(),
  scanStartedAt: timestamp("scanStartedAt"),
  scanCompletedAt: timestamp("scanCompletedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type DomainRecon = typeof domainRecon.$inferSelect;
export type InsertDomainRecon = typeof domainRecon.$inferInsert;

/**
 * Typosquat domain candidates discovered per engagement
 */
export const typosquatDomains = mysqlTable("typosquat_domains", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  reconId: int("reconId").notNull(), // links to domainRecon
  originalDomain: varchar("originalDomain", { length: 255 }).notNull(),
  permutedDomain: varchar("permutedDomain", { length: 255 }).notNull(),
  permutationType: varchar("permutationType", { length: 64 }).notNull(), // bitsquatting, homoglyph, insertion, etc.
  isRegistered: boolean("isRegistered").default(false),
  dnsResolved: boolean("dnsResolved").default(false),
  resolvedIp: varchar("resolvedIp", { length: 45 }),
  // MX/SPF/DMARC for the typosquat domain
  mxRecords: json("mxRecords"),
  spoofable: boolean("spoofable").default(false),
  // Management status
  status: mysqlEnum("status", [
    "discovered",
    "recommended",
    "purchased",
    "configured",
    "in_use",
    "transferred",
    "released"
  ]).default("discovered").notNull(),
  registrar: varchar("registrar", { length: 255 }),
  purchaseDate: timestamp("purchaseDate"),
  expiryDate: timestamp("expiryDate"),
  annualCost: varchar("annualCost", { length: 32 }),
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type TyposquatDomain = typeof typosquatDomains.$inferSelect;
export type InsertTyposquatDomain = typeof typosquatDomains.$inferInsert;

/**
 * OSINT findings that feed into campaign auto-design
 */
export const osintFindings = mysqlTable("osint_findings", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  reconId: int("reconId"),
  category: mysqlEnum("category", [
    "subdomain",
    "email",
    "credential_leak",
    "tech_stack",
    "social_media",
    "dark_web",
    "dns_misconfiguration",
    "certificate",
    "open_port",
    "other"
  ]).notNull(),
  severity: mysqlEnum("severity", ["info", "low", "medium", "high", "critical"]).default("info").notNull(),
  title: varchar("title", { length: 512 }).notNull(),
  description: text("description"),
  rawData: json("rawData"),
  source: varchar("source", { length: 255 }), // crt.sh, dns, whois, etc.
  // Campaign recommendation
  campaignRelevance: text("campaignRelevance"), // LLM-generated suggestion
  usedInCampaign: boolean("usedInCampaign").default(false),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type OsintFinding = typeof osintFindings.$inferSelect;
export type InsertOsintFinding = typeof osintFindings.$inferInsert;


/**
 * OSINT monitoring schedules for recurring domain scans
 */
export const osintMonitors = mysqlTable("osint_monitors", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId"),
  domain: varchar("domain", { length: 255 }).notNull(),
  // Monitoring config
  intervalHours: int("intervalHours").default(24).notNull(), // scan frequency
  enabled: boolean("enabled").default(true).notNull(),
  // Client type for tailored monitoring
  clientType: mysqlEnum("clientType", [
    "msp",
    "enterprise",
    "saas",
    "paas",
    "iaas",
    "mixed_hosting",
    "other"
  ]).default("enterprise").notNull(),
  // Last scan tracking
  lastScanAt: timestamp("lastScanAt"),
  lastChangeDetectedAt: timestamp("lastChangeDetectedAt"),
  totalScans: int("totalScans").default(0),
  totalChangesDetected: int("totalChangesDetected").default(0),
  // Notification preferences
  notifyOnChange: boolean("notifyOnChange").default(true),
  notifyEmail: varchar("notifyEmail", { length: 320 }),
  // Baseline snapshot (JSON of last known DNS state)
  baselineSnapshot: json("baselineSnapshot"),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type OsintMonitor = typeof osintMonitors.$inferSelect;
export type InsertOsintMonitor = typeof osintMonitors.$inferInsert;

/**
 * OSINT monitor change logs
 */
export const osintMonitorChanges = mysqlTable("osint_monitor_changes", {
  id: int("id").autoincrement().primaryKey(),
  monitorId: int("monitorId").notNull(),
  domain: varchar("domain", { length: 255 }).notNull(),
  changeType: varchar("changeType", { length: 64 }).notNull(),
  severity: mysqlEnum("severity", ["info", "warning", "critical"]).default("info").notNull(),
  previousValue: text("previousValue"),
  currentValue: text("currentValue"),
  description: text("description"),
  acknowledged: boolean("acknowledged").default(false),
  acknowledgedBy: int("acknowledgedBy"),
  acknowledgedAt: timestamp("acknowledgedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type OsintMonitorChange = typeof osintMonitorChanges.$inferSelect;
export type InsertOsintMonitorChange = typeof osintMonitorChanges.$inferInsert;

/**
 * Engagement reports (PDF generation tracking)
 */
export const engagementReports = mysqlTable("engagement_reports", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  // Report configuration
  reportType: mysqlEnum("reportType", [
    "executive_summary",
    "technical_detail",
    "compliance",
    "phishing_results",
    "osint_assessment",
    "full_engagement",
    "purple_team",
    "red_team_assessment",
    "detection_gap_analysis"
  ]).notNull(),
  clientType: mysqlEnum("clientType", [
    "msp",
    "enterprise",
    "saas",
    "paas",
    "iaas",
    "mixed_hosting",
    "other"
  ]).default("enterprise").notNull(),
  // Report metadata
  title: varchar("title", { length: 512 }).notNull(),
  preparedFor: varchar("preparedFor", { length: 255 }),
  preparedBy: varchar("preparedBy", { length: 255 }),
  // Sections included
  includeSections: json("includeSections"), // array of section IDs
  // Generated output
  reportUrl: text("reportUrl"), // S3 URL to generated PDF
  reportKey: varchar("reportKey", { length: 512 }),
  status: mysqlEnum("status", ["pending", "generating", "completed", "failed"]).default("pending").notNull(),
  generatedAt: timestamp("generatedAt"),
  // Branding
  brandingLogo: text("brandingLogo"),
  brandingColor: varchar("brandingColor", { length: 32 }),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type EngagementReport = typeof engagementReports.$inferSelect;
export type InsertEngagementReport = typeof engagementReports.$inferInsert;


/**
 * Domain Intel Scans - tracks each full pipeline run
 */
export const domainIntelScans = mysqlTable("domain_intel_scans", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId"),
  // Input
  primaryDomain: varchar("primaryDomain", { length: 255 }).notNull(),
  additionalDomains: json("additionalDomains"), // string[]
  clientType: mysqlEnum("clientType", [
    "msp", "enterprise", "saas", "paas", "iaas", "mixed_hosting", "other"
  ]).default("enterprise").notNull(),
  sector: varchar("sector", { length: 128 }),
  criticalFunctions: json("criticalFunctions"), // string[]
  complianceFlags: json("complianceFlags"), // string[]
  notes: text("notes"),
  // Org profile for BIA
  orgProfile: json("orgProfile"),
  // Pipeline status
  status: mysqlEnum("status", [
    "pending", "passive_recon", "discovering", "analyzing", "scoring", "recommending", "scan_complete", "completed", "failed"
  ]).default("pending").notNull(),
  // Aggregated results
  totalAssets: int("totalAssets").default(0),
  totalFindings: int("totalFindings").default(0),
  confirmedFindings: int("confirmedFindings").default(0),
  probableFindings: int("probableFindings").default(0),
  potentialFindings: int("potentialFindings").default(0),
  discoveryCoverageScore: int("discoveryCoverageScore").default(0), // 0-100 red team coverage
  discoveryCoverageBand: varchar("discoveryCoverageBand", { length: 32 }), // comprehensive/good/partial/limited
  overallRiskScore: int("overallRiskScore"), // 0-100
  overallRiskBand: varchar("overallRiskBand", { length: 32 }), // critical/high/medium/low
  // LLM-generated summaries
  executiveSummary: text("executiveSummary"),
  threatModelSummary: text("threatModelSummary"),
  // Campaign recommendations (JSON array)
  campaignRecommendations: json("campaignRecommendations"),
  // Full pipeline output
  pipelineOutput: json("pipelineOutput"),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type DomainIntelScan = typeof domainIntelScans.$inferSelect;
export type InsertDomainIntelScan = typeof domainIntelScans.$inferInsert;

/**
 * Discovered assets from domain intel scans
 */
export const discoveredAssets = mysqlTable("discovered_assets", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  // Asset identification
  assetId: varchar("assetId", { length: 128 }),
  hostname: varchar("hostname", { length: 255 }).notNull(),
  url: text("url"),
  assetType: varchar("assetType", { length: 64 }), // sso, mail_gateway, api, payment, cdn, etc.
  // DNS & infrastructure
  dnsRecords: json("dnsRecords"),
  dnsStatus: varchar("dnsStatus", { length: 32 }),
  headers: text("headers"),
  technologies: json("technologies"), // detected tech stack
  // Classification & tags
  assetClasses: json("assetClasses"), // string[]
  tags: json("tags"), // string[]
  // BIA scoring (CARVER+SHOCK)
  carverScores: json("carverScores"), // { criticality, accessibility, recuperability, vulnerability, effect, recognizability }
  shockScores: json("shockScores"), // { scope, handling, operationalImpact, cascadingEffects, knowledge }
  missionImpactScore: int("missionImpactScore"), // 0-10 scaled
  suggestedTier: varchar("suggestedTier", { length: 32 }), // tier0-tier3
  // Hybrid risk
  hybridRiskScore: int("hybridRiskScore"), // 0-100
  riskBand: varchar("riskBand", { length: 32 }), // critical/high/medium/low
  cvssEstimate: int("cvssEstimate"), // 0-10 scaled
  // Impact × Likelihood decomposition
  impactScore: int("impactScore"), // 0-100, from CARVER/SHOCK mission impact
  likelihoodScore: int("likelihoodScore"), // 0-100, from CVSS + exposure + recognizability
  // Asset criticality (BIA-derived)
  assetCriticalityScore: int("assetCriticalityScore"), // 0-100
  assetCriticalityBand: varchar("assetCriticalityBand", { length: 32 }), // critical/high/medium/low
  // Vulnerability risk (scan-confirmed findings only)
  vulnRiskScore: int("vulnRiskScore"), // 0-100
  vulnRiskBand: varchar("vulnRiskBand", { length: 32 }), // critical/high/medium/low
  // Context indicators
  contextIndicators: json("contextIndicators"), // { exposure, recognizability, confidence }
  // Posture findings
  postureFindings: json("postureFindings"), // array of findings
  // Test vector hypotheses
  testVectors: json("testVectors"), // array of attack vector suggestions
  // Campaign mapping
  recommendedCalderaAbilities: json("recommendedCalderaAbilities"), // ability IDs
  recommendedGophishTemplates: json("recommendedGophishTemplates"), // template suggestions
  recommendedAttackChain: json("recommendedAttackChain"), // ordered attack steps
  // Confidence
  confidence: int("confidence"), // 0-100
  confidenceExplanation: json("confidenceExplanation"),
  // Curation / exclusion
  excluded: boolean("excluded").default(false).notNull(), // false = included, true = excluded by user
  exclusionReason: varchar("exclusionReason", { length: 512 }), // why the user excluded this asset
  excludedAt: timestamp("excludedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  // Mission function mapping (LLM-classified)
  missionFunction: varchar("missionFunction", { length: 128 }), // e.g. "authentication", "data_storage", "communications"
  essentialService: varchar("essentialService", { length: 128 }), // e.g. "email", "sso", "payment_processing"
  assetPurpose: text("assetPurpose"), // LLM-generated description of asset's role in org
  businessImpactLevel: varchar("businessImpactLevel", { length: 32 }), // mission_critical, business_essential, operational, administrative
  missionDependencies: json("missionDependencies"), // { upstreamAssets: string[], downstreamAssets: string[], sharedServices: string[] }
  llmClassification: json("llmClassification"), // full LLM classification output for audit trail
  // Dynamic scoring metadata
  scoringVersion: int("scoringVersion").default(1), // increments on each re-score
  lastScoredAt: timestamp("lastScoredAt"), // when the asset was last scored
  scoringProfileId: int("scoringProfileId"), // which scoring profile was used
  // CVSS v4.0 integration
  cvssV4Vector: varchar("cvssV4Vector", { length: 512 }), // full CVSS v4.0 vector string
  // FIPS 199 security categorization
  fips199Category: json("fips199Category"), // { confidentiality, integrity, availability } each low/moderate/high
  // Criticality tier (1-5, aligned to BCP/DR recovery tiers)
  criticalityTier: int("criticalityTier"), // 1=Mission Critical, 2=Business Essential, 3=Operational, 4=Administrative, 5=Non-Essential
  // Enhanced asset classification
  deviceType: varchar("deviceType", { length: 64 }), // server, workstation, network_device, iot, mobile, etc.
  platformType: varchar("platformType", { length: 64 }), // web_application, api_service, database, mail_server, etc.
});

export type DiscoveredAsset = typeof discoveredAssets.$inferSelect;
export type InsertDiscoveredAsset = typeof discoveredAssets.$inferInsert;


/**
 * Comprehensive threat actor database (400+ actors)
 */
export const threatActors = mysqlTable("threat_actors", {
  id: int("id").autoincrement().primaryKey(),
  actorId: varchar("actorId", { length: 128 }).notNull().unique(), // e.g. "apt29", "fin7", "lockbit"
  name: varchar("name", { length: 255 }).notNull(),
  aliases: json("aliases"), // string[]
  type: mysqlEnum("actorType", ["apt", "cybercrime", "ransomware", "hacktivist", "access_broker", "influence_ops", "unknown"]).notNull(),
  origin: varchar("origin", { length: 128 }), // country or region
  description: text("description"),
  motivation: varchar("motivation", { length: 255 }), // espionage, financial, disruption, etc.
  firstSeen: varchar("firstSeen", { length: 32 }),
  lastActive: varchar("lastActive", { length: 32 }),
  threatLevel: mysqlEnum("threatLevel", ["critical", "high", "medium", "low"]).default("medium"),
  sophistication: mysqlEnum("sophistication", ["nation-state", "advanced", "intermediate", "basic"]).default("intermediate"),
  targetSectors: json("targetSectors"), // string[]
  targetRegions: json("targetRegions"), // string[]
  // MITRE ATT&CK mapping
  techniques: json("techniques"), // { id, name, tactic, score, description }[]
  // Tools and malware
  tools: json("tools"), // string[]
  malware: json("malware"), // string[]
  // Caldera profile
  calderaProfile: json("calderaProfile"), // { id, atomicOrdering, objectives }
  // Activity timeline
  activityTimeline: json("activityTimeline"), // { date, event, source }[]
  // STIX data
  stixId: varchar("stixId", { length: 128 }),
  // Metadata
  dataSource: varchar("dataSource", { length: 128 }), // mitre, osint, llm-enriched
  confidence: int("confidence"), // 0-100
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type ThreatActor = typeof threatActors.$inferSelect;
export type InsertThreatActor = typeof threatActors.$inferInsert;

/**
 * Caldera abilities linked to threat actors
 */
export const threatActorAbilities = mysqlTable("threat_actor_abilities", {
  id: int("id").autoincrement().primaryKey(),
  actorId: varchar("actorId", { length: 128 }).notNull(),
  abilityId: varchar("abilityId", { length: 128 }).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  tactic: varchar("tactic", { length: 128 }).notNull(),
  techniqueId: varchar("techniqueId", { length: 32 }).notNull(),
  techniqueName: varchar("techniqueName", { length: 255 }),
  platforms: json("platforms"), // { [platform]: { [executor]: { command, cleanup?, timeout? } } }
  singleton: boolean("singleton").default(false),
  repeatable: boolean("repeatable").default(true),
  requirements: json("requirements"), // { module, source }[]
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type ThreatActorAbility = typeof threatActorAbilities.$inferSelect;
export type InsertThreatActorAbility = typeof threatActorAbilities.$inferInsert;

/**
 * IOCs linked to threat actors
 */
export const threatActorIocs = mysqlTable("threat_actor_iocs", {
  id: int("id").autoincrement().primaryKey(),
  actorId: varchar("actorId", { length: 128 }).notNull(),
  type: varchar("iocType", { length: 64 }).notNull(), // hash_md5, hash_sha256, domain, ip, url, email, filename, registry, mutex
  value: text("value").notNull(),
  description: text("description"),
  confidence: mysqlEnum("iocConfidence", ["high", "medium", "low"]).default("medium"),
  firstSeen: varchar("iocFirstSeen", { length: 32 }),
  lastSeen: varchar("iocLastSeen", { length: 32 }),
  source: varchar("source", { length: 128 }), // cisa_kev, otx, abusech, osint, manual
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type ThreatActorIoc = typeof threatActorIocs.$inferSelect;
export type InsertThreatActorIoc = typeof threatActorIocs.$inferInsert;

/**
 * Live IOC feed entries from external sources
 */
export const iocFeeds = mysqlTable("ioc_feeds", {
  id: int("id").autoincrement().primaryKey(),
  feedSource: varchar("feedSource", { length: 64 }).notNull(), // cisa_kev, otx, abusech_urlhaus, abusech_malwarebazaar, abusech_threatfox
  feedType: varchar("feedType", { length: 64 }).notNull(), // vulnerability, malware, url, domain, ip, hash
  title: text("title"),
  description: text("description"),
  severity: mysqlEnum("feedSeverity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  // IOC data
  iocType: varchar("feedIocType", { length: 64 }), // cve, hash, domain, ip, url
  iocValue: text("iocValue"),
  // Metadata
  cveId: varchar("cveId", { length: 32 }),
  vendorProduct: varchar("vendorProduct", { length: 255 }),
  knownRansomware: boolean("knownRansomware").default(false),
  dateAdded: varchar("dateAdded", { length: 32 }),
  dueDate: varchar("dueDate", { length: 32 }),
  // Linked actors
  linkedActors: json("linkedActors"), // string[] of actorIds
  // Tags
  tags: json("feedTags"), // string[]
  rawData: json("rawData"), // original API response
  fetchedAt: timestamp("fetchedAt").defaultNow().notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type IocFeed = typeof iocFeeds.$inferSelect;
export type InsertIocFeed = typeof iocFeeds.$inferInsert;

/**
 * Automated engagement pipelines
 */
export const engagementPipelines = mysqlTable("engagement_pipelines", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  name: varchar("pipelineName", { length: 255 }).notNull(),
  status: mysqlEnum("pipelineStatus", ["pending", "intel_scan", "risk_scoring", "campaign_design", "caldera_setup", "gophish_setup", "ready", "running", "completed", "failed"]).default("pending").notNull(),
  // Input
  targetDomains: json("targetDomains"), // string[]
  clientType: varchar("pipelineClientType", { length: 64 }),
  orgProfile: json("orgProfile"), // { industry, size, compliance, etc. }
  // Pipeline results
  intelScanId: int("intelScanId"), // FK to domain_intel_scans
  riskSummary: json("riskSummary"), // { overallRisk, criticalAssets, topThreats }
  recommendedActors: json("recommendedActors"), // string[] of actorIds
  // Caldera operation
  calderaOperationId: varchar("calderaOperationId", { length: 128 }),
  calderaAdversaryId: varchar("calderaAdversaryId", { length: 128 }),
  calderaAbilitiesDeployed: int("calderaAbilitiesDeployed"),
  // GoPhish campaign
  gophishCampaignId: int("gophishCampaignId"),
  gophishTemplateId: int("gophishTemplateId"),
  gophishLandingPageId: int("gophishLandingPageId"),
  // Engagement
  engagementId: int("engagementId"), // FK to engagements
  // Progress tracking
  currentStep: int("currentStep").default(0),
  totalSteps: int("totalSteps").default(6),
  stepLog: json("stepLog"), // { step, status, message, timestamp }[]
  errorMessage: text("errorMessage"),
  completedAt: timestamp("completedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type EngagementPipeline = typeof engagementPipelines.$inferSelect;
export type InsertEngagementPipeline = typeof engagementPipelines.$inferInsert;

// ─── IOC Sync Log ─────────────────────────────────────────────────────────
export const iocSyncLogs = mysqlTable("ioc_sync_logs", {
  id: int("id").autoincrement().primaryKey(),
  syncType: varchar("syncType", { length: 32 }).notNull(), // 'scheduled' | 'manual'
  status: varchar("status", { length: 32 }).notNull(), // 'running' | 'completed' | 'failed'
  results: json("results"), // { source, fetched, error? }[]
  totalFetched: int("totalFetched").default(0),
  errorMessage: text("errorMessage"),
  startedAt: timestamp("startedAt").defaultNow().notNull(),
  completedAt: timestamp("completedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type IocSyncLog = typeof iocSyncLogs.$inferSelect;
export type InsertIocSyncLog = typeof iocSyncLogs.$inferInsert;

// ─── TTP Knowledge Base ───────────────────────────────────────────────
/**
 * Deep knowledge base for MITRE ATT&CK techniques.
 * Stores how each technique is performed, what IOCs it generates,
 * detection rules, and Caldera ability mappings.
 */
export const ttpKnowledge = mysqlTable("ttp_knowledge", {
  id: int("id").autoincrement().primaryKey(),
  techniqueId: varchar("techniqueId", { length: 32 }).notNull().unique(), // e.g. T1059.001
  techniqueName: varchar("techniqueName", { length: 255 }).notNull(),
  tactic: varchar("tactic", { length: 128 }).notNull(),
  // Deep understanding
  description: text("description"), // Comprehensive description of the technique
  executionMethods: json("executionMethods"), // Array of { method, tools, commands, prerequisites, platforms }
  toolsUsed: json("toolsUsed"), // Array of { name, type, description, commonActors }
  // IOC Generation
  iocPatterns: json("iocPatterns"), // Array of { type, pattern, description, confidence, volatility }
  // type: file_hash, registry_key, network_signature, event_log, process, dns, certificate, mutex
  artifacts: json("artifacts"), // Array of { category, description, location, persistence }
  // Detection
  detectionRules: json("detectionRules"), // Array of { format, name, rule, description, falsePositiveRate }
  // format: sigma, yara, suricata, splunk_spl, kql
  eventLogSources: json("eventLogSources"), // Array of { source, eventId, description }
  // e.g. { source: "Sysmon", eventId: "1", description: "Process creation" }
  // Caldera mapping
  calderaAbilities: json("calderaAbilities"), // Array of { abilityId, name, executor, command }
  // Campaign design intelligence
  attackChainPosition: varchar("attackChainPosition", { length: 64 }), // initial_access, execution, persistence, etc.
  prerequisiteTechniques: json("prerequisiteTechniques"), // string[] - techniques that typically precede this one
  followUpTechniques: json("followUpTechniques"), // string[] - techniques that typically follow this one
  defensiveGaps: json("defensiveGaps"), // Array of { gap, impact, recommendation }
  // Red/Blue/Purple team relevance
  redTeamValue: int("redTeamValue"), // 1-10 how valuable for red team exercises
  blueTeamPriority: int("blueTeamPriority"), // 1-10 how important for blue team to detect
  purpleTeamNotes: text("purpleTeamNotes"), // Notes for purple team exercises
  // Metadata
  dataSource: varchar("dataSource", { length: 128 }), // mitre, llm-enriched, manual
  confidence: int("confidence"), // 0-100
  lastEnriched: timestamp("lastEnriched"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type TtpKnowledge = typeof ttpKnowledge.$inferSelect;
export type InsertTtpKnowledge = typeof ttpKnowledge.$inferInsert;


// ─── False Positive Findings ─────────────────────────────────────────────
/**
 * Tracks findings that analysts have marked as false positives.
 * References a finding by scanId + findingIndex (position in the postureFindings array)
 * or by a content hash for deduplication across scans.
 */
export const falsePositiveFindings = mysqlTable("false_positive_findings", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("scanId").notNull(),
  assetId: int("assetId").notNull(), // FK to discovered_assets.id
  findingIndex: int("findingIndex").notNull(), // index within postureFindings array
  // Finding identification (for cross-scan dedup)
  findingHash: varchar("findingHash", { length: 64 }).notNull(), // SHA-256 of title+asset+type
  findingTitle: varchar("findingTitle", { length: 512 }).notNull(),
  findingType: varchar("findingType", { length: 128 }), // vulnerability, misconfiguration, exposure, etc.
  findingSeverity: varchar("findingSeverity", { length: 32 }), // critical, high, medium, low, info
  // FP metadata
  reason: text("reason").notNull(), // analyst's explanation for why this is a false positive
  status: mysqlEnum("fpStatus", ["false_positive", "under_review", "reinstated"]).default("false_positive").notNull(),
  // Who marked it
  markedBy: varchar("markedBy", { length: 255 }), // username or user ID
  markedAt: timestamp("markedAt").defaultNow().notNull(),
  // If reinstated (un-FP'd)
  reinstatedBy: varchar("reinstatedBy", { length: 255 }),
  reinstatedAt: timestamp("reinstatedAt"),
  reinstatedReason: text("reinstatedReason"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type FalsePositiveFinding = typeof falsePositiveFindings.$inferSelect;
export type InsertFalsePositiveFinding = typeof falsePositiveFindings.$inferInsert;


// ─── Ransomware Group Profiles ───────────────────────────────────────────
/**
 * Comprehensive ransomware group catalog with activity scoring,
 * TTP mapping, and targeting intelligence. Enriched via LLM from
 * public threat intel sources.
 */
export const ransomwareGroups = mysqlTable("ransomware_groups", {
  id: int("id").autoincrement().primaryKey(),
  groupName: varchar("groupName", { length: 255 }).notNull().unique(),
  aliases: json("aliases"),                     // string[]
  description: text("description"),
  // Activity scoring
  activityScore: int("activityScore").default(0),    // 0-100 composite
  trend: mysqlEnum("trend", ["surging", "active", "declining", "dormant"]).default("active"),
  threatLevel: mysqlEnum("rwThreatLevel", ["critical", "high", "medium", "low"]).default("medium"),
  // Victim statistics
  victims7d: int("victims7d").default(0),
  victims30d: int("victims30d").default(0),
  totalVictims: int("totalVictims").default(0),
  // Targeting intelligence
  topSectors: json("topSectors"),               // string[]
  topCountries: json("topCountries"),           // string[]
  // Technical profile
  associatedMalware: json("associatedMalware"), // string[]
  mitreTechniques: json("mitreTechniques"),     // string[] (T-codes)
  ransomwareFamily: varchar("ransomwareFamily", { length: 255 }),
  extortionModel: mysqlEnum("extortionModel", ["single", "double", "triple", "unknown"]).default("unknown"),
  affiliateProgram: boolean("affiliateProgram").default(false),
  // Infrastructure
  knownInfrastructure: json("knownInfrastructure"), // string[] (.onion sites, leak sites)
  notableAttacks: json("notableAttacks"),       // NotableAttack[]
  // Timeline
  firstSeen: varchar("rwFirstSeen", { length: 32 }),
  lastActive: varchar("rwLastActive", { length: 32 }),
  // Caldera integration
  calderaActorId: varchar("calderaActorId", { length: 128 }), // FK to threat_actors.actorId
  // Metadata
  dataSource: varchar("rwDataSource", { length: 128 }), // llm_enriched, manual, osint
  confidence: int("rwConfidence").default(75),
  lastEnriched: timestamp("lastEnriched"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type RansomwareGroup = typeof ransomwareGroups.$inferSelect;
export type InsertRansomwareGroup = typeof ransomwareGroups.$inferInsert;

// ─── Ransomware Victim Events ────────────────────────────────────────────
/**
 * Individual ransomware victim reports / leak site postings.
 * Tracks which groups are actively attacking which sectors/countries.
 */
export const ransomwareEvents = mysqlTable("ransomware_events", {
  id: int("id").autoincrement().primaryKey(),
  groupName: varchar("reGroupName", { length: 255 }).notNull(),
  victimName: varchar("victimName", { length: 512 }).notNull(),
  victimUrl: varchar("victimUrl", { length: 512 }),
  country: varchar("reCountry", { length: 128 }),
  sector: varchar("reSector", { length: 128 }),
  description: text("reDescription"),
  publishedAt: timestamp("publishedAt"),
  source: varchar("reSource", { length: 128 }),  // leak_site, news, osint
  verified: boolean("verified").default(false),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type RansomwareEventRow = typeof ransomwareEvents.$inferSelect;
export type InsertRansomwareEvent = typeof ransomwareEvents.$inferInsert;

// ─── Threat Group Events (Activity History) ──────────────────────────────
/**
 * Granular event tracking for all threat groups.
 * Each row represents a specific activity: attack, infrastructure change,
 * new malware variant, law enforcement action, etc.
 */
export const threatGroupEvents = mysqlTable("threat_group_events", {
  id: int("id").autoincrement().primaryKey(),
  actorId: varchar("tgeActorId", { length: 128 }).notNull(), // FK to threat_actors.actorId
  eventType: mysqlEnum("eventType", [
    "attack", "campaign", "infrastructure_change", "malware_update",
    "law_enforcement", "affiliate_change", "data_leak", "ttp_evolution",
    "group_merger", "group_rebrand", "new_tool", "zero_day",
  ]).notNull(),
  title: varchar("tgeTitle", { length: 512 }).notNull(),
  description: text("tgeDescription"),
  severity: mysqlEnum("tgeSeverity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  // Victim/target details (for attack events)
  victimName: varchar("tgeVictimName", { length: 512 }),
  victimSector: varchar("tgeVictimSector", { length: 128 }),
  victimCountry: varchar("tgeVictimCountry", { length: 128 }),
  // Technical details
  mitreTechniques: json("tgeMitreTechniques"), // string[] — techniques used in this event
  iocs: json("tgeIocs"), // { type, value }[] — IOCs from this event
  // Source attribution
  source: varchar("tgeSource", { length: 255 }), // news URL, feed name, etc.
  sourceUrl: varchar("tgeSourceUrl", { length: 1024 }),
  confidence: int("tgeConfidence").default(75), // 0-100
  // Timestamps
  eventDate: timestamp("eventDate"), // when the event occurred
  discoveredAt: timestamp("discoveredAt").defaultNow().notNull(), // when we learned about it
  createdAt: timestamp("tgeCreatedAt").defaultNow().notNull(),
});
export type ThreatGroupEvent = typeof threatGroupEvents.$inferSelect;
export type InsertThreatGroupEvent = typeof threatGroupEvents.$inferInsert;

// ─── Threat Intelligence Updates (LLM Monitoring Log) ────────────────────
/**
 * Tracks LLM monitoring sweeps — when the system scanned news/feeds
 * and what updates were discovered and applied.
 */
export const threatIntelUpdates = mysqlTable("threat_intel_updates", {
  id: int("id").autoincrement().primaryKey(),
  sweepType: mysqlEnum("sweepType", ["scheduled", "manual", "triggered"]).default("manual"),
  status: mysqlEnum("tiuStatus", ["running", "completed", "failed"]).default("running"),
  // Results
  groupsScanned: int("groupsScanned").default(0),
  updatesApplied: int("updatesApplied").default(0),
  newEventsFound: int("newEventsFound").default(0),
  newIocsFound: int("newIocsFound").default(0),
  newTtpsFound: int("newTtpsFound").default(0),
  // Details
  summary: text("tiuSummary"), // LLM-generated summary of what changed
  details: json("tiuDetails"), // { groupName, changes[] }[]
  errors: json("tiuErrors"), // string[]
  // Timing
  startedAt: timestamp("tiuStartedAt").defaultNow().notNull(),
  completedAt: timestamp("tiuCompletedAt"),
  durationMs: int("durationMs"),
});
export type ThreatIntelUpdate = typeof threatIntelUpdates.$inferSelect;
export type InsertThreatIntelUpdate = typeof threatIntelUpdates.$inferInsert;


/**
 * Campaign archetype templates — reusable attack patterns
 * (SaaS OAuth compromise, token abuse, cloud lateral movement, etc.)
 * that auto-populate with actor-specific MITRE techniques.
 */
export const campaignArchetypes = mysqlTable("campaign_archetypes", {
  id: int("id").autoincrement().primaryKey(),
  slug: varchar("slug", { length: 128 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  category: mysqlEnum("archetypeCategory", [
    "saas_oauth_compromise",
    "token_abuse",
    "cloud_lateral_movement",
    "supply_chain",
    "credential_harvesting",
    "ransomware_deployment",
    "data_exfiltration",
    "persistence_implant",
    "custom",
  ]).notNull(),
  description: text("description"),
  // Kill chain phases this archetype covers
  killChainPhases: json("killChainPhases"), // string[] — e.g. ["initial-access", "execution", "lateral-movement"]
  // Default MITRE techniques for this archetype
  defaultTechniques: json("defaultTechniques"), // { id: string, name: string, tactic: string }[]
  // Caldera ability IDs that implement the archetype steps
  defaultAbilities: json("defaultAbilities"), // { abilityId: string, name: string, step: number, description: string }[]
  // Target environment descriptors
  targetPlatforms: json("targetPlatforms"), // string[] — e.g. ["azure", "aws", "gcp", "m365"]
  targetServices: json("targetServices"), // string[] — e.g. ["Exchange Online", "SharePoint", "S3"]
  // Prerequisites and assumptions
  prerequisites: json("prerequisites"), // string[] — e.g. ["Valid OAuth token", "Compromised service account"]
  // Detection guidance
  detectionGuidance: text("detectionGuidance"),
  // Difficulty / complexity rating
  complexity: mysqlEnum("archetypeComplexity", ["low", "medium", "high", "expert"]).default("medium"),
  // Metadata
  isBuiltIn: boolean("isBuiltIn").default(true),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type CampaignArchetype = typeof campaignArchetypes.$inferSelect;
export type InsertCampaignArchetype = typeof campaignArchetypes.$inferInsert;

/**
 * Links campaign archetypes to specific threat actors.
 * When an actor is selected, the archetype auto-populates
 * with the actor's known techniques that overlap the archetype.
 */
export const archetypeActorMappings = mysqlTable("archetype_actor_mappings", {
  id: int("id").autoincrement().primaryKey(),
  archetypeId: int("archetypeId").notNull(),
  actorId: varchar("actorId", { length: 128 }).notNull(),
  // Actor-specific technique overrides for this archetype
  actorTechniques: json("actorTechniques"), // { id, name, tactic, actorScore }[]
  // Actor-specific ability overrides
  actorAbilities: json("actorAbilities"), // { abilityId, name, step }[]
  // Confidence that this actor uses this archetype pattern
  confidence: int("confidence").default(50), // 0-100
  // Evidence / source
  evidence: text("evidence"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type ArchetypeActorMapping = typeof archetypeActorMappings.$inferSelect;
export type InsertArchetypeActorMapping = typeof archetypeActorMappings.$inferInsert;


/**
 * Phishing Drafts — materialized campaign resources from domain intel scan recommendations.
 * Bridges the gap between LLM-generated campaign recommendations and actual GoPhish deployment.
 * Workflow: Domain Scan → Campaign Recommendation → Materialize Draft → Review → Deploy to GoPhish
 */
export const phishingDrafts = mysqlTable("phishing_drafts", {
  id: int("id").autoincrement().primaryKey(),
  // Link to source intelligence
  scanId: int("scanId"),
  engagementId: int("engagementId"),
  campaignRecommendationIndex: int("campaignRecommendationIndex"),

  // Draft lifecycle
  status: mysqlEnum("draftStatus", [
    "draft",
    "approved",
    "deployed",
    "launched",
    "completed",
    "archived",
  ]).default("draft").notNull(),

  // Campaign metadata
  campaignName: varchar("campaignName", { length: 255 }).notNull(),
  campaignType: varchar("campaignType", { length: 64 }),
  priority: mysqlEnum("draftPriority", ["critical", "high", "medium", "low"]).default("medium"),
  targetDomain: varchar("targetDomain", { length: 255 }),
  targetSector: varchar("targetSector", { length: 128 }),

  // GoPhish Email Template
  templateName: varchar("templateName", { length: 255 }),
  templateSubject: varchar("templateSubject", { length: 500 }),
  templateHtml: text("templateHtml"),
  templateText: text("templateText"),

  // GoPhish Landing Page
  landingPageName: varchar("landingPageName", { length: 255 }),
  landingPageHtml: text("landingPageHtml"),
  landingPageRedirectUrl: varchar("landingPageRedirectUrl", { length: 500 }),
  captureCredentials: boolean("captureCredentials").default(true),
  capturePasswords: boolean("capturePasswords").default(false),

  // Target Group
  targetGroupName: varchar("targetGroupName", { length: 255 }),
  targetEmails: json("targetEmails"),

  // Sending Profile
  smtpProfileName: varchar("smtpProfileName", { length: 255 }),
  phishingUrl: varchar("phishingUrl", { length: 500 }),

  // Attack Chain & Caldera Integration
  attackChain: json("attackChain"),
  calderaAbilities: json("calderaAbilities"),
  calderaOperationId: varchar("calderaOperationId", { length: 128 }),
  autoTriggerCaldera: boolean("autoTriggerCaldera").default(false),
  triggerCondition: json("triggerCondition"),

  // Threat Actor Intelligence
  threatActorId: varchar("threatActorId", { length: 128 }),
  threatActorName: varchar("threatActorName", { length: 255 }),
  matchRationale: text("matchRationale"),

  // Phishing Exploit Enhancements
  phishingExploits: json("phishingExploits"), // Array of matched exploit IDs from phishing-exploits.ts
  exploitEnhancedLandingPage: text("exploitEnhancedLandingPage"), // Landing page HTML with injected exploit code
  // GoPhish Resource IDs (populated after deployment)
  gophishTemplateId: int("gophishTemplateId"),
  gophishPageId: int("gophishPageId"),
  gophishGroupId: int("gophishGroupId"),
  gophishCampaignId: int("gophishCampaignId"),

  // Scheduling
  launchDate: timestamp("launchDate"),
  sendByDate: timestamp("sendByDate"),

  // Campaign Results (synced from GoPhish after launch)
  campaignStats: json("campaignStats"),

  // Metadata
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type PhishingDraft = typeof phishingDrafts.$inferSelect;
export type InsertPhishingDraft = typeof phishingDrafts.$inferInsert;


// ─── Access Broker Listings ────────────────────────────────────────────
/**
 * Tracks Initial Access Broker (IAB) marketplace listings.
 * IABs sell compromised network access on darkweb forums (Exploit, XSS, RAMP, BreachForums).
 * Each row represents a known listing or broker profile.
 */
export const accessBrokerListings = mysqlTable("access_broker_listings", {
  id: int("id").autoincrement().primaryKey(),
  brokerId: varchar("brokerId", { length: 128 }).notNull(), // unique slug e.g. "exotic-lily"
  brokerName: varchar("brokerName", { length: 255 }).notNull(),
  aliases: json("aliases"), // string[]
  // Listing details
  listingType: mysqlEnum("listingType", [
    "vpn_access", "rdp_access", "citrix_access", "webshell",
    "domain_admin", "cloud_access", "email_access", "database_access",
    "zero_day", "exploit_kit", "credential_dump", "other"
  ]).default("other").notNull(),
  accessType: varchar("accessType", { length: 128 }), // VPN, RDP, Citrix, webshell, etc.
  // Victim / target info
  victimSector: varchar("victimSector", { length: 128 }),
  victimCountry: varchar("victimCountry", { length: 128 }),
  victimRevenue: varchar("victimRevenue", { length: 64 }), // e.g. "$50M-$100M"
  victimEmployeeCount: varchar("victimEmployeeCount", { length: 64 }),
  // Pricing
  askingPrice: varchar("askingPrice", { length: 64 }), // e.g. "$5,000", "auction"
  currency: varchar("currency", { length: 16 }).default("USD"),
  // Forum / marketplace
  forumSource: varchar("forumSource", { length: 128 }), // exploit.in, xss.is, ramp, breachforums
  forumPostUrl: text("forumPostUrl"),
  // Broker profile
  brokerReputation: mysqlEnum("brokerReputation", ["established", "rising", "new", "unknown"]).default("unknown"),
  totalListings: int("totalListings").default(0),
  successfulSales: int("successfulSales").default(0),
  activeForums: json("activeForums"), // string[] — forums they operate on
  // Linked threat actors
  linkedActorIds: json("linkedActorIds"), // string[] — FK to threat_actors.actorId
  linkedRansomwareGroups: json("linkedRansomwareGroups"), // string[] — known ransomware buyers
  // Technical details
  accessLevel: mysqlEnum("accessLevel", ["domain_admin", "local_admin", "user", "service_account", "unknown"]).default("unknown"),
  persistenceMechanism: varchar("persistenceMechanism", { length: 255 }),
  mitreTechniques: json("mitreTechniques"), // string[] — T-codes used for initial access
  // Status
  status: mysqlEnum("iabStatus", ["active", "sold", "expired", "removed", "law_enforcement"]).default("active"),
  // Timeline
  firstSeen: varchar("iabFirstSeen", { length: 32 }),
  lastActive: varchar("iabLastActive", { length: 32 }),
  postedAt: timestamp("postedAt"),
  // Metadata
  dataSource: varchar("iabDataSource", { length: 128 }), // osint, darkweb_monitor, llm_enriched, manual
  confidence: int("iabConfidence").default(75), // 0-100
  description: text("iabDescription"),
  rawData: json("iabRawData"),
  createdAt: timestamp("iabCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("iabUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type AccessBrokerListing = typeof accessBrokerListings.$inferSelect;
export type InsertAccessBrokerListing = typeof accessBrokerListings.$inferInsert;


// ─── Information Operations Campaigns ──────────────────────────────────
/**
 * Tracks information operations (IO) / influence campaigns by nation-state
 * and non-state actors. Sources include DFRLab FIAT, EUvsDisinfo,
 * Stanford IO Archive, and LLM-enriched OSINT.
 */
export const infoOpsCampaigns = mysqlTable("info_ops_campaigns", {
  id: int("id").autoincrement().primaryKey(),
  campaignId: varchar("ioCampaignId", { length: 128 }).notNull().unique(), // unique slug
  campaignName: varchar("ioCampaignName", { length: 255 }).notNull(),
  aliases: json("ioAliases"), // string[]
  // Attribution
  attributedTo: varchar("attributedTo", { length: 255 }), // country or group
  sponsorState: varchar("sponsorState", { length: 128 }), // Russia, China, Iran, etc.
  operatorGroup: varchar("operatorGroup", { length: 255 }), // IRA, Ghostwriter, DRAGONBRIDGE, etc.
  linkedActorIds: json("ioLinkedActorIds"), // string[] — FK to threat_actors.actorId
  // Campaign details
  operationType: mysqlEnum("operationType", [
    "disinformation", "influence", "hack_and_leak", "astroturfing",
    "election_interference", "propaganda", "cyber_espionage_io",
    "economic_coercion", "diplomatic_pressure", "other"
  ]).default("other").notNull(),
  status: mysqlEnum("ioStatus", ["active", "disrupted", "dormant", "attributed", "ongoing"]).default("active"),
  // Targeting
  targetCountries: json("ioTargetCountries"), // string[]
  targetAudiences: json("targetAudiences"), // string[] — e.g. "military personnel", "voters", "diaspora"
  targetPlatforms: json("ioTargetPlatforms"), // string[] — Twitter/X, Facebook, Telegram, Reddit, etc.
  targetNarratives: json("targetNarratives"), // string[] — key narratives pushed
  // Scale & impact
  estimatedReach: varchar("estimatedReach", { length: 128 }), // e.g. "millions", "10K-50K accounts"
  accountsIdentified: int("accountsIdentified").default(0),
  contentPiecesIdentified: int("contentPiecesIdentified").default(0),
  platformActionsTaken: json("platformActionsTaken"), // { platform, action, date }[]
  // Techniques
  techniques: json("ioTechniques"), // string[] — e.g. "bot networks", "fake news sites", "deepfakes"
  // Cyber component (if hybrid)
  cyberComponent: boolean("cyberComponent").default(false),
  linkedCyberOps: json("linkedCyberOps"), // string[] — related APT campaigns
  mitreTechniques: json("ioMitreTechniques"), // string[] — MITRE ATT&CK techniques if applicable
  // Evidence & sources
  primarySource: varchar("primarySource", { length: 255 }), // DFRLab, Stanford IO, EUvsDisinfo, etc.
  sourceUrls: json("sourceUrls"), // string[]
  reportTitle: varchar("reportTitle", { length: 512 }),
  // Timeline
  startDate: varchar("ioStartDate", { length: 32 }),
  endDate: varchar("ioEndDate", { length: 32 }),
  discoveredDate: varchar("discoveredDate", { length: 32 }),
  // Metadata
  threatLevel: mysqlEnum("ioThreatLevel", ["critical", "high", "medium", "low"]).default("medium"),
  confidence: int("ioConfidence").default(75), // 0-100
  description: text("ioDescription"),
  dataSource: varchar("ioDataSource", { length: 128 }), // dfrlab_fiat, euvsdisinf, stanford_io, llm_enriched, manual
  lastEnriched: timestamp("ioLastEnriched"),
  createdAt: timestamp("ioCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("ioUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type InfoOpsCampaign = typeof infoOpsCampaigns.$inferSelect;
export type InsertInfoOpsCampaign = typeof infoOpsCampaigns.$inferInsert;


/**
 * Metasploit server instances managed via DigitalOcean
 */
export const metasploitServers = mysqlTable("metasploit_servers", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  dropletId: varchar("dropletId", { length: 64 }),
  ipAddress: varchar("ipAddress", { length: 45 }),
  region: varchar("region", { length: 32 }).default("nyc1"),
  dropletSize: varchar("dropletSize", { length: 32 }).default("s-2vcpu-4gb"),
  // MSGRPC connection
  rpcPort: int("rpcPort").default(55553),
  rpcUser: varchar("rpcUser", { length: 64 }).default("msf"),
  rpcPass: text("rpcPass"),
  rpcSsl: boolean("rpcSsl").default(false),
  rpcToken: text("rpcToken"), // Session token from auth
  // Status
  status: mysqlEnum("msfStatus", ["provisioning", "installing", "online", "offline", "error", "destroying"]).default("provisioning").notNull(),
  statusMessage: text("msfStatusMessage"),
  lastHealthCheck: timestamp("msfLastHealthCheck"),
  // Metasploit info
  msfVersion: varchar("msfVersion", { length: 64 }),
  moduleCount: int("moduleCount"),
  activeSessionCount: int("activeSessionCount").default(0),
  // Lifecycle
  autoDestroy: boolean("autoDestroy").default(false), // Destroy after engagement
  engagementId: int("engagementId"), // Link to engagement if scoped
  // SSH Tunnel configuration
  sshTunnelEnabled: boolean("sshTunnelEnabled").default(true),
  sshUser: varchar("sshUser", { length: 64 }).default("root"),
  sshKeyPath: text("msfSshKeyPath"),
  tunnelStatus: mysqlEnum("msfTunnelStatus", ["connected", "connecting", "disconnected", "reconnecting", "error"]).default("disconnected"),
  tunnelLocalPort: int("tunnelLocalPort"),
  createdAt: timestamp("msfCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("msfUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type MetasploitServer = typeof metasploitServers.$inferSelect;
export type InsertMetasploitServer = typeof metasploitServers.$inferInsert;

/**
 * Exploit execution jobs — tracks each exploit attempt
 */
export const exploitJobs = mysqlTable("exploit_jobs", {
  id: int("id").autoincrement().primaryKey(),
  msfServerId: int("msfServerId").notNull(),
  // Target
  targetIp: varchar("targetIp", { length: 45 }).notNull(),
  targetPort: int("targetPort"),
  targetDomain: varchar("targetDomain", { length: 255 }),
  scanId: int("exploitScanId"), // Link to domain intel scan
  // Exploit details
  exploitModule: varchar("exploitModule", { length: 512 }).notNull(), // e.g. "exploit/windows/http/exchange_proxyshell_rce"
  payloadModule: varchar("payloadModule", { length: 512 }), // e.g. "windows/x64/meterpreter/reverse_https"
  cveId: varchar("exploitCveId", { length: 32 }),
  options: json("exploitOptions"), // { RHOSTS, RPORT, LHOST, LPORT, ... }
  // Caldera integration
  calderaStagerUrl: text("calderaStagerUrl"), // URL for Caldera agent callback
  calderaAgentPaw: varchar("calderaAgentPaw", { length: 64 }), // Agent ID once connected
  // Execution
  status: mysqlEnum("exploitJobStatus", ["pending", "approved", "running", "success", "failed", "aborted", "timeout"]).default("pending").notNull(),
  msfJobId: int("msfJobId"), // Metasploit job ID
  msfSessionId: int("msfSessionId"), // Metasploit session ID if successful
  sessionType: varchar("sessionType", { length: 32 }), // "meterpreter", "shell", "caldera_agent"
  // Results
  result: text("exploitResult"),
  errorMessage: text("exploitErrorMessage"),
  startedAt: timestamp("exploitStartedAt"),
  completedAt: timestamp("exploitCompletedAt"),
  // Safety
  approvedBy: varchar("approvedBy", { length: 255 }),
  approvedAt: timestamp("approvedAt"),
  scopeVerified: boolean("scopeVerified").default(false),
  // Audit
  createdAt: timestamp("exploitJobCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("exploitJobUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type ExploitJob = typeof exploitJobs.$inferSelect;
export type InsertExploitJob = typeof exploitJobs.$inferInsert;

/**
 * Unified exploit catalog — merges phishing exploits, CVE exploits, and custom payloads
 * into a single catalog with Caldera ability metadata for sync
 */
export const unifiedExploitCatalog = mysqlTable("unified_exploit_catalog", {
  id: int("id").autoincrement().primaryKey(),
  // Identity
  catalogId: varchar("catalogId", { length: 128 }).notNull().unique(), // e.g. "msf:exploit/windows/http/...", "phish:cred-bitb-sso", "edb:12345"
  name: varchar("exploitName", { length: 512 }).notNull(),
  description: text("exploitDescription"),
  // Classification
  tier: mysqlEnum("tier", ["initial_access", "post_access"]).notNull(), // Pre-agent vs post-agent
  category: varchar("exploitCategory", { length: 64 }).notNull(), // "rce", "credential_harvesting", "privesc", "lateral_movement", etc.
  source: varchar("exploitSource", { length: 32 }).notNull(), // "metasploit", "exploitdb", "phishing_library", "custom", "caldera_stockpile"
  // CVE & vulnerability mapping
  cveIds: json("exploitCveIds"), // string[]
  cvssScore: double("exploitCvssScore"),
  severity: varchar("exploitSeverity", { length: 16 }), // critical, high, medium, low
  // MITRE ATT&CK mapping
  mitreId: varchar("exploitMitreId", { length: 32 }),
  mitreName: varchar("exploitMitreName", { length: 255 }),
  mitreTactic: varchar("exploitMitreTactic", { length: 64 }),
  // Exploit metadata
  platform: varchar("exploitPlatform", { length: 64 }), // "windows", "linux", "multi", "web"
  exploitType: varchar("exploitType", { length: 32 }), // "remote", "local", "webapps", "dos", "phishing"
  reliability: varchar("exploitReliability", { length: 16 }), // excellent, great, good, normal, average, low
  difficulty: varchar("exploitDifficulty", { length: 16 }), // basic, intermediate, advanced, expert
  effectiveness: int("exploitEffectiveness"), // 1-10
  // Source-specific references
  msfModule: varchar("msfModule", { length: 512 }), // Metasploit module path
  msfRank: int("msfRank"), // Metasploit ranking
  edbId: varchar("edbId", { length: 32 }), // ExploitDB ID
  edbUrl: varchar("edbUrl", { length: 512 }),
  phishingExploitId: varchar("phishingExploitId", { length: 64 }), // ID from phishing-exploits.ts
  // Caldera ability payload (ready for sync)
  calderaAbilityId: varchar("calderaAbilityId", { length: 128 }),
  calderaAbilityPayload: json("calderaAbilityPayload"), // Full CalderaAbilityPayload JSON
  calderaSynced: boolean("calderaSynced").default(false),
  calderaSyncedAt: timestamp("calderaSyncedAt"),
  // Agent stager config (for initial_access tier)
  agentStagerType: varchar("agentStagerType", { length: 32 }), // "sandcat", "manx", "custom"
  agentStagerCommand: text("agentStagerCommand"), // Shell command to deploy agent
  agentStagerPayload: text("agentStagerPayload"), // Encoded payload bytes or download URL
  agentCallbackUrl: text("agentCallbackUrl"), // Caldera C2 callback URL
  // Injectable code (for phishing exploits)
  landingPageCode: text("landingPageCode"),
  emailTemplateCode: text("emailTemplateCode"),
  // Tags and detection
  tags: json("exploitTags"), // string[]
  detectionIndicators: json("exploitDetectionIndicators"), // string[]
  prerequisites: json("exploitPrerequisites"), // string[]
  // Status
  verified: boolean("exploitVerified").default(false),
  lastVerifiedAt: timestamp("exploitLastVerifiedAt"),
  enabled: boolean("exploitEnabled").default(true),
  // Metadata
  author: varchar("exploitAuthor", { length: 255 }),
  datePublished: varchar("exploitDatePublished", { length: 32 }),
  createdAt: timestamp("catalogCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("catalogUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type UnifiedExploit = typeof unifiedExploitCatalog.$inferSelect;
export type InsertUnifiedExploit = typeof unifiedExploitCatalog.$inferInsert;


/**
 * Client Portal Share Tokens — enables read-only, white-labeled engagement report access
 * 
 * Each token grants access to a specific engagement's data (findings, risk scores,
 * executive summary, recommendations) without requiring authentication.
 * Tokens can be time-limited, password-protected, and branded.
 */
export const engagementShares = mysqlTable("engagement_shares", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagementId").notNull(),
  // Share token (unique, URL-safe)
  token: varchar("token", { length: 64 }).notNull().unique(),
  // Access controls
  expiresAt: timestamp("expiresAt"),
  accessPassword: varchar("accessPassword", { length: 255 }), // optional bcrypt hash
  maxViews: int("maxViews"), // null = unlimited
  viewCount: int("viewCount").default(0).notNull(),
  isActive: boolean("isActive").default(true).notNull(),
  // What to include
  includeSections: json("includeSections"), // string[] of section IDs to show
  includeFindings: boolean("includeFindings").default(true).notNull(),
  includeRiskScores: boolean("includeRiskScores").default(true).notNull(),
  includeRecommendations: boolean("includeRecommendations").default(true).notNull(),
  includeExecutiveSummary: boolean("includeExecutiveSummary").default(true).notNull(),
  includeAssets: boolean("includeAssets").default(true).notNull(),
  includeCompliance: boolean("includeCompliance").default(false).notNull(),
  // Branding
  clientName: varchar("clientName", { length: 255 }),
  clientLogo: text("clientLogo"), // URL to client logo
  brandingColor: varchar("brandingColor", { length: 32 }),
  customMessage: text("customMessage"), // welcome message for client
  // Metadata
  createdBy: int("createdBy"),
  lastAccessedAt: timestamp("lastAccessedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type EngagementShare = typeof engagementShares.$inferSelect;
export type InsertEngagementShare = typeof engagementShares.$inferInsert;

// ─── Adversary Emulation Playbooks ───
export const emulationPlaybooks = mysqlTable("emulation_playbooks", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  actorId: varchar("actorId", { length: 128 }),
  actorName: varchar("actorName", { length: 255 }),
  status: varchar("status", { length: 32 }).default("draft").notNull(),
  difficulty: varchar("difficulty", { length: 32 }),
  estimatedDuration: int("estimatedDuration"),
  targetPlatforms: json("targetPlatforms"),
  phases: json("phases"),
  tacticsUsed: json("tacticsUsed"),
  techniquesUsed: json("techniquesUsed"),
  totalAbilities: int("totalAbilities"),
  calderaAdversaryId: varchar("calderaAdversaryId", { length: 128 }),
  calderaDeployedAt: timestamp("calderaDeployedAt"),
  tags: json("tags"),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type EmulationPlaybook = typeof emulationPlaybooks.$inferSelect;
export type InsertEmulationPlaybook = typeof emulationPlaybooks.$inferInsert;

export const playbookExecutions = mysqlTable("playbook_executions", {
  id: int("id").primaryKey().autoincrement(),
  playbookId: int("playbookId"),
  playbookName: varchar("playbookName", { length: 255 }),
  calderaOperationId: varchar("calderaOperationId", { length: 128 }),
  calderaOperationName: varchar("calderaOperationName", { length: 255 }),
  execStatus: varchar("execStatus", { length: 32 }).default("pending").notNull(),
  targetGroup: varchar("targetGroup", { length: 128 }),
  targetAgentCount: int("targetAgentCount"),
  abilitiesTotal: int("abilitiesTotal"),
  abilitiesSucceeded: int("abilitiesSucceeded"),
  abilitiesFailed: int("abilitiesFailed"),
  abilitiesSkipped: int("abilitiesSkipped"),
  startedAt: timestamp("startedAt"),
  completedAt: timestamp("completedAt"),
  launchedBy: varchar("launchedBy", { length: 128 }),
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type PlaybookExecution = typeof playbookExecutions.$inferSelect;

// ─── Evidence Collection & Chain of Custody ───
export const evidenceItems = mysqlTable("evidence_items", {
  id: int("id").primaryKey().autoincrement(),
  evidenceId: varchar("evidenceId", { length: 64 }).notNull().unique(),
  engagementId: varchar("engagementId", { length: 128 }),
  operationId: varchar("operationId", { length: 128 }),
  title: varchar("title", { length: 255 }).notNull(),
  description: text("description"),
  type: varchar("type", { length: 64 }).notNull(),
  category: varchar("category", { length: 64 }),
  fileUrl: text("fileUrl"),
  fileKey: varchar("fileKey", { length: 512 }),
  fileName: varchar("fileName", { length: 255 }),
  fileSize: int("fileSize"),
  mimeType: varchar("mimeType", { length: 128 }),
  sha256Hash: varchar("sha256Hash", { length: 128 }),
  md5Hash: varchar("md5Hash", { length: 64 }),
  tags: json("tags"),
  metadata: json("metadata"),
  classification: varchar("classification", { length: 32 }).default("confidential"),
  collectedBy: varchar("collectedBy", { length: 255 }),
  collectedAt: timestamp("collectedAt"),
  notes: text("notes"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type EvidenceItem = typeof evidenceItems.$inferSelect;

export const evidenceChainOfCustody = mysqlTable("evidence_chain_of_custody", {
  id: int("id").primaryKey().autoincrement(),
  evidenceId: varchar("evidenceId", { length: 64 }).notNull(),
  action: varchar("action", { length: 64 }).notNull(),
  performedBy: varchar("performedBy", { length: 128 }).notNull(),
  performedAt: timestamp("performedAt").defaultNow().notNull(),
  details: text("details"),
  ipAddress: varchar("ipAddress", { length: 64 }),
  userAgent: varchar("userAgent", { length: 255 }),
  integrityHash: varchar("integrityHash", { length: 128 }),
  previousHash: varchar("previousHash", { length: 128 }),
});

// ─── Attack Path Visualization ───
export const attackPaths = mysqlTable("attack_paths", {
  id: int("id").primaryKey().autoincrement(),
  pathId: varchar("pathId", { length: 64 }).notNull().unique(),
  engagementId: varchar("engagementId", { length: 128 }),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  nodes: json("nodes"),
  edges: json("edges"),
  riskScore: int("riskScore"),
  status: varchar("status", { length: 32 }).default("draft"),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type AttackPath = typeof attackPaths.$inferSelect;

// ─── Purple Team / Detection Tests ───
export const detectionTests = mysqlTable("detection_tests", {
  id: int("id").primaryKey().autoincrement(),
  testId: varchar("testId", { length: 64 }).notNull().unique(),
  engagementId: varchar("engagementId", { length: 128 }),
  techniqueId: varchar("techniqueId", { length: 32 }).notNull(),
  techniqueName: varchar("techniqueName", { length: 255 }),
  tactic: varchar("tactic", { length: 64 }),
  abilityId: varchar("abilityId", { length: 128 }),
  abilityName: varchar("abilityName", { length: 255 }),
  executedAt: timestamp("executedAt"),
  executionResult: varchar("executionResult", { length: 32 }).default("pending"),
  detected: boolean("detected").default(false),
  detectionTime: int("detectionTime"),
  detectionSource: varchar("detectionSource", { length: 255 }),
  detectionRule: varchar("detectionRule", { length: 255 }),
  alertSeverity: varchar("alertSeverity", { length: 32 }),
  isGap: boolean("isGap").default(false),
  gapSeverity: varchar("gapSeverity", { length: 32 }),
  recommendation: text("recommendation"),
  mitigationStatus: varchar("mitigationStatus", { length: 32 }).default("open"),
  notes: text("notes"),
  evidence: json("evidence"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type DetectionTest = typeof detectionTests.$inferSelect;

// ─── Webhook & SIEM Integration ───
export const webhookEndpoints = mysqlTable("webhook_endpoints", {
  id: int("id").primaryKey().autoincrement(),
  webhookId: varchar("webhookId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  url: text("url").notNull(),
  secret: varchar("secret", { length: 255 }),
  events: json("events"),
  format: varchar("format", { length: 32 }).default("json"),
  headers: json("headers"),
  enabled: boolean("enabled").default(true),
  lastTriggered: timestamp("lastTriggered"),
  failCount: int("failCount").default(0),
  createdBy: int("createdBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type WebhookEndpoint = typeof webhookEndpoints.$inferSelect;

export const webhookDeliveries = mysqlTable("webhook_deliveries", {
  id: int("id").primaryKey().autoincrement(),
  webhookId: varchar("webhookId", { length: 64 }).notNull(),
  event: varchar("event", { length: 128 }).notNull(),
  payload: json("payload"),
  responseStatus: int("responseStatus"),
  responseBody: text("responseBody"),
  success: boolean("success").default(false),
  deliveredAt: timestamp("deliveredAt").defaultNow().notNull(),
});

// ─── Threat-Informed Defense Scoring ───
export const defenseScores = mysqlTable("defense_scores", {
  id: int("id").primaryKey().autoincrement(),
  scoreId: varchar("score_id", { length: 64 }).notNull().unique(),
  organizationName: varchar("organization_name", { length: 255 }).notNull(),
  threatActorId: int("threat_actor_id"),
  threatActorName: varchar("threat_actor_name", { length: 255 }),
  overallScore: int("overall_score"),
  detectionScore: int("detection_score"),
  vulnerabilityScore: int("vulnerability_score"),
  surfaceScore: int("surface_score"),
  responseScore: int("response_score"),
  breakdown: json("breakdown"),
  recommendations: json("recommendations"),
  engagementId: varchar("engagement_id", { length: 128 }),
  createdBy: varchar("created_by", { length: 128 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type DefenseScore = typeof defenseScores.$inferSelect;


// ─── Bug Bounty Platform Integration ───

export const bugBountyPrograms = mysqlTable("bug_bounty_programs", {
  id: int("id").primaryKey().autoincrement(),
  platform: varchar("platform", { length: 32 }).notNull(), // hackerone | bugcrowd | manual
  handle: varchar("handle", { length: 255 }).notNull(),
  name: varchar("name", { length: 512 }).notNull(),
  url: varchar("url", { length: 1024 }),
  logoUrl: varchar("logo_url", { length: 1024 }),
  state: varchar("state", { length: 64 }), // open, paused, closed
  submissionState: varchar("submission_state", { length: 64 }),
  currency: varchar("currency", { length: 16 }),
  minBounty: double("min_bounty"),
  maxBounty: double("max_bounty"),
  avgBounty: double("avg_bounty"),
  totalPaid: double("total_paid"),
  resolvedCount: int("resolved_count"),
  hackerCount: int("hacker_count"),
  scopeAssets: json("scope_assets"), // array of { type, identifier, eligible, maxSeverity }
  policyUrl: varchar("policy_url", { length: 1024 }),
  lastSyncedAt: timestamp("last_synced_at"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type BugBountyProgram = typeof bugBountyPrograms.$inferSelect;

export const bugBountyFindings = mysqlTable("bug_bounty_findings", {
  id: int("id").primaryKey().autoincrement(),
  programId: int("program_id"),
  platform: varchar("platform", { length: 32 }).notNull(),
  externalId: varchar("external_id", { length: 128 }),
  title: varchar("title", { length: 1024 }).notNull(),
  severityRating: varchar("severity_rating", { length: 32 }), // critical, high, medium, low, none
  cveIds: json("cve_ids"), // array of CVE IDs
  cweId: varchar("cwe_id", { length: 32 }),
  cweName: varchar("cwe_name", { length: 512 }),
  substate: varchar("substate", { length: 64 }), // resolved, informative, duplicate, etc.
  reportUrl: varchar("report_url", { length: 1024 }),
  disclosedAt: timestamp("disclosed_at"),
  awardedAmount: double("awarded_amount"),
  currency: varchar("currency", { length: 16 }),
  reporterUsername: varchar("reporter_username", { length: 255 }),
  reporterReputation: int("reporter_reputation"),
  programHandle: varchar("program_handle", { length: 255 }),
  programName: varchar("program_name", { length: 512 }),
  assetIdentifier: varchar("asset_identifier", { length: 512 }),
  assetType: varchar("asset_type", { length: 64 }),
  votes: int("votes"),
  summary: text("summary"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});
export type BugBountyFinding = typeof bugBountyFindings.$inferSelect;

export const bugBountyCorrelations = mysqlTable("bug_bounty_correlations", {
  id: int("id").primaryKey().autoincrement(),
  findingId: int("finding_id").notNull(),
  correlationType: varchar("correlation_type", { length: 64 }).notNull(), // cve_match, asset_match, cwe_match
  matchedEntityType: varchar("matched_entity_type", { length: 64 }).notNull(), // vuln_intel, discovered_asset, ttp_knowledge
  matchedEntityId: int("matched_entity_id").notNull(),
  matchedEntityName: varchar("matched_entity_name", { length: 512 }),
  confidenceScore: double("confidence_score"), // 0.0 - 1.0
  details: json("details"), // { matchField, matchValue, context }
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});
export type BugBountyCorrelation = typeof bugBountyCorrelations.$inferSelect;

export const bugBountySyncLogs = mysqlTable("bug_bounty_sync_logs", {
  id: int("id").primaryKey().autoincrement(),
  platform: varchar("platform", { length: 32 }).notNull(),
  syncType: varchar("sync_type", { length: 64 }).notNull(), // programs, hacktivity, scopes
  status: varchar("status", { length: 32 }).notNull(), // running, completed, failed
  itemsSynced: int("items_synced").default(0),
  errorMessage: text("error_message"),
  startedAt: timestamp("started_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});
export type BugBountySyncLog = typeof bugBountySyncLogs.$inferSelect;


// ─── CARVER+Shock Scoring Profiles ──────────────────────────────────────
/**
 * Stores adjustable CARVER+Shock factor weight profiles per engagement.
 * Users can create custom weight profiles for different engagement objectives
 * (e.g., emphasizing "Shock" for critical infrastructure assessments).
 */
export const scoringProfiles = mysqlTable("scoring_profiles", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  engagementId: int("engagementId"), // optional link to a specific engagement
  isDefault: boolean("isDefault").default(false),
  // CARVER factor weights (0-10 scale, default weights match existing algorithm)
  wCriticality: double("wCriticality").default(2.0).notNull(),
  wAccessibility: double("wAccessibility").default(1.5).notNull(),
  wRecuperability: double("wRecuperability").default(1.0).notNull(),
  wVulnerability: double("wVulnerability").default(1.5).notNull(),
  wEffect: double("wEffect").default(1.5).notNull(),
  wRecognizability: double("wRecognizability").default(0.5).notNull(),
  // Shock factor weights
  wScope: double("wScope").default(1.5).notNull(),
  wHandling: double("wHandling").default(1.0).notNull(),
  wOperationalImpact: double("wOperationalImpact").default(2.0).notNull(),
  wCascadingEffects: double("wCascadingEffects").default(1.5).notNull(),
  wKnowledge: double("wKnowledge").default(1.0).notNull(),
  // Meta-weights: how much CARVER vs Shock vs CVSS contribute to final score
  carverWeight: double("carverWeight").default(0.4).notNull(), // 0-1
  shockWeight: double("shockWeight").default(0.3).notNull(),   // 0-1
  cvssWeight: double("cvssWeight").default(0.3).notNull(),     // 0-1
  // Thresholds for risk bands
  criticalThreshold: int("criticalThreshold").default(85).notNull(),
  highThreshold: int("highThreshold").default(65).notNull(),
  mediumThreshold: int("mediumThreshold").default(40).notNull(),
  // Metadata
  createdBy: int("createdBy").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull(),
});
export type ScoringProfile = typeof scoringProfiles.$inferSelect;
export type InsertScoringProfile = typeof scoringProfiles.$inferInsert;

// ─── Scoring Audit Log ──────────────────────────────────────────────────
/**
 * Immutable audit trail of every scoring computation.
 * Records the profile used, input factors, and computed scores for traceability.
 */
export const scoringAuditLog = mysqlTable("scoring_audit_log", {
  id: int("id").autoincrement().primaryKey(),
  assetId: int("assetId").notNull(),
  scanId: int("scanId"),
  profileId: int("profileId"), // null = default weights
  // Input factors snapshot
  carverScores: json("carverScores"),  // { criticality, accessibility, ... }
  shockScores: json("shockScores"),    // { scope, handling, ... }
  cvssEstimate: double("cvssEstimate"),
  // Computed outputs
  missionImpactScore: double("missionImpactScore"),
  impactScore: double("impactScore"),
  likelihoodScore: double("likelihoodScore"),
  hybridRiskScore: double("hybridRiskScore"),
  riskBand: varchar("riskBand", { length: 32 }),
  // Weight snapshot (for reproducibility)
  weightsSnapshot: json("weightsSnapshot"), // full profile weights at time of computation
  // Dynamic re-scoring fields
  triggerType: varchar("triggerType", { length: 64 }), // e.g., 'kev_match', 'new_cve_discovered', 'initial_scan'
  previousScore: double("previousScore"), // score before this event
  delta: double("delta"), // score change (newScore - previousScore)
  changeDescription: text("changeDescription"), // human-readable description of what changed
  factorChanges: json("factorChanges"), // Array<{ factor, previousValue, newValue, reason }>
  pipelinePhase: varchar("pipelinePhase", { length: 64 }), // e.g., 'kev_enrichment', 'vuln_feed', 'port_risk'
  // Metadata
  computedBy: varchar("computedBy", { length: 255 }),
  computedAt: timestamp("computedAt").defaultNow().notNull(),
});
export type ScoringAuditEntry = typeof scoringAuditLog.$inferSelect;


/**
 * Autonomous Validation Engine — Validation Runs
 * Tracks each validation run (batch of candidate validations)
 */
export const validationRuns = mysqlTable("validation_runs", {
  id: int("id").autoincrement().primaryKey(),
  scanId: int("validationScanId").notNull(), // Link to domain_intel_scans
  msfServerId: int("validationMsfServerId").notNull(), // MSF server used
  engagementId: int("validationEngagementId"), // Optional engagement link
  // Configuration
  mode: mysqlEnum("validationMode", ["check_only", "auxiliary_scan", "safe_exploit"]).notNull(),
  maxCandidates: int("maxCandidates").default(10).notNull(),
  timeoutPerCandidate: int("timeoutPerCandidate").default(60).notNull(),
  requireApproval: boolean("requireApproval").default(true).notNull(),
  scopeRestrictions: json("scopeRestrictions"), // string[]
  // Status
  status: mysqlEnum("validationRunStatus", ["pending", "running", "completed", "failed", "cancelled"]).default("pending").notNull(),
  // Results summary
  totalCandidates: int("totalCandidates").default(0).notNull(),
  validated: int("validatedCount").default(0).notNull(),
  notVulnerable: int("notVulnerableCount").default(0).notNull(),
  inconclusive: int("inconclusiveCount").default(0).notNull(),
  errors: int("errorCount").default(0).notNull(),
  skipped: int("skippedCount").default(0).notNull(),
  avgScoreAdjustment: double("avgScoreAdjustment").default(0),
  // Audit
  operatorId: varchar("validationOperatorId", { length: 255 }).notNull(),
  startedAt: timestamp("validationStartedAt").defaultNow().notNull(),
  completedAt: timestamp("validationCompletedAt"),
  totalDurationMs: int("totalDurationMs"),
  errorMessage: text("validationRunError"),
});
export type ValidationRun = typeof validationRuns.$inferSelect;
export type InsertValidationRun = typeof validationRuns.$inferInsert;

/**
 * Autonomous Validation Engine — Individual Validation Results
 * Each row is a single candidate validation attempt with proof-of-exploit evidence
 */
export const validationResults = mysqlTable("validation_results", {
  id: int("id").autoincrement().primaryKey(),
  runId: int("validationRunId").notNull(), // Link to validation_runs
  assetId: int("validationAssetId").notNull(), // Link to discovered_assets
  // Target
  cveId: varchar("validationCveId", { length: 32 }).notNull(),
  hostname: varchar("validationHostname", { length: 255 }).notNull(),
  msfModule: varchar("validationMsfModule", { length: 512 }),
  // Result
  mode: mysqlEnum("resultMode", ["check_only", "auxiliary_scan", "safe_exploit"]).notNull(),
  status: mysqlEnum("validationResultStatus", ["pending", "running", "validated", "not_vulnerable", "inconclusive", "error", "skipped", "approved_pending"]).default("pending").notNull(),
  exploitable: boolean("exploitable").default(false).notNull(),
  // Evidence
  rawOutput: text("validationRawOutput"),
  evidence: json("validationEvidence"), // ValidationEvidence JSON
  // Scoring
  scoreAdjustment: double("scoreAdjustment").default(0),
  previousRiskScore: double("previousRiskScore"),
  newRiskScore: double("newRiskScore"),
  // Timing
  durationMs: int("validationDurationMs"),
  errorMessage: text("validationResultError"),
  // Evidence artifacts (S3 URLs)
  evidenceUrl: text("evidenceUrl"), // Primary evidence report URL
  evidenceArtifacts: json("evidenceArtifacts"), // Array of S3 artifact URLs
  // Audit
  createdAt: timestamp("validationResultCreatedAt").defaultNow().notNull(),
});
export type ValidationResult = typeof validationResults.$inferSelect;
export type InsertValidationResult = typeof validationResults.$inferInsert;


// ─── Session Recordings ──────────────────────────────────────────────────────

export const sessionRecordings = mysqlTable("session_recordings", {
  id: int("id").autoincrement().primaryKey(),
  serverId: int("serverId").notNull(),
  sessionId: varchar("sessionId", { length: 64 }).notNull(),
  sessionType: mysqlEnum("sessionType", ["shell", "meterpreter"]).notNull(),
  targetHost: varchar("targetHost", { length: 255 }),
  username: varchar("recordingUsername", { length: 255 }),
  platform: varchar("recordingPlatform", { length: 128 }),
  viaExploit: varchar("viaExploit", { length: 512 }),
  status: mysqlEnum("recordingStatus", ["recording", "completed", "error"]).default("recording").notNull(),
  totalChunks: int("totalChunks").default(0).notNull(),
  totalBytes: int("totalBytes").default(0).notNull(),
  durationMs: int("durationMs").default(0),
  startedAt: timestamp("recordingStartedAt").defaultNow().notNull(),
  completedAt: timestamp("recordingCompletedAt"),
  createdBy: varchar("recordingCreatedBy", { length: 64 }),
});
export type SessionRecording = typeof sessionRecordings.$inferSelect;
export type InsertSessionRecording = typeof sessionRecordings.$inferInsert;

export const recordingChunks = mysqlTable("recording_chunks", {
  id: int("id").autoincrement().primaryKey(),
  recordingId: int("recordingId").notNull(),
  chunkIndex: int("chunkIndex").notNull(),
  chunkType: mysqlEnum("chunkType", ["input", "output", "system"]).default("output").notNull(),
  content: text("chunkContent").notNull(),
  timestampMs: int("timestampMs").notNull(), // ms offset from recording start
  createdAt: timestamp("chunkCreatedAt").defaultNow().notNull(),
});
export type RecordingChunk = typeof recordingChunks.$inferSelect;
export type InsertRecordingChunk = typeof recordingChunks.$inferInsert;

// ─── Post-Exploitation Playbooks ─────────────────────────────────────────────

export const postExploitPlaybooks = mysqlTable("post_exploit_playbooks", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("playbookName", { length: 255 }).notNull(),
  description: text("playbookDescription"),
  category: mysqlEnum("playbookCategory", ["recon", "credential", "persistence", "lateral", "exfil", "cleanup", "custom"]).default("custom").notNull(),
  targetSessionType: mysqlEnum("targetSessionType", ["shell", "meterpreter", "both"]).default("both").notNull(),
  commands: json("playbookCommands").notNull(), // Array of { command: string, description: string, delayMs: number }
  autoTrigger: boolean("autoTrigger").default(false).notNull(),
  autoTriggerFilter: json("autoTriggerFilter"), // { platform?: string, arch?: string, exploit?: string }
  isBuiltIn: boolean("isBuiltIn").default(false).notNull(),
  enabled: boolean("playbookEnabled").default(true).notNull(),
  createdBy: varchar("playbookCreatedBy", { length: 64 }),
  createdAt: timestamp("playbookCreatedAt").defaultNow().notNull(),
  updatedAt: timestamp("playbookUpdatedAt").defaultNow().onUpdateNow().notNull(),
});
export type PostExploitPlaybook = typeof postExploitPlaybooks.$inferSelect;
export type InsertPostExploitPlaybook = typeof postExploitPlaybooks.$inferInsert;

export const postExploitExecutions = mysqlTable("post_exploit_executions", {
  id: int("id").autoincrement().primaryKey(),
  playbookId: int("pePlaybookId").notNull(),
  serverId: int("peServerId").notNull(),
  sessionId: varchar("peSessionId", { length: 64 }).notNull(),
  status: mysqlEnum("peStatus", ["pending", "running", "completed", "failed", "aborted"]).default("pending").notNull(),
  currentStep: int("peCurrentStep").default(0).notNull(),
  totalSteps: int("peTotalSteps").notNull(),
  output: json("peOutput"), // Array of { step: number, command: string, output: string, status: string, durationMs: number }
  errorMessage: text("peErrorMessage"),
  startedAt: timestamp("peStartedAt").defaultNow().notNull(),
  completedAt: timestamp("peCompletedAt"),
  triggeredBy: mysqlEnum("peTriggeredBy", ["manual", "auto"]).default("manual").notNull(),
  createdBy: varchar("peCreatedBy", { length: 64 }),
});
export type PostExploitExecution = typeof postExploitExecutions.$inferSelect;
export type InsertPostExploitExecution = typeof postExploitExecutions.$inferInsert;

// ─── File Transfers ──────────────────────────────────────────────────────────

export const fileTransfers = mysqlTable("file_transfers", {
  id: int("id").autoincrement().primaryKey(),
  serverId: int("transferServerId").notNull(),
  sessionId: varchar("transferSessionId", { length: 64 }).notNull(),
  direction: mysqlEnum("transferDirection", ["upload", "download"]).notNull(),
  remotePath: varchar("remotePath", { length: 1024 }).notNull(),
  fileName: varchar("transferFileName", { length: 255 }).notNull(),
  fileSize: int("fileSize"),
  mimeType: varchar("transferMimeType", { length: 128 }),
  s3Key: varchar("s3Key", { length: 512 }),
  s3Url: text("s3Url"),
  status: mysqlEnum("transferStatus", ["pending", "in_progress", "completed", "failed"]).default("pending").notNull(),
  errorMessage: text("transferErrorMessage"),
  createdBy: varchar("transferCreatedBy", { length: 64 }),
  createdAt: timestamp("transferCreatedAt").defaultNow().notNull(),
  completedAt: timestamp("transferCompletedAt"),
});
export type FileTransfer = typeof fileTransfers.$inferSelect;
export type InsertFileTransfer = typeof fileTransfers.$inferInsert;


// ─── Generated Payloads (msfvenom) ──────────────────────────────────────────
export const generatedPayloads = mysqlTable("generated_payloads", {
  id: int("id").primaryKey().autoincrement(),
  serverId: int("server_id").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  payload: varchar("payload_type", { length: 255 }).notNull(), // e.g. windows/meterpreter/reverse_tcp
  format: varchar("format", { length: 50 }).notNull(), // exe, elf, apk, ps1, py, raw, dll, macho
  lhost: varchar("lhost", { length: 255 }).notNull(),
  lport: int("lport").notNull(),
  encoder: varchar("encoder", { length: 255 }), // e.g. x86/shikata_ga_nai
  iterations: int("iterations").default(1),
  arch: varchar("arch", { length: 50 }), // x86, x64
  platform: varchar("platform", { length: 50 }), // windows, linux, osx, android
  extraOptions: text("extra_options"), // JSON string of additional msfvenom options
  msfvenomCommand: text("msfvenom_command"), // The full command that was run
  status: mysqlEnum("status", ["pending", "generating", "completed", "failed"]).default("pending").notNull(),
  errorMessage: text("error_message"),
  fileKey: varchar("file_key", { length: 500 }), // S3 key
  fileUrl: varchar("file_url", { length: 1000 }), // S3 URL
  fileSize: int("file_size"), // bytes
  fileSha256: varchar("file_sha256", { length: 64 }), // SHA256 hash
  createdBy: int("created_by"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});
export type GeneratedPayload = typeof generatedPayloads.$inferSelect;
export type InsertGeneratedPayload = typeof generatedPayloads.$inferInsert;


// ═══════════════════════════════════════════════════════════════════════
// SIEM/EDR EVASION ENGINE TABLES
// ═══════════════════════════════════════════════════════════════════════

/**
 * Evasion test sessions — each run of the mutation engine or scorecard
 */
export const evasionSessions = mysqlTable("evasion_sessions", {
  id: int("id").autoincrement().primaryKey(),
  /** Link to a campaign or scan */
  campaignId: varchar("campaign_id", { length: 255 }),
  /** Session type */
  sessionType: mysqlEnum("session_type", ["mutation_test", "pipeline_config", "scorecard", "purple_cycle"]).notNull(),
  /** ATT&CK techniques tested (JSON array of strings) */
  techniques: json("techniques"),
  /** Evasion profile used */
  evasionProfile: mysqlEnum("evasion_profile", ["none", "low", "medium", "high"]).default("none"),
  /** Campaign stealth score (0-100) */
  stealthScore: int("stealth_score"),
  /** Stealth band classification */
  stealthBand: varchar("stealth_band", { length: 20 }),
  /** Detection coverage percentage */
  detectionCoverage: int("detection_coverage"),
  /** Evasion success rate percentage */
  evasionSuccessRate: int("evasion_success_rate"),
  /** Full scorecard result (JSON) */
  scorecardData: json("scorecard_data"),
  /** Full mutation results (JSON) */
  mutationData: json("mutation_data"),
  /** Full pipeline config (JSON) */
  pipelineData: json("pipeline_data"),
  /** Purple team cycle data (JSON) */
  purpleCycleData: json("purple_cycle_data"),
  /** Summary stats */
  totalTechniques: int("total_techniques"),
  detectedCount: int("detected_count"),
  evadedCount: int("evaded_count"),
  partialCount: int("partial_count"),
  untestedCount: int("untested_count"),
  totalRules: int("total_rules"),
  robustRules: int("robust_rules"),
  fragileRules: int("fragile_rules"),
  criticalGaps: int("critical_gaps"),
  /** Status */
  status: mysqlEnum("status", ["running", "completed", "failed"]).default("running").notNull(),
  errorMessage: text("error_message"),
  /** Ownership */
  createdBy: int("created_by"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});
export type EvasionSession = typeof evasionSessions.$inferSelect;
export type InsertEvasionSession = typeof evasionSessions.$inferInsert;

/**
 * Individual rule robustness test results
 */
export const ruleRobustnessResults = mysqlTable("rule_robustness_results", {
  id: int("id").autoincrement().primaryKey(),
  sessionId: int("session_id").notNull(),
  /** Rule identifier */
  ruleId: varchar("rule_id", { length: 255 }).notNull(),
  ruleTitle: varchar("rule_title", { length: 500 }),
  /** The original command tested */
  originalCommand: text("original_command"),
  /** Detection pattern tested against */
  detectionPattern: text("detection_pattern"),
  /** Robustness score (0-100) */
  robustnessScore: int("robustness_score"),
  /** Robustness classification */
  robustnessClass: mysqlEnum("robustness_class", ["robust", "moderate", "fragile", "bypassed"]),
  /** Variant counts */
  totalVariants: int("total_variants"),
  detectedCount: int("detected_count"),
  evadedCount: int("evaded_count"),
  /** Weakest mutation categories (JSON array) */
  weakestCategories: json("weakest_categories"),
  /** Hardening tips (JSON array) */
  hardeningTips: json("hardening_tips"),
  /** Full variant details (JSON) */
  variantDetails: json("variant_details"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});
export type RuleRobustnessResult = typeof ruleRobustnessResults.$inferSelect;
export type InsertRuleRobustnessResult = typeof ruleRobustnessResults.$inferInsert;

/**
 * SIEM Connections — Wazuh / Elastic configuration
 */
export const siemConnections = mysqlTable("siem_connections", {
  id: int("id").autoincrement().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  backend: mysqlEnum("backend", ["wazuh", "elastic"]).notNull(),
  baseUrl: varchar("base_url", { length: 512 }).notNull(),
  username: varchar("username", { length: 255 }),
  password: varchar("password", { length: 512 }),
  apiKey: varchar("api_key", { length: 512 }),
  insecure: boolean("insecure").default(false),
  timeoutMs: int("timeout_ms").default(15000),
  indexPattern: varchar("index_pattern", { length: 512 }),
  useSecurityDetections: boolean("use_security_detections").default(false),
  /** Connection status */
  connected: boolean("connected").default(false),
  enabled: boolean("enabled").default(true),
  lastTestedAt: timestamp("last_tested_at"),
  version: varchar("version", { length: 64 }),
  clusterName: varchar("cluster_name", { length: 255 }),
  alertCount: int("alert_count"),
  errorMessage: text("error_message"),
  /** Ownership */
  createdBy: int("created_by"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().onUpdateNow().notNull(),
});
export type SiemConnection = typeof siemConnections.$inferSelect;
export type InsertSiemConnection = typeof siemConnections.$inferInsert;


// ═══════════════════════════════════════════════════════════════════════════
// DARKWEB INTELLIGENCE PIPELINE — Self-contained feed ingestion & enrichment
// ═══════════════════════════════════════════════════════════════════════════

// ─── Underground Intel Events (unified event stream) ─────────────────────
/**
 * Unified event stream for all underground intelligence categories.
 * Each row is a normalized event from any darkweb source.
 */
export const undergroundIntelEvents = mysqlTable("underground_intel_events", {
  id: int("id").autoincrement().primaryKey(),
  category: mysqlEnum("uie_category", [
    "ransomware", "credential", "iab", "malware", "influence",
    "botnet", "phishing", "exploit", "data_leak", "other",
  ]).notNull(),
  source: varchar("uie_source", { length: 128 }).notNull(),
  sourceUrl: varchar("uie_source_url", { length: 1024 }),
  title: varchar("uie_title", { length: 512 }).notNull(),
  description: text("uie_description"),
  severity: mysqlEnum("uie_severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  confidence: int("uie_confidence").default(75),
  // IOC linkage
  iocType: varchar("uie_ioc_type", { length: 64 }),
  iocValue: text("uie_ioc_value"),
  // Actor linkage
  actorName: varchar("uie_actor_name", { length: 255 }),
  actorAliases: json("uie_actor_aliases"),
  // Victim / target
  victimName: varchar("uie_victim_name", { length: 512 }),
  victimSector: varchar("uie_victim_sector", { length: 128 }),
  victimCountry: varchar("uie_victim_country", { length: 128 }),
  // MITRE mapping
  mitreTechniques: json("uie_mitre_techniques"),
  // Enrichment
  enriched: boolean("uie_enriched").default(false),
  enrichmentData: json("uie_enrichment_data"),
  // Tags & metadata
  tags: json("uie_tags"),
  rawData: json("uie_raw_data"),
  eventDate: timestamp("uie_event_date"),
  ingestedAt: timestamp("uie_ingested_at").defaultNow().notNull(),
  createdAt: timestamp("uie_created_at").defaultNow().notNull(),
  updatedAt: timestamp("uie_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type UndergroundIntelEvent = typeof undergroundIntelEvents.$inferSelect;
export type InsertUndergroundIntelEvent = typeof undergroundIntelEvents.$inferInsert;

// ─── Network Events (C2, botnet, malicious infrastructure) ───────────────
export const networkEvents = mysqlTable("network_events", {
  id: int("id").autoincrement().primaryKey(),
  eventType: mysqlEnum("ne_event_type", [
    "c2_server", "botnet_controller", "malicious_ip", "tor_exit_node",
    "proxy_node", "vpn_endpoint", "dns_sinkhole", "fast_flux",
    "ssl_blacklist", "spam_source", "scanner", "other",
  ]).notNull(),
  source: varchar("ne_source", { length: 128 }).notNull(),
  ipAddress: varchar("ne_ip_address", { length: 45 }),
  port: int("ne_port"),
  hostname: varchar("ne_hostname", { length: 512 }),
  protocol: varchar("ne_protocol", { length: 32 }),
  malwareFamily: varchar("ne_malware_family", { length: 255 }),
  description: text("ne_description"),
  severity: mysqlEnum("ne_severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  confidence: int("ne_confidence").default(75),
  // GeoIP
  country: varchar("ne_country", { length: 128 }),
  asn: varchar("ne_asn", { length: 64 }),
  asnOrg: varchar("ne_asn_org", { length: 255 }),
  // Status
  status: mysqlEnum("ne_status", ["active", "inactive", "sinkholed", "takedown"]).default("active"),
  firstSeen: timestamp("ne_first_seen"),
  lastSeen: timestamp("ne_last_seen"),
  tags: json("ne_tags"),
  rawData: json("ne_raw_data"),
  createdAt: timestamp("ne_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ne_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type NetworkEvent = typeof networkEvents.$inferSelect;
export type InsertNetworkEvent = typeof networkEvents.$inferInsert;

// ─── IAB Activity (Initial Access Broker listings) ───────────────────────
export const iabActivity = mysqlTable("iab_activity", {
  id: int("id").autoincrement().primaryKey(),
  brokerId: varchar("iab_broker_id", { length: 128 }).notNull(),
  brokerName: varchar("iab_broker_name", { length: 255 }).notNull(),
  listingType: mysqlEnum("iab_listing_type", [
    "vpn_access", "rdp_access", "citrix_access", "webshell",
    "domain_admin", "cloud_access", "email_access", "database_access",
    "zero_day", "exploit_kit", "credential_dump", "other",
  ]).notNull(),
  accessType: varchar("iab_access_type", { length: 255 }),
  description: text("iab_description"),
  // Victim / target
  victimName: varchar("iab_victim_name", { length: 512 }),
  victimSector: varchar("iab_victim_sector", { length: 128 }),
  victimCountry: varchar("iab_victim_country", { length: 128 }),
  victimRevenue: varchar("iab_victim_revenue", { length: 64 }),
  // Pricing
  askingPrice: varchar("iab_asking_price", { length: 64 }),
  currency: varchar("iab_currency", { length: 16 }).default("USD"),
  // Attribution
  forumSource: varchar("iab_forum_source", { length: 255 }),
  linkedRansomwareGroups: json("iab_linked_rw_groups"),
  mitreTechniques: json("iab_mitre_techniques"),
  // Status
  status: mysqlEnum("iab_status", ["active", "sold", "expired", "removed", "law_enforcement"]).default("active"),
  confidence: int("iab_confidence").default(75),
  firstSeen: timestamp("iab_first_seen"),
  lastActive: timestamp("iab_last_active"),
  tags: json("iab_tags"),
  rawData: json("iab_raw_data"),
  createdAt: timestamp("iab_created_at").defaultNow().notNull(),
  updatedAt: timestamp("iab_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type IabActivityRow = typeof iabActivity.$inferSelect;
export type InsertIabActivity = typeof iabActivity.$inferInsert;

// ─── Influence Operations ────────────────────────────────────────────────
export const influenceOperations = mysqlTable("influence_operations", {
  id: int("id").autoincrement().primaryKey(),
  operationName: varchar("io_operation_name", { length: 512 }).notNull(),
  attributedTo: varchar("io_attributed_to", { length: 255 }),
  nationState: varchar("io_nation_state", { length: 128 }),
  description: text("io_description"),
  // Targeting
  targetCountries: json("io_target_countries"),
  targetSectors: json("io_target_sectors"),
  targetNarratives: json("io_target_narratives"),
  // Platforms
  platforms: json("io_platforms"),
  // Techniques
  techniques: json("io_techniques"),
  mitreTechniques: json("io_mitre_techniques"),
  // Scale
  accountsIdentified: int("io_accounts_identified").default(0),
  contentPieces: int("io_content_pieces").default(0),
  // Source
  source: varchar("io_source", { length: 255 }),
  sourceUrl: varchar("io_source_url", { length: 1024 }),
  reportDate: timestamp("io_report_date"),
  // Status
  status: mysqlEnum("io_status", ["active", "disrupted", "dormant", "attributed"]).default("active"),
  confidence: int("io_confidence").default(75),
  tags: json("io_tags"),
  rawData: json("io_raw_data"),
  createdAt: timestamp("io_created_at").defaultNow().notNull(),
  updatedAt: timestamp("io_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type InfluenceOperation = typeof influenceOperations.$inferSelect;
export type InsertInfluenceOperation = typeof influenceOperations.$inferInsert;

// ─── Credential Exposures ────────────────────────────────────────────────
export const credentialExposures = mysqlTable("credential_exposures", {
  id: int("id").autoincrement().primaryKey(),
  source: varchar("ce_source", { length: 128 }).notNull(),
  breachName: varchar("ce_breach_name", { length: 512 }).notNull(),
  breachDate: timestamp("ce_breach_date"),
  // Scope
  domain: varchar("ce_domain", { length: 512 }),
  emailCount: int("ce_email_count").default(0),
  totalRecords: int("ce_total_records").default(0),
  // Data types exposed
  dataClasses: json("ce_data_classes"),
  // Attribution
  actorName: varchar("ce_actor_name", { length: 255 }),
  // Severity
  severity: mysqlEnum("ce_severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  isVerified: boolean("ce_is_verified").default(false),
  isSensitive: boolean("ce_is_sensitive").default(false),
  isRetired: boolean("ce_is_retired").default(false),
  isSpamList: boolean("ce_is_spam_list").default(false),
  // Source metadata
  sourceUrl: varchar("ce_source_url", { length: 1024 }),
  description: text("ce_description"),
  tags: json("ce_tags"),
  rawData: json("ce_raw_data"),
  createdAt: timestamp("ce_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ce_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type CredentialExposure = typeof credentialExposures.$inferSelect;
export type InsertCredentialExposure = typeof credentialExposures.$inferInsert;

// ─── Darkweb Enriched Records (LLM-enriched intel) ──────────────────────
export const darkwebEnrichedRecords = mysqlTable("darkweb_enriched_records", {
  id: int("id").autoincrement().primaryKey(),
  sourceEventId: int("der_source_event_id"),
  sourceTable: varchar("der_source_table", { length: 128 }),
  // LLM enrichment output
  summary: text("der_summary"),
  threatAssessment: text("der_threat_assessment"),
  riskScore: int("der_risk_score").default(0),
  impactAnalysis: text("der_impact_analysis"),
  recommendedActions: json("der_recommended_actions"),
  // Cross-references
  relatedActors: json("der_related_actors"),
  relatedCampaigns: json("der_related_campaigns"),
  relatedCves: json("der_related_cves"),
  relatedIocs: json("der_related_iocs"),
  // MITRE mapping
  mitreTactics: json("der_mitre_tactics"),
  mitreTechniques: json("der_mitre_techniques"),
  // Sector / geo impact
  affectedSectors: json("der_affected_sectors"),
  affectedCountries: json("der_affected_countries"),
  // Metadata
  enrichmentModel: varchar("der_enrichment_model", { length: 128 }),
  enrichmentVersion: varchar("der_enrichment_version", { length: 32 }),
  processingTimeMs: int("der_processing_time_ms"),
  createdAt: timestamp("der_created_at").defaultNow().notNull(),
  updatedAt: timestamp("der_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type DarkwebEnrichedRecord = typeof darkwebEnrichedRecords.$inferSelect;
export type InsertDarkwebEnrichedRecord = typeof darkwebEnrichedRecords.$inferInsert;

// ─── Darkweb Feed Registry (feed source health tracking) ────────────────
export const darkwebFeedRegistry = mysqlTable("darkweb_feed_registry", {
  id: int("id").autoincrement().primaryKey(),
  feedName: varchar("dfr_feed_name", { length: 255 }).notNull().unique(),
  feedUrl: varchar("dfr_feed_url", { length: 1024 }).notNull(),
  feedType: mysqlEnum("dfr_feed_type", [
    "ioc", "malware", "ransomware", "credential", "phishing",
    "botnet", "c2", "blocklist", "vulnerability", "influence", "other",
  ]).notNull(),
  provider: varchar("dfr_provider", { length: 255 }),
  description: text("dfr_description"),
  // Auth
  requiresAuth: boolean("dfr_requires_auth").default(false),
  authType: mysqlEnum("dfr_auth_type", ["none", "api_key", "bearer", "basic", "custom"]).default("none"),
  authEnvVar: varchar("dfr_auth_env_var", { length: 128 }),
  // Schedule
  syncInterval: varchar("dfr_sync_interval", { length: 32 }).default("daily"),
  lastSyncAt: timestamp("dfr_last_sync_at"),
  nextSyncAt: timestamp("dfr_next_sync_at"),
  // Health
  status: mysqlEnum("dfr_status", ["active", "degraded", "down", "disabled", "pending"]).default("pending"),
  lastError: text("dfr_last_error"),
  consecutiveFailures: int("dfr_consecutive_failures").default(0),
  totalSyncs: int("dfr_total_syncs").default(0),
  totalRecordsFetched: int("dfr_total_records_fetched").default(0),
  avgResponseTimeMs: int("dfr_avg_response_time_ms"),
  // Metadata
  isBuiltIn: boolean("dfr_is_built_in").default(true),
  enabled: boolean("dfr_enabled").default(true),
  config: json("dfr_config"),
  createdAt: timestamp("dfr_created_at").defaultNow().notNull(),
  updatedAt: timestamp("dfr_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type DarkwebFeedRegistryRow = typeof darkwebFeedRegistry.$inferSelect;
export type InsertDarkwebFeedRegistry = typeof darkwebFeedRegistry.$inferInsert;

// ─── Ransomware Affiliates ───────────────────────────────────────────────
export const ransomwareAffiliates = mysqlTable("ransomware_affiliates", {
  id: int("id").autoincrement().primaryKey(),
  affiliateId: varchar("ra_affiliate_id", { length: 128 }).notNull(),
  affiliateName: varchar("ra_affiliate_name", { length: 255 }).notNull(),
  aliases: json("ra_aliases"),
  description: text("ra_description"),
  // Group affiliations
  primaryGroup: varchar("ra_primary_group", { length: 255 }),
  affiliatedGroups: json("ra_affiliated_groups"),
  // Activity
  activityScore: int("ra_activity_score").default(0),
  totalVictims: int("ra_total_victims").default(0),
  topSectors: json("ra_top_sectors"),
  topCountries: json("ra_top_countries"),
  // TTPs
  mitreTechniques: json("ra_mitre_techniques"),
  preferredAccess: varchar("ra_preferred_access", { length: 255 }),
  toolsUsed: json("ra_tools_used"),
  // Status
  status: mysqlEnum("ra_status", ["active", "inactive", "arrested", "unknown"]).default("active"),
  confidence: int("ra_confidence").default(75),
  firstSeen: varchar("ra_first_seen", { length: 32 }),
  lastActive: varchar("ra_last_active", { length: 32 }),
  tags: json("ra_tags"),
  rawData: json("ra_raw_data"),
  createdAt: timestamp("ra_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ra_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type RansomwareAffiliate = typeof ransomwareAffiliates.$inferSelect;
export type InsertRansomwareAffiliate = typeof ransomwareAffiliates.$inferInsert;


// ─── Threat Intel Training Pipeline ─────────────────────────────────────

/**
 * Ingested incident reports from DFIR Report, CISA advisories, vendor reports, etc.
 * Raw source material for LLM training on attack sequences and TTPs.
 */
export const incidentReports = mysqlTable("incident_reports", {
  id: int("id").autoincrement().primaryKey(),
  sourceId: varchar("sourceId", { length: 255 }).notNull(), // unique ID from source (URL hash, advisory ID, etc.)
  source: varchar("source", { length: 64 }).notNull(), // dfir_report, cisa_advisory, unit42, hacker_news, dark_reading, cyberscoop, cybersecurity_dive, wikipedia_breaches, hhs_ocr, misp
  title: text("title").notNull(),
  url: text("url"),
  publishedAt: varchar("publishedAt", { length: 64 }),
  // Content
  summary: text("summary"),
  fullContent: text("fullContent"), // raw extracted text
  // Extracted intelligence
  attackSequence: json("attackSequence"), // ordered array of { phase, technique, techniqueId, description, tools, duration }
  ttpsExtracted: json("ttpsExtracted"), // { techniqueId, techniqueName, tactic, confidence }[]
  iocsExtracted: json("iocsExtracted"), // { type, value, context }[]
  actorsIdentified: json("actorsIdentified"), // { name, aliases, type, confidence }[]
  malwareIdentified: json("malwareIdentified"), // string[]
  cvesMentioned: json("cvesMentioned"), // string[]
  targetSectors: json("targetSectors"), // string[]
  targetCountries: json("targetCountries"), // string[]
  // LLM analysis
  attackNarrative: text("attackNarrative"), // LLM-generated narrative of the attack flow
  lessonsLearned: text("lessonsLearned"), // What defenders should take away
  emulationGuidance: text("emulationGuidance"), // How to emulate this attack in Caldera
  exploitContext: json("exploitContext"), // { cve, exploitType, targetProduct, patchAvailable, weaponized }[]
  // Classification
  incidentType: varchar("incidentType", { length: 64 }), // ransomware, apt, data_breach, supply_chain, phishing, etc.
  severity: mysqlEnum("ir_severity", ["critical", "high", "medium", "low"]).default("medium"),
  // Processing status
  status: mysqlEnum("ir_status", ["raw", "extracted", "enriched", "training_ready"]).default("raw"),
  enrichedAt: timestamp("ir_enriched_at"),
  createdAt: timestamp("ir_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ir_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type IncidentReport = typeof incidentReports.$inferSelect;
export type InsertIncidentReport = typeof incidentReports.$inferInsert;

/**
 * Attack sequence templates derived from real incidents.
 * Used by the chain builder and campaign recommendation engine.
 */
export const attackSequenceTemplates = mysqlTable("attack_sequence_templates", {
  id: int("id").autoincrement().primaryKey(),
  templateId: varchar("templateId", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  // Source incident(s)
  sourceIncidentIds: json("sourceIncidentIds"), // int[] referencing incidentReports.id
  sourceActors: json("sourceActors"), // string[] actor names
  // Attack sequence
  phases: json("phases"), // ordered array of { order, tactic, techniques: { id, name, tools, commands }[], duration, description }
  totalPhases: int("totalPhases"),
  // Classification
  attackType: varchar("attackType", { length: 64 }), // ransomware, apt_espionage, data_theft, supply_chain, etc.
  complexity: mysqlEnum("ast_complexity", ["basic", "intermediate", "advanced", "nation-state"]).default("intermediate"),
  targetEnvironment: varchar("targetEnvironment", { length: 128 }), // windows_ad, linux_cloud, hybrid, ot_ics, etc.
  targetSectors: json("ast_targetSectors"), // string[]
  // Caldera mapping
  calderaAbilities: json("ast_calderaAbilities"), // { abilityId, name, phase, executor }[]
  calderaAdversaryProfile: json("calderaAdversaryProfile"), // { name, atomicOrdering, objectives }
  // Evasion intelligence
  detectionDifficulty: int("detectionDifficulty"), // 1-10
  commonDetections: json("commonDetections"), // string[] Sigma rule names that detect this sequence
  evasionTechniques: json("evasionTechniques"), // string[] techniques used for evasion
  // Metrics
  avgDwellTime: varchar("avgDwellTime", { length: 64 }), // average time from initial access to objective
  successRate: double("successRate"), // from real-world data
  useCount: int("useCount").default(0), // how many times this template has been used
  // Metadata
  confidence: int("ast_confidence"), // 0-100
  status: mysqlEnum("ast_status", ["draft", "validated", "production"]).default("draft"),
  createdAt: timestamp("ast_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ast_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type AttackSequenceTemplate = typeof attackSequenceTemplates.$inferSelect;
export type InsertAttackSequenceTemplate = typeof attackSequenceTemplates.$inferInsert;

/**
 * Exploit intelligence database — maps CVEs to real-world exploitation context.
 */
export const exploitIntelligence = mysqlTable("exploit_intelligence", {
  id: int("id").autoincrement().primaryKey(),
  cveId: varchar("cveId", { length: 32 }).notNull(),
  // Exploit details
  exploitType: varchar("exploitType", { length: 64 }), // rce, lpe, sqli, xss, auth_bypass, etc.
  targetProduct: varchar("targetProduct", { length: 255 }),
  targetVersion: varchar("targetVersion", { length: 128 }),
  // Weaponization
  weaponized: boolean("weaponized").default(false),
  publicExploitUrl: text("publicExploitUrl"), // GitHub, ExploitDB, etc.
  metasploitModule: varchar("metasploitModule", { length: 255 }),
  nucleiTemplate: varchar("nucleiTemplate", { length: 255 }),
  // Real-world usage
  usedByActors: json("usedByActors"), // string[] actor names
  usedInIncidents: json("usedInIncidents"), // int[] referencing incidentReports.id
  firstExploitedInWild: varchar("firstExploitedInWild", { length: 64 }),
  // Attack context
  attackPhase: varchar("attackPhase", { length: 64 }), // initial_access, privilege_escalation, etc.
  prerequisites: json("ei_prerequisites"), // string[] what's needed before this exploit
  postExploitActions: json("postExploitActions"), // string[] what typically follows
  // Scoring
  cvssScore: double("cvssScore"),
  epssScore: double("epssScore"),
  cisaKev: boolean("cisaKev").default(false),
  // Metadata
  source: varchar("ei_source", { length: 64 }), // cisa_kev, nvd, exploitdb, incident_report, osint
  confidence: int("ei_confidence"),
  createdAt: timestamp("ei_created_at").defaultNow().notNull(),
  updatedAt: timestamp("ei_updated_at").defaultNow().onUpdateNow().notNull(),
});
export type ExploitIntelligence = typeof exploitIntelligence.$inferSelect;
export type InsertExploitIntelligence = typeof exploitIntelligence.$inferInsert;

// ─── Validation Schedules ───────────────────────────────────────────────────
export const validationSchedules = mysqlTable("validation_schedules", {
  id: int("id").primaryKey().autoincrement(),
  name: varchar("name", { length: 255 }).notNull(),
  scheduleType: varchar("schedule_type", { length: 50 }).notNull(),
  targetId: varchar("target_id", { length: 255 }),
  targetLabel: varchar("target_label", { length: 255 }),
  intervalHours: int("interval_hours").notNull().default(168),
  cronExpression: varchar("cron_expression", { length: 100 }),
  enabled: boolean("enabled").notNull().default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  lastStatus: varchar("last_status", { length: 50 }),
  lastError: text("last_error"),
  runCount: int("run_count").notNull().default(0),
  config: json("config"),
  createdBy: varchar("created_by", { length: 255 }),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});


// ============================================================
// Cloud-Native Attack Paths
// ============================================================

export const cloudProviders = mysqlTable("cloud_providers", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  provider: mysqlEnum("provider", ["aws", "azure", "gcp"]).notNull(),
  accountId: varchar("account_id", { length: 255 }).notNull(),
  accountAlias: varchar("account_alias", { length: 255 }),
  region: varchar("region", { length: 64 }),
  status: mysqlEnum("status", ["active", "inactive", "scanning"]).default("active").notNull(),
  lastScanAt: timestamp("last_scan_at"),
  config: json("config"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const cloudIdentities = mysqlTable("cloud_identities", {
  id: int("id").autoincrement().primaryKey(),
  providerId: int("provider_id").notNull(),
  identityType: mysqlEnum("identity_type", ["user", "role", "service_account", "group", "app_registration"]).notNull(),
  arn: varchar("arn", { length: 512 }),
  name: varchar("name", { length: 255 }).notNull(),
  email: varchar("email", { length: 320 }),
  isPrivileged: boolean("is_privileged").default(false),
  lastActivity: timestamp("last_activity"),
  permissions: json("permissions"),
  policies: json("policies"),
  metadata: json("metadata"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const cloudAttackPaths = mysqlTable("cloud_attack_paths", {
  id: int("id").autoincrement().primaryKey(),
  providerId: int("provider_id").notNull(),
  engagementId: int("engagement_id"),
  pathName: varchar("path_name", { length: 255 }).notNull(),
  attackType: mysqlEnum("attack_type", [
    "privilege_escalation", "role_chaining", "cross_account",
    "service_account_impersonation", "org_policy_bypass",
    "consent_grant_abuse", "app_registration_abuse", "pim_escalation",
    "s3_public_access", "storage_misconfiguration", "iam_misconfiguration",
    "lateral_movement", "data_exfiltration"
  ]).notNull(),
  provider: mysqlEnum("cloud_provider", ["aws", "azure", "gcp"]).notNull(),
  sourceIdentity: varchar("source_identity", { length: 512 }),
  targetResource: varchar("target_resource", { length: 512 }),
  pathNodes: json("path_nodes"),
  riskScore: double("risk_score"),
  severity: mysqlEnum("severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  description: text("description"),
  mitreTechniques: json("mitre_techniques"),
  remediationSteps: json("remediation_steps"),
  status: mysqlEnum("path_status", ["open", "exploited", "mitigated", "accepted"]).default("open"),
  exploitedAt: timestamp("exploited_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const cloudMisconfigurations = mysqlTable("cloud_misconfigurations", {
  id: int("id").autoincrement().primaryKey(),
  providerId: int("provider_id").notNull(),
  resourceType: varchar("resource_type", { length: 128 }).notNull(),
  resourceArn: varchar("resource_arn", { length: 512 }),
  resourceName: varchar("resource_name", { length: 255 }),
  misconfigType: varchar("misconfig_type", { length: 128 }).notNull(),
  severity: mysqlEnum("misconfig_severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  description: text("description"),
  currentValue: text("current_value"),
  expectedValue: text("expected_value"),
  remediationSteps: text("remediation_steps"),
  complianceFrameworks: json("compliance_frameworks"),
  status: mysqlEnum("misconfig_status", ["open", "remediated", "accepted", "false_positive"]).default("open"),
  createdAt: timestamp("created_at").defaultNow(),
});

// ============================================================
// Active Directory Attack Simulation
// ============================================================

export const adEnvironments = mysqlTable("ad_environments", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  domainName: varchar("domain_name", { length: 255 }).notNull(),
  domainController: varchar("domain_controller", { length: 255 }),
  forestName: varchar("forest_name", { length: 255 }),
  functionalLevel: varchar("functional_level", { length: 64 }),
  status: mysqlEnum("ad_status", ["connected", "disconnected", "scanning", "error"]).default("disconnected").notNull(),
  lastEnumAt: timestamp("last_enum_at"),
  connectionConfig: json("connection_config"),
  stats: json("stats"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const adObjects = mysqlTable("ad_objects", {
  id: int("id").autoincrement().primaryKey(),
  environmentId: int("environment_id").notNull(),
  objectType: mysqlEnum("object_type", ["user", "group", "computer", "gpo", "ou", "trust", "spn", "certificate_template"]).notNull(),
  distinguishedName: varchar("distinguished_name", { length: 1024 }),
  samAccountName: varchar("sam_account_name", { length: 255 }),
  displayName: varchar("display_name", { length: 255 }),
  isPrivileged: boolean("is_privileged").default(false),
  isEnabled: boolean("is_enabled").default(true),
  memberOf: json("member_of"),
  members: json("members"),
  properties: json("properties"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const adAttackSimulations = mysqlTable("ad_attack_simulations", {
  id: int("id").autoincrement().primaryKey(),
  environmentId: int("environment_id").notNull(),
  engagementId: int("engagement_id"),
  attackType: mysqlEnum("ad_attack_type", [
    "kerberoasting", "as_rep_roasting", "dcsync",
    "golden_ticket", "silver_ticket", "pass_the_hash",
    "pass_the_ticket", "overpass_the_hash", "skeleton_key",
    "dcshadow", "sid_history_injection", "gpo_abuse",
    "certificate_abuse", "constrained_delegation", "unconstrained_delegation",
    "resource_based_constrained_delegation", "ad_enumeration"
  ]).notNull(),
  targetObject: varchar("target_object", { length: 512 }),
  sourceObject: varchar("source_object", { length: 512 }),
  status: mysqlEnum("sim_status", ["pending", "running", "success", "failed", "blocked"]).default("pending").notNull(),
  riskScore: double("risk_score"),
  severity: mysqlEnum("ad_severity", ["critical", "high", "medium", "low"]).default("high"),
  description: text("description"),
  attackPath: json("attack_path"),
  prerequisites: json("prerequisites"),
  mitreTechniques: json("mitre_techniques"),
  evidence: json("evidence"),
  remediationSteps: json("remediation_steps"),
  detectedBy: json("detected_by"),
  executedAt: timestamp("executed_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const adAttackPaths = mysqlTable("ad_attack_paths", {
  id: int("id").autoincrement().primaryKey(),
  environmentId: int("environment_id").notNull(),
  pathName: varchar("path_name", { length: 255 }).notNull(),
  sourceNode: varchar("source_node", { length: 512 }).notNull(),
  targetNode: varchar("target_node", { length: 512 }).notNull(),
  pathLength: int("path_length"),
  pathNodes: json("path_nodes"),
  pathEdges: json("path_edges"),
  riskScore: double("risk_score"),
  isShortestPath: boolean("is_shortest_path").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

// ============================================================
// EDR Effectiveness Validation
// ============================================================

export const edrProducts = mysqlTable("edr_products", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  productName: varchar("product_name", { length: 255 }).notNull(),
  vendor: varchar("vendor", { length: 255 }).notNull(),
  version: varchar("version", { length: 64 }),
  deploymentType: mysqlEnum("deployment_type", ["endpoint", "network", "cloud", "hybrid"]).default("endpoint"),
  agentCount: int("agent_count"),
  config: json("config"),
  status: mysqlEnum("edr_status", ["active", "inactive", "testing"]).default("active").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const edrTestCatalog = mysqlTable("edr_test_catalog", {
  id: int("id").autoincrement().primaryKey(),
  testName: varchar("test_name", { length: 255 }).notNull(),
  category: mysqlEnum("test_category", [
    "process_injection", "credential_access", "defense_evasion",
    "lateral_movement", "persistence", "privilege_escalation",
    "command_and_control", "exfiltration", "execution",
    "discovery", "collection", "impact"
  ]).notNull(),
  mitreTechniqueId: varchar("mitre_technique_id", { length: 32 }),
  mitreTechniqueName: varchar("mitre_technique_name", { length: 255 }),
  description: text("description"),
  testBinaryType: mysqlEnum("binary_type", ["safe_mimikatz", "safe_injection", "safe_dump", "safe_lateral", "safe_persist", "safe_c2", "safe_exfil", "custom"]).default("custom"),
  testPayload: json("test_payload"),
  expectedBehavior: text("expected_behavior"),
  riskLevel: mysqlEnum("test_risk", ["safe", "low", "medium", "high"]).default("safe"),
  isBuiltin: boolean("is_builtin").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const edrTestResults = mysqlTable("edr_test_results", {
  id: int("id").autoincrement().primaryKey(),
  edrProductId: int("edr_product_id").notNull(),
  testCatalogId: int("test_catalog_id").notNull(),
  engagementId: int("engagement_id"),
  executionStatus: mysqlEnum("execution_status", ["pending", "running", "completed", "error"]).default("pending").notNull(),
  detectionResult: mysqlEnum("detection_result", ["detected", "missed", "partial", "delayed", "blocked"]),
  detectionTimeMs: int("detection_time_ms"),
  alertSeverity: varchar("alert_severity", { length: 32 }),
  alertTitle: varchar("alert_title", { length: 512 }),
  responseAction: varchar("response_action", { length: 255 }),
  falsePositive: boolean("false_positive").default(false),
  evidence: json("evidence"),
  notes: text("notes"),
  executedAt: timestamp("executed_at"),
  detectedAt: timestamp("detected_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const edrCoverageMatrix = mysqlTable("edr_coverage_matrix", {
  id: int("id").autoincrement().primaryKey(),
  edrProductId: int("edr_product_id").notNull(),
  mitreTacticId: varchar("mitre_tactic_id", { length: 32 }).notNull(),
  mitreTechniqueId: varchar("mitre_technique_id", { length: 32 }).notNull(),
  totalTests: int("total_tests").default(0),
  detected: int("detected").default(0),
  missed: int("missed").default(0),
  partial: int("partial").default(0),
  blocked: int("blocked").default(0),
  avgDetectionTimeMs: int("avg_detection_time_ms"),
  coverageScore: double("coverage_score"),
  lastTestedAt: timestamp("last_tested_at"),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// ============================================================
// Compliance Framework Mapping
// ============================================================

export const complianceFrameworks = mysqlTable("compliance_frameworks", {
  id: int("id").autoincrement().primaryKey(),
  frameworkName: varchar("framework_name", { length: 128 }).notNull(),
  frameworkVersion: varchar("framework_version", { length: 32 }),
  frameworkType: mysqlEnum("framework_type", ["soc2", "iso27001", "nist_csf", "pci_dss", "hipaa", "cis", "fedramp", "dod_stig", "cmmc", "custom"]).notNull(),
  description: text("description"),
  totalControls: int("total_controls"),
  controlHierarchy: json("control_hierarchy"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const complianceControls = mysqlTable("compliance_controls", {
  id: int("id").autoincrement().primaryKey(),
  frameworkId: int("framework_id").notNull(),
  controlId: varchar("control_id", { length: 64 }).notNull(),
  controlName: varchar("control_name", { length: 512 }).notNull(),
  controlDescription: text("control_description"),
  parentControlId: varchar("parent_control_id", { length: 64 }),
  category: varchar("category", { length: 255 }),
  subcategory: varchar("subcategory", { length: 255 }),
  implementationGuidance: text("implementation_guidance"),
  testProcedures: json("test_procedures"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const complianceMappings = mysqlTable("compliance_mappings", {
  id: int("id").autoincrement().primaryKey(),
  controlId: int("control_id").notNull(),
  engagementId: int("engagement_id"),
  findingType: varchar("finding_type", { length: 128 }),
  findingId: int("finding_id"),
  findingSource: mysqlEnum("finding_source", ["vulnerability", "misconfiguration", "attack_path", "edr_test", "pentest", "manual"]).notNull(),
  mappingStatus: mysqlEnum("mapping_status", ["covered", "gap", "partial", "not_applicable", "compensating"]).default("gap").notNull(),
  evidenceNotes: text("evidence_notes"),
  compensatingControl: text("compensating_control"),
  riskAcceptance: text("risk_acceptance"),
  assessedBy: varchar("assessed_by", { length: 255 }),
  assessedAt: timestamp("assessed_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const complianceReports = mysqlTable("compliance_reports", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  frameworkId: int("framework_id").notNull(),
  reportName: varchar("report_name", { length: 255 }).notNull(),
  totalControls: int("total_controls").default(0),
  coveredControls: int("covered_controls").default(0),
  gapControls: int("gap_controls").default(0),
  partialControls: int("partial_controls").default(0),
  naControls: int("na_controls").default(0),
  overallScore: double("overall_score"),
  reportData: json("report_data"),
  generatedBy: varchar("generated_by", { length: 255 }),
  createdAt: timestamp("created_at").defaultNow(),
});

// ============================================================
// API Security Testing
// ============================================================

export const apiTargets = mysqlTable("api_targets", {
  id: int("id").autoincrement().primaryKey(),
  engagementId: int("engagement_id"),
  name: varchar("api_name", { length: 255 }).notNull(),
  baseUrl: varchar("base_url", { length: 1024 }).notNull(),
  specType: mysqlEnum("spec_type", ["openapi_3", "openapi_2", "swagger", "graphql", "grpc", "manual"]).default("manual"),
  specUrl: varchar("spec_url", { length: 1024 }),
  specContent: json("spec_content"),
  authType: mysqlEnum("auth_type", ["none", "api_key", "bearer", "basic", "oauth2", "custom"]).default("none"),
  authConfig: json("auth_config"),
  totalEndpoints: int("total_endpoints").default(0),
  status: mysqlEnum("api_status", ["active", "inactive", "scanning"]).default("active").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const apiEndpoints = mysqlTable("api_endpoints", {
  id: int("id").autoincrement().primaryKey(),
  targetId: int("target_id").notNull(),
  method: mysqlEnum("http_method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).notNull(),
  path: varchar("endpoint_path", { length: 1024 }).notNull(),
  operationId: varchar("operation_id", { length: 255 }),
  summary: text("summary"),
  parameters: json("parameters"),
  requestBody: json("request_body"),
  responseSchemas: json("response_schemas"),
  authRequired: boolean("auth_required").default(false),
  rateLimited: boolean("rate_limited").default(false),
  deprecated: boolean("deprecated").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const apiSecurityTests = mysqlTable("api_security_tests", {
  id: int("id").autoincrement().primaryKey(),
  testName: varchar("api_test_name", { length: 255 }).notNull(),
  owaspCategory: mysqlEnum("owasp_category", [
    "API1_BOLA", "API2_BROKEN_AUTH", "API3_OBJECT_PROPERTY",
    "API4_UNRESTRICTED_CONSUMPTION", "API5_BROKEN_FUNCTION_AUTH",
    "API6_SERVER_SIDE_REQUEST_FORGERY", "API7_SECURITY_MISCONFIGURATION",
    "API8_LACK_OF_PROTECTION", "API9_IMPROPER_INVENTORY",
    "API10_UNSAFE_API_CONSUMPTION"
  ]).notNull(),
  description: text("api_test_description"),
  testType: mysqlEnum("test_type", ["automated", "semi_automated", "manual"]).default("automated"),
  testPayload: json("test_payload"),
  expectedResult: text("expected_result"),
  severity: mysqlEnum("api_test_severity", ["critical", "high", "medium", "low", "info"]).default("medium"),
  isBuiltin: boolean("is_builtin").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const apiTestResults = mysqlTable("api_test_results", {
  id: int("id").autoincrement().primaryKey(),
  endpointId: int("endpoint_id").notNull(),
  testId: int("test_id").notNull(),
  engagementId: int("engagement_id"),
  result: mysqlEnum("test_result", ["vulnerable", "secure", "error", "inconclusive", "skipped"]).default("inconclusive").notNull(),
  severity: mysqlEnum("result_severity", ["critical", "high", "medium", "low", "info"]),
  requestSent: json("request_sent"),
  responseReceived: json("response_received"),
  evidence: json("api_evidence"),
  notes: text("api_notes"),
  falsePositive: boolean("api_false_positive").default(false),
  executedAt: timestamp("executed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const apiFuzzingRuns = mysqlTable("api_fuzzing_runs", {
  id: int("id").autoincrement().primaryKey(),
  targetId: int("target_id").notNull(),
  engagementId: int("engagement_id"),
  fuzzType: mysqlEnum("fuzz_type", ["parameter_mutation", "injection", "auth_bypass", "rate_limit", "schema_violation"]).notNull(),
  status: mysqlEnum("fuzz_status", ["pending", "running", "completed", "error"]).default("pending").notNull(),
  totalRequests: int("total_requests").default(0),
  anomaliesFound: int("anomalies_found").default(0),
  errorsFound: int("errors_found").default(0),
  config: json("fuzz_config"),
  results: json("fuzz_results"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// ============================================================
// Cloud Provider Credentials (encrypted at-rest)
// ============================================================

export const cloudCredentials = mysqlTable("cloud_credentials", {
  id: int("id").autoincrement().primaryKey(),
  providerId: int("provider_id"),
  engagementId: int("engagement_id"),
  provider: mysqlEnum("cred_provider", ["aws", "azure", "gcp"]).notNull(),
  credentialName: varchar("credential_name", { length: 255 }).notNull(),
  credentialType: mysqlEnum("credential_type", [
    "aws_access_key", "aws_assume_role", "aws_session_token",
    "azure_client_secret", "azure_managed_identity", "azure_cli",
    "gcp_service_account_key", "gcp_workload_identity", "gcp_oauth"
  ]).notNull(),
  // Encrypted credential blob (AES-256-GCM)
  encryptedData: text("encrypted_data").notNull(),
  encryptionIv: varchar("encryption_iv", { length: 64 }).notNull(),
  encryptionTag: varchar("encryption_tag", { length: 64 }).notNull(),
  // Metadata (not encrypted)
  accountId: varchar("cred_account_id", { length: 255 }),
  region: varchar("cred_region", { length: 64 }),
  roleArn: varchar("role_arn", { length: 512 }),
  externalId: varchar("external_id", { length: 255 }),
  tenantId: varchar("tenant_id", { length: 255 }),
  subscriptionId: varchar("subscription_id", { length: 255 }),
  projectId: varchar("project_id", { length: 255 }),
  status: mysqlEnum("cred_status", ["active", "expired", "revoked", "testing", "error"]).default("active").notNull(),
  lastValidatedAt: timestamp("last_validated_at"),
  lastUsedAt: timestamp("last_used_at"),
  expiresAt: timestamp("expires_at"),
  createdBy: varchar("cred_created_by", { length: 255 }),
  createdAt: timestamp("cred_created_at").defaultNow(),
  updatedAt: timestamp("cred_updated_at").defaultNow(),
});

// ============================================================
// Cloud Enumeration Results
// ============================================================

export const cloudEnumerationRuns = mysqlTable("cloud_enumeration_runs", {
  id: int("id").autoincrement().primaryKey(),
  credentialId: int("credential_id").notNull(),
  providerId: int("enum_provider_id"),
  engagementId: int("enum_engagement_id"),
  provider: mysqlEnum("enum_provider", ["aws", "azure", "gcp"]).notNull(),
  status: mysqlEnum("enum_status", ["pending", "running", "completed", "error", "partial"]).default("pending").notNull(),
  scope: json("enum_scope"),
  totalUsersFound: int("total_users_found").default(0),
  totalRolesFound: int("total_roles_found").default(0),
  totalPoliciesFound: int("total_policies_found").default(0),
  totalGroupsFound: int("total_groups_found").default(0),
  totalServiceAccountsFound: int("total_service_accounts_found").default(0),
  totalMisconfigsFound: int("total_misconfigs_found").default(0),
  results: json("enum_results"),
  errorLog: json("enum_error_log"),
  startedAt: timestamp("enum_started_at"),
  completedAt: timestamp("enum_completed_at"),
  createdAt: timestamp("enum_created_at").defaultNow(),
});

// ============================================================
// AD Domain Connections (LDAP/LDAPS)
// ============================================================

export const adDomainConnections = mysqlTable("ad_domain_connections", {
  id: int("id").autoincrement().primaryKey(),
  environmentId: int("ad_environment_id"),
  engagementId: int("ad_conn_engagement_id"),
  connectionName: varchar("connection_name", { length: 255 }).notNull(),
  serverHost: varchar("server_host", { length: 255 }).notNull(),
  serverPort: int("server_port").default(389).notNull(),
  useTls: boolean("use_tls").default(false),
  tlsRejectUnauthorized: boolean("tls_reject_unauthorized").default(true),
  baseDn: varchar("base_dn", { length: 1024 }).notNull(),
  bindDn: varchar("bind_dn", { length: 1024 }),
  // Encrypted bind password (AES-256-GCM)
  encryptedBindPassword: text("encrypted_bind_password"),
  bindPasswordIv: varchar("bind_password_iv", { length: 64 }),
  bindPasswordTag: varchar("bind_password_tag", { length: 64 }),
  domainName: varchar("ldap_domain_name", { length: 255 }).notNull(),
  searchScope: mysqlEnum("search_scope", ["base", "one", "sub"]).default("sub"),
  status: mysqlEnum("conn_status", ["connected", "disconnected", "testing", "error"]).default("disconnected").notNull(),
  lastConnectedAt: timestamp("last_connected_at"),
  lastEnumerationAt: timestamp("last_enumeration_at"),
  errorMessage: text("conn_error_message"),
  createdBy: varchar("conn_created_by", { length: 255 }),
  createdAt: timestamp("conn_created_at").defaultNow(),
  updatedAt: timestamp("conn_updated_at").defaultNow(),
});

// ============================================================
// AD Enumeration Runs
// ============================================================

export const adEnumerationRuns = mysqlTable("ad_enumeration_runs", {
  id: int("id").autoincrement().primaryKey(),
  connectionId: int("ad_connection_id").notNull(),
  environmentId: int("ad_enum_environment_id"),
  engagementId: int("ad_enum_engagement_id"),
  status: mysqlEnum("ad_enum_status", ["pending", "running", "completed", "error", "partial"]).default("pending").notNull(),
  scope: mysqlEnum("ad_enum_scope", ["full", "users", "groups", "computers", "gpos", "ous", "trusts", "spns", "certificates"]).default("full"),
  totalUsersFound: int("ad_total_users_found").default(0),
  totalGroupsFound: int("ad_total_groups_found").default(0),
  totalComputersFound: int("ad_total_computers_found").default(0),
  totalGposFound: int("ad_total_gpos_found").default(0),
  totalOusFound: int("ad_total_ous_found").default(0),
  totalTrustsFound: int("ad_total_trusts_found").default(0),
  totalSpnsFound: int("ad_total_spns_found").default(0),
  privilegedUsersFound: int("privileged_users_found").default(0),
  kerberoastableFound: int("kerberoastable_found").default(0),
  asrepRoastableFound: int("asrep_roastable_found").default(0),
  results: json("ad_enum_results"),
  errorLog: json("ad_enum_error_log"),
  startedAt: timestamp("ad_enum_started_at"),
  completedAt: timestamp("ad_enum_completed_at"),
  createdAt: timestamp("ad_enum_created_at").defaultNow(),
});


// ============================================================
// Credential Alert Rules
// ============================================================

export const credentialAlertRules = mysqlTable("credential_alert_rules", {
  id: int("id").autoincrement().primaryKey(),
  credentialId: int("cred_alert_credential_id").notNull(),
  alertName: varchar("alert_name", { length: 255 }).notNull(),
  thresholdDays: int("threshold_days").default(30).notNull(),
  isEnabled: boolean("alert_is_enabled").default(true).notNull(),
  notifyOwner: boolean("alert_notify_owner").default(true).notNull(),
  lastCheckedAt: timestamp("alert_last_checked_at"),
  lastAlertedAt: timestamp("alert_last_alerted_at"),
  nextAlertAt: timestamp("alert_next_alert_at"),
  createdBy: varchar("alert_created_by", { length: 255 }),
  createdAt: timestamp("alert_created_at").defaultNow(),
});

// ============================================================
// Credential Alert History
// ============================================================

export const credentialAlertHistory = mysqlTable("credential_alert_history", {
  id: int("id").autoincrement().primaryKey(),
  ruleId: int("alert_rule_id").notNull(),
  credentialId: int("alert_hist_credential_id").notNull(),
  alertType: mysqlEnum("alert_type", ["expiring_soon", "expired", "rotation_due", "validation_failed"]).notNull(),
  severity: mysqlEnum("alert_severity", ["critical", "high", "medium", "low"]).default("medium").notNull(),
  message: text("alert_message").notNull(),
  notificationSent: boolean("notification_sent").default(false).notNull(),
  notificationResult: varchar("notification_result", { length: 255 }),
  acknowledgedAt: timestamp("alert_acknowledged_at"),
  acknowledgedBy: varchar("alert_acknowledged_by", { length: 255 }),
  credentialProvider: varchar("alert_cred_provider", { length: 32 }),
  credentialName: varchar("alert_cred_name", { length: 255 }),
  expiresAt: timestamp("alert_expires_at"),
  daysUntilExpiry: int("days_until_expiry"),
  createdAt: timestamp("alert_hist_created_at").defaultNow(),
});

// ============================================================
// Forest Domains (Multi-Domain Forest Mapping)
// ============================================================

export const forestDomains = mysqlTable("forest_domains", {
  id: int("id").autoincrement().primaryKey(),
  forestName: varchar("forest_name", { length: 255 }).notNull(),
  domainName: varchar("forest_domain_name", { length: 255 }).notNull(),
  connectionId: int("forest_connection_id"),
  parentDomainId: int("parent_domain_id"),
  engagementId: int("forest_engagement_id"),
  domainSid: varchar("domain_sid", { length: 128 }),
  domainFunctionalLevel: varchar("domain_functional_level", { length: 64 }),
  forestFunctionalLevel: varchar("forest_functional_level", { length: 64 }),
  isForestRoot: boolean("is_forest_root").default(false).notNull(),
  totalUsers: int("forest_total_users").default(0),
  totalGroups: int("forest_total_groups").default(0),
  totalComputers: int("forest_total_computers").default(0),
  privilegedUsers: int("forest_privileged_users").default(0),
  lastEnumeratedAt: timestamp("forest_last_enumerated_at"),
  metadata: json("forest_metadata"),
  createdAt: timestamp("forest_domain_created_at").defaultNow(),
});

// ============================================================
// Forest Trust Relationships
// ============================================================

export const forestTrusts = mysqlTable("forest_trusts", {
  id: int("id").autoincrement().primaryKey(),
  sourceDomainId: int("trust_source_domain_id").notNull(),
  targetDomainId: int("trust_target_domain_id").notNull(),
  trustDirection: mysqlEnum("trust_direction", ["inbound", "outbound", "bidirectional"]).notNull(),
  trustType: mysqlEnum("trust_type", ["parent_child", "tree_root", "shortcut", "forest", "external", "realm"]).notNull(),
  isTransitive: boolean("trust_is_transitive").default(true).notNull(),
  sidFilteringEnabled: boolean("sid_filtering_enabled").default(true).notNull(),
  selectiveAuth: boolean("selective_auth").default(false).notNull(),
  trustAttributes: int("trust_attributes").default(0),
  isVulnerable: boolean("trust_is_vulnerable").default(false).notNull(),
  vulnerabilityNotes: text("trust_vulnerability_notes"),
  discoveredAt: timestamp("trust_discovered_at").defaultNow(),
  createdAt: timestamp("forest_trust_created_at").defaultNow(),
});
