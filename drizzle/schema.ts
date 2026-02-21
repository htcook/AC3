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
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export type Engagement = typeof engagements.$inferSelect;
export type InsertEngagement = typeof engagements.$inferInsert;

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
