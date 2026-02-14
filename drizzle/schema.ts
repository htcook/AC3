import { int, mysqlEnum, mysqlTable, text, timestamp, varchar, json, boolean } from "drizzle-orm/mysql-core";

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
    "full_engagement"
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
    "pending", "discovering", "analyzing", "scoring", "recommending", "completed", "failed"
  ]).default("pending").notNull(),
  // Aggregated results
  totalAssets: int("totalAssets").default(0),
  totalFindings: int("totalFindings").default(0),
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
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type DiscoveredAsset = typeof discoveredAssets.$inferSelect;
export type InsertDiscoveredAsset = typeof discoveredAssets.$inferInsert;
