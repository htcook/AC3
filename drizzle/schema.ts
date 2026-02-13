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
