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
