/**
 * Infrastructure Wiki Modules Router
 * 
 * Combines 5 modules based on Red Team Infrastructure Wiki:
 *   1. Redirector Management
 *   2. Domain Reputation Engine
 *   3. C2 Traffic Profiles & Domain Fronting
 *   4. Infrastructure Deployment Automation
 *   5. OpSec Hardening & Monitoring
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";

import * as redirectorMgr from "../lib/redirector-manager";
import * as domainRep from "../lib/domain-reputation-engine";
import * as c2Profiles from "../lib/c2-traffic-profiles";
import * as infraDeploy from "../lib/infra-deploy-automation";
import * as opsecMon from "../lib/opsec-monitor";

// Initialize built-in data
c2Profiles.initBuiltInProfiles();
c2Profiles.initFrontingConfigs();
infraDeploy.initBlueprints();

export const infraWikiRouter = router({
  // ═══════════════════════════════════════════════════════════════════
  // 1. REDIRECTOR MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════

  listRedirectors: protectedProcedure
    .input(z.object({
      type: z.enum(["smtp", "http", "https", "dns", "c2"]).optional(),
      status: z.enum(["provisioning", "active", "degraded", "down", "decommissioned"]).optional(),
      engagementId: z.string().optional(),
    }).optional())
    .query(({ input }) => redirectorMgr.listRedirectors(input)),

  createRedirector: protectedProcedure
    .input(z.object({
      name: z.string(),
      type: z.enum(["smtp", "http", "https", "dns", "c2"]),
      engine: z.enum(["socat", "apache_mod_rewrite", "nginx_proxy", "iptables_nat", "ssh_tunnel", "caddy", "haproxy"]),
      frontendHost: z.string(),
      frontendPort: z.number(),
      backendHost: z.string(),
      backendPort: z.number(),
      engagementId: z.string().optional(),
      domain: z.string().optional(),
      sslEnabled: z.boolean().optional(),
    }))
    .mutation(({ input }) => redirectorMgr.createRedirector(input)),

  createFromTemplate: protectedProcedure
    .input(z.object({
      templateId: z.string(),
      name: z.string(),
      frontendHost: z.string(),
      backendHost: z.string(),
      backendPort: z.number(),
      engagementId: z.string().optional(),
      domain: z.string().optional(),
    }))
    .mutation(({ input }) => {
      const result = redirectorMgr.createFromTemplate(input.templateId, input);
      if (!result) throw new Error("Template not found");
      return result;
    }),

  activateRedirector: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = redirectorMgr.activateRedirector(input.id);
      if (!result) throw new Error("Redirector not found");
      return result;
    }),

  decommissionRedirector: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = redirectorMgr.decommissionRedirector(input.id);
      if (!result) throw new Error("Redirector not found");
      return result;
    }),

  deleteRedirector: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => redirectorMgr.deleteRedirector(input.id)),

  healthCheckRedirector: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => redirectorMgr.performHealthCheck(input.id)),

  healthCheckAll: protectedProcedure
    .mutation(() => redirectorMgr.healthCheckAll()),

  getRedirectorConfig: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const config = redirectorMgr.generateRedirectorConfig(input.id);
      if (!config) throw new Error("Redirector not found");
      return config;
    }),

  getRedirectorTopology: protectedProcedure
    .query(() => redirectorMgr.buildTopology()),

  getRedirectorTemplates: protectedProcedure
    .query(() => redirectorMgr.getTemplates()),

  addFilterRule: protectedProcedure
    .input(z.object({
      redirectorId: z.string(),
      type: z.enum(["ip_allowlist", "ip_blocklist", "ua_filter", "uri_pattern", "header_match", "geo_block", "time_window"]),
      description: z.string(),
      value: z.string(),
      action: z.enum(["allow", "block", "redirect_to_decoy"]),
      enabled: z.boolean(),
    }))
    .mutation(({ input }) => {
      const { redirectorId, ...rule } = input;
      const result = redirectorMgr.addFilterRule(redirectorId, rule);
      if (!result) throw new Error("Redirector not found");
      return result;
    }),

  removeFilterRule: protectedProcedure
    .input(z.object({ redirectorId: z.string(), ruleId: z.string() }))
    .mutation(({ input }) => redirectorMgr.removeFilterRule(input.redirectorId, input.ruleId)),

  getHealthHistory: protectedProcedure
    .input(z.object({ id: z.string(), limit: z.number().optional() }))
    .query(({ input }) => redirectorMgr.getHealthHistory(input.id, input.limit)),

  // ═══════════════════════════════════════════════════════════════════
  // 2. DOMAIN REPUTATION ENGINE
  // ═══════════════════════════════════════════════════════════════════

  analyzeDomain: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .mutation(({ input }) => domainRep.analyzeDomain(input.domain)),

  getDomainProfile: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .query(({ input }) => domainRep.getProfile(input.domain) ?? null),

  listDomainProfiles: protectedProcedure
    .query(() => domainRep.listProfiles()),

  rankExpiredDomains: protectedProcedure
    .input(z.object({ domains: z.array(z.string()) }))
    .mutation(({ input }) => domainRep.rankExpiredDomainCandidates(input.domains)),

  addDomainToMonitoring: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .mutation(({ input }) => { domainRep.addToMonitoring(input.domain); return { success: true }; }),

  removeDomainFromMonitoring: protectedProcedure
    .input(z.object({ domain: z.string() }))
    .mutation(({ input }) => { domainRep.removeFromMonitoring(input.domain); return { success: true }; }),

  getMonitoredDomains: protectedProcedure
    .query(() => domainRep.getMonitoredDomains()),

  checkMonitoredDomains: protectedProcedure
    .mutation(() => domainRep.checkMonitoredDomains()),

  // ═══════════════════════════════════════════════════════════════════
  // 3. C2 TRAFFIC PROFILES & DOMAIN FRONTING
  // ═══════════════════════════════════════════════════════════════════

  listC2Profiles: protectedProcedure
    .input(z.object({
      framework: z.enum(["cobalt_strike", "sliver", "empire", "covenant", "mythic", "havoc", "caldera"]).optional(),
      pattern: z.enum(["web_browsing", "api_calls", "cdn_traffic", "cloud_storage", "social_media", "email_service", "custom"]).optional(),
    }).optional())
    .query(({ input }) => c2Profiles.listProfiles(input)),

  getC2Profile: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => c2Profiles.getProfile(input.id) ?? null),

  createC2Profile: protectedProcedure
    .input(z.object({
      name: z.string(),
      description: z.string(),
      framework: z.enum(["cobalt_strike", "sliver", "empire", "covenant", "mythic", "havoc", "caldera"]),
      trafficPattern: z.enum(["web_browsing", "api_calls", "cdn_traffic", "cloud_storage", "social_media", "email_service", "custom"]),
      sleepTime: z.number(),
      jitter: z.number(),
      userAgents: z.array(z.string()),
      tags: z.array(z.string()),
    }))
    .mutation(({ input }) => c2Profiles.createProfile({
      ...input,
      httpGet: { uri: ["/"], headers: {}, parameters: {}, server: { headers: {}, contentType: "text/html" } },
      httpPost: { uri: ["/"], headers: {}, parameters: {}, server: { headers: {}, contentType: "application/json" } },
      ssl: { cipherSuites: [] },
      spawnTo: [],
      mitreTechniques: ["T1071.001"],
    })),

  exportC2Profile: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const result = c2Profiles.exportMalleableC2(input.id);
      if (!result) throw new Error("Profile not found");
      return result;
    }),

  listFrontingConfigs: protectedProcedure
    .query(() => c2Profiles.listFrontingConfigs()),

  testFrontingConfig: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = c2Profiles.testFrontingConfig(input.id);
      if (!result) throw new Error("Fronting config not found");
      return result;
    }),

  getThirdPartyChannels: protectedProcedure
    .query(() => c2Profiles.getThirdPartyChannels()),

  // ═══════════════════════════════════════════════════════════════════
  // 4. INFRASTRUCTURE DEPLOYMENT AUTOMATION
  // ═══════════════════════════════════════════════════════════════════

  listBlueprints: protectedProcedure
    .query(() => infraDeploy.listBlueprints()),

  getBlueprint: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const bp = infraDeploy.getBlueprint(input.id);
      if (!bp) throw new Error("Blueprint not found");
      return bp;
    }),

  createDeployment: protectedProcedure
    .input(z.object({
      name: z.string(),
      blueprintId: z.string(),
      engagementId: z.string().optional(),
      provider: z.enum(["digitalocean", "aws", "azure", "gcp", "linode", "vultr"]),
      region: z.string(),
    }))
    .mutation(({ input }) => {
      const result = infraDeploy.createDeployment(input);
      if (!result) throw new Error("Blueprint not found");
      return result;
    }),

  startDeployment: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = infraDeploy.startDeployment(input.id);
      if (!result) throw new Error("Deployment not found or not in draft status");
      return result;
    }),

  destroyDeployment: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = infraDeploy.destroyDeployment(input.id);
      if (!result) throw new Error("Deployment not found");
      return result;
    }),

  listDeployments: protectedProcedure
    .input(z.object({
      status: z.enum(["draft", "planning", "deploying", "active", "destroying", "destroyed", "failed"]).optional(),
      engagementId: z.string().optional(),
    }).optional())
    .query(({ input }) => infraDeploy.listDeployments(input)),

  getDeployment: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ input }) => {
      const d = infraDeploy.getDeployment(input.id);
      if (!d) throw new Error("Deployment not found");
      return d;
    }),

  generateTerraform: protectedProcedure
    .input(z.object({
      blueprintId: z.string(),
      provider: z.enum(["digitalocean", "aws", "azure", "gcp", "linode", "vultr"]),
      region: z.string(),
      sshKeyFingerprint: z.string(),
      adminCidr: z.string(),
    }))
    .query(({ input }) => {
      const result = infraDeploy.generateTerraform(input.blueprintId, input);
      if (!result) throw new Error("Blueprint not found");
      return result;
    }),

  generateAnsible: protectedProcedure
    .input(z.object({ blueprintId: z.string() }))
    .query(({ input }) => {
      const result = infraDeploy.generateAnsiblePlaybook(input.blueprintId);
      if (!result) throw new Error("Blueprint not found");
      return result;
    }),

  // ═══════════════════════════════════════════════════════════════════
  // 5. OPSEC HARDENING & MONITORING
  // ═══════════════════════════════════════════════════════════════════

  assessPosture: protectedProcedure
    .input(z.object({ targetHost: z.string().optional() }).optional())
    .mutation(({ input }) => opsecMon.assessPosture(input?.targetHost)),

  listAlerts: protectedProcedure
    .input(z.object({
      type: z.enum(["opsec_violation", "health_degraded", "certificate_expiry", "suspicious_activity", "config_drift"]).optional(),
      severity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
      acknowledged: z.boolean().optional(),
    }).optional())
    .query(({ input }) => opsecMon.listAlerts(input)),

  acknowledgeAlert: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => opsecMon.acknowledgeAlert(input.id)),

  addLogSource: protectedProcedure
    .input(z.object({
      name: z.string(),
      type: z.enum(["syslog", "auth_log", "web_access", "c2_log", "phishing_log", "dns_log", "firewall_log"]),
      host: z.string(),
      port: z.number(),
      protocol: z.enum(["tcp", "udp", "tls"]),
    }))
    .mutation(({ input }) => opsecMon.addLogSource(input)),

  listLogSources: protectedProcedure
    .query(() => opsecMon.listLogSources()),

  removeLogSource: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => opsecMon.removeLogSource(input.id)),

  getIRCountermeasures: protectedProcedure
    .query(() => opsecMon.getIRCountermeasures()),

  toggleCountermeasure: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ input }) => {
      const result = opsecMon.toggleCountermeasure(input.id);
      if (!result) throw new Error("Countermeasure not found");
      return result;
    }),

  getCountermeasureStats: protectedProcedure
    .query(() => opsecMon.getCountermeasureStats()),

  generateRsyslogConfig: protectedProcedure
    .input(z.object({ logSinkHost: z.string(), logSinkPort: z.number() }))
    .query(({ input }) => opsecMon.generateRsyslogConfig(input.logSinkHost, input.logSinkPort)),
});
