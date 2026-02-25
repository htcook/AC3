import { describe, it, expect, beforeEach } from "vitest";

// ── Module 1: Redirector Manager ──────────────────────────────────────

import * as redirectorMgr from "./lib/redirector-manager";

describe("Redirector Manager", () => {
  beforeEach(() => {
    redirectorMgr._resetForTesting();
  });

  it("creates a redirector with correct fields", () => {
    const rdr = redirectorMgr.createRedirector({
      name: "SMTP Relay 1",
      type: "smtp",
      engine: "socat",
      frontendHost: "10.0.0.1",
      frontendPort: 25,
      backendHost: "10.0.0.2",
      backendPort: 25,
    });
    expect(rdr.name).toBe("SMTP Relay 1");
    expect(rdr.type).toBe("smtp");
    expect(rdr.status).toBe("provisioning");
    expect(rdr.filterRules).toEqual([]);
  });

  it("lists redirectors with type filter", () => {
    redirectorMgr.createRedirector({ name: "A", type: "smtp", engine: "socat", frontendHost: "1", frontendPort: 25, backendHost: "2", backendPort: 25 });
    redirectorMgr.createRedirector({ name: "B", type: "http", engine: "nginx_proxy", frontendHost: "1", frontendPort: 80, backendHost: "2", backendPort: 80 });
    expect(redirectorMgr.listRedirectors({ type: "smtp" })).toHaveLength(1);
    expect(redirectorMgr.listRedirectors({ type: "http" })).toHaveLength(1);
    expect(redirectorMgr.listRedirectors()).toHaveLength(2);
  });

  it("activates and decommissions a redirector", () => {
    const rdr = redirectorMgr.createRedirector({ name: "R", type: "c2", engine: "caddy", frontendHost: "1", frontendPort: 443, backendHost: "2", backendPort: 443 });
    const activated = redirectorMgr.activateRedirector(rdr.id);
    expect(activated?.status).toBe("active");

    const decommissioned = redirectorMgr.decommissionRedirector(rdr.id);
    expect(decommissioned?.status).toBe("decommissioned");
  });

  it("creates from template", () => {
    const templates = redirectorMgr.getTemplates();
    expect(templates.length).toBeGreaterThan(0);

    const rdr = redirectorMgr.createFromTemplate(templates[0].id, {
      name: "From Template",
      frontendHost: "10.0.0.5",
      backendHost: "10.0.0.6",
      backendPort: 443,
    });
    expect(rdr).not.toBeNull();
    expect(rdr!.name).toBe("From Template");
  });

  it("performs health check", async () => {
    const rdr = redirectorMgr.createRedirector({ name: "HC", type: "http", engine: "nginx_proxy", frontendHost: "1", frontendPort: 80, backendHost: "2", backendPort: 80 });
    redirectorMgr.activateRedirector(rdr.id);
    const result = await redirectorMgr.performHealthCheck(rdr.id);
    expect(result).not.toBeNull();
    expect(result).toHaveProperty("status");
  });

  it("adds and removes filter rules", () => {
    const rdr = redirectorMgr.createRedirector({ name: "FR", type: "http", engine: "apache_mod_rewrite", frontendHost: "1", frontendPort: 80, backendHost: "2", backendPort: 80 });
    const rule = redirectorMgr.addFilterRule(rdr.id, {
      type: "ip_blocklist",
      description: "Block scanners",
      value: "1.2.3.4/32",
      action: "block",
      enabled: true,
    });
    expect(rule).not.toBeNull();
    
    const updated = redirectorMgr.listRedirectors()!.find(r => r.id === rdr.id);
    expect(updated!.filterRules).toHaveLength(1);

    redirectorMgr.removeFilterRule(rdr.id, rule!.id);
    const after = redirectorMgr.listRedirectors()!.find(r => r.id === rdr.id);
    expect(after!.filterRules).toHaveLength(0);
  });

  it("builds topology", () => {
    redirectorMgr.createRedirector({ name: "T1", type: "http", engine: "nginx_proxy", frontendHost: "1", frontendPort: 80, backendHost: "2", backendPort: 80 });
    const topo = redirectorMgr.buildTopology();
    expect(topo.stats.total).toBe(1);
    expect(topo.stats).toBeDefined();
  });

  it("generates redirector config", () => {
    const rdr = redirectorMgr.createRedirector({ name: "CFG", type: "http", engine: "nginx_proxy", frontendHost: "1", frontendPort: 80, backendHost: "2", backendPort: 80 });
    const config = redirectorMgr.generateRedirectorConfig(rdr.id);
    expect(config).not.toBeNull();
    expect(config).toContain("upstream");
  });

  it("deletes a redirector", () => {
    const rdr = redirectorMgr.createRedirector({ name: "Del", type: "dns", engine: "socat", frontendHost: "1", frontendPort: 53, backendHost: "2", backendPort: 53 });
    expect(redirectorMgr.deleteRedirector(rdr.id)).toBe(true);
    expect(redirectorMgr.listRedirectors()).toHaveLength(0);
  });
});

// ── Module 2: Domain Reputation Engine ────────────────────────────────

import * as domainRep from "./lib/domain-reputation-engine";

describe("Domain Reputation Engine", () => {
  beforeEach(() => {
    domainRep._resetForTesting();
  });

  it("analyzes a domain and returns a profile", () => {
    const profile = domainRep.analyzeDomain("test-example.com");
    expect(profile.domain).toBe("test-example.com");
    expect(profile.overallScore).toBeGreaterThanOrEqual(0);
    expect(profile.overallScore).toBeLessThanOrEqual(100);
    expect(profile.categorizations.length).toBeGreaterThan(0);
    expect(profile.suitability).toBeDefined();
    expect(profile.suitability.phishingScore).toBeGreaterThanOrEqual(0);
  });

  it("stores and retrieves domain profiles", () => {
    domainRep.analyzeDomain("alpha.com");
    domainRep.analyzeDomain("beta.org");
    
    const profiles = domainRep.listProfiles();
    expect(profiles).toHaveLength(2);

    const single = domainRep.getProfile("alpha.com");
    expect(single).not.toBeNull();
    expect(single!.domain).toBe("alpha.com");
  });

  it("ranks expired domain candidates", () => {
    const candidates = domainRep.rankExpiredDomainCandidates([
      "old-business.com",
      "legacy-corp.org",
      "abandoned-site.net",
    ]);
    expect(candidates).toHaveLength(3);
    // Should be sorted by rankScore descending
    for (let i = 1; i < candidates.length; i++) {
      expect(candidates[i - 1].rankScore).toBeGreaterThanOrEqual(candidates[i].rankScore);
    }
    expect(candidates[0].rankScore).toBeGreaterThan(0);
  });

  it("manages monitoring list", () => {
    domainRep.addToMonitoring("watch-this.com");
    domainRep.addToMonitoring("also-this.org");
    expect(domainRep.getMonitoredDomains()).toHaveLength(2);

    domainRep.removeFromMonitoring("watch-this.com");
    expect(domainRep.getMonitoredDomains()).toHaveLength(1);
  });

  it("checks monitored domains", () => {
    domainRep.addToMonitoring("monitored.com");
    const results = domainRep.checkMonitoredDomains();
    expect(results).toHaveLength(1);
    expect(results[0].domain).toBe("monitored.com");
  });

  it("categorizations include standard vendors", () => {
    const profile = domainRep.analyzeDomain("vendor-test.com");
    const vendors = profile.categorizations.map(c => c.vendor);
    expect(vendors.length).toBeGreaterThan(0);
    // Check that at least some known vendors are present
    expect(vendors).toContain("mcafee_trustedsource");
  });
});

// ── Module 3: C2 Traffic Profiles ─────────────────────────────────────

import * as c2Profiles from "./lib/c2-traffic-profiles";

describe("C2 Traffic Profiles", () => {
  beforeEach(() => {
    c2Profiles._resetForTesting();
    c2Profiles.initBuiltInProfiles();
    c2Profiles.initFrontingConfigs();
  });

  it("lists built-in profiles", () => {
    const profiles = c2Profiles.listProfiles();
    expect(profiles.length).toBeGreaterThan(0);
  });

  it("filters profiles by framework", () => {
    const csProfiles = c2Profiles.listProfiles({ framework: "cobalt_strike" });
    csProfiles.forEach(p => expect(p.framework).toBe("cobalt_strike"));
  });

  it("gets a profile by ID", () => {
    const all = c2Profiles.listProfiles();
    const first = c2Profiles.getProfile(all[0].id);
    expect(first).not.toBeNull();
    expect(first!.id).toBe(all[0].id);
  });

  it("creates a custom profile", () => {
    const profile = c2Profiles.createProfile({
      name: "Custom Test Profile",
      description: "Test",
      framework: "caldera",
      trafficPattern: "custom",
      sleepTime: 5000,
      jitter: 20,
      userAgents: ["TestAgent/1.0"],
      httpGet: { uri: ["/test"], headers: {}, parameters: {}, server: { headers: {}, contentType: "text/html" } },
      httpPost: { uri: ["/submit"], headers: {}, parameters: {}, server: { headers: {}, contentType: "application/json" } },
      ssl: { cipherSuites: [] },
      spawnTo: [],
      tags: ["test"],
      mitreTechniques: ["T1071.001"],
    });
    expect(profile.name).toBe("Custom Test Profile");
    expect(profile.framework).toBe("caldera");
  });

  it("exports malleable C2 config", () => {
    const all = c2Profiles.listProfiles();
    const exported = c2Profiles.exportMalleableC2(all[0].id);
    expect(exported).not.toBeNull();
    expect(exported).toContain("set sleeptime");
    expect(exported).toContain("set jitter");
  });

  it("lists domain fronting configs", () => {
    const configs = c2Profiles.listFrontingConfigs();
    expect(configs.length).toBeGreaterThan(0);
    configs.forEach(c => {
      expect(c.frontDomain).toBeTruthy();
      expect(c.hostHeader).toBeTruthy();
    });
  });

  it("tests a fronting config", () => {
    const configs = c2Profiles.listFrontingConfigs();
    const result = c2Profiles.testFrontingConfig(configs[0].id);
    expect(result).not.toBeNull();
    expect(result!.lastTest).toBeDefined();
    expect(typeof result!.lastTest!.success).toBe("boolean");
  });

  it("returns third-party C2 channels", () => {
    const channels = c2Profiles.getThirdPartyChannels();
    expect(channels.length).toBeGreaterThan(0);
    channels.forEach(ch => {
      expect(ch.platform).toBeTruthy();
      expect(ch.characteristics.maxBandwidthKbps).toBeGreaterThan(0);
    });
  });
});

// ── Module 4: Infrastructure Deployment Automation ────────────────────

import * as infraDeploy from "./lib/infra-deploy-automation";

describe("Infrastructure Deployment Automation", () => {
  beforeEach(() => {
    infraDeploy._resetForTesting();
    infraDeploy.initBlueprints();
  });

  it("lists built-in blueprints", () => {
    const bps = infraDeploy.listBlueprints();
    expect(bps.length).toBeGreaterThan(0);
  });

  it("gets a blueprint by ID", () => {
    const bps = infraDeploy.listBlueprints();
    const bp = infraDeploy.getBlueprint(bps[0].id);
    expect(bp).not.toBeNull();
    expect(bp!.components.length).toBeGreaterThan(0);
  });

  it("creates a deployment from blueprint", () => {
    const bps = infraDeploy.listBlueprints();
    const deployment = infraDeploy.createDeployment({
      name: "Test Deploy",
      blueprintId: bps[0].id,
      provider: "digitalocean",
      region: "nyc3",
    });
    expect(deployment).not.toBeNull();
    expect(deployment!.name).toBe("Test Deploy");
    expect(deployment!.status).toBe("draft");
    // Resources are populated when deployment starts, not at creation
    expect(deployment!.resources).toBeDefined();
  });

  it("starts and tracks deployment", () => {
    const bps = infraDeploy.listBlueprints();
    const deployment = infraDeploy.createDeployment({
      name: "Start Test",
      blueprintId: bps[0].id,
      provider: "aws",
      region: "us-east-1",
    });
    expect(deployment).not.toBeNull();

    const started = infraDeploy.startDeployment(deployment!.id);
    expect(started).not.toBeNull();
    expect(started!.status).toBe("active");
    expect(started!.log.length).toBeGreaterThan(0);
  });

  it("destroys a deployment", () => {
    const bps = infraDeploy.listBlueprints();
    const deployment = infraDeploy.createDeployment({
      name: "Destroy Test",
      blueprintId: bps[0].id,
      provider: "digitalocean",
      region: "sfo3",
    });
    infraDeploy.startDeployment(deployment!.id);
    const destroyed = infraDeploy.destroyDeployment(deployment!.id);
    expect(destroyed).not.toBeNull();
    expect(destroyed!.status).toBe("destroyed");
  });

  it("lists deployments with status filter", () => {
    const bps = infraDeploy.listBlueprints();
    infraDeploy.createDeployment({ name: "D1", blueprintId: bps[0].id, provider: "digitalocean", region: "nyc3" });
    const d2 = infraDeploy.createDeployment({ name: "D2", blueprintId: bps[0].id, provider: "aws", region: "us-east-1" });
    infraDeploy.startDeployment(d2!.id);

    expect(infraDeploy.listDeployments({ status: "draft" })).toHaveLength(1);
    expect(infraDeploy.listDeployments({ status: "active" })).toHaveLength(1);
    expect(infraDeploy.listDeployments()).toHaveLength(2);
  });

  it("generates Terraform config", () => {
    const bps = infraDeploy.listBlueprints();
    const tf = infraDeploy.generateTerraform(bps[0].id, {
      provider: "digitalocean",
      region: "nyc3",
      sshKeyFingerprint: "aa:bb:cc:dd",
      adminCidr: "10.0.0.0/24",
    });
    expect(tf).not.toBeNull();
    expect(tf).toContain("terraform");
    expect(tf).toContain("digitalocean");
  });

  it("generates Ansible playbook", () => {
    const bps = infraDeploy.listBlueprints();
    const ansible = infraDeploy.generateAnsiblePlaybook(bps[0].id);
    expect(ansible).not.toBeNull();
    expect(ansible).toContain("hosts:");
  });
});

// ── Module 5: OpSec Hardening & Monitoring ────────────────────────────

import * as opsecMon from "./lib/opsec-monitor";

describe("OpSec Hardening & Monitoring", () => {
  beforeEach(() => {
    opsecMon._resetForTesting();
  });

  it("assesses security posture", () => {
    const posture = opsecMon.assessPosture();
    expect(posture.overallScore).toBeGreaterThanOrEqual(0);
    expect(posture.overallScore).toBeLessThanOrEqual(100);
    expect(posture.allChecks.length).toBeGreaterThan(0);
    expect(posture.assessedAt).toBeGreaterThan(0);
  });

  it("posture has category breakdown", () => {
    const posture = opsecMon.assessPosture();
    expect(posture.categoryScores.ssh).toBeDefined();
    expect(posture.categoryScores.firewall).toBeDefined();
    expect(posture.categoryScores.logging).toBeDefined();
    expect(posture.categoryScores.ssh.total).toBeGreaterThan(0);
  });

  it("identifies critical findings", () => {
    const posture = opsecMon.assessPosture();
    posture.criticalFindings.forEach(f => {
      expect(f.status).toBe("fail");
      expect(["critical", "high"]).toContain(f.severity);
    });
  });

  it("creates and lists alerts", () => {
    opsecMon.createAlert({
      type: "opsec_violation",
      severity: "high",
      title: "Exposed Port Detected",
      description: "Port 4444 open on redirector",
      source: "redirector-1",
      recommendation: "Close port or restrict with iptables",
    });
    opsecMon.createAlert({
      type: "certificate_expiry",
      severity: "medium",
      title: "Cert Expiring Soon",
      description: "SSL cert expires in 7 days",
      source: "c2-server",
      recommendation: "Renew with certbot",
    });

    const all = opsecMon.listAlerts();
    expect(all).toHaveLength(2);

    const highOnly = opsecMon.listAlerts({ severity: "high" });
    expect(highOnly).toHaveLength(1);
    expect(highOnly[0].title).toBe("Exposed Port Detected");
  });

  it("acknowledges an alert", () => {
    const alert = opsecMon.createAlert({
      type: "suspicious_activity",
      severity: "critical",
      title: "Test",
      description: "Test",
      source: "test",
      recommendation: "Test",
    });
    expect(alert.acknowledged).toBe(false);
    
    const result = opsecMon.acknowledgeAlert(alert.id);
    expect(result).toBe(true);

    const updated = opsecMon.listAlerts().find(a => a.id === alert.id);
    expect(updated!.acknowledged).toBe(true);
  });

  it("manages log sources", () => {
    opsecMon.addLogSource({
      name: "Auth Logs",
      type: "auth_log",
      host: "10.0.0.1",
      port: 514,
      protocol: "tcp",
    });
    opsecMon.addLogSource({
      name: "C2 Logs",
      type: "c2_log",
      host: "10.0.0.2",
      port: 514,
      protocol: "tls",
    });

    const sources = opsecMon.listLogSources();
    expect(sources).toHaveLength(2);

    opsecMon.removeLogSource(sources[0].id);
    expect(opsecMon.listLogSources()).toHaveLength(1);
  });

  it("returns IR countermeasures", () => {
    const cms = opsecMon.getIRCountermeasures();
    expect(cms.length).toBeGreaterThan(0);
    cms.forEach(cm => {
      expect(cm.irTechnique).toBeTruthy();
      expect(cm.countermeasure).toBeTruthy();
      expect(["easy", "medium", "hard"]).toContain(cm.difficulty);
    });
  });

  it("toggles countermeasure implementation status", () => {
    const cms = opsecMon.getIRCountermeasures();
    const first = cms[0];
    expect(first.implemented).toBe(false);

    const toggled = opsecMon.toggleCountermeasure(first.id);
    expect(toggled!.implemented).toBe(true);

    const toggledBack = opsecMon.toggleCountermeasure(first.id);
    expect(toggledBack!.implemented).toBe(false);
  });

  it("computes countermeasure stats", () => {
    const cms = opsecMon.getIRCountermeasures();
    opsecMon.toggleCountermeasure(cms[0].id);
    opsecMon.toggleCountermeasure(cms[1].id);

    const stats = opsecMon.getCountermeasureStats();
    expect(stats.implemented).toBe(2);
    expect(stats.pending).toBe(stats.total - 2);
    expect(stats.byDifficulty).toBeDefined();
    expect(Object.keys(stats.byCategory).length).toBeGreaterThan(0);
  });

  it("generates rsyslog config", () => {
    const config = opsecMon.generateRsyslogConfig("10.0.0.100", 514);
    expect(config).toContain("10.0.0.100:514");
    expect(config).toContain("rsyslog");
  });
});
