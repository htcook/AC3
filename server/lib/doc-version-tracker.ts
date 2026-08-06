/**
 * Documentation Version Tracker
 *
 * Tracks platform changes and maps them to documentation sections that need updating.
 * When a route, router, schema table, or integration is added/modified, this system
 * identifies which guide sections are affected and flags them for review.
 *
 * Architecture:
 *   1. DocManifest — maps every doc section to the platform components it covers
 *   2. PlatformSnapshot — captures current state of routes, routers, schema, integrations
 *   3. DiffEngine — compares snapshots to find changes
 *   4. DocImpactAnalyzer — maps changes to affected doc sections
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DocSection {
  /** Unique section ID (e.g., "admin-guide.user-management") */
  id: string;
  /** Guide this section belongs to */
  guide: "admin" | "user" | "msp-mssp" | "ember-design";
  /** Section title */
  title: string;
  /** Section heading path (e.g., "Admin Guide > User Management > Role Configuration") */
  path: string;
  /** Platform components this section documents */
  covers: PlatformComponent[];
  /** Last verified platform snapshot version */
  lastVerifiedVersion: string;
  /** Last update timestamp */
  lastUpdated: number;
}

export interface PlatformComponent {
  /** Component type */
  type: "route" | "router" | "schema_table" | "server_lib" | "integration" | "env_var" | "page";
  /** Component identifier (file path, table name, route path, etc.) */
  id: string;
  /** Optional: specific exports or functions within the component */
  exports?: string[];
}

export interface PlatformSnapshot {
  /** Snapshot version (ISO timestamp) */
  version: string;
  /** Timestamp */
  timestamp: number;
  /** All frontend routes */
  routes: RouteEntry[];
  /** All router files with procedure counts */
  routers: RouterEntry[];
  /** All schema tables */
  schemaTables: SchemaTableEntry[];
  /** All server library modules */
  serverLibs: ServerLibEntry[];
  /** All integrations (env vars for external services) */
  integrations: IntegrationEntry[];
  /** All page files */
  pages: PageEntry[];
}

export interface RouteEntry {
  path: string;
  component: string;
  protected: boolean;
}

export interface RouterEntry {
  file: string;
  procedures: string[];
  lineCount: number;
  lastModified: number;
}

export interface SchemaTableEntry {
  name: string;
  columns: string[];
  lineRange: [number, number];
}

export interface ServerLibEntry {
  file: string;
  exports: string[];
  lineCount: number;
  lastModified: number;
}

export interface IntegrationEntry {
  name: string;
  envVars: string[];
  category: string;
}

export interface PageEntry {
  file: string;
  route: string;
  lineCount: number;
  lastModified: number;
}

export interface PlatformDiff {
  /** Snapshot versions being compared */
  from: string;
  to: string;
  /** Added components */
  added: DiffEntry[];
  /** Removed components */
  removed: DiffEntry[];
  /** Modified components */
  modified: DiffEntry[];
}

export interface DiffEntry {
  type: PlatformComponent["type"];
  id: string;
  details: string;
}

export interface DocImpact {
  /** The diff that triggered this impact */
  diff: DiffEntry;
  /** Affected doc sections */
  affectedSections: DocSection[];
  /** Severity: how urgently the doc needs updating */
  severity: "critical" | "moderate" | "low";
  /** Suggested action */
  action: string;
}

export interface DocUpdateReport {
  /** Report generation timestamp */
  generatedAt: number;
  /** Platform diff summary */
  diff: PlatformDiff;
  /** Doc sections that need updating */
  impacts: DocImpact[];
  /** Summary statistics */
  stats: {
    totalChanges: number;
    criticalUpdates: number;
    moderateUpdates: number;
    lowUpdates: number;
    sectionsAffected: number;
    sectionsUpToDate: number;
  };
}

// ─── Documentation Manifest ─────────────────────────────────────────────────

/**
 * Maps every documentation section to the platform components it covers.
 * When any covered component changes, the section is flagged for review.
 */
export const DOC_MANIFEST: DocSection[] = [
  // ═══ ADMIN GUIDE ═══
  {
    id: "admin.initial-setup",
    guide: "admin",
    title: "Initial Platform Setup",
    path: "Admin Guide > Initial Setup",
    covers: [
      { type: "env_var", id: "CALDERA_BASE_URL" },
      { type: "env_var", id: "CALDERA_API_KEY" },
      { type: "env_var", id: "SCAN_SERVER_HOST" },
      { type: "env_var", id: "ZAP_BASE_URL" },
      { type: "env_var", id: "GOPHISH_BASE_URL" },
      { type: "route", id: "/settings" },
      { type: "page", id: "Settings.tsx" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.user-management",
    guide: "admin",
    title: "User Management and RBAC",
    path: "Admin Guide > User Management",
    covers: [
      { type: "route", id: "/team" },
      { type: "page", id: "Team.tsx" },
      { type: "schema_table", id: "users" },
      { type: "router", id: "auth-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.integration-management",
    guide: "admin",
    title: "Integration Management",
    path: "Admin Guide > Integration Management",
    covers: [
      { type: "route", id: "/integrations" },
      { type: "page", id: "Integrations.tsx" },
      { type: "router", id: "integrations-router.ts" },
      { type: "schema_table", id: "integrationConfigs" },
      { type: "schema_table", id: "integrationHealthChecks" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.caldera-c2",
    guide: "admin",
    title: "Caldera C2 Administration",
    path: "Admin Guide > Caldera C2",
    covers: [
      { type: "route", id: "/caldera-dashboard" },
      { type: "route", id: "/caldera-agents" },
      { type: "route", id: "/caldera-operations" },
      { type: "route", id: "/caldera-abilities" },
      { type: "page", id: "CalderaDashboard.tsx" },
      { type: "router", id: "caldera-router.ts" },
      { type: "server_lib", id: "caldera-api.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.ember-fleet",
    guide: "admin",
    title: "Ember Agent Fleet Management",
    path: "Admin Guide > Ember Fleet",
    covers: [
      { type: "route", id: "/ember" },
      { type: "route", id: "/ember-deploy" },
      { type: "route", id: "/ember-swarm" },
      { type: "page", id: "EmberAgents.tsx" },
      { type: "page", id: "EmberDeploy.tsx" },
      { type: "page", id: "EmberSwarm.tsx" },
      { type: "router", id: "ember-agent-router.ts" },
      { type: "server_lib", id: "ember-agent-core.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.scanforge",
    guide: "admin",
    title: "ScanForge Infrastructure",
    path: "Admin Guide > ScanForge",
    covers: [
      { type: "route", id: "/scan-servers" },
      { type: "page", id: "ScanServers.tsx" },
      { type: "server_lib", id: "do-scan-api.ts" },
      { type: "server_lib", id: "scan-server-executor.ts" },
      { type: "env_var", id: "SCAN_SERVER_HOST" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.tenant-management",
    guide: "admin",
    title: "Multi-Tenant Management",
    path: "Admin Guide > Tenant Management",
    covers: [
      { type: "route", id: "/tenants" },
      { type: "page", id: "Tenants.tsx" },
      { type: "router", id: "tenant-router.ts" },
      { type: "schema_table", id: "tenants" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.compliance",
    guide: "admin",
    title: "Compliance Management",
    path: "Admin Guide > Compliance",
    covers: [
      { type: "route", id: "/compliance-dashboard" },
      { type: "route", id: "/fips-compliance" },
      { type: "page", id: "ComplianceDashboard.tsx" },
      { type: "page", id: "FIPSCompliance.tsx" },
      { type: "router", id: "compliance-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "admin.msf-servers",
    guide: "admin",
    title: "Metasploit Server Management",
    path: "Admin Guide > MSF Servers",
    covers: [
      { type: "route", id: "/msf-servers" },
      { type: "page", id: "MSFServers.tsx" },
      { type: "router", id: "msf-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ USER GUIDE — Penetration Tester ═══
  {
    id: "user.pentest.domain-intel",
    guide: "user",
    title: "Domain Intelligence Scanning",
    path: "User Guide > Penetration Tester > Domain Intelligence",
    covers: [
      { type: "route", id: "/domain-intel" },
      { type: "page", id: "DomainIntel.tsx" },
      { type: "router", id: "domain-intel-core.ts" },
      { type: "server_lib", id: "di-pipeline.ts" },
      { type: "server_lib", id: "di-threat-enrichment.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.vuln-scanner",
    guide: "user",
    title: "Vulnerability Scanner",
    path: "User Guide > Penetration Tester > Vulnerability Scanner",
    covers: [
      { type: "route", id: "/vuln-scanner" },
      { type: "page", id: "VulnScanner.tsx" },
      { type: "router", id: "vuln-scanner-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.nuclei",
    guide: "user",
    title: "Nuclei Scanner",
    path: "User Guide > Penetration Tester > Nuclei Scanner",
    covers: [
      { type: "route", id: "/nuclei-scanner" },
      { type: "page", id: "NucleiScanner.tsx" },
      { type: "router", id: "nuclei-router.ts" },
      { type: "server_lib", id: "nuclei-orchestrator.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.zap",
    guide: "user",
    title: "ZAP DAST Scanner",
    path: "User Guide > Penetration Tester > ZAP Scanner",
    covers: [
      { type: "route", id: "/zap-scanner" },
      { type: "page", id: "ZapScanner.tsx" },
      { type: "router", id: "zap-router.ts" },
      { type: "server_lib", id: "zap-api.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.web-app-scanner",
    guide: "user",
    title: "Web Application Scanner",
    path: "User Guide > Penetration Tester > Web App Scanner",
    covers: [
      { type: "route", id: "/web-app-scanner" },
      { type: "page", id: "WebAppScanner.tsx" },
      { type: "router", id: "web-app-scanner-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.exploit-arsenal",
    guide: "user",
    title: "Exploit Arsenal",
    path: "User Guide > Penetration Tester > Exploit Arsenal",
    covers: [
      { type: "route", id: "/exploit-arsenal" },
      { type: "page", id: "ExploitArsenal.tsx" },
      { type: "router", id: "exploit-arsenal-router.ts" },
      { type: "server_lib", id: "enhanced-exploit-orchestration.ts" },
      { type: "server_lib", id: "functional-exploit-generator.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.engagements",
    guide: "user",
    title: "Engagement Operations",
    path: "User Guide > Penetration Tester > Engagements",
    covers: [
      { type: "route", id: "/engagement-ops" },
      { type: "route", id: "/engagement-detail/:id" },
      { type: "page", id: "EngagementOps.tsx" },
      { type: "page", id: "EngagementDetail.tsx" },
      { type: "router", id: "engagement-router.ts" },
      { type: "server_lib", id: "engagement-orchestrator.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.unified-findings",
    guide: "user",
    title: "Unified Findings",
    path: "User Guide > Penetration Tester > Unified Findings",
    covers: [
      { type: "route", id: "/unified-findings" },
      { type: "page", id: "UnifiedFindings.tsx" },
      { type: "router", id: "unified-findings-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.ops-viewer",
    guide: "user",
    title: "Ops Viewer (Battlespace)",
    path: "User Guide > Penetration Tester > Ops Viewer",
    covers: [
      { type: "route", id: "/ops-viewer" },
      { type: "page", id: "OpsViewer.tsx" },
      { type: "server_lib", id: "battlespace-engine.ts" },
      { type: "server_lib", id: "battlespace-transform.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.pentest.reporting",
    guide: "user",
    title: "Pentest Reporting",
    path: "User Guide > Penetration Tester > Reporting",
    covers: [
      { type: "route", id: "/pentest-report" },
      { type: "page", id: "PentestReport.tsx" },
      { type: "router", id: "pentest-report-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ USER GUIDE — Red Team ═══
  {
    id: "user.redteam.caldera-ops",
    guide: "user",
    title: "Caldera Operations",
    path: "User Guide > Red Team > Caldera Operations",
    covers: [
      { type: "route", id: "/caldera-operations" },
      { type: "route", id: "/caldera-abilities" },
      { type: "page", id: "CalderaOperations.tsx" },
      { type: "page", id: "CalderaAbilities.tsx" },
      { type: "router", id: "caldera-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.redteam.ember",
    guide: "user",
    title: "Ember Agent Operations",
    path: "User Guide > Red Team > Ember Agent",
    covers: [
      { type: "route", id: "/ember" },
      { type: "route", id: "/ember-deploy" },
      { type: "route", id: "/ember-swarm" },
      { type: "route", id: "/ember-intelligence" },
      { type: "route", id: "/ember-cognitive" },
      { type: "page", id: "EmberAgents.tsx" },
      { type: "page", id: "EmberDeploy.tsx" },
      { type: "page", id: "EmberSwarm.tsx" },
      { type: "page", id: "EmberIntelligence.tsx" },
      { type: "page", id: "EmberCognitive.tsx" },
      { type: "router", id: "ember-agent-router.ts" },
      { type: "server_lib", id: "ember-agent-core.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.redteam.gophish",
    guide: "user",
    title: "GoPhish Campaigns",
    path: "User Guide > Red Team > GoPhish",
    covers: [
      { type: "route", id: "/gophish" },
      { type: "page", id: "GoPhish.tsx" },
      { type: "router", id: "gophish-router.ts" },
      { type: "server_lib", id: "gophish-api.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.redteam.evasion",
    guide: "user",
    title: "Evasion Engine",
    path: "User Guide > Red Team > Evasion Engine",
    covers: [
      { type: "route", id: "/evasion-engine" },
      { type: "page", id: "EvasionEngine.tsx" },
      { type: "router", id: "evasion-engine-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.redteam.payload-gen",
    guide: "user",
    title: "Payload Generator",
    path: "User Guide > Red Team > Payload Generator",
    covers: [
      { type: "route", id: "/payload-generator" },
      { type: "page", id: "PayloadGenerator.tsx" },
      { type: "router", id: "payload-generator-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ USER GUIDE — Purple Team ═══
  {
    id: "user.purple.detection-coverage",
    guide: "user",
    title: "Detection Coverage Analysis",
    path: "User Guide > Purple Team > Detection Coverage",
    covers: [
      { type: "route", id: "/detection-coverage" },
      { type: "page", id: "DetectionCoverage.tsx" },
      { type: "router", id: "detection-coverage-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.purple.agentless-bas",
    guide: "user",
    title: "Agentless BAS",
    path: "User Guide > Purple Team > Agentless BAS",
    covers: [
      { type: "route", id: "/agentless-bas" },
      { type: "page", id: "AgentlessBAS.tsx" },
      { type: "router", id: "agentless-bas-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.purple.purple-team",
    guide: "user",
    title: "Purple Team Exercises",
    path: "User Guide > Purple Team > Exercises",
    covers: [
      { type: "route", id: "/purple-team" },
      { type: "page", id: "PurpleTeam.tsx" },
      { type: "router", id: "purple-team-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ USER GUIDE — Blue Team / SOC ═══
  {
    id: "user.blue.threat-intel",
    guide: "user",
    title: "Threat Intelligence Hub",
    path: "User Guide > Blue Team > Threat Intel Hub",
    covers: [
      { type: "route", id: "/threat-intel-hub" },
      { type: "page", id: "ThreatIntelHub.tsx" },
      { type: "router", id: "threat-intel-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.blue.darkweb",
    guide: "user",
    title: "Dark Web Intelligence",
    path: "User Guide > Blue Team > Dark Web Intel",
    covers: [
      { type: "route", id: "/darkweb-intel" },
      { type: "page", id: "DarkwebIntel.tsx" },
      { type: "router", id: "darkweb-intel-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.blue.osint",
    guide: "user",
    title: "OSINT Monitor",
    path: "User Guide > Blue Team > OSINT Monitor",
    covers: [
      { type: "route", id: "/osint-monitor" },
      { type: "page", id: "OSINTMonitor.tsx" },
      { type: "router", id: "osint-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.blue.apt-library",
    guide: "user",
    title: "APT Library",
    path: "User Guide > Blue Team > APT Library",
    covers: [
      { type: "route", id: "/apt-library" },
      { type: "page", id: "APTLibrary.tsx" },
      { type: "router", id: "apt-library-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "user.blue.soc-dashboard",
    guide: "user",
    title: "SOC Dashboard",
    path: "User Guide > SOC Analyst > Dashboard",
    covers: [
      { type: "route", id: "/soc-dashboard" },
      { type: "page", id: "SOCDashboard.tsx" },
      { type: "router", id: "soc-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ MSP/MSSP GUIDE ═══
  {
    id: "mssp.tenant-onboarding",
    guide: "msp-mssp",
    title: "Client Tenant Onboarding",
    path: "MSP/MSSP Guide > Client Onboarding",
    covers: [
      { type: "route", id: "/tenants" },
      { type: "page", id: "Tenants.tsx" },
      { type: "router", id: "tenant-router.ts" },
      { type: "schema_table", id: "tenants" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "mssp.managed-scanning",
    guide: "msp-mssp",
    title: "Managed Scanning Services",
    path: "MSP/MSSP Guide > Managed Scanning",
    covers: [
      { type: "route", id: "/domain-intel" },
      { type: "route", id: "/vuln-scanner" },
      { type: "route", id: "/nuclei-scanner" },
      { type: "router", id: "domain-intel-core.ts" },
      { type: "router", id: "vuln-scanner-router.ts" },
      { type: "router", id: "nuclei-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "mssp.managed-pentesting",
    guide: "msp-mssp",
    title: "Managed Penetration Testing",
    path: "MSP/MSSP Guide > Managed Pentesting",
    covers: [
      { type: "route", id: "/engagement-ops" },
      { type: "route", id: "/exploit-arsenal" },
      { type: "router", id: "engagement-router.ts" },
      { type: "server_lib", id: "engagement-orchestrator.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "mssp.client-reporting",
    guide: "msp-mssp",
    title: "Client Reporting and Deliverables",
    path: "MSP/MSSP Guide > Client Reporting",
    covers: [
      { type: "route", id: "/reports" },
      { type: "route", id: "/pentest-report" },
      { type: "page", id: "Reports.tsx" },
      { type: "page", id: "PentestReport.tsx" },
      { type: "router", id: "report-router.ts" },
      { type: "router", id: "pentest-report-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },

  // ═══ EMBER DESIGN ═══
  {
    id: "ember.deployment-models",
    guide: "ember-design",
    title: "Deployment Models",
    path: "Ember Design > Deployment Models",
    covers: [
      { type: "server_lib", id: "ember-agent-core.ts", exports: ["generateEmberPayload", "EMBER_PROFILE_DESCRIPTIONS"] },
      { type: "page", id: "EmberDeploy.tsx" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
  {
    id: "ember.fips-crypto",
    guide: "ember-design",
    title: "FIPS 140-3 Cryptographic Architecture",
    path: "Ember Design > FIPS Crypto",
    covers: [
      { type: "page", id: "FIPSCompliance.tsx" },
      { type: "router", id: "ember-agent-router.ts" },
    ],
    lastVerifiedVersion: "",
    lastUpdated: 0,
  },
];

// ─── Platform Snapshot Builder ──────────────────────────────────────────────

/**
 * Builds a snapshot of the current platform state by scanning the filesystem.
 * This is called periodically or on-demand to detect changes.
 */
export function buildSnapshotFromFileList(files: {
  routes: Array<{ path: string; component: string; protected: boolean }>;
  routers: Array<{ file: string; lineCount: number; lastModified: number }>;
  schemaTables: Array<{ name: string; columns: string[] }>;
  serverLibs: Array<{ file: string; lineCount: number; lastModified: number }>;
  pages: Array<{ file: string; route: string; lineCount: number; lastModified: number }>;
}): PlatformSnapshot {
  const version = new Date().toISOString();
  return {
    version,
    timestamp: Date.now(),
    routes: files.routes.map(r => ({
      path: r.path,
      component: r.component,
      protected: r.protected,
    })),
    routers: files.routers.map(r => ({
      file: r.file,
      procedures: [], // populated by deeper analysis
      lineCount: r.lineCount,
      lastModified: r.lastModified,
    })),
    schemaTables: files.schemaTables.map(t => ({
      name: t.name,
      columns: t.columns,
      lineRange: [0, 0] as [number, number],
    })),
    serverLibs: files.serverLibs.map(l => ({
      file: l.file,
      exports: [],
      lineCount: l.lineCount,
      lastModified: l.lastModified,
    })),
    integrations: [], // populated from env analysis
    pages: files.pages.map(p => ({
      file: p.file,
      route: p.route,
      lineCount: p.lineCount,
      lastModified: p.lastModified,
    })),
  };
}

// ─── Diff Engine ────────────────────────────────────────────────────────────

/**
 * Compares two platform snapshots and returns the differences.
 */
export function diffSnapshots(from: PlatformSnapshot, to: PlatformSnapshot): PlatformDiff {
  const diff: PlatformDiff = {
    from: from.version,
    to: to.version,
    added: [],
    removed: [],
    modified: [],
  };

  // Compare routes
  const fromRoutes = new Set(from.routes.map(r => r.path));
  const toRoutes = new Set(to.routes.map(r => r.path));
  for (const r of to.routes) {
    if (!fromRoutes.has(r.path)) {
      diff.added.push({ type: "route", id: r.path, details: `New route: ${r.path} → ${r.component}` });
    }
  }
  for (const r of from.routes) {
    if (!toRoutes.has(r.path)) {
      diff.removed.push({ type: "route", id: r.path, details: `Removed route: ${r.path}` });
    }
  }

  // Compare routers (by file, check line count changes)
  const fromRouterMap = new Map(from.routers.map(r => [r.file, r]));
  const toRouterMap = new Map(to.routers.map(r => [r.file, r]));
  for (const [file, router] of toRouterMap) {
    const prev = fromRouterMap.get(file);
    if (!prev) {
      diff.added.push({ type: "router", id: file, details: `New router: ${file} (${router.lineCount} lines)` });
    } else if (router.lastModified > prev.lastModified || router.lineCount !== prev.lineCount) {
      diff.modified.push({
        type: "router",
        id: file,
        details: `Modified router: ${file} (${prev.lineCount}→${router.lineCount} lines)`,
      });
    }
  }
  for (const [file] of fromRouterMap) {
    if (!toRouterMap.has(file)) {
      diff.removed.push({ type: "router", id: file, details: `Removed router: ${file}` });
    }
  }

  // Compare schema tables
  const fromTables = new Set(from.schemaTables.map(t => t.name));
  const toTables = new Set(to.schemaTables.map(t => t.name));
  const toTableMap = new Map(to.schemaTables.map(t => [t.name, t]));
  const fromTableMap = new Map(from.schemaTables.map(t => [t.name, t]));
  for (const t of to.schemaTables) {
    if (!fromTables.has(t.name)) {
      diff.added.push({ type: "schema_table", id: t.name, details: `New table: ${t.name} (${t.columns.length} columns)` });
    } else {
      const prev = fromTableMap.get(t.name)!;
      const newCols = t.columns.filter(c => !prev.columns.includes(c));
      const removedCols = prev.columns.filter(c => !t.columns.includes(c));
      if (newCols.length > 0 || removedCols.length > 0) {
        diff.modified.push({
          type: "schema_table",
          id: t.name,
          details: `Modified table: ${t.name} (+${newCols.length} cols, -${removedCols.length} cols)`,
        });
      }
    }
  }
  for (const t of from.schemaTables) {
    if (!toTables.has(t.name)) {
      diff.removed.push({ type: "schema_table", id: t.name, details: `Removed table: ${t.name}` });
    }
  }

  // Compare server libs
  const fromLibMap = new Map(from.serverLibs.map(l => [l.file, l]));
  const toLibMap = new Map(to.serverLibs.map(l => [l.file, l]));
  for (const [file, lib] of toLibMap) {
    const prev = fromLibMap.get(file);
    if (!prev) {
      diff.added.push({ type: "server_lib", id: file, details: `New server lib: ${file}` });
    } else if (lib.lastModified > prev.lastModified || lib.lineCount !== prev.lineCount) {
      diff.modified.push({
        type: "server_lib",
        id: file,
        details: `Modified server lib: ${file} (${prev.lineCount}→${lib.lineCount} lines)`,
      });
    }
  }
  for (const [file] of fromLibMap) {
    if (!toLibMap.has(file)) {
      diff.removed.push({ type: "server_lib", id: file, details: `Removed server lib: ${file}` });
    }
  }

  // Compare pages
  const fromPageMap = new Map(from.pages.map(p => [p.file, p]));
  const toPageMap = new Map(to.pages.map(p => [p.file, p]));
  for (const [file, page] of toPageMap) {
    const prev = fromPageMap.get(file);
    if (!prev) {
      diff.added.push({ type: "page", id: file, details: `New page: ${file} (route: ${page.route})` });
    } else if (page.lastModified > prev.lastModified || page.lineCount !== prev.lineCount) {
      diff.modified.push({
        type: "page",
        id: file,
        details: `Modified page: ${file} (${prev.lineCount}→${page.lineCount} lines)`,
      });
    }
  }
  for (const [file] of fromPageMap) {
    if (!toPageMap.has(file)) {
      diff.removed.push({ type: "page", id: file, details: `Removed page: ${file}` });
    }
  }

  return diff;
}

// ─── Doc Impact Analyzer ────────────────────────────────────────────────────

/**
 * Given a platform diff, determines which documentation sections need updating.
 */
export function analyzeDocImpact(diff: PlatformDiff): DocImpact[] {
  const impacts: DocImpact[] = [];
  const allChanges = [...diff.added, ...diff.removed, ...diff.modified];

  for (const change of allChanges) {
    const affectedSections = DOC_MANIFEST.filter(section =>
      section.covers.some(component => {
        // Match by type and id
        if (component.type !== change.type) return false;
        // For routes, match exact path
        if (component.type === "route") return component.id === change.id;
        // For routers and server_libs, match filename
        if (component.type === "router" || component.type === "server_lib") {
          return change.id.includes(component.id) || component.id.includes(change.id);
        }
        // For schema tables, match table name
        if (component.type === "schema_table") return component.id === change.id;
        // For pages, match filename
        if (component.type === "page") {
          return change.id.includes(component.id) || component.id.includes(change.id);
        }
        // For env vars, match var name
        if (component.type === "env_var") return component.id === change.id;
        return false;
      })
    );

    if (affectedSections.length > 0) {
      // Determine severity
      let severity: DocImpact["severity"] = "low";
      if (diff.added.includes(change)) {
        severity = change.type === "route" || change.type === "page" ? "critical" : "moderate";
      } else if (diff.removed.includes(change)) {
        severity = "critical"; // Removed components always critical
      } else if (diff.modified.includes(change)) {
        severity = change.type === "router" || change.type === "schema_table" ? "moderate" : "low";
      }

      // Generate action
      let action = "";
      if (diff.added.includes(change)) {
        action = `Add documentation for new ${change.type}: ${change.id}`;
      } else if (diff.removed.includes(change)) {
        action = `Remove or update references to removed ${change.type}: ${change.id}`;
      } else {
        action = `Review and update documentation for modified ${change.type}: ${change.id}`;
      }

      impacts.push({
        diff: change,
        affectedSections,
        severity,
        action,
      });
    }
  }

  return impacts;
}

// ─── Report Generator ───────────────────────────────────────────────────────

/**
 * Generates a full documentation update report from two snapshots.
 */
export function generateDocUpdateReport(
  fromSnapshot: PlatformSnapshot,
  toSnapshot: PlatformSnapshot
): DocUpdateReport {
  const diff = diffSnapshots(fromSnapshot, toSnapshot);
  const impacts = analyzeDocImpact(diff);

  const affectedSectionIds = new Set(impacts.flatMap(i => i.affectedSections.map(s => s.id)));

  return {
    generatedAt: Date.now(),
    diff,
    impacts,
    stats: {
      totalChanges: diff.added.length + diff.removed.length + diff.modified.length,
      criticalUpdates: impacts.filter(i => i.severity === "critical").length,
      moderateUpdates: impacts.filter(i => i.severity === "moderate").length,
      lowUpdates: impacts.filter(i => i.severity === "low").length,
      sectionsAffected: affectedSectionIds.size,
      sectionsUpToDate: DOC_MANIFEST.length - affectedSectionIds.size,
    },
  };
}

/**
 * Formats a DocUpdateReport as a human-readable Markdown string.
 */
export function formatReportAsMarkdown(report: DocUpdateReport): string {
  const lines: string[] = [];

  lines.push("# Documentation Update Report");
  lines.push("");
  lines.push(`**Generated:** ${new Date(report.generatedAt).toISOString()}`);
  lines.push(`**Platform Diff:** ${report.diff.from} → ${report.diff.to}`);
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Platform Changes | ${report.stats.totalChanges} |`);
  lines.push(`| Critical Doc Updates | ${report.stats.criticalUpdates} |`);
  lines.push(`| Moderate Doc Updates | ${report.stats.moderateUpdates} |`);
  lines.push(`| Low Doc Updates | ${report.stats.lowUpdates} |`);
  lines.push(`| Sections Affected | ${report.stats.sectionsAffected} |`);
  lines.push(`| Sections Up-to-Date | ${report.stats.sectionsUpToDate} |`);
  lines.push("");

  if (report.impacts.length === 0) {
    lines.push("**All documentation is up to date.** No platform changes affect documented sections.");
    return lines.join("\n");
  }

  // Group by severity
  for (const severity of ["critical", "moderate", "low"] as const) {
    const filtered = report.impacts.filter(i => i.severity === severity);
    if (filtered.length === 0) continue;

    const label = severity === "critical" ? "CRITICAL" : severity === "moderate" ? "MODERATE" : "LOW";
    lines.push(`## ${label} Updates`);
    lines.push("");

    for (const impact of filtered) {
      lines.push(`### ${impact.diff.details}`);
      lines.push("");
      lines.push(`**Action:** ${impact.action}`);
      lines.push("");
      lines.push("**Affected Sections:**");
      for (const section of impact.affectedSections) {
        lines.push(`- ${section.path} (\`${section.id}\`)`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
