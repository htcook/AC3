/**
 * Role-Specific Quick Actions Catalog
 *
 * Defines the actions each role's AI can trigger via tool-calling.
 * Each action has a name, description, parameters schema, and execution handler.
 */

import type { CalderaRole } from "./role-chat-prompts";

export interface QuickActionParam {
  name: string;
  type: "string" | "number" | "boolean";
  description: string;
  required: boolean;
  enum?: string[];
}

export interface QuickAction {
  name: string;
  displayName: string;
  description: string;
  icon: string;
  confirmRequired: boolean;
  params: QuickActionParam[];
}

/** LLM tool-calling format for OpenAI-compatible function calling */
export interface LLMTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, { type: string; description: string; enum?: string[] }>;
      required: string[];
    };
  };
}

const OPERATOR_ACTIONS: QuickAction[] = [
  {
    name: "launch_domain_scan",
    displayName: "Launch Domain Scan",
    description: "Start a domain intelligence scan against a target domain to discover subdomains, open ports, and vulnerabilities",
    icon: "Globe",
    confirmRequired: true,
    params: [
      { name: "domain", type: "string", description: "Target domain to scan (e.g., example.com)", required: true },
    ],
  },
  {
    name: "check_server_health",
    displayName: "Check Server Health",
    description: "Run a health check on a configured Caldera server to verify connectivity and status",
    icon: "HeartPulse",
    confirmRequired: false,
    params: [
      { name: "serverId", type: "number", description: "Server ID to check", required: true },
    ],
  },
  {
    name: "lookup_cve",
    displayName: "Lookup CVE Details",
    description: "Look up details for a specific CVE vulnerability including severity, affected products, and exploit availability",
    icon: "Bug",
    confirmRequired: false,
    params: [
      { name: "cveId", type: "string", description: "CVE identifier (e.g., CVE-2024-1234)", required: true },
    ],
  },
  {
    name: "search_threat_actor",
    displayName: "Search Threat Actor",
    description: "Search the threat actor database for information about a specific APT group or threat actor",
    icon: "UserSearch",
    confirmRequired: false,
    params: [
      { name: "query", type: "string", description: "Threat actor name or alias to search for", required: true },
    ],
  },
  {
    name: "generate_payload",
    displayName: "Generate Payload Command",
    description: "Generate a payload or reverse shell command for a specific platform and protocol",
    icon: "Terminal",
    confirmRequired: true,
    params: [
      { name: "platform", type: "string", description: "Target platform", required: true, enum: ["windows", "linux", "macos"] },
      { name: "protocol", type: "string", description: "Connection protocol", required: true, enum: ["tcp", "http", "https", "dns"] },
      { name: "lhost", type: "string", description: "Listener host IP address", required: true },
      { name: "lport", type: "number", description: "Listener port number", required: true },
    ],
  },
];

const EXECUTIVE_ACTIONS: QuickAction[] = [
  {
    name: "generate_risk_summary",
    displayName: "Generate Risk Summary",
    description: "Generate an executive risk posture summary with key metrics and trends",
    icon: "BarChart3",
    confirmRequired: false,
    params: [],
  },
  {
    name: "export_compliance_report",
    displayName: "Export Compliance Report",
    description: "Generate a compliance status report for a specific framework",
    icon: "FileText",
    confirmRequired: false,
    params: [
      { name: "framework", type: "string", description: "Compliance framework", required: true, enum: ["nist", "iso27001", "soc2", "hipaa", "pci-dss", "cmmc"] },
    ],
  },
  {
    name: "get_engagement_roi",
    displayName: "Engagement ROI Analysis",
    description: "Calculate the return on investment for security engagements based on findings and remediation",
    icon: "TrendingUp",
    confirmRequired: false,
    params: [],
  },
];

const ANALYST_ACTIONS: QuickAction[] = [
  {
    name: "enrich_ioc",
    displayName: "Enrich IOC",
    description: "Enrich an Indicator of Compromise with threat intelligence from multiple sources",
    icon: "Search",
    confirmRequired: false,
    params: [
      { name: "indicator", type: "string", description: "IOC value (IP, domain, hash, or email)", required: true },
      { name: "type", type: "string", description: "IOC type", required: true, enum: ["ip", "domain", "hash", "email", "url"] },
    ],
  },
  {
    name: "search_threat_actor",
    displayName: "Search Threat Actor",
    description: "Search the threat actor database for information about a specific APT group",
    icon: "UserSearch",
    confirmRequired: false,
    params: [
      { name: "query", type: "string", description: "Threat actor name or alias", required: true },
    ],
  },
  {
    name: "generate_stix_bundle",
    displayName: "Generate STIX Bundle",
    description: "Generate a STIX 2.1 bundle for a set of indicators or a threat actor campaign",
    icon: "Package",
    confirmRequired: false,
    params: [
      { name: "actorName", type: "string", description: "Threat actor name to generate STIX bundle for", required: true },
    ],
  },
  {
    name: "lookup_cve",
    displayName: "Lookup CVE Details",
    description: "Look up details for a specific CVE vulnerability",
    icon: "Bug",
    confirmRequired: false,
    params: [
      { name: "cveId", type: "string", description: "CVE identifier (e.g., CVE-2024-1234)", required: true },
    ],
  },
];

const TEAM_LEAD_ACTIONS: QuickAction[] = [
  {
    name: "get_pipeline_summary",
    displayName: "Pipeline Summary",
    description: "Get a summary of the engagement pipeline including status counts and upcoming deadlines",
    icon: "Kanban",
    confirmRequired: false,
    params: [],
  },
  {
    name: "get_team_workload",
    displayName: "Team Workload Report",
    description: "Generate a team workload report showing assignments and capacity",
    icon: "Users",
    confirmRequired: false,
    params: [],
  },
  {
    name: "draft_status_report",
    displayName: "Draft Status Report",
    description: "Draft a client status report for an engagement with current progress and findings",
    icon: "FileText",
    confirmRequired: false,
    params: [
      { name: "engagementId", type: "number", description: "Engagement ID to report on", required: true },
    ],
  },
];

const CLIENT_ACTIONS: QuickAction[] = [
  {
    name: "get_findings_summary",
    displayName: "Findings Summary",
    description: "Get a summary of all findings from your security assessment organized by severity",
    icon: "AlertTriangle",
    confirmRequired: false,
    params: [],
  },
  {
    name: "get_remediation_plan",
    displayName: "Remediation Plan",
    description: "Generate a prioritized remediation plan based on your assessment findings",
    icon: "ClipboardCheck",
    confirmRequired: false,
    params: [],
  },
  {
    name: "explain_finding",
    displayName: "Explain Finding",
    description: "Get a plain-language explanation of a specific security finding and how to fix it",
    icon: "HelpCircle",
    confirmRequired: false,
    params: [
      { name: "findingId", type: "number", description: "Finding ID to explain", required: true },
    ],
  },
];

const ADMIN_ACTIONS: QuickAction[] = [
  {
    name: "check_server_health",
    displayName: "Check Server Health",
    description: "Run a health check on all configured servers and report their status",
    icon: "HeartPulse",
    confirmRequired: false,
    params: [
      { name: "serverId", type: "number", description: "Server ID to check (omit for all servers)", required: false },
    ],
  },
  {
    name: "get_error_report",
    displayName: "Error Report",
    description: "Generate a report of recent platform errors grouped by source and severity",
    icon: "AlertOctagon",
    confirmRequired: false,
    params: [
      { name: "hours", type: "number", description: "Hours to look back (default: 24)", required: false },
    ],
  },
  {
    name: "get_user_activity",
    displayName: "User Activity Report",
    description: "Generate a user activity report showing logins, actions, and engagement across the platform",
    icon: "Activity",
    confirmRequired: false,
    params: [],
  },
  {
    name: "purge_old_errors",
    displayName: "Purge Old Errors",
    description: "Clean up resolved platform errors older than the specified number of days",
    icon: "Trash2",
    confirmRequired: true,
    params: [
      { name: "olderThanDays", type: "number", description: "Delete errors older than this many days (default: 30)", required: false },
    ],
  },
];

const ROLE_ACTIONS: Record<CalderaRole, QuickAction[]> = {
  operator: OPERATOR_ACTIONS,
  executive: EXECUTIVE_ACTIONS,
  analyst: ANALYST_ACTIONS,
  team_lead: TEAM_LEAD_ACTIONS,
  client: CLIENT_ACTIONS,
  admin: ADMIN_ACTIONS,
};

/**
 * Get the quick actions available for a given role.
 */
export function getRoleActions(role: string): QuickAction[] {
  return ROLE_ACTIONS[role as CalderaRole] || OPERATOR_ACTIONS;
}

/**
 * Convert quick actions to LLM tool-calling format.
 */
export function actionsToLLMTools(actions: QuickAction[]): LLMTool[] {
  return actions.map((action) => ({
    type: "function" as const,
    function: {
      name: action.name,
      description: action.description,
      parameters: {
        type: "object" as const,
        properties: Object.fromEntries(
          action.params.map((p) => [
            p.name,
            {
              type: p.type,
              description: p.description,
              ...(p.enum ? { enum: p.enum } : {}),
            },
          ])
        ),
        required: action.params.filter((p) => p.required).map((p) => p.name),
      },
    },
  }));
}
