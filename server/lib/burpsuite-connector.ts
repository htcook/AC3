/**
 * Burp Suite Connector — API Integration for Professional & Enterprise/DAST
 *
 * Supports two modes:
 *   1. Burp Suite Professional — REST API on user's local/network Burp instance
 *      - Endpoint pattern: {baseUrl}/{apiKey}/v0.1/...
 *      - Scan management, issue retrieval
 *
 *   2. Burp Suite Enterprise/DAST — REST + GraphQL API on server
 *      - REST: {baseUrl}/api/{apiKey}/...
 *      - GraphQL: {baseUrl}/graphql/v1 with Authorization header
 *      - Full scan management, site management, issue tracking
 *
 * Imported issues are normalized into the AC3 bug bounty findings format
 * and can be linked to engagements for tracking.
 */

// ─── Types ───

export type BurpEdition = "professional" | "enterprise";

export interface BurpConfig {
  edition: BurpEdition;
  baseUrl: string; // e.g., http://127.0.0.1:1337 or https://burp.company.com
  apiKey: string;
}

export interface BurpScanStatus {
  scanId: string;
  status: "queued" | "running" | "paused" | "succeeded" | "failed" | "unknown";
  progress: number; // 0-100
  issueCount: number;
  startTime?: string;
  endTime?: string;
  auditItemsCount?: number;
  crawlRequestsCount?: number;
}

export interface BurpIssue {
  issueType: string;
  name: string;
  severity: "high" | "medium" | "low" | "info";
  confidence: "certain" | "firm" | "tentative";
  host: string;
  path: string;
  description?: string;
  remediation?: string;
  issueBackground?: string;
  remediationBackground?: string;
  serialNumber?: string;
  references?: string[];
  vulnerabilityClassifications?: string[];
}

export interface BurpScanRequest {
  urls: string[];
  scanConfiguration?: string; // Named scan config or JSON config
  resourcePool?: string;
  applicationLogin?: {
    username: string;
    password: string;
    loginUrl?: string;
  };
}

export interface BurpSite {
  id: string;
  name: string;
  url: string;
  scanCount?: number;
  lastScanDate?: string;
}

// ─── Connector Class ───

export class BurpSuiteConnector {
  private config: BurpConfig;

  constructor(config: BurpConfig) {
    this.config = config;
    // Normalize base URL
    this.config.baseUrl = config.baseUrl.replace(/\/+$/, "");
  }

  // ─── Connection Verification ───

  async verify(): Promise<{ valid: boolean; message: string; edition: BurpEdition; version?: string }> {
    if (this.config.edition === "professional") {
      return this.verifyProfessional();
    }
    return this.verifyEnterprise();
  }

  private async verifyProfessional(): Promise<{ valid: boolean; message: string; edition: BurpEdition; version?: string }> {
    try {
      // Burp Pro REST API: GET /{apiKey}/v0.1/ returns API info
      const res = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/v0.1/`, {
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) {
        return { valid: true, message: "Connected to Burp Suite Professional REST API", edition: "professional" };
      }
      if (res.status === 401 || res.status === 403) {
        return { valid: false, message: "Invalid API key — check your Burp Suite REST API settings", edition: "professional" };
      }
      // Try without version prefix (some setups)
      const res2 = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res2.ok) {
        return { valid: true, message: "Connected to Burp Suite Professional REST API (legacy)", edition: "professional" };
      }
      return { valid: false, message: `Burp Suite returned HTTP ${res.status}. Ensure REST API is enabled in Settings > Suite > REST API`, edition: "professional" };
    } catch (err: any) {
      if (err.name === "TimeoutError" || err.message?.includes("timeout")) {
        return { valid: false, message: "Connection timed out — ensure Burp Suite is running and REST API is enabled on the specified URL", edition: "professional" };
      }
      return { valid: false, message: `Connection failed: ${err.message}. Ensure Burp Suite is running with REST API enabled.`, edition: "professional" };
    }
  }

  private async verifyEnterprise(): Promise<{ valid: boolean; message: string; edition: BurpEdition; version?: string }> {
    try {
      // Enterprise/DAST: Try GraphQL introspection
      const res = await fetch(`${this.config.baseUrl}/graphql/v1`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: this.config.apiKey,
        },
        body: JSON.stringify({
          query: `{ __typename }`,
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        return { valid: true, message: "Connected to Burp Suite Enterprise/DAST GraphQL API", edition: "enterprise" };
      }

      // Try REST API fallback
      const restRes = await fetch(`${this.config.baseUrl}/api/${this.config.apiKey}/`, {
        signal: AbortSignal.timeout(5000),
      });
      if (restRes.ok) {
        return { valid: true, message: "Connected to Burp Suite Enterprise/DAST REST API", edition: "enterprise" };
      }

      if (res.status === 401 || res.status === 403) {
        return { valid: false, message: "Invalid API key — create an API user in Burp Suite DAST settings", edition: "enterprise" };
      }
      return { valid: false, message: `Burp Suite DAST returned HTTP ${res.status}`, edition: "enterprise" };
    } catch (err: any) {
      return { valid: false, message: `Connection failed: ${err.message}`, edition: "enterprise" };
    }
  }

  // ─── Scan Management (Professional) ───

  async startScanPro(request: BurpScanRequest): Promise<{ scanId: string }> {
    const body: any = {
      urls: request.urls,
    };
    if (request.scanConfiguration) {
      body.scan_configurations = [{ type: "NamedConfiguration", name: request.scanConfiguration }];
    }
    if (request.applicationLogin) {
      body.application_logins = [{
        password: request.applicationLogin.password,
        username: request.applicationLogin.username,
      }];
    }
    if (request.resourcePool) {
      body.resource_pool = request.resourcePool;
    }

    const res = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Failed to start scan: HTTP ${res.status} — ${text}`);
    }

    // Burp Pro returns the scan task ID in the Location header
    const location = res.headers.get("Location") || "";
    const scanId = location.split("/").pop() || `scan-${Date.now()}`;
    return { scanId };
  }

  async getScanStatusPro(scanId: string): Promise<BurpScanStatus> {
    const res = await fetch(
      `${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan/${scanId}`,
      { signal: AbortSignal.timeout(10000) }
    );

    if (!res.ok) {
      throw new Error(`Failed to get scan status: HTTP ${res.status}`);
    }

    const data = await res.json();
    return {
      scanId,
      status: mapBurpStatus(data.scan_status || "unknown"),
      progress: data.scan_metrics?.crawl_and_audit_progress || 0,
      issueCount: data.issue_events?.length || 0,
      auditItemsCount: data.scan_metrics?.audit_items_count,
      crawlRequestsCount: data.scan_metrics?.crawl_requests_made,
    };
  }

  async getScanIssuesPro(scanId: string): Promise<BurpIssue[]> {
    const res = await fetch(
      `${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan/${scanId}`,
      { signal: AbortSignal.timeout(15000) }
    );

    if (!res.ok) {
      throw new Error(`Failed to get scan issues: HTTP ${res.status}`);
    }

    const data = await res.json();
    const issueEvents = data.issue_events || [];

    return issueEvents.map((event: any) => {
      const issue = event.issue || {};
      return {
        issueType: issue.type_index?.toString() || "unknown",
        name: issue.name || "Unknown Issue",
        severity: mapBurpSeverity(issue.severity || "information"),
        confidence: mapBurpConfidence(issue.confidence || "tentative"),
        host: issue.origin || "",
        path: issue.path || "/",
        description: issue.description || "",
        remediation: issue.remediation || "",
        issueBackground: issue.issue_background || "",
        remediationBackground: issue.remediation_background || "",
        serialNumber: issue.serial_number?.toString(),
        vulnerabilityClassifications: issue.vulnerability_classifications
          ? [issue.vulnerability_classifications]
          : [],
      };
    });
  }

  // ─── Scan Management (Enterprise/DAST via GraphQL) ───

  async listSitesEnterprise(): Promise<BurpSite[]> {
    const query = `
      query {
        sites {
          id
          name
          scope {
            included_urls
          }
          scans(limit: 1, offset: 0) {
            id
          }
        }
      }
    `;

    const data = await this.graphqlQuery(query);
    return (data.sites || []).map((s: any) => ({
      id: s.id,
      name: s.name,
      url: s.scope?.included_urls?.[0] || "",
      scanCount: s.scans?.length || 0,
    }));
  }

  async listScansEnterprise(siteId?: string): Promise<BurpScanStatus[]> {
    const filter = siteId ? `(site_id: "${siteId}")` : "(limit: 20, offset: 0)";
    const query = `
      query {
        scans${filter} {
          id
          status
          start_time
          end_time
          issue_count
          audit_items_count
          crawl_requests_count
        }
      }
    `;

    const data = await this.graphqlQuery(query);
    return (data.scans || []).map((s: any) => ({
      scanId: s.id,
      status: mapBurpStatus(s.status || "unknown"),
      progress: s.status === "succeeded" ? 100 : 50,
      issueCount: s.issue_count || 0,
      startTime: s.start_time,
      endTime: s.end_time,
      auditItemsCount: s.audit_items_count,
      crawlRequestsCount: s.crawl_requests_count,
    }));
  }

  async getScanIssuesEnterprise(scanId: string): Promise<BurpIssue[]> {
    const query = `
      query {
        scan(id: "${scanId}") {
          issues {
            issue_type {
              type_index
              name
              description_html
              remediation_html
              vulnerability_classifications_html
              references_html
            }
            severity
            confidence
            origin
            path
            serial_number
          }
        }
      }
    `;

    const data = await this.graphqlQuery(query);
    const issues = data.scan?.issues || [];

    return issues.map((i: any) => ({
      issueType: i.issue_type?.type_index?.toString() || "unknown",
      name: i.issue_type?.name || "Unknown Issue",
      severity: mapBurpSeverity(i.severity || "info"),
      confidence: mapBurpConfidence(i.confidence || "tentative"),
      host: i.origin || "",
      path: i.path || "/",
      description: stripHtml(i.issue_type?.description_html || ""),
      remediation: stripHtml(i.issue_type?.remediation_html || ""),
      serialNumber: i.serial_number?.toString(),
      vulnerabilityClassifications: i.issue_type?.vulnerability_classifications_html
        ? [stripHtml(i.issue_type.vulnerability_classifications_html)]
        : [],
    }));
  }

  async startScanEnterprise(siteId: string, configName?: string): Promise<{ scanId: string }> {
    const configArg = configName
      ? `, scan_configuration_ids: ["${configName}"]`
      : "";
    const query = `
      mutation {
        create_scan(input: {
          site_id: "${siteId}"
          ${configArg}
        }) {
          scan {
            id
          }
        }
      }
    `;

    const data = await this.graphqlQuery(query);
    return { scanId: data.create_scan?.scan?.id || `scan-${Date.now()}` };
  }

  // ─── Unified Interface ───

  async getIssues(scanId: string): Promise<BurpIssue[]> {
    if (this.config.edition === "professional") {
      return this.getScanIssuesPro(scanId);
    }
    return this.getScanIssuesEnterprise(scanId);
  }

  async getScanStatus(scanId: string): Promise<BurpScanStatus> {
    if (this.config.edition === "professional") {
      return this.getScanStatusPro(scanId);
    }
    // Enterprise: use GraphQL
    const query = `
      query {
        scan(id: "${scanId}") {
          id status start_time end_time issue_count
          audit_items_count crawl_requests_count
        }
      }
    `;
    const data = await this.graphqlQuery(query);
    const s = data.scan || {};
    return {
      scanId: s.id || scanId,
      status: mapBurpStatus(s.status || "unknown"),
      progress: s.status === "succeeded" ? 100 : 50,
      issueCount: s.issue_count || 0,
      startTime: s.start_time,
      endTime: s.end_time,
      auditItemsCount: s.audit_items_count,
      crawlRequestsCount: s.crawl_requests_count,
    };
  }

  // ─── GraphQL Helper ───

  private async graphqlQuery(query: string): Promise<any> {
    const res = await fetch(`${this.config.baseUrl}/graphql/v1`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: this.config.apiKey,
      },
      body: JSON.stringify({ query }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`GraphQL request failed: HTTP ${res.status} — ${text}`);
    }

    const json = await res.json();
    if (json.errors?.length) {
      throw new Error(`GraphQL errors: ${json.errors.map((e: any) => e.message).join(", ")}`);
    }

    return json.data || {};
  }
}

// ─── Issue Normalizer — Convert Burp issues to AC3 bug bounty findings format ───

export interface NormalizedBurpFinding {
  title: string;
  severityRating: "critical" | "high" | "medium" | "low" | "none";
  summary: string;
  assetIdentifier: string;
  assetType: string;
  cweId: string | null;
  cveIds: string[];
  reportUrl: string | null;
  platform: "burpsuite";
  programHandle: string;
  metadata: {
    burpIssueType: string;
    confidence: string;
    path: string;
    remediation: string;
    issueBackground: string;
    serialNumber: string | null;
    source: "burp_professional" | "burp_enterprise";
  };
}

export function normalizeBurpIssues(
  issues: BurpIssue[],
  engagementHandle: string,
  edition: BurpEdition
): NormalizedBurpFinding[] {
  return issues.map((issue) => {
    // Extract CWE from vulnerability classifications
    const cweMatch = (issue.vulnerabilityClassifications || [])
      .join(" ")
      .match(/CWE-(\d+)/);

    return {
      title: issue.name,
      severityRating: issue.severity === "info" ? "none" : issue.severity,
      summary: truncate(issue.description || issue.issueBackground || "", 2000),
      assetIdentifier: issue.host,
      assetType: "URL",
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
      cveIds: [],
      reportUrl: null,
      platform: "burpsuite" as const,
      programHandle: engagementHandle,
      metadata: {
        burpIssueType: issue.issueType,
        confidence: issue.confidence,
        path: issue.path,
        remediation: issue.remediation || "",
        issueBackground: issue.issueBackground || "",
        serialNumber: issue.serialNumber || null,
        source: edition === "professional" ? "burp_professional" : "burp_enterprise",
      },
    };
  });
}

// ─── Helpers ───

function mapBurpStatus(status: string): BurpScanStatus["status"] {
  const map: Record<string, BurpScanStatus["status"]> = {
    queued: "queued",
    running: "running",
    paused: "paused",
    succeeded: "succeeded",
    completed: "succeeded",
    failed: "failed",
    cancelled: "failed",
  };
  return map[status.toLowerCase()] || "unknown";
}

function mapBurpSeverity(severity: string): BurpIssue["severity"] {
  const map: Record<string, BurpIssue["severity"]> = {
    high: "high",
    medium: "medium",
    low: "low",
    information: "info",
    info: "info",
  };
  return map[severity.toLowerCase()] || "info";
}

function mapBurpConfidence(confidence: string): BurpIssue["confidence"] {
  const map: Record<string, BurpIssue["confidence"]> = {
    certain: "certain",
    firm: "firm",
    tentative: "tentative",
  };
  return map[confidence.toLowerCase()] || "tentative";
}

function stripHtml(html: string): string {
  return html
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}
