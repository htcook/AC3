import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/burpsuite-connector.ts
function normalizeBurpIssues(issues, engagementHandle, edition) {
  return issues.map((issue) => {
    const cweMatch = (issue.vulnerabilityClassifications || []).join(" ").match(/CWE-(\d+)/);
    return {
      title: issue.name,
      severityRating: issue.severity === "info" ? "none" : issue.severity,
      summary: truncate(issue.description || issue.issueBackground || "", 2e3),
      assetIdentifier: issue.host,
      assetType: "URL",
      cweId: cweMatch ? `CWE-${cweMatch[1]}` : null,
      cveIds: [],
      reportUrl: null,
      platform: "burpsuite",
      programHandle: engagementHandle,
      metadata: {
        burpIssueType: issue.issueType,
        confidence: issue.confidence,
        path: issue.path,
        remediation: issue.remediation || "",
        issueBackground: issue.issueBackground || "",
        serialNumber: issue.serialNumber || null,
        source: edition === "professional" ? "burp_professional" : "burp_enterprise"
      }
    };
  });
}
function mapBurpStatus(status) {
  const map = {
    queued: "queued",
    running: "running",
    paused: "paused",
    succeeded: "succeeded",
    completed: "succeeded",
    failed: "failed",
    cancelled: "failed"
  };
  return map[status.toLowerCase()] || "unknown";
}
function mapBurpSeverity(severity) {
  const map = {
    high: "high",
    medium: "medium",
    low: "low",
    information: "info",
    info: "info"
  };
  return map[severity.toLowerCase()] || "info";
}
function mapBurpConfidence(confidence) {
  const map = {
    certain: "certain",
    firm: "firm",
    tentative: "tentative"
  };
  return map[confidence.toLowerCase()] || "tentative";
}
function stripHtml(html) {
  return html.replace(/<[^>]*>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();
}
function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + "...";
}
var BurpSuiteConnector;
var init_burpsuite_connector = __esm({
  "server/lib/burpsuite-connector.ts"() {
    BurpSuiteConnector = class {
      constructor(config) {
        this.config = config;
        this.config.baseUrl = config.baseUrl.replace(/\/+$/, "");
      }
      // ─── Connection Verification ───
      async verify() {
        if (this.config.edition === "professional") {
          return this.verifyProfessional();
        }
        return this.verifyEnterprise();
      }
      async verifyProfessional() {
        try {
          const res = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/v0.1/`, {
            signal: AbortSignal.timeout(1e4)
          });
          if (res.ok) {
            return { valid: true, message: "Connected to Burp Suite Professional REST API", edition: "professional" };
          }
          if (res.status === 401 || res.status === 403) {
            return { valid: false, message: "Invalid API key \u2014 check your Burp Suite REST API settings", edition: "professional" };
          }
          const res2 = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/`, {
            signal: AbortSignal.timeout(5e3)
          });
          if (res2.ok) {
            return { valid: true, message: "Connected to Burp Suite Professional REST API (legacy)", edition: "professional" };
          }
          return { valid: false, message: `Burp Suite returned HTTP ${res.status}. Ensure REST API is enabled in Settings > Suite > REST API`, edition: "professional" };
        } catch (err) {
          if (err.name === "TimeoutError" || err.message?.includes("timeout")) {
            return { valid: false, message: "Connection timed out \u2014 ensure Burp Suite is running and REST API is enabled on the specified URL", edition: "professional" };
          }
          return { valid: false, message: `Connection failed: ${err.message}. Ensure Burp Suite is running with REST API enabled.`, edition: "professional" };
        }
      }
      async verifyEnterprise() {
        try {
          const res = await fetch(`${this.config.baseUrl}/graphql/v1`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: this.config.apiKey
            },
            body: JSON.stringify({
              query: `{ __typename }`
            }),
            signal: AbortSignal.timeout(1e4)
          });
          if (res.ok) {
            return { valid: true, message: "Connected to Burp Suite Enterprise/DAST GraphQL API", edition: "enterprise" };
          }
          const restRes = await fetch(`${this.config.baseUrl}/api/${this.config.apiKey}/`, {
            signal: AbortSignal.timeout(5e3)
          });
          if (restRes.ok) {
            return { valid: true, message: "Connected to Burp Suite Enterprise/DAST REST API", edition: "enterprise" };
          }
          if (res.status === 401 || res.status === 403) {
            return { valid: false, message: "Invalid API key \u2014 create an API user in Burp Suite DAST settings", edition: "enterprise" };
          }
          return { valid: false, message: `Burp Suite DAST returned HTTP ${res.status}`, edition: "enterprise" };
        } catch (err) {
          return { valid: false, message: `Connection failed: ${err.message}`, edition: "enterprise" };
        }
      }
      // ─── Scan Management (Professional) ───
      async startScanPro(request) {
        const body = {
          urls: request.urls
        };
        if (request.scanConfiguration) {
          body.scan_configurations = [{ type: "NamedConfiguration", name: request.scanConfiguration }];
        }
        if (request.applicationLogin) {
          body.application_logins = [{
            password: request.applicationLogin.password,
            username: request.applicationLogin.username
          }];
        }
        if (request.resourcePool) {
          body.resource_pool = request.resourcePool;
        }
        const res = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(15e3)
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          if (res.status === 400 && text.includes("Unknown configuration") && body.scan_configurations) {
            console.warn(`[BurpConnector] Named config "${request.scanConfiguration}" not found, retrying with Burp defaults`);
            delete body.scan_configurations;
            const retryRes = await fetch(`${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(body),
              signal: AbortSignal.timeout(15e3)
            });
            if (!retryRes.ok) {
              const retryText = await retryRes.text().catch(() => "");
              throw new Error(`Failed to start scan (retry without config): HTTP ${retryRes.status} \u2014 ${retryText}`);
            }
            const retryLocation = retryRes.headers.get("Location") || "";
            const retryScanId = retryLocation.split("/").pop() || `scan-${Date.now()}`;
            return { scanId: retryScanId };
          }
          throw new Error(`Failed to start scan: HTTP ${res.status} \u2014 ${text}`);
        }
        const location = res.headers.get("Location") || "";
        const scanId = location.split("/").pop() || `scan-${Date.now()}`;
        return { scanId };
      }
      async getScanStatusPro(scanId) {
        const res = await fetch(
          `${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan/${scanId}`,
          { signal: AbortSignal.timeout(1e4) }
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
          crawlRequestsCount: data.scan_metrics?.crawl_requests_made
        };
      }
      async getScanIssuesPro(scanId) {
        const res = await fetch(
          `${this.config.baseUrl}/${this.config.apiKey}/v0.1/scan/${scanId}`,
          { signal: AbortSignal.timeout(15e3) }
        );
        if (!res.ok) {
          throw new Error(`Failed to get scan issues: HTTP ${res.status}`);
        }
        const data = await res.json();
        const issueEvents = data.issue_events || [];
        return issueEvents.map((event) => {
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
            vulnerabilityClassifications: issue.vulnerability_classifications ? [issue.vulnerability_classifications] : []
          };
        });
      }
      // ─── Scan Management (Enterprise/DAST via GraphQL) ───
      async listSitesEnterprise() {
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
        return (data.sites || []).map((s) => ({
          id: s.id,
          name: s.name,
          url: s.scope?.included_urls?.[0] || "",
          scanCount: s.scans?.length || 0
        }));
      }
      async listScansEnterprise(siteId) {
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
        return (data.scans || []).map((s) => ({
          scanId: s.id,
          status: mapBurpStatus(s.status || "unknown"),
          progress: s.status === "succeeded" ? 100 : 50,
          issueCount: s.issue_count || 0,
          startTime: s.start_time,
          endTime: s.end_time,
          auditItemsCount: s.audit_items_count,
          crawlRequestsCount: s.crawl_requests_count
        }));
      }
      async getScanIssuesEnterprise(scanId) {
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
        return issues.map((i) => ({
          issueType: i.issue_type?.type_index?.toString() || "unknown",
          name: i.issue_type?.name || "Unknown Issue",
          severity: mapBurpSeverity(i.severity || "info"),
          confidence: mapBurpConfidence(i.confidence || "tentative"),
          host: i.origin || "",
          path: i.path || "/",
          description: stripHtml(i.issue_type?.description_html || ""),
          remediation: stripHtml(i.issue_type?.remediation_html || ""),
          serialNumber: i.serial_number?.toString(),
          vulnerabilityClassifications: i.issue_type?.vulnerability_classifications_html ? [stripHtml(i.issue_type.vulnerability_classifications_html)] : []
        }));
      }
      async startScanEnterprise(siteId, configName) {
        const configArg = configName ? `, scan_configuration_ids: ["${configName}"]` : "";
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
      async getIssues(scanId) {
        if (this.config.edition === "professional") {
          return this.getScanIssuesPro(scanId);
        }
        return this.getScanIssuesEnterprise(scanId);
      }
      async getScanStatus(scanId) {
        if (this.config.edition === "professional") {
          return this.getScanStatusPro(scanId);
        }
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
          crawlRequestsCount: s.crawl_requests_count
        };
      }
      // ─── GraphQL Helper ───
      async graphqlQuery(query) {
        const res = await fetch(`${this.config.baseUrl}/graphql/v1`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: this.config.apiKey
          },
          body: JSON.stringify({ query }),
          signal: AbortSignal.timeout(15e3)
        });
        if (!res.ok) {
          const text = await res.text().catch(() => "");
          throw new Error(`GraphQL request failed: HTTP ${res.status} \u2014 ${text}`);
        }
        const json = await res.json();
        if (json.errors?.length) {
          throw new Error(`GraphQL errors: ${json.errors.map((e) => e.message).join(", ")}`);
        }
        return json.data || {};
      }
    };
  }
});

export {
  BurpSuiteConnector,
  normalizeBurpIssues,
  init_burpsuite_connector
};
