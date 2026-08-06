/**
 * Burp Suite Enterprise Connector
 * Uses existing BURP_LICENSE_EMAIL and BURP_LICENSE_PASSWORD secrets.
 * API Docs: https://portswigger.net/burp/documentation/enterprise/api
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class BurpEnterpriseConnector extends BaseConnector {
  readonly platform = "burp_suite_enterprise";

  protected getAuthHeaders(): Record<string, string> {
    const apiKey = this.config.credentials.apiKey || process.env.BURP_ENTERPRISE_API_KEY || "";
    return apiKey ? { Authorization: `Bearer ${apiKey}` } : {};
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      // Burp Enterprise uses GraphQL
      const resp = await this.request<{ data: { __schema: { queryType: { name: string } } } }>("/graphql/v1", {
        method: "POST",
        body: { query: "{ __schema { queryType { name } } }" },
      });
      return { reachable: true, authenticated: true, apiVersion: "graphql/v1", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    const siteId = options?.siteId as string;
    const scanConfigId = options?.scanConfigId as string;

    // Create a scan via GraphQL
    const mutation = `mutation {
      CreateScheduleItem(input: {
        site: { id: "${siteId}" }
        scan_configuration_ids: ["${scanConfigId || ""}"]
        schedule: { initial_run_time: "${new Date().toISOString()}" }
      }) { schedule_item { id } }
    }`;

    const resp = await this.request<{ data: { CreateScheduleItem: { schedule_item: { id: string } } } }>("/graphql/v1", {
      method: "POST", body: { query: mutation },
    });
    return { scanId: resp.data?.CreateScheduleItem?.schedule_item?.id || `burp-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const query = `{ scan(id: "${scanId}") { status audit_items_count audit_items_completed } }`;
    const resp = await this.request<{ data: { scan: { status: string; audit_items_count: number; audit_items_completed: number } } }>("/graphql/v1", {
      method: "POST", body: { query },
    });
    const scan = resp.data?.scan;
    const map: Record<string, ScanStatus> = { running: "running", succeeded: "completed", failed: "failed", cancelled: "cancelled", queued: "pending" };
    const progress = scan?.audit_items_count ? Math.round((scan.audit_items_completed / scan.audit_items_count) * 100) : undefined;
    return { status: map[scan?.status] || "running", progress };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const query = `{
      scan(id: "${scanId}") {
        status start end
        issue_events {
          issue {
            serial_number type_index confidence severity
            origin { url } evidence { request_segments { data_html } }
            description_html remediation_html
            novelty
          }
        }
      }
    }`;
    const resp = await this.request<{ data: { scan: { status: string; start: string; end: string; issue_events: Array<{ issue: any }> } } }>("/graphql/v1", {
      method: "POST", body: { query },
    });

    const scan = resp.data?.scan;
    const findings: NormalizedFinding[] = (scan?.issue_events || []).map((evt: any) => {
      const issue = evt.issue;
      return {
        externalId: `burp-${scanId}-${issue.serial_number}`, source: "burp_suite_enterprise",
        title: `Burp Issue #${issue.type_index}`,
        description: issue.description_html || "",
        severity: this.mapSeverity(issue.severity),
        cveIds: [], cweIds: [],
        affectedAsset: issue.origin?.url || "",
        remediation: issue.remediation_html,
        evidence: issue.evidence?.request_segments?.map((s: any) => s.data_html).join("") || undefined,
        complianceFrameworks: ["nist_800_53"] as any,
        firstSeen: scan.start ? new Date(scan.start).getTime() : Date.now(),
        lastSeen: scan.end ? new Date(scan.end).getTime() : Date.now(),
        verified: issue.confidence === "certain",
      };
    });
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return {
      platform: "burp_suite_enterprise", scanId, status: scan?.status === "succeeded" ? "completed" : "running",
      startedAt: scan?.start ? new Date(scan.start).getTime() : Date.now(),
      completedAt: scan?.end ? new Date(scan.end).getTime() : undefined,
      totalFindings: findings.length, findingsBySeverity: bySeverity, findings,
    };
  }

  async listPolicies(): Promise<Array<{ id: string; name: string; description?: string }>> {
    const query = `{ scan_configurations { id name } }`;
    const resp = await this.request<{ data: { scan_configurations: Array<{ id: string; name: string }> } }>("/graphql/v1", {
      method: "POST", body: { query },
    });
    return (resp.data?.scan_configurations || []).map(c => ({ id: c.id, name: c.name }));
  }

  private mapSeverity(burpSeverity: string): SeverityLevel {
    switch (burpSeverity?.toLowerCase()) {
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      case "info": case "information": return "info";
      default: return "medium";
    }
  }
}
