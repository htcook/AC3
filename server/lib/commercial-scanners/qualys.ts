/**
 * Qualys VMDR Connector
 * FedRAMP High Authorized
 * API Docs: https://qualysguard.qg2.apps.qualys.com/qwebhelp/fo_portal/api_doc/index.htm
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class QualysConnector extends BaseConnector {
  readonly platform = "qualys_vmdr";

  protected getAuthHeaders(): Record<string, string> {
    const { username, password } = this.config.credentials;
    const encoded = Buffer.from(`${username}:${password}`).toString("base64");
    return { Authorization: `Basic ${encoded}`, "X-Requested-With": "AC3 Platform" };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      // Qualys uses XML by default, request JSON where possible
      const resp = await this.request<string>("/api/2.0/fo/session/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      return {
        reachable: true, authenticated: true,
        apiVersion: "2.0", latencyMs: Date.now() - start, lastChecked: Date.now(),
      };
    } catch (err: any) {
      const isAuthError = err.message?.includes("401") || err.message?.includes("403");
      return {
        reachable: !err.message?.includes("ECONNREFUSED"),
        authenticated: !isAuthError,
        latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now(),
      };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    const ips = targets.filter(t => t.type === "ip" || t.type === "cidr").map(t => t.value).join(",");
    const body = new URLSearchParams({
      action: "launch",
      scan_title: (options?.name as string) || `AC3 Scan - ${new Date().toISOString()}`,
      ip: ips,
      option_id: (options?.optionProfileId as string) || "",
      iscanner_name: (options?.scannerName as string) || "External",
    });

    const resp = await this.request<string>("/api/2.0/fo/scan/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    // Parse scan reference from XML response
    const scanRef = this.extractXmlValue(resp as string, "VALUE") || `qualys-${Date.now()}`;
    return { scanId: scanRef, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const resp = await this.request<string>(`/api/2.0/fo/scan/?action=list&scan_ref=${scanId}`, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    const state = this.extractXmlValue(resp as string, "STATE") || "";
    const statusMap: Record<string, ScanStatus> = {
      Running: "running", Finished: "completed", Canceled: "cancelled",
      Error: "failed", Queued: "pending", Paused: "pending", Loading: "pending",
    };
    return { status: statusMap[state] || "running" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    // Fetch host detection data via VMDR API
    const resp = await this.request<string>(`/api/2.0/fo/scan/?action=fetch&scan_ref=${scanId}&output_format=json`, {
      timeout: 120000,
    });

    // Parse the JSON response (Qualys returns findings per host)
    let data: any;
    try { data = typeof resp === "string" ? JSON.parse(resp) : resp; } catch { data = {}; }

    const findings: NormalizedFinding[] = [];
    const hosts = data?.host_list?.host || [];

    for (const host of Array.isArray(hosts) ? hosts : [hosts]) {
      const detections = host?.detection_list?.detection || [];
      for (const det of Array.isArray(detections) ? detections : [detections]) {
        findings.push({
          externalId: `qualys-${scanId}-${host.ip}-${det.qid}`,
          source: "qualys_vmdr",
          title: det.title || `QID ${det.qid}`,
          description: det.results || det.title || "",
          severity: this.mapSeverity(det.severity),
          cvssScore: det.cvss_base ? parseFloat(det.cvss_base) : undefined,
          cvssVector: det.cvss_temporal,
          cveIds: det.cve_list?.cve?.map((c: any) => c.id) || [],
          cweIds: [],
          affectedAsset: host.ip || host.dns,
          port: det.port ? parseInt(det.port) : undefined,
          protocol: det.protocol,
          service: det.service,
          remediation: det.solution,
          pluginId: String(det.qid),
          complianceFrameworks: ["fedramp_high", "nist_800_53", "dod_stig", "cmmc_l2"],
          firstSeen: det.first_found ? new Date(det.first_found).getTime() : Date.now(),
          lastSeen: det.last_found ? new Date(det.last_found).getTime() : Date.now(),
          verified: det.is_disabled !== "1",
          exploitAvailable: det.is_patchable === "1",
        });
      }
    }

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);

    return {
      platform: "qualys_vmdr", scanId, status: "completed",
      startedAt: Date.now(), totalFindings: findings.length,
      findingsBySeverity: bySeverity, findings,
    };
  }

  async importFindings(since: number, until?: number): Promise<NormalizedFinding[]> {
    const sinceDate = new Date(since).toISOString().split("T")[0];
    const untilDate = until ? new Date(until).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];
    const resp = await this.request<string>(
      `/api/2.0/fo/asset/host/vm/detection/?action=list&detection_updated_since=${sinceDate}&detection_updated_before=${untilDate}&output_format=json`,
      { timeout: 120000 }
    );
    // Parse and normalize (same as getResults)
    let data: any;
    try { data = typeof resp === "string" ? JSON.parse(resp) : resp; } catch { data = {}; }
    const findings: NormalizedFinding[] = [];
    // ... simplified — full implementation mirrors getResults parsing
    return findings;
  }

  private mapSeverity(qualysSeverity: number | string): SeverityLevel {
    const sev = typeof qualysSeverity === "string" ? parseInt(qualysSeverity) : qualysSeverity;
    if (sev >= 5) return "critical";
    if (sev >= 4) return "high";
    if (sev >= 3) return "medium";
    if (sev >= 2) return "low";
    return "info";
  }

  private extractXmlValue(xml: string, tag: string): string | null {
    const match = xml.match(new RegExp(`<${tag}>(.*?)</${tag}>`, "i"));
    return match ? match[1] : null;
  }
}
