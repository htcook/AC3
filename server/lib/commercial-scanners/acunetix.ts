/**
 * Acunetix (Invicti) Connector
 * NIST/DoD Approved — Web Application Vulnerability Scanner
 * API Docs: https://www.acunetix.com/resources/documentation/
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class AcunetixConnector extends BaseConnector {
  readonly platform = "acunetix";

  protected getAuthHeaders(): Record<string, string> {
    return { "X-Auth": this.config.credentials.apiKey };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.request<{ info: { version: string } }>("/api/v1/info");
      return { reachable: true, authenticated: true, apiVersion: "v1", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    // First add target
    const targetResp = await this.request<{ target_id: string }>("/api/v1/targets", {
      method: "POST",
      body: { address: targets[0]?.value, description: "AC3 scan target" },
    });
    // Then start scan
    const scanResp = await this.request<{ scan_id: string }>("/api/v1/scans", {
      method: "POST",
      body: {
        target_id: targetResp.target_id,
        profile_id: (options?.profileId as string) || "11111111-1111-1111-1111-111111111111", // Full Scan
        schedule: { disable: false, start_date: null, time_sensitive: false },
      },
    });
    return { scanId: scanResp.scan_id, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const resp = await this.request<{ current_session: { status: string; progress: number } }>(`/api/v1/scans/${scanId}`);
    const map: Record<string, ScanStatus> = { processing: "running", completed: "completed", aborted: "cancelled", failed: "failed", scheduled: "pending" };
    return { status: map[resp.current_session?.status] || "running", progress: resp.current_session?.progress };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const resp = await this.request<{
      vulnerabilities: Array<{
        vuln_id: string; severity: number; target_id: string; vt_name: string;
        affects_url: string; confidence: number; criticality: number;
      }>;
    }>(`/api/v1/scans/${scanId}/results`);

    const findings: NormalizedFinding[] = (resp.vulnerabilities || []).map(v => ({
      externalId: `acunetix-${v.vuln_id}`, source: "acunetix",
      title: v.vt_name, description: v.vt_name,
      severity: this.mapSeverity(v.severity),
      cveIds: [], cweIds: [],
      affectedAsset: v.affects_url || "",
      complianceFrameworks: ["nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(),
      verified: v.confidence >= 80,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "acunetix", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }

  private mapSeverity(sev: number): SeverityLevel {
    if (sev >= 4) return "critical";
    if (sev >= 3) return "high";
    if (sev >= 2) return "medium";
    if (sev >= 1) return "low";
    return "info";
  }
}
