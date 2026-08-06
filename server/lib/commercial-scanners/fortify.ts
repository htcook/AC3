/**
 * Fortify on Demand (OpenText) Connector
 * FedRAMP Authorized, DoD STIG Approved
 * API Docs: https://api.ams.fortify.com/swagger/ui/index
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class FortifyConnector extends BaseConnector {
  readonly platform = "fortify_on_demand";
  private accessToken: string | null = null;
  private tokenExpiry = 0;

  protected getAuthHeaders(): Record<string, string> {
    if (this.accessToken && Date.now() < this.tokenExpiry) {
      return { Authorization: `Bearer ${this.accessToken}` };
    }
    return {};
  }

  private async authenticate(): Promise<void> {
    const { clientId, clientSecret, tenant } = this.config.credentials;
    const resp = await fetch(`${this.config.baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        scope: "api-tenant",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (!resp.ok) throw new Error(`Fortify auth failed: ${resp.status}`);
    const data = await resp.json() as { access_token: string; expires_in: number };
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      await this.request("/api/v3/releases?limit=1");
      return { reachable: true, authenticated: true, apiVersion: "v3", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    const releaseId = options?.releaseId as string;
    if (!releaseId) throw new Error("Fortify requires a releaseId to launch a scan");
    const body = {
      startDate: new Date().toISOString(),
      assessmentTypeId: options?.assessmentTypeId || 163, // Static Assessment
      entitlementId: options?.entitlementId,
      entitlementFrequencyType: "SingleScan",
      technologyStack: options?.techStack || "JAVA/J2EE",
    };
    const resp = await this.request<{ scanId: number }>(`/api/v3/releases/${releaseId}/static-scans/start-scan`, { method: "POST", body });
    return { scanId: String(resp.scanId), status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    await this.authenticate();
    const resp = await this.request<{ analysisStatusType: string; pauseDetails?: { percentage: number } }>(`/api/v3/scans/${scanId}`);
    const map: Record<string, ScanStatus> = { InProgress: "running", Completed: "completed", Canceled: "cancelled", Waiting: "pending" };
    return { status: map[resp.analysisStatusType] || "running", progress: resp.pauseDetails?.percentage };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const resp = await this.request<{
      items: Array<{ id: number; category: string; severity: number; primaryLocation: { file: string; line: number }; cwe: number }>;
      totalCount: number;
    }>(`/api/v3/scans/${scanId}/vulnerabilities?limit=500`);

    const findings: NormalizedFinding[] = (resp.items || []).map(v => ({
      externalId: `fortify-${scanId}-${v.id}`, source: "fortify_on_demand",
      title: v.category, description: v.category,
      severity: this.mapSeverity(v.severity),
      cveIds: [], cweIds: v.cwe ? [`CWE-${v.cwe}`] : [],
      affectedAsset: v.primaryLocation?.file || "",
      complianceFrameworks: ["fedramp_moderate", "nist_800_53", "dod_stig"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "fortify_on_demand", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }

  private mapSeverity(sev: number): SeverityLevel {
    if (sev >= 4) return "critical";
    if (sev >= 3) return "high";
    if (sev >= 2) return "medium";
    if (sev >= 1) return "low";
    return "info";
  }
}
