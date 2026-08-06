/**
 * Checkmarx One Connector
 * FedRAMP Authorized — SAST, SCA, KICS (IaC), API Security
 * API Docs: https://checkmarx.com/resource/documents/en/34965-68618-checkmarx-one-api.html
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class CheckmarxConnector extends BaseConnector {
  readonly platform = "checkmarx_one";
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
    const tokenUrl = `${this.config.baseUrl}/auth/realms/${tenant}/protocol/openid-connect/token`;
    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    if (!resp.ok) throw new Error(`Checkmarx auth failed: ${resp.status}`);
    const data = await resp.json() as { access_token: string; expires_in: number };
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      return { reachable: true, authenticated: true, apiVersion: "v1", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    const body = {
      type: "git",
      handler: { repoUrl: targets[0]?.value || "", branch: (options?.branch as string) || "main" },
      project: { id: options?.projectId },
      config: [
        { type: "sast", value: {} },
        { type: "sca", value: {} },
        { type: "kics", value: {} },
      ],
    };
    const resp = await this.request<{ id: string }>("/api/scans", { method: "POST", body });
    return { scanId: resp.id, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    await this.authenticate();
    const resp = await this.request<{ status: string }>(`/api/scans/${scanId}`);
    const map: Record<string, ScanStatus> = { Running: "running", Completed: "completed", Failed: "failed", Canceled: "cancelled", Queued: "pending" };
    return { status: map[resp.status] || "running" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const resp = await this.request<{ results: Array<{ id: string; type: string; severity: string; data: { queryName: string; description: string; cweId: number } }> }>(
      `/api/results?scan-id=${scanId}&limit=500`
    );
    const findings: NormalizedFinding[] = (resp.results || []).map(r => ({
      externalId: `checkmarx-${scanId}-${r.id}`, source: "checkmarx_one",
      title: r.data?.queryName || r.type, description: r.data?.description || "",
      severity: r.severity.toLowerCase() as SeverityLevel,
      cveIds: [], cweIds: r.data?.cweId ? [`CWE-${r.data.cweId}`] : [],
      affectedAsset: "", complianceFrameworks: ["fedramp_moderate", "nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "checkmarx_one", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
