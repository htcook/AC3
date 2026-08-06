/**
 * HCL AppScan Connector
 * FedRAMP Authorized — DAST, SAST, IAST, SCA
 * API Docs: https://help.hcltechsw.com/appscan/ASoC/appseccloud_api.html
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class HclAppScanConnector extends BaseConnector {
  readonly platform = "hcl_appscan";
  private token: string | null = null;

  protected getAuthHeaders(): Record<string, string> {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }

  private async authenticate(): Promise<void> {
    const { apiKey, apiSecret } = this.config.credentials;
    const resp = await fetch(`${this.config.baseUrl}/api/v4/Account/ApiKeyLogin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ KeyId: apiKey, KeySecret: apiSecret }),
    });
    if (!resp.ok) throw new Error(`HCL AppScan auth failed: ${resp.status}`);
    const data = await resp.json() as { Token: string };
    this.token = data.Token;
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      return { reachable: true, authenticated: true, apiVersion: "v4", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    const body = {
      ScanType: (options?.scanType as string) || "Production",
      StartingUrl: targets[0]?.value,
      TestPolicy: options?.testPolicy || "Default",
    };
    const resp = await this.request<{ Id: string }>("/api/v4/Scans/DynamicAnalyzer", { method: "POST", body });
    return { scanId: resp.Id, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    await this.authenticate();
    const resp = await this.request<{ LatestExecution: { Status: string; Progress: number } }>(`/api/v4/Scans/${scanId}`);
    const map: Record<string, ScanStatus> = { Running: "running", Ready: "completed", Failed: "failed", Paused: "pending" };
    return { status: map[resp.LatestExecution?.Status] || "running", progress: resp.LatestExecution?.Progress };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const resp = await this.request<{
      Items: Array<{ Id: string; IssueType: string; Severity: string; Url: string; CweId: number; CvssScore: number }>;
      Count: number;
    }>(`/api/v4/Issues?$filter=ScanId eq '${scanId}'&$top=500`);

    const findings: NormalizedFinding[] = (resp.Items || []).map(i => ({
      externalId: `appscan-${i.Id}`, source: "hcl_appscan",
      title: i.IssueType, description: i.IssueType,
      severity: i.Severity.toLowerCase() as SeverityLevel,
      cvssScore: i.CvssScore, cveIds: [], cweIds: i.CweId ? [`CWE-${i.CweId}`] : [],
      affectedAsset: i.Url || "",
      complianceFrameworks: ["fedramp_moderate", "nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "hcl_appscan", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
