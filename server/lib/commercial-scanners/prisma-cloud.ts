/**
 * Prisma Cloud (Palo Alto) Connector
 * FedRAMP High Authorized — CSPM, CWPP, CIEM
 * API Docs: https://pan.dev/prisma-cloud/api/cspm/
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class PrismaCloudConnector extends BaseConnector {
  readonly platform = "prisma_cloud";
  private token: string | null = null;
  private tokenExpiry = 0;

  protected getAuthHeaders(): Record<string, string> {
    return this.token ? { "x-redlock-auth": this.token } : {};
  }

  private async authenticate(): Promise<void> {
    const { accessKey, secretKey } = this.config.credentials;
    const resp = await fetch(`${this.config.baseUrl}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: accessKey, password: secretKey }),
    });
    if (!resp.ok) throw new Error(`Prisma Cloud auth failed: ${resp.status}`);
    const data = await resp.json() as { token: string };
    this.token = data.token;
    this.tokenExpiry = Date.now() + 9 * 60 * 1000; // 10 min token, refresh at 9
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      const resp = await this.request<{ customerName: string }>("/v2/profile");
      return { reachable: true, authenticated: true, apiVersion: "v2", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    // Prisma Cloud scans are continuous — we trigger an on-demand scan of a cloud account
    const body = { cloudAccountId: targets[0]?.value, scanType: "full" };
    const resp = await this.request<{ id: string }>("/cloud/scan", { method: "POST", body });
    return { scanId: resp.id || `prisma-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    await this.authenticate();
    return { status: "completed" }; // Prisma Cloud scans are typically instant for posture
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const resp = await this.request<{
      items: Array<{
        id: string; name: string; description: string; severity: string;
        resourceType: string; resourceName: string; accountId: string;
        complianceMetadata: Array<{ standardName: string; requirementId: string }>;
      }>;
    }>("/v2/alert?limit=500&timeType=relative&timeAmount=1&timeUnit=day");

    const findings: NormalizedFinding[] = (resp.items || []).map(a => ({
      externalId: `prisma-${a.id}`, source: "prisma_cloud",
      title: a.name, description: a.description,
      severity: a.severity.toLowerCase() as SeverityLevel,
      cveIds: [], cweIds: [],
      affectedAsset: `${a.resourceType}/${a.resourceName}`,
      complianceFrameworks: ["fedramp_high", "nist_800_53"] as any,
      nistControls: a.complianceMetadata?.filter(c => c.standardName?.includes("NIST")).map(c => c.requirementId),
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "prisma_cloud", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }

  async importFindings(since: number): Promise<NormalizedFinding[]> {
    await this.authenticate();
    const resp = await this.request<{ items: Array<any> }>(
      `/v2/alert?limit=500&timeType=absolute&startTime=${since}&endTime=${Date.now()}`
    );
    return (resp.items || []).map(a => ({
      externalId: `prisma-${a.id}`, source: "prisma_cloud",
      title: a.name || "Alert", description: a.description || "",
      severity: (a.severity || "medium").toLowerCase() as SeverityLevel,
      cveIds: [], cweIds: [], affectedAsset: a.resourceName || "",
      complianceFrameworks: ["fedramp_high", "nist_800_53"] as any,
      firstSeen: since, lastSeen: Date.now(), verified: true,
    }));
  }
}
