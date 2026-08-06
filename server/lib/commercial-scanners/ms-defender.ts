/**
 * Microsoft Defender Vulnerability Management Connector
 * FedRAMP High, DoD IL5 — Endpoint Vulnerability Assessment
 * API Docs: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api/
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class MsDefenderConnector extends BaseConnector {
  readonly platform = "ms_defender_vuln";
  private accessToken: string | null = null;
  private tokenExpiry = 0;

  protected getAuthHeaders(): Record<string, string> {
    return this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {};
  }

  private async authenticate(): Promise<void> {
    const { tenantId, clientId, clientSecret } = this.config.credentials;
    const tokenUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId, client_secret: clientSecret,
        scope: "https://api.securitycenter.microsoft.com/.default",
        grant_type: "client_credentials",
      }),
    });
    if (!resp.ok) throw new Error(`MS Defender auth failed: ${resp.status}`);
    const data = await resp.json() as { access_token: string; expires_in: number };
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      await this.request("/api/machines?$top=1");
      return { reachable: true, authenticated: true, apiVersion: "v1.0", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[]): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    return { scanId: `defender-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus }> {
    return { status: "completed" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const baseUrl = this.config.baseUrl || "https://api.securitycenter.microsoft.com";
    const resp = await this.request<{
      value: Array<{
        id: string; cveId: string; machineId: string; severity: string;
        productName: string; productVersion: string;
        recommendedSecurityUpdate: string; firstDetectedTimestamp: string;
      }>;
    }>("/api/vulnerabilities/machinesVulnerabilities?$top=500");

    const findings: NormalizedFinding[] = (resp.value || []).map(v => ({
      externalId: `defender-${v.id}`, source: "ms_defender_vuln",
      title: `${v.cveId} - ${v.productName} ${v.productVersion}`,
      description: `Vulnerability in ${v.productName} ${v.productVersion}`,
      severity: v.severity.toLowerCase() as SeverityLevel,
      cveIds: v.cveId ? [v.cveId] : [], cweIds: [],
      affectedAsset: v.machineId,
      remediation: v.recommendedSecurityUpdate,
      complianceFrameworks: ["fedramp_high", "dod_il5", "nist_800_53", "cmmc_l2"] as any,
      firstSeen: v.firstDetectedTimestamp ? new Date(v.firstDetectedTimestamp).getTime() : Date.now(),
      lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "ms_defender_vuln", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
