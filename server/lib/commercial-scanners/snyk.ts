/**
 * Snyk Connector — Developer-First Security
 * FedRAMP Authorized — SCA, SAST, Container, IaC
 * API Docs: https://docs.snyk.io/snyk-api
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class SnykConnector extends BaseConnector {
  readonly platform = "snyk";

  protected getAuthHeaders(): Record<string, string> {
    return { Authorization: `token ${this.config.credentials.token}` };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      const resp = await this.request<{ orgs: Array<{ id: string; name: string }> }>("/rest/self?version=2024-04-22");
      return { reachable: true, authenticated: true, apiVersion: "rest/v1", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    const orgId = this.config.credentials.orgId || (options?.orgId as string);
    // Snyk test is triggered per project — import or test a target
    const body = { target: { remoteUrl: targets[0]?.value } };
    const resp = await this.request<{ id: string }>(`/rest/orgs/${orgId}/imports?version=2024-04-22`, { method: "POST", body });
    return { scanId: resp.id || `snyk-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus }> {
    return { status: "completed" }; // Snyk tests are typically synchronous
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const orgId = this.config.credentials.orgId;
    const resp = await this.request<{
      issues: Array<{
        id: string; title: string; severity: string; type: string;
        pkgName: string; pkgVersions: string[]; identifiers: { CVE: string[]; CWE: string[] };
        isUpgradable: boolean; isPatchable: boolean; description: string;
      }>;
    }>(`/v1/org/${orgId}/project/${scanId}/aggregated-issues`);

    const findings: NormalizedFinding[] = (resp.issues || []).map(i => ({
      externalId: `snyk-${i.id}`, source: "snyk",
      title: i.title, description: i.description || "",
      severity: i.severity.toLowerCase() as SeverityLevel,
      cveIds: i.identifiers?.CVE || [], cweIds: i.identifiers?.CWE || [],
      affectedAsset: `${i.pkgName}@${i.pkgVersions?.[0] || "unknown"}`,
      remediation: i.isUpgradable ? "Upgrade available" : i.isPatchable ? "Patch available" : undefined,
      complianceFrameworks: ["fedramp_moderate", "nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
      exploitAvailable: undefined,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "snyk", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
