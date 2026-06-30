/**
 * Anchore Enterprise Connector
 * FedRAMP Authorized, DoD Iron Bank Approved — Container Security & SBOM
 * API Docs: https://docs.anchore.com/current/docs/api/
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class AnchoreConnector extends BaseConnector {
  readonly platform = "anchore_enterprise";

  protected getAuthHeaders(): Record<string, string> {
    const { username, password } = this.config.credentials;
    return { Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}` };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      const resp = await this.request<{ version: string }>("/version");
      return { reachable: true, authenticated: true, apiVersion: resp.version, latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[]): Promise<{ scanId: string; status: ScanStatus }> {
    const imageTag = targets[0]?.value || "";
    const body = { source: { tag: { pullstring: imageTag } } };
    const resp = await this.request<Array<{ imageDigest: string }>>("/images", { method: "POST", body });
    return { scanId: resp[0]?.imageDigest || `anchore-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus }> {
    const resp = await this.request<Array<{ analysis_status: string }>>(`/images/${scanId}`);
    const status = resp[0]?.analysis_status;
    const map: Record<string, ScanStatus> = { analyzed: "completed", analyzing: "running", not_analyzed: "pending" };
    return { status: map[status] || "running" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const resp = await this.request<{
      vulnerabilities: Array<{
        vuln: string; severity: string; package: string; package_version: string;
        fix: string; url: string; feed_group: string;
      }>;
    }>(`/images/${scanId}/vuln/all`);

    const findings: NormalizedFinding[] = (resp.vulnerabilities || []).map(v => ({
      externalId: `anchore-${scanId}-${v.vuln}-${v.package}`, source: "anchore_enterprise",
      title: `${v.vuln} in ${v.package}:${v.package_version}`,
      description: `Vulnerability ${v.vuln} found in package ${v.package} version ${v.package_version}`,
      severity: v.severity.toLowerCase() as SeverityLevel,
      cveIds: v.vuln.startsWith("CVE") ? [v.vuln] : [], cweIds: [],
      affectedAsset: `${v.package}:${v.package_version}`,
      remediation: v.fix ? `Update to ${v.fix}` : undefined,
      complianceFrameworks: ["fedramp_moderate", "nist_800_53", "dod_stig"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "anchore_enterprise", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
