/**
 * Rapid7 InsightVM (Nexpose) Connector
 * FedRAMP Authorized
 * API Docs: https://help.rapid7.com/insightvm/en-us/api/index.html
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class Rapid7Connector extends BaseConnector {
  readonly platform = "rapid7_insightvm";

  protected getAuthHeaders(): Record<string, string> {
    const { apiKey } = this.config.credentials;
    return { "X-Api-Key": apiKey };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      const resp = await this.request<{ version: string }>("/api/3/administration/info");
      return {
        reachable: true, authenticated: true,
        apiVersion: resp.version, latencyMs: Date.now() - start, lastChecked: Date.now(),
      };
    } catch (err: any) {
      return {
        reachable: !err.message?.includes("ECONNREFUSED"),
        authenticated: !err.message?.includes("401"),
        latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now(),
      };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    const ips = targets.filter(t => t.type === "ip" || t.type === "cidr").map(t => t.value);
    const body = {
      name: (options?.name as string) || `AC3 Scan - ${new Date().toISOString()}`,
      assets: { includedTargets: { addresses: ips } },
      engineId: options?.engineId || 1,
      templateId: (options?.templateId as string) || "full-audit-without-web-spider",
    };

    const resp = await this.request<{ id: number }>("/api/3/sites/1/scans", { method: "POST", body });
    return { scanId: String(resp.id), status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const resp = await this.request<{ status: string; scanName: string }>(`/api/3/scans/${scanId}`);
    const statusMap: Record<string, ScanStatus> = {
      running: "running", finished: "completed", aborted: "cancelled",
      stopped: "cancelled", error: "failed", paused: "pending", dispatched: "pending",
    };
    return { status: statusMap[resp.status] || "running" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    // Get vulnerabilities from the scan
    const resp = await this.request<{
      resources: Array<{
        id: string; title: string; description: { text: string }; severity: string;
        cvss: { v3: { score: number; vector: string } };
        cves: string[]; instances: number;
      }>;
      page: { totalResources: number };
    }>(`/api/3/scans/${scanId}/vulnerabilities?size=500`);

    const findings: NormalizedFinding[] = (resp.resources || []).map(vuln => ({
      externalId: `rapid7-${scanId}-${vuln.id}`,
      source: "rapid7_insightvm",
      title: vuln.title,
      description: vuln.description?.text || vuln.title,
      severity: this.mapSeverity(vuln.severity),
      cvssScore: vuln.cvss?.v3?.score,
      cvssVector: vuln.cvss?.v3?.vector,
      cveIds: vuln.cves || [],
      cweIds: [],
      affectedAsset: "",
      complianceFrameworks: ["fedramp_moderate", "nist_800_53", "dod_stig"] as any,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      verified: true,
    }));

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);

    return {
      platform: "rapid7_insightvm", scanId, status: "completed",
      startedAt: Date.now(), totalFindings: findings.length,
      findingsBySeverity: bySeverity, findings,
    };
  }

  async listAssets(): Promise<Array<{ id: string; name: string; type: string; lastScan?: number }>> {
    const resp = await this.request<{
      resources: Array<{ id: number; hostName: string; ip: string; assessedForVulnerabilities: boolean }>;
    }>("/api/3/assets?size=100");
    return (resp.resources || []).map(a => ({
      id: String(a.id), name: a.hostName || a.ip, type: a.hostName ? "hostname" : "ip",
    }));
  }

  private mapSeverity(severity: string): SeverityLevel {
    switch (severity?.toLowerCase()) {
      case "critical": return "critical";
      case "severe": return "high";
      case "moderate": return "medium";
      case "low": return "low";
      default: return "info";
    }
  }
}
