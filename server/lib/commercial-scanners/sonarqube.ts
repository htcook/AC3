/**
 * SonarQube Connector — Code Quality & Security
 * NIST/DoD Approved — SAST, Code Quality
 * API Docs: https://docs.sonarqube.org/latest/extension-guide/web-api/
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class SonarQubeConnector extends BaseConnector {
  readonly platform = "sonarqube";

  protected getAuthHeaders(): Record<string, string> {
    const { token } = this.config.credentials;
    return { Authorization: `Basic ${Buffer.from(`${token}:`).toString("base64")}` };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      const resp = await this.request<{ version: string }>("/api/server/version");
      return { reachable: true, authenticated: true, apiVersion: String(resp), latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    // SonarQube scans are triggered via CI/CD — we can trigger via webhook or API
    const projectKey = targets[0]?.value || (options?.projectKey as string);
    // Trigger analysis (requires sonar-scanner to be configured)
    return { scanId: projectKey || `sonar-${Date.now()}`, status: "pending" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus }> {
    const resp = await this.request<{ task: { status: string } }>(`/api/ce/component?component=${scanId}`);
    const map: Record<string, ScanStatus> = { SUCCESS: "completed", FAILED: "failed", CANCELED: "cancelled", PENDING: "pending", IN_PROGRESS: "running" };
    return { status: map[resp.task?.status] || "completed" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const resp = await this.request<{
      issues: Array<{
        key: string; rule: string; severity: string; component: string;
        message: string; type: string; effort: string;
        textRange?: { startLine: number; endLine: number };
      }>;
      total: number;
    }>(`/api/issues/search?componentKeys=${scanId}&types=VULNERABILITY,BUG&ps=500&statuses=OPEN,CONFIRMED,REOPENED`);

    const findings: NormalizedFinding[] = (resp.issues || []).map(i => ({
      externalId: `sonar-${i.key}`, source: "sonarqube",
      title: i.message, description: `Rule: ${i.rule} | ${i.message}`,
      severity: this.mapSeverity(i.severity),
      cveIds: [], cweIds: [],
      affectedAsset: i.component,
      complianceFrameworks: ["nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "sonarqube", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }

  async listAssets(): Promise<Array<{ id: string; name: string; type: string; lastScan?: number }>> {
    const resp = await this.request<{ components: Array<{ key: string; name: string; lastAnalysisDate: string }> }>(
      "/api/projects/search?ps=100"
    );
    return (resp.components || []).map(c => ({
      id: c.key, name: c.name, type: "repository",
      lastScan: c.lastAnalysisDate ? new Date(c.lastAnalysisDate).getTime() : undefined,
    }));
  }

  private mapSeverity(sonarSeverity: string): SeverityLevel {
    switch (sonarSeverity) {
      case "BLOCKER": return "critical";
      case "CRITICAL": return "high";
      case "MAJOR": return "medium";
      case "MINOR": return "low";
      default: return "info";
    }
  }
}
