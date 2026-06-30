/**
 * Tenable.io (Nessus) Connector
 * FedRAMP High Authorized
 * API Docs: https://developer.tenable.com/reference/navigate
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class TenableConnector extends BaseConnector {
  readonly platform = "tenable_io";

  protected getAuthHeaders(): Record<string, string> {
    return {
      "X-ApiKeys": `accessKey=${this.config.credentials.accessKey};secretKey=${this.config.credentials.secretKey}`,
    };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      const resp = await this.request<{ info: { version: string; license?: { type: string } } }>("/server/properties");
      return {
        reachable: true,
        authenticated: true,
        apiVersion: resp.info?.version,
        licenseStatus: resp.info?.license?.type || "unknown",
        latencyMs: Date.now() - start,
        lastChecked: Date.now(),
      };
    } catch (err: any) {
      return {
        reachable: false,
        authenticated: false,
        latencyMs: Date.now() - start,
        error: err.message,
        lastChecked: Date.now(),
      };
    }
  }

  async launchScan(targets: ScanTarget[], options?: Record<string, unknown>): Promise<{ scanId: string; status: ScanStatus }> {
    const targetList = targets.map(t => t.value).join(",");
    const body = {
      uuid: options?.templateUuid || "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65", // Advanced Network Scan
      settings: {
        name: options?.name || `AC3 Scan - ${new Date().toISOString()}`,
        text_targets: targetList,
        launch: "ON_DEMAND",
        enabled: true,
        scanner_id: options?.scannerId || 1,
        folder_id: options?.folderId,
        policy_id: options?.policyId,
      },
    };

    const scan = await this.request<{ scan: { id: number } }>("/scans", { method: "POST", body });
    // Launch the scan
    await this.request(`/scans/${scan.scan.id}/launch`, { method: "POST" });

    return { scanId: String(scan.scan.id), status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const resp = await this.request<{ info: { status: string }; hosts?: Array<{ progress: number }> }>(`/scans/${scanId}`);
    const statusMap: Record<string, ScanStatus> = {
      running: "running", completed: "completed", canceled: "cancelled",
      aborted: "failed", paused: "pending", pending: "pending",
    };
    const progress = resp.hosts?.length
      ? Math.round(resp.hosts.reduce((sum, h) => sum + (h.progress || 0), 0) / resp.hosts.length)
      : undefined;
    return { status: statusMap[resp.info.status] || "running", progress };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const resp = await this.request<{
      info: { status: string; scan_start: number; scan_end: number };
      vulnerabilities: Array<{
        plugin_id: number; plugin_name: string; severity: number; count: number;
        plugin_family: string; vuln_index: number;
      }>;
      hosts: Array<{ hostname: string; host_id: number }>;
    }>(`/scans/${scanId}`);

    const findings: NormalizedFinding[] = [];

    // Fetch detailed vulnerability data for each host
    for (const host of resp.hosts || []) {
      const hostVulns = await this.request<{
        vulnerabilities: Array<{
          plugin_id: number; plugin_name: string; severity: number;
          plugin_output: string; plugin_family: string;
        }>;
      }>(`/scans/${scanId}/hosts/${host.host_id}`);

      for (const vuln of hostVulns.vulnerabilities || []) {
        if (vuln.severity === 0) continue; // Skip info-only

        // Get plugin details for CVE/CWE mapping
        const pluginDetails = await this.request<{
          id: number; name: string; description: string; solution: string;
          cvss_base_score: number; cvss_vector: { raw: string };
          cve: string[]; cwe: string[]; see_also: string[];
        }>(`/plugins/plugin/${vuln.plugin_id}`).catch(() => null);

        findings.push({
          externalId: `tenable-${scanId}-${host.host_id}-${vuln.plugin_id}`,
          source: "tenable_io",
          title: vuln.plugin_name,
          description: pluginDetails?.description || vuln.plugin_name,
          severity: this.mapSeverity(vuln.severity),
          cvssScore: pluginDetails?.cvss_base_score,
          cvssVector: pluginDetails?.cvss_vector?.raw,
          cveIds: pluginDetails?.cve || [],
          cweIds: pluginDetails?.cwe || [],
          affectedAsset: host.hostname,
          remediation: pluginDetails?.solution,
          pluginId: String(vuln.plugin_id),
          complianceFrameworks: ["fedramp_high", "nist_800_53", "dod_stig"],
          firstSeen: (resp.info.scan_start || 0) * 1000,
          lastSeen: (resp.info.scan_end || Date.now() / 1000) * 1000,
          verified: true,
          exploitAvailable: undefined,
        });
      }
    }

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);

    return {
      platform: "tenable_io",
      scanId,
      status: resp.info.status === "completed" ? "completed" : "running",
      startedAt: (resp.info.scan_start || 0) * 1000,
      completedAt: resp.info.scan_end ? resp.info.scan_end * 1000 : undefined,
      totalFindings: findings.length,
      findingsBySeverity: bySeverity,
      findings,
    };
  }

  async listPolicies(): Promise<Array<{ id: string; name: string; description?: string }>> {
    const resp = await this.request<{ policies: Array<{ id: number; name: string; description: string }> }>("/policies");
    return (resp.policies || []).map(p => ({ id: String(p.id), name: p.name, description: p.description }));
  }

  async listAssets(): Promise<Array<{ id: string; name: string; type: string; lastScan?: number }>> {
    const resp = await this.request<{ assets: Array<{ id: string; fqdn: string[]; ipv4: string[]; last_seen: string }> }>("/assets");
    return (resp.assets || []).map(a => ({
      id: a.id,
      name: a.fqdn?.[0] || a.ipv4?.[0] || a.id,
      type: a.fqdn?.length ? "domain" : "ip",
      lastScan: a.last_seen ? new Date(a.last_seen).getTime() : undefined,
    }));
  }

  private mapSeverity(tenableSeverity: number): SeverityLevel {
    switch (tenableSeverity) {
      case 4: return "critical";
      case 3: return "high";
      case 2: return "medium";
      case 1: return "low";
      default: return "info";
    }
  }
}
