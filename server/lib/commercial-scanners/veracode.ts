/**
 * Veracode Connector
 * FedRAMP Authorized — SAST, DAST, SCA
 * API Docs: https://docs.veracode.com/r/c_rest_intro
 * Uses HMAC-SHA256 authentication per Veracode API spec.
 */
import { createHmac } from "crypto";
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class VeracodeConnector extends BaseConnector {
  readonly platform = "veracode";

  protected getAuthHeaders(): Record<string, string> {
    // Veracode uses HMAC-based authentication
    const { apiId, apiKey } = this.config.credentials;
    const nonce = this.generateNonce();
    const timestamp = Date.now();
    const signingData = `id=${apiId}&host=${new URL(this.config.baseUrl).host}&url=/&method=GET`;
    const signature = createHmac("sha256", apiKey).update(signingData).digest("hex");
    return {
      Authorization: `VERACODE-HMAC-SHA-256 id=${apiId},ts=${timestamp},nonce=${nonce},sig=${signature}`,
    };
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.request<{ _embedded: { applications: unknown[] } }>("/appsec/v1/applications?size=1");
      return {
        reachable: true, authenticated: true,
        apiVersion: "v1", latencyMs: Date.now() - start, lastChecked: Date.now(),
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
    // Veracode scans are tied to applications — create/find the app first
    const appGuid = (options?.appGuid as string) || "";
    if (!appGuid) throw new Error("Veracode requires an application GUID (appGuid) to launch a scan");

    // Create a new scan (static or dynamic)
    const scanType = (options?.scanType as string) || "STATIC";
    const body = {
      scan_type: scanType,
      app_id: appGuid,
    };

    const resp = await this.request<{ guid: string }>("/appsec/v2/scans", { method: "POST", body });
    return { scanId: resp.guid, status: "pending" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus; progress?: number }> {
    const resp = await this.request<{ status: string }>(`/appsec/v2/scans/${scanId}`);
    const statusMap: Record<string, ScanStatus> = {
      PENDING: "pending", RUNNING: "running", COMPLETED: "completed",
      FAILED: "failed", CANCELLED: "cancelled",
    };
    return { status: statusMap[resp.status] || "running" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    const resp = await this.request<{
      _embedded: { findings: Array<{
        issue_id: number; scan_type: string; description: string;
        severity: number; finding_status: { status: string };
        cwe: { id: number; name: string }; cvss: number;
        finding_details: { file_path?: string; module?: string; attack_vector?: string };
      }> };
      page: { total_elements: number };
    }>(`/appsec/v2/applications/${scanId}/findings?size=500`);

    const findings: NormalizedFinding[] = (resp._embedded?.findings || []).map(f => ({
      externalId: `veracode-${scanId}-${f.issue_id}`,
      source: "veracode",
      title: f.cwe?.name || f.description?.slice(0, 100) || "Unknown",
      description: f.description || "",
      severity: this.mapSeverity(f.severity),
      cvssScore: f.cvss,
      cveIds: [],
      cweIds: f.cwe ? [`CWE-${f.cwe.id}`] : [],
      affectedAsset: f.finding_details?.file_path || f.finding_details?.module || "",
      complianceFrameworks: ["fedramp_moderate", "nist_800_53"] as any,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      verified: f.finding_status?.status === "OPEN",
    }));

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);

    return {
      platform: "veracode", scanId, status: "completed",
      startedAt: Date.now(), totalFindings: findings.length,
      findingsBySeverity: bySeverity, findings,
    };
  }

  private mapSeverity(veracodeSeverity: number): SeverityLevel {
    if (veracodeSeverity >= 5) return "critical";
    if (veracodeSeverity >= 4) return "high";
    if (veracodeSeverity >= 3) return "medium";
    if (veracodeSeverity >= 2) return "low";
    return "info";
  }

  private generateNonce(): string {
    return Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  }
}
