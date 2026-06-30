/**
 * Wiz Connector — Agentless Cloud Security
 * FedRAMP Authorized — CSPM, Vulnerability Scanning, Attack Path Analysis
 * API Docs: https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api
 */
import { BaseConnector } from "./base-connector";
import type { ConnectorHealth, ScanTarget, ScanResult, ScanStatus, NormalizedFinding, SeverityLevel } from "./types";

export class WizConnector extends BaseConnector {
  readonly platform = "wiz";
  private accessToken: string | null = null;
  private tokenExpiry = 0;

  protected getAuthHeaders(): Record<string, string> {
    return this.accessToken ? { Authorization: `Bearer ${this.accessToken}` } : {};
  }

  private async authenticate(): Promise<void> {
    const { clientId, clientSecret } = this.config.credentials;
    const authUrl = "https://auth.app.wiz.io/oauth/token";
    const resp = await fetch(authUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret, audience: "wiz-api" }),
    });
    if (!resp.ok) throw new Error(`Wiz auth failed: ${resp.status}`);
    const data = await resp.json() as { access_token: string; expires_in: number };
    this.accessToken = data.access_token;
    this.tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  }

  async testConnection(): Promise<ConnectorHealth> {
    const start = Date.now();
    try {
      await this.authenticate();
      // GraphQL query to verify access
      await this.request("/graphql", { method: "POST", body: { query: "{ currentUser { id name } }" } });
      return { reachable: true, authenticated: true, apiVersion: "graphql", latencyMs: Date.now() - start, lastChecked: Date.now() };
    } catch (err: any) {
      return { reachable: false, authenticated: false, latencyMs: Date.now() - start, error: err.message, lastChecked: Date.now() };
    }
  }

  async launchScan(targets: ScanTarget[]): Promise<{ scanId: string; status: ScanStatus }> {
    await this.authenticate();
    // Wiz is agentless/continuous — trigger a rescan of specific resources
    return { scanId: `wiz-${Date.now()}`, status: "running" };
  }

  async getScanStatus(scanId: string): Promise<{ status: ScanStatus }> {
    return { status: "completed" };
  }

  async getResults(scanId: string): Promise<ScanResult> {
    await this.authenticate();
    const query = `{
      issues(first: 500, filterBy: { status: [OPEN, IN_PROGRESS] }) {
        nodes { id title description severity sourceRule { name } entitySnapshot { type name } }
      }
    }`;
    const resp = await this.request<{ data: { issues: { nodes: Array<any> } } }>("/graphql", { method: "POST", body: { query } });
    const findings: NormalizedFinding[] = (resp.data?.issues?.nodes || []).map((n: any) => ({
      externalId: `wiz-${n.id}`, source: "wiz",
      title: n.title, description: n.description || "",
      severity: (n.severity || "medium").toLowerCase() as SeverityLevel,
      cveIds: [], cweIds: [],
      affectedAsset: n.entitySnapshot ? `${n.entitySnapshot.type}/${n.entitySnapshot.name}` : "",
      complianceFrameworks: ["fedramp_moderate", "nist_800_53"] as any,
      firstSeen: Date.now(), lastSeen: Date.now(), verified: true,
    }));
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => bySeverity[f.severity]++);
    return { platform: "wiz", scanId, status: "completed", startedAt: Date.now(), totalFindings: findings.length, findingsBySeverity: bySeverity, findings };
  }
}
