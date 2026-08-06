/**
 * Coalition Control ASM — Attack Surface Monitoring Connector
 *
 * Replaces the deprecated BinaryEdge connector (shut down March 31, 2025).
 * Coalition acquired BinaryEdge in 2020 and integrated its scanning engine
 * into Coalition Control.
 *
 * Coalition Control provides:
 *   - Attack surface monitoring with BinaryEdge's core scanning engine
 *   - Security findings (vulnerabilities, misconfigurations)
 *   - Data leak detection
 *   - Asset discovery (domains, IPs, services)
 *
 * API docs: https://api.control.coalitioninc.com/docs/api
 * Auth: Bearer token from POST /auth/login (email + password)
 * Free tier: Register at https://www.coalitioninc.com/control
 *
 * Requires: COALITION_CONTROL_EMAIL + COALITION_CONTROL_PASSWORD env vars
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

const CONTROL_BASE_URL = "https://api.control.coalitioninc.com";
const REQUEST_TIMEOUT_MS = 15_000;

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// ─── Auth Token Cache ───────────────────────────────────────────────

let cachedToken: { token: string; expiresAt: number } | null = null;

async function getAuthToken(email: string, password: string): Promise<string | null> {
  // Return cached token if still valid (with 5min buffer)
  if (cachedToken && Date.now() < cachedToken.expiresAt - 5 * 60 * 1000) {
    return cachedToken.token;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const response = await fetch(`${CONTROL_BASE_URL}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: email, password }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) return null;

    const data = await response.json();
    const token = data.access_token || data.token;
    if (!token) return null;

    // Cache for 1 hour (typical JWT lifetime)
    cachedToken = { token, expiresAt: Date.now() + 60 * 60 * 1000 };
    return token;
  } catch {
    return null;
  }
}

async function authedFetch(path: string, token: string): Promise<any | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const response = await fetch(`${CONTROL_BASE_URL}${path}`, {
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

// ─── Connector Implementation ───────────────────────────────────────

export const coalitionControlConnector: PassiveConnector = {
  name: "coalition_control",
  description: "Coalition Control ASM — Attack surface monitoring powered by BinaryEdge scanning engine. Provides security findings, data leaks, and asset discovery.",
  requiresApiKey: true,
  freeUrl: "https://www.coalitioninc.com/control",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const now = new Date().toISOString();

    const email = process.env.COALITION_CONTROL_EMAIL;
    const password = process.env.COALITION_CONTROL_PASSWORD;

    if (!email || !password) {
      errors.push("Coalition Control credentials not configured — register free at https://www.coalitioninc.com/control");
      return {
        connector: "coalition_control",
        domain,
        observations,
        errors,
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    // Authenticate
    const token = await getAuthToken(email, password);
    if (!token) {
      errors.push("Coalition Control authentication failed — check email/password");
      return {
        connector: "coalition_control",
        domain,
        observations,
        errors,
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      // Step 1: Get entity ID
      const meData = await authedFetch("/asm/me", token);
      if (!meData || !meData.entity_id) {
        errors.push("Coalition Control: could not retrieve entity ID");
        return { connector: "coalition_control", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }
      const entityId = meData.entity_id;

      // Step 2: Fetch security findings
      const findingsData = await authedFetch(`/asm/entity/${entityId}/findings`, token);
      if (findingsData && Array.isArray(findingsData.findings || findingsData)) {
        const findings = findingsData.findings || findingsData;
        for (const finding of findings) {
          // Filter findings relevant to our target domain
          const findingDomain = finding.domain || finding.asset || "";
          if (!findingDomain.includes(domain) && !domain.includes(findingDomain)) continue;

          observations.push({
            assetId: makeAssetId(domain, `${finding.id || finding.title}|coalition_finding`, "coalition_control"),
            domain,
            assetType: "finding",
            name: `[Coalition] ${finding.title || finding.name || "Security Finding"}`,
            source: "coalition_control",
            observedAt: finding.created_at || now,
            tags: [
              "coalition_control",
              "security_finding",
              finding.severity ? `severity:${finding.severity}` : "severity:unknown",
              finding.category ? `category:${finding.category}` : "",
              finding.cve_id ? `cve:${finding.cve_id}` : "",
            ].filter(Boolean),
            evidence: {
              title: finding.title || finding.name,
              severity: finding.severity,
              category: finding.category,
              description: finding.description,
              cve_id: finding.cve_id,
              remediation: finding.remediation,
              asset: finding.asset || finding.domain,
              port: finding.port,
              service: finding.service,
              first_seen: finding.first_seen || finding.created_at,
              last_seen: finding.last_seen || finding.updated_at,
            },
            attribution: {
              provider: "Coalition Control",
              url: "https://app.control.coalitioninc.com",
              method: `Coalition Control ASM finding — ${finding.title || "security issue"} detected via BinaryEdge scanning engine`,
              verifyUrl: "https://app.control.coalitioninc.com",
            },
          });
        }
      }

      // Step 3: Fetch impacted assets
      const assetsData = await authedFetch(`/asm/entity/${entityId}/assets/impacted`, token);
      if (assetsData && Array.isArray(assetsData.assets || assetsData)) {
        const assets = assetsData.assets || assetsData;
        for (const asset of assets) {
          const assetDomain = asset.domain || asset.hostname || "";
          if (!assetDomain.includes(domain) && !domain.includes(assetDomain)) continue;

          observations.push({
            assetId: makeAssetId(domain, `${asset.ip || asset.hostname}|coalition_asset`, "coalition_control"),
            domain,
            assetType: "ip",
            name: `[Coalition] Impacted asset: ${asset.hostname || asset.ip}`,
            ip: asset.ip,
            source: "coalition_control",
            observedAt: now,
            tags: [
              "coalition_control",
              "impacted_asset",
              asset.ip ? `ip:${asset.ip}` : "",
              ...(asset.open_ports || []).map((p: number) => `port:${p}`),
              `risk_score:${asset.risk_score || "unknown"}`,
            ].filter(Boolean),
            evidence: {
              ip: asset.ip,
              hostname: asset.hostname,
              open_ports: asset.open_ports,
              risk_score: asset.risk_score,
              findings_count: asset.findings_count,
              services: asset.services,
            },
            attribution: {
              provider: "Coalition Control",
              url: "https://app.control.coalitioninc.com",
              method: `Coalition Control ASM — impacted asset ${asset.hostname || asset.ip} with ${asset.findings_count || 0} findings`,
              verifyUrl: "https://app.control.coalitioninc.com",
            },
          });
        }
      }

      // Step 4: Fetch data leaks
      const leaksData = await authedFetch(`/asm/entity/${entityId}/dataleaks`, token);
      if (leaksData && Array.isArray(leaksData.dataleaks || leaksData)) {
        const leaks = leaksData.dataleaks || leaksData;
        for (const leak of leaks) {
          observations.push({
            assetId: makeAssetId(domain, `${leak.id || leak.source}|coalition_leak`, "coalition_control"),
            domain,
            assetType: "data_leak",
            name: `[Coalition] Data leak: ${leak.source || leak.title || "Unknown source"}`,
            source: "coalition_control",
            observedAt: leak.discovered_at || now,
            tags: [
              "coalition_control",
              "data_leak",
              "credential_exposure",
              leak.source ? `leak_source:${leak.source}` : "",
              leak.severity ? `severity:${leak.severity}` : "",
            ].filter(Boolean),
            evidence: {
              source: leak.source,
              title: leak.title,
              description: leak.description,
              severity: leak.severity,
              discovered_at: leak.discovered_at,
              affected_emails: leak.affected_emails,
              data_types: leak.data_types,
            },
            attribution: {
              provider: "Coalition Control",
              url: "https://app.control.coalitioninc.com",
              method: `Coalition Control data leak detection — ${leak.source || "breach"} affecting ${domain}`,
              verifyUrl: "https://app.control.coalitioninc.com",
            },
          });
        }
      }

    } catch (err: any) {
      errors.push(`Coalition Control error: ${err.message}`);
    }

    return {
      connector: "coalition_control",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
