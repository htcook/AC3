/**
 * OpenCorporates Connector — Free Tier (Rate Limited), API Key Optional
 * 
 * Queries the world's largest open database of companies for corporate
 * intelligence associated with the target domain. Provides BIA context:
 * incorporation details, jurisdiction, status, and related entities.
 * 
 * API docs: https://api.opencorporates.com/documentation/API-Reference
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const OC_API = "https://api.opencorporates.com/v0.4";

export const opencorporatesConnector: PassiveConnector = {
  name: "opencorporates",
  description: "OpenCorporates — global corporate registry for BIA context (140M+ companies across 140 jurisdictions)",
  requiresApiKey: false,
  freeUrl: "https://opencorporates.com/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Extract company name from domain
      const companySearch = domain.replace(/\.(com|co\.uk|org|net|io|uk|ltd|plc|inc|llc|gmbh|ag|sa|bv)$/i, "").replace(/[.-]/g, " ");

      // Build URL with optional API key
      const apiKey = config?.env?.OPENCORPORATES_API_KEY;
      const params = new URLSearchParams({
        q: companySearch,
        per_page: "5",
        order: "score",
      });
      if (apiKey) params.set("api_token", apiKey);

      const resp = await rateLimitedFetch("opencorporates", `${OC_API}/companies/search?${params}`, {
        headers: { "User-Agent": "AC3-SecurityScanner/1.0" },
        signal: AbortSignal.timeout(15000),
      });

      if (resp.status === 429) {
        rateLimited = true;
        errors.push("OpenCorporates rate limited — consider adding API key");
        return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      if (resp.status === 403) {
        errors.push("OpenCorporates API access denied — may need API key for this query");
        return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      if (!resp.ok) {
        errors.push(`OpenCorporates returned ${resp.status}`);
        return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const data = await resp.json() as any;
      const companies = data?.results?.companies || [];

      if (companies.length === 0) {
        return { connector: "opencorporates", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Process top matches
      for (const item of companies.slice(0, 3)) {
        const company = item.company;
        if (!company) continue;

        const isActive = company.current_status?.toLowerCase().includes("active") ||
                         company.current_status?.toLowerCase().includes("good standing");

        const name = `OpenCorporates: ${company.name} (${company.jurisdiction_code?.toUpperCase() || "?"})`;

        observations.push({
          assetId: makeAssetId(domain, company.company_number || name, "opencorporates"),
          domain,
          assetType: "organization",
          name,
          source: "opencorporates",
          observedAt: now,
          firstSeen: company.incorporation_date ? new Date(company.incorporation_date) : undefined,
          tags: [
            "opencorporates",
            "corporate_intel",
            company.jurisdiction_code || "unknown_jurisdiction",
            isActive ? "active" : "inactive",
          ],
          evidence: {
            severity: isActive ? 1 : 4,
            confidence: company.score ? Math.min(company.score * 10, 90) : 50,
            value: `${company.name} — ${company.current_status || "unknown status"} in ${company.jurisdiction_code?.toUpperCase() || "?"}`,
            company_name: company.name,
            company_number: company.company_number,
            jurisdiction: company.jurisdiction_code,
            incorporation_date: company.incorporation_date,
            dissolution_date: company.dissolution_date,
            company_type: company.company_type,
            current_status: company.current_status,
            registry_url: company.registry_url,
            opencorporates_url: company.opencorporates_url,
            registered_address: company.registered_address_in_full,
            branch: company.branch,
            branch_status: company.branch_status,
            inactive: company.inactive,
            agent_name: company.agent_name,
            agent_address: company.agent_address,
            previous_names: (company.previous_names || []).slice(0, 5).map((pn: any) => ({
              name: pn.company_name,
              start_date: pn.con_date,
            })),
          },
          attribution: {
            provider: "OpenCorporates",
            url: "https://opencorporates.com/",
            method: "api",
          },
        });
      }

      // Observation: Multi-jurisdiction presence
      const jurisdictions = new Set(companies.map((c: any) => c.company?.jurisdiction_code).filter(Boolean));
      if (jurisdictions.size > 1) {
        const name = `Multi-Jurisdiction: ${companySearch} found in ${jurisdictions.size} jurisdictions`;
        observations.push({
          assetId: makeAssetId(domain, name, "opencorporates"),
          domain,
          assetType: "organization",
          name,
          source: "opencorporates",
          observedAt: now,
          tags: ["opencorporates", "multi_jurisdiction", "corporate_intel"],
          evidence: {
            severity: 2,
            confidence: 70,
            value: `Company entities found in ${jurisdictions.size} jurisdictions: ${Array.from(jurisdictions).join(", ")}`,
            jurisdiction_count: jurisdictions.size,
            jurisdictions: Array.from(jurisdictions),
          },
          attribution: {
            provider: "OpenCorporates",
            url: "https://opencorporates.com/",
            method: "api",
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during OpenCorporates lookup");
    }

    return {
      connector: "opencorporates",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
