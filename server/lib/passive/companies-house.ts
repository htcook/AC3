/**
 * Companies House (UK) Connector — Free, API Key Required
 * 
 * Queries the UK Companies House registry for corporate information
 * associated with the target domain. Provides BIA context: company
 * status, officers, filing history, and registered address.
 * 
 * API docs: https://developer.company-information.service.gov.uk/
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const CH_API = "https://api.company-information.service.gov.uk";

export const companiesHouseConnector: PassiveConnector = {
  name: "companies_house",
  description: "Companies House (UK) — corporate registry for BIA context (officers, filings, company status)",
  requiresApiKey: true,
  freeUrl: "https://find-and-update.company-information.service.gov.uk/",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    const apiKey = config?.env?.COMPANIES_HOUSE_API_KEY;
    if (!apiKey) {
      return {
        connector: "companies_house",
        domain,
        observations,
        errors: ["No COMPANIES_HOUSE_API_KEY configured — skipping"],
        durationMs: Date.now() - start,
        rateLimited: false,
      };
    }

    try {
      // Extract company name from domain (strip TLD)
      const companySearch = domain.replace(/\.(com|co\.uk|org|net|io|uk|ltd|plc)$/i, "").replace(/[.-]/g, " ");

      // Step 1: Search for the company
      const searchResp = await rateLimitedFetch("companies_house", `${CH_API}/search/companies?q=${encodeURIComponent(companySearch)}&items_per_page=5`, {
        headers: {
          Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`,
        },
        signal: AbortSignal.timeout(12000),
      });

      if (searchResp.status === 429) {
        rateLimited = true;
        errors.push("Companies House rate limited");
        return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      if (!searchResp.ok) {
        errors.push(`Companies House search returned ${searchResp.status}`);
        return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      const searchData = await searchResp.json() as any;
      const companies = searchData?.items || [];

      if (companies.length === 0) {
        return { connector: "companies_house", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Take the best match
      const company = companies[0];
      const companyNumber = company.company_number;

      // Step 2: Get full company profile
      let profile: any = null;
      try {
        const profileResp = await rateLimitedFetch("companies_house", `${CH_API}/company/${companyNumber}`, {
          headers: {
            Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`,
          },
          signal: AbortSignal.timeout(10000),
        });
        if (profileResp.ok) profile = await profileResp.json();
      } catch (e: any) {
        errors.push(`Profile fetch: ${e.message}`);
      }

      // Step 3: Get officers
      let officers: any[] = [];
      try {
        const officersResp = await rateLimitedFetch("companies_house", `${CH_API}/company/${companyNumber}/officers?items_per_page=10`, {
          headers: {
            Authorization: `Basic ${Buffer.from(`${apiKey}:`).toString("base64")}`,
          },
          signal: AbortSignal.timeout(10000),
        });
        if (officersResp.ok) {
          const data = await officersResp.json() as any;
          officers = data?.items || [];
        }
      } catch (e: any) {
        errors.push(`Officers fetch: ${e.message}`);
      }

      // Observation 1: Company profile
      if (profile) {
        const name = `Companies House: ${profile.company_name || company.title}`;
        const isActive = profile.company_status === "active";

        observations.push({
          assetId: makeAssetId(domain, name, "companies_house"),
          domain,
          assetType: "organization",
          name,
          source: "companies_house",
          observedAt: now,
          firstSeen: profile.date_of_creation ? new Date(profile.date_of_creation) : undefined,
          tags: ["companies_house", "uk_registry", "corporate_intel", isActive ? "active" : "inactive"],
          evidence: {
            severity: isActive ? 1 : 5,
            confidence: 85,
            value: `${profile.company_name} — ${profile.company_status} (${profile.type || "unknown type"})`,
            company_name: profile.company_name,
            company_number: companyNumber,
            company_status: profile.company_status,
            company_type: profile.type,
            date_of_creation: profile.date_of_creation,
            jurisdiction: profile.jurisdiction,
            registered_office: profile.registered_office_address ? {
              address_line_1: profile.registered_office_address.address_line_1,
              locality: profile.registered_office_address.locality,
              postal_code: profile.registered_office_address.postal_code,
              country: profile.registered_office_address.country,
            } : null,
            sic_codes: profile.sic_codes,
            has_charges: profile.has_charges,
            has_insolvency_history: profile.has_insolvency_history,
            accounts_overdue: profile.accounts?.overdue,
            last_accounts_date: profile.accounts?.last_accounts?.made_up_to,
            confirmation_statement_overdue: profile.confirmation_statement?.overdue,
          },
          attribution: {
            provider: "Companies House (UK)",
            url: "https://find-and-update.company-information.service.gov.uk/",
            method: "api",
          },
        });
      }

      // Observation 2: Officers / Directors
      if (officers.length > 0) {
        const activeOfficers = officers.filter(o => !o.resigned_on);
        const name = `CH Officers: ${activeOfficers.length} active directors for ${company.title || domain}`;

        observations.push({
          assetId: makeAssetId(domain, name, "companies_house"),
          domain,
          assetType: "organization",
          name,
          source: "companies_house",
          observedAt: now,
          tags: ["companies_house", "officers", "corporate_intel"],
          evidence: {
            severity: 2,
            confidence: 90,
            value: `${activeOfficers.length} active officers, ${officers.length - activeOfficers.length} resigned`,
            active_officers: activeOfficers.slice(0, 10).map(o => ({
              name: o.name,
              role: o.officer_role,
              appointed_on: o.appointed_on,
              nationality: o.nationality,
              country_of_residence: o.country_of_residence,
            })),
            total_officers: officers.length,
            active_count: activeOfficers.length,
          },
          attribution: {
            provider: "Companies House (UK)",
            url: "https://find-and-update.company-information.service.gov.uk/",
            method: "api",
          },
        });
      }

      // Observation 3: Risk indicators
      if (profile?.has_insolvency_history || profile?.accounts?.overdue || profile?.confirmation_statement?.overdue) {
        const risks: string[] = [];
        if (profile.has_insolvency_history) risks.push("insolvency history");
        if (profile.accounts?.overdue) risks.push("accounts overdue");
        if (profile.confirmation_statement?.overdue) risks.push("confirmation statement overdue");

        const name = `CH Risk: ${risks.join(", ")} for ${company.title || domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, "companies_house"),
          domain,
          assetType: "organization",
          name,
          source: "companies_house",
          observedAt: now,
          tags: ["companies_house", "corporate_risk", ...risks.map(r => r.replace(/\s+/g, "_"))],
          evidence: {
            severity: 6,
            confidence: 95,
            value: `Corporate risk indicators: ${risks.join(", ")}`,
            risk_indicators: risks,
            has_insolvency_history: profile.has_insolvency_history,
            accounts_overdue: profile.accounts?.overdue,
            confirmation_overdue: profile.confirmation_statement?.overdue,
          },
          attribution: {
            provider: "Companies House (UK)",
            url: "https://find-and-update.company-information.service.gov.uk/",
            method: "api",
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during Companies House lookup");
    }

    return {
      connector: "companies_house",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
