/**
 * LinkedIn Company Intelligence Connector
 * 
 * Uses the Manus Data API (LinkedIn/get_company_details) to fetch structured
 * firmographic data: company name, industry, employee count, specialties,
 * description, headquarters, and Crunchbase URL.
 * 
 * This data enriches the OrgProfile for BIA scoring and LLM context.
 * No external API key required — uses built-in Data API credentials.
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface LinkedInCompanyData {
  name?: string;
  universalName?: string;
  description?: string;
  website?: string;
  industry?: string;
  companySize?: { start?: number; end?: number };
  staffCount?: number;
  headquarter?: { city?: string; country?: string; geographicArea?: string; postalCode?: string; line1?: string };
  specialities?: string[];
  founded?: { year?: number };
  companyType?: string;
  crunchbaseUrl?: string;
  linkedinUrl?: string;
  tagline?: string;
  logo?: string;
  followerCount?: number;
  // Some APIs return nested structures
  staffCountRange?: string;
  industries?: string[];
  locations?: { city?: string; country?: string; geographicArea?: string }[];
}

async function callDataApi(apiId: string, options: { query?: Record<string, unknown> }): Promise<unknown> {
  const forgeUrl = process.env.BUILT_IN_FORGE_API_URL;
  const forgeKey = process.env.BUILT_IN_FORGE_API_KEY;
  if (!forgeUrl || !forgeKey) return null;

  const baseUrl = forgeUrl.endsWith("/") ? forgeUrl : `${forgeUrl}/`;
  const fullUrl = new URL("webdevtoken.v1.WebDevService/CallApi", baseUrl).toString();
  const response = await fetch(fullUrl, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "connect-protocol-version": "1",
      authorization: `Bearer ${forgeKey}`,
    },
    body: JSON.stringify({
      apiId,
      query: options.query,
    }),
  });
  if (!response.ok) return null;
  const payload = await response.json().catch(() => ({}));
  if (payload && typeof payload === "object" && "jsonData" in payload) {
    try {
      return JSON.parse((payload as Record<string, string>).jsonData ?? "{}");
    } catch {
      return (payload as Record<string, unknown>).jsonData;
    }
  }
  return payload;
}

export const linkedinCompanyConnector: PassiveConnector = {
  name: "linkedin_company",
  description: "LinkedIn Company Intelligence — firmographics, employee count, industry, specialties, headquarters via Manus Data API",
  requiresApiKey: false,
  freeUrl: "https://linkedin.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const now = new Date();

    try {
      // Try to find the company by domain name
      const companyName = domain.replace(/\.(com|org|net|io|co|gov|edu|mil)$/i, "").replace(/\./g, " ");
      
      const result = await callDataApi("LinkedIn/get_company_details", {
        query: { username: companyName },
      }) as LinkedInCompanyData | null;

      if (!result || (!result.name && !result.universalName)) {
        // Try with just the first part of the domain
        const simpleName = domain.split(".")[0];
        const retryResult = await callDataApi("LinkedIn/get_company_details", {
          query: { username: simpleName },
        }) as LinkedInCompanyData | null;

        if (!retryResult || (!retryResult.name && !retryResult.universalName)) {
          errors.push(`No LinkedIn company profile found for domain ${domain}`);
          return { connector: "linkedin_company", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
        }
        Object.assign(result || {}, retryResult);
      }

      const data = result!;

      // Create a comprehensive company intel observation
      const employeeCount = data.staffCount || data.companySize?.end || data.companySize?.start || 0;
      const employeeRange = data.staffCountRange || 
        (data.companySize ? `${data.companySize.start || 0}-${data.companySize.end || "?"}` : "unknown");

      observations.push({
        assetId: makeAssetId(domain, "linkedin_company_profile", "linkedin"),
        domain,
        assetType: "url" as any,
        name: `${data.name || domain} — LinkedIn Company Profile`,
        source: "linkedin_company",
        observedAt: now,
        tags: [
          "company_intel",
          "firmographics",
          ...(data.industry ? [`industry:${data.industry}`] : []),
          ...(employeeCount > 0 ? [`employees:${employeeCount}`] : []),
          ...(data.companyType ? [`type:${data.companyType}`] : []),
          ...(data.founded?.year ? [`founded:${data.founded.year}`] : []),
        ],
        evidence: {
          companyName: data.name,
          universalName: data.universalName,
          industry: data.industry,
          industries: data.industries,
          description: data.description?.substring(0, 2000),
          tagline: data.tagline,
          website: data.website,
          employeeCount,
          employeeRange,
          companyType: data.companyType,
          foundedYear: data.founded?.year,
          headquarters: data.headquarter ? {
            city: data.headquarter.city,
            state: data.headquarter.geographicArea,
            country: data.headquarter.country,
            address: data.headquarter.line1,
            postalCode: data.headquarter.postalCode,
          } : null,
          locations: data.locations || [],
          specialties: data.specialities || [],
          crunchbaseUrl: data.crunchbaseUrl,
          linkedinUrl: data.linkedinUrl || `https://linkedin.com/company/${data.universalName}`,
          followerCount: data.followerCount,
          logoUrl: data.logo,
        },
        attribution: {
          provider: "LinkedIn (via Manus Data API)",
          url: data.linkedinUrl || `https://linkedin.com/company/${data.universalName || companyName}`,
          method: `Company firmographic data retrieved from LinkedIn — ${data.name || domain} (${data.industry || "unknown industry"}, ~${employeeCount} employees)`,
          verifyUrl: data.linkedinUrl || `https://linkedin.com/company/${data.universalName || companyName}`,
        },
      });

      // Extract specialties as additional context
      if (data.specialities && data.specialities.length > 0) {
        observations.push({
          assetId: makeAssetId(domain, "linkedin_specialties", "linkedin"),
          domain,
          assetType: "url" as any,
          name: `${data.name || domain} — Business Specialties`,
          source: "linkedin_company",
          observedAt: now,
          tags: ["company_intel", "specialties", ...data.specialities.slice(0, 10).map(s => `specialty:${s.toLowerCase().trim()}`)],
          evidence: {
            specialties: data.specialities,
            companyName: data.name,
            relevance: "Products, services, and capabilities that define the organization's mission-critical functions",
          },
          attribution: {
            provider: "LinkedIn (via Manus Data API)",
            url: data.linkedinUrl || `https://linkedin.com/company/${data.universalName || companyName}`,
            method: `Business specialties extracted from LinkedIn company profile — ${data.specialities.length} specialties identified`,
          },
        });
      }

    } catch (err: any) {
      if (err.name === "AbortError") {
        errors.push("LinkedIn company lookup timed out");
      } else {
        errors.push(`LinkedIn company error: ${err.message}`);
      }
    }

    return {
      connector: "linkedin_company",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
