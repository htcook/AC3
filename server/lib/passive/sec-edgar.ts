/**
 * SEC EDGAR Connector — Free, No API Key (User-Agent required)
 * 
 * Queries the SEC EDGAR full-text search and company filings API
 * to extract financial context for BIA: revenue, business segments,
 * risk factors, and operational dependencies from 10-K/10-Q filings.
 * 
 * API docs: https://efts.sec.gov/LATEST/search-index?q=...
 *           https://data.sec.gov/submissions/CIK*.json
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const EFTS_BASE = "https://efts.sec.gov/LATEST/search-index";
const SUBMISSIONS_BASE = "https://data.sec.gov/submissions";
const USER_AGENT = "AceC3Platform/1.0 (security-research@acec3.com)";

async function edgarFetch(url: string): Promise<any> {
  const resp = await fetch(url, {
    headers: {
      "User-Agent": USER_AGENT,
      "Accept": "application/json",
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) return null;
  return resp.json();
}

/**
 * Search EDGAR full-text search for a company by domain or name
 */
async function searchCompany(query: string): Promise<any> {
  const url = `https://efts.sec.gov/LATEST/search-index?q=%22${encodeURIComponent(query)}%22&dateRange=custom&startdt=2023-01-01&forms=10-K,10-Q,8-K&from=0&size=5`;
  return edgarFetch(url);
}

/**
 * Get company submissions by CIK number
 */
async function getSubmissions(cik: string): Promise<any> {
  const paddedCik = cik.padStart(10, "0");
  return edgarFetch(`${SUBMISSIONS_BASE}/CIK${paddedCik}.json`);
}

/**
 * Extract company name from domain (strip TLD, capitalize)
 */
function domainToCompanyName(domain: string): string {
  return domain.split(".")[0].replace(/-/g, " ");
}

export const secEdgarConnector: PassiveConnector = {
  name: "sec_edgar",
  description: "SEC EDGAR — free US public company filings (10-K, 10-Q, 8-K) for BIA financial impact context",
  requiresApiKey: false,
  freeUrl: "https://www.sec.gov/cgi-bin/browse-edgar",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Try searching by domain first (companies often reference their domain in filings)
      const companyName = domainToCompanyName(domain);
      
      // Search EDGAR for filings mentioning this domain or company name
      let searchResult = await searchCompany(domain);
      
      // If no results for domain, try company name
      if (!searchResult?.hits?.hits?.length && companyName.length > 2) {
        searchResult = await searchCompany(companyName);
      }

      if (!searchResult?.hits?.hits?.length) {
        observations.push({
          assetId: makeAssetId(domain, `SEC EDGAR: no filings for ${domain}`, "sec_edgar"),
          domain,
          assetType: "info",
          name: `SEC EDGAR: No public filings found for ${domain}`,
          source: "sec_edgar",
          observedAt: now,
          tags: ["sec_edgar", "bia_context", "financial", "no_results"],
          evidence: {
            severity: 0,
            status: "not_found",
            value: `No SEC filings found — organization may be private, non-US, or not publicly traded`,
          },
          attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" },
        });
        return { connector: "sec_edgar", domain, observations, errors, durationMs: Date.now() - start, rateLimited };
      }

      // Extract CIK and company info from search results
      const topHit = searchResult.hits.hits[0]._source || searchResult.hits.hits[0];
      const cik = topHit.entity_id || topHit.ciks?.[0];
      const entityName = topHit.entity_name || topHit.display_names?.[0] || companyName;

      // Get full submission history for this entity
      let submissions: any = null;
      if (cik) {
        try {
          submissions = await getSubmissions(String(cik));
        } catch {
          // Submissions lookup is best-effort
        }
      }

      // Build company profile observation
      const recentFilings = searchResult.hits.hits.slice(0, 5);
      const filingTypes = recentFilings.map((h: any) => (h._source || h).form_type || (h._source || h).forms).filter(Boolean);

      observations.push({
        assetId: makeAssetId(domain, `SEC EDGAR company: ${entityName}`, "sec_edgar"),
        domain,
        assetType: "info",
        name: `SEC EDGAR: ${entityName} (CIK ${cik || 'unknown'})`,
        source: "sec_edgar",
        observedAt: now,
        tags: ["sec_edgar", "bia_context", "financial", "public_company", "company_profile"],
        evidence: {
          severity: 2,
          confidence: cik ? 85 : 60,
          value: `Public company: ${entityName} — recent filings: ${filingTypes.join(", ") || "various"}`,
          entity_name: entityName,
          cik: cik || null,
          is_public_company: true,
          recent_filing_types: filingTypes,
          total_filings: searchResult.hits.total?.value || recentFilings.length,
          edgar_url: cik ? `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${cik}&type=10-K&dateb=&owner=include&count=10` : null,
        },
        attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" },
      });

      // Extract submission details if available
      if (submissions) {
        const companyInfo = {
          name: submissions.name,
          sic: submissions.sic,
          sicDescription: submissions.sicDescription,
          stateOfIncorporation: submissions.stateOfIncorporation,
          fiscalYearEnd: submissions.fiscalYearEnd,
          exchanges: submissions.exchanges || [],
          tickers: submissions.tickers || [],
          category: submissions.category,
          entityType: submissions.entityType,
          phone: submissions.phone,
          addresses: submissions.addresses,
        };

        observations.push({
          assetId: makeAssetId(domain, `SEC EDGAR profile: ${entityName}`, "sec_edgar"),
          domain,
          assetType: "info",
          name: `SEC EDGAR Profile: ${companyInfo.name || entityName} — ${companyInfo.sicDescription || 'unknown sector'}`,
          source: "sec_edgar",
          observedAt: now,
          tags: [
            "sec_edgar", "bia_context", "financial", "company_profile",
            ...(companyInfo.tickers?.length ? [`ticker:${companyInfo.tickers[0]}`] : []),
            ...(companyInfo.sic ? [`sic:${companyInfo.sic}`] : []),
          ],
          evidence: {
            severity: 2,
            confidence: 90,
            value: `${companyInfo.name || entityName} — SIC: ${companyInfo.sicDescription || 'unknown'} | Ticker: ${companyInfo.tickers?.join(", ") || 'N/A'} | Exchange: ${companyInfo.exchanges?.join(", ") || 'N/A'}`,
            company_name: companyInfo.name,
            sic_code: companyInfo.sic,
            sic_description: companyInfo.sicDescription,
            state_of_incorporation: companyInfo.stateOfIncorporation,
            fiscal_year_end: companyInfo.fiscalYearEnd,
            exchanges: companyInfo.exchanges,
            tickers: companyInfo.tickers,
            entity_type: companyInfo.entityType,
            category: companyInfo.category,
          },
          attribution: { provider: "SEC EDGAR", url: `https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=${cik}`, method: "api" },
        });

        // Extract recent 10-K filings for financial data
        const recentFilingsData = submissions.filings?.recent;
        if (recentFilingsData?.form) {
          const tenKIndices: number[] = [];
          for (let i = 0; i < recentFilingsData.form.length && tenKIndices.length < 3; i++) {
            if (recentFilingsData.form[i] === "10-K") {
              tenKIndices.push(i);
            }
          }

          for (const idx of tenKIndices) {
            const filingDate = recentFilingsData.filingDate?.[idx];
            const accessionNumber = recentFilingsData.accessionNumber?.[idx];
            const primaryDoc = recentFilingsData.primaryDocument?.[idx];

            observations.push({
              assetId: makeAssetId(domain, `SEC 10-K: ${entityName} ${filingDate}`, "sec_edgar"),
              domain,
              assetType: "info",
              name: `SEC 10-K Filing: ${entityName} (${filingDate || 'unknown date'})`,
              source: "sec_edgar",
              observedAt: now,
              firstSeen: filingDate ? new Date(filingDate) : undefined,
              tags: ["sec_edgar", "bia_context", "financial", "10-K", "annual_report"],
              evidence: {
                severity: 2,
                confidence: 95,
                value: `Annual report (10-K) filed ${filingDate || 'unknown'} — contains revenue, risk factors, business segments`,
                filing_type: "10-K",
                filing_date: filingDate,
                accession_number: accessionNumber,
                primary_document: primaryDoc,
                filing_url: accessionNumber
                  ? `https://www.sec.gov/Archives/edgar/data/${cik}/${accessionNumber.replace(/-/g, "")}/${primaryDoc}`
                  : null,
                bia_relevance: "Contains revenue data, business segment descriptions, risk factors, and operational dependencies for BIA financial impact calculation",
              },
              attribution: { provider: "SEC EDGAR", url: "https://www.sec.gov/edgar", method: "api" },
            });
          }
        }
      }
    } catch (err: any) {
      if (err.message?.includes("429") || err.message?.includes("rate")) {
        rateLimited = true;
        errors.push("SEC EDGAR rate limited (10 req/sec limit)");
      } else if (err.message?.includes("timeout")) {
        errors.push("SEC EDGAR API timeout");
      } else {
        errors.push(err.message || "Unknown error during SEC EDGAR lookup");
      }
    }

    return {
      connector: "sec_edgar",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
