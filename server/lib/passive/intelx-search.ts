/**
 * IntelX (Intelligence X) Passive Connector
 * 
 * Searches Intelligence X for domain-specific darkweb mentions,
 * paste sites, leaked databases, and stealer logs.
 * API: https://intelx.io/developers
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

const INTELX_BASE = 'https://2.intelx.io';

interface IntelXSearchResult {
  id: string;
  name: string;
  date: string;
  bucket: string;
  keywordhmac: string;
  mediah: string;
  mediahp: string;
  storageid: string;
  type: number;
  typeh: string;
  added: string;
  systemid: string;
  accesslevel: number;
  media: number;
  tags: string[];
  simhash: number;
}

export const intelxSearchConnector: PassiveConnector = {
  name: "intelx_search",
  description: 'Searches darkweb, paste sites, leaked databases, and stealer logs for domain mentions',
  requiresApiKey: true,
  freeUrl: "https://intelx.io",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const now = new Date();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    let rateLimited = false;

    const apiKey = config?.apiKey;
    if (!apiKey) {
      errors.push("No IntelX API key configured");
      return {
        connector: this.name,
        domain,
        observations,
        errors,
        durationMs: Date.now() - start,
        rateLimited,
      };
    }

    try {
      // Step 1: Start search
      const searchResp = await fetch(`${INTELX_BASE}/intelligent/search`, {
        method: 'POST',
        headers: {
          'x-key': apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          term: domain,
          buckets: ['pastes', 'leaks', 'darknet', 'dumpster'],
          lookuplevel: 0,
          maxresults: 100,
          timeout: 10,
          datefrom: '',
          dateto: '',
          sort: 2, // sort by date descending
          media: 0, // all media types
        }),
        signal: config?.signal,
      });

      if (searchResp.status === 402) {
        rateLimited = true;
        errors.push("IntelX API rate limit exceeded or payment required");
      } else if (!searchResp.ok) {
        throw new Error(`IntelX search failed with status: ${searchResp.status}`);
      }

      const searchData = await searchResp.json() as { id: string; status: number };
      const searchId = searchData.id;

      // Step 2: Poll for results (wait up to 15s)
      let results: IntelXSearchResult[] = [];
      for (let attempt = 0; attempt < 5; attempt++) {
        await new Promise(r => setTimeout(r, 3000));
        if (config?.signal?.aborted) throw new Error("Operation aborted");

        const resultResp = await fetch(
          `${INTELX_BASE}/intelligent/search/result?id=${searchId}&limit=100&offset=0`,
          { headers: { 'x-key': apiKey }, signal: config?.signal }
        );

        if (resultResp.ok) {
          const resultData = await resultResp.json() as { records: IntelXSearchResult[]; status: number };
          if (resultData.records?.length > 0) {
            results = resultData.records;
          }
          if (resultData.status === 0 || resultData.status === 2) break; // done or no more results
        }
      }

      // Step 3: Process results into observations
      const stealerLogEntries: IntelXSearchResult[] = [];
      const pasteEntries: IntelXSearchResult[] = [];
      const leakEntries: IntelXSearchResult[] = [];
      const darknetEntries: IntelXSearchResult[] = [];

      for (const record of results) {
        const bucket = record.bucket?.toLowerCase() || 'unknown';
        if (bucket === 'darknet') darknetEntries.push(record);
        else if (bucket === 'leaks') leakEntries.push(record);
        else if (bucket === 'pastes') pasteEntries.push(record);

        if (record.name?.match(/stealer|redline|raccoon|vidar|aurora|lumma|stealc|meta_stealer/i)) {
          stealerLogEntries.push(record);
        }
      }

      const attribution = { provider: 'Intelligence X', url: `https://intelx.io/results?s=${searchId}`, method: "api" as const };

      // Darknet-specific observations
      for (const entry of darknetEntries.slice(0, 10)) {
        const name = entry.name || `Darknet mention: ${domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, this.name),
          domain,
          assetType: 'breach',
          name,
          source: this.name,
          observedAt: now,
          firstSeen: entry.date ? new Date(entry.date) : undefined,
          tags: ['darkweb', 'darknet_mention', 'intelx'],
          evidence: {
            severity: 8,
            confidence: 80,
            description: `Darknet mention found on ${entry.date || 'unknown date'} in ${entry.bucket}`,
            date: entry.date,
            media_type: entry.typeh,
            storage_id: entry.storageid,
            system_id: entry.systemid,
          },
          attribution,
        });
      }

      // Stealer log observations
      for (const entry of stealerLogEntries.slice(0, 10)) {
        const name = `Stealer log: ${entry.name || domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, this.name),
          domain,
          assetType: 'breach',
          name,
          source: this.name,
          observedAt: now,
          firstSeen: entry.date ? new Date(entry.date) : undefined,
          tags: ['darkweb', 'stealer_log', 'credential_leak', 'intelx'],
          evidence: {
            severity: 9,
            confidence: 85,
            description: `Stealer log containing ${domain} credentials found`,
            stealer_name: entry.name,
            date: entry.date,
            storage_id: entry.storageid,
          },
          attribution,
        });
      }

      // Paste site observations
      for (const entry of pasteEntries.slice(0, 5)) {
        const name = `Paste: ${entry.name || domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, this.name),
          domain,
          assetType: 'breach',
          name,
          source: this.name,
          observedAt: now,
          firstSeen: entry.date ? new Date(entry.date) : undefined,
          tags: ['paste_site', 'intelx'],
          evidence: {
            severity: 5,
            confidence: 70,
            description: `Domain mentioned in paste site on ${entry.date || 'unknown date'}`,
            date: entry.date,
            storage_id: entry.storageid,
          },
          attribution,
        });
      }

      // Leak database observations
      for (const entry of leakEntries.slice(0, 5)) {
        const name = `Leak DB: ${entry.name || domain}`;
        observations.push({
          assetId: makeAssetId(domain, name, this.name),
          domain,
          assetType: 'breach',
          name,
          source: this.name,
          observedAt: now,
          firstSeen: entry.date ? new Date(entry.date) : undefined,
          tags: ['data_leak', 'breach_database', 'intelx'],
          evidence: {
            severity: 8,
            confidence: 80,
            description: `Domain found in leaked database: ${entry.name}`,
            leak_name: entry.name,
            date: entry.date,
            storage_id: entry.storageid,
          },
          attribution,
        });
      }

    } catch (err: any) {
      errors.push(err.message || 'Unknown error during IntelX search');
    }

    return {
      connector: this.name,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
