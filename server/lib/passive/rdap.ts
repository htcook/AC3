/**
 * RDAP — Registration Data Access Protocol Connector
 * 
 * Queries RDAP (successor to WHOIS) for domain registration data.
 * Returns registrar, registration dates, nameservers, and status codes.
 * 
 * Method: Queries RDAP bootstrap via rdap.org for domain registration records
 * Data Source: IANA RDAP bootstrap registry → authoritative registrar RDAP servers
 * Attribution: Each observation links to the RDAP JSON response for verification
 * Free: Yes, no API key required (RDAP is an open standard)
 */

import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

export const rdapConnector: PassiveConnector = {
  name: "rdap",
  description: "Domain registration data via RDAP — discovers registrar, nameservers, registration dates, and domain status",
  requiresApiKey: false,
  freeUrl: "https://rdap.org",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;

    try {
      const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);

      let data: any;
      try {
        const res = await fetch(url, { signal: controller.signal, headers: { Accept: "application/rdap+json" } });
        if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
        data = await res.json();
      } finally {
        clearTimeout(timer);
      }

      const now = new Date();

      // Extract registration events
      const events: Record<string, string> = {};
      for (const evt of (data.events || [])) {
        if (evt.eventAction && evt.eventDate) {
          events[evt.eventAction] = evt.eventDate;
        }
      }

      // Extract nameservers
      const nameservers: string[] = [];
      for (const ns of (data.nameservers || [])) {
        const nsName = ns.ldhName || ns.unicodeName;
        if (nsName) {
          nameservers.push(nsName.toLowerCase());
          observations.push({
            assetId: makeAssetId(domain, nsName, "rdap_ns"),
            domain,
            assetType: "ns",
            name: nsName.toLowerCase(),
            source: "rdap",
            observedAt: now,
            tags: ["nameserver", "rdap"],
            evidence: { nameserver: nsName, ip_addresses: ns.ipAddresses },
            attribution: {
              provider: "RDAP (Registration Data Access Protocol)",
              url: `https://rdap.org/domain/${domain}`,
              method: `RDAP query for ${domain} — nameserver ${nsName} listed in authoritative registration data`,
              verifyUrl: `https://rdap.org/domain/${domain}`,
            },
          });
        }
      }

      // Extract registrar info from entities
      let registrar = "";
      for (const entity of (data.entities || [])) {
        if ((entity.roles || []).includes("registrar")) {
          registrar = entity.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] || entity.handle || "";
        }
      }

      // Main domain observation
      observations.push({
        assetId: makeAssetId(domain, domain, "rdap"),
        domain,
        assetType: "subdomain",
        name: domain,
        source: "rdap",
        observedAt: now,
        firstSeen: events.registration ? new Date(events.registration) : undefined,
        lastSeen: events.last_changed ? new Date(events.last_changed) : undefined,
        tags: [
          "registration_data",
          ...(data.status || []),
          ...(registrar ? [`registrar:${registrar}`] : []),
        ],
        evidence: {
          handle: data.handle,
          ldhName: data.ldhName,
          status: data.status,
          registrar,
          nameservers,
          events,
          secureDNS: data.secureDNS,
        },
        attribution: {
          provider: "RDAP (Registration Data Access Protocol)",
          url: `https://rdap.org/domain/${domain}`,
          method: `RDAP domain lookup — queried authoritative registrar for ${domain} registration data including registrar, nameservers, and status`,
          verifyUrl: `https://rdap.org/domain/${domain}`,
        },
      });

    } catch (err: any) {
      errors.push(`RDAP error: ${err.message}`);
    }

    return { connector: "rdap", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
