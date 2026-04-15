/**
 * DNS Zone Transfer (AXFR) Attempt Connector
 * 
 * Attempts DNS zone transfers against each NS record for the target domain.
 * Misconfigured DNS servers may allow AXFR, revealing the entire zone file
 * including all subdomains, mail servers, and other records.
 * 
 * Method: Resolve NS records → attempt AXFR against each nameserver
 * Data Source: Direct DNS query (active, but standard DNS protocol)
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import { resolveNs, resolve4, resolveMx, resolveTxt, resolveCname } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

/**
 * Attempt a DNS zone transfer using a raw TCP connection.
 * AXFR uses TCP on port 53 with a specific wire format.
 */
async function attemptAxfr(nameserver: string, domain: string, timeout: number): Promise<string[]> {
  const net = await import("net");
  
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("AXFR timeout"));
    }, timeout);

    const socket = new net.Socket();
    const subdomains: string[] = [];

    // Build AXFR query packet
    const domainParts = domain.split(".");
    let qnameLen = 0;
    for (const part of domainParts) qnameLen += 1 + part.length;
    qnameLen += 1; // null terminator

    const queryLen = 12 + qnameLen + 4; // header + qname + qtype + qclass
    const packet = Buffer.alloc(2 + queryLen); // 2-byte length prefix for TCP

    // TCP length prefix
    packet.writeUInt16BE(queryLen, 0);
    // Transaction ID
    packet.writeUInt16BE(0x1234, 2);
    // Flags: standard query
    packet.writeUInt16BE(0x0000, 4);
    // Questions: 1
    packet.writeUInt16BE(1, 6);
    // Answer/Authority/Additional: 0
    packet.writeUInt16BE(0, 8);
    packet.writeUInt16BE(0, 10);
    packet.writeUInt16BE(0, 12);

    // QNAME
    let offset = 14;
    for (const part of domainParts) {
      packet.writeUInt8(part.length, offset++);
      packet.write(part, offset, "ascii");
      offset += part.length;
    }
    packet.writeUInt8(0, offset++);
    // QTYPE: AXFR (252)
    packet.writeUInt16BE(252, offset);
    offset += 2;
    // QCLASS: IN (1)
    packet.writeUInt16BE(1, offset);

    let responseBuffer = Buffer.alloc(0);

    socket.connect(53, nameserver, () => {
      socket.write(packet);
    });

    socket.on("data", (data: Buffer) => {
      responseBuffer = Buffer.concat([responseBuffer, data]);
      
      // Try to extract domain names from the response
      // Simple heuristic: look for domain name patterns in the response
      const responseStr = responseBuffer.toString("ascii");
      const domainPattern = new RegExp(`[a-zA-Z0-9][-a-zA-Z0-9]*\\.${domain.replace(/\./g, '\\.')}`, 'gi');
      let match: RegExpExecArray | null;
      while ((match = domainPattern.exec(responseStr)) !== null) {
        const found = match[0].toLowerCase();
        if (!subdomains.includes(found)) {
          subdomains.push(found);
        }
      }
    });

    socket.on("end", () => {
      clearTimeout(timer);
      resolve(subdomains);
    });

    socket.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export const dnsZoneTransferConnector: PassiveConnector = {
  name: "dns_zone_transfer",
  description: "DNS zone transfer (AXFR) attempt — discovers all DNS records from misconfigured nameservers",
  requiresApiKey: false,
  freeUrl: "https://en.wikipedia.org/wiki/DNS_zone_transfer",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 10000;
    const maxResults = config?.maxResults ?? 500;

    try {
      // Step 1: Resolve NS records
      let nameservers: string[];
      try {
        nameservers = await resolveNs(domain);
      } catch {
        return { connector: "dns_zone_transfer", domain, observations, errors: ["Could not resolve NS records"], durationMs: Date.now() - start, rateLimited: false };
      }

      const seen = new Set<string>();
      const now = new Date();
      let transferSucceeded = false;

      // Step 2: Attempt AXFR against each nameserver
      for (const ns of nameservers.slice(0, 4)) { // Limit to 4 NS records
        try {
          // Resolve NS hostname to IP
          let nsIps: string[];
          try {
            nsIps = await resolve4(ns);
          } catch {
            continue;
          }

          for (const nsIp of nsIps.slice(0, 2)) {
            try {
              const subdomains = await attemptAxfr(nsIp, domain, timeout);
              
              if (subdomains.length > 0) {
                transferSucceeded = true;

                // Log the zone transfer success as a finding
                observations.push({
                  assetId: makeAssetId(domain, `axfr:${ns}`, "dns_zone_transfer"),
                  domain,
                  assetType: "infrastructure",
                  name: `axfr:${ns}`,
                  source: "dns_zone_transfer",
                  observedAt: now,
                  tags: ["zone_transfer", "misconfiguration", "critical"],
                  evidence: {
                    nameserver: ns,
                    nameserverIp: nsIp,
                    subdomainsFound: subdomains.length,
                    vulnerability: "DNS zone transfer allowed — entire zone file is publicly accessible",
                  },
                  attribution: {
                    provider: "DNS Zone Transfer (AXFR)",
                    method: `Successful AXFR zone transfer from ${ns} (${nsIp}) — ${subdomains.length} records exposed`,
                  },
                });

                // Add discovered subdomains
                for (const sub of subdomains) {
                  if (seen.has(sub) || seen.size > maxResults) continue;
                  seen.add(sub);

                  observations.push({
                    assetId: makeAssetId(domain, sub, "dns_zone_transfer"),
                    domain,
                    assetType: "subdomain",
                    name: sub,
                    source: "dns_zone_transfer",
                    observedAt: now,
                    tags: ["zone_transfer", "subdomain_enum"],
                    evidence: { nameserver: ns, discoveryMethod: "AXFR" },
                    attribution: {
                      provider: "DNS Zone Transfer (AXFR)",
                      method: `Discovered via zone transfer from ${ns}`,
                    },
                  });
                }
              }
            } catch {
              // AXFR refused or failed — expected for properly configured servers
              continue;
            }
          }
        } catch {
          continue;
        }
      }

      if (!transferSucceeded) {
        // Not an error — zone transfers SHOULD be blocked
        observations.push({
          assetId: makeAssetId(domain, "axfr:blocked", "dns_zone_transfer"),
          domain,
          assetType: "infrastructure",
          name: `axfr:${domain}`,
          source: "dns_zone_transfer",
          observedAt: new Date(),
          tags: ["zone_transfer", "secure"],
          evidence: {
            nameservers: nameservers,
            result: "Zone transfer properly blocked on all nameservers",
          },
          attribution: {
            provider: "DNS Zone Transfer (AXFR)",
            method: `Attempted AXFR against ${nameservers.length} nameservers — all properly blocked`,
          },
        });
      }
    } catch (err: any) {
      errors.push(`DNS zone transfer error: ${err.message}`);
    }

    return { connector: "dns_zone_transfer", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
