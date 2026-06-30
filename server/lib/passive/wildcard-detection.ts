/**
 * Wildcard DNS Detection
 * 
 * Before accepting subdomain enumeration results, resolves a random non-existent
 * subdomain (e.g., randomstring12345.example.com). If it resolves, the domain has
 * wildcard DNS and all brute-force results should be filtered or flagged.
 * 
 * This prevents false-positive subdomain discovery when wildcard DNS is configured.
 */

import { resolve4 } from "dns/promises";
import { randomBytes } from "crypto";
import type { AssetObservation } from "./types";

export interface WildcardCheckResult {
  domain: string;
  isWildcard: boolean;
  wildcardIps: string[];
  probeHostname: string;
  durationMs: number;
}

/**
 * Generate a random subdomain label that is extremely unlikely to exist.
 */
function randomLabel(): string {
  return `wc-probe-${randomBytes(8).toString("hex")}`;
}

/**
 * Check if a domain has wildcard DNS configured.
 * Resolves 3 random non-existent subdomains. If 2+ resolve to the same IP(s),
 * the domain is considered to have wildcard DNS.
 */
export async function detectWildcardDns(domain: string, timeout = 5000): Promise<WildcardCheckResult> {
  const start = Date.now();
  const probes = [randomLabel(), randomLabel(), randomLabel()];
  const resolvedSets: string[][] = [];

  for (const label of probes) {
    const hostname = `${label}.${domain}`;
    try {
      const ips = await Promise.race([
        resolve4(hostname),
        new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error("DNS timeout")), timeout)),
      ]);
      resolvedSets.push(ips.sort());
    } catch {
      resolvedSets.push([]); // NXDOMAIN or timeout — expected for non-wildcard
    }
  }

  // Count how many probes resolved
  const resolvedCount = resolvedSets.filter(s => s.length > 0).length;

  // If 2+ probes resolved, it's likely wildcard DNS
  const isWildcard = resolvedCount >= 2;

  // Collect the wildcard IPs (union of all resolved IPs)
  const wildcardIps = [...new Set(resolvedSets.flat())];

  return {
    domain,
    isWildcard,
    wildcardIps,
    probeHostname: `${probes[0]}.${domain}`,
    durationMs: Date.now() - start,
  };
}

/**
 * Filter subdomain observations to remove wildcard false positives.
 * Subdomains that resolve to the wildcard IP(s) are tagged as "wildcard_candidate"
 * but NOT removed — they may still be real subdomains that happen to share the wildcard IP.
 * 
 * Returns the observations with wildcard tags added where applicable.
 */
export function tagWildcardObservations(
  observations: AssetObservation[],
  wildcardResult: WildcardCheckResult,
): AssetObservation[] {
  if (!wildcardResult.isWildcard || wildcardResult.wildcardIps.length === 0) {
    return observations;
  }

  const wildcardIpSet = new Set(wildcardResult.wildcardIps);

  return observations.map(obs => {
    if (obs.ip && wildcardIpSet.has(obs.ip)) {
      return {
        ...obs,
        tags: [...obs.tags, "wildcard_candidate"],
        evidence: {
          ...obs.evidence,
          wildcardDetected: true,
          wildcardIps: wildcardResult.wildcardIps,
        },
      };
    }
    return obs;
  });
}

/**
 * Create a risk signal for wildcard DNS detection.
 */
export function createWildcardSignal(domain: string, wildcardResult: WildcardCheckResult) {
  return {
    signalType: "wildcard_dns",
    severity: "info" as const,
    confidence: wildcardResult.wildcardIps.length > 0 ? 0.95 : 0.7,
    rationale: `Domain ${domain} has wildcard DNS configured — all non-existent subdomains resolve to ${wildcardResult.wildcardIps.join(", ")}. Subdomain enumeration results may contain false positives.`,
    evidenceRefs: [wildcardResult.probeHostname],
  };
}
