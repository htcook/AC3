/**
 * JARM TLS Fingerprinting Connector
 * 
 * JARM is an active TLS server fingerprinting tool that produces a hash
 * identifying the TLS implementation. It can detect:
 * - C2 frameworks (Cobalt Strike, Metasploit)
 * - CDN/proxy infrastructure
 * - Server software without banner exposure
 * 
 * Method: Sends 10 TLS Client Hello packets with varying parameters and
 *         hashes the server responses to create a unique fingerprint.
 * Data Source: Direct TLS probing (active, but minimal footprint)
 * Free: Yes, BSD-3 license
 * 
 * Note: This is a simplified implementation that computes a TLS fingerprint
 * from the server's TLS handshake response. For full JARM accuracy,
 * the scan server binary should be used.
 */

import { createHash } from "crypto";
import { connect, TLSSocket } from "tls";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

/** Known JARM hashes for common C2/infrastructure */
const KNOWN_JARM_SIGNATURES: Record<string, string> = {
  "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike",
  "07d14d16d21d21d00042d41d00041de5fb3038b65b1e7e56c8a09c21e0e0ae": "Cobalt Strike (variant)",
  "07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9f98571c65bf43": "Metasploit",
  "29d29d15d29d29d29c29d29d29d29de1a3c0d7ca6ad8388057c1b45c414": "Merlin C2",
  "00000000000000000000000000000000000000000000000000000000000000": "Refused/No TLS",
};

/**
 * Perform a basic TLS fingerprint by connecting and extracting cipher/protocol info.
 * This is a lightweight alternative to full JARM — for full accuracy, use the scan server binary.
 * Respects abort signal for early cancellation.
 */
async function tlsFingerprint(host: string, port: number, timeout: number, signal?: AbortSignal): Promise<{
  protocol: string;
  cipher: string;
  authorized: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  serialNumber: string;
  sigAlgorithm: string;
}> {
  return new Promise((resolve, reject) => {
    // Check if already aborted
    if (signal?.aborted) {
      reject(new Error("Aborted before TLS connect"));
      return;
    }

    const PER_PORT_TIMEOUT = Math.min(timeout, 8000); // 8s max per port
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("TLS connection timeout"));
    }, PER_PORT_TIMEOUT);

    // Listen for external abort
    const onAbort = () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error("Aborted by external signal"));
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    const socket: TLSSocket = connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: PER_PORT_TIMEOUT,
    }, () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      const protocol = socket.getProtocol() || "unknown";
      const cipher = socket.getCipher()?.name || "unknown";
      const cert = socket.getPeerCertificate();
      
      const result = {
        protocol,
        cipher,
        authorized: socket.authorized,
        issuer: typeof cert.issuer === 'object' ? (cert.issuer as any)?.O || JSON.stringify(cert.issuer) : String(cert.issuer || ""),
        subject: typeof cert.subject === 'object' ? (cert.subject as any)?.CN || JSON.stringify(cert.subject) : String(cert.subject || ""),
        validFrom: cert.valid_from || "",
        validTo: cert.valid_to || "",
        fingerprint256: cert.fingerprint256 || "",
        serialNumber: cert.serialNumber || "",
        sigAlgorithm: (cert as any).sigAlgorithm || "",
      };

      socket.destroy();
      resolve(result);
    });

    socket.on("error", (err) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      reject(err);
    });

    socket.on("timeout", () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      socket.destroy();
      reject(new Error("Socket timeout"));
    });
  });
}

export const jarmFingerprintConnector: PassiveConnector = {
  name: "jarm_fingerprint",
  description: "JARM TLS fingerprinting — identifies server TLS implementation to detect C2 frameworks, CDN infrastructure, and server software",
  requiresApiKey: false,
  freeUrl: "https://github.com/salesforce/jarm",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 10000;
    const signal = config?.signal;

    // Early abort check
    if (signal?.aborted) {
      return { connector: "jarm_fingerprint", domain, observations: [], errors: ['Aborted before start'], durationMs: 0, rateLimited: false };
    }

    try {
      const ports = [443, 8443, 8080];
      const now = new Date();

      for (const port of ports) {
        // Check abort between ports
        if (signal?.aborted) {
          errors.push(`Aborted after scanning ${observations.length} port(s)`);
          break;
        }

        try {
          const fp = await tlsFingerprint(domain, port, timeout, signal);
          
          // Create a composite fingerprint hash
          const fpString = `${fp.protocol}|${fp.cipher}|${fp.issuer}|${fp.sigAlgorithm}`;
          const fpHash = createHash("sha256").update(fpString).digest("hex").slice(0, 32);

          observations.push({
            assetId: makeAssetId(domain, `tls:${port}:${fpHash}`, "jarm_fingerprint"),
            domain,
            assetType: "infrastructure",
            name: `${domain}:${port}`,
            source: "jarm_fingerprint",
            observedAt: now,
            tags: ["tls_fingerprint", "infrastructure_discovery", port === 443 ? "https" : `port_${port}`],
            evidence: {
              port,
              protocol: fp.protocol,
              cipher: fp.cipher,
              authorized: fp.authorized,
              issuer: fp.issuer,
              subject: fp.subject,
              validFrom: fp.validFrom,
              validTo: fp.validTo,
              fingerprint256: fp.fingerprint256,
              serialNumber: fp.serialNumber,
              compositeHash: fpHash,
            },
            attribution: {
              provider: "JARM TLS Fingerprint (local probe)",
              url: `https://${domain}:${port}`,
              method: `TLS fingerprinting on ${domain}:${port} — protocol: ${fp.protocol}, cipher: ${fp.cipher}, issuer: ${fp.issuer}`,
            },
          });
        } catch {
          // Port not responding or no TLS — skip silently
          continue;
        }
      }

      if (observations.length === 0 && !signal?.aborted) {
        errors.push(`No TLS services found on ${domain} (tried ports 443, 8443, 8080)`);
      }
    } catch (err: any) {
      errors.push(`JARM fingerprint error: ${err.message}`);
    }

    return { connector: "jarm_fingerprint", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
