/**
 * DKIM Key Generation for Phishing Infrastructure
 *
 * Generates RSA keypairs for DKIM signing, outputs DNS TXT record values,
 * and provides the private key for Postfix/OpenDKIM configuration.
 *
 * Flow:
 * 1. Generate 2048-bit RSA keypair
 * 2. Extract public key in DNS-compatible format (base64, no headers)
 * 3. Store private key for OpenDKIM on the mail server
 * 4. Return DNS TXT record value for the selector._domainkey subdomain
 */

import crypto from "crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DkimKeypair {
  domain: string;
  selector: string;
  privateKey: string;       // PEM format (for OpenDKIM)
  publicKey: string;        // Base64 (for DNS TXT record)
  dnsRecord: DkimDnsRecord;
  opendkimConfig: OpenDkimConfig;
}

export interface DkimDnsRecord {
  hostname: string;         // e.g., "default._domainkey.example.com"
  type: "TXT";
  value: string;            // e.g., "v=DKIM1; k=rsa; p=MIIBIjAN..."
  ttl: number;
}

export interface OpenDkimConfig {
  keyTable: string;         // KeyTable entry
  signingTable: string;     // SigningTable entry
  privateKeyPath: string;   // Where to store the private key
}

export interface DkimVerifyResult {
  valid: boolean;
  domain: string;
  selector: string;
  error?: string;
}

// ─── Key Generation ──────────────────────────────────────────────────────────

/**
 * Generate a DKIM keypair for a domain.
 *
 * @param domain - The domain to generate DKIM for (e.g., "phish-example.com")
 * @param selector - The DKIM selector (default: "default", can use date-based like "202508")
 * @param keySize - RSA key size in bits (2048 recommended, 1024 for legacy compatibility)
 */
export function generateDkimKeypair(
  domain: string,
  selector: string = "default",
  keySize: 1024 | 2048 = 2048
): DkimKeypair {
  // Generate RSA keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: keySize,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  // Extract raw public key (remove PEM headers and newlines)
  const publicKeyBase64 = publicKey
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\n/g, "")
    .trim();

  // Build DNS TXT record value
  const dnsValue = `v=DKIM1; k=rsa; p=${publicKeyBase64}`;

  // For TXT records > 255 chars, split into multiple strings
  const dnsRecordValue = dnsValue.length > 255
    ? splitTxtRecord(dnsValue)
    : dnsValue;

  const hostname = `${selector}._domainkey.${domain}`;
  const privateKeyPath = `/etc/opendkim/keys/${domain}/${selector}.private`;

  return {
    domain,
    selector,
    privateKey,
    publicKey: publicKeyBase64,
    dnsRecord: {
      hostname,
      type: "TXT",
      value: dnsRecordValue,
      ttl: 300,
    },
    opendkimConfig: {
      keyTable: `${selector}._domainkey.${domain} ${domain}:${selector}:${privateKeyPath}`,
      signingTable: `*@${domain} ${selector}._domainkey.${domain}`,
      privateKeyPath,
    },
  };
}

/**
 * Generate DKIM keypairs for multiple domains (batch operation).
 */
export function generateBatchDkim(
  domains: string[],
  selector: string = "default"
): DkimKeypair[] {
  return domains.map((domain) => generateDkimKeypair(domain, selector));
}

/**
 * Generate OpenDKIM configuration files content for a set of domains.
 */
export function generateOpendkimConfig(keypairs: DkimKeypair[]): {
  keyTable: string;
  signingTable: string;
  trustedHosts: string;
} {
  const keyTableLines = keypairs.map((kp) => kp.opendkimConfig.keyTable);
  const signingTableLines = keypairs.map((kp) => kp.opendkimConfig.signingTable);
  const trustedDomains = keypairs.map((kp) => kp.domain);

  return {
    keyTable: keyTableLines.join("\n"),
    signingTable: signingTableLines.join("\n"),
    trustedHosts: ["127.0.0.1", "localhost", ...trustedDomains].join("\n"),
  };
}

/**
 * Generate a Postfix main.cf snippet for DKIM integration.
 */
export function generatePostfixDkimConfig(): string {
  return [
    "# DKIM Configuration (OpenDKIM)",
    "milter_default_action = accept",
    "milter_protocol = 6",
    "smtpd_milters = inet:localhost:8891",
    "non_smtpd_milters = inet:localhost:8891",
  ].join("\n");
}

/**
 * Verify a DKIM DNS record is properly published (via DNS lookup).
 */
export async function verifyDkimRecord(
  domain: string,
  selector: string = "default"
): Promise<DkimVerifyResult> {
  const hostname = `${selector}._domainkey.${domain}`;

  try {
    const { resolve } = await import("dns/promises");
    const records = await resolve(hostname, "TXT");

    if (!records || records.length === 0) {
      return { valid: false, domain, selector, error: "No TXT record found" };
    }

    // TXT records come as arrays of strings (split at 255 chars)
    const fullRecord = records[0].join("");

    if (!fullRecord.includes("v=DKIM1")) {
      return { valid: false, domain, selector, error: "Record missing v=DKIM1" };
    }
    if (!fullRecord.includes("k=rsa")) {
      return { valid: false, domain, selector, error: "Record missing k=rsa" };
    }
    if (!fullRecord.includes("p=")) {
      return { valid: false, domain, selector, error: "Record missing public key (p=)" };
    }

    return { valid: true, domain, selector };
  } catch (err: any) {
    return {
      valid: false,
      domain,
      selector,
      error: err.code === "ENOTFOUND" ? "DNS record not found" : err.message,
    };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Split a long TXT record value into 255-char chunks (RFC 4408).
 */
function splitTxtRecord(value: string): string {
  const chunks: string[] = [];
  for (let i = 0; i < value.length; i += 255) {
    chunks.push(`"${value.slice(i, i + 255)}"`);
  }
  return chunks.join(" ");
}
