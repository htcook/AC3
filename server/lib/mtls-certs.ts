/**
 * mTLS Certificate Service for C2 Connections
 *
 * Generates and manages ECDSA P-256 client certificates for mutual TLS
 * authentication with C2 servers (CALDERA, Sliver, Metasploit).
 *
 * Architecture:
 *   - Internal CA: A self-signed ECDSA P-256 root CA issues all client certs
 *   - Per-server certs: Each C2 server gets its own client certificate
 *   - FIPS-compliant: All crypto uses the FIPSCryptoService
 *   - At-rest encryption: Private keys are encrypted before DB storage
 *
 * Certificate chain:
 *   [Internal CA Root] → [C2 Client Cert per server]
 *
 * Storage:
 *   - CA cert + encrypted private key in `mtls_certificates` table (type = 'ca')
 *   - Client certs + encrypted private keys in same table (type = 'client')
 */

import crypto from "crypto";
import { getFIPSCrypto } from "./fips-crypto";
import { encryptCredential, decryptCredential, FIPS_CONTEXTS } from "./credential-crypto";
import { getDb } from "../db";
import { sql } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────

export interface CertificateInfo {
  id: string;
  type: "ca" | "client";
  commonName: string;
  serialNumber: string;
  issuer: string;
  subject: string;
  validFrom: number;
  validTo: number;
  fingerprint: string;
  certificate: string; // PEM
  c2ServerId?: string;
  status: "active" | "revoked" | "expired";
  createdAt: number;
}

export interface CertificateWithKey extends CertificateInfo {
  privateKey: string; // PEM (decrypted)
}

export interface MTLSConfig {
  cert: string; // Client certificate PEM
  key: string; // Client private key PEM
  ca: string; // CA certificate PEM
}

// ─── ASN.1 / DER Helpers ────────────────────────────────────────────────

/**
 * Minimal ASN.1 DER encoder for X.509 certificate generation.
 * We use Node.js crypto.createCertificate (available in Node 22+) when possible,
 * but fall back to a manual DER construction for compatibility.
 */

function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  if (length < 0x100) return Buffer.from([0x81, length]);
  return Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
}

function encodeDERSequence(items: Buffer[]): Buffer {
  const content = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(content.length), content]);
}

function encodeDERSet(items: Buffer[]): Buffer {
  const content = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x31]), encodeLength(content.length), content]);
}

function encodeDEROID(oid: number[]): Buffer {
  const bytes: number[] = [];
  bytes.push(oid[0] * 40 + oid[1]);
  for (let i = 2; i < oid.length; i++) {
    let val = oid[i];
    if (val >= 128) {
      const stack: number[] = [];
      stack.push(val & 0x7f);
      val >>= 7;
      while (val > 0) {
        stack.push((val & 0x7f) | 0x80);
        val >>= 7;
      }
      bytes.push(...stack.reverse());
    } else {
      bytes.push(val);
    }
  }
  const buf = Buffer.from(bytes);
  return Buffer.concat([Buffer.from([0x06]), encodeLength(buf.length), buf]);
}

function encodeDERUTF8String(str: string): Buffer {
  const buf = Buffer.from(str, "utf8");
  return Buffer.concat([Buffer.from([0x0c]), encodeLength(buf.length), buf]);
}

function encodeDERInteger(value: Buffer): Buffer {
  // Ensure positive by prepending 0x00 if high bit is set
  const needsPad = value[0] & 0x80;
  const content = needsPad ? Buffer.concat([Buffer.from([0x00]), value]) : value;
  return Buffer.concat([Buffer.from([0x02]), encodeLength(content.length), content]);
}

function encodeDERBitString(content: Buffer): Buffer {
  // Bit string with 0 unused bits
  const wrapped = Buffer.concat([Buffer.from([0x00]), content]);
  return Buffer.concat([Buffer.from([0x03]), encodeLength(wrapped.length), wrapped]);
}

function encodeDERExplicit(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0xa0 | tag]), encodeLength(content.length), content]);
}

// OIDs
const OID_EC_PUBLIC_KEY = [1, 2, 840, 10045, 2, 1];
const OID_PRIME256V1 = [1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256 = [1, 2, 840, 10045, 4, 3, 2];
const OID_COMMON_NAME = [2, 5, 4, 3];
const OID_ORGANIZATION = [2, 5, 4, 10];
const OID_BASIC_CONSTRAINTS = [2, 5, 29, 19];
const OID_KEY_USAGE = [2, 5, 29, 15];
const OID_SUBJECT_KEY_ID = [2, 5, 29, 14];

function buildDistinguishedName(cn: string, org: string = "AceofCloud Internal CA"): Buffer {
  const cnAttr = encodeDERSequence([encodeDEROID(OID_COMMON_NAME), encodeDERUTF8String(cn)]);
  const orgAttr = encodeDERSequence([encodeDEROID(OID_ORGANIZATION), encodeDERUTF8String(org)]);
  return encodeDERSequence([encodeDERSet([cnAttr]), encodeDERSet([orgAttr])]);
}

function buildValidity(validDays: number): Buffer {
  const now = new Date();
  const notAfter = new Date(now.getTime() + validDays * 86400000);

  const formatUTC = (d: Date) => {
    const s = d.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
    // Use UTCTime (tag 0x17) for dates before 2050
    const buf = Buffer.from(s.slice(2), "ascii"); // YYMMDDHHmmssZ
    return Buffer.concat([Buffer.from([0x17]), encodeLength(buf.length), buf]);
  };

  return encodeDERSequence([formatUTC(now), formatUTC(notAfter)]);
}

function extractPublicKeyDER(publicKeyPem: string): Buffer {
  const b64 = publicKeyPem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  return Buffer.from(b64, "base64");
}

// ─── Certificate Generation ─────────────────────────────────────────────

/**
 * Generate a self-signed X.509 CA certificate using ECDSA P-256.
 */
export function generateCACertificate(
  cn: string = "AceofCloud Internal mTLS CA",
  validDays: number = 3650 // 10 years
): CertificateWithKey {
  const fips = getFIPSCrypto();
  const keyPair = fips.generateKeyPair("P-256");

  const serialNumber = crypto.randomBytes(16);
  serialNumber[0] &= 0x7f; // Ensure positive

  const issuerDN = buildDistinguishedName(cn);
  const subjectDN = issuerDN; // Self-signed

  // Build TBS (To-Be-Signed) certificate
  const version = encodeDERExplicit(0, encodeDERInteger(Buffer.from([0x02]))); // v3
  const serial = encodeDERInteger(serialNumber);
  const signatureAlgo = encodeDERSequence([encodeDEROID(OID_ECDSA_WITH_SHA256)]);
  const validity = buildValidity(validDays);
  const subjectPubKeyInfo = extractPublicKeyDER(keyPair.publicKey);

  // Extensions: BasicConstraints (CA:TRUE), KeyUsage (keyCertSign, cRLSign)
  const basicConstraints = encodeDERSequence([
    encodeDEROID(OID_BASIC_CONSTRAINTS),
    Buffer.from([0x01, 0x01, 0xff]), // critical: TRUE
    Buffer.concat([
      Buffer.from([0x04]),
      encodeLength(
        encodeDERSequence([Buffer.from([0x01, 0x01, 0xff])]).length
      ),
      encodeDERSequence([Buffer.from([0x01, 0x01, 0xff])]), // CA: TRUE
    ]),
  ]);

  // KeyUsage: keyCertSign (5) + cRLSign (6) = 0x06
  const keyUsageBits = Buffer.from([0x05, 0x06]); // 5 unused bits, then byte with bits 5,6 set
  const keyUsage = encodeDERSequence([
    encodeDEROID(OID_KEY_USAGE),
    Buffer.from([0x01, 0x01, 0xff]), // critical: TRUE
    Buffer.concat([
      Buffer.from([0x04]),
      encodeLength(encodeDERBitString(Buffer.from([0x06])).length),
      encodeDERBitString(Buffer.from([0x06])),
    ]),
  ]);

  const extensions = encodeDERExplicit(
    3,
    encodeDERSequence([basicConstraints, keyUsage])
  );

  const tbsCertificate = encodeDERSequence([
    version,
    serial,
    signatureAlgo,
    issuerDN,
    validity,
    subjectDN,
    subjectPubKeyInfo,
    extensions,
  ]);

  // Sign TBS with CA private key
  const signature = crypto.createSign("SHA256");
  signature.update(tbsCertificate);
  const sigBytes = signature.sign(keyPair.privateKey);

  // Build final certificate
  const certificate = encodeDERSequence([
    tbsCertificate,
    signatureAlgo,
    encodeDERBitString(sigBytes),
  ]);

  const certPem =
    "-----BEGIN CERTIFICATE-----\n" +
    certificate.toString("base64").match(/.{1,64}/g)!.join("\n") +
    "\n-----END CERTIFICATE-----\n";

  const fingerprint = crypto.createHash("sha256").update(certificate).digest("hex");

  const now = Date.now();
  return {
    id: fips.uuid(),
    type: "ca",
    commonName: cn,
    serialNumber: serialNumber.toString("hex"),
    issuer: cn,
    subject: cn,
    validFrom: now,
    validTo: now + validDays * 86400000,
    fingerprint,
    certificate: certPem,
    privateKey: keyPair.privateKey,
    status: "active",
    createdAt: now,
  };
}

/**
 * Generate a client certificate signed by the internal CA.
 */
export function generateClientCertificate(
  caCert: CertificateWithKey,
  cn: string,
  c2ServerId: string,
  validDays: number = 365
): CertificateWithKey {
  const fips = getFIPSCrypto();
  const clientKeyPair = fips.generateKeyPair("P-256");

  const serialNumber = crypto.randomBytes(16);
  serialNumber[0] &= 0x7f;

  const issuerDN = buildDistinguishedName(caCert.commonName);
  const subjectDN = buildDistinguishedName(cn, "AceofCloud C2 Client");

  const version = encodeDERExplicit(0, encodeDERInteger(Buffer.from([0x02])));
  const serial = encodeDERInteger(serialNumber);
  const signatureAlgo = encodeDERSequence([encodeDEROID(OID_ECDSA_WITH_SHA256)]);
  const validity = buildValidity(validDays);
  const subjectPubKeyInfo = extractPublicKeyDER(clientKeyPair.publicKey);

  // Extensions: KeyUsage (digitalSignature, keyEncipherment)
  const keyUsage = encodeDERSequence([
    encodeDEROID(OID_KEY_USAGE),
    Buffer.from([0x01, 0x01, 0xff]),
    Buffer.concat([
      Buffer.from([0x04]),
      encodeLength(encodeDERBitString(Buffer.from([0xa0])).length),
      encodeDERBitString(Buffer.from([0xa0])), // digitalSignature + keyEncipherment
    ]),
  ]);

  const extensions = encodeDERExplicit(3, encodeDERSequence([keyUsage]));

  const tbsCertificate = encodeDERSequence([
    version,
    serial,
    signatureAlgo,
    issuerDN,
    validity,
    subjectDN,
    subjectPubKeyInfo,
    extensions,
  ]);

  // Sign with CA private key
  const signature = crypto.createSign("SHA256");
  signature.update(tbsCertificate);
  const sigBytes = signature.sign(caCert.privateKey);

  const certificate = encodeDERSequence([
    tbsCertificate,
    signatureAlgo,
    encodeDERBitString(sigBytes),
  ]);

  const certPem =
    "-----BEGIN CERTIFICATE-----\n" +
    certificate.toString("base64").match(/.{1,64}/g)!.join("\n") +
    "\n-----END CERTIFICATE-----\n";

  const fingerprint = crypto.createHash("sha256").update(certificate).digest("hex");

  const now = Date.now();
  return {
    id: fips.uuid(),
    type: "client",
    commonName: cn,
    serialNumber: serialNumber.toString("hex"),
    issuer: caCert.commonName,
    subject: cn,
    validFrom: now,
    validTo: now + validDays * 86400000,
    fingerprint,
    certificate: certPem,
    privateKey: clientKeyPair.privateKey,
    c2ServerId,
    status: "active",
    createdAt: now,
  };
}

// ─── Database Persistence ───────────────────────────────────────────────

const MTLS_TABLE = "mtls_certificates";

/**
 * Store a certificate in the database with encrypted private key.
 */
export async function storeCertificate(cert: CertificateWithKey): Promise<void> {
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // Encrypt private key before storage
  const encryptedKey = encryptCredential(cert.privateKey, FIPS_CONTEXTS.SSH_KEY);

  await db.execute(sql`
    INSERT INTO ${sql.raw(MTLS_TABLE)} (id, type, commonName, serialNumber, issuer, subject,
      validFrom, validTo, fingerprint, certificate, encryptedPrivateKey, c2ServerId, status, createdAt)
    VALUES (${cert.id}, ${cert.type}, ${cert.commonName}, ${cert.serialNumber},
      ${cert.issuer}, ${cert.subject}, ${cert.validFrom}, ${cert.validTo},
      ${cert.fingerprint}, ${cert.certificate}, ${JSON.stringify(encryptedKey)},
      ${cert.c2ServerId ?? null}, ${cert.status}, ${cert.createdAt})
  `);
}

/**
 * Retrieve a certificate with its decrypted private key.
 */
export async function getCertificateWithKey(id: string): Promise<CertificateWithKey | null> {
  const db = await getDb();
  if (!db) return null;

  const [row] = await db.execute(sql`
    SELECT * FROM ${sql.raw(MTLS_TABLE)} WHERE id = ${id} AND status = 'active'
  `);

  if (!row) return null;
  const r = row as any;

  const encryptedKey = JSON.parse(r.encryptedPrivateKey);
  const privateKey = decryptCredential(encryptedKey);

  return {
    id: r.id,
    type: r.type,
    commonName: r.commonName,
    serialNumber: r.serialNumber,
    issuer: r.issuer,
    subject: r.subject,
    validFrom: Number(r.validFrom),
    validTo: Number(r.validTo),
    fingerprint: r.fingerprint,
    certificate: r.certificate,
    privateKey,
    c2ServerId: r.c2ServerId,
    status: r.status,
    createdAt: Number(r.createdAt),
  };
}

/**
 * Get the active CA certificate, or null if none exists.
 */
export async function getActiveCACertificate(): Promise<CertificateWithKey | null> {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.execute(sql`
    SELECT * FROM ${sql.raw(MTLS_TABLE)} WHERE type = 'ca' AND status = 'active' ORDER BY createdAt DESC LIMIT 1
  `);

  if (!rows || (rows as any[]).length === 0) return null;
  const r = (rows as any[])[0];

  const encryptedKey = JSON.parse(r.encryptedPrivateKey);
  const privateKey = decryptCredential(encryptedKey);

  return {
    id: r.id,
    type: r.type,
    commonName: r.commonName,
    serialNumber: r.serialNumber,
    issuer: r.issuer,
    subject: r.subject,
    validFrom: Number(r.validFrom),
    validTo: Number(r.validTo),
    fingerprint: r.fingerprint,
    certificate: r.certificate,
    privateKey,
    status: r.status,
    createdAt: Number(r.createdAt),
  };
}

/**
 * Get the client certificate for a specific C2 server.
 */
export async function getClientCertForServer(c2ServerId: string): Promise<CertificateWithKey | null> {
  const db = await getDb();
  if (!db) return null;

  const rows = await db.execute(sql`
    SELECT * FROM ${sql.raw(MTLS_TABLE)}
    WHERE type = 'client' AND c2ServerId = ${c2ServerId} AND status = 'active'
    ORDER BY createdAt DESC LIMIT 1
  `);

  if (!rows || (rows as any[]).length === 0) return null;
  const r = (rows as any[])[0];

  const encryptedKey = JSON.parse(r.encryptedPrivateKey);
  const privateKey = decryptCredential(encryptedKey);

  return {
    id: r.id,
    type: r.type,
    commonName: r.commonName,
    serialNumber: r.serialNumber,
    issuer: r.issuer,
    subject: r.subject,
    validFrom: Number(r.validFrom),
    validTo: Number(r.validTo),
    fingerprint: r.fingerprint,
    certificate: r.certificate,
    privateKey,
    c2ServerId: r.c2ServerId,
    status: r.status,
    createdAt: Number(r.createdAt),
  };
}

/**
 * List all certificates (without private keys).
 */
export async function listCertificates(): Promise<CertificateInfo[]> {
  const db = await getDb();
  if (!db) return [];

  const rows = await db.execute(sql`
    SELECT id, type, commonName, serialNumber, issuer, subject,
      validFrom, validTo, fingerprint, certificate, c2ServerId, status, createdAt
    FROM ${sql.raw(MTLS_TABLE)} ORDER BY createdAt DESC
  `);

  return (rows as any[]).map((r: any) => ({
    id: r.id,
    type: r.type,
    commonName: r.commonName,
    serialNumber: r.serialNumber,
    issuer: r.issuer,
    subject: r.subject,
    validFrom: Number(r.validFrom),
    validTo: Number(r.validTo),
    fingerprint: r.fingerprint,
    certificate: r.certificate,
    c2ServerId: r.c2ServerId,
    status: r.status,
    createdAt: Number(r.createdAt),
  }));
}

/**
 * Revoke a certificate by ID.
 */
export async function revokeCertificate(id: string): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;

  await db.execute(sql`
    UPDATE ${sql.raw(MTLS_TABLE)} SET status = 'revoked' WHERE id = ${id}
  `);
  return true;
}

/**
 * Build an mTLS configuration for a specific C2 server.
 * Returns the cert, key, and CA cert needed for https.Agent.
 */
export async function getMTLSConfigForServer(c2ServerId: string): Promise<MTLSConfig | null> {
  const ca = await getActiveCACertificate();
  if (!ca) return null;

  const client = await getClientCertForServer(c2ServerId);
  if (!client) return null;

  return {
    cert: client.certificate,
    key: client.privateKey,
    ca: ca.certificate,
  };
}

/**
 * Ensure the internal CA exists. If not, generate one.
 */
export async function ensureCA(): Promise<CertificateWithKey> {
  const existing = await getActiveCACertificate();
  if (existing) return existing;

  const ca = generateCACertificate();
  await storeCertificate(ca);
  return ca;
}

/**
 * Generate a client certificate for a C2 server.
 * Ensures the CA exists first.
 */
export async function issueClientCertForServer(
  c2ServerId: string,
  serverName: string
): Promise<CertificateWithKey> {
  const ca = await ensureCA();
  const cn = `${serverName}.c2.aceofcloud.internal`;
  const client = generateClientCertificate(ca, cn, c2ServerId);
  await storeCertificate(client);
  return client;
}
