# Ace C3 Platform — Agent Infrastructure & Multi-C2 Architecture

**Author:** Manus AI | **Date:** February 26, 2026 | **Status:** Architecture Specification

---

## Executive Summary

This document specifies the architecture for the Ace C3 platform's adversary simulation agent infrastructure, designed to compete directly with Pentera, Cymulate, and SafeBreach on internal network testing capabilities. The architecture introduces a **unified agent framework** that abstracts communication across multiple Command and Control (C2) platforms — MITRE CALDERA, Sliver, Metasploit Framework, and a custom Ace C3 native protocol — while enforcing **FIPS 140-3 cryptographic compliance** across every communication channel, credential store, and data-at-rest boundary.

The design addresses three critical requirements simultaneously. First, agents must be **lightweight and deployable from within target environments** for internal network penetration testing, matching the deployment simplicity of Pentera's agentless approach while exceeding it with persistent agent capabilities. Second, all cryptographic operations must use **FIPS 140-3 validated modules** (OpenSSL 3.1.2+ FIPS provider, certificate #4282) to satisfy FedRAMP Moderate and CMMC Level 2 requirements. Third, every agent action must produce **immutable audit records** that satisfy NIST 800-53 AU-2, AU-3, and AU-6 controls, enabling the platform to operate in regulated federal environments where competitors cannot.

Throughout all phases of development and migration, the existing **red ADMiN123 super_admin account** remains the permanent break-glass owner with unrestricted platform access.

---

## 1. Competitive Landscape Analysis

Before defining the architecture, it is essential to understand how competitors approach agent deployment, as this directly informs our design decisions.

### 1.1 Competitor Agent Architectures

| Platform | Deployment Model | Agent Type | Internal Testing | C2 Flexibility | FIPS Compliance |
|----------|-----------------|------------|-----------------|----------------|-----------------|
| **Pentera** | Agentless (VM appliance) | No persistent agent; scans from appliance | Yes, from appliance VLAN | Proprietary only | Partial (TLS only) |
| **Cymulate** | Lightweight agent per segment | Single-binary agent + cloud C2 | Yes, agent-based | Proprietary only | Not validated |
| **SafeBreach** | Simulator agents (attacker + target) | Paired simulators | Yes, paired deployment | Proprietary only | SOC 2 only |
| **Ace C3** (proposed) | Multi-mode: agentless scan + persistent agent + C2 relay | Unified agent with C2 adapters | Yes, all modes | CALDERA, Sliver, MSF, Native | FIPS 140-3 Level 1 |

### 1.2 Competitive Advantages

The Ace C3 agent architecture provides three distinct advantages over the competitive field. The **multi-C2 adapter pattern** allows operators to leverage the technique libraries of CALDERA (580+ abilities), Sliver (native post-exploitation), and Metasploit (2,300+ exploits) through a single management interface, rather than being locked into a proprietary technique set. The **FIPS 140-3 validated cryptography** enables deployment in federal environments (DoD, IC, civilian agencies) where Pentera, Cymulate, and SafeBreach cannot operate without waivers. The **hybrid deployment model** combines Pentera's agentless scanning convenience with Cymulate's persistent agent capabilities, giving operators flexibility to choose the right approach for each engagement.

---

## 2. Agent Architecture Overview

### 2.1 High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Ace C3 Platform (Server)                        │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Agent Manager │  │ C2 Adapter   │  │ FIPS Crypto Service      │  │
│  │              │  │ Registry     │  │ (OpenSSL 3.x FIPS)       │  │
│  │ - Lifecycle  │  │              │  │                          │  │
│  │ - Auth       │  │ - CALDERA    │  │ - TLS 1.2/1.3           │  │
│  │ - Tasking    │  │ - Sliver     │  │ - AES-256-GCM            │  │
│  │ - Telemetry  │  │ - MSF        │  │ - ECDSA P-256/P-384     │  │
│  │ - Audit      │  │ - Native     │  │ - SHA-256/384/512        │  │
│  └──────┬───────┘  └──────┬───────┘  │ - HMAC-SHA256            │  │
│         │                 │          │ - HKDF key derivation    │  │
│         │                 │          └──────────┬───────────────┘  │
│         └────────┬────────┘                     │                  │
│                  │                              │                  │
│         ┌────────▼──────────────────────────────▼──────────┐       │
│         │            Agent Communication Gateway            │       │
│         │     (mTLS termination, JWT validation,            │       │
│         │      rate limiting, payload signing)              │       │
│         └──────────────────────┬────────────────────────────┘       │
└────────────────────────────────┼────────────────────────────────────┘
                                 │
                    ┌────────────┼────────────────┐
                    │            │                │
              ┌─────▼─────┐ ┌───▼───────┐ ┌──────▼──────┐
              │  Agent A   │ │  Agent B  │ │  Agent C    │
              │ (CALDERA)  │ │ (Sliver)  │ │ (Native)    │
              │            │ │           │ │             │
              │ Windows    │ │ Linux     │ │ macOS       │
              │ Internal   │ │ DMZ       │ │ Cloud       │
              └────────────┘ └───────────┘ └─────────────┘
```

### 2.2 Core Design Principles

The agent architecture is built on five foundational principles that govern all implementation decisions:

**Principle 1 — Cryptographic Compliance by Default.** Every byte transmitted between an agent and the platform traverses a FIPS 140-3 validated cryptographic boundary. There is no "non-FIPS mode." The OpenSSL 3.x FIPS provider is loaded at process initialization, and all `crypto` module calls are routed through validated algorithms. This is not a configuration option — it is an architectural invariant.

**Principle 2 — C2 Protocol Abstraction.** Agents do not communicate directly with CALDERA, Sliver, or Metasploit servers. Instead, the Ace C3 platform acts as a **C2 relay and translator**, receiving agent telemetry through the unified Agent Communication Gateway and forwarding tasking through the appropriate C2 adapter. This decouples agent deployment from C2 infrastructure and enables technique composition across frameworks.

**Principle 3 — Immutable Audit Trail.** Every agent lifecycle event — registration, tasking, execution, result collection, deregistration — produces a cryptographically signed audit record stored in the platform database. These records satisfy NIST 800-53 AU-2 (Audit Events), AU-3 (Content of Audit Records), and AU-6 (Audit Review, Analysis, and Reporting) controls required for FedRAMP Moderate authorization.

**Principle 4 — Least Privilege Execution.** Agents request only the permissions required for their assigned tasks. Privilege escalation techniques are gated behind explicit authorization from the engagement lead, with approval recorded in the audit trail. This maps to NIST 800-53 AC-6 (Least Privilege) and CMMC 3.1.5 (Least Privilege).

**Principle 5 — Self-Limiting Execution.** Every agent deployment includes a mandatory time-to-live (TTL), a kill switch accessible from the platform, and automatic self-destruction if the agent cannot reach the C2 gateway within a configurable watchdog interval. This ensures agents do not persist beyond their authorized engagement window.

---

## 3. FIPS 140-3 Cryptographic Architecture

### 3.1 Platform-Wide Cryptographic Requirements

FIPS 140-3 compliance is not limited to agent communications — it applies to **every cryptographic operation across the entire Ace C3 platform**. The following table maps each platform component to its required cryptographic algorithms and the FIPS 140-3 validation status.

| Component | Operation | Algorithm | FIPS 140-3 Status | NIST Reference |
|-----------|-----------|-----------|-------------------|----------------|
| **TLS Transport** | All API traffic, agent comms | TLS 1.2 (AES-256-GCM, ECDHE) or TLS 1.3 (AES-256-GCM, X25519) | Validated via OpenSSL 3.1.2 FIPS provider | SP 800-52 Rev 2 |
| **JWT Signing** | Session tokens, agent auth | ECDSA P-256 (ES256) or RSA-2048 (RS256) | Validated | SP 800-186 |
| **Password Hashing** | User authentication | Argon2id with SHA-256 HMAC verification | Argon2id not FIPS-validated; use PBKDF2-HMAC-SHA256 as FIPS fallback | SP 800-132 |
| **Credential Encryption** | Vendor API keys, secrets | AES-256-GCM with HKDF-derived keys | Validated | SP 800-38D, SP 800-108 |
| **Agent Identity** | Agent registration, mTLS | ECDSA P-384 key pairs, X.509 certificates | Validated | SP 800-186 |
| **Payload Signing** | Task integrity verification | ECDSA P-256 with SHA-256 | Validated | SP 800-186 |
| **Data at Rest** | Database field encryption | AES-256-GCM with per-tenant keys | Validated | SP 800-38D |
| **Key Derivation** | Deriving encryption keys | HKDF-SHA256 (RFC 5869) | Validated | SP 800-108 |
| **Random Generation** | Nonces, IVs, session IDs | CTR_DRBG (NIST SP 800-90A) | Validated | SP 800-90A |
| **Integrity Checking** | Audit log tamper detection | HMAC-SHA256 chain | Validated | FIPS 198-1 |

### 3.2 Prohibited Algorithms

The following algorithms are explicitly prohibited across the entire platform. Any code path that invokes these algorithms will fail at the OpenSSL FIPS provider level and will also be flagged by the platform's cryptographic compliance monitor:

| Prohibited Algorithm | Reason | Replacement |
|---------------------|--------|-------------|
| MD5 | Collision attacks demonstrated | SHA-256 |
| SHA-1 (for signatures) | NIST deprecated for digital signatures | SHA-256 or SHA-384 |
| DES / 3DES | Withdrawn by NIST (2023) | AES-256 |
| RC4 | Multiple practical attacks | AES-256-GCM |
| RSA < 2048 bits | Insufficient key length | RSA-2048+ or ECDSA P-256 |
| Blowfish / Twofish | Not FIPS validated | AES-256 |
| ChaCha20-Poly1305 | Not yet FIPS validated (pending) | AES-256-GCM |

### 3.3 Node.js FIPS Provider Configuration

The Ace C3 platform runs on Node.js with OpenSSL 3.x. Enabling the FIPS provider requires configuration at both the OpenSSL level and the Node.js runtime level:

```javascript
// server/lib/fips-crypto.ts — Platform-wide FIPS cryptographic service

import crypto from 'node:crypto';

/**
 * FIPS 140-3 Cryptographic Service
 * 
 * Provides validated cryptographic operations for the entire platform.
 * All operations route through the OpenSSL 3.x FIPS provider when available,
 * with runtime validation that only approved algorithms are in use.
 */

// Approved cipher suites for TLS 1.2 (FIPS mode)
const FIPS_TLS12_CIPHERS = [
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
].join(':');

// TLS 1.3 cipher suites (always FIPS-compliant when using AES-GCM)
const FIPS_TLS13_CIPHERS = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_AES_128_GCM_SHA256',
].join(':');

export class FIPSCryptoService {
  private fipsEnabled: boolean;
  private masterKey: Buffer;

  constructor(masterKeyHex?: string) {
    // Check if OpenSSL FIPS provider is active
    this.fipsEnabled = this.checkFIPSMode();
    
    // Derive master key from environment or generate
    this.masterKey = masterKeyHex 
      ? Buffer.from(masterKeyHex, 'hex')
      : this.generateSecureRandom(32);
  }

  /** Check if Node.js is running with FIPS-validated OpenSSL */
  checkFIPSMode(): boolean {
    try {
      return crypto.getFips() === 1;
    } catch {
      return false;
    }
  }

  /** Get comprehensive FIPS compliance status */
  getComplianceStatus() {
    return {
      fipsProviderActive: this.fipsEnabled,
      opensslVersion: crypto.constants.OPENSSL_VERSION_TEXT ?? 'unknown',
      approvedAlgorithms: {
        symmetric: ['aes-256-gcm', 'aes-128-gcm'],
        hash: ['sha256', 'sha384', 'sha512'],
        mac: ['hmac-sha256', 'hmac-sha384'],
        signature: ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096'],
        kdf: ['hkdf-sha256', 'pbkdf2-sha256'],
        random: ['ctr-drbg'],
      },
      prohibitedAlgorithms: ['md5', 'sha1-sig', 'des', '3des', 'rc4', 'blowfish'],
      tlsCiphers: {
        tls12: FIPS_TLS12_CIPHERS,
        tls13: FIPS_TLS13_CIPHERS,
      },
      timestamp: Date.now(),
    };
  }

  // ─── Symmetric Encryption (AES-256-GCM) ─────────────────────────────

  /** Encrypt data using AES-256-GCM with FIPS-validated module */
  encrypt(plaintext: Buffer | string, context?: string): EncryptedPayload {
    const iv = this.generateSecureRandom(12); // 96-bit IV for GCM
    const key = context 
      ? this.deriveKey(this.masterKey, context)
      : this.masterKey;
    
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: 'aes-256-gcm',
      keyDerivation: context ? 'hkdf-sha256' : 'direct',
    };
  }

  /** Decrypt AES-256-GCM encrypted data */
  decrypt(payload: EncryptedPayload, context?: string): Buffer {
    const key = context
      ? this.deriveKey(this.masterKey, context)
      : this.masterKey;
    
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(payload.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
    
    return Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final(),
    ]);
  }

  // ─── Key Derivation (HKDF-SHA256) ───────────────────────────────────

  /** Derive a key using HKDF (RFC 5869) with SHA-256 */
  deriveKey(ikm: Buffer, info: string, length: number = 32): Buffer {
    return crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, length);
  }

  // ─── Digital Signatures (ECDSA P-256) ───────────────────────────────

  /** Generate an ECDSA P-256 key pair for agent identity */
  generateAgentKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }

  /** Sign data with ECDSA P-256 + SHA-256 */
  sign(data: Buffer | string, privateKeyPem: string): string {
    const signer = crypto.createSign('SHA256');
    signer.update(typeof data === 'string' ? data : data);
    signer.end();
    return signer.sign(privateKeyPem, 'base64');
  }

  /** Verify an ECDSA P-256 + SHA-256 signature */
  verify(data: Buffer | string, signature: string, publicKeyPem: string): boolean {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(typeof data === 'string' ? data : data);
    verifier.end();
    return verifier.verify(publicKeyPem, signature, 'base64');
  }

  // ─── HMAC (SHA-256) ─────────────────────────────────────────────────

  /** Compute HMAC-SHA256 for integrity verification */
  hmac(data: Buffer | string, key?: Buffer): string {
    const hmacKey = key ?? this.masterKey;
    return crypto.createHmac('sha256', hmacKey)
      .update(typeof data === 'string' ? data : data)
      .digest('hex');
  }

  /** Verify HMAC-SHA256 */
  verifyHmac(data: Buffer | string, expectedHmac: string, key?: Buffer): boolean {
    const computed = this.hmac(data, key);
    return crypto.timingSafeEqual(
      Buffer.from(computed, 'hex'),
      Buffer.from(expectedHmac, 'hex')
    );
  }

  // ─── Hashing (SHA-256/384/512) ──────────────────────────────────────

  /** Compute SHA-256 hash */
  hash(data: Buffer | string, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'): string {
    return crypto.createHash(algorithm)
      .update(typeof data === 'string' ? data : data)
      .digest('hex');
  }

  // ─── Password Hashing (PBKDF2-HMAC-SHA256) ─────────────────────────

  /** Hash password using PBKDF2-HMAC-SHA256 (FIPS-validated) */
  hashPassword(password: string): { hash: string; salt: string; iterations: number } {
    const salt = this.generateSecureRandom(32);
    const iterations = 600000; // OWASP 2023 recommendation for PBKDF2-SHA256
    const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha256');
    return {
      hash: hash.toString('base64'),
      salt: salt.toString('base64'),
      iterations,
    };
  }

  /** Verify password against PBKDF2 hash */
  verifyPassword(password: string, storedHash: string, salt: string, iterations: number): boolean {
    const hash = crypto.pbkdf2Sync(
      password,
      Buffer.from(salt, 'base64'),
      iterations,
      64,
      'sha256'
    );
    return crypto.timingSafeEqual(hash, Buffer.from(storedHash, 'base64'));
  }

  // ─── Secure Random Generation ───────────────────────────────────────

  /** Generate cryptographically secure random bytes (CTR_DRBG) */
  generateSecureRandom(bytes: number): Buffer {
    return crypto.randomBytes(bytes);
  }

  /** Generate a secure random UUID v4 */
  generateUUID(): string {
    return crypto.randomUUID();
  }

  // ─── JWT Operations (ECDSA ES256) ───────────────────────────────────

  /** Create a JWT signed with ECDSA P-256 (ES256) */
  createJWT(payload: Record<string, unknown>, privateKeyPem: string, expiresInSeconds: number = 3600): string {
    const header = { alg: 'ES256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };
    
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
    const signingInput = `${headerB64}.${payloadB64}`;
    
    const signature = this.sign(signingInput, privateKeyPem);
    const sigB64 = Buffer.from(signature, 'base64').toString('base64url');
    
    return `${signingInput}.${sigB64}`;
  }

  // ─── Audit Log Integrity Chain ──────────────────────────────────────

  /** Create a chained HMAC for audit log tamper detection */
  chainAuditRecord(record: string, previousHash: string): string {
    return this.hmac(`${previousHash}|${record}`);
  }
}

// ─── Types ────────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: string;
  keyDerivation: string;
}

export interface FIPSComplianceReport {
  fipsProviderActive: boolean;
  opensslVersion: string;
  approvedAlgorithms: Record<string, string[]>;
  prohibitedAlgorithms: string[];
  tlsCiphers: { tls12: string; tls13: string };
  timestamp: number;
}
```

### 3.4 FIPS Compliance Monitoring

The platform includes a real-time FIPS compliance dashboard that monitors all cryptographic operations and flags any non-compliant algorithm usage. This satisfies NIST 800-53 SC-13 (Cryptographic Protection) and provides auditors with continuous evidence of cryptographic compliance.

---

## 4. Multi-C2 Adapter Architecture

### 4.1 C2 Adapter Pattern

The C2 adapter pattern decouples agent management from specific C2 platform implementations. Each adapter translates between the Ace C3 unified agent protocol and the native C2 protocol, enabling operators to leverage technique libraries across frameworks without modifying agents.

```
┌─────────────────────────────────────────────────────────────────┐
│                    C2 Adapter Registry                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ CALDERA      │  │ Sliver       │  │ Metasploit           │  │
│  │ Adapter      │  │ Adapter      │  │ Adapter              │  │
│  │              │  │              │  │                      │  │
│  │ HTTP Beacon  │  │ gRPC Client  │  │ MSFRPC Client        │  │
│  │ /beacon POST │  │ mTLS/HTTP(S) │  │ MessagePack RPC      │  │
│  │              │  │              │  │                      │  │
│  │ Abilities:   │  │ Implant:     │  │ Modules:             │  │
│  │ 580+ TTPs    │  │ Process mgmt │  │ 2,300+ exploits      │  │
│  │ Executors:   │  │ File system  │  │ Meterpreter:         │  │
│  │ psh,sh,cmd   │  │ Network      │  │ Sessions, channels   │  │
│  │ proc,pwsh    │  │ Registry     │  │ Post modules         │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│         └────────┬────────┴──────────────────────┘              │
│                  │                                              │
│         ┌────────▼────────────────────────────────────┐         │
│         │        Unified Agent Protocol (UAP)         │         │
│         │                                             │         │
│         │  register() → AgentIdentity                 │         │
│         │  getTasking() → Task[]                      │         │
│         │  reportResult(taskId, result) → void        │         │
│         │  heartbeat() → HeartbeatResponse             │         │
│         │  downloadPayload(name) → Buffer             │         │
│         │  uploadArtifact(name, data) → void          │         │
│         │  deregister() → void                        │         │
│         └─────────────────────────────────────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 CALDERA Adapter

The CALDERA adapter implements the native CALDERA beacon protocol documented at [caldera.readthedocs.io](https://caldera.readthedocs.io/en/latest/How-to-Build-Agents.html). The adapter translates between the Ace C3 Unified Agent Protocol and CALDERA's HTTP beacon protocol, enabling agents to execute CALDERA abilities (580+ MITRE ATT&CK techniques) through the Ace C3 management interface.

**Registration Flow:** When an agent registers with the Ace C3 platform, the CALDERA adapter creates a corresponding agent profile on the CALDERA server by POSTing to `/beacon` with the agent's platform, executors, hostname, and group assignment. The CALDERA server returns a unique `paw` identifier that the adapter stores alongside the Ace C3 agent ID, maintaining a bidirectional mapping.

**Tasking Flow:** When an operator assigns a CALDERA ability to an agent, the adapter translates the ability into the CALDERA instruction format (link ID, base64-encoded command, executor, timeout, payload references) and queues it for the next agent beacon. The agent receives instructions through the Ace C3 gateway, executes them, and reports results back through the gateway. The adapter then forwards the results to the CALDERA server in the expected format (output, stderr, exit_code, status, pid).

**Key Protocol Details:**

| Field | Description | Example |
|-------|-------------|---------|
| `paw` | Unique agent identifier assigned by CALDERA | `dcoify` |
| `platform` | Operating system | `windows`, `linux`, `darwin` |
| `executors` | Available command executors | `["psh", "cmd", "sh"]` |
| `group` | Red or blue team assignment | `red` |
| `instructions` | Base64-encoded commands from server | Array of link objects |
| `results` | Execution output sent back to server | `{id, output, stderr, exit_code, status, pid}` |
| `sleep` | Beacon interval in seconds | `59` |
| `watchdog` | Self-destruct timeout (0 = infinite) | `0` |

### 4.3 Sliver Adapter

The Sliver adapter integrates with BishopFox's Sliver C2 framework through its gRPC operator API. Sliver provides native post-exploitation capabilities with per-binary asymmetric encryption, making it particularly valuable for engagements requiring stealth and evasion.

**Integration Approach:** Rather than deploying Sliver implants directly, the Ace C3 platform connects to a Sliver server instance as an **external operator** via the gRPC API. This allows the platform to generate implants, manage sessions/beacons, and execute commands through the Sliver infrastructure while maintaining centralized management and audit logging.

**Supported Transport Protocols:**

| Protocol | Use Case | FIPS Compliance |
|----------|----------|-----------------|
| mTLS | Primary encrypted channel | Compliant with FIPS TLS cipher suites |
| HTTP(S) | Firewall traversal, proxy support | Compliant when using AES-GCM cipher suites |
| WireGuard | Tunnel for pivoting | Requires FIPS-approved cipher replacement |
| DNS | Covert channel, last resort | Payload encryption via AES-256-GCM overlay |

**Key Capabilities:** Process management (list, kill, migrate), file system operations (upload, download, list), network operations (port forwarding, SOCKS proxy, pivoting), registry manipulation (Windows), screenshot capture, and keylogging.

### 4.4 Metasploit Adapter

The Metasploit adapter connects to Metasploit Framework instances through the MSFRPC (MessagePack RPC) interface, providing access to the world's largest collection of public exploits (2,300+), auxiliary modules, and post-exploitation capabilities through Meterpreter sessions.

**Integration Approach:** The adapter authenticates to the Metasploit RPC service using token-based authentication, then manages exploit execution, session handling, and post-exploitation through the RPC API. This enables operators to chain Metasploit exploits with CALDERA techniques and Sliver post-exploitation in a single engagement.

**Key RPC Methods:**

| Method | Purpose | Category |
|--------|---------|----------|
| `auth.login` | Authenticate to MSFRPC | Authentication |
| `module.execute` | Run exploit/auxiliary/post module | Execution |
| `session.list` | List active Meterpreter sessions | Session Mgmt |
| `session.meterpreter_write` | Send command to Meterpreter | Interaction |
| `session.meterpreter_read` | Read Meterpreter output | Interaction |
| `session.stop` | Terminate a session | Cleanup |
| `module.exploits` | List available exploit modules | Discovery |
| `module.info` | Get module metadata | Discovery |

### 4.5 Native Ace C3 Protocol

For environments where deploying CALDERA, Sliver, or Metasploit infrastructure is impractical or prohibited, the Ace C3 platform includes a native lightweight agent protocol. This protocol is designed from the ground up for FIPS 140-3 compliance and minimal footprint.

**Protocol Specification:**

The native protocol uses HTTPS with mutual TLS (mTLS) authentication. Each agent possesses an ECDSA P-384 key pair provisioned during deployment, and the platform's Agent Communication Gateway validates the agent's certificate against the platform's internal CA before processing any request.

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `/api/agent/register` | POST | Agent registration with platform | mTLS + registration token |
| `/api/agent/heartbeat` | POST | Keepalive with system info | mTLS + agent JWT |
| `/api/agent/tasking` | GET | Retrieve pending tasks | mTLS + agent JWT |
| `/api/agent/result` | POST | Submit task execution results | mTLS + agent JWT |
| `/api/agent/artifact` | POST | Upload collected artifacts | mTLS + agent JWT |
| `/api/agent/payload` | GET | Download task payloads | mTLS + agent JWT |
| `/api/agent/deregister` | POST | Graceful agent shutdown | mTLS + agent JWT |

---

## 5. Agent Lifecycle Management

### 5.1 Deployment Authorization Workflow

Agent deployment follows a controlled authorization workflow that satisfies NIST 800-53 CA-7 (Continuous Monitoring) and SI-4 (System Monitoring) controls. No agent can be deployed without explicit approval from an authorized role.

```
Operator Request → Engagement Lead Approval → ROE Verification →
  Platform Generates Agent Package → Operator Deploys →
    Agent Registers → Platform Validates → Agent Active
```

**Step 1 — Deployment Request:** A `red_team_operator` or `engagement_lead` creates an agent deployment request specifying the target environment, C2 protocol, operating system, TTL, and authorized techniques.

**Step 2 — Approval Gate:** The `engagement_lead` (or `org_admin` for the organization) reviews and approves the deployment request. The approval is recorded in the audit log with the approver's identity, timestamp, and justification.

**Step 3 — ROE Verification:** The platform automatically verifies that the requested agent capabilities fall within the Rules of Engagement (ROE) defined for the active engagement. Any technique outside the ROE scope is flagged and requires explicit override.

**Step 4 — Agent Package Generation:** The platform generates a deployment package containing the agent binary (or script), a one-time registration token (ECDSA-signed, time-limited), and the platform's CA certificate for mTLS establishment.

**Step 5 — Registration:** Upon execution, the agent presents its registration token to the Agent Communication Gateway. The gateway validates the token signature, checks expiration, and provisions the agent with a unique identity (agent ID, JWT, mTLS certificate).

**Step 6 — Active Operation:** The agent enters its beacon loop, periodically checking for tasking, executing assigned techniques, and reporting results. All activity is logged.

### 5.2 Agent States

| State | Description | Transitions |
|-------|-------------|-------------|
| `pending_approval` | Deployment requested, awaiting authorization | → `approved` or `rejected` |
| `approved` | Authorized for deployment, package generated | → `deploying` |
| `deploying` | Package delivered, awaiting registration | → `active` or `failed` |
| `active` | Registered and beaconing normally | → `paused`, `completed`, `lost` |
| `paused` | Temporarily suspended by operator | → `active`, `completed` |
| `lost` | Missed heartbeat beyond watchdog threshold | → `active` (if reconnects), `terminated` |
| `completed` | Engagement finished, graceful deregistration | Terminal state |
| `terminated` | Force-killed by operator or TTL expiry | Terminal state |
| `failed` | Registration failed or deployment error | → `approved` (retry) |

### 5.3 Self-Destruct Mechanisms

Every agent includes three independent self-destruct mechanisms to prevent unauthorized persistence:

**TTL Expiry:** Each agent has a maximum lifetime set during deployment. When the TTL expires, the agent executes its cleanup routine (remove artifacts, clear logs, delete binary) and terminates. The TTL cannot be extended without a new deployment authorization.

**Watchdog Timer:** If the agent cannot reach the platform's Agent Communication Gateway for a configurable period (default: 4 hours), the watchdog triggers self-destruction. This prevents orphaned agents from persisting if network connectivity is lost.

**Remote Kill Switch:** The platform can issue an immediate termination command to any active agent. The kill command is signed with the platform's ECDSA key and verified by the agent before execution, preventing spoofed kill commands.

---

## 6. FedRAMP and CMMC Control Mapping

### 6.1 FedRAMP Moderate Controls

The following table maps the agent infrastructure to specific FedRAMP Moderate (NIST 800-53 Rev 5) controls:

| Control ID | Control Name | Implementation |
|-----------|-------------|----------------|
| **AC-2** | Account Management | Agent identities managed through platform; automated provisioning/deprovisioning |
| **AC-3** | Access Enforcement | C2 adapter authorization gates; technique-level ROE enforcement |
| **AC-6** | Least Privilege | Agents request only required permissions; privilege escalation requires approval |
| **AU-2** | Audit Events | All agent lifecycle events logged: register, task, execute, result, deregister |
| **AU-3** | Content of Audit Records | Records include: who (agent ID + operator), what (technique), when (timestamp), where (target), outcome (success/fail) |
| **AU-6** | Audit Review | Automated anomaly detection on agent behavior; dashboard for manual review |
| **CA-7** | Continuous Monitoring | Real-time agent health monitoring; automated compliance checks |
| **IA-2** | Identification & Authentication | mTLS for agent identity; JWT for session auth; ECDSA key pairs |
| **IA-5** | Authenticator Management | Agent credentials rotated per engagement; registration tokens are one-time use |
| **SC-8** | Transmission Confidentiality | All agent comms over TLS 1.2/1.3 with FIPS cipher suites |
| **SC-12** | Cryptographic Key Management | HKDF key derivation; per-agent key pairs; platform CA for mTLS |
| **SC-13** | Cryptographic Protection | OpenSSL 3.x FIPS provider for all crypto operations |
| **SC-28** | Protection of Information at Rest | AES-256-GCM encryption for stored credentials, results, artifacts |
| **SI-4** | System Monitoring | Agent telemetry feeds into platform monitoring; anomaly detection |
| **SI-7** | Software Integrity | Agent payloads signed with ECDSA; integrity verified before execution |

### 6.2 CMMC Level 2 Control Mapping

| CMMC Practice | NIST 800-171 Reference | Implementation |
|---------------|----------------------|----------------|
| **AC.L2-3.1.1** | Limit system access | Agent deployment requires authorization; technique scope limited by ROE |
| **AC.L2-3.1.2** | Limit transaction types | C2 adapter enforces allowed technique categories per agent |
| **AC.L2-3.1.5** | Least privilege | Agents operate with minimum required permissions |
| **AU.L2-3.3.1** | System-level auditing | All agent actions produce audit records |
| **AU.L2-3.3.2** | User accountability | Agent actions traceable to deploying operator |
| **IA.L2-3.5.1** | Identify system users | Agent identity via mTLS certificates |
| **IA.L2-3.5.2** | Authenticate users | Multi-factor: mTLS + JWT + registration token |
| **SC.L2-3.13.1** | Boundary protection | Agent Communication Gateway as controlled boundary |
| **SC.L2-3.13.8** | CUI in transit | TLS 1.2/1.3 with FIPS cipher suites |
| **SC.L2-3.13.11** | CUI encryption | AES-256-GCM for all sensitive data |
| **SI.L2-3.14.1** | Flaw remediation | Agent update mechanism with signed packages |
| **SI.L2-3.14.2** | Malicious code protection | Payload signing prevents tampering |

---

## 7. Database Schema for Agent Management

The following schema additions support the agent infrastructure. These tables integrate with the existing Drizzle ORM schema:

```sql
-- Agent deployments (lifecycle tracking)
CREATE TABLE agent_deployments (
  id VARCHAR(36) PRIMARY KEY,
  engagement_id INT,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  target_platform ENUM('windows', 'linux', 'darwin') NOT NULL,
  c2_protocol ENUM('caldera', 'sliver', 'metasploit', 'native') NOT NULL,
  status ENUM('pending_approval', 'approved', 'deploying', 'active', 'paused',
              'lost', 'completed', 'terminated', 'failed') DEFAULT 'pending_approval',
  -- Crypto identity
  public_key TEXT,
  certificate TEXT,
  registration_token TEXT,
  -- Lifecycle
  ttl_seconds INT NOT NULL DEFAULT 86400,
  watchdog_seconds INT NOT NULL DEFAULT 14400,
  beacon_interval_seconds INT NOT NULL DEFAULT 60,
  -- C2-specific identifiers
  caldera_paw VARCHAR(64),
  sliver_implant_id VARCHAR(64),
  msf_session_id VARCHAR(64),
  -- Target info
  target_hostname VARCHAR(255),
  target_ip VARCHAR(45),
  target_network VARCHAR(255),
  -- Authorization
  requested_by INT NOT NULL,
  approved_by INT,
  approved_at BIGINT,
  -- Timestamps
  deployed_at BIGINT,
  last_heartbeat BIGINT,
  terminated_at BIGINT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

-- Agent tasks (individual technique executions)
CREATE TABLE agent_tasks (
  id VARCHAR(36) PRIMARY KEY,
  agent_id VARCHAR(36) NOT NULL REFERENCES agent_deployments(id),
  -- Task definition
  technique_id VARCHAR(32),
  technique_name VARCHAR(255),
  c2_source ENUM('caldera', 'sliver', 'metasploit', 'native') NOT NULL,
  command_encrypted TEXT,
  executor VARCHAR(32),
  timeout_seconds INT DEFAULT 300,
  -- Execution
  status ENUM('queued', 'sent', 'executing', 'completed', 'failed', 'timeout') DEFAULT 'queued',
  output_encrypted TEXT,
  stderr_encrypted TEXT,
  exit_code INT,
  pid INT,
  -- Timing
  queued_at BIGINT NOT NULL,
  sent_at BIGINT,
  started_at BIGINT,
  completed_at BIGINT,
  -- Audit
  assigned_by INT NOT NULL,
  roe_verified BOOLEAN DEFAULT FALSE
);

-- Agent audit log (immutable, HMAC-chained)
CREATE TABLE agent_audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  agent_id VARCHAR(36) NOT NULL,
  event_type ENUM('register', 'heartbeat', 'task_assigned', 'task_sent',
                  'task_completed', 'task_failed', 'artifact_uploaded',
                  'payload_downloaded', 'paused', 'resumed', 'terminated',
                  'lost', 'reconnected', 'deregistered') NOT NULL,
  actor_id INT,
  actor_type ENUM('operator', 'system', 'agent') NOT NULL,
  details JSON,
  -- Integrity chain
  record_hash VARCHAR(64) NOT NULL,
  previous_hash VARCHAR(64) NOT NULL,
  -- Metadata
  ip_address VARCHAR(45),
  user_agent VARCHAR(512),
  created_at BIGINT NOT NULL
);

-- C2 server configurations
CREATE TABLE c2_servers (
  id VARCHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type ENUM('caldera', 'sliver', 'metasploit') NOT NULL,
  base_url VARCHAR(512) NOT NULL,
  -- Auth (encrypted)
  auth_config_encrypted TEXT NOT NULL,
  -- Status
  status ENUM('connected', 'disconnected', 'error') DEFAULT 'disconnected',
  last_health_check BIGINT,
  health_details JSON,
  -- Metadata
  version VARCHAR(64),
  capabilities JSON,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);
```

---

## 8. Implementation Roadmap

### 8.1 Phase Schedule

| Phase | Duration | Deliverables | Dependencies |
|-------|----------|-------------|-------------|
| **Phase 1: FIPS Crypto Service** | Week 1 | `FIPSCryptoService` class, compliance dashboard endpoint, unit tests | OpenSSL 3.x |
| **Phase 2: Agent DB Schema** | Week 1 | Drizzle schema, migrations, query helpers | Phase 1 |
| **Phase 3: C2 Adapters** | Weeks 2-3 | CALDERA, Sliver, MSF adapters with unit tests | Phase 2 |
| **Phase 4: Agent Gateway** | Week 3 | mTLS termination, JWT validation, rate limiting | Phase 1, 2 |
| **Phase 5: Agent Manager** | Week 4 | Lifecycle management, approval workflow, audit logging | Phase 2, 3, 4 |
| **Phase 6: Agent UI** | Weeks 4-5 | Deployment wizard, monitoring dashboard, task viewer | Phase 5 |
| **Phase 7: Native Agent** | Weeks 5-6 | Cross-platform agent binary (Go), FIPS crypto, beacon loop | Phase 4 |
| **Phase 8: Integration Testing** | Week 7 | End-to-end tests with CALDERA, Sliver, MSF instances | Phase 3, 5, 7 |
| **Phase 9: Compliance Audit** | Week 8 | FedRAMP SSP sections, CMMC evidence packages | All phases |

### 8.2 Immediate Implementation (This Sprint)

The following components will be implemented immediately as part of the current development sprint:

1. **FIPS 140-3 Cryptographic Service** (`server/lib/fips-crypto.ts`) — Platform-wide cryptographic operations with compliance monitoring
2. **Agent Database Schema** — Drizzle schema additions for `agent_deployments`, `agent_tasks`, `agent_audit_log`, `c2_servers`
3. **Agent Management tRPC Router** — CRUD operations, lifecycle management, approval workflow
4. **Agent Management UI** — Dashboard showing agent status, deployment wizard, task viewer
5. **FIPS Compliance Dashboard** — Real-time view of cryptographic compliance status

---

## 9. Security Considerations

### 9.1 Threat Model

The agent infrastructure faces several unique threats that are addressed by the architecture:

**Threat 1 — Agent Compromise.** If an adversary captures a deployed agent binary, they gain access to the agent's private key and registration token. Mitigation: registration tokens are one-time use and time-limited; agent private keys are unique per deployment and cannot be used to impersonate other agents or access the platform directly.

**Threat 2 — C2 Channel Interception.** An adversary monitoring network traffic could attempt to intercept or modify agent communications. Mitigation: all communications use TLS 1.2/1.3 with FIPS-approved cipher suites and mutual TLS authentication, making interception computationally infeasible.

**Threat 3 — Rogue Agent Deployment.** An unauthorized user could attempt to deploy agents outside the approved engagement scope. Mitigation: the multi-step authorization workflow requires engagement lead approval, ROE verification, and signed deployment packages.

**Threat 4 — Agent Persistence Beyond Engagement.** Agents could persist on target systems after an engagement concludes. Mitigation: TTL expiry, watchdog timers, and remote kill switches provide three independent self-destruct mechanisms.

**Threat 5 — Audit Log Tampering.** An adversary with database access could modify audit records to cover their tracks. Mitigation: HMAC-SHA256 chain integrity ensures any modification to historical records is detectable.

### 9.2 Break-Glass Access

The **red ADMiN123 super_admin account** retains unrestricted access to all agent management functions, including the ability to override approval workflows, force-terminate any agent, and access all audit logs. This break-glass capability is essential during the development and migration phases and will be preserved throughout the AWS deployment transition.

---

## 10. References

- [1] NIST FIPS 140-3, "Security Requirements for Cryptographic Modules," https://csrc.nist.gov/pubs/fips/140-3/final
- [2] NIST SP 800-53 Rev 5, "Security and Privacy Controls for Information Systems," https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- [3] NIST SP 800-171 Rev 2, "Protecting Controlled Unclassified Information," https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final
- [4] MITRE CALDERA, "How to Build Agents," https://caldera.readthedocs.io/en/latest/How-to-Build-Agents.html
- [5] BishopFox Sliver C2, "External Builders," https://github.com/BishopFox/sliver/wiki/External-Builders
- [6] Rapid7 Metasploit, "RPC API Documentation," https://docs.rapid7.com/metasploit/rpc-api/
- [7] OpenSSL 3.1.2 FIPS 140-3 Validation, https://openssl-library.org/post/2025-03-11-fips-140-3/
- [8] NIST SP 800-52 Rev 2, "Guidelines for TLS Implementations," https://csrc.nist.gov/pubs/sp/800/52/r2/final
- [9] NIST SP 800-132, "Recommendation for Password-Based Key Derivation," https://csrc.nist.gov/pubs/sp/800/132/final
- [10] CMMC Model Overview, https://dodcio.defense.gov/CMMC/
