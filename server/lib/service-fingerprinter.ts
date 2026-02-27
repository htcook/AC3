/**
 * Service Fingerprinting Engine — Protocol-specific probes for administrative
 * and network services discovered on in-scope assets.
 *
 * Architecture:
 *   Nmap port scan → service-fingerprinter → enriched service metadata → SSIL pipeline
 *
 * Each protocol probe uses Node.js built-in `net` / `tls` / `dgram` modules
 * to connect to the target, send protocol-specific handshakes, and parse the
 * response to extract version info, capabilities, security configuration, and
 * potential weaknesses.
 *
 * All probes respect the ROE scope guard — targets are validated before any
 * connection is made.
 *
 * Supported protocols:
 *   - SSH (banner, key exchange, algorithms, HASSH)
 *   - SMTP (banner, EHLO, STARTTLS, auth methods, open relay)
 *   - FTP (banner, anonymous login, TLS, directory listing)
 *   - SNMP (v1/v2c community string, sysDescr, v3 detection)
 *   - RDP (NLA, encryption level, certificate)
 *   - SMB (version, signing, null session, shares)
 *   - LDAP (anonymous bind, base DN, TLS)
 *   - Telnet (banner, authentication type)
 *   - MySQL (banner, version, auth plugin, TLS)
 *   - MSSQL (banner, version, encryption)
 *   - PostgreSQL (version, auth method, TLS)
 *   - Redis (INFO, auth required, version)
 *   - MongoDB (isMaster, version, auth)
 *   - VNC (version, auth type, encryption)
 */

import * as net from "net";
import * as tls from "tls";
import * as dgram from "dgram";
import * as crypto from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ServiceProtocol =
  | "ssh" | "smtp" | "ftp" | "snmp" | "rdp" | "smb" | "ldap" | "telnet"
  | "mysql" | "mssql" | "postgresql" | "redis" | "mongodb" | "vnc"
  | "sftp" | "pop3" | "imap" | "dns" | "ntp" | "sip";

export interface FingerprintResult {
  protocol: ServiceProtocol;
  host: string;
  port: number;
  banner: string | null;
  version: string | null;
  product: string | null;
  os: string | null;
  capabilities: Record<string, boolean>;
  securityFlags: SecurityFlags;
  metadata: Record<string, any>;
  rawResponse: string | null;
  durationMs: number;
  error: string | null;
  /** MITRE ATT&CK techniques relevant to discovered weaknesses */
  mitreRelevance: string[];
  /** CVEs potentially relevant based on version fingerprint */
  potentialCves: string[];
  /** Risk indicators discovered during fingerprinting */
  riskIndicators: RiskIndicator[];
}

export interface SecurityFlags {
  tlsSupported: boolean;
  tlsRequired: boolean;
  tlsVersion: string | null;
  authRequired: boolean;
  anonymousAccess: boolean;
  weakCredentials: boolean;
  defaultCredentials: boolean;
  encryptionEnabled: boolean;
  signingEnabled: boolean;
}

export interface RiskIndicator {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  cweId?: string;
  mitreId?: string;
}

export interface FingerprintConfig {
  host: string;
  port: number;
  protocol?: ServiceProtocol;
  timeoutMs?: number;
  /** Engagement ID for ROE scope validation */
  engagementId?: number;
  /** Operator ID for audit logging */
  operatorId?: string;
  /** Try default/common credentials (only if ROE permits) */
  tryDefaultCreds?: boolean;
}

export interface BatchFingerprintConfig {
  targets: Array<{ host: string; port: number; protocol?: ServiceProtocol }>;
  engagementId?: number;
  operatorId?: string;
  timeoutMs?: number;
  concurrency?: number;
  tryDefaultCreds?: boolean;
}

// ─── Port-to-Protocol Mapping ───────────────────────────────────────────────

export const PORT_PROTOCOL_MAP: Record<number, ServiceProtocol> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  110: "pop3",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "smtp", // could be HTTPS, but handled elsewhere
  445: "smb",
  465: "smtp",
  587: "smtp",
  636: "ldap",
  993: "imap",
  995: "pop3",
  1433: "mssql",
  1521: "postgresql", // Oracle, but similar probe
  2049: "ntp",
  3306: "mysql",
  3389: "rdp",
  5432: "postgresql",
  5900: "vnc",
  5901: "vnc",
  5902: "vnc",
  6379: "redis",
  6380: "redis",
  27017: "mongodb",
  27018: "mongodb",
  27019: "mongodb",
};

/** Detect protocol from port number if not explicitly specified */
export function detectProtocol(port: number): ServiceProtocol | null {
  return PORT_PROTOCOL_MAP[port] ?? null;
}

// ─── TCP Connection Helper ──────────────────────────────────────────────────

function tcpConnect(host: string, port: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`Connection timeout after ${timeoutMs}ms`));
    });
    socket.on("error", (err) => reject(err));
    socket.connect(port, host, () => resolve(socket));
  });
}

function tlsConnect(host: string, port: number, timeoutMs: number): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, rejectUnauthorized: false, timeout: timeoutMs },
      () => resolve(socket),
    );
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`TLS connection timeout after ${timeoutMs}ms`));
    });
    socket.on("error", (err) => reject(err));
  });
}

function readBanner(socket: net.Socket, timeoutMs: number = 5000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      resolve(Buffer.alloc(0));
    }, timeoutMs);
    const chunks: Buffer[] = [];
    socket.on("data", (data) => {
      chunks.push(data);
      // Most banners arrive in the first packet
      clearTimeout(timer);
      setTimeout(() => resolve(Buffer.concat(chunks)), 200);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.on("end", () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks));
    });
  });
}

function sendAndReceive(
  socket: net.Socket,
  data: Buffer | string,
  timeoutMs: number = 5000,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(Buffer.alloc(0)), timeoutMs);
    const chunks: Buffer[] = [];
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      clearTimeout(timer);
      setTimeout(() => {
        socket.removeListener("data", onData);
        resolve(Buffer.concat(chunks));
      }, 300);
    };
    socket.on("data", onData);
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.write(data);
  });
}

// ─── Default Security Flags ─────────────────────────────────────────────────

function defaultSecurityFlags(): SecurityFlags {
  return {
    tlsSupported: false,
    tlsRequired: false,
    tlsVersion: null,
    authRequired: true,
    anonymousAccess: false,
    weakCredentials: false,
    defaultCredentials: false,
    encryptionEnabled: false,
    signingEnabled: false,
  };
}

function defaultResult(protocol: ServiceProtocol, host: string, port: number): FingerprintResult {
  return {
    protocol,
    host,
    port,
    banner: null,
    version: null,
    product: null,
    os: null,
    capabilities: {},
    securityFlags: defaultSecurityFlags(),
    metadata: {},
    rawResponse: null,
    durationMs: 0,
    error: null,
    mitreRelevance: [],
    potentialCves: [],
    riskIndicators: [],
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Protocol-Specific Probes
// ═══════════════════════════════════════════════════════════════════════════════

// ─── SSH Fingerprinting ─────────────────────────────────────────────────────

export async function fingerprintSSH(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port, timeoutMs = 10000 } = config;
  const result = defaultResult("ssh", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Read SSH banner
      const bannerBuf = await readBanner(socket, 5000);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;

      // Parse SSH version string: SSH-protoversion-softwareversion SP comments
      const sshMatch = banner.match(/^SSH-(\d+\.\d+)-(\S+)(?:\s+(.*))?/);
      if (sshMatch) {
        result.metadata.sshProtocolVersion = sshMatch[1];
        result.metadata.softwareVersion = sshMatch[2];
        if (sshMatch[3]) result.metadata.comments = sshMatch[3];

        // Extract product and version
        const swParts = sshMatch[2].match(/^(\w+)[_-]?([\d.]+\w*)?/);
        if (swParts) {
          result.product = swParts[1]; // e.g., "OpenSSH"
          result.version = swParts[2] || null; // e.g., "8.9p1"
        }

        // Detect OS from banner
        if (/ubuntu/i.test(banner)) result.os = "Ubuntu Linux";
        else if (/debian/i.test(banner)) result.os = "Debian Linux";
        else if (/centos|rhel|red\s*hat/i.test(banner)) result.os = "RHEL/CentOS";
        else if (/freebsd/i.test(banner)) result.os = "FreeBSD";
        else if (/windows/i.test(banner)) result.os = "Windows";
      }

      // Send our SSH version to trigger key exchange
      const clientIdent = "SSH-2.0-CalderaProbe_1.0\r\n";
      socket.write(clientIdent);

      // Read key exchange init (SSH_MSG_KEXINIT = 20)
      const kexBuf = await readBanner(socket, 5000);
      if (kexBuf.length > 17) {
        // Parse KEXINIT packet
        try {
          // Skip packet length (4) + padding length (1) + message type (1) + cookie (16)
          let offset = 0;
          // Find the KEXINIT message type (byte 20)
          for (let i = 0; i < Math.min(kexBuf.length - 1, 100); i++) {
            if (kexBuf[i] === 20) { // SSH_MSG_KEXINIT
              offset = i + 1; // skip message type
              break;
            }
          }
          if (offset > 0) {
            offset += 16; // skip cookie
            const readNameList = (buf: Buffer, off: number): { names: string[]; newOffset: number } => {
              if (off + 4 > buf.length) return { names: [], newOffset: off };
              const len = buf.readUInt32BE(off);
              off += 4;
              if (off + len > buf.length) return { names: [], newOffset: off };
              const names = buf.subarray(off, off + len).toString("utf-8").split(",");
              return { names, newOffset: off + len };
            };

            const kexAlgos = readNameList(kexBuf, offset);
            result.metadata.kexAlgorithms = kexAlgos.names;
            offset = kexAlgos.newOffset;

            const hostKeyAlgos = readNameList(kexBuf, offset);
            result.metadata.hostKeyAlgorithms = hostKeyAlgos.names;
            offset = hostKeyAlgos.newOffset;

            const encClientToServer = readNameList(kexBuf, offset);
            result.metadata.encryptionAlgorithms = encClientToServer.names;
            offset = encClientToServer.newOffset;

            const encServerToClient = readNameList(kexBuf, offset);
            offset = encServerToClient.newOffset;

            const macClientToServer = readNameList(kexBuf, offset);
            result.metadata.macAlgorithms = macClientToServer.names;
            offset = macClientToServer.newOffset;

            const macServerToClient = readNameList(kexBuf, offset);
            offset = macServerToClient.newOffset;

            const compClientToServer = readNameList(kexBuf, offset);
            result.metadata.compressionAlgorithms = compClientToServer.names;

            // Compute HASSH fingerprint (MD5 of kex;enc_c2s;mac_c2s;comp_c2s)
            const hasshInput = [
              kexAlgos.names.join(","),
              encClientToServer.names.join(","),
              macClientToServer.names.join(","),
              compClientToServer.names.join(","),
            ].join(";");
            result.metadata.hasshServer = crypto.createHash("md5").update(hasshInput).digest("hex");

            // Security analysis
            result.securityFlags.encryptionEnabled = true;
            result.capabilities.kexInit = true;

            // Check for weak algorithms
            const weakKex = kexAlgos.names.filter(a =>
              /diffie-hellman-group1|diffie-hellman-group-exchange-sha1/i.test(a));
            const weakEnc = encClientToServer.names.filter(a =>
              /arcfour|blowfish|3des|cast128|des-cbc/i.test(a));
            const weakMac = macClientToServer.names.filter(a =>
              /hmac-md5|hmac-sha1-96|hmac-md5-96|umac-64/i.test(a));

            if (weakKex.length > 0) {
              result.metadata.weakKexAlgorithms = weakKex;
              result.riskIndicators.push({
                severity: "medium",
                title: "Weak SSH Key Exchange Algorithms",
                description: `Server supports weak KEX: ${weakKex.join(", ")}`,
                cweId: "CWE-327",
                mitreId: "T1557",
              });
            }
            if (weakEnc.length > 0) {
              result.metadata.weakEncryptionAlgorithms = weakEnc;
              result.riskIndicators.push({
                severity: "high",
                title: "Weak SSH Encryption Ciphers",
                description: `Server supports weak ciphers: ${weakEnc.join(", ")}`,
                cweId: "CWE-327",
                mitreId: "T1040",
              });
            }
            if (weakMac.length > 0) {
              result.metadata.weakMacAlgorithms = weakMac;
              result.riskIndicators.push({
                severity: "low",
                title: "Weak SSH MAC Algorithms",
                description: `Server supports weak MACs: ${weakMac.join(", ")}`,
                cweId: "CWE-328",
              });
            }
          }
        } catch {
          // KEXINIT parsing failed — not critical
          result.metadata.kexParseError = true;
        }
      }

      // Check for known vulnerable versions
      if (result.product === "OpenSSH" && result.version) {
        const ver = result.version.replace(/p\d+$/, "");
        const vNum = parseFloat(ver);
        if (vNum < 7.0) {
          result.potentialCves.push("CVE-2016-0777", "CVE-2016-0778");
          result.riskIndicators.push({
            severity: "critical",
            title: "Severely Outdated OpenSSH",
            description: `OpenSSH ${result.version} is critically outdated and vulnerable to multiple CVEs`,
            cweId: "CWE-1104",
          });
        } else if (vNum < 8.0) {
          result.potentialCves.push("CVE-2019-6111", "CVE-2019-6109");
        } else if (vNum >= 9.1 && vNum < 9.8) {
          result.potentialCves.push("CVE-2024-6387"); // regreSSHion
          result.riskIndicators.push({
            severity: "critical",
            title: "Potential regreSSHion (CVE-2024-6387)",
            description: `OpenSSH ${result.version} may be vulnerable to regreSSHion RCE`,
            cweId: "CWE-362",
            mitreId: "T1210",
          });
        }
      }

      result.mitreRelevance.push("T1021.004"); // Remote Services: SSH
      result.capabilities.ssh = true;
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── SMTP Fingerprinting ────────────────────────────────────────────────────

export async function fingerprintSMTP(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port, timeoutMs = 15000, tryDefaultCreds = false } = config;
  const result = defaultResult("smtp", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Read SMTP banner
      const bannerBuf = await readBanner(socket, 5000);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;

      // Parse banner: 220 hostname ESMTP product version
      const bannerMatch = banner.match(/^220\s+(\S+)\s+(?:E?SMTP\s+)?(\S+)(?:\s+(.*))?/i);
      if (bannerMatch) {
        result.metadata.hostname = bannerMatch[1];
        result.product = bannerMatch[2];
        const verMatch = (bannerMatch[3] || bannerMatch[2]).match(/([\d.]+)/);
        if (verMatch) result.version = verMatch[1];
      }

      // Detect common SMTP products
      if (/postfix/i.test(banner)) result.product = "Postfix";
      else if (/sendmail/i.test(banner)) result.product = "Sendmail";
      else if (/exim/i.test(banner)) result.product = "Exim";
      else if (/microsoft|exchange/i.test(banner)) { result.product = "Microsoft Exchange"; result.os = "Windows"; }
      else if (/dovecot/i.test(banner)) result.product = "Dovecot";
      else if (/haraka/i.test(banner)) result.product = "Haraka";

      // Send EHLO to get capabilities
      const ehloResp = await sendAndReceive(socket, `EHLO probe.caldera.local\r\n`, 5000);
      const ehloText = ehloResp.toString("utf-8");
      result.metadata.ehloResponse = ehloText.trim();

      // Parse EHLO capabilities
      const ehloLines = ehloText.split("\n").map(l => l.trim());
      const capabilities: Record<string, boolean> = {};
      const authMethods: string[] = [];

      for (const line of ehloLines) {
        if (/250[- ]STARTTLS/i.test(line)) {
          capabilities.starttls = true;
          result.securityFlags.tlsSupported = true;
        }
        if (/250[- ]AUTH\s+(.*)/i.test(line)) {
          const authMatch = line.match(/250[- ]AUTH\s+(.*)/i);
          if (authMatch) {
            authMethods.push(...authMatch[1].split(/\s+/));
            capabilities.auth = true;
            result.securityFlags.authRequired = false; // Auth is available but not necessarily required
          }
        }
        if (/250[- ]SIZE\s+(\d+)/i.test(line)) {
          const sizeMatch = line.match(/250[- ]SIZE\s+(\d+)/i);
          if (sizeMatch) result.metadata.maxMessageSize = parseInt(sizeMatch[1]);
          capabilities.size = true;
        }
        if (/250[- ]PIPELINING/i.test(line)) capabilities.pipelining = true;
        if (/250[- ]8BITMIME/i.test(line)) capabilities["8bitmime"] = true;
        if (/250[- ]ENHANCEDSTATUSCODES/i.test(line)) capabilities.enhancedStatusCodes = true;
        if (/250[- ]DSN/i.test(line)) capabilities.dsn = true;
        if (/250[- ]VRFY/i.test(line)) capabilities.vrfy = true;
        if (/250[- ]EXPN/i.test(line)) capabilities.expn = true;
        if (/250[- ]CHUNKING/i.test(line)) capabilities.chunking = true;
        if (/250[- ]SMTPUTF8/i.test(line)) capabilities.smtpUtf8 = true;
      }

      result.capabilities = capabilities;
      result.metadata.authMethods = authMethods;

      // Check for weak auth methods
      if (authMethods.includes("PLAIN") || authMethods.includes("LOGIN")) {
        if (!capabilities.starttls) {
          result.riskIndicators.push({
            severity: "high",
            title: "SMTP Plaintext Authentication Without TLS",
            description: "Server supports PLAIN/LOGIN auth without STARTTLS, credentials sent in cleartext",
            cweId: "CWE-319",
            mitreId: "T1040",
          });
          result.securityFlags.weakCredentials = true;
        }
      }

      // Check for VRFY/EXPN (user enumeration)
      if (capabilities.vrfy) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP VRFY Command Enabled",
          description: "VRFY allows user enumeration — attackers can verify valid email addresses",
          cweId: "CWE-200",
          mitreId: "T1589.002",
        });
      }
      if (capabilities.expn) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP EXPN Command Enabled",
          description: "EXPN reveals mailing list members — information disclosure risk",
          cweId: "CWE-200",
          mitreId: "T1589.002",
        });
      }

      // Open relay check (only if ROE permits)
      if (tryDefaultCreds) {
        try {
          const relayTest = await sendAndReceive(socket, `MAIL FROM:<test@probe.caldera.local>\r\n`, 3000);
          const relayText = relayTest.toString("utf-8");
          if (/^250/m.test(relayText)) {
            const rcptTest = await sendAndReceive(socket, `RCPT TO:<test@example.com>\r\n`, 3000);
            const rcptText = rcptTest.toString("utf-8");
            if (/^250/m.test(rcptText)) {
              result.securityFlags.anonymousAccess = true;
              result.riskIndicators.push({
                severity: "critical",
                title: "SMTP Open Relay Detected",
                description: "Server accepts mail for arbitrary external domains without authentication",
                cweId: "CWE-284",
                mitreId: "T1071.003",
              });
            }
            // Reset
            await sendAndReceive(socket, "RSET\r\n", 2000);
          }
        } catch { /* relay check failed, non-critical */ }
      }

      // Quit gracefully
      socket.write("QUIT\r\n");

      // Check for no STARTTLS
      if (!capabilities.starttls && (port === 25 || port === 587)) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP STARTTLS Not Supported",
          description: "Server does not support STARTTLS — email transmitted in plaintext",
          cweId: "CWE-319",
          mitreId: "T1040",
        });
      }

      result.mitreRelevance.push("T1071.003"); // Application Layer Protocol: Mail
      if (port === 25) result.mitreRelevance.push("T1048.002"); // Exfiltration Over Alternative Protocol
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── FTP Fingerprinting ─────────────────────────────────────────────────────

export async function fingerprintFTP(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port, timeoutMs = 10000, tryDefaultCreds = false } = config;
  const result = defaultResult("ftp", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Read FTP banner
      const bannerBuf = await readBanner(socket, 5000);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;

      // Parse banner: 220 hostname FTP server (product version) ready
      const bannerMatch = banner.match(/^220[- ](.+)/);
      if (bannerMatch) {
        const bannerText = bannerMatch[1];
        if (/vsftpd/i.test(bannerText)) {
          result.product = "vsftpd";
          const verMatch = bannerText.match(/vsftpd\s+([\d.]+)/i);
          if (verMatch) result.version = verMatch[1];
        } else if (/proftpd/i.test(bannerText)) {
          result.product = "ProFTPD";
          const verMatch = bannerText.match(/proftpd\s+([\d.]+)/i);
          if (verMatch) result.version = verMatch[1];
        } else if (/pure-ftpd/i.test(bannerText)) {
          result.product = "Pure-FTPd";
        } else if (/filezilla/i.test(bannerText)) {
          result.product = "FileZilla Server";
          result.os = "Windows";
        } else if (/microsoft|iis/i.test(bannerText)) {
          result.product = "Microsoft FTP Service";
          result.os = "Windows";
        }
      }

      // Check AUTH TLS/SSL support
      const featResp = await sendAndReceive(socket, "FEAT\r\n", 3000);
      const featText = featResp.toString("utf-8");
      result.metadata.featResponse = featText.trim();

      if (/AUTH TLS/i.test(featText) || /AUTH SSL/i.test(featText)) {
        result.securityFlags.tlsSupported = true;
        result.capabilities.authTls = true;
      }
      if (/PBSZ/i.test(featText)) result.capabilities.pbsz = true;
      if (/PROT/i.test(featText)) result.capabilities.prot = true;
      if (/UTF8/i.test(featText)) result.capabilities.utf8 = true;
      if (/MLST/i.test(featText)) result.capabilities.mlst = true;
      if (/MDTM/i.test(featText)) result.capabilities.mdtm = true;
      if (/SIZE/i.test(featText)) result.capabilities.size = true;
      if (/EPSV/i.test(featText)) result.capabilities.epsv = true;
      if (/EPRT/i.test(featText)) result.capabilities.eprt = true;

      // Anonymous login check
      if (tryDefaultCreds) {
        const userResp = await sendAndReceive(socket, "USER anonymous\r\n", 3000);
        const userText = userResp.toString("utf-8");
        if (/^331/m.test(userText)) {
          const passResp = await sendAndReceive(socket, "PASS anonymous@probe.caldera.local\r\n", 3000);
          const passText = passResp.toString("utf-8");
          if (/^230/m.test(passText)) {
            result.securityFlags.anonymousAccess = true;
            result.riskIndicators.push({
              severity: "high",
              title: "FTP Anonymous Login Allowed",
              description: "Server allows anonymous FTP access — potential data exposure",
              cweId: "CWE-284",
              mitreId: "T1078.001",
            });

            // Try to list directory
            try {
              const pwdResp = await sendAndReceive(socket, "PWD\r\n", 2000);
              result.metadata.anonymousRoot = pwdResp.toString("utf-8").trim();
            } catch { /* non-critical */ }

            // Quit anonymous session
            await sendAndReceive(socket, "QUIT\r\n", 2000);
          }
        }
      }

      // Check for no TLS
      if (!result.securityFlags.tlsSupported) {
        result.riskIndicators.push({
          severity: "high",
          title: "FTP Without TLS Support",
          description: "Server does not support AUTH TLS/SSL — credentials and data transmitted in cleartext",
          cweId: "CWE-319",
          mitreId: "T1040",
        });
      }

      // Check for known vulnerable versions
      if (result.product === "vsftpd" && result.version === "2.3.4") {
        result.potentialCves.push("CVE-2011-2523");
        result.riskIndicators.push({
          severity: "critical",
          title: "vsftpd 2.3.4 Backdoor",
          description: "This version contains a known backdoor triggered by :) in the username",
          cweId: "CWE-506",
          mitreId: "T1190",
        });
      }
      if (result.product === "ProFTPD") {
        const ver = parseFloat(result.version || "0");
        if (ver > 0 && ver <= 1.36) {
          result.potentialCves.push("CVE-2019-12815");
        }
      }

      result.mitreRelevance.push("T1021.002"); // Remote Services: SMB/Windows Admin Shares (FTP similar)
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── SNMP Fingerprinting ────────────────────────────────────────────────────

export async function fingerprintSNMP(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 161, timeoutMs = 10000, tryDefaultCreds = true } = config;
  const result = defaultResult("snmp", host, port);
  const start = Date.now();

  try {
    const socket = dgram.createSocket("udp4");

    const sendSnmpGet = (community: string): Promise<Buffer | null> => {
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          resolve(null);
        }, 5000);

        // Build SNMPv1 GET-REQUEST for sysDescr.0 (1.3.6.1.2.1.1.1.0)
        const communityBuf = Buffer.from(community, "ascii");
        const oid = Buffer.from([
          0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        ]); // 1.3.6.1.2.1.1.1.0
        const nullVal = Buffer.from([0x05, 0x00]);
        const varbind = Buffer.concat([
          Buffer.from([0x30, oid.length + nullVal.length]),
          oid,
          nullVal,
        ]);
        const varbindList = Buffer.concat([
          Buffer.from([0x30, varbind.length]),
          varbind,
        ]);
        const requestId = Buffer.from([0x02, 0x04, 0x00, 0x00, 0x00, 0x01]);
        const errorStatus = Buffer.from([0x02, 0x01, 0x00]);
        const errorIndex = Buffer.from([0x02, 0x01, 0x00]);
        const pduBody = Buffer.concat([requestId, errorStatus, errorIndex, varbindList]);
        const pdu = Buffer.concat([
          Buffer.from([0xa0, pduBody.length]),
          pduBody,
        ]);
        const versionField = Buffer.from([0x02, 0x01, 0x00]); // SNMPv1
        const communityField = Buffer.concat([
          Buffer.from([0x04, communityBuf.length]),
          communityBuf,
        ]);
        const messageBody = Buffer.concat([versionField, communityField, pdu]);
        const message = Buffer.concat([
          Buffer.from([0x30, messageBody.length]),
          messageBody,
        ]);

        socket.once("message", (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        socket.send(message, 0, message.length, port, host);
      });
    };

    // Test common community strings
    const communities = tryDefaultCreds
      ? ["public", "private", "community", "snmp", "monitor", "admin"]
      : ["public"];

    const validCommunities: string[] = [];

    for (const community of communities) {
      const resp = await sendSnmpGet(community);
      if (resp && resp.length > 10) {
        validCommunities.push(community);

        // Parse sysDescr from response
        try {
          // Find the OctetString value in the response (type 0x04)
          let sysDescr = "";
          for (let i = 0; i < resp.length - 2; i++) {
            if (resp[i] === 0x04 && resp[i + 1] > 5 && resp[i + 1] < 200) {
              const len = resp[i + 1];
              if (i + 2 + len <= resp.length) {
                const candidate = resp.subarray(i + 2, i + 2 + len).toString("utf-8");
                if (candidate.length > sysDescr.length && /[a-zA-Z]/.test(candidate)) {
                  sysDescr = candidate;
                }
              }
            }
          }
          if (sysDescr) {
            result.banner = sysDescr;
            result.metadata.sysDescr = sysDescr;

            // Extract OS/product from sysDescr
            if (/linux/i.test(sysDescr)) result.os = "Linux";
            else if (/windows/i.test(sysDescr)) result.os = "Windows";
            else if (/cisco/i.test(sysDescr)) { result.product = "Cisco IOS"; result.os = "Cisco IOS"; }
            else if (/juniper|junos/i.test(sysDescr)) { result.product = "Juniper JunOS"; result.os = "JunOS"; }
            else if (/fortinet|fortigate/i.test(sysDescr)) result.product = "FortiGate";
            else if (/palo alto|pan-os/i.test(sysDescr)) result.product = "Palo Alto PAN-OS";
            else if (/hp|hewlett/i.test(sysDescr)) result.product = "HP";
            else if (/vmware/i.test(sysDescr)) result.product = "VMware ESXi";

            const verMatch = sysDescr.match(/(?:version|ver\.?|v)\s*([\d.]+)/i);
            if (verMatch) result.version = verMatch[1];
          }
        } catch { /* parsing failed */ }

        // First valid community is enough for basic fingerprinting
        if (community === "public") break;
      }
    }

    socket.close();

    result.metadata.validCommunities = validCommunities;
    result.capabilities.snmpV1 = validCommunities.length > 0;

    if (validCommunities.length > 0) {
      result.securityFlags.authRequired = false;

      if (validCommunities.includes("public")) {
        result.securityFlags.defaultCredentials = true;
        result.riskIndicators.push({
          severity: "high",
          title: "SNMP Default Community String 'public'",
          description: "Server responds to default 'public' community string — information disclosure",
          cweId: "CWE-798",
          mitreId: "T1552.001",
        });
      }
      if (validCommunities.includes("private")) {
        result.securityFlags.defaultCredentials = true;
        result.riskIndicators.push({
          severity: "critical",
          title: "SNMP Default Write Community String 'private'",
          description: "Server responds to default 'private' community — read/write access to device configuration",
          cweId: "CWE-798",
          mitreId: "T1552.001",
        });
      }
      if (validCommunities.length > 1) {
        result.riskIndicators.push({
          severity: "medium",
          title: "Multiple SNMP Community Strings Accepted",
          description: `Server accepts ${validCommunities.length} community strings: ${validCommunities.join(", ")}`,
          cweId: "CWE-287",
        });
      }
    }

    result.mitreRelevance.push("T1602.001"); // Data from Configuration Repository: SNMP
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── RDP Fingerprinting ─────────────────────────────────────────────────────

export async function fingerprintRDP(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 3389, timeoutMs = 10000 } = config;
  const result = defaultResult("rdp", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send RDP Connection Request (X.224 CR TPDU)
      // This is the initial negotiation that reveals NLA/TLS support
      const x224CR = Buffer.from([
        // TPKT header
        0x03, 0x00, 0x00, 0x13, // version=3, length=19
        // X.224 CR TPDU
        0x0e, // length indicator
        0xe0, // CR TPDU code
        0x00, 0x00, // DST-REF
        0x00, 0x00, // SRC-REF
        0x00, // class 0
        // RDP Negotiation Request
        0x01, // TYPE_RDP_NEG_REQ
        0x00, // flags
        0x08, 0x00, // length = 8
        0x0b, 0x00, 0x00, 0x00, // requestedProtocols: TLS | CredSSP | RDSTLS
      ]);

      socket.write(x224CR);
      const respBuf = await readBanner(socket, 5000);

      if (respBuf.length >= 11) {
        result.rawResponse = respBuf.toString("hex");
        result.capabilities.rdp = true;
        result.product = "Microsoft RDP";
        result.os = "Windows";

        // Parse X.224 CC response
        const tpduCode = respBuf[5];
        if (tpduCode === 0xd0) { // CC TPDU
          // Check for RDP Negotiation Response
          if (respBuf.length >= 19) {
            const negType = respBuf[11];
            if (negType === 0x02) { // TYPE_RDP_NEG_RSP
              const selectedProtocol = respBuf.readUInt32LE(15);
              result.metadata.selectedProtocol = selectedProtocol;

              if (selectedProtocol & 0x01) {
                result.securityFlags.tlsSupported = true;
                result.metadata.negotiatedSecurity = "TLS";
              }
              if (selectedProtocol & 0x02) {
                result.capabilities.nla = true;
                result.securityFlags.authRequired = true;
                result.metadata.negotiatedSecurity = "CredSSP (NLA)";
              }
              if (selectedProtocol & 0x08) {
                result.metadata.negotiatedSecurity = "RDSTLS";
              }
              if (selectedProtocol === 0x00) {
                result.metadata.negotiatedSecurity = "Standard RDP Security";
                result.riskIndicators.push({
                  severity: "high",
                  title: "RDP Standard Security (No NLA/TLS)",
                  description: "Server uses legacy RDP security without NLA or TLS — vulnerable to MITM",
                  cweId: "CWE-319",
                  mitreId: "T1557",
                });
              }
            } else if (negType === 0x03) { // TYPE_RDP_NEG_FAILURE
              const failureCode = respBuf.readUInt32LE(15);
              result.metadata.negotiationFailure = failureCode;
              result.riskIndicators.push({
                severity: "info",
                title: "RDP Negotiation Failure",
                description: `Server rejected security negotiation with code ${failureCode}`,
              });
            }
          }
        }

        // Check for NLA not required
        if (!result.capabilities.nla) {
          result.riskIndicators.push({
            severity: "high",
            title: "RDP Network Level Authentication (NLA) Not Required",
            description: "NLA is not enforced — server vulnerable to pre-authentication attacks",
            cweId: "CWE-287",
            mitreId: "T1021.001",
          });
        }

        // BlueKeep check hint (CVE-2019-0708)
        result.metadata.blueKeepNote = "Requires dedicated exploit probe — not tested in fingerprint phase";
        result.potentialCves.push("CVE-2019-0708"); // BlueKeep — always flag for RDP
      }

      result.mitreRelevance.push("T1021.001"); // Remote Services: RDP
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── SMB Fingerprinting ─────────────────────────────────────────────────────

export async function fingerprintSMB(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 445, timeoutMs = 10000 } = config;
  const result = defaultResult("smb", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send SMB2 Negotiate Request
      // This reveals SMB version, signing requirements, and server capabilities
      const smbNeg = Buffer.alloc(140);
      let offset = 0;

      // NetBIOS Session Service header
      smbNeg[offset++] = 0x00; // Session Message
      // Length will be filled in later (3 bytes)
      offset += 3;

      // SMB2 Header
      const headerStart = offset;
      smbNeg.write("\xfeSMB", offset); offset += 4; // Protocol ID
      smbNeg.writeUInt16LE(64, offset); offset += 2; // Structure Size
      smbNeg.writeUInt16LE(0, offset); offset += 2; // Credit Charge
      smbNeg.writeUInt32LE(0, offset); offset += 4; // Status
      smbNeg.writeUInt16LE(0x0000, offset); offset += 2; // Command: NEGOTIATE
      smbNeg.writeUInt16LE(1, offset); offset += 2; // Credit Request
      smbNeg.writeUInt32LE(0, offset); offset += 4; // Flags
      smbNeg.writeUInt32LE(0, offset); offset += 4; // Next Command
      smbNeg.writeBigUInt64LE(1n, offset); offset += 8; // Message ID
      smbNeg.writeUInt32LE(0, offset); offset += 4; // Reserved (Process ID)
      smbNeg.writeUInt32LE(0, offset); offset += 4; // Tree ID
      smbNeg.writeBigUInt64LE(0n, offset); offset += 8; // Session ID
      smbNeg.fill(0, offset, offset + 16); offset += 16; // Signature

      // SMB2 Negotiate Request body
      smbNeg.writeUInt16LE(36, offset); offset += 2; // Structure Size
      smbNeg.writeUInt16LE(5, offset); offset += 2; // Dialect Count
      smbNeg.writeUInt16LE(1, offset); offset += 2; // Security Mode (signing enabled)
      smbNeg.writeUInt16LE(0, offset); offset += 2; // Reserved
      smbNeg.writeUInt32LE(0x7f, offset); offset += 4; // Capabilities

      // Client GUID
      crypto.randomFillSync(smbNeg, offset, 16); offset += 16;

      // Negotiate Context Offset/Count (SMB 3.1.1)
      smbNeg.writeUInt32LE(0, offset); offset += 4; // NegotiateContextOffset
      smbNeg.writeUInt16LE(0, offset); offset += 2; // NegotiateContextCount
      smbNeg.writeUInt16LE(0, offset); offset += 2; // Reserved2

      // Dialects
      smbNeg.writeUInt16LE(0x0202, offset); offset += 2; // SMB 2.0.2
      smbNeg.writeUInt16LE(0x0210, offset); offset += 2; // SMB 2.1
      smbNeg.writeUInt16LE(0x0300, offset); offset += 2; // SMB 3.0
      smbNeg.writeUInt16LE(0x0302, offset); offset += 2; // SMB 3.0.2
      smbNeg.writeUInt16LE(0x0311, offset); offset += 2; // SMB 3.1.1

      // Fill in NetBIOS length
      const totalLen = offset - 4;
      smbNeg[1] = (totalLen >> 16) & 0xff;
      smbNeg[2] = (totalLen >> 8) & 0xff;
      smbNeg[3] = totalLen & 0xff;

      const packet = smbNeg.subarray(0, offset);
      socket.write(packet);

      const respBuf = await readBanner(socket, 5000);

      if (respBuf.length >= 68) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");
        result.product = "Microsoft SMB";
        result.os = "Windows";

        // Check for SMB2 response
        const protoId = respBuf.subarray(4, 8).toString("ascii");
        if (protoId === "\xfeSMB") {
          // Parse SMB2 Negotiate Response
          const dialectOffset = 4 + 64 + 4; // NetBIOS(4) + Header(64) + StructureSize(2) + SecurityMode(2)
          if (respBuf.length > dialectOffset + 2) {
            const securityMode = respBuf.readUInt16LE(4 + 64 + 2);
            const dialect = respBuf.readUInt16LE(dialectOffset);

            const dialectMap: Record<number, string> = {
              0x0202: "SMB 2.0.2",
              0x0210: "SMB 2.1",
              0x0300: "SMB 3.0",
              0x0302: "SMB 3.0.2",
              0x0311: "SMB 3.1.1",
            };

            result.version = dialectMap[dialect] || `0x${dialect.toString(16)}`;
            result.metadata.smbDialect = dialect;
            result.metadata.smbVersion = result.version;

            // Security mode flags
            result.securityFlags.signingEnabled = (securityMode & 0x01) !== 0;
            const signingRequired = (securityMode & 0x02) !== 0;
            result.metadata.signingRequired = signingRequired;

            if (!signingRequired) {
              result.riskIndicators.push({
                severity: "medium",
                title: "SMB Signing Not Required",
                description: "Server does not require SMB signing — vulnerable to relay attacks",
                cweId: "CWE-345",
                mitreId: "T1557.001",
              });
            }

            // Check for SMBv1 (very old)
            if (dialect < 0x0202) {
              result.riskIndicators.push({
                severity: "critical",
                title: "SMBv1 Detected",
                description: "Server supports SMBv1 — vulnerable to EternalBlue and other critical exploits",
                cweId: "CWE-1104",
                mitreId: "T1210",
              });
              result.potentialCves.push("CVE-2017-0144"); // EternalBlue
            }

            // Check for encryption support (SMB 3.0+)
            if (dialect >= 0x0300) {
              result.securityFlags.encryptionEnabled = true;
              result.capabilities.smbEncryption = true;
            }
          }
        }

        result.capabilities.smb = true;
      }

      result.mitreRelevance.push("T1021.002"); // Remote Services: SMB
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── LDAP Fingerprinting ────────────────────────────────────────────────────

export async function fingerprintLDAP(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 389, timeoutMs = 10000 } = config;
  const result = defaultResult("ldap", host, port);
  const start = Date.now();

  try {
    const useTls = port === 636;
    const socket = useTls
      ? await tlsConnect(host, port, timeoutMs)
      : await tcpConnect(host, port, timeoutMs);

    if (useTls) {
      result.securityFlags.tlsSupported = true;
      result.securityFlags.tlsRequired = true;
      const tlsSock = socket as tls.TLSSocket;
      result.securityFlags.tlsVersion = tlsSock.getProtocol() || null;
    }

    try {
      // Send LDAP SearchRequest for RootDSE (anonymous bind)
      // This is a standard way to fingerprint LDAP servers
      const searchRequest = Buffer.from([
        // LDAP Message
        0x30, 0x25, // SEQUENCE, length
        0x02, 0x01, 0x01, // MessageID = 1
        // SearchRequest (Application 3)
        0x63, 0x20,
        // BaseDN: "" (empty = RootDSE)
        0x04, 0x00,
        // Scope: baseObject (0)
        0x0a, 0x01, 0x00,
        // DerefAliases: neverDerefAliases (0)
        0x0a, 0x01, 0x00,
        // SizeLimit: 0
        0x02, 0x01, 0x00,
        // TimeLimit: 30
        0x02, 0x01, 0x1e,
        // TypesOnly: false
        0x01, 0x01, 0x00,
        // Filter: present(objectClass)
        0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73,
        // Attributes: empty (return all)
        0x30, 0x00,
      ]);

      socket.write(searchRequest);
      const respBuf = await readBanner(socket, 5000);

      if (respBuf.length > 10) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 500)).toString("hex");
        result.capabilities.ldap = true;

        // Try to extract readable strings from the response
        const respText = respBuf.toString("utf-8", 0, Math.min(respBuf.length, 2000));

        // Look for common LDAP attributes in the response
        if (/namingContexts/i.test(respText)) {
          result.securityFlags.anonymousAccess = true;
          result.capabilities.anonymousBind = true;

          // Extract naming contexts (base DNs)
          const dnMatches = respText.match(/(?:DC|dc)=[\w.-]+(?:,(?:DC|dc)=[\w.-]+)*/g);
          if (dnMatches) {
            result.metadata.namingContexts = [...new Set(dnMatches)];
          }

          result.riskIndicators.push({
            severity: "high",
            title: "LDAP Anonymous Bind Allowed",
            description: "Server allows anonymous LDAP queries — directory information exposed",
            cweId: "CWE-284",
            mitreId: "T1087.002",
          });
        }

        // Detect product
        if (/Microsoft/i.test(respText) || /Active Directory/i.test(respText)) {
          result.product = "Microsoft Active Directory";
          result.os = "Windows";
          result.mitreRelevance.push("T1087.002"); // Account Discovery: Domain Account
        } else if (/OpenLDAP/i.test(respText) || /openldap/i.test(respText)) {
          result.product = "OpenLDAP";
        } else if (/389 Directory/i.test(respText)) {
          result.product = "389 Directory Server";
        } else if (/ApacheDS/i.test(respText)) {
          result.product = "Apache Directory Server";
        }

        // Extract version info
        const verMatch = respText.match(/(?:vendorVersion|supportedLDAPVersion)[:\s]*([\d.]+)/i);
        if (verMatch) result.version = verMatch[1];

        // Check for STARTTLS support
        if (/1\.3\.6\.1\.4\.1\.1466\.20037/i.test(respText)) {
          result.securityFlags.tlsSupported = true;
          result.capabilities.startTls = true;
        }
      } else {
        // Empty response might mean anonymous bind is rejected
        result.securityFlags.authRequired = true;
      }

      result.mitreRelevance.push("T1018"); // Remote System Discovery
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── Telnet Fingerprinting ──────────────────────────────────────────────────

export async function fingerprintTelnet(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 23, timeoutMs = 10000 } = config;
  const result = defaultResult("telnet", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5000);
      const banner = bannerBuf.toString("utf-8").replace(/[\x00-\x1f]/g, "").trim();
      result.banner = banner;
      result.rawResponse = bannerBuf.toString("hex").substring(0, 400);

      // Parse telnet options from IAC sequences
      const iacOptions: string[] = [];
      for (let i = 0; i < bannerBuf.length - 2; i++) {
        if (bannerBuf[i] === 0xff) { // IAC
          const cmd = bannerBuf[i + 1];
          const opt = bannerBuf[i + 2];
          const cmdName = cmd === 0xfb ? "WILL" : cmd === 0xfd ? "DO" : cmd === 0xfc ? "WONT" : cmd === 0xfe ? "DONT" : `0x${cmd.toString(16)}`;
          iacOptions.push(`${cmdName} ${opt}`);
        }
      }
      result.metadata.telnetOptions = iacOptions;

      // Detect product/OS from banner
      if (/cisco/i.test(banner)) { result.product = "Cisco IOS"; result.os = "Cisco IOS"; }
      else if (/juniper|junos/i.test(banner)) { result.product = "Juniper JunOS"; result.os = "JunOS"; }
      else if (/linux|ubuntu|debian|centos/i.test(banner)) result.os = "Linux";
      else if (/windows/i.test(banner)) result.os = "Windows";
      else if (/busybox/i.test(banner)) { result.product = "BusyBox"; result.os = "Embedded Linux"; }

      // Telnet is always a risk
      result.securityFlags.encryptionEnabled = false;
      result.riskIndicators.push({
        severity: "critical",
        title: "Telnet Service Exposed",
        description: "Telnet transmits all data including credentials in cleartext — should be replaced with SSH",
        cweId: "CWE-319",
        mitreId: "T1021.004",
      });

      result.capabilities.telnet = true;
      result.mitreRelevance.push("T1021"); // Remote Services
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── MySQL Fingerprinting ───────────────────────────────────────────────────

export async function fingerprintMySQL(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 3306, timeoutMs = 10000 } = config;
  const result = defaultResult("mysql", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5000);

      if (bannerBuf.length > 4) {
        result.rawResponse = bannerBuf.subarray(0, Math.min(bannerBuf.length, 200)).toString("hex");

        // MySQL Initial Handshake Packet
        // Skip packet header (4 bytes: 3 length + 1 sequence)
        const payloadStart = 4;
        const protocolVersion = bannerBuf[payloadStart];
        result.metadata.protocolVersion = protocolVersion;

        if (protocolVersion === 0xff) {
          // Error packet — server rejected connection
          const errorMsg = bannerBuf.subarray(payloadStart + 3).toString("utf-8").trim();
          result.banner = `Error: ${errorMsg}`;
          result.metadata.connectionError = errorMsg;
          if (/too many connections/i.test(errorMsg)) {
            result.riskIndicators.push({
              severity: "info",
              title: "MySQL Max Connections Reached",
              description: "Server is at connection limit — may indicate heavy load or misconfiguration",
            });
          }
        } else if (protocolVersion === 10 || protocolVersion === 9) {
          // Valid handshake
          // Read null-terminated server version string
          let versionEnd = payloadStart + 1;
          while (versionEnd < bannerBuf.length && bannerBuf[versionEnd] !== 0x00) versionEnd++;
          const versionStr = bannerBuf.subarray(payloadStart + 1, versionEnd).toString("utf-8");
          result.version = versionStr;
          result.banner = `MySQL ${versionStr}`;

          // Detect product
          if (/mariadb/i.test(versionStr)) result.product = "MariaDB";
          else if (/percona/i.test(versionStr)) result.product = "Percona Server";
          else result.product = "MySQL";

          if (protocolVersion === 10 && versionEnd + 1 < bannerBuf.length) {
            // Skip connection ID (4 bytes)
            let off = versionEnd + 1 + 4;

            // Auth plugin data part 1 (8 bytes) + filler (1 byte)
            off += 9;

            // Capability flags (lower 2 bytes)
            if (off + 2 <= bannerBuf.length) {
              const capLow = bannerBuf.readUInt16LE(off);
              off += 2;

              // Character set (1 byte)
              if (off < bannerBuf.length) {
                result.metadata.charset = bannerBuf[off];
                off += 1;
              }

              // Status flags (2 bytes)
              if (off + 2 <= bannerBuf.length) {
                result.metadata.statusFlags = bannerBuf.readUInt16LE(off);
                off += 2;
              }

              // Capability flags (upper 2 bytes)
              if (off + 2 <= bannerBuf.length) {
                const capHigh = bannerBuf.readUInt16LE(off);
                const capabilities = (capHigh << 16) | capLow;
                off += 2;

                result.capabilities.ssl = (capabilities & 0x0800) !== 0;
                result.capabilities.compress = (capabilities & 0x0020) !== 0;
                result.capabilities.secureConnection = (capabilities & 0x8000) !== 0;
                result.capabilities.pluginAuth = (capabilities & 0x00080000) !== 0;

                result.securityFlags.tlsSupported = result.capabilities.ssl;

                // Skip to auth plugin name
                off += 1 + 10; // auth_plugin_data_len(1) + reserved(10)
                // Auth plugin data part 2
                if (off < bannerBuf.length) {
                  const authDataLen = Math.max(13, bannerBuf[off - 11] - 8);
                  off += authDataLen;

                  // Auth plugin name
                  if (off < bannerBuf.length) {
                    let pluginEnd = off;
                    while (pluginEnd < bannerBuf.length && bannerBuf[pluginEnd] !== 0x00) pluginEnd++;
                    const authPlugin = bannerBuf.subarray(off, pluginEnd).toString("utf-8");
                    result.metadata.authPlugin = authPlugin;

                    if (authPlugin === "mysql_native_password") {
                      result.riskIndicators.push({
                        severity: "low",
                        title: "MySQL Using Legacy Auth Plugin",
                        description: "Server uses mysql_native_password — consider upgrading to caching_sha2_password",
                        cweId: "CWE-327",
                      });
                    }
                  }
                }
              }
            }
          }

          // Check for no TLS
          if (!result.securityFlags.tlsSupported) {
            result.riskIndicators.push({
              severity: "high",
              title: "MySQL TLS Not Supported",
              description: "Server does not support SSL/TLS — database connections are unencrypted",
              cweId: "CWE-319",
              mitreId: "T1040",
            });
          }
        }

        result.capabilities.mysql = true;
        result.mitreRelevance.push("T1505.001"); // Server Software Component: SQL Stored Procedures
      }
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── PostgreSQL Fingerprinting ──────────────────────────────────────────────

export async function fingerprintPostgreSQL(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 5432, timeoutMs = 10000 } = config;
  const result = defaultResult("postgresql", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send SSLRequest first to check TLS support
      const sslRequest = Buffer.alloc(8);
      sslRequest.writeUInt32BE(8, 0); // length
      sslRequest.writeUInt32BE(80877103, 4); // SSLRequest code
      socket.write(sslRequest);

      const sslResp = await readBanner(socket, 3000);
      if (sslResp.length > 0) {
        const sslByte = sslResp[0];
        if (sslByte === 0x53) { // 'S' — SSL supported
          result.securityFlags.tlsSupported = true;
          result.capabilities.ssl = true;
        } else if (sslByte === 0x4e) { // 'N' — SSL not supported
          result.securityFlags.tlsSupported = false;
          result.riskIndicators.push({
            severity: "high",
            title: "PostgreSQL SSL Not Supported",
            description: "Server does not support SSL — database connections are unencrypted",
            cweId: "CWE-319",
            mitreId: "T1040",
          });
        }
      }

      // Reconnect for version probe (SSL negotiation changes socket state)
      socket.destroy();
      const socket2 = await tcpConnect(host, port, timeoutMs);

      try {
        // Send StartupMessage with a probe user
        const user = "probe";
        const database = "postgres";
        const params = `user\0${user}\0database\0${database}\0\0`;
        const startupLen = 4 + 4 + params.length;
        const startup = Buffer.alloc(startupLen);
        startup.writeUInt32BE(startupLen, 0);
        startup.writeUInt32BE(196608, 4); // Protocol 3.0
        startup.write(params, 8, "utf-8");
        socket2.write(startup);

        const respBuf = await readBanner(socket2, 5000);
        if (respBuf.length > 0) {
          const msgType = String.fromCharCode(respBuf[0]);
          result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");

          if (msgType === "R") {
            // Authentication request
            if (respBuf.length >= 8) {
              const authType = respBuf.readUInt32BE(5);
              const authNames: Record<number, string> = {
                0: "trust (no auth)",
                2: "kerberos",
                3: "cleartext password",
                5: "md5",
                7: "gss",
                8: "gss-continue",
                9: "sspi",
                10: "sasl",
              };
              result.metadata.authMethod = authNames[authType] || `unknown(${authType})`;

              if (authType === 0) {
                result.securityFlags.authRequired = false;
                result.securityFlags.anonymousAccess = true;
                result.riskIndicators.push({
                  severity: "critical",
                  title: "PostgreSQL Trust Authentication",
                  description: "Server uses trust authentication — no password required for connections",
                  cweId: "CWE-287",
                  mitreId: "T1078",
                });
              } else if (authType === 3) {
                result.riskIndicators.push({
                  severity: "high",
                  title: "PostgreSQL Cleartext Password Auth",
                  description: "Server uses cleartext password authentication — credentials sent unencrypted",
                  cweId: "CWE-319",
                });
              }
            }
          } else if (msgType === "E") {
            // Error response — parse error message
            const errText = respBuf.subarray(5).toString("utf-8").replace(/\0/g, " ").trim();
            result.banner = errText;

            // Extract version from error message
            const verMatch = errText.match(/PostgreSQL\s+([\d.]+)/i);
            if (verMatch) result.version = verMatch[1];
          }

          result.product = "PostgreSQL";
          result.capabilities.postgresql = true;
          result.mitreRelevance.push("T1505.001");
        }
      } finally {
        socket2.destroy();
      }
    } finally {
      if (!socket.destroyed) socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── MSSQL Fingerprinting ───────────────────────────────────────────────────

export async function fingerprintMSSQL(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 1433, timeoutMs = 10000 } = config;
  const result = defaultResult("mssql", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send TDS Pre-Login message to fingerprint MSSQL
      const prelogin = Buffer.from([
        // TDS Header
        0x12, // Type: Pre-Login
        0x01, // Status: EOM
        0x00, 0x2f, // Length
        0x00, 0x00, // SPID
        0x00, // PacketID
        0x00, // Window
        // Pre-Login options
        0x00, 0x00, 0x15, 0x00, 0x06, // VERSION: offset=21, len=6
        0x01, 0x00, 0x1b, 0x00, 0x01, // ENCRYPTION: offset=27, len=1
        0x02, 0x00, 0x1c, 0x00, 0x01, // INSTOPT: offset=28, len=1
        0xff, // Terminator
        // VERSION data (6 bytes): major.minor.build.sub
        0x0f, 0x00, 0x07, 0xd0, 0x00, 0x00,
        // ENCRYPTION data (1 byte): 0x02 = NOT_SUP
        0x02,
        // INSTOPT data (1 byte)
        0x00,
      ]);

      socket.write(prelogin);
      const respBuf = await readBanner(socket, 5000);

      if (respBuf.length >= 8) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");
        result.product = "Microsoft SQL Server";
        result.os = "Windows";

        // Parse TDS Pre-Login Response
        const tdsType = respBuf[0];
        if (tdsType === 0x04) { // Tabular Result
          // Parse pre-login options
          let off = 8; // Skip TDS header
          while (off < respBuf.length && respBuf[off] !== 0xff) {
            const optType = respBuf[off];
            const optOffset = respBuf.readUInt16BE(off + 1) + 8; // relative to payload start
            const optLen = respBuf.readUInt16BE(off + 3);
            off += 5;

            if (optType === 0x00 && optLen >= 6 && optOffset + optLen <= respBuf.length) {
              // VERSION
              const major = respBuf[optOffset];
              const minor = respBuf[optOffset + 1];
              const build = respBuf.readUInt16BE(optOffset + 2);
              result.version = `${major}.${minor}.${build}`;
              result.metadata.sqlServerVersion = { major, minor, build };

              // Map to SQL Server edition
              const editionMap: Record<number, string> = {
                8: "SQL Server 2000",
                9: "SQL Server 2005",
                10: "SQL Server 2008/2008R2",
                11: "SQL Server 2012",
                12: "SQL Server 2014",
                13: "SQL Server 2016",
                14: "SQL Server 2017",
                15: "SQL Server 2019",
                16: "SQL Server 2022",
              };
              result.metadata.edition = editionMap[major] || `SQL Server (v${major})`;
            }
            if (optType === 0x01 && optLen >= 1 && optOffset < respBuf.length) {
              // ENCRYPTION
              const encByte = respBuf[optOffset];
              const encMap: Record<number, string> = {
                0x00: "off",
                0x01: "on",
                0x02: "not_supported",
                0x03: "required",
              };
              result.metadata.encryption = encMap[encByte] || `unknown(${encByte})`;
              result.securityFlags.encryptionEnabled = encByte === 0x01 || encByte === 0x03;
              result.securityFlags.tlsSupported = encByte !== 0x02;

              if (encByte === 0x00 || encByte === 0x02) {
                result.riskIndicators.push({
                  severity: "high",
                  title: "MSSQL Encryption Not Enabled",
                  description: `SQL Server encryption is ${encMap[encByte]} — connections may be unencrypted`,
                  cweId: "CWE-319",
                  mitreId: "T1040",
                });
              }
            }
          }
        }

        result.capabilities.mssql = true;
        result.mitreRelevance.push("T1505.001");
      }
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── Redis Fingerprinting ───────────────────────────────────────────────────

export async function fingerprintRedis(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 6379, timeoutMs = 10000 } = config;
  const result = defaultResult("redis", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send INFO command (works without auth on misconfigured servers)
      const infoCmd = "*1\r\n$4\r\nINFO\r\n";
      socket.write(infoCmd);
      const respBuf = await readBanner(socket, 5000);
      const respText = respBuf.toString("utf-8");

      result.rawResponse = respText.substring(0, 500);
      result.product = "Redis";

      if (respText.startsWith("-NOAUTH") || respText.startsWith("-ERR")) {
        // Auth required — good
        result.securityFlags.authRequired = true;
        result.banner = respText.trim();

        if (/NOAUTH/i.test(respText)) {
          result.metadata.authRequired = true;
        }
      } else if (respText.startsWith("$") || respText.startsWith("+")) {
        // INFO response — no auth required!
        result.securityFlags.authRequired = false;
        result.securityFlags.anonymousAccess = true;

        result.riskIndicators.push({
          severity: "critical",
          title: "Redis No Authentication Required",
          description: "Redis server accepts commands without authentication — full read/write access to data",
          cweId: "CWE-287",
          mitreId: "T1078",
        });

        // Parse INFO response
        const versionMatch = respText.match(/redis_version:([\d.]+)/);
        if (versionMatch) result.version = versionMatch[1];

        const osMatch = respText.match(/os:(.+)/);
        if (osMatch) result.os = osMatch[1].trim();

        const modeMatch = respText.match(/redis_mode:(\w+)/);
        if (modeMatch) result.metadata.mode = modeMatch[1];

        const connMatch = respText.match(/connected_clients:(\d+)/);
        if (connMatch) result.metadata.connectedClients = parseInt(connMatch[1]);

        const memMatch = respText.match(/used_memory_human:([\d.]+\w+)/);
        if (memMatch) result.metadata.usedMemory = memMatch[1];

        const dbMatch = respText.match(/db\d+:keys=(\d+)/g);
        if (dbMatch) result.metadata.databases = dbMatch;

        // Check for dangerous config
        const configResp = await sendAndReceive(socket, "*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nprotected-mode\r\n", 3000);
        const configText = configResp.toString("utf-8");
        if (/no/i.test(configText)) {
          result.riskIndicators.push({
            severity: "critical",
            title: "Redis Protected Mode Disabled",
            description: "Redis protected-mode is off — server accepts connections from any IP",
            cweId: "CWE-284",
          });
        }

        result.banner = `Redis ${result.version || "unknown"} (no auth)`;
      }

      result.capabilities.redis = true;
      result.mitreRelevance.push("T1005"); // Data from Local System
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── MongoDB Fingerprinting ─────────────────────────────────────────────────

export async function fingerprintMongoDB(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 27017, timeoutMs = 10000 } = config;
  const result = defaultResult("mongodb", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Send isMaster command using OP_MSG (MongoDB 3.6+)
      // Build BSON document: { isMaster: 1, $db: "admin" }
      const bsonDoc = Buffer.from([
        // Document length (will be calculated)
        0x00, 0x00, 0x00, 0x00,
        // isMaster: 1 (int32)
        0x10, // type: int32
        ...Buffer.from("isMaster\0"),
        0x01, 0x00, 0x00, 0x00, // value: 1
        // $db: "admin"
        0x02, // type: string
        ...Buffer.from("$db\0"),
        0x06, 0x00, 0x00, 0x00, // string length (including null)
        ...Buffer.from("admin\0"),
        // Document terminator
        0x00,
      ]);
      bsonDoc.writeInt32LE(bsonDoc.length, 0);

      // OP_MSG header
      const header = Buffer.alloc(16 + 4 + 1); // MsgHeader(16) + flagBits(4) + sectionKind(1)
      const totalLen = header.length + bsonDoc.length;
      header.writeInt32LE(totalLen, 0); // messageLength
      header.writeInt32LE(1, 4); // requestID
      header.writeInt32LE(0, 8); // responseTo
      header.writeInt32LE(2013, 12); // opCode: OP_MSG
      header.writeUInt32LE(0, 16); // flagBits
      header[20] = 0; // Section Kind 0 (body)

      socket.write(Buffer.concat([header, bsonDoc]));
      const respBuf = await readBanner(socket, 5000);

      if (respBuf.length > 20) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 300)).toString("hex");
        result.product = "MongoDB";

        // Try to extract readable strings from BSON response
        const respText = respBuf.toString("utf-8", 0, Math.min(respBuf.length, 2000));

        // Look for version string
        const verMatch = respText.match(/version\x00.{4}([\d.]+)/);
        if (verMatch) result.version = verMatch[1];

        // Check for ismaster response
        if (/ismaster/i.test(respText) || /isWritablePrimary/i.test(respText)) {
          result.capabilities.mongodb = true;
          result.securityFlags.anonymousAccess = true;

          result.riskIndicators.push({
            severity: "high",
            title: "MongoDB Accepts Unauthenticated Commands",
            description: "Server responds to isMaster without authentication — check if auth is enforced",
            cweId: "CWE-287",
            mitreId: "T1078",
          });
        }

        // Check for maxWireVersion (indicates MongoDB version capabilities)
        const wireMatch = respText.match(/maxWireVersion\x00.{0,2}([\x00-\xff])/);
        if (wireMatch) {
          result.metadata.maxWireVersion = wireMatch[1].charCodeAt(0);
        }

        result.banner = `MongoDB ${result.version || "unknown"}`;
        result.mitreRelevance.push("T1005");
      }
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ─── VNC Fingerprinting ─────────────────────────────────────────────────────

export async function fingerprintVNC(config: FingerprintConfig): Promise<FingerprintResult> {
  const { host, port = 5900, timeoutMs = 10000 } = config;
  const result = defaultResult("vnc", host, port);
  const start = Date.now();

  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      // Read VNC protocol version
      const bannerBuf = await readBanner(socket, 5000);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;

      // Parse RFB protocol version: "RFB 003.008\n"
      const rfbMatch = banner.match(/RFB\s+(\d{3})\.(\d{3})/);
      if (rfbMatch) {
        result.version = `${parseInt(rfbMatch[1])}.${parseInt(rfbMatch[2])}`;
        result.metadata.rfbVersion = result.version;
        result.product = "VNC";

        // Send our protocol version
        socket.write(`RFB 003.008\n`);

        // Read security types
        const secBuf = await readBanner(socket, 3000);
        if (secBuf.length > 0) {
          const numSecTypes = secBuf[0];
          const secTypes: number[] = [];
          for (let i = 1; i <= numSecTypes && i < secBuf.length; i++) {
            secTypes.push(secBuf[i]);
          }
          result.metadata.securityTypes = secTypes;

          const secTypeNames: Record<number, string> = {
            0: "Invalid",
            1: "None",
            2: "VNC Authentication",
            5: "RA2",
            6: "RA2ne",
            16: "Tight",
            17: "Ultra",
            18: "TLS",
            19: "VeNCrypt",
            30: "Apple Remote Desktop",
          };

          result.metadata.securityTypeNames = secTypes.map(t => secTypeNames[t] || `Unknown(${t})`);

          if (secTypes.includes(1)) {
            result.securityFlags.authRequired = false;
            result.securityFlags.anonymousAccess = true;
            result.riskIndicators.push({
              severity: "critical",
              title: "VNC No Authentication Required",
              description: "VNC server allows connections without any authentication",
              cweId: "CWE-287",
              mitreId: "T1021.005",
            });
          }

          if (secTypes.includes(2) && !secTypes.includes(18) && !secTypes.includes(19)) {
            result.riskIndicators.push({
              severity: "high",
              title: "VNC Without Encryption",
              description: "VNC uses password authentication but no TLS/encryption — credentials and screen data in cleartext",
              cweId: "CWE-319",
              mitreId: "T1040",
            });
          }

          if (secTypes.includes(18) || secTypes.includes(19)) {
            result.securityFlags.tlsSupported = true;
            result.securityFlags.encryptionEnabled = true;
          }
        }

        result.capabilities.vnc = true;
        result.mitreRelevance.push("T1021.005"); // Remote Services: VNC
      }
    } finally {
      socket.destroy();
    }
  } catch (err: any) {
    result.error = err.message;
  }

  result.durationMs = Date.now() - start;
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Orchestration
// ═══════════════════════════════════════════════════════════════════════════════

/** Protocol probe dispatch map */
const PROBE_MAP: Record<ServiceProtocol, (config: FingerprintConfig) => Promise<FingerprintResult>> = {
  ssh: fingerprintSSH,
  smtp: fingerprintSMTP,
  ftp: fingerprintFTP,
  sftp: fingerprintSSH, // SFTP runs over SSH
  snmp: fingerprintSNMP,
  rdp: fingerprintRDP,
  smb: fingerprintSMB,
  ldap: fingerprintLDAP,
  telnet: fingerprintTelnet,
  mysql: fingerprintMySQL,
  mssql: fingerprintMSSQL,
  postgresql: fingerprintPostgreSQL,
  redis: fingerprintRedis,
  mongodb: fingerprintMongoDB,
  vnc: fingerprintVNC,
  pop3: fingerprintTelnet, // Basic banner grab
  imap: fingerprintTelnet, // Basic banner grab
  dns: fingerprintTelnet,  // Basic probe
  ntp: fingerprintTelnet,  // Basic probe
  sip: fingerprintTelnet,  // Basic probe
};

/**
 * Fingerprint a single service on a specific host:port.
 * Auto-detects protocol from port if not specified.
 */
export async function fingerprintService(config: FingerprintConfig): Promise<FingerprintResult> {
  const protocol = config.protocol || detectProtocol(config.port);
  if (!protocol) {
    return {
      ...defaultResult("ssh", config.host, config.port),
      error: `Cannot detect protocol for port ${config.port} — specify protocol explicitly`,
    };
  }

  // ROE scope validation
  if (config.engagementId) {
    try {
      const { enforceSingleTarget } = await import("./scope-guard");
      await enforceSingleTarget(
        config.engagementId,
        config.host,
        `Service Fingerprint (${protocol})`,
        config.operatorId || "system",
      );
    } catch (err: any) {
      return {
        ...defaultResult(protocol, config.host, config.port),
        error: `ROE scope violation: ${err.message}`,
      };
    }
  }

  const probe = PROBE_MAP[protocol];
  if (!probe) {
    return {
      ...defaultResult(protocol, config.host, config.port),
      error: `No probe available for protocol ${protocol}`,
    };
  }

  return probe({ ...config, protocol });
}

/**
 * Batch fingerprint multiple services with concurrency control.
 * Validates all targets against ROE scope before starting.
 */
export async function batchFingerprint(config: BatchFingerprintConfig): Promise<FingerprintResult[]> {
  const { targets, engagementId, operatorId, timeoutMs = 10000, concurrency = 5, tryDefaultCreds = false } = config;

  // ROE scope validation for all targets
  if (engagementId) {
    try {
      const { filterInScopeTargets } = await import("./scope-guard");
      const scopeResult = await filterInScopeTargets({
        engagementId,
        targets: targets.map(t => ({ value: t.host })),
        tool: "Service Fingerprinter",
        operatorId: operatorId || "system",
      });
      // Only scan in-scope targets
      const inScopeHosts = new Set(scopeResult.inScope.map(t => t.value));
      const outOfScope = targets.filter(t => !inScopeHosts.has(t.host));
      if (outOfScope.length > 0) {
        console.warn(`[ServiceFingerprinter] ${outOfScope.length} targets out of scope, skipping`);
      }
    } catch {
      // If scope check fails, proceed with caution
    }
  }

  const results: FingerprintResult[] = [];
  const queue = [...targets];

  const worker = async () => {
    while (queue.length > 0) {
      const target = queue.shift();
      if (!target) break;
      const result = await fingerprintService({
        host: target.host,
        port: target.port,
        protocol: target.protocol,
        timeoutMs,
        engagementId,
        operatorId,
        tryDefaultCreds,
      });
      results.push(result);
    }
  };

  const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => worker());
  await Promise.all(workers);

  return results;
}

/**
 * Auto-fingerprint all admin services on a host based on open ports.
 * Takes Nmap scan results and runs protocol-specific probes on each discovered service.
 */
export async function autoFingerprint(
  host: string,
  openPorts: number[],
  options?: {
    engagementId?: number;
    operatorId?: string;
    timeoutMs?: number;
    tryDefaultCreds?: boolean;
  },
): Promise<FingerprintResult[]> {
  const targets = openPorts
    .map(port => ({
      host,
      port,
      protocol: detectProtocol(port),
    }))
    .filter((t): t is { host: string; port: number; protocol: ServiceProtocol } => t.protocol !== null);

  if (targets.length === 0) return [];

  return batchFingerprint({
    targets,
    engagementId: options?.engagementId,
    operatorId: options?.operatorId,
    timeoutMs: options?.timeoutMs,
    concurrency: 3,
    tryDefaultCreds: options?.tryDefaultCreds,
  });
}

/**
 * Generate a summary report from fingerprint results.
 */
export function summarizeFingerprints(results: FingerprintResult[]): {
  totalServices: number;
  successfulProbes: number;
  failedProbes: number;
  criticalRisks: number;
  highRisks: number;
  mediumRisks: number;
  lowRisks: number;
  servicesWithAnonymousAccess: FingerprintResult[];
  servicesWithDefaultCreds: FingerprintResult[];
  servicesWithoutTls: FingerprintResult[];
  servicesWithWeakAuth: FingerprintResult[];
  allCves: string[];
  allMitreTechniques: string[];
} {
  const successful = results.filter(r => !r.error);
  const failed = results.filter(r => !!r.error);

  const allRisks = results.flatMap(r => r.riskIndicators);
  const criticalRisks = allRisks.filter(r => r.severity === "critical").length;
  const highRisks = allRisks.filter(r => r.severity === "high").length;
  const mediumRisks = allRisks.filter(r => r.severity === "medium").length;
  const lowRisks = allRisks.filter(r => r.severity === "low").length;

  return {
    totalServices: results.length,
    successfulProbes: successful.length,
    failedProbes: failed.length,
    criticalRisks,
    highRisks,
    mediumRisks,
    lowRisks,
    servicesWithAnonymousAccess: results.filter(r => r.securityFlags.anonymousAccess),
    servicesWithDefaultCreds: results.filter(r => r.securityFlags.defaultCredentials),
    servicesWithoutTls: successful.filter(r => !r.securityFlags.tlsSupported),
    servicesWithWeakAuth: results.filter(r => r.securityFlags.weakCredentials || !r.securityFlags.authRequired),
    allCves: [...new Set(results.flatMap(r => r.potentialCves))],
    allMitreTechniques: [...new Set(results.flatMap(r => r.mitreRelevance))],
  };
}
