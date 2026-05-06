import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/service-fingerprinter.ts
import * as net from "net";
import * as tls from "tls";
import * as dgram from "dgram";
import * as crypto from "crypto";
function detectProtocol(port) {
  return PORT_PROTOCOL_MAP[port] ?? null;
}
function tcpConnect(host, port, timeoutMs) {
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
function tlsConnect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, rejectUnauthorized: false, timeout: timeoutMs },
      () => resolve(socket)
    );
    socket.setTimeout(timeoutMs);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`TLS connection timeout after ${timeoutMs}ms`));
    });
    socket.on("error", (err) => reject(err));
  });
}
function readBanner(socket, timeoutMs = 5e3) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      resolve(Buffer.alloc(0));
    }, timeoutMs);
    const chunks = [];
    socket.on("data", (data) => {
      chunks.push(data);
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
function sendAndReceive(socket, data, timeoutMs = 5e3) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(Buffer.alloc(0)), timeoutMs);
    const chunks = [];
    const onData = (chunk) => {
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
function defaultSecurityFlags() {
  return {
    tlsSupported: false,
    tlsRequired: false,
    tlsVersion: null,
    authRequired: true,
    anonymousAccess: false,
    weakCredentials: false,
    defaultCredentials: false,
    encryptionEnabled: false,
    signingEnabled: false
  };
}
function defaultResult(protocol, host, port) {
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
    riskIndicators: []
  };
}
async function fingerprintSSH(config) {
  const { host, port, timeoutMs = 1e4 } = config;
  const result = defaultResult("ssh", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;
      const sshMatch = banner.match(/^SSH-(\d+\.\d+)-(\S+)(?:\s+(.*))?/);
      if (sshMatch) {
        result.metadata.sshProtocolVersion = sshMatch[1];
        result.metadata.softwareVersion = sshMatch[2];
        if (sshMatch[3]) result.metadata.comments = sshMatch[3];
        const swParts = sshMatch[2].match(/^(\w+)[_-]?([\d.]+\w*)?/);
        if (swParts) {
          result.product = swParts[1];
          result.version = swParts[2] || null;
        }
        if (/ubuntu/i.test(banner)) result.os = "Ubuntu Linux";
        else if (/debian/i.test(banner)) result.os = "Debian Linux";
        else if (/centos|rhel|red\s*hat/i.test(banner)) result.os = "RHEL/CentOS";
        else if (/freebsd/i.test(banner)) result.os = "FreeBSD";
        else if (/windows/i.test(banner)) result.os = "Windows";
      }
      const clientIdent = "SSH-2.0-CalderaProbe_1.0\r\n";
      socket.write(clientIdent);
      const kexBuf = await readBanner(socket, 5e3);
      if (kexBuf.length > 17) {
        try {
          let offset = 0;
          for (let i = 0; i < Math.min(kexBuf.length - 1, 100); i++) {
            if (kexBuf[i] === 20) {
              offset = i + 1;
              break;
            }
          }
          if (offset > 0) {
            offset += 16;
            const readNameList = (buf, off) => {
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
            const hasshInput = [
              kexAlgos.names.join(","),
              encClientToServer.names.join(","),
              macClientToServer.names.join(","),
              compClientToServer.names.join(",")
            ].join(";");
            result.metadata.hasshServer = crypto.createHash("md5").update(hasshInput).digest("hex");
            result.securityFlags.encryptionEnabled = true;
            result.capabilities.kexInit = true;
            const weakKex = kexAlgos.names.filter((a) => /diffie-hellman-group1|diffie-hellman-group-exchange-sha1/i.test(a));
            const weakEnc = encClientToServer.names.filter((a) => /arcfour|blowfish|3des|cast128|des-cbc/i.test(a));
            const weakMac = macClientToServer.names.filter((a) => /hmac-md5|hmac-sha1-96|hmac-md5-96|umac-64/i.test(a));
            if (weakKex.length > 0) {
              result.metadata.weakKexAlgorithms = weakKex;
              result.riskIndicators.push({
                severity: "medium",
                title: "Weak SSH Key Exchange Algorithms",
                description: `Server supports weak KEX: ${weakKex.join(", ")}`,
                cweId: "CWE-327",
                mitreId: "T1557"
              });
            }
            if (weakEnc.length > 0) {
              result.metadata.weakEncryptionAlgorithms = weakEnc;
              result.riskIndicators.push({
                severity: "high",
                title: "Weak SSH Encryption Ciphers",
                description: `Server supports weak ciphers: ${weakEnc.join(", ")}`,
                cweId: "CWE-327",
                mitreId: "T1040"
              });
            }
            if (weakMac.length > 0) {
              result.metadata.weakMacAlgorithms = weakMac;
              result.riskIndicators.push({
                severity: "low",
                title: "Weak SSH MAC Algorithms",
                description: `Server supports weak MACs: ${weakMac.join(", ")}`,
                cweId: "CWE-328"
              });
            }
          }
        } catch {
          result.metadata.kexParseError = true;
        }
      }
      if (result.product === "OpenSSH" && result.version) {
        const ver = result.version.replace(/p\d+$/, "");
        const vNum = parseFloat(ver);
        if (vNum < 7) {
          result.potentialCves.push("CVE-2016-0777", "CVE-2016-0778");
          result.riskIndicators.push({
            severity: "critical",
            title: "Severely Outdated OpenSSH",
            description: `OpenSSH ${result.version} is critically outdated and vulnerable to multiple CVEs`,
            cweId: "CWE-1104"
          });
        } else if (vNum < 8) {
          result.potentialCves.push("CVE-2019-6111", "CVE-2019-6109");
        } else if (vNum >= 9.1 && vNum < 9.8) {
          result.potentialCves.push("CVE-2024-6387");
          result.riskIndicators.push({
            severity: "critical",
            title: "Potential regreSSHion (CVE-2024-6387)",
            description: `OpenSSH ${result.version} may be vulnerable to regreSSHion RCE`,
            cweId: "CWE-362",
            mitreId: "T1210"
          });
        }
      }
      result.mitreRelevance.push("T1021.004");
      result.capabilities.ssh = true;
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintSMTP(config) {
  const { host, port, timeoutMs = 15e3, tryDefaultCreds = false } = config;
  const result = defaultResult("smtp", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;
      const bannerMatch = banner.match(/^220\s+(\S+)\s+(?:E?SMTP\s+)?(\S+)(?:\s+(.*))?/i);
      if (bannerMatch) {
        result.metadata.hostname = bannerMatch[1];
        result.product = bannerMatch[2];
        const verMatch = (bannerMatch[3] || bannerMatch[2]).match(/([\d.]+)/);
        if (verMatch) result.version = verMatch[1];
      }
      if (/postfix/i.test(banner)) result.product = "Postfix";
      else if (/sendmail/i.test(banner)) result.product = "Sendmail";
      else if (/exim/i.test(banner)) result.product = "Exim";
      else if (/microsoft|exchange/i.test(banner)) {
        result.product = "Microsoft Exchange";
        result.os = "Windows";
      } else if (/dovecot/i.test(banner)) result.product = "Dovecot";
      else if (/haraka/i.test(banner)) result.product = "Haraka";
      const ehloResp = await sendAndReceive(socket, `EHLO probe.caldera.local\r
`, 5e3);
      const ehloText = ehloResp.toString("utf-8");
      result.metadata.ehloResponse = ehloText.trim();
      const ehloLines = ehloText.split("\n").map((l) => l.trim());
      const capabilities = {};
      const authMethods = [];
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
            result.securityFlags.authRequired = false;
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
      if (authMethods.includes("PLAIN") || authMethods.includes("LOGIN")) {
        if (!capabilities.starttls) {
          result.riskIndicators.push({
            severity: "high",
            title: "SMTP Plaintext Authentication Without TLS",
            description: "Server supports PLAIN/LOGIN auth without STARTTLS, credentials sent in cleartext",
            cweId: "CWE-319",
            mitreId: "T1040"
          });
          result.securityFlags.weakCredentials = true;
        }
      }
      if (capabilities.vrfy) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP VRFY Command Enabled",
          description: "VRFY allows user enumeration \u2014 attackers can verify valid email addresses",
          cweId: "CWE-200",
          mitreId: "T1589.002"
        });
      }
      if (capabilities.expn) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP EXPN Command Enabled",
          description: "EXPN reveals mailing list members \u2014 information disclosure risk",
          cweId: "CWE-200",
          mitreId: "T1589.002"
        });
      }
      if (tryDefaultCreds) {
        try {
          const relayTest = await sendAndReceive(socket, `MAIL FROM:<test@probe.caldera.local>\r
`, 3e3);
          const relayText = relayTest.toString("utf-8");
          if (/^250/m.test(relayText)) {
            const rcptTest = await sendAndReceive(socket, `RCPT TO:<test@example.com>\r
`, 3e3);
            const rcptText = rcptTest.toString("utf-8");
            if (/^250/m.test(rcptText)) {
              result.securityFlags.anonymousAccess = true;
              result.riskIndicators.push({
                severity: "critical",
                title: "SMTP Open Relay Detected",
                description: "Server accepts mail for arbitrary external domains without authentication",
                cweId: "CWE-284",
                mitreId: "T1071.003"
              });
            }
            await sendAndReceive(socket, "RSET\r\n", 2e3);
          }
        } catch {
        }
      }
      socket.write("QUIT\r\n");
      if (!capabilities.starttls && (port === 25 || port === 587)) {
        result.riskIndicators.push({
          severity: "medium",
          title: "SMTP STARTTLS Not Supported",
          description: "Server does not support STARTTLS \u2014 email transmitted in plaintext",
          cweId: "CWE-319",
          mitreId: "T1040"
        });
      }
      result.mitreRelevance.push("T1071.003");
      if (port === 25) result.mitreRelevance.push("T1048.002");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintFTP(config) {
  const { host, port, timeoutMs = 1e4, tryDefaultCreds = false } = config;
  const result = defaultResult("ftp", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;
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
      const featResp = await sendAndReceive(socket, "FEAT\r\n", 3e3);
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
      if (tryDefaultCreds) {
        const userResp = await sendAndReceive(socket, "USER anonymous\r\n", 3e3);
        const userText = userResp.toString("utf-8");
        if (/^331/m.test(userText)) {
          const passResp = await sendAndReceive(socket, "PASS anonymous@probe.caldera.local\r\n", 3e3);
          const passText = passResp.toString("utf-8");
          if (/^230/m.test(passText)) {
            result.securityFlags.anonymousAccess = true;
            result.riskIndicators.push({
              severity: "high",
              title: "FTP Anonymous Login Allowed",
              description: "Server allows anonymous FTP access \u2014 potential data exposure",
              cweId: "CWE-284",
              mitreId: "T1078.001"
            });
            try {
              const pwdResp = await sendAndReceive(socket, "PWD\r\n", 2e3);
              result.metadata.anonymousRoot = pwdResp.toString("utf-8").trim();
            } catch {
            }
            await sendAndReceive(socket, "QUIT\r\n", 2e3);
          }
        }
      }
      if (!result.securityFlags.tlsSupported) {
        result.riskIndicators.push({
          severity: "high",
          title: "FTP Without TLS Support",
          description: "Server does not support AUTH TLS/SSL \u2014 credentials and data transmitted in cleartext",
          cweId: "CWE-319",
          mitreId: "T1040"
        });
      }
      if (result.product === "vsftpd" && result.version === "2.3.4") {
        result.potentialCves.push("CVE-2011-2523");
        result.riskIndicators.push({
          severity: "critical",
          title: "vsftpd 2.3.4 Backdoor",
          description: "This version contains a known backdoor triggered by :) in the username",
          cweId: "CWE-506",
          mitreId: "T1190"
        });
      }
      if (result.product === "ProFTPD") {
        const ver = parseFloat(result.version || "0");
        if (ver > 0 && ver <= 1.36) {
          result.potentialCves.push("CVE-2019-12815");
        }
      }
      result.mitreRelevance.push("T1021.002");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintSNMP(config) {
  const { host, port = 161, timeoutMs = 1e4, tryDefaultCreds = true } = config;
  const result = defaultResult("snmp", host, port);
  const start = Date.now();
  try {
    const socket = dgram.createSocket("udp4");
    const sendSnmpGet = (community) => {
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          resolve(null);
        }, 5e3);
        const communityBuf = Buffer.from(community, "ascii");
        const oid = Buffer.from([
          6,
          8,
          43,
          6,
          1,
          2,
          1,
          1,
          1,
          0
        ]);
        const nullVal = Buffer.from([5, 0]);
        const varbind = Buffer.concat([
          Buffer.from([48, oid.length + nullVal.length]),
          oid,
          nullVal
        ]);
        const varbindList = Buffer.concat([
          Buffer.from([48, varbind.length]),
          varbind
        ]);
        const requestId = Buffer.from([2, 4, 0, 0, 0, 1]);
        const errorStatus = Buffer.from([2, 1, 0]);
        const errorIndex = Buffer.from([2, 1, 0]);
        const pduBody = Buffer.concat([requestId, errorStatus, errorIndex, varbindList]);
        const pdu = Buffer.concat([
          Buffer.from([160, pduBody.length]),
          pduBody
        ]);
        const versionField = Buffer.from([2, 1, 0]);
        const communityField = Buffer.concat([
          Buffer.from([4, communityBuf.length]),
          communityBuf
        ]);
        const messageBody = Buffer.concat([versionField, communityField, pdu]);
        const message = Buffer.concat([
          Buffer.from([48, messageBody.length]),
          messageBody
        ]);
        socket.once("message", (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        socket.send(message, 0, message.length, port, host);
      });
    };
    const communities = tryDefaultCreds ? ["public", "private", "community", "snmp", "monitor", "admin"] : ["public"];
    const validCommunities = [];
    for (const community of communities) {
      const resp = await sendSnmpGet(community);
      if (resp && resp.length > 10) {
        validCommunities.push(community);
        try {
          let sysDescr = "";
          for (let i = 0; i < resp.length - 2; i++) {
            if (resp[i] === 4 && resp[i + 1] > 5 && resp[i + 1] < 200) {
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
            if (/linux/i.test(sysDescr)) result.os = "Linux";
            else if (/windows/i.test(sysDescr)) result.os = "Windows";
            else if (/cisco/i.test(sysDescr)) {
              result.product = "Cisco IOS";
              result.os = "Cisco IOS";
            } else if (/juniper|junos/i.test(sysDescr)) {
              result.product = "Juniper JunOS";
              result.os = "JunOS";
            } else if (/fortinet|fortigate/i.test(sysDescr)) result.product = "FortiGate";
            else if (/palo alto|pan-os/i.test(sysDescr)) result.product = "Palo Alto PAN-OS";
            else if (/hp|hewlett/i.test(sysDescr)) result.product = "HP";
            else if (/vmware/i.test(sysDescr)) result.product = "VMware ESXi";
            const verMatch = sysDescr.match(/(?:version|ver\.?|v)\s*([\d.]+)/i);
            if (verMatch) result.version = verMatch[1];
          }
        } catch {
        }
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
          description: "Server responds to default 'public' community string \u2014 information disclosure",
          cweId: "CWE-798",
          mitreId: "T1552.001"
        });
      }
      if (validCommunities.includes("private")) {
        result.securityFlags.defaultCredentials = true;
        result.riskIndicators.push({
          severity: "critical",
          title: "SNMP Default Write Community String 'private'",
          description: "Server responds to default 'private' community \u2014 read/write access to device configuration",
          cweId: "CWE-798",
          mitreId: "T1552.001"
        });
      }
      if (validCommunities.length > 1) {
        result.riskIndicators.push({
          severity: "medium",
          title: "Multiple SNMP Community Strings Accepted",
          description: `Server accepts ${validCommunities.length} community strings: ${validCommunities.join(", ")}`,
          cweId: "CWE-287"
        });
      }
    }
    result.mitreRelevance.push("T1602.001");
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintRDP(config) {
  const { host, port = 3389, timeoutMs = 1e4 } = config;
  const result = defaultResult("rdp", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const x224CR = Buffer.from([
        // TPKT header
        3,
        0,
        0,
        19,
        // version=3, length=19
        // X.224 CR TPDU
        14,
        // length indicator
        224,
        // CR TPDU code
        0,
        0,
        // DST-REF
        0,
        0,
        // SRC-REF
        0,
        // class 0
        // RDP Negotiation Request
        1,
        // TYPE_RDP_NEG_REQ
        0,
        // flags
        8,
        0,
        // length = 8
        11,
        0,
        0,
        0
        // requestedProtocols: TLS | CredSSP | RDSTLS
      ]);
      socket.write(x224CR);
      const respBuf = await readBanner(socket, 5e3);
      if (respBuf.length >= 11) {
        result.rawResponse = respBuf.toString("hex");
        result.capabilities.rdp = true;
        result.product = "Microsoft RDP";
        result.os = "Windows";
        const tpduCode = respBuf[5];
        if (tpduCode === 208) {
          if (respBuf.length >= 19) {
            const negType = respBuf[11];
            if (negType === 2) {
              const selectedProtocol = respBuf.readUInt32LE(15);
              result.metadata.selectedProtocol = selectedProtocol;
              if (selectedProtocol & 1) {
                result.securityFlags.tlsSupported = true;
                result.metadata.negotiatedSecurity = "TLS";
              }
              if (selectedProtocol & 2) {
                result.capabilities.nla = true;
                result.securityFlags.authRequired = true;
                result.metadata.negotiatedSecurity = "CredSSP (NLA)";
              }
              if (selectedProtocol & 8) {
                result.metadata.negotiatedSecurity = "RDSTLS";
              }
              if (selectedProtocol === 0) {
                result.metadata.negotiatedSecurity = "Standard RDP Security";
                result.riskIndicators.push({
                  severity: "high",
                  title: "RDP Standard Security (No NLA/TLS)",
                  description: "Server uses legacy RDP security without NLA or TLS \u2014 vulnerable to MITM",
                  cweId: "CWE-319",
                  mitreId: "T1557"
                });
              }
            } else if (negType === 3) {
              const failureCode = respBuf.readUInt32LE(15);
              result.metadata.negotiationFailure = failureCode;
              result.riskIndicators.push({
                severity: "info",
                title: "RDP Negotiation Failure",
                description: `Server rejected security negotiation with code ${failureCode}`
              });
            }
          }
        }
        if (!result.capabilities.nla) {
          result.riskIndicators.push({
            severity: "high",
            title: "RDP Network Level Authentication (NLA) Not Required",
            description: "NLA is not enforced \u2014 server vulnerable to pre-authentication attacks",
            cweId: "CWE-287",
            mitreId: "T1021.001"
          });
        }
        result.metadata.blueKeepNote = "Requires dedicated exploit probe \u2014 not tested in fingerprint phase";
        result.potentialCves.push("CVE-2019-0708");
      }
      result.mitreRelevance.push("T1021.001");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintSMB(config) {
  const { host, port = 445, timeoutMs = 1e4 } = config;
  const result = defaultResult("smb", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const smbNeg = Buffer.alloc(140);
      let offset = 0;
      smbNeg[offset++] = 0;
      offset += 3;
      const headerStart = offset;
      smbNeg.write("\xFESMB", offset);
      offset += 4;
      smbNeg.writeUInt16LE(64, offset);
      offset += 2;
      smbNeg.writeUInt16LE(0, offset);
      offset += 2;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeUInt16LE(0, offset);
      offset += 2;
      smbNeg.writeUInt16LE(1, offset);
      offset += 2;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeBigUInt64LE(1n, offset);
      offset += 8;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeBigUInt64LE(0n, offset);
      offset += 8;
      smbNeg.fill(0, offset, offset + 16);
      offset += 16;
      smbNeg.writeUInt16LE(36, offset);
      offset += 2;
      smbNeg.writeUInt16LE(5, offset);
      offset += 2;
      smbNeg.writeUInt16LE(1, offset);
      offset += 2;
      smbNeg.writeUInt16LE(0, offset);
      offset += 2;
      smbNeg.writeUInt32LE(127, offset);
      offset += 4;
      crypto.randomFillSync(smbNeg, offset, 16);
      offset += 16;
      smbNeg.writeUInt32LE(0, offset);
      offset += 4;
      smbNeg.writeUInt16LE(0, offset);
      offset += 2;
      smbNeg.writeUInt16LE(0, offset);
      offset += 2;
      smbNeg.writeUInt16LE(514, offset);
      offset += 2;
      smbNeg.writeUInt16LE(528, offset);
      offset += 2;
      smbNeg.writeUInt16LE(768, offset);
      offset += 2;
      smbNeg.writeUInt16LE(770, offset);
      offset += 2;
      smbNeg.writeUInt16LE(785, offset);
      offset += 2;
      const totalLen = offset - 4;
      smbNeg[1] = totalLen >> 16 & 255;
      smbNeg[2] = totalLen >> 8 & 255;
      smbNeg[3] = totalLen & 255;
      const packet = smbNeg.subarray(0, offset);
      socket.write(packet);
      const respBuf = await readBanner(socket, 5e3);
      if (respBuf.length >= 68) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");
        result.product = "Microsoft SMB";
        result.os = "Windows";
        const protoId = respBuf.subarray(4, 8).toString("ascii");
        if (protoId === "\xFESMB") {
          const dialectOffset = 4 + 64 + 4;
          if (respBuf.length > dialectOffset + 2) {
            const securityMode = respBuf.readUInt16LE(4 + 64 + 2);
            const dialect = respBuf.readUInt16LE(dialectOffset);
            const dialectMap = {
              514: "SMB 2.0.2",
              528: "SMB 2.1",
              768: "SMB 3.0",
              770: "SMB 3.0.2",
              785: "SMB 3.1.1"
            };
            result.version = dialectMap[dialect] || `0x${dialect.toString(16)}`;
            result.metadata.smbDialect = dialect;
            result.metadata.smbVersion = result.version;
            result.securityFlags.signingEnabled = (securityMode & 1) !== 0;
            const signingRequired = (securityMode & 2) !== 0;
            result.metadata.signingRequired = signingRequired;
            if (!signingRequired) {
              result.riskIndicators.push({
                severity: "medium",
                title: "SMB Signing Not Required",
                description: "Server does not require SMB signing \u2014 vulnerable to relay attacks",
                cweId: "CWE-345",
                mitreId: "T1557.001"
              });
            }
            if (dialect < 514) {
              result.riskIndicators.push({
                severity: "critical",
                title: "SMBv1 Detected",
                description: "Server supports SMBv1 \u2014 vulnerable to EternalBlue and other critical exploits",
                cweId: "CWE-1104",
                mitreId: "T1210"
              });
              result.potentialCves.push("CVE-2017-0144");
            }
            if (dialect >= 768) {
              result.securityFlags.encryptionEnabled = true;
              result.capabilities.smbEncryption = true;
            }
          }
        }
        result.capabilities.smb = true;
      }
      result.mitreRelevance.push("T1021.002");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintLDAP(config) {
  const { host, port = 389, timeoutMs = 1e4 } = config;
  const result = defaultResult("ldap", host, port);
  const start = Date.now();
  try {
    const useTls = port === 636;
    const socket = useTls ? await tlsConnect(host, port, timeoutMs) : await tcpConnect(host, port, timeoutMs);
    if (useTls) {
      result.securityFlags.tlsSupported = true;
      result.securityFlags.tlsRequired = true;
      const tlsSock = socket;
      result.securityFlags.tlsVersion = tlsSock.getProtocol() || null;
    }
    try {
      const searchRequest = Buffer.from([
        // LDAP Message
        48,
        37,
        // SEQUENCE, length
        2,
        1,
        1,
        // MessageID = 1
        // SearchRequest (Application 3)
        99,
        32,
        // BaseDN: "" (empty = RootDSE)
        4,
        0,
        // Scope: baseObject (0)
        10,
        1,
        0,
        // DerefAliases: neverDerefAliases (0)
        10,
        1,
        0,
        // SizeLimit: 0
        2,
        1,
        0,
        // TimeLimit: 30
        2,
        1,
        30,
        // TypesOnly: false
        1,
        1,
        0,
        // Filter: present(objectClass)
        135,
        11,
        111,
        98,
        106,
        101,
        99,
        116,
        67,
        108,
        97,
        115,
        115,
        // Attributes: empty (return all)
        48,
        0
      ]);
      socket.write(searchRequest);
      const respBuf = await readBanner(socket, 5e3);
      if (respBuf.length > 10) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 500)).toString("hex");
        result.capabilities.ldap = true;
        const respText = respBuf.toString("utf-8", 0, Math.min(respBuf.length, 2e3));
        if (/namingContexts/i.test(respText)) {
          result.securityFlags.anonymousAccess = true;
          result.capabilities.anonymousBind = true;
          const dnMatches = respText.match(/(?:DC|dc)=[\w.-]+(?:,(?:DC|dc)=[\w.-]+)*/g);
          if (dnMatches) {
            result.metadata.namingContexts = [...new Set(dnMatches)];
          }
          result.riskIndicators.push({
            severity: "high",
            title: "LDAP Anonymous Bind Allowed",
            description: "Server allows anonymous LDAP queries \u2014 directory information exposed",
            cweId: "CWE-284",
            mitreId: "T1087.002"
          });
        }
        if (/Microsoft/i.test(respText) || /Active Directory/i.test(respText)) {
          result.product = "Microsoft Active Directory";
          result.os = "Windows";
          result.mitreRelevance.push("T1087.002");
        } else if (/OpenLDAP/i.test(respText) || /openldap/i.test(respText)) {
          result.product = "OpenLDAP";
        } else if (/389 Directory/i.test(respText)) {
          result.product = "389 Directory Server";
        } else if (/ApacheDS/i.test(respText)) {
          result.product = "Apache Directory Server";
        }
        const verMatch = respText.match(/(?:vendorVersion|supportedLDAPVersion)[:\s]*([\d.]+)/i);
        if (verMatch) result.version = verMatch[1];
        if (/1\.3\.6\.1\.4\.1\.1466\.20037/i.test(respText)) {
          result.securityFlags.tlsSupported = true;
          result.capabilities.startTls = true;
        }
      } else {
        result.securityFlags.authRequired = true;
      }
      result.mitreRelevance.push("T1018");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintTelnet(config) {
  const { host, port = 23, timeoutMs = 1e4 } = config;
  const result = defaultResult("telnet", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      const banner = bannerBuf.toString("utf-8").replace(/[\x00-\x1f]/g, "").trim();
      result.banner = banner;
      result.rawResponse = bannerBuf.toString("hex").substring(0, 400);
      const iacOptions = [];
      for (let i = 0; i < bannerBuf.length - 2; i++) {
        if (bannerBuf[i] === 255) {
          const cmd = bannerBuf[i + 1];
          const opt = bannerBuf[i + 2];
          const cmdName = cmd === 251 ? "WILL" : cmd === 253 ? "DO" : cmd === 252 ? "WONT" : cmd === 254 ? "DONT" : `0x${cmd.toString(16)}`;
          iacOptions.push(`${cmdName} ${opt}`);
        }
      }
      result.metadata.telnetOptions = iacOptions;
      if (/cisco/i.test(banner)) {
        result.product = "Cisco IOS";
        result.os = "Cisco IOS";
      } else if (/juniper|junos/i.test(banner)) {
        result.product = "Juniper JunOS";
        result.os = "JunOS";
      } else if (/linux|ubuntu|debian|centos/i.test(banner)) result.os = "Linux";
      else if (/windows/i.test(banner)) result.os = "Windows";
      else if (/busybox/i.test(banner)) {
        result.product = "BusyBox";
        result.os = "Embedded Linux";
      }
      result.securityFlags.encryptionEnabled = false;
      result.riskIndicators.push({
        severity: "critical",
        title: "Telnet Service Exposed",
        description: "Telnet transmits all data including credentials in cleartext \u2014 should be replaced with SSH",
        cweId: "CWE-319",
        mitreId: "T1021.004"
      });
      result.capabilities.telnet = true;
      result.mitreRelevance.push("T1021");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintMySQL(config) {
  const { host, port = 3306, timeoutMs = 1e4 } = config;
  const result = defaultResult("mysql", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      if (bannerBuf.length > 4) {
        result.rawResponse = bannerBuf.subarray(0, Math.min(bannerBuf.length, 200)).toString("hex");
        const payloadStart = 4;
        const protocolVersion = bannerBuf[payloadStart];
        result.metadata.protocolVersion = protocolVersion;
        if (protocolVersion === 255) {
          const errorMsg = bannerBuf.subarray(payloadStart + 3).toString("utf-8").trim();
          result.banner = `Error: ${errorMsg}`;
          result.metadata.connectionError = errorMsg;
          if (/too many connections/i.test(errorMsg)) {
            result.riskIndicators.push({
              severity: "info",
              title: "MySQL Max Connections Reached",
              description: "Server is at connection limit \u2014 may indicate heavy load or misconfiguration"
            });
          }
        } else if (protocolVersion === 10 || protocolVersion === 9) {
          let versionEnd = payloadStart + 1;
          while (versionEnd < bannerBuf.length && bannerBuf[versionEnd] !== 0) versionEnd++;
          const versionStr = bannerBuf.subarray(payloadStart + 1, versionEnd).toString("utf-8");
          result.version = versionStr;
          result.banner = `MySQL ${versionStr}`;
          if (/mariadb/i.test(versionStr)) result.product = "MariaDB";
          else if (/percona/i.test(versionStr)) result.product = "Percona Server";
          else result.product = "MySQL";
          if (protocolVersion === 10 && versionEnd + 1 < bannerBuf.length) {
            let off = versionEnd + 1 + 4;
            off += 9;
            if (off + 2 <= bannerBuf.length) {
              const capLow = bannerBuf.readUInt16LE(off);
              off += 2;
              if (off < bannerBuf.length) {
                result.metadata.charset = bannerBuf[off];
                off += 1;
              }
              if (off + 2 <= bannerBuf.length) {
                result.metadata.statusFlags = bannerBuf.readUInt16LE(off);
                off += 2;
              }
              if (off + 2 <= bannerBuf.length) {
                const capHigh = bannerBuf.readUInt16LE(off);
                const capabilities = capHigh << 16 | capLow;
                off += 2;
                result.capabilities.ssl = (capabilities & 2048) !== 0;
                result.capabilities.compress = (capabilities & 32) !== 0;
                result.capabilities.secureConnection = (capabilities & 32768) !== 0;
                result.capabilities.pluginAuth = (capabilities & 524288) !== 0;
                result.securityFlags.tlsSupported = result.capabilities.ssl;
                off += 1 + 10;
                if (off < bannerBuf.length) {
                  const authDataLen = Math.max(13, bannerBuf[off - 11] - 8);
                  off += authDataLen;
                  if (off < bannerBuf.length) {
                    let pluginEnd = off;
                    while (pluginEnd < bannerBuf.length && bannerBuf[pluginEnd] !== 0) pluginEnd++;
                    const authPlugin = bannerBuf.subarray(off, pluginEnd).toString("utf-8");
                    result.metadata.authPlugin = authPlugin;
                    if (authPlugin === "mysql_native_password") {
                      result.riskIndicators.push({
                        severity: "low",
                        title: "MySQL Using Legacy Auth Plugin",
                        description: "Server uses mysql_native_password \u2014 consider upgrading to caching_sha2_password",
                        cweId: "CWE-327"
                      });
                    }
                  }
                }
              }
            }
          }
          if (!result.securityFlags.tlsSupported) {
            result.riskIndicators.push({
              severity: "high",
              title: "MySQL TLS Not Supported",
              description: "Server does not support SSL/TLS \u2014 database connections are unencrypted",
              cweId: "CWE-319",
              mitreId: "T1040"
            });
          }
        }
        result.capabilities.mysql = true;
        result.mitreRelevance.push("T1505.001");
      }
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintPostgreSQL(config) {
  const { host, port = 5432, timeoutMs = 1e4 } = config;
  const result = defaultResult("postgresql", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const sslRequest = Buffer.alloc(8);
      sslRequest.writeUInt32BE(8, 0);
      sslRequest.writeUInt32BE(80877103, 4);
      socket.write(sslRequest);
      const sslResp = await readBanner(socket, 3e3);
      if (sslResp.length > 0) {
        const sslByte = sslResp[0];
        if (sslByte === 83) {
          result.securityFlags.tlsSupported = true;
          result.capabilities.ssl = true;
        } else if (sslByte === 78) {
          result.securityFlags.tlsSupported = false;
          result.riskIndicators.push({
            severity: "high",
            title: "PostgreSQL SSL Not Supported",
            description: "Server does not support SSL \u2014 database connections are unencrypted",
            cweId: "CWE-319",
            mitreId: "T1040"
          });
        }
      }
      socket.destroy();
      const socket2 = await tcpConnect(host, port, timeoutMs);
      try {
        const user = "probe";
        const database = "postgres";
        const params = `user\0${user}\0database\0${database}\0\0`;
        const startupLen = 4 + 4 + params.length;
        const startup = Buffer.alloc(startupLen);
        startup.writeUInt32BE(startupLen, 0);
        startup.writeUInt32BE(196608, 4);
        startup.write(params, 8, "utf-8");
        socket2.write(startup);
        const respBuf = await readBanner(socket2, 5e3);
        if (respBuf.length > 0) {
          const msgType = String.fromCharCode(respBuf[0]);
          result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");
          if (msgType === "R") {
            if (respBuf.length >= 8) {
              const authType = respBuf.readUInt32BE(5);
              const authNames = {
                0: "trust (no auth)",
                2: "kerberos",
                3: "cleartext password",
                5: "md5",
                7: "gss",
                8: "gss-continue",
                9: "sspi",
                10: "sasl"
              };
              result.metadata.authMethod = authNames[authType] || `unknown(${authType})`;
              if (authType === 0) {
                result.securityFlags.authRequired = false;
                result.securityFlags.anonymousAccess = true;
                result.riskIndicators.push({
                  severity: "critical",
                  title: "PostgreSQL Trust Authentication",
                  description: "Server uses trust authentication \u2014 no password required for connections",
                  cweId: "CWE-287",
                  mitreId: "T1078"
                });
              } else if (authType === 3) {
                result.riskIndicators.push({
                  severity: "high",
                  title: "PostgreSQL Cleartext Password Auth",
                  description: "Server uses cleartext password authentication \u2014 credentials sent unencrypted",
                  cweId: "CWE-319"
                });
              }
            }
          } else if (msgType === "E") {
            const errText = respBuf.subarray(5).toString("utf-8").replace(/\0/g, " ").trim();
            result.banner = errText;
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
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintMSSQL(config) {
  const { host, port = 1433, timeoutMs = 1e4 } = config;
  const result = defaultResult("mssql", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const prelogin = Buffer.from([
        // TDS Header
        18,
        // Type: Pre-Login
        1,
        // Status: EOM
        0,
        47,
        // Length
        0,
        0,
        // SPID
        0,
        // PacketID
        0,
        // Window
        // Pre-Login options
        0,
        0,
        21,
        0,
        6,
        // VERSION: offset=21, len=6
        1,
        0,
        27,
        0,
        1,
        // ENCRYPTION: offset=27, len=1
        2,
        0,
        28,
        0,
        1,
        // INSTOPT: offset=28, len=1
        255,
        // Terminator
        // VERSION data (6 bytes): major.minor.build.sub
        15,
        0,
        7,
        208,
        0,
        0,
        // ENCRYPTION data (1 byte): 0x02 = NOT_SUP
        2,
        // INSTOPT data (1 byte)
        0
      ]);
      socket.write(prelogin);
      const respBuf = await readBanner(socket, 5e3);
      if (respBuf.length >= 8) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 200)).toString("hex");
        result.product = "Microsoft SQL Server";
        result.os = "Windows";
        const tdsType = respBuf[0];
        if (tdsType === 4) {
          let off = 8;
          while (off < respBuf.length && respBuf[off] !== 255) {
            const optType = respBuf[off];
            const optOffset = respBuf.readUInt16BE(off + 1) + 8;
            const optLen = respBuf.readUInt16BE(off + 3);
            off += 5;
            if (optType === 0 && optLen >= 6 && optOffset + optLen <= respBuf.length) {
              const major = respBuf[optOffset];
              const minor = respBuf[optOffset + 1];
              const build = respBuf.readUInt16BE(optOffset + 2);
              result.version = `${major}.${minor}.${build}`;
              result.metadata.sqlServerVersion = { major, minor, build };
              const editionMap = {
                8: "SQL Server 2000",
                9: "SQL Server 2005",
                10: "SQL Server 2008/2008R2",
                11: "SQL Server 2012",
                12: "SQL Server 2014",
                13: "SQL Server 2016",
                14: "SQL Server 2017",
                15: "SQL Server 2019",
                16: "SQL Server 2022"
              };
              result.metadata.edition = editionMap[major] || `SQL Server (v${major})`;
            }
            if (optType === 1 && optLen >= 1 && optOffset < respBuf.length) {
              const encByte = respBuf[optOffset];
              const encMap = {
                0: "off",
                1: "on",
                2: "not_supported",
                3: "required"
              };
              result.metadata.encryption = encMap[encByte] || `unknown(${encByte})`;
              result.securityFlags.encryptionEnabled = encByte === 1 || encByte === 3;
              result.securityFlags.tlsSupported = encByte !== 2;
              if (encByte === 0 || encByte === 2) {
                result.riskIndicators.push({
                  severity: "high",
                  title: "MSSQL Encryption Not Enabled",
                  description: `SQL Server encryption is ${encMap[encByte]} \u2014 connections may be unencrypted`,
                  cweId: "CWE-319",
                  mitreId: "T1040"
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
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintRedis(config) {
  const { host, port = 6379, timeoutMs = 1e4 } = config;
  const result = defaultResult("redis", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const infoCmd = "*1\r\n$4\r\nINFO\r\n";
      socket.write(infoCmd);
      const respBuf = await readBanner(socket, 5e3);
      const respText = respBuf.toString("utf-8");
      result.rawResponse = respText.substring(0, 500);
      result.product = "Redis";
      if (respText.startsWith("-NOAUTH") || respText.startsWith("-ERR")) {
        result.securityFlags.authRequired = true;
        result.banner = respText.trim();
        if (/NOAUTH/i.test(respText)) {
          result.metadata.authRequired = true;
        }
      } else if (respText.startsWith("$") || respText.startsWith("+")) {
        result.securityFlags.authRequired = false;
        result.securityFlags.anonymousAccess = true;
        result.riskIndicators.push({
          severity: "critical",
          title: "Redis No Authentication Required",
          description: "Redis server accepts commands without authentication \u2014 full read/write access to data",
          cweId: "CWE-287",
          mitreId: "T1078"
        });
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
        const configResp = await sendAndReceive(socket, "*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$10\r\nprotected-mode\r\n", 3e3);
        const configText = configResp.toString("utf-8");
        if (/no/i.test(configText)) {
          result.riskIndicators.push({
            severity: "critical",
            title: "Redis Protected Mode Disabled",
            description: "Redis protected-mode is off \u2014 server accepts connections from any IP",
            cweId: "CWE-284"
          });
        }
        result.banner = `Redis ${result.version || "unknown"} (no auth)`;
      }
      result.capabilities.redis = true;
      result.mitreRelevance.push("T1005");
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintMongoDB(config) {
  const { host, port = 27017, timeoutMs = 1e4 } = config;
  const result = defaultResult("mongodb", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bsonDoc = Buffer.from([
        // Document length (will be calculated)
        0,
        0,
        0,
        0,
        // isMaster: 1 (int32)
        16,
        // type: int32
        ...Buffer.from("isMaster\0"),
        1,
        0,
        0,
        0,
        // value: 1
        // $db: "admin"
        2,
        // type: string
        ...Buffer.from("$db\0"),
        6,
        0,
        0,
        0,
        // string length (including null)
        ...Buffer.from("admin\0"),
        // Document terminator
        0
      ]);
      bsonDoc.writeInt32LE(bsonDoc.length, 0);
      const header = Buffer.alloc(16 + 4 + 1);
      const totalLen = header.length + bsonDoc.length;
      header.writeInt32LE(totalLen, 0);
      header.writeInt32LE(1, 4);
      header.writeInt32LE(0, 8);
      header.writeInt32LE(2013, 12);
      header.writeUInt32LE(0, 16);
      header[20] = 0;
      socket.write(Buffer.concat([header, bsonDoc]));
      const respBuf = await readBanner(socket, 5e3);
      if (respBuf.length > 20) {
        result.rawResponse = respBuf.subarray(0, Math.min(respBuf.length, 300)).toString("hex");
        result.product = "MongoDB";
        const respText = respBuf.toString("utf-8", 0, Math.min(respBuf.length, 2e3));
        const verMatch = respText.match(/version\x00.{4}([\d.]+)/);
        if (verMatch) result.version = verMatch[1];
        if (/ismaster/i.test(respText) || /isWritablePrimary/i.test(respText)) {
          result.capabilities.mongodb = true;
          result.securityFlags.anonymousAccess = true;
          result.riskIndicators.push({
            severity: "high",
            title: "MongoDB Accepts Unauthenticated Commands",
            description: "Server responds to isMaster without authentication \u2014 check if auth is enforced",
            cweId: "CWE-287",
            mitreId: "T1078"
          });
        }
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
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintVNC(config) {
  const { host, port = 5900, timeoutMs = 1e4 } = config;
  const result = defaultResult("vnc", host, port);
  const start = Date.now();
  try {
    const socket = await tcpConnect(host, port, timeoutMs);
    try {
      const bannerBuf = await readBanner(socket, 5e3);
      const banner = bannerBuf.toString("utf-8").trim();
      result.banner = banner;
      result.rawResponse = banner;
      const rfbMatch = banner.match(/RFB\s+(\d{3})\.(\d{3})/);
      if (rfbMatch) {
        result.version = `${parseInt(rfbMatch[1])}.${parseInt(rfbMatch[2])}`;
        result.metadata.rfbVersion = result.version;
        result.product = "VNC";
        socket.write(`RFB 003.008
`);
        const secBuf = await readBanner(socket, 3e3);
        if (secBuf.length > 0) {
          const numSecTypes = secBuf[0];
          const secTypes = [];
          for (let i = 1; i <= numSecTypes && i < secBuf.length; i++) {
            secTypes.push(secBuf[i]);
          }
          result.metadata.securityTypes = secTypes;
          const secTypeNames = {
            0: "Invalid",
            1: "None",
            2: "VNC Authentication",
            5: "RA2",
            6: "RA2ne",
            16: "Tight",
            17: "Ultra",
            18: "TLS",
            19: "VeNCrypt",
            30: "Apple Remote Desktop"
          };
          result.metadata.securityTypeNames = secTypes.map((t) => secTypeNames[t] || `Unknown(${t})`);
          if (secTypes.includes(1)) {
            result.securityFlags.authRequired = false;
            result.securityFlags.anonymousAccess = true;
            result.riskIndicators.push({
              severity: "critical",
              title: "VNC No Authentication Required",
              description: "VNC server allows connections without any authentication",
              cweId: "CWE-287",
              mitreId: "T1021.005"
            });
          }
          if (secTypes.includes(2) && !secTypes.includes(18) && !secTypes.includes(19)) {
            result.riskIndicators.push({
              severity: "high",
              title: "VNC Without Encryption",
              description: "VNC uses password authentication but no TLS/encryption \u2014 credentials and screen data in cleartext",
              cweId: "CWE-319",
              mitreId: "T1040"
            });
          }
          if (secTypes.includes(18) || secTypes.includes(19)) {
            result.securityFlags.tlsSupported = true;
            result.securityFlags.encryptionEnabled = true;
          }
        }
        result.capabilities.vnc = true;
        result.mitreRelevance.push("T1021.005");
      }
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintHTTP(config) {
  const isHttps = config.protocol === "https" || [443, 4443, 8443, 9443].includes(config.port);
  const result = defaultResult(isHttps ? "https" : "http", config.host, config.port);
  const start = Date.now();
  try {
    const connectFn = isHttps ? tlsConnect : tcpConnect;
    const socket = await connectFn(config.host, config.port, config.timeoutMs || 1e4);
    try {
      if (isHttps && "getPeerCertificate" in socket) {
        const tlsSock = socket;
        result.securityFlags.tlsSupported = true;
        result.securityFlags.encryptionEnabled = true;
        const proto = tlsSock.getProtocol?.();
        if (proto) result.securityFlags.tlsVersion = proto;
        try {
          const cert = tlsSock.getPeerCertificate();
          if (cert && cert.subject) {
            result.metadata.tlsCertSubject = cert.subject?.CN || "";
            result.metadata.tlsCertIssuer = cert.issuer?.O || cert.issuer?.CN || "";
            result.metadata.tlsCertExpiry = cert.valid_to || "";
            result.metadata.tlsCertSerial = cert.serialNumber || "";
            if (cert.valid_to) {
              const expiry = new Date(cert.valid_to);
              if (expiry < /* @__PURE__ */ new Date()) {
                result.riskIndicators.push({
                  severity: "medium",
                  title: "Expired TLS Certificate",
                  description: `TLS certificate expired on ${cert.valid_to}`,
                  cweId: "CWE-295"
                });
              }
            }
            if (cert.subject?.CN === cert.issuer?.CN && cert.subject?.O === cert.issuer?.O) {
              result.metadata.selfSigned = true;
              result.riskIndicators.push({
                severity: "low",
                title: "Self-Signed TLS Certificate",
                description: "Server uses a self-signed certificate",
                cweId: "CWE-295"
              });
            }
          }
        } catch {
        }
      }
      const httpReq = `HEAD / HTTP/1.1\r
Host: ${config.host}\r
User-Agent: Mozilla/5.0 (compatible; ServiceProbe/1.0)\r
Accept: */*\r
Connection: close\r
\r
`;
      const respBuf = await sendAndReceive(socket, Buffer.from(httpReq), config.timeoutMs || 1e4);
      const resp = respBuf.toString("utf-8");
      result.rawResponse = resp.substring(0, 4096);
      const statusMatch = resp.match(/^HTTP\/(\d\.\d)\s+(\d{3})\s+(.*)$/m);
      if (statusMatch) {
        result.metadata.httpVersion = statusMatch[1];
        result.metadata.statusCode = parseInt(statusMatch[2], 10);
        result.metadata.statusText = statusMatch[3]?.trim();
      }
      const headerBlock = resp.split("\r\n\r\n")[0] || resp.split("\n\n")[0] || "";
      const headers = {};
      for (const line of headerBlock.split(/\r?\n/).slice(1)) {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          const key = line.substring(0, colonIdx).trim().toLowerCase();
          const val = line.substring(colonIdx + 1).trim();
          headers[key] = val;
        }
      }
      result.metadata.headers = headers;
      const server = headers["server"] || "";
      if (server) {
        result.banner = server;
        const serverParts = server.match(/^([\w.-]+)(?:\/([\d.]+))?/);
        if (serverParts) {
          result.product = serverParts[1];
          result.version = serverParts[2] || null;
        }
        if (/ubuntu/i.test(server)) result.os = "Ubuntu Linux";
        else if (/debian/i.test(server)) result.os = "Debian Linux";
        else if (/centos|rhel|red\s*hat/i.test(server)) result.os = "RHEL/CentOS";
        else if (/win|microsoft|iis/i.test(server)) result.os = "Windows";
        else if (/freebsd/i.test(server)) result.os = "FreeBSD";
      }
      const poweredBy = headers["x-powered-by"] || "";
      if (poweredBy) {
        result.metadata.poweredBy = poweredBy;
        if (!result.product) {
          const pbParts = poweredBy.match(/^([\w.-]+)(?:\/([\d.]+))?/);
          if (pbParts) {
            result.product = pbParts[1];
            result.version = pbParts[2] || null;
          }
        }
        if (/php/i.test(poweredBy)) result.metadata.techPhp = true;
        if (/asp\.?net/i.test(poweredBy)) result.metadata.techAspNet = true;
        if (/express/i.test(poweredBy)) result.metadata.techExpress = true;
        if (/next\.?js/i.test(poweredBy)) result.metadata.techNextJs = true;
      }
      const securityHeaders = {
        "strict-transport-security": !!headers["strict-transport-security"],
        "x-frame-options": !!headers["x-frame-options"],
        "x-content-type-options": !!headers["x-content-type-options"],
        "x-xss-protection": !!headers["x-xss-protection"],
        "content-security-policy": !!headers["content-security-policy"],
        "referrer-policy": !!headers["referrer-policy"],
        "permissions-policy": !!headers["permissions-policy"]
      };
      result.metadata.securityHeaders = securityHeaders;
      const missingCritical = [];
      if (!securityHeaders["strict-transport-security"] && isHttps) missingCritical.push("Strict-Transport-Security");
      if (!securityHeaders["x-frame-options"] && !securityHeaders["content-security-policy"]) missingCritical.push("X-Frame-Options / CSP frame-ancestors");
      if (!securityHeaders["x-content-type-options"]) missingCritical.push("X-Content-Type-Options");
      if (missingCritical.length > 0) {
        result.riskIndicators.push({
          severity: "low",
          title: "Missing Security Headers",
          description: `Missing: ${missingCritical.join(", ")}`,
          cweId: "CWE-693"
        });
      }
      const setCookie = headers["set-cookie"] || "";
      if (setCookie) {
        result.metadata.hasCookies = true;
        if (!/secure/i.test(setCookie) && isHttps) {
          result.riskIndicators.push({
            severity: "medium",
            title: "Cookie Missing Secure Flag",
            description: "Set-Cookie header lacks Secure flag on HTTPS service",
            cweId: "CWE-614"
          });
        }
        if (!/httponly/i.test(setCookie)) {
          result.riskIndicators.push({
            severity: "low",
            title: "Cookie Missing HttpOnly Flag",
            description: "Set-Cookie header lacks HttpOnly flag",
            cweId: "CWE-1004"
          });
        }
      }
      if (headers["x-aspnet-version"]) result.metadata.techAspNet = true;
      if (headers["x-drupal-cache"] || headers["x-generator"]?.includes("Drupal")) result.metadata.techDrupal = true;
      if (headers["x-wordpress"] || headers["link"]?.includes("wp-json")) result.metadata.techWordPress = true;
      if (headers["x-varnish"]) result.metadata.techVarnish = true;
      if (headers["x-cache"]) result.metadata.cdnDetected = headers["x-cache"];
      if (headers["cf-ray"]) {
        result.metadata.cdnCloudflare = true;
        result.metadata.cdnDetected = "Cloudflare";
      }
      if (headers["x-amz-cf-id"]) {
        result.metadata.cdnCloudfront = true;
        result.metadata.cdnDetected = "CloudFront";
      }
      if (!isHttps) {
        result.securityFlags.tlsSupported = false;
        result.securityFlags.encryptionEnabled = false;
        if (result.metadata.statusCode && result.metadata.statusCode < 400) {
          result.riskIndicators.push({
            severity: "info",
            title: "Unencrypted HTTP Service",
            description: `HTTP service on port ${config.port} \u2014 data transmitted in cleartext`,
            cweId: "CWE-319",
            mitreId: "T1557"
          });
        }
      }
      if (result.product && result.version) {
        const prod = result.product.toLowerCase();
        const ver = result.version;
        if (prod === "apache" || prod.includes("apache")) {
          if (ver < "2.4.50") {
            result.potentialCves.push("CVE-2021-41773", "CVE-2021-42013");
            result.riskIndicators.push({
              severity: "critical",
              title: "Apache Path Traversal (CVE-2021-41773)",
              description: `Apache ${ver} may be vulnerable to path traversal and RCE`,
              cweId: "CWE-22"
            });
          }
        }
        if (prod === "nginx") {
          if (ver < "1.20.0") {
            result.potentialCves.push("CVE-2021-23017");
            result.riskIndicators.push({
              severity: "high",
              title: "Nginx DNS Resolver Vulnerability",
              description: `Nginx ${ver} may be vulnerable to DNS resolver off-by-one (CVE-2021-23017)`,
              cweId: "CWE-193"
            });
          }
        }
        if (prod.includes("iis") || prod.includes("Microsoft-IIS")) {
          if (parseFloat(ver) <= 7.5) {
            result.potentialCves.push("CVE-2017-7269");
            result.riskIndicators.push({
              severity: "critical",
              title: "IIS WebDAV Buffer Overflow",
              description: `IIS ${ver} may be vulnerable to WebDAV buffer overflow (CVE-2017-7269)`,
              cweId: "CWE-120"
            });
          }
        }
      }
      result.capabilities.http = true;
      if (isHttps) result.capabilities.https = true;
      result.mitreRelevance.push("T1190");
      if (!result.product && result.metadata.statusCode) {
        try {
          const getSocket = await connectFn(config.host, config.port, config.timeoutMs || 1e4);
          const getReq = `GET / HTTP/1.1\r
Host: ${config.host}\r
User-Agent: Mozilla/5.0 (compatible; ServiceProbe/1.0)\r
Accept: text/html\r
Connection: close\r
\r
`;
          const getResp = await sendAndReceive(getSocket, Buffer.from(getReq), config.timeoutMs || 1e4);
          const body = getResp.toString("utf-8");
          getSocket.destroy();
          const titleMatch = body.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
          if (titleMatch) result.metadata.pageTitle = titleMatch[1].trim();
          const genMatch = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
          if (genMatch) {
            result.metadata.generator = genMatch[1];
            const genParts = genMatch[1].match(/^([\w.-]+)\s*([\d.]+)?/);
            if (genParts) {
              result.product = genParts[1];
              result.version = genParts[2] || null;
            }
          }
          if (/wp-content|wp-includes|wordpress/i.test(body)) {
            result.metadata.techWordPress = true;
            if (!result.product) result.product = "WordPress";
          }
          if (/drupal|sites\/default/i.test(body)) {
            result.metadata.techDrupal = true;
            if (!result.product) result.product = "Drupal";
          }
          if (/joomla|com_content/i.test(body)) {
            result.metadata.techJoomla = true;
            if (!result.product) result.product = "Joomla";
          }
          if (/\.php|PHPSESSID/i.test(body) || /\.php/i.test(setCookie)) {
            result.metadata.techPhp = true;
          }
        } catch {
        }
      }
    } finally {
      socket.destroy();
    }
  } catch (err) {
    result.error = err.message;
    if (isHttps && !result.product) {
      try {
        const plainSocket = await tcpConnect(config.host, config.port, config.timeoutMs || 1e4);
        const httpReq = `HEAD / HTTP/1.1\r
Host: ${config.host}\r
Connection: close\r
\r
`;
        const resp = await sendAndReceive(plainSocket, Buffer.from(httpReq), 5e3);
        const respStr = resp.toString("utf-8");
        plainSocket.destroy();
        if (/^HTTP\//m.test(respStr)) {
          result.error = null;
          result.protocol = "http";
          result.metadata.httpsDowngraded = true;
          const serverMatch = respStr.match(/^Server:\s*(.+)$/mi);
          if (serverMatch) {
            result.banner = serverMatch[1].trim();
            const sp = result.banner.match(/^([\w.-]+)(?:\/([\d.]+))?/);
            if (sp) {
              result.product = sp[1];
              result.version = sp[2] || null;
            }
          }
          result.riskIndicators.push({
            severity: "medium",
            title: "HTTPS Not Available",
            description: `Port ${config.port} expected HTTPS but only serves HTTP`,
            cweId: "CWE-319"
          });
        }
      } catch {
      }
    }
  }
  result.durationMs = Date.now() - start;
  return result;
}
async function fingerprintService(config) {
  const protocol = config.protocol || detectProtocol(config.port);
  if (!protocol) {
    return {
      ...defaultResult("ssh", config.host, config.port),
      error: `Cannot detect protocol for port ${config.port} \u2014 specify protocol explicitly`
    };
  }
  if (config.engagementId) {
    try {
      const { enforceSingleTarget } = await import("./scope-guard-JZ327Z7X.js");
      await enforceSingleTarget(
        config.engagementId,
        config.host,
        `Service Fingerprint (${protocol})`,
        config.operatorId || "system"
      );
    } catch (err) {
      return {
        ...defaultResult(protocol, config.host, config.port),
        error: `ROE scope violation: ${err.message}`
      };
    }
  }
  const probe = PROBE_MAP[protocol];
  if (!probe) {
    return {
      ...defaultResult(protocol, config.host, config.port),
      error: `No probe available for protocol ${protocol}`
    };
  }
  return probe({ ...config, protocol });
}
async function batchFingerprint(config) {
  const { targets, engagementId, operatorId, timeoutMs = 1e4, concurrency = 5, tryDefaultCreds = false } = config;
  if (engagementId) {
    try {
      const { filterInScopeTargets } = await import("./scope-guard-JZ327Z7X.js");
      const scopeResult = await filterInScopeTargets({
        engagementId,
        targets: targets.map((t) => ({ value: t.host })),
        tool: "Service Fingerprinter",
        operatorId: operatorId || "system"
      });
      const inScopeHosts = new Set(scopeResult.inScope.map((t) => t.value));
      const outOfScope = targets.filter((t) => !inScopeHosts.has(t.host));
      if (outOfScope.length > 0) {
        console.warn(`[ServiceFingerprinter] ${outOfScope.length} targets out of scope, skipping`);
      }
    } catch {
    }
  }
  const results = [];
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
        tryDefaultCreds
      });
      results.push(result);
    }
  };
  const workers = Array.from({ length: Math.min(concurrency, targets.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
async function autoFingerprint(host, openPorts, options) {
  const targets = openPorts.map((port) => ({
    host,
    port,
    // For unmapped ports, default to HTTP probe as a fallback — most unknown
    // services on high ports are web services. The HTTP probe will gracefully
    // handle non-HTTP services by returning an error result.
    protocol: detectProtocol(port) || "http"
  }));
  if (targets.length === 0) return [];
  return batchFingerprint({
    targets,
    engagementId: options?.engagementId,
    operatorId: options?.operatorId,
    timeoutMs: options?.timeoutMs,
    concurrency: 3,
    tryDefaultCreds: options?.tryDefaultCreds
  });
}
function summarizeFingerprints(results) {
  const successful = results.filter((r) => !r.error);
  const failed = results.filter((r) => !!r.error);
  const allRisks = results.flatMap((r) => r.riskIndicators);
  const criticalRisks = allRisks.filter((r) => r.severity === "critical").length;
  const highRisks = allRisks.filter((r) => r.severity === "high").length;
  const mediumRisks = allRisks.filter((r) => r.severity === "medium").length;
  const lowRisks = allRisks.filter((r) => r.severity === "low").length;
  return {
    totalServices: results.length,
    successfulProbes: successful.length,
    failedProbes: failed.length,
    criticalRisks,
    highRisks,
    mediumRisks,
    lowRisks,
    servicesWithAnonymousAccess: results.filter((r) => r.securityFlags.anonymousAccess),
    servicesWithDefaultCreds: results.filter((r) => r.securityFlags.defaultCredentials),
    servicesWithoutTls: successful.filter((r) => !r.securityFlags.tlsSupported),
    servicesWithWeakAuth: results.filter((r) => r.securityFlags.weakCredentials || !r.securityFlags.authRequired),
    allCves: [...new Set(results.flatMap((r) => r.potentialCves))],
    allMitreTechniques: [...new Set(results.flatMap((r) => r.mitreRelevance))]
  };
}
var PORT_PROTOCOL_MAP, PROBE_MAP;
var init_service_fingerprinter = __esm({
  "server/lib/service-fingerprinter.ts"() {
    PORT_PROTOCOL_MAP = {
      21: "ftp",
      22: "ssh",
      23: "telnet",
      25: "smtp",
      53: "dns",
      110: "pop3",
      143: "imap",
      161: "snmp",
      389: "ldap",
      80: "http",
      443: "https",
      445: "smb",
      465: "smtp",
      587: "smtp",
      636: "ldap",
      993: "imap",
      995: "pop3",
      1433: "mssql",
      1521: "postgresql",
      // Oracle, but similar probe
      4e3: "http",
      // Common alt HTTP
      4443: "https",
      // Common alt HTTPS
      2049: "ntp",
      3306: "mysql",
      3389: "rdp",
      8e3: "http",
      // Common alt HTTP
      8080: "http",
      // Common alt HTTP
      8090: "http",
      // Common alt HTTP
      8443: "https",
      // Common alt HTTPS
      8888: "http",
      // Common alt HTTP
      9090: "http",
      // Common alt HTTP
      9443: "https",
      // Common alt HTTPS
      5432: "postgresql",
      5900: "vnc",
      5901: "vnc",
      5902: "vnc",
      6379: "redis",
      6380: "redis",
      27017: "mongodb",
      27018: "mongodb",
      27019: "mongodb"
    };
    PROBE_MAP = {
      ssh: fingerprintSSH,
      smtp: fingerprintSMTP,
      ftp: fingerprintFTP,
      sftp: fingerprintSSH,
      // SFTP runs over SSH
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
      pop3: fingerprintTelnet,
      // Basic banner grab
      imap: fingerprintTelnet,
      // Basic banner grab
      dns: fingerprintTelnet,
      // Basic probe
      ntp: fingerprintTelnet,
      // Basic probe
      sip: fingerprintTelnet,
      // Basic probe
      http: fingerprintHTTP,
      https: fingerprintHTTP
    };
  }
});

export {
  PORT_PROTOCOL_MAP,
  detectProtocol,
  fingerprintSSH,
  fingerprintSMTP,
  fingerprintFTP,
  fingerprintSNMP,
  fingerprintRDP,
  fingerprintSMB,
  fingerprintLDAP,
  fingerprintTelnet,
  fingerprintMySQL,
  fingerprintPostgreSQL,
  fingerprintMSSQL,
  fingerprintRedis,
  fingerprintMongoDB,
  fingerprintVNC,
  fingerprintHTTP,
  fingerprintService,
  batchFingerprint,
  autoFingerprint,
  summarizeFingerprints,
  init_service_fingerprinter
};
