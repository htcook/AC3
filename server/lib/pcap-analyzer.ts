/**
 * PCAP Analyzer — Packet Capture, Analysis & Manipulation
 * ═══════════════════════════════════════════════════════════════
 * Provides packet-level capabilities via remote scan server tools:
 *
 *   1. tcpdump — Live packet capture with BPF filters
 *   2. tshark  — Protocol dissection, PCAP analysis, JSON export
 *   3. editcap — PCAP file manipulation (split, merge, filter)
 *   4. capinfos — PCAP metadata extraction
 *
 * Architecture:
 *   Dashboard → SSH → scan server (tcpdump/tshark installed) → JSON output → parse → SSIL
 *
 * The PCAP adapter converts tshark JSON dissection output into
 * NormalizedObservation[] for the SSIL observation pipeline.
 *
 * @module pcap-analyzer
 */
import * as crypto from "crypto";
import {
  generateObservationId,
  fingerprintData,
  type NormalizedObservation,
  type AdapterResult,
  type Severity,
} from "./observation-normalizer";

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

/** Capture mode: live capture vs offline analysis */
export type CaptureMode = "live" | "offline";

/** Live capture configuration */
export interface LiveCaptureConfig {
  /** Target interface (e.g., "eth0", "any") */
  interface: string;
  /** BPF filter expression (e.g., "host 10.0.0.1 and port 80") */
  filter?: string;
  /** Capture duration in seconds (max 300) */
  durationSeconds: number;
  /** Max packets to capture (0 = unlimited within duration) */
  maxPackets?: number;
  /** Snap length — bytes per packet to capture (0 = full packet) */
  snapLen?: number;
  /** Whether to resolve hostnames */
  resolveNames?: boolean;
  /** Output format */
  outputFormat?: "pcap" | "pcapng";
  /** Engagement ID for audit trail */
  engagementId?: number;
  /** Target host for scope enforcement */
  target?: string;
}

/** Offline PCAP analysis configuration */
export interface PcapAnalysisConfig {
  /** Path to PCAP file on scan server */
  pcapPath: string;
  /** Display filter (Wireshark syntax, e.g., "http.request.method == POST") */
  displayFilter?: string;
  /** Protocol to decode as (e.g., "http", "tls", "dns") */
  decodeAs?: string;
  /** Max packets to analyze (0 = all) */
  maxPackets?: number;
  /** Whether to include raw hex dump */
  includeHex?: boolean;
  /** Whether to follow TCP streams */
  followStreams?: boolean;
  /** Engagement ID for audit trail */
  engagementId?: number;
}

/** PCAP file metadata from capinfos */
export interface PcapMetadata {
  filename: string;
  fileType: string;
  encapsulation: string;
  captureTime: { start: string; end: string; durationSeconds: number };
  packetCount: number;
  fileSizeBytes: number;
  dataRate: { bytesPerSecond: number; bitsPerSecond: number; packetsPerSecond: number };
  averagePacketSize: number;
  interfaces: string[];
}

/** Parsed packet from tshark JSON output */
export interface ParsedPacket {
  frameNumber: number;
  timestamp: string;
  epochTime: number;
  /** Source address (IP or MAC) */
  srcAddr: string;
  /** Destination address (IP or MAC) */
  dstAddr: string;
  srcPort?: number;
  dstPort?: number;
  protocol: string;
  /** All protocol layers in order */
  protocolStack: string[];
  length: number;
  info: string;
  /** Detailed layer dissection */
  layers: Record<string, Record<string, string>>;
  /** TCP flags if applicable */
  tcpFlags?: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
    urg: boolean;
  };
  /** TLS info if applicable */
  tls?: {
    version?: string;
    contentType?: string;
    handshakeType?: string;
    cipherSuite?: string;
    serverName?: string;
  };
  /** HTTP info if applicable */
  http?: {
    method?: string;
    uri?: string;
    host?: string;
    statusCode?: number;
    contentType?: string;
    userAgent?: string;
    setCookie?: string;
    authorization?: string;
  };
  /** DNS info if applicable */
  dns?: {
    queryName?: string;
    queryType?: string;
    responseCode?: string;
    answers?: Array<{ name: string; type: string; data: string; ttl: number }>;
  };
}

/** TCP stream reconstruction */
export interface TcpStream {
  streamIndex: number;
  srcAddr: string;
  srcPort: number;
  dstAddr: string;
  dstPort: number;
  protocol: string;
  packetCount: number;
  byteCount: number;
  startTime: string;
  endTime: string;
  durationMs: number;
  /** Reassembled payload (truncated to 10KB) */
  payload?: string;
  /** Whether stream contains credentials or sensitive data */
  sensitiveDataDetected: boolean;
  sensitiveDataTypes: string[];
}

/** Protocol statistics from tshark */
export interface ProtocolStats {
  protocol: string;
  packetCount: number;
  byteCount: number;
  percentOfTotal: number;
}

/** Full PCAP analysis result */
export interface PcapAnalysisResult {
  metadata: PcapMetadata;
  packets: ParsedPacket[];
  streams: TcpStream[];
  protocolStats: ProtocolStats[];
  /** Security-relevant findings extracted from packets */
  findings: PcapFinding[];
  /** Conversation matrix (top talkers) */
  conversations: Array<{
    srcAddr: string;
    dstAddr: string;
    protocol: string;
    packets: number;
    bytes: number;
  }>;
}

/** Security finding from packet analysis */
export interface PcapFinding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  protocol: string;
  srcAddr: string;
  dstAddr: string;
  port?: number;
  category: PcapFindingCategory;
  /** Relevant packet frame numbers */
  frameNumbers: number[];
  /** MITRE ATT&CK technique if applicable */
  mitreTechnique?: string;
}

export type PcapFindingCategory =
  | "cleartext_credentials"
  | "cleartext_protocol"
  | "suspicious_dns"
  | "port_scan_detected"
  | "arp_anomaly"
  | "tls_downgrade"
  | "protocol_anomaly"
  | "data_exfiltration"
  | "c2_beaconing"
  | "lateral_movement"
  | "sensitive_data_exposure"
  | "malformed_packet"
  | "replay_attack";

// ═══════════════════════════════════════════════════════════════
// §2 — TSHARK COMMAND BUILDERS
// ═══════════════════════════════════════════════════════════════

/** Build tcpdump command for live capture */
export function buildTcpdumpCommand(config: LiveCaptureConfig): string {
  const parts = ["tcpdump"];
  parts.push(`-i ${config.interface}`);
  parts.push(`-c ${config.maxPackets || 10000}`);
  // Write to file for later tshark analysis
  const outputFile = `/tmp/capture_${Date.now()}.${config.outputFormat || "pcap"}`;
  parts.push(`-w ${outputFile}`);
  if (config.snapLen) parts.push(`-s ${config.snapLen}`);
  if (!config.resolveNames) parts.push("-nn"); // No DNS resolution
  if (config.filter) parts.push(config.filter);
  return `timeout ${config.durationSeconds} ${parts.join(" ")} 2>/dev/null; echo "PCAP_FILE=${outputFile}"`;
}

/** Build tshark command for JSON packet dissection */
export function buildTsharkJsonCommand(config: PcapAnalysisConfig): string {
  const parts = ["tshark"];
  parts.push(`-r ${config.pcapPath}`);
  parts.push("-T json"); // JSON output
  parts.push("-e frame.number -e frame.time_epoch -e frame.time -e frame.len");
  parts.push("-e frame.protocols");
  // IP layer
  parts.push("-e ip.src -e ip.dst -e ip.proto -e ip.ttl");
  // IPv6
  parts.push("-e ipv6.src -e ipv6.dst");
  // TCP
  parts.push("-e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.reset -e tcp.flags.push -e tcp.stream");
  // UDP
  parts.push("-e udp.srcport -e udp.dstport");
  // HTTP
  parts.push("-e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.content_type -e http.user_agent -e http.authorization -e http.set_cookie");
  // TLS
  parts.push("-e tls.handshake.type -e tls.record.version -e tls.handshake.ciphersuite -e tls.handshake.extensions_server_name");
  // DNS
  parts.push("-e dns.qry.name -e dns.qry.type -e dns.flags.rcode -e dns.a -e dns.aaaa -e dns.cname -e dns.mx.mail_exchange");
  // ARP
  parts.push("-e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4");
  // ICMP
  parts.push("-e icmp.type -e icmp.code");

  if (config.displayFilter) parts.push(`-Y "${config.displayFilter}"`);
  if (config.decodeAs) parts.push(`--decode-as "${config.decodeAs}"`);
  if (config.maxPackets) parts.push(`-c ${config.maxPackets}`);

  return parts.join(" ");
}

/** Build tshark command for protocol statistics */
export function buildTsharkStatsCommand(pcapPath: string): string {
  return `tshark -r ${pcapPath} -q -z io,phs`;
}

/** Build tshark command for conversation extraction */
export function buildTsharkConversationsCommand(pcapPath: string): string {
  return `tshark -r ${pcapPath} -q -z conv,ip`;
}

/** Build tshark command for TCP stream following */
export function buildTsharkFollowStreamCommand(pcapPath: string, streamIndex: number): string {
  return `tshark -r ${pcapPath} -q -z "follow,tcp,ascii,${streamIndex}" 2>/dev/null | head -500`;
}

/** Build capinfos command for PCAP metadata */
export function buildCapinfosCommand(pcapPath: string): string {
  return `capinfos -M ${pcapPath} 2>/dev/null`;
}

// ═══════════════════════════════════════════════════════════════
// §3 — TSHARK JSON PARSER
// ═══════════════════════════════════════════════════════════════

/**
 * Parse tshark JSON output into structured ParsedPacket array.
 * tshark -T json produces an array of packet objects with _source.layers.
 */
export function parseTsharkJson(jsonOutput: string): ParsedPacket[] {
  const packets: ParsedPacket[] = [];
  let parsed: any[];

  try {
    parsed = JSON.parse(jsonOutput);
  } catch {
    // tshark sometimes outputs line-delimited JSON
    const lines = jsonOutput.trim().split("\n").filter(Boolean);
    parsed = [];
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (Array.isArray(obj)) parsed.push(...obj);
        else parsed.push(obj);
      } catch { /* skip malformed lines */ }
    }
  }

  for (const pkt of parsed) {
    try {
      const layers = pkt._source?.layers || pkt.layers || pkt;
      const frame = layers.frame || {};
      const ip = layers.ip || {};
      const ipv6 = layers.ipv6 || {};
      const tcp = layers.tcp || {};
      const udp = layers.udp || {};
      const http = layers.http || {};
      const tls = layers.tls || {};
      const dns = layers.dns || {};
      const arp = layers.arp || {};
      const icmp = layers.icmp || {};

      // Extract field values — tshark JSON wraps values in arrays
      const field = (obj: any, key: string): string => {
        const val = obj[key];
        if (Array.isArray(val)) return val[0] || "";
        return val || "";
      };

      const srcAddr = field(ip, "ip.src") || field(ipv6, "ipv6.src") || field(arp, "arp.src.proto_ipv4") || "";
      const dstAddr = field(ip, "ip.dst") || field(ipv6, "ipv6.dst") || field(arp, "arp.dst.proto_ipv4") || "";
      const srcPort = parseInt(field(tcp, "tcp.srcport") || field(udp, "udp.srcport")) || undefined;
      const dstPort = parseInt(field(tcp, "tcp.dstport") || field(udp, "udp.dstport")) || undefined;
      const protocols = field(frame, "frame.protocols") || "";
      const protocolStack = protocols.split(":").filter(Boolean);
      const topProtocol = protocolStack[protocolStack.length - 1] || "unknown";

      const packet: ParsedPacket = {
        frameNumber: parseInt(field(frame, "frame.number")) || 0,
        timestamp: field(frame, "frame.time") || "",
        epochTime: parseFloat(field(frame, "frame.time_epoch")) || 0,
        srcAddr,
        dstAddr,
        srcPort,
        dstPort,
        protocol: topProtocol,
        protocolStack,
        length: parseInt(field(frame, "frame.len")) || 0,
        info: buildPacketInfo(topProtocol, { http, dns, tcp, tls, arp, icmp }),
        layers: {},
      };

      // TCP flags
      if (Object.keys(tcp).length > 0) {
        packet.tcpFlags = {
          syn: field(tcp, "tcp.flags.syn") === "1",
          ack: field(tcp, "tcp.flags.ack") === "1",
          fin: field(tcp, "tcp.flags.fin") === "1",
          rst: field(tcp, "tcp.flags.reset") === "1",
          psh: field(tcp, "tcp.flags.push") === "1",
          urg: false,
        };
      }

      // TLS info
      if (Object.keys(tls).length > 0) {
        packet.tls = {
          handshakeType: field(tls, "tls.handshake.type") || undefined,
          version: field(tls, "tls.record.version") || undefined,
          cipherSuite: field(tls, "tls.handshake.ciphersuite") || undefined,
          serverName: field(tls, "tls.handshake.extensions_server_name") || undefined,
        };
      }

      // HTTP info
      if (Object.keys(http).length > 0) {
        packet.http = {
          method: field(http, "http.request.method") || undefined,
          uri: field(http, "http.request.uri") || undefined,
          host: field(http, "http.host") || undefined,
          statusCode: parseInt(field(http, "http.response.code")) || undefined,
          contentType: field(http, "http.content_type") || undefined,
          userAgent: field(http, "http.user_agent") || undefined,
          setCookie: field(http, "http.set_cookie") || undefined,
          authorization: field(http, "http.authorization") || undefined,
        };
      }

      // DNS info
      if (Object.keys(dns).length > 0) {
        packet.dns = {
          queryName: field(dns, "dns.qry.name") || undefined,
          queryType: field(dns, "dns.qry.type") || undefined,
          responseCode: field(dns, "dns.flags.rcode") || undefined,
        };
      }

      packets.push(packet);
    } catch { /* skip malformed packets */ }
  }

  return packets;
}

/** Build human-readable info string for a packet */
function buildPacketInfo(
  protocol: string,
  layers: { http: any; dns: any; tcp: any; tls: any; arp: any; icmp: any }
): string {
  const field = (obj: any, key: string): string => {
    const val = obj[key];
    if (Array.isArray(val)) return val[0] || "";
    return val || "";
  };

  if (field(layers.http, "http.request.method")) {
    return `${field(layers.http, "http.request.method")} ${field(layers.http, "http.request.uri")} HTTP`;
  }
  if (field(layers.http, "http.response.code")) {
    return `HTTP ${field(layers.http, "http.response.code")}`;
  }
  if (field(layers.dns, "dns.qry.name")) {
    return `DNS ${field(layers.dns, "dns.qry.type") || "A"} ${field(layers.dns, "dns.qry.name")}`;
  }
  if (field(layers.tls, "tls.handshake.type")) {
    const types: Record<string, string> = { "1": "ClientHello", "2": "ServerHello", "11": "Certificate", "16": "ClientKeyExchange" };
    return `TLS ${types[field(layers.tls, "tls.handshake.type")] || "Handshake"}`;
  }
  if (field(layers.arp, "arp.opcode")) {
    return field(layers.arp, "arp.opcode") === "1" ? "ARP Request" : "ARP Reply";
  }
  if (field(layers.tcp, "tcp.flags.syn") === "1" && field(layers.tcp, "tcp.flags.ack") === "0") {
    return "TCP SYN";
  }
  if (field(layers.tcp, "tcp.flags.syn") === "1" && field(layers.tcp, "tcp.flags.ack") === "1") {
    return "TCP SYN-ACK";
  }
  if (field(layers.tcp, "tcp.flags.fin") === "1") {
    return "TCP FIN";
  }
  if (field(layers.tcp, "tcp.flags.reset") === "1") {
    return "TCP RST";
  }
  return protocol.toUpperCase();
}

// ═══════════════════════════════════════════════════════════════
// §4 — CAPINFOS PARSER
// ═══════════════════════════════════════════════════════════════

/** Parse capinfos machine-readable output */
export function parseCapinfos(output: string): PcapMetadata {
  const lines = output.split("\n");
  const get = (prefix: string): string => {
    const line = lines.find((l) => l.startsWith(prefix));
    return line ? line.substring(prefix.length).trim() : "";
  };

  return {
    filename: get("File name:") || "unknown",
    fileType: get("File type:") || "unknown",
    encapsulation: get("File encapsulation:") || "unknown",
    captureTime: {
      start: get("First packet time:") || "",
      end: get("Last packet time:") || "",
      durationSeconds: parseFloat(get("Data byte rate:")) || 0,
    },
    packetCount: parseInt(get("Number of packets:")) || 0,
    fileSizeBytes: parseInt(get("File size:")) || 0,
    dataRate: {
      bytesPerSecond: parseFloat(get("Data byte rate:")) || 0,
      bitsPerSecond: parseFloat(get("Data bit rate:")) || 0,
      packetsPerSecond: parseFloat(get("Average packet rate:")) || 0,
    },
    averagePacketSize: parseFloat(get("Average packet size:")) || 0,
    interfaces: [get("Capture oper-sys:") || "unknown"],
  };
}

// ═══════════════════════════════════════════════════════════════
// §5 — PROTOCOL STATS PARSER
// ═══════════════════════════════════════════════════════════════

/** Parse tshark protocol hierarchy statistics */
export function parseProtocolStats(output: string): ProtocolStats[] {
  const stats: ProtocolStats[] = [];
  const lines = output.split("\n");
  // Skip header lines until we find the data
  let dataStarted = false;

  for (const line of lines) {
    if (line.includes("===")) {
      dataStarted = true;
      continue;
    }
    if (!dataStarted || !line.trim()) continue;

    // Format: "  eth:eth:ip:tcp   frames:1234 bytes:567890"
    const match = line.match(/^\s*(\S+)\s+frames:(\d+)\s+bytes:(\d+)/);
    if (match) {
      const protocol = match[1].split(":").pop() || match[1];
      stats.push({
        protocol,
        packetCount: parseInt(match[2]),
        byteCount: parseInt(match[3]),
        percentOfTotal: 0, // Calculated after all stats are collected
      });
    }
  }

  // Calculate percentages
  const totalPackets = stats.reduce((sum, s) => sum + s.packetCount, 0);
  for (const s of stats) {
    s.percentOfTotal = totalPackets > 0 ? Math.round((s.packetCount / totalPackets) * 10000) / 100 : 0;
  }

  return stats;
}

// ═══════════════════════════════════════════════════════════════
// §6 — CONVERSATION PARSER
// ═══════════════════════════════════════════════════════════════

/** Parse tshark conversation output */
export function parseConversations(output: string): Array<{
  srcAddr: string;
  dstAddr: string;
  protocol: string;
  packets: number;
  bytes: number;
}> {
  const conversations: Array<{ srcAddr: string; dstAddr: string; protocol: string; packets: number; bytes: number }> = [];
  const lines = output.split("\n");

  for (const line of lines) {
    // Format: "10.0.0.1  <-> 10.0.0.2   1234  567890  ..."
    const match = line.match(/^\s*(\S+)\s+<->\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      conversations.push({
        srcAddr: match[1],
        dstAddr: match[2],
        protocol: "ip",
        packets: parseInt(match[3]) + parseInt(match[5]),
        bytes: parseInt(match[4]) + parseInt(match[6]),
      });
    }
  }

  return conversations.sort((a, b) => b.bytes - a.bytes);
}

// ═══════════════════════════════════════════════════════════════
// §7 — SECURITY FINDING DETECTOR
// ═══════════════════════════════════════════════════════════════

/**
 * Analyze parsed packets for security-relevant findings.
 * Detects cleartext credentials, suspicious patterns, protocol anomalies, etc.
 */
export function detectFindings(packets: ParsedPacket[]): PcapFinding[] {
  const findings: PcapFinding[] = [];
  let findingCounter = 0;
  const genId = () => `pcap-finding-${++findingCounter}-${Date.now()}`;

  // ── Cleartext Credential Detection ──
  const credentialPackets = packets.filter(
    (p) =>
      p.http?.authorization?.startsWith("Basic ") ||
      p.http?.uri?.match(/password=|passwd=|pwd=|pass=|token=|api_key=|apikey=/i) ||
      p.http?.setCookie?.match(/session|token|auth/i)
  );
  for (const pkt of credentialPackets) {
    findings.push({
      id: genId(),
      severity: "critical",
      title: "Cleartext Credentials Detected",
      description: pkt.http?.authorization
        ? "HTTP Basic Authentication credentials transmitted in cleartext"
        : pkt.http?.uri?.match(/password=/i)
        ? "Password parameter visible in HTTP request URI"
        : "Session token transmitted without encryption",
      evidence: pkt.http?.authorization
        ? `Authorization: ${pkt.http.authorization.substring(0, 30)}...`
        : pkt.http?.uri?.substring(0, 200) || "Session cookie in cleartext",
      protocol: "http",
      srcAddr: pkt.srcAddr,
      dstAddr: pkt.dstAddr,
      port: pkt.dstPort,
      category: "cleartext_credentials",
      frameNumbers: [pkt.frameNumber],
      mitreTechnique: "T1040",
    });
  }

  // ── Cleartext Protocol Detection ──
  const cleartextProtocols = new Map<string, ParsedPacket[]>();
  for (const pkt of packets) {
    if (["ftp", "telnet", "pop", "imap", "smtp"].includes(pkt.protocol)) {
      if (!cleartextProtocols.has(pkt.protocol)) cleartextProtocols.set(pkt.protocol, []);
      cleartextProtocols.get(pkt.protocol)!.push(pkt);
    }
    // HTTP without TLS
    if (pkt.http?.method && !pkt.protocolStack.includes("tls")) {
      if (!cleartextProtocols.has("http")) cleartextProtocols.set("http", []);
      cleartextProtocols.get("http")!.push(pkt);
    }
  }
  for (const [proto, pkts] of cleartextProtocols) {
    findings.push({
      id: genId(),
      severity: proto === "telnet" || proto === "ftp" ? "high" : "medium",
      title: `Cleartext ${proto.toUpperCase()} Traffic Detected`,
      description: `${pkts.length} packets of unencrypted ${proto.toUpperCase()} traffic observed. All data including potential credentials is visible to network sniffers.`,
      evidence: `${pkts.length} ${proto} packets between ${pkts[0].srcAddr} and ${pkts[0].dstAddr}`,
      protocol: proto,
      srcAddr: pkts[0].srcAddr,
      dstAddr: pkts[0].dstAddr,
      port: pkts[0].dstPort,
      category: "cleartext_protocol",
      frameNumbers: pkts.slice(0, 10).map((p) => p.frameNumber),
      mitreTechnique: "T1040",
    });
  }

  // ── Port Scan Detection ──
  const synPackets = packets.filter((p) => p.tcpFlags?.syn && !p.tcpFlags?.ack);
  const synBySource = new Map<string, Set<number>>();
  for (const pkt of synPackets) {
    if (!synBySource.has(pkt.srcAddr)) synBySource.set(pkt.srcAddr, new Set());
    if (pkt.dstPort) synBySource.get(pkt.srcAddr)!.add(pkt.dstPort);
  }
  for (const [src, ports] of synBySource) {
    if (ports.size >= 10) {
      findings.push({
        id: genId(),
        severity: ports.size >= 100 ? "high" : "medium",
        title: `Port Scan Detected from ${src}`,
        description: `${ports.size} unique destination ports probed via SYN packets from ${src}. This indicates active port scanning.`,
        evidence: `SYN packets to ${ports.size} unique ports: ${[...ports].slice(0, 20).join(", ")}${ports.size > 20 ? "..." : ""}`,
        protocol: "tcp",
        srcAddr: src,
        dstAddr: packets.find((p) => p.srcAddr === src)?.dstAddr || "multiple",
        category: "port_scan_detected",
        frameNumbers: synPackets.filter((p) => p.srcAddr === src).slice(0, 10).map((p) => p.frameNumber),
        mitreTechnique: "T1046",
      });
    }
  }

  // ── ARP Anomaly Detection (Spoofing) ──
  const arpReplies = packets.filter((p) => p.protocol === "arp" && p.info === "ARP Reply");
  const macToIp = new Map<string, Set<string>>();
  for (const pkt of arpReplies) {
    const mac = pkt.layers?.arp?.["arp.src.hw_mac"] || pkt.srcAddr;
    if (!macToIp.has(mac)) macToIp.set(mac, new Set());
    macToIp.get(mac)!.add(pkt.srcAddr);
  }
  for (const [mac, ips] of macToIp) {
    if (ips.size > 1) {
      findings.push({
        id: genId(),
        severity: "high",
        title: "Possible ARP Spoofing Detected",
        description: `MAC address ${mac} is claiming multiple IP addresses: ${[...ips].join(", ")}. This may indicate ARP cache poisoning.`,
        evidence: `MAC ${mac} → IPs: ${[...ips].join(", ")}`,
        protocol: "arp",
        srcAddr: [...ips][0],
        dstAddr: "broadcast",
        category: "arp_anomaly",
        frameNumbers: arpReplies.slice(0, 5).map((p) => p.frameNumber),
        mitreTechnique: "T1557.002",
      });
    }
  }

  // ── Suspicious DNS Detection (Tunneling, DGA) ──
  const dnsQueries = packets.filter((p) => p.dns?.queryName);
  const longDnsQueries = dnsQueries.filter((p) => (p.dns?.queryName?.length || 0) > 50);
  if (longDnsQueries.length >= 5) {
    findings.push({
      id: genId(),
      severity: "high",
      title: "Possible DNS Tunneling Detected",
      description: `${longDnsQueries.length} DNS queries with unusually long domain names (>50 chars) detected. This pattern is consistent with DNS tunneling for data exfiltration.`,
      evidence: `Sample queries: ${longDnsQueries.slice(0, 3).map((p) => p.dns?.queryName?.substring(0, 60)).join(", ")}`,
      protocol: "dns",
      srcAddr: longDnsQueries[0].srcAddr,
      dstAddr: longDnsQueries[0].dstAddr,
      port: 53,
      category: "suspicious_dns",
      frameNumbers: longDnsQueries.slice(0, 10).map((p) => p.frameNumber),
      mitreTechnique: "T1071.004",
    });
  }

  // ── TLS Downgrade Detection ──
  const tlsPackets = packets.filter((p) => p.tls?.version);
  const weakTls = tlsPackets.filter((p) => {
    const v = p.tls?.version || "";
    return v.includes("0x0300") || v.includes("0x0301") || v.includes("0x0302"); // SSLv3, TLS 1.0, TLS 1.1
  });
  if (weakTls.length > 0) {
    findings.push({
      id: genId(),
      severity: "medium",
      title: "Weak TLS Version Detected",
      description: `${weakTls.length} packets using deprecated TLS versions (SSLv3/TLS 1.0/TLS 1.1). These versions have known vulnerabilities.`,
      evidence: `Weak TLS versions in ${weakTls.length} packets`,
      protocol: "tls",
      srcAddr: weakTls[0].srcAddr,
      dstAddr: weakTls[0].dstAddr,
      port: weakTls[0].dstPort,
      category: "tls_downgrade",
      frameNumbers: weakTls.slice(0, 5).map((p) => p.frameNumber),
      mitreTechnique: "T1557",
    });
  }

  // ── C2 Beaconing Detection ──
  const httpRequests = packets.filter((p) => p.http?.method);
  const requestsByDest = new Map<string, number[]>();
  for (const pkt of httpRequests) {
    const key = `${pkt.dstAddr}:${pkt.dstPort}`;
    if (!requestsByDest.has(key)) requestsByDest.set(key, []);
    requestsByDest.get(key)!.push(pkt.epochTime);
  }
  for (const [dest, times] of requestsByDest) {
    if (times.length >= 5) {
      // Check for regular intervals (beaconing)
      const intervals: number[] = [];
      for (let i = 1; i < times.length; i++) {
        intervals.push(times[i] - times[i - 1]);
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
      const stdDev = Math.sqrt(variance);
      // Low standard deviation relative to mean = regular beaconing
      if (avgInterval > 0 && stdDev / avgInterval < 0.3) {
        findings.push({
          id: genId(),
          severity: "high",
          title: `Possible C2 Beaconing to ${dest}`,
          description: `Regular HTTP request pattern detected to ${dest} with ~${Math.round(avgInterval)}s intervals (σ=${stdDev.toFixed(1)}s). Consistent beaconing pattern may indicate C2 communication.`,
          evidence: `${times.length} requests at ~${Math.round(avgInterval)}s intervals`,
          protocol: "http",
          srcAddr: httpRequests.find((p) => `${p.dstAddr}:${p.dstPort}` === dest)?.srcAddr || "",
          dstAddr: dest.split(":")[0],
          port: parseInt(dest.split(":")[1]) || 80,
          category: "c2_beaconing",
          frameNumbers: httpRequests.filter((p) => `${p.dstAddr}:${p.dstPort}` === dest).slice(0, 10).map((p) => p.frameNumber),
          mitreTechnique: "T1071.001",
        });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════
// §8 — SSIL ADAPTER (tshark → NormalizedObservation)
// ═══════════════════════════════════════════════════════════════

/**
 * Convert PCAP analysis findings into SSIL NormalizedObservation format.
 * This is the bridge between packet analysis and the observation pipeline.
 */
export function adaptPcapFindings(findings: PcapFinding[], packets: ParsedPacket[]): AdapterResult {
  const startTime = Date.now();
  const observations: NormalizedObservation[] = [];
  const errors: string[] = [];

  for (const finding of findings) {
    try {
      const obs: NormalizedObservation = {
        observationId: generateObservationId(
          "pcap_analyzer",
          finding.dstAddr,
          finding.port || 0,
          mapCategoryToObsType(finding.category),
          finding.id
        ),
        asset: {
          assetId: `pcap-${finding.dstAddr}`,
          host: finding.dstAddr,
          port: finding.port || 0,
          protocol: finding.protocol,
          tags: ["pcap-analysis", finding.category],
        },
        scanner: {
          name: "pcap_analyzer",
          version: "1.0.0",
          adapter: "tshark-json",
          mode: "passive",
        },
        observationType: mapCategoryToObsType(finding.category),
        severity: finding.severity,
        confidence: findingConfidence(finding),
        timestamp: new Date().toISOString(),
        evidence: {
          summary: finding.title + ": " + finding.description,
          cve: undefined,
          artifacts: [
            {
              findingId: finding.id,
              category: finding.category,
              evidence: finding.evidence,
              frameNumbers: finding.frameNumbers,
              mitreTechnique: finding.mitreTechnique,
            },
          ],
        },
        metadata: {
          notes: `Detected via packet capture analysis. ${finding.frameNumbers.length} relevant packets.`,
        },
      };
      observations.push(obs);
    } catch (err: any) {
      errors.push(`PCAP adapter error for finding ${finding.id}: ${err.message}`);
    }
  }

  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: packets.length,
      observationsEmitted: observations.length,
      errors,
    },
  };
}

/** Map PCAP finding category to SSIL observation type */
function mapCategoryToObsType(category: PcapFindingCategory): "vulnerability_finding" | "misconfiguration" | "exposure_surface" {
  switch (category) {
    case "cleartext_credentials":
    case "cleartext_protocol":
    case "tls_downgrade":
      return "vulnerability_finding";
    case "port_scan_detected":
    case "arp_anomaly":
    case "suspicious_dns":
    case "c2_beaconing":
    case "data_exfiltration":
    case "lateral_movement":
      return "exposure_surface";
    default:
      return "misconfiguration";
  }
}

/** Assign confidence based on finding category */
function findingConfidence(finding: PcapFinding): number {
  switch (finding.category) {
    case "cleartext_credentials":
      return 0.95;
    case "port_scan_detected":
      return 0.9;
    case "cleartext_protocol":
      return 0.95;
    case "arp_anomaly":
      return 0.7;
    case "suspicious_dns":
      return 0.6;
    case "tls_downgrade":
      return 0.9;
    case "c2_beaconing":
      return 0.5;
    default:
      return 0.7;
  }
}

// ═══════════════════════════════════════════════════════════════
// §9 — SCAN SERVER EXECUTION HELPERS
// ═══════════════════════════════════════════════════════════════

/**
 * Execute a live packet capture on the scan server.
 * Returns the path to the captured PCAP file on the remote server.
 */
export async function executeLiveCapture(config: LiveCaptureConfig): Promise<{
  pcapPath: string;
  packetsCaptured: number;
  durationMs: number;
}> {
  const { executeTool, executeRawCommand } = await import("./scan-server-executor");
  const cmd = buildTcpdumpCommand(config);
  const result = await executeTool({
    tool: "bash",
    args: `-c "${cmd.replace(/"/g, '\\"')}"`,
    timeoutSeconds: config.durationSeconds + 30, // Extra buffer
    engagementId: config.engagementId,
    sudo: true, // tcpdump requires root
  });

  // Extract PCAP file path from output
  const pcapMatch = result.stdout.match(/PCAP_FILE=(\S+)/);
  const pcapPath = pcapMatch?.[1] || `/tmp/capture_${Date.now()}.pcap`;

  // Get packet count
  const countResult = await executeTool({
    tool: "bash",
    args: `-c "capinfos -c ${pcapPath} 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
    timeoutSeconds: 10,
  });
  const packetsCaptured = parseInt(countResult.stdout.trim()) || 0;

  return { pcapPath, packetsCaptured, durationMs: result.durationMs };
}

/**
 * Analyze a PCAP file on the scan server using tshark.
 * Returns fully parsed analysis results.
 */
export async function analyzePcap(config: PcapAnalysisConfig): Promise<PcapAnalysisResult> {
  const { executeTool } = await import("./scan-server-executor");

  // 1. Get metadata via capinfos
  const capinfosResult = await executeTool({
    tool: "bash",
    args: `-c "${buildCapinfosCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId,
  });
  const metadata = parseCapinfos(capinfosResult.stdout);

  // 2. Parse packets via tshark JSON
  const tsharkCmd = buildTsharkJsonCommand(config);
  const tsharkResult = await executeTool({
    tool: "bash",
    args: `-c '${tsharkCmd.replace(/'/g, "'\\''")}'`,
    timeoutSeconds: 120,
    engagementId: config.engagementId,
  });
  const packets = parseTsharkJson(tsharkResult.stdout);

  // 3. Get protocol stats
  const statsResult = await executeTool({
    tool: "bash",
    args: `-c "${buildTsharkStatsCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId,
  });
  const protocolStats = parseProtocolStats(statsResult.stdout);

  // 4. Get conversations
  const convResult = await executeTool({
    tool: "bash",
    args: `-c "${buildTsharkConversationsCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId,
  });
  const conversations = parseConversations(convResult.stdout);

  // 5. Follow TCP streams (top 10 by packet count)
  const streams: TcpStream[] = [];
  if (config.followStreams) {
    const streamIndices = new Set<number>();
    for (const pkt of packets) {
      if (pkt.layers?.tcp?.["tcp.stream"]) {
        streamIndices.add(parseInt(pkt.layers.tcp["tcp.stream"]));
      }
    }
    const topStreams = [...streamIndices].slice(0, 10);
    for (const idx of topStreams) {
      try {
        const streamResult = await executeTool({
          tool: "bash",
          args: `-c "${buildTsharkFollowStreamCommand(config.pcapPath, idx)}"`,
          timeoutSeconds: 15,
          engagementId: config.engagementId,
        });
        const streamPackets = packets.filter(
          (p) => p.layers?.tcp?.["tcp.stream"] === String(idx)
        );
        if (streamPackets.length > 0) {
          const payload = streamResult.stdout.substring(0, 10240); // 10KB max
          const sensitivePatterns = [
            /password/i, /passwd/i, /secret/i, /token/i, /api[_-]?key/i,
            /authorization/i, /cookie/i, /session/i, /bearer/i,
          ];
          const sensitiveTypes = sensitivePatterns
            .filter((p) => p.test(payload))
            .map((p) => p.source.replace(/[/\\i]/g, ""));

          streams.push({
            streamIndex: idx,
            srcAddr: streamPackets[0].srcAddr,
            srcPort: streamPackets[0].srcPort || 0,
            dstAddr: streamPackets[0].dstAddr,
            dstPort: streamPackets[0].dstPort || 0,
            protocol: streamPackets[0].protocol,
            packetCount: streamPackets.length,
            byteCount: streamPackets.reduce((sum, p) => sum + p.length, 0),
            startTime: streamPackets[0].timestamp,
            endTime: streamPackets[streamPackets.length - 1].timestamp,
            durationMs: (streamPackets[streamPackets.length - 1].epochTime - streamPackets[0].epochTime) * 1000,
            payload: payload.substring(0, 2048),
            sensitiveDataDetected: sensitiveTypes.length > 0,
            sensitiveDataTypes: sensitiveTypes,
          });
        }
      } catch { /* stream follow failed, skip */ }
    }
  }

  // 6. Detect security findings
  const findings = detectFindings(packets);

  return { metadata, packets, streams, protocolStats, findings, conversations };
}

/**
 * Ingest PCAP analysis results into the SSIL observation pipeline.
 */
export async function ingestPcapResults(findings: PcapFinding[], packets: ParsedPacket[]) {
  const { ingestRawObservations } = await import("./observation-ingestor");
  const adapterResult = adaptPcapFindings(findings, packets);

  if (adapterResult.observations.length > 0) {
    await ingestRawObservations(adapterResult.observations, "pcap_analyzer");
  }

  return {
    observations: adapterResult.observations.length,
    findings: findings.length,
    errors: adapterResult.metrics.errors,
  };
}
