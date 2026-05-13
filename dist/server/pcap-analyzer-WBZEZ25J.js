import {
  generateObservationId,
  init_observation_normalizer
} from "./chunk-BCMODKPD.js";
import "./chunk-5BWO4Y3K.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/pcap-analyzer.ts
function buildTcpdumpCommand(config) {
  const parts = ["tcpdump"];
  parts.push(`-i ${config.interface}`);
  parts.push(`-c ${config.maxPackets || 1e4}`);
  const outputFile = `/tmp/capture_${Date.now()}.${config.outputFormat || "pcap"}`;
  parts.push(`-w ${outputFile}`);
  if (config.snapLen) parts.push(`-s ${config.snapLen}`);
  if (!config.resolveNames) parts.push("-nn");
  if (config.filter) parts.push(config.filter);
  return `timeout ${config.durationSeconds} ${parts.join(" ")} 2>/dev/null; echo "PCAP_FILE=${outputFile}"`;
}
function buildTsharkJsonCommand(config) {
  const parts = ["tshark"];
  parts.push(`-r ${config.pcapPath}`);
  parts.push("-T json");
  parts.push("-e frame.number -e frame.time_epoch -e frame.time -e frame.len");
  parts.push("-e frame.protocols");
  parts.push("-e ip.src -e ip.dst -e ip.proto -e ip.ttl");
  parts.push("-e ipv6.src -e ipv6.dst");
  parts.push("-e tcp.srcport -e tcp.dstport -e tcp.flags -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.reset -e tcp.flags.push -e tcp.stream");
  parts.push("-e udp.srcport -e udp.dstport");
  parts.push("-e http.request.method -e http.request.uri -e http.host -e http.response.code -e http.content_type -e http.user_agent -e http.authorization -e http.set_cookie");
  parts.push("-e tls.handshake.type -e tls.record.version -e tls.handshake.ciphersuite -e tls.handshake.extensions_server_name");
  parts.push("-e dns.qry.name -e dns.qry.type -e dns.flags.rcode -e dns.a -e dns.aaaa -e dns.cname -e dns.mx.mail_exchange");
  parts.push("-e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4");
  parts.push("-e icmp.type -e icmp.code");
  if (config.displayFilter) parts.push(`-Y "${config.displayFilter}"`);
  if (config.decodeAs) parts.push(`--decode-as "${config.decodeAs}"`);
  if (config.maxPackets) parts.push(`-c ${config.maxPackets}`);
  return parts.join(" ");
}
function buildTsharkStatsCommand(pcapPath) {
  return `tshark -r ${pcapPath} -q -z io,phs`;
}
function buildTsharkConversationsCommand(pcapPath) {
  return `tshark -r ${pcapPath} -q -z conv,ip`;
}
function buildTsharkFollowStreamCommand(pcapPath, streamIndex) {
  return `tshark -r ${pcapPath} -q -z "follow,tcp,ascii,${streamIndex}" 2>/dev/null | head -500`;
}
function buildCapinfosCommand(pcapPath) {
  return `capinfos -M ${pcapPath} 2>/dev/null`;
}
function parseTsharkJson(jsonOutput) {
  const packets = [];
  let parsed;
  try {
    parsed = JSON.parse(jsonOutput);
  } catch {
    const lines = jsonOutput.trim().split("\n").filter(Boolean);
    parsed = [];
    for (const line of lines) {
      try {
        const obj = JSON.parse(line);
        if (Array.isArray(obj)) parsed.push(...obj);
        else parsed.push(obj);
      } catch {
      }
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
      const field = (obj, key) => {
        const val = obj[key];
        if (Array.isArray(val)) return val[0] || "";
        return val || "";
      };
      const srcAddr = field(ip, "ip.src") || field(ipv6, "ipv6.src") || field(arp, "arp.src.proto_ipv4") || "";
      const dstAddr = field(ip, "ip.dst") || field(ipv6, "ipv6.dst") || field(arp, "arp.dst.proto_ipv4") || "";
      const srcPort = parseInt(field(tcp, "tcp.srcport") || field(udp, "udp.srcport")) || void 0;
      const dstPort = parseInt(field(tcp, "tcp.dstport") || field(udp, "udp.dstport")) || void 0;
      const protocols = field(frame, "frame.protocols") || "";
      const protocolStack = protocols.split(":").filter(Boolean);
      const topProtocol = protocolStack[protocolStack.length - 1] || "unknown";
      const packet = {
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
        layers: {}
      };
      if (Object.keys(tcp).length > 0) {
        packet.tcpFlags = {
          syn: field(tcp, "tcp.flags.syn") === "1",
          ack: field(tcp, "tcp.flags.ack") === "1",
          fin: field(tcp, "tcp.flags.fin") === "1",
          rst: field(tcp, "tcp.flags.reset") === "1",
          psh: field(tcp, "tcp.flags.push") === "1",
          urg: false
        };
      }
      if (Object.keys(tls).length > 0) {
        packet.tls = {
          handshakeType: field(tls, "tls.handshake.type") || void 0,
          version: field(tls, "tls.record.version") || void 0,
          cipherSuite: field(tls, "tls.handshake.ciphersuite") || void 0,
          serverName: field(tls, "tls.handshake.extensions_server_name") || void 0
        };
      }
      if (Object.keys(http).length > 0) {
        packet.http = {
          method: field(http, "http.request.method") || void 0,
          uri: field(http, "http.request.uri") || void 0,
          host: field(http, "http.host") || void 0,
          statusCode: parseInt(field(http, "http.response.code")) || void 0,
          contentType: field(http, "http.content_type") || void 0,
          userAgent: field(http, "http.user_agent") || void 0,
          setCookie: field(http, "http.set_cookie") || void 0,
          authorization: field(http, "http.authorization") || void 0
        };
      }
      if (Object.keys(dns).length > 0) {
        packet.dns = {
          queryName: field(dns, "dns.qry.name") || void 0,
          queryType: field(dns, "dns.qry.type") || void 0,
          responseCode: field(dns, "dns.flags.rcode") || void 0
        };
      }
      packets.push(packet);
    } catch {
    }
  }
  return packets;
}
function buildPacketInfo(protocol, layers) {
  const field = (obj, key) => {
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
    const types = { "1": "ClientHello", "2": "ServerHello", "11": "Certificate", "16": "ClientKeyExchange" };
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
function parseCapinfos(output) {
  const lines = output.split("\n");
  const get = (prefix) => {
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
      durationSeconds: parseFloat(get("Data byte rate:")) || 0
    },
    packetCount: parseInt(get("Number of packets:")) || 0,
    fileSizeBytes: parseInt(get("File size:")) || 0,
    dataRate: {
      bytesPerSecond: parseFloat(get("Data byte rate:")) || 0,
      bitsPerSecond: parseFloat(get("Data bit rate:")) || 0,
      packetsPerSecond: parseFloat(get("Average packet rate:")) || 0
    },
    averagePacketSize: parseFloat(get("Average packet size:")) || 0,
    interfaces: [get("Capture oper-sys:") || "unknown"]
  };
}
function parseProtocolStats(output) {
  const stats = [];
  const lines = output.split("\n");
  let dataStarted = false;
  for (const line of lines) {
    if (line.includes("===")) {
      dataStarted = true;
      continue;
    }
    if (!dataStarted || !line.trim()) continue;
    const match = line.match(/^\s*(\S+)\s+frames:(\d+)\s+bytes:(\d+)/);
    if (match) {
      const protocol = match[1].split(":").pop() || match[1];
      stats.push({
        protocol,
        packetCount: parseInt(match[2]),
        byteCount: parseInt(match[3]),
        percentOfTotal: 0
        // Calculated after all stats are collected
      });
    }
  }
  const totalPackets = stats.reduce((sum, s) => sum + s.packetCount, 0);
  for (const s of stats) {
    s.percentOfTotal = totalPackets > 0 ? Math.round(s.packetCount / totalPackets * 1e4) / 100 : 0;
  }
  return stats;
}
function parseConversations(output) {
  const conversations = [];
  const lines = output.split("\n");
  for (const line of lines) {
    const match = line.match(/^\s*(\S+)\s+<->\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      conversations.push({
        srcAddr: match[1],
        dstAddr: match[2],
        protocol: "ip",
        packets: parseInt(match[3]) + parseInt(match[5]),
        bytes: parseInt(match[4]) + parseInt(match[6])
      });
    }
  }
  return conversations.sort((a, b) => b.bytes - a.bytes);
}
function detectFindings(packets) {
  const findings = [];
  let findingCounter = 0;
  const genId = () => `pcap-finding-${++findingCounter}-${Date.now()}`;
  const credentialPackets = packets.filter(
    (p) => p.http?.authorization?.startsWith("Basic ") || p.http?.uri?.match(/password=|passwd=|pwd=|pass=|token=|api_key=|apikey=/i) || p.http?.setCookie?.match(/session|token|auth/i)
  );
  for (const pkt of credentialPackets) {
    findings.push({
      id: genId(),
      severity: "critical",
      title: "Cleartext Credentials Detected",
      description: pkt.http?.authorization ? "HTTP Basic Authentication credentials transmitted in cleartext" : pkt.http?.uri?.match(/password=/i) ? "Password parameter visible in HTTP request URI" : "Session token transmitted without encryption",
      evidence: pkt.http?.authorization ? `Authorization: ${pkt.http.authorization.substring(0, 30)}...` : pkt.http?.uri?.substring(0, 200) || "Session cookie in cleartext",
      protocol: "http",
      srcAddr: pkt.srcAddr,
      dstAddr: pkt.dstAddr,
      port: pkt.dstPort,
      category: "cleartext_credentials",
      frameNumbers: [pkt.frameNumber],
      mitreTechnique: "T1040"
    });
  }
  const cleartextProtocols = /* @__PURE__ */ new Map();
  for (const pkt of packets) {
    if (["ftp", "telnet", "pop", "imap", "smtp"].includes(pkt.protocol)) {
      if (!cleartextProtocols.has(pkt.protocol)) cleartextProtocols.set(pkt.protocol, []);
      cleartextProtocols.get(pkt.protocol).push(pkt);
    }
    if (pkt.http?.method && !pkt.protocolStack.includes("tls")) {
      if (!cleartextProtocols.has("http")) cleartextProtocols.set("http", []);
      cleartextProtocols.get("http").push(pkt);
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
      mitreTechnique: "T1040"
    });
  }
  const synPackets = packets.filter((p) => p.tcpFlags?.syn && !p.tcpFlags?.ack);
  const synBySource = /* @__PURE__ */ new Map();
  for (const pkt of synPackets) {
    if (!synBySource.has(pkt.srcAddr)) synBySource.set(pkt.srcAddr, /* @__PURE__ */ new Set());
    if (pkt.dstPort) synBySource.get(pkt.srcAddr).add(pkt.dstPort);
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
        mitreTechnique: "T1046"
      });
    }
  }
  const arpReplies = packets.filter((p) => p.protocol === "arp" && p.info === "ARP Reply");
  const macToIp = /* @__PURE__ */ new Map();
  for (const pkt of arpReplies) {
    const mac = pkt.layers?.arp?.["arp.src.hw_mac"] || pkt.srcAddr;
    if (!macToIp.has(mac)) macToIp.set(mac, /* @__PURE__ */ new Set());
    macToIp.get(mac).add(pkt.srcAddr);
  }
  for (const [mac, ips] of macToIp) {
    if (ips.size > 1) {
      findings.push({
        id: genId(),
        severity: "high",
        title: "Possible ARP Spoofing Detected",
        description: `MAC address ${mac} is claiming multiple IP addresses: ${[...ips].join(", ")}. This may indicate ARP cache poisoning.`,
        evidence: `MAC ${mac} \u2192 IPs: ${[...ips].join(", ")}`,
        protocol: "arp",
        srcAddr: [...ips][0],
        dstAddr: "broadcast",
        category: "arp_anomaly",
        frameNumbers: arpReplies.slice(0, 5).map((p) => p.frameNumber),
        mitreTechnique: "T1557.002"
      });
    }
  }
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
      mitreTechnique: "T1071.004"
    });
  }
  const tlsPackets = packets.filter((p) => p.tls?.version);
  const weakTls = tlsPackets.filter((p) => {
    const v = p.tls?.version || "";
    return v.includes("0x0300") || v.includes("0x0301") || v.includes("0x0302");
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
      mitreTechnique: "T1557"
    });
  }
  const httpRequests = packets.filter((p) => p.http?.method);
  const requestsByDest = /* @__PURE__ */ new Map();
  for (const pkt of httpRequests) {
    const key = `${pkt.dstAddr}:${pkt.dstPort}`;
    if (!requestsByDest.has(key)) requestsByDest.set(key, []);
    requestsByDest.get(key).push(pkt.epochTime);
  }
  for (const [dest, times] of requestsByDest) {
    if (times.length >= 5) {
      const intervals = [];
      for (let i = 1; i < times.length; i++) {
        intervals.push(times[i] - times[i - 1]);
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
      const stdDev = Math.sqrt(variance);
      if (avgInterval > 0 && stdDev / avgInterval < 0.3) {
        findings.push({
          id: genId(),
          severity: "high",
          title: `Possible C2 Beaconing to ${dest}`,
          description: `Regular HTTP request pattern detected to ${dest} with ~${Math.round(avgInterval)}s intervals (\u03C3=${stdDev.toFixed(1)}s). Consistent beaconing pattern may indicate C2 communication.`,
          evidence: `${times.length} requests at ~${Math.round(avgInterval)}s intervals`,
          protocol: "http",
          srcAddr: httpRequests.find((p) => `${p.dstAddr}:${p.dstPort}` === dest)?.srcAddr || "",
          dstAddr: dest.split(":")[0],
          port: parseInt(dest.split(":")[1]) || 80,
          category: "c2_beaconing",
          frameNumbers: httpRequests.filter((p) => `${p.dstAddr}:${p.dstPort}` === dest).slice(0, 10).map((p) => p.frameNumber),
          mitreTechnique: "T1071.001"
        });
      }
    }
  }
  return findings;
}
function adaptPcapFindings(findings, packets) {
  const startTime = Date.now();
  const observations = [];
  const errors = [];
  for (const finding of findings) {
    try {
      const obs = {
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
          tags: ["pcap-analysis", finding.category]
        },
        scanner: {
          name: "pcap_analyzer",
          version: "1.0.0",
          adapter: "tshark-json",
          mode: "passive"
        },
        observationType: mapCategoryToObsType(finding.category),
        severity: finding.severity,
        confidence: findingConfidence(finding),
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        evidence: {
          summary: finding.title + ": " + finding.description,
          cve: void 0,
          artifacts: [
            {
              findingId: finding.id,
              category: finding.category,
              evidence: finding.evidence,
              frameNumbers: finding.frameNumbers,
              mitreTechnique: finding.mitreTechnique
            }
          ]
        },
        metadata: {
          notes: `Detected via packet capture analysis. ${finding.frameNumbers.length} relevant packets.`
        }
      };
      observations.push(obs);
    } catch (err) {
      errors.push(`PCAP adapter error for finding ${finding.id}: ${err.message}`);
    }
  }
  return {
    observations,
    metrics: {
      durationMs: Date.now() - startTime,
      requestsMade: packets.length,
      observationsEmitted: observations.length,
      errors
    }
  };
}
function mapCategoryToObsType(category) {
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
function findingConfidence(finding) {
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
async function executeLiveCapture(config) {
  const { executeTool, executeRawCommand } = await import("./scan-server-executor-YEYTXLFW.js");
  const cmd = buildTcpdumpCommand(config);
  const result = await executeTool({
    tool: "bash",
    args: `-c "${cmd.replace(/"/g, '\\"')}"`,
    timeoutSeconds: config.durationSeconds + 30,
    // Extra buffer
    engagementId: config.engagementId,
    sudo: true
    // tcpdump requires root
  });
  const pcapMatch = result.stdout.match(/PCAP_FILE=(\S+)/);
  const pcapPath = pcapMatch?.[1] || `/tmp/capture_${Date.now()}.pcap`;
  const countResult = await executeTool({
    tool: "bash",
    args: `-c "capinfos -c ${pcapPath} 2>/dev/null | grep 'Number of packets' | awk '{print \\$NF}'"`,
    timeoutSeconds: 10
  });
  const packetsCaptured = parseInt(countResult.stdout.trim()) || 0;
  return { pcapPath, packetsCaptured, durationMs: result.durationMs };
}
async function analyzePcap(config) {
  const { executeTool } = await import("./scan-server-executor-YEYTXLFW.js");
  const capinfosResult = await executeTool({
    tool: "bash",
    args: `-c "${buildCapinfosCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId
  });
  const metadata = parseCapinfos(capinfosResult.stdout);
  const tsharkCmd = buildTsharkJsonCommand(config);
  const tsharkResult = await executeTool({
    tool: "bash",
    args: `-c '${tsharkCmd.replace(/'/g, "'\\''")}'`,
    timeoutSeconds: 120,
    engagementId: config.engagementId
  });
  const packets = parseTsharkJson(tsharkResult.stdout);
  const statsResult = await executeTool({
    tool: "bash",
    args: `-c "${buildTsharkStatsCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId
  });
  const protocolStats = parseProtocolStats(statsResult.stdout);
  const convResult = await executeTool({
    tool: "bash",
    args: `-c "${buildTsharkConversationsCommand(config.pcapPath)}"`,
    timeoutSeconds: 30,
    engagementId: config.engagementId
  });
  const conversations = parseConversations(convResult.stdout);
  const streams = [];
  if (config.followStreams) {
    const streamIndices = /* @__PURE__ */ new Set();
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
          engagementId: config.engagementId
        });
        const streamPackets = packets.filter(
          (p) => p.layers?.tcp?.["tcp.stream"] === String(idx)
        );
        if (streamPackets.length > 0) {
          const payload = streamResult.stdout.substring(0, 10240);
          const sensitivePatterns = [
            /password/i,
            /passwd/i,
            /secret/i,
            /token/i,
            /api[_-]?key/i,
            /authorization/i,
            /cookie/i,
            /session/i,
            /bearer/i
          ];
          const sensitiveTypes = sensitivePatterns.filter((p) => p.test(payload)).map((p) => p.source.replace(/[/\\i]/g, ""));
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
            durationMs: (streamPackets[streamPackets.length - 1].epochTime - streamPackets[0].epochTime) * 1e3,
            payload: payload.substring(0, 2048),
            sensitiveDataDetected: sensitiveTypes.length > 0,
            sensitiveDataTypes: sensitiveTypes
          });
        }
      } catch {
      }
    }
  }
  const findings = detectFindings(packets);
  return { metadata, packets, streams, protocolStats, findings, conversations };
}
async function ingestPcapResults(findings, packets) {
  const { ingestRawObservations } = await import("./observation-ingestor-VVPWUX7Y.js");
  const adapterResult = adaptPcapFindings(findings, packets);
  if (adapterResult.observations.length > 0) {
    await ingestRawObservations(adapterResult.observations, "pcap_analyzer");
  }
  return {
    observations: adapterResult.observations.length,
    findings: findings.length,
    errors: adapterResult.metrics.errors
  };
}
var init_pcap_analyzer = __esm({
  "server/lib/pcap-analyzer.ts"() {
    init_observation_normalizer();
  }
});
init_pcap_analyzer();
export {
  adaptPcapFindings,
  analyzePcap,
  buildCapinfosCommand,
  buildTcpdumpCommand,
  buildTsharkConversationsCommand,
  buildTsharkFollowStreamCommand,
  buildTsharkJsonCommand,
  buildTsharkStatsCommand,
  detectFindings,
  executeLiveCapture,
  ingestPcapResults,
  parseCapinfos,
  parseConversations,
  parseProtocolStats,
  parseTsharkJson
};
