import "./chunk-KFQGP6VL.js";

// server/lib/scapy-crafter.ts
function generateScapyScript(config) {
  switch (config.template) {
    case "syn_scan":
      return generateSynScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "ack_scan":
      return generateAckScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "fin_scan":
      return generateFinScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "xmas_scan":
      return generateXmasScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "null_scan":
      return generateNullScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "window_scan":
      return generateWindowScanScript(config.target, config.ports || [80, 443, 22, 8080]);
    case "os_fingerprint":
      return generateOsFingerprintScript(config.target);
    case "firewall_map":
      return generateFirewallMapScript(config.target, config.ports || [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]);
    case "traceroute":
      return generateTracerouteScript(config.target, config.options?.maxHops || 30);
    case "arp_discover":
      return generateArpDiscoverScript(config.target);
    case "dns_amplification_test":
      return generateDnsAmplificationScript(config.target);
    case "icmp_tunnel_probe":
      return generateIcmpTunnelProbeScript(config.target);
    case "tcp_isn_analysis":
      return generateTcpIsnScript(config.target, config.ports?.[0] || 80);
    case "ip_id_analysis":
      return generateIpIdScript(config.target, config.ports?.[0] || 80);
    case "idle_scan_zombie_check":
      return generateIdleScanZombieScript(config.target);
    default:
      throw new Error(`Unknown probe template: ${config.template}`);
  }
}
function scriptPreamble() {
  return `#!/usr/bin/env python3
import json, sys, time
from scapy.all import *
conf.verb = 0  # Suppress Scapy output
results = []
start_time = time.time()
`;
}
function scriptPostamble(probeType) {
  return `
duration_ms = int((time.time() - start_time) * 1000)
output = {
    "probeType": "${probeType}",
    "packetsSent": len(results),
    "responsesReceived": sum(1 for r in results if r.get("responded")),
    "durationMs": duration_ms,
    "results": results
}
print(json.dumps(output))
`;
}
function generateSynScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=2)
    result = {"dstPort": port, "responded": resp is not None}
    if resp:
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            result["responseFlags"] = str(flags)
            result["responseTtl"] = resp[IP].ttl
            if flags == 0x12:  # SYN-ACK
                result["portState"] = "open"
                result["responseType"] = "SA"
                # Send RST to close
                sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=0.5)
            elif flags & 0x04:  # RST
                result["portState"] = "closed"
                result["responseType"] = "R"
        elif resp.haslayer(ICMP):
            result["portState"] = "filtered"
            result["responseType"] = "ICMP unreachable"
    else:
        result["portState"] = "filtered"
    results.append(result)
${scriptPostamble("syn_scan")}`;
}
function generateAckScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=2)
    result = {"dstPort": port, "responded": resp is not None}
    if resp:
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            result["responseFlags"] = str(flags)
            result["responseTtl"] = resp[IP].ttl
            if flags & 0x04:  # RST
                result["portState"] = "unfiltered"
                result["responseType"] = "R"
                # Window size analysis for firewall detection
                if resp[TCP].window > 0:
                    result["osHint"] = "Window > 0 may indicate open port behind stateless firewall"
            else:
                result["portState"] = "filtered"
        elif resp.haslayer(ICMP):
            result["portState"] = "filtered"
            result["responseType"] = "ICMP unreachable"
    else:
        result["portState"] = "filtered"
    results.append(result)
${scriptPostamble("ack_scan")}`;
}
function generateFinScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="F")
    resp = sr1(pkt, timeout=3)
    result = {"dstPort": port, "responded": resp is not None}
    if resp:
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            result["portState"] = "closed"
            result["responseType"] = "R"
        elif resp.haslayer(ICMP):
            result["portState"] = "filtered"
            result["responseType"] = "ICMP unreachable"
    else:
        result["portState"] = "open|filtered"
    results.append(result)
${scriptPostamble("fin_scan")}`;
}
function generateXmasScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="FPU")
    resp = sr1(pkt, timeout=3)
    result = {"dstPort": port, "responded": resp is not None}
    if resp:
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            result["portState"] = "closed"
            result["responseType"] = "R"
        elif resp.haslayer(ICMP):
            result["portState"] = "filtered"
            result["responseType"] = "ICMP unreachable"
    else:
        result["portState"] = "open|filtered"
    results.append(result)
${scriptPostamble("xmas_scan")}`;
}
function generateNullScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="")
    resp = sr1(pkt, timeout=3)
    result = {"dstPort": port, "responded": resp is not None}
    if resp:
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            result["portState"] = "closed"
            result["responseType"] = "R"
        elif resp.haslayer(ICMP):
            result["portState"] = "filtered"
            result["responseType"] = "ICMP unreachable"
    else:
        result["portState"] = "open|filtered"
    results.append(result)
${scriptPostamble("null_scan")}`;
}
function generateWindowScanScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
for port in ports:
    pkt = IP(dst=target)/TCP(dport=port, flags="A")
    resp = sr1(pkt, timeout=2)
    result = {"dstPort": port, "responded": resp is not None}
    if resp and resp.haslayer(TCP):
        win = resp[TCP].window
        flags = resp[TCP].flags
        result["responseFlags"] = str(flags)
        result["responseTtl"] = resp[IP].ttl
        if flags & 0x04:  # RST
            if win > 0:
                result["portState"] = "open"
                result["responseType"] = f"R (window={win})"
                result["osHint"] = f"TCP window={win} in RST suggests open port"
            else:
                result["portState"] = "closed"
                result["responseType"] = f"R (window=0)"
    elif resp and resp.haslayer(ICMP):
        result["portState"] = "filtered"
        result["responseType"] = "ICMP unreachable"
    elif not resp:
        result["portState"] = "filtered"
    results.append(result)
${scriptPostamble("window_scan")}`;
}
function generateOsFingerprintScript(target) {
  return `${scriptPreamble()}
target = "${target}"
# Probe 1: SYN to open port (80)
syn_resp = sr1(IP(dst=target)/TCP(dport=80, flags="S"), timeout=3)
if syn_resp and syn_resp.haslayer(TCP):
    ttl = syn_resp[IP].ttl
    win = syn_resp[TCP].window
    df = bool(syn_resp[IP].flags & 0x02)
    mss = 0
    for opt in syn_resp[TCP].options:
        if opt[0] == "MSS":
            mss = opt[1]
    results.append({
        "dstPort": 80,
        "responded": True,
        "responseTtl": ttl,
        "responseFlags": str(syn_resp[TCP].flags),
        "responseType": "SYN-ACK fingerprint",
        "osHint": f"TTL={ttl} WIN={win} DF={df} MSS={mss}",
        "portState": "open"
    })
    # Send RST
    sr1(IP(dst=target)/TCP(dport=80, flags="R"), timeout=0.5)
    # OS guess based on TTL and window
    os_guess = "Unknown"
    if ttl <= 64:
        if win == 5840 or win == 14600 or win == 29200:
            os_guess = "Linux"
        elif win == 65535:
            os_guess = "FreeBSD/macOS"
        else:
            os_guess = "Linux/Unix (TTL<=64)"
    elif ttl <= 128:
        if win == 8192 or win == 65535:
            os_guess = "Windows"
        else:
            os_guess = "Windows (TTL<=128)"
    elif ttl <= 255:
        os_guess = "Cisco/Network device (TTL<=255)"
    results[-1]["osHint"] += f" -> Likely: {os_guess}"
else:
    results.append({"dstPort": 80, "responded": False, "portState": "filtered"})

# Probe 2: ICMP echo
icmp_resp = sr1(IP(dst=target)/ICMP(), timeout=3)
if icmp_resp:
    results.append({
        "dstPort": 0,
        "responded": True,
        "responseTtl": icmp_resp[IP].ttl,
        "responseType": "ICMP echo reply",
        "osHint": f"ICMP TTL={icmp_resp[IP].ttl}"
    })
else:
    results.append({"dstPort": 0, "responded": False, "responseType": "No ICMP reply", "osHint": "ICMP filtered"})

# Probe 3: TCP timestamp option
ts_pkt = IP(dst=target)/TCP(dport=80, flags="S", options=[("Timestamp", (0, 0))])
ts_resp = sr1(ts_pkt, timeout=3)
if ts_resp and ts_resp.haslayer(TCP):
    for opt in ts_resp[TCP].options:
        if opt[0] == "Timestamp":
            results.append({
                "dstPort": 80,
                "responded": True,
                "responseType": "TCP timestamp",
                "osHint": f"TSval={opt[1][0]} TSecr={opt[1][1]}"
            })
            break
    sr1(IP(dst=target)/TCP(dport=80, flags="R"), timeout=0.5)
${scriptPostamble("os_fingerprint")}`;
}
function generateFirewallMapScript(target, ports) {
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
# Phase 1: SYN scan to find open/closed/filtered
for port in ports:
    syn = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2)
    ack = sr1(IP(dst=target)/TCP(dport=port, flags="A"), timeout=2)
    result = {"dstPort": port, "responded": syn is not None or ack is not None}
    syn_state = "filtered"
    ack_state = "filtered"
    if syn:
        if syn.haslayer(TCP):
            if syn[TCP].flags == 0x12: syn_state = "open"
            elif syn[TCP].flags & 0x04: syn_state = "closed"
        elif syn.haslayer(ICMP): syn_state = "filtered"
    if ack:
        if ack.haslayer(TCP) and ack[TCP].flags & 0x04:
            ack_state = "unfiltered"
        elif ack.haslayer(ICMP): ack_state = "filtered"
    # Infer firewall behavior
    if syn_state == "filtered" and ack_state == "unfiltered":
        fw = "stateful firewall (blocks SYN, passes ACK)"
    elif syn_state == "filtered" and ack_state == "filtered":
        fw = "strict firewall (blocks both)"
    elif syn_state != "filtered" and ack_state == "filtered":
        fw = "stateful firewall (passes SYN, blocks unsolicited ACK)"
    else:
        fw = "no firewall detected"
    result["portState"] = syn_state
    result["responseType"] = f"SYN={syn_state} ACK={ack_state}"
    result["osHint"] = fw
    results.append(result)
    if syn and syn.haslayer(TCP) and syn[TCP].flags == 0x12:
        sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=0.5)
${scriptPostamble("firewall_map")}`;
}
function generateTracerouteScript(target, maxHops) {
  return `${scriptPreamble()}
target = "${target}"
max_hops = ${maxHops}
for ttl in range(1, max_hops + 1):
    pkt = IP(dst=target, ttl=ttl)/ICMP()
    resp = sr1(pkt, timeout=2)
    result = {"dstPort": 0, "responded": resp is not None, "responseTtl": ttl}
    if resp:
        result["responseType"] = f"hop {ttl}: {resp[IP].src}"
        result["rawResponse"] = resp[IP].src
        result["osHint"] = f"TTL={ttl} -> {resp[IP].src}"
        if resp[IP].src == target or (resp.haslayer(ICMP) and resp[ICMP].type == 0):
            result["portState"] = "open"
            results.append(result)
            break
        result["portState"] = "filtered" if resp[ICMP].type == 11 else "closed"
    else:
        result["responseType"] = f"hop {ttl}: * (timeout)"
        result["rawResponse"] = "*"
    results.append(result)
${scriptPostamble("traceroute")}`;
}
function generateArpDiscoverScript(target) {
  return `${scriptPreamble()}
target = "${target}"
# ARP scan the subnet
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3)
for sent, received in ans:
    results.append({
        "dstPort": 0,
        "responded": True,
        "responseType": f"ARP reply from {received[ARP].psrc} ({received[Ether].src})",
        "rawResponse": f"{received[ARP].psrc} -> {received[Ether].src}",
        "osHint": f"MAC={received[Ether].src}",
        "portState": "open"
    })
${scriptPostamble("arp_discover")}`;
}
function generateDnsAmplificationScript(target) {
  return `${scriptPreamble()}
target = "${target}"
# Test DNS amplification factor
queries = [
    ("ANY", ".", "root ANY"),
    ("ANY", "google.com", "google ANY"),
    ("TXT", "google.com", "google TXT"),
    ("DNSKEY", ".", "root DNSKEY"),
]
for qtype, qname, label in queries:
    pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSKEY(qname=qname, qtype=qtype))
    resp = sr1(pkt, timeout=3)
    result = {"dstPort": 53, "responded": resp is not None}
    if resp and resp.haslayer(DNS):
        req_size = len(pkt)
        resp_size = len(resp)
        amp_factor = resp_size / req_size if req_size > 0 else 0
        result["responseType"] = f"{label}: req={req_size}B resp={resp_size}B amp={amp_factor:.1f}x"
        result["osHint"] = f"Amplification factor: {amp_factor:.1f}x"
        result["portState"] = "open" if amp_factor > 1 else "closed"
    results.append(result)
${scriptPostamble("dns_amplification_test")}`;
}
function generateIcmpTunnelProbeScript(target) {
  return `${scriptPreamble()}
target = "${target}"
# Test ICMP echo with various payload sizes to detect tunneling potential
payloads = [
    (b"A" * 32, "32B standard"),
    (b"A" * 64, "64B standard"),
    (b"A" * 512, "512B large"),
    (b"A" * 1024, "1024B very large"),
    (b"\\x00" * 64, "64B null"),
    (b"GET / HTTP/1.1\\r\\n" + b"A" * 48, "64B HTTP-in-ICMP"),
]
for payload, label in payloads:
    pkt = IP(dst=target)/ICMP()/Raw(load=payload)
    resp = sr1(pkt, timeout=3)
    result = {"dstPort": 0, "responded": resp is not None}
    if resp:
        resp_payload = bytes(resp[Raw].load) if resp.haslayer(Raw) else b""
        result["responseType"] = f"{label}: echoed {len(resp_payload)}B"
        result["osHint"] = f"Payload echoed: {len(resp_payload) == len(payload)}"
        result["portState"] = "open"
    else:
        result["responseType"] = f"{label}: no reply"
        result["portState"] = "filtered"
    results.append(result)
${scriptPostamble("icmp_tunnel_probe")}`;
}
function generateTcpIsnScript(target, port) {
  return `${scriptPreamble()}
target = "${target}"
port = ${port}
# Collect TCP ISN (Initial Sequence Number) samples
isns = []
for i in range(10):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=2)
    if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:
        isn = resp[TCP].seq
        isns.append(isn)
        sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=0.5)
        results.append({
            "dstPort": port,
            "responded": True,
            "responseType": f"ISN sample {i+1}: {isn}",
            "portState": "open"
        })
    else:
        results.append({"dstPort": port, "responded": False, "portState": "filtered"})
    time.sleep(0.1)

# Analyze ISN predictability
if len(isns) >= 3:
    diffs = [isns[i+1] - isns[i] for i in range(len(isns)-1)]
    avg_diff = sum(diffs) / len(diffs) if diffs else 0
    variance = sum((d - avg_diff)**2 for d in diffs) / len(diffs) if diffs else 0
    std_dev = variance ** 0.5
    predictable = std_dev < (avg_diff * 0.1) if avg_diff > 0 else std_dev < 1000
    results.append({
        "dstPort": port,
        "responded": True,
        "responseType": f"ISN analysis: avg_diff={avg_diff:.0f} stddev={std_dev:.0f}",
        "osHint": f"ISN {'PREDICTABLE' if predictable else 'random'} (stddev={std_dev:.0f})",
        "portState": "open"
    })
${scriptPostamble("tcp_isn_analysis")}`;
}
function generateIpIdScript(target, port) {
  return `${scriptPreamble()}
target = "${target}"
port = ${port}
# Collect IP ID values to check for incrementing (zombie candidate)
ip_ids = []
for i in range(10):
    pkt = IP(dst=target)/TCP(dport=port, flags="SA")
    resp = sr1(pkt, timeout=2)
    if resp and resp.haslayer(IP):
        ip_id = resp[IP].id
        ip_ids.append(ip_id)
        results.append({
            "dstPort": port,
            "responded": True,
            "responseType": f"IP ID sample {i+1}: {ip_id}",
            "portState": "open"
        })
    else:
        results.append({"dstPort": port, "responded": False})
    time.sleep(0.2)

if len(ip_ids) >= 3:
    diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
    incremental = all(0 < d <= 10 for d in diffs)
    results.append({
        "dstPort": port,
        "responded": True,
        "responseType": f"IP ID analysis: diffs={diffs}",
        "osHint": f"IP ID {'INCREMENTAL (zombie candidate)' if incremental else 'random/not suitable'}",
        "portState": "open"
    })
${scriptPostamble("ip_id_analysis")}`;
}
function generateIdleScanZombieScript(target) {
  return `${scriptPreamble()}
target = "${target}"
# Check if target is suitable as an idle scan zombie
# Requirements: incremental IP ID, responsive to SYN-ACK
ip_ids = []
for i in range(5):
    pkt = IP(dst=target)/TCP(dport=80, flags="SA")
    resp = sr1(pkt, timeout=2)
    if resp and resp.haslayer(IP):
        ip_ids.append(resp[IP].id)
    time.sleep(0.3)

if len(ip_ids) >= 3:
    diffs = [ip_ids[i+1] - ip_ids[i] for i in range(len(ip_ids)-1)]
    incremental = all(0 < d <= 5 for d in diffs)
    results.append({
        "dstPort": 80,
        "responded": True,
        "responseType": f"Zombie check: IP IDs={ip_ids} diffs={diffs}",
        "osHint": f"{'SUITABLE zombie (incremental IP ID, step={diffs[0] if diffs else 0})' if incremental else 'NOT suitable (non-incremental IP ID)'}",
        "portState": "open"
    })
else:
    results.append({
        "dstPort": 80,
        "responded": False,
        "responseType": "Insufficient responses for zombie check",
        "osHint": "NOT suitable (unresponsive)"
    })
${scriptPostamble("idle_scan_zombie_check")}`;
}
function generateCustomPacketScript(config) {
  const target = config.target;
  const count = config.count || 1;
  const timeout = config.timeout || 3;
  const delay = config.delay || 0;
  let packetConstruction;
  switch (config.protocol) {
    case "tcp":
      packetConstruction = `IP(dst="${target}"${config.ttl ? `, ttl=${config.ttl}` : ""})/TCP(dport=port, ${config.srcPort ? `sport=${config.srcPort}, ` : ""}flags="${config.tcpFlags || "S"}")`;
      break;
    case "udp":
      packetConstruction = `IP(dst="${target}"${config.ttl ? `, ttl=${config.ttl}` : ""})/UDP(dport=port${config.srcPort ? `, sport=${config.srcPort}` : ""})${config.payload ? `/Raw(load=b"${config.payload}")` : ""}`;
      break;
    case "icmp":
      packetConstruction = `IP(dst="${target}"${config.ttl ? `, ttl=${config.ttl}` : ""})/ICMP()${config.payload ? `/Raw(load=b"${config.payload}")` : ""}`;
      break;
    case "arp":
      packetConstruction = `Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="${target}")`;
      break;
    case "dns":
      packetConstruction = `IP(dst="${target}")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="${config.payload || "example.com"}"))`;
      break;
    default:
      packetConstruction = `IP(dst="${target}"${config.ttl ? `, ttl=${config.ttl}` : ""})/Raw(load=b"${config.payload || ""}")`;
  }
  const ports = config.ports || [0];
  return `${scriptPreamble()}
target = "${target}"
ports = ${JSON.stringify(ports)}
count = ${count}
timeout = ${timeout}
delay = ${delay}

for port in ports:
    for i in range(count):
        pkt = ${packetConstruction}
        ${config.captureResponses !== false ? `resp = sr1(pkt, timeout=timeout)` : `send(pkt); resp = None`}
        result = {"dstPort": port, "responded": resp is not None}
        if resp:
            if resp.haslayer(TCP):
                result["responseFlags"] = str(resp[TCP].flags)
                result["responseTtl"] = resp[IP].ttl
                result["responseTimeMs"] = int((time.time() - start_time) * 1000)
            elif resp.haslayer(ICMP):
                result["responseType"] = f"ICMP type={resp[ICMP].type} code={resp[ICMP].code}"
                result["responseTtl"] = resp[IP].ttl
            elif resp.haslayer(IP):
                result["responseTtl"] = resp[IP].ttl
            result["rawResponse"] = resp.summary()
        results.append(result)
        if delay > 0:
            time.sleep(delay)
${scriptPostamble("custom_packet")}`;
}
async function executeScapyProbe(config) {
  const { executeTool } = await import("./scan-server-executor-HXNK5NX6.js");
  const script = generateScapyScript(config);
  const scriptPath = `/tmp/scapy_probe_${Date.now()}.py`;
  const escapedScript = script.replace(/'/g, "'\\''");
  await executeTool({
    tool: "bash",
    args: `-c 'cat > ${scriptPath} << '"'"'SCAPY_EOF'"'"'
${escapedScript}
SCAPY_EOF'`,
    timeoutSeconds: 10,
    engagementId: config.engagementId
  });
  const result = await executeTool({
    tool: "python3",
    args: scriptPath,
    timeoutSeconds: 120,
    engagementId: config.engagementId,
    sudo: true
  });
  await executeTool({
    tool: "bash",
    args: `-c "rm -f ${scriptPath}"`,
    timeoutSeconds: 5
  }).catch(() => {
  });
  let probeResult;
  try {
    const parsed = JSON.parse(result.stdout.trim());
    probeResult = {
      probeType: parsed.probeType || config.template,
      target: config.target,
      packetsSent: parsed.packetsSent || 0,
      responsesReceived: parsed.responsesReceived || 0,
      durationMs: parsed.durationMs || result.durationMs,
      results: parsed.results || [],
      analysis: generateAnalysis(config.template, parsed.results || []),
      rawOutput: result.stdout.substring(0, 5e3)
    };
  } catch {
    probeResult = {
      probeType: config.template,
      target: config.target,
      packetsSent: 0,
      responsesReceived: 0,
      durationMs: result.durationMs,
      results: [],
      analysis: `Probe failed: ${result.stderr || "Unknown error"}`,
      rawOutput: (result.stdout + "\n" + result.stderr).substring(0, 5e3)
    };
  }
  return probeResult;
}
async function executeCustomPacket(config) {
  const { executeTool } = await import("./scan-server-executor-HXNK5NX6.js");
  const script = generateCustomPacketScript(config);
  const scriptPath = `/tmp/scapy_custom_${Date.now()}.py`;
  const escapedScript = script.replace(/'/g, "'\\''");
  await executeTool({
    tool: "bash",
    args: `-c 'cat > ${scriptPath} << '"'"'SCAPY_EOF'"'"'
${escapedScript}
SCAPY_EOF'`,
    timeoutSeconds: 10,
    engagementId: config.engagementId
  });
  const result = await executeTool({
    tool: "python3",
    args: scriptPath,
    timeoutSeconds: 120,
    engagementId: config.engagementId,
    sudo: true
  });
  await executeTool({
    tool: "bash",
    args: `-c "rm -f ${scriptPath}"`,
    timeoutSeconds: 5
  }).catch(() => {
  });
  try {
    const parsed = JSON.parse(result.stdout.trim());
    return {
      probeType: "custom_packet",
      target: config.target,
      packetsSent: parsed.packetsSent || 0,
      responsesReceived: parsed.responsesReceived || 0,
      durationMs: parsed.durationMs || result.durationMs,
      results: parsed.results || [],
      analysis: `Custom ${config.protocol.toUpperCase()} packet${config.tcpFlags ? ` (flags=${config.tcpFlags})` : ""} sent to ${config.target}`,
      rawOutput: result.stdout.substring(0, 5e3)
    };
  } catch {
    return {
      probeType: "custom_packet",
      target: config.target,
      packetsSent: 0,
      responsesReceived: 0,
      durationMs: result.durationMs,
      results: [],
      analysis: `Custom packet failed: ${result.stderr || "Unknown error"}`,
      rawOutput: (result.stdout + "\n" + result.stderr).substring(0, 5e3)
    };
  }
}
function generateAnalysis(template, results) {
  const responded = results.filter((r) => r.responded);
  const total = results.length;
  switch (template) {
    case "syn_scan": {
      const open = results.filter((r) => r.portState === "open");
      const closed = results.filter((r) => r.portState === "closed");
      const filtered = results.filter((r) => r.portState === "filtered");
      return `SYN scan: ${open.length} open, ${closed.length} closed, ${filtered.length} filtered out of ${total} ports probed. Open ports: ${open.map((r) => r.dstPort).join(", ") || "none"}`;
    }
    case "ack_scan": {
      const unfiltered = results.filter((r) => r.portState === "unfiltered");
      const filtered = results.filter((r) => r.portState === "filtered");
      return `ACK scan (firewall detection): ${unfiltered.length} unfiltered, ${filtered.length} filtered. ${filtered.length > 0 ? "Stateful firewall detected on filtered ports." : "No stateful firewall detected."}`;
    }
    case "firewall_map": {
      const fwTypes = new Set(results.map((r) => r.osHint).filter(Boolean));
      return `Firewall mapping: ${total} ports probed. Detected behaviors: ${[...fwTypes].join("; ")}`;
    }
    case "os_fingerprint": {
      const osHints = results.filter((r) => r.osHint).map((r) => r.osHint);
      return `OS fingerprinting: ${osHints.join("; ")}`;
    }
    case "traceroute": {
      const hops = results.filter((r) => r.rawResponse && r.rawResponse !== "*");
      return `Traceroute: ${hops.length} hops responded out of ${total}. Path: ${results.map((r) => r.rawResponse || "*").join(" \u2192 ")}`;
    }
    case "tcp_isn_analysis": {
      const analysis = results.find((r) => r.responseType?.includes("ISN analysis"));
      return analysis?.osHint || `TCP ISN analysis: ${responded.length} samples collected`;
    }
    case "ip_id_analysis": {
      const analysis = results.find((r) => r.responseType?.includes("IP ID analysis"));
      return analysis?.osHint || `IP ID analysis: ${responded.length} samples collected`;
    }
    case "idle_scan_zombie_check": {
      const check = results.find((r) => r.osHint);
      return check?.osHint || "Zombie suitability check inconclusive";
    }
    default:
      return `${template}: ${responded.length}/${total} packets received responses`;
  }
}
async function provisionPacketTools() {
  const { executeTool } = await import("./scan-server-executor-HXNK5NX6.js");
  const installed = [];
  const failed = [];
  let output = "";
  const installScript = `
set -e
export DEBIAN_FRONTEND=noninteractive

# Update package lists
apt-get update -qq

# Install tshark (includes editcap, mergecap, capinfos)
echo "=== Installing tshark ==="
apt-get install -y -qq tshark 2>&1 || echo "FAIL: tshark"

# Install tcpdump
echo "=== Installing tcpdump ==="
apt-get install -y -qq tcpdump 2>&1 || echo "FAIL: tcpdump"

# Install Python3 and Scapy
echo "=== Installing Scapy ==="
apt-get install -y -qq python3-pip python3-scapy 2>&1 || pip3 install scapy 2>&1 || echo "FAIL: scapy"

# Verify installations
echo "=== Verification ==="
which tshark && echo "OK: tshark $(tshark --version 2>&1 | head -1)" || echo "FAIL: tshark not found"
which tcpdump && echo "OK: tcpdump $(tcpdump --version 2>&1 | head -1)" || echo "FAIL: tcpdump not found"
which editcap && echo "OK: editcap" || echo "FAIL: editcap not found"
which capinfos && echo "OK: capinfos" || echo "FAIL: capinfos not found"
python3 -c "import scapy; print(f'OK: scapy {scapy.VERSION}')" 2>&1 || echo "FAIL: scapy import"

echo "=== Done ==="
`;
  try {
    const result = await executeTool({
      tool: "bash",
      args: `-c '${installScript.replace(/'/g, "'\\''")}'`,
      timeoutSeconds: 180,
      sudo: true
    });
    output = result.stdout + "\n" + result.stderr;
    const lines = output.split("\n");
    for (const line of lines) {
      if (line.startsWith("OK: ")) {
        installed.push(line.substring(4).split(" ")[0]);
      } else if (line.startsWith("FAIL: ")) {
        failed.push(line.substring(6));
      }
    }
    return {
      success: failed.length === 0,
      installed,
      failed,
      output: output.substring(0, 3e3)
    };
  } catch (err) {
    return {
      success: false,
      installed,
      failed: ["installation script failed"],
      output: err.message
    };
  }
}
export {
  executeCustomPacket,
  executeScapyProbe,
  generateCustomPacketScript,
  generateScapyScript,
  provisionPacketTools
};
