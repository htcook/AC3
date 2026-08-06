/**
 * ScanForge SNMP Protocol Handler
 * 
 * Inspired by OpenVAS nasl_snmp.c — provides network device scanning
 * via SNMP v1/v2c/v3 protocol.
 * 
 * Features:
 * - Community string brute-force (v1/v2c)
 * - System information extraction (sysDescr, sysName, sysLocation, etc.)
 * - Interface enumeration
 * - Routing table extraction
 * - ARP table extraction
 * - Default community string detection
 * - SNMP v3 user enumeration
 * - Network device fingerprinting
 * - Populates KB with SNMP-specific findings
 * 
 * Implementation: Generates shell commands executed on the scan server
 * via SSH, using snmpwalk, snmpget, onesixtyone, etc.
 */

import { ScanForgeKB, KB_KEYS } from "./knowledge-base";

export interface SNMPScanConfig {
  host: string;
  port?: number;            // Default 161
  communities?: string[];   // Community strings to try
  version?: "1" | "2c" | "3";
  v3User?: string;
  v3AuthPass?: string;
  v3PrivPass?: string;
  v3AuthProto?: "MD5" | "SHA";
  v3PrivProto?: "DES" | "AES";
  timeout?: number;
}

export interface SNMPHostInfo {
  host: string;
  port: number;
  community?: string;       // Working community string
  version: string;
  sysDescr?: string;
  sysName?: string;
  sysLocation?: string;
  sysContact?: string;
  sysObjectID?: string;
  uptime?: string;
  interfaces: SNMPInterface[];
  routes: SNMPRoute[];
  deviceType?: string;       // router, switch, firewall, printer, etc.
}

export interface SNMPInterface {
  index: number;
  name: string;
  type: string;
  speed: string;
  mac?: string;
  ip?: string;
  status: "up" | "down" | "unknown";
}

export interface SNMPRoute {
  destination: string;
  nextHop: string;
  mask: string;
  metric: number;
  type: string;
}

export interface SNMPVuln {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  remediation: string;
  evidence: string;
}

// Standard OIDs
const OID = {
  sysDescr:    "1.3.6.1.2.1.1.1.0",
  sysObjectID: "1.3.6.1.2.1.1.2.0",
  sysUpTime:   "1.3.6.1.2.1.1.3.0",
  sysContact:  "1.3.6.1.2.1.1.4.0",
  sysName:     "1.3.6.1.2.1.1.5.0",
  sysLocation: "1.3.6.1.2.1.1.6.0",
  sysServices: "1.3.6.1.2.1.1.7.0",
  ifTable:     "1.3.6.1.2.1.2.2",
  ipRouteTable: "1.3.6.1.2.1.4.21",
  ipNetToMedia: "1.3.6.1.2.1.4.22",  // ARP table
  hrSWInstalled: "1.3.6.1.2.1.25.6.3.1", // Installed software
  hrProcessorLoad: "1.3.6.1.2.1.25.3.3.1.2", // CPU load
  hrStorageTable: "1.3.6.1.2.1.25.2.3", // Storage
} as const;

// Default community strings to test
const DEFAULT_COMMUNITIES = [
  "public", "private", "community", "snmp", "admin",
  "default", "password", "test", "monitor", "manager",
  "cisco", "switch", "router", "cable-docsis", "secret",
  "write", "read", "security", "system", "network",
  "mngt", "internal", "restricted", "ILMI", "all private",
  "all public", "snmpd", "guest", "proxy", "superuser",
];

/**
 * SNMP Protocol Handler
 */
export class SNMPHandler {
  
  /**
   * Generate all SNMP scan commands for a host
   */
  buildScanCommands(config: SNMPScanConfig): Array<{
    id: string;
    command: string;
    parser: string;
    timeout: number;
  }> {
    const host = config.host;
    const port = config.port || 161;
    const timeout = config.timeout || 15;
    const communities = config.communities || DEFAULT_COMMUNITIES;
    
    const commands: Array<{
      id: string;
      command: string;
      parser: string;
      timeout: number;
    }> = [];
    
    // 1. Community string brute-force using onesixtyone
    const commFile = `/tmp/snmp_comm_${Date.now()}.txt`;
    commands.push({
      id: "snmp-community-brute",
      command: `echo '${communities.join("\\n")}' > ${commFile} && timeout ${timeout * 2} onesixtyone -c ${commFile} -p ${port} ${host} 2>/dev/null; rm -f ${commFile}`,
      parser: "parseCommunityBrute",
      timeout: timeout * 2,
    });
    
    // 2. System information (try "public" first, then "private")
    for (const community of ["public", "private"]) {
      commands.push({
        id: `snmp-sysinfo-${community}`,
        command: [
          `timeout ${timeout} snmpget -v2c -c '${community}' ${host}:${port} ${OID.sysDescr} ${OID.sysName} ${OID.sysLocation} ${OID.sysContact} ${OID.sysObjectID} ${OID.sysUpTime} 2>/dev/null || echo "TIMEOUT"`,
        ].join(" && "),
        parser: "parseSysInfo",
        timeout,
      });
    }
    
    // 3. Interface enumeration
    commands.push({
      id: "snmp-interfaces",
      command: `timeout ${timeout} snmpwalk -v2c -c public ${host}:${port} ${OID.ifTable} 2>/dev/null | head -100 || echo "TIMEOUT"`,
      parser: "parseInterfaces",
      timeout,
    });
    
    // 4. Routing table
    commands.push({
      id: "snmp-routes",
      command: `timeout ${timeout} snmpwalk -v2c -c public ${host}:${port} ${OID.ipRouteTable} 2>/dev/null | head -100 || echo "TIMEOUT"`,
      parser: "parseRoutes",
      timeout,
    });
    
    // 5. ARP table
    commands.push({
      id: "snmp-arp",
      command: `timeout ${timeout} snmpwalk -v2c -c public ${host}:${port} ${OID.ipNetToMedia} 2>/dev/null | head -100 || echo "TIMEOUT"`,
      parser: "parseARP",
      timeout,
    });
    
    // 6. Installed software (if host-resources MIB available)
    commands.push({
      id: "snmp-software",
      command: `timeout ${timeout} snmpwalk -v2c -c public ${host}:${port} ${OID.hrSWInstalled} 2>/dev/null | head -200 || echo "TIMEOUT"`,
      parser: "parseSoftware",
      timeout,
    });
    
    // 7. SNMPv3 user enumeration
    commands.push({
      id: "snmp-v3-users",
      command: `timeout ${timeout} snmpwalk -v3 -l noAuthNoPriv -u "" ${host}:${port} 1.3.6.1.6.3.15.1.2.2.1.3 2>&1 | head -20 || echo "TIMEOUT"`,
      parser: "parseV3Users",
      timeout,
    });
    
    // 8. Write access test (try setting sysLocation with "private")
    commands.push({
      id: "snmp-write-test",
      command: `timeout ${timeout} snmpset -v2c -c private ${host}:${port} ${OID.sysLocation} s "ScanForge-WriteTest" 2>&1 | head -5 || echo "DENIED"`,
      parser: "parseWriteTest",
      timeout,
    });
    
    return commands;
  }
  
  // ─── Output Parsers ────────────────────────────────────────────
  
  parseCommunityBrute(output: string): string[] {
    const communities: string[] = [];
    const lines = output.split("\n");
    for (const line of lines) {
      // onesixtyone output format: "IP [community] description"
      const match = line.match(/\[([^\]]+)\]/);
      if (match) communities.push(match[1]);
    }
    return [...new Set(communities)];
  }
  
  parseSysInfo(output: string): Partial<SNMPHostInfo> {
    const info: Partial<SNMPHostInfo> = {};
    
    const descrMatch = output.match(/sysDescr\.0\s*=\s*STRING:\s*"?(.+)"?/i);
    if (descrMatch) info.sysDescr = descrMatch[1].trim().replace(/"/g, "");
    
    const nameMatch = output.match(/sysName\.0\s*=\s*STRING:\s*"?(.+)"?/i);
    if (nameMatch) info.sysName = nameMatch[1].trim().replace(/"/g, "");
    
    const locMatch = output.match(/sysLocation\.0\s*=\s*STRING:\s*"?(.+)"?/i);
    if (locMatch) info.sysLocation = locMatch[1].trim().replace(/"/g, "");
    
    const contactMatch = output.match(/sysContact\.0\s*=\s*STRING:\s*"?(.+)"?/i);
    if (contactMatch) info.sysContact = contactMatch[1].trim().replace(/"/g, "");
    
    const oidMatch = output.match(/sysObjectID\.0\s*=\s*OID:\s*(.+)/i);
    if (oidMatch) info.sysObjectID = oidMatch[1].trim();
    
    const uptimeMatch = output.match(/sysUpTime.*Timeticks:\s*\((\d+)\)\s*(.+)/i);
    if (uptimeMatch) info.uptime = uptimeMatch[2].trim();
    
    return info;
  }
  
  /**
   * Fingerprint device type from sysDescr and sysObjectID
   */
  fingerPrintDevice(sysDescr?: string, sysObjectID?: string): string {
    if (!sysDescr && !sysObjectID) return "unknown";
    
    const desc = (sysDescr || "").toLowerCase();
    const oid = sysObjectID || "";
    
    // Cisco devices
    if (desc.includes("cisco") || oid.startsWith("1.3.6.1.4.1.9")) {
      if (desc.includes("asa") || desc.includes("firewall") || desc.includes("ftd")) return "firewall";
      if (desc.includes("router") || desc.includes("isr") || desc.includes("asr")) return "router";
      if (desc.includes("switch") || desc.includes("catalyst") || desc.includes("nexus")) return "switch";
      if (desc.includes("wireless") || desc.includes("wlc") || desc.includes("aironet")) return "wireless-controller";
      return "cisco-device";
    }
    
    // Juniper
    if (desc.includes("juniper") || oid.startsWith("1.3.6.1.4.1.2636")) {
      if (desc.includes("srx")) return "firewall";
      if (desc.includes("ex")) return "switch";
      if (desc.includes("mx") || desc.includes("router")) return "router";
      return "juniper-device";
    }
    
    // Fortinet
    if (desc.includes("fortigate") || desc.includes("fortios")) return "firewall";
    if (desc.includes("fortiswitch")) return "switch";
    if (desc.includes("fortiwifi")) return "wireless-controller";
    
    // Palo Alto
    if (desc.includes("palo alto") || desc.includes("pan-os")) return "firewall";
    
    // HP/Aruba
    if (desc.includes("procurve") || desc.includes("aruba")) return "switch";
    
    // Printers
    if (desc.includes("printer") || desc.includes("laserjet") || desc.includes("officejet")) return "printer";
    
    // UPS
    if (desc.includes("ups") || desc.includes("apc") || oid.startsWith("1.3.6.1.4.1.318")) return "ups";
    
    // Linux/Windows servers
    if (desc.includes("linux")) return "linux-server";
    if (desc.includes("windows")) return "windows-server";
    
    // VMware
    if (desc.includes("vmware") || desc.includes("esxi")) return "hypervisor";
    
    return "unknown";
  }
  
  // ─── Vulnerability Detection ───────────────────────────────────
  
  detectVulnerabilities(
    hostInfo: SNMPHostInfo,
    discoveredCommunities: string[],
    writeAccess: boolean
  ): SNMPVuln[] {
    const vulns: SNMPVuln[] = [];
    
    // Default community strings
    const defaultComms = discoveredCommunities.filter(c => 
      DEFAULT_COMMUNITIES.slice(0, 5).includes(c.toLowerCase())
    );
    if (defaultComms.length > 0) {
      vulns.push({
        id: "snmp-default-community",
        title: "SNMP Default Community String",
        severity: defaultComms.includes("private") ? "critical" : "high",
        description: `Default SNMP community string(s) detected: ${defaultComms.join(", ")}. This allows unauthorized read${defaultComms.includes("private") ? "/write" : ""} access to device configuration and network information.`,
        remediation: "Change all SNMP community strings to complex, non-default values. Consider migrating to SNMPv3 with authentication and encryption.",
        evidence: `Communities found: ${defaultComms.join(", ")} on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // Write access with community string
    if (writeAccess) {
      vulns.push({
        id: "snmp-write-access",
        title: "SNMP Write Access Available",
        severity: "critical",
        description: "SNMP write access is available, allowing remote modification of device configuration. An attacker could change routing tables, disable interfaces, or reconfigure the device.",
        remediation: "Disable SNMP write access or restrict it to specific management stations using ACLs. Migrate to SNMPv3 with authentication.",
        evidence: `Write access confirmed on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // SNMPv1/v2c in use (no encryption)
    if (hostInfo.version === "1" || hostInfo.version === "2c") {
      vulns.push({
        id: "snmp-no-encryption",
        title: `SNMP ${hostInfo.version === "1" ? "v1" : "v2c"} in Use (No Encryption)`,
        severity: "medium",
        description: `SNMP ${hostInfo.version} transmits community strings in plaintext. An attacker on the network can sniff SNMP traffic to obtain community strings and gain access.`,
        remediation: "Migrate to SNMPv3 with authPriv security level (authentication + encryption). Disable SNMPv1 and SNMPv2c.",
        evidence: `SNMP ${hostInfo.version} active on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // Sensitive information exposure
    if (hostInfo.sysDescr || hostInfo.sysName || hostInfo.sysLocation) {
      const infoLeaked: string[] = [];
      if (hostInfo.sysDescr) infoLeaked.push(`OS/Version: ${hostInfo.sysDescr.substring(0, 100)}`);
      if (hostInfo.sysName) infoLeaked.push(`Hostname: ${hostInfo.sysName}`);
      if (hostInfo.sysLocation) infoLeaked.push(`Location: ${hostInfo.sysLocation}`);
      
      vulns.push({
        id: "snmp-info-disclosure",
        title: "SNMP Information Disclosure",
        severity: "low",
        description: `SNMP exposes sensitive system information: ${infoLeaked.join("; ")}. This information aids reconnaissance and targeted attacks.`,
        remediation: "Restrict SNMP access to authorized management stations using ACLs. Consider removing or obfuscating sysLocation and sysContact values.",
        evidence: infoLeaked.join("\n"),
      });
    }
    
    // Multiple community strings found
    if (discoveredCommunities.length > 3) {
      vulns.push({
        id: "snmp-excessive-communities",
        title: "Excessive SNMP Community Strings",
        severity: "medium",
        description: `${discoveredCommunities.length} SNMP community strings were discovered. This suggests poor SNMP configuration management and increases the attack surface.`,
        remediation: "Consolidate SNMP community strings. Use a single read-only community for monitoring and restrict write access. Migrate to SNMPv3.",
        evidence: `Communities: ${discoveredCommunities.join(", ")}`,
      });
    }
    
    return vulns;
  }
  
  // ─── KB Population ─────────────────────────────────────────────
  
  populateKB(kb: ScanForgeKB, hostInfo: SNMPHostInfo, communities: string[]): void {
    const source = "snmp-handler";
    const host = hostInfo.host;
    const port = hostInfo.port;
    
    kb.set(KB_KEYS.PORT_SERVICE(port, "udp"), "snmp", source, { host, confidence: 1.0 });
    
    if (communities.length > 0) {
      kb.set(KB_KEYS.SERVICE_SNMP_COMMUNITY(port), communities, source, { host, confidence: 1.0 });
    }
    
    const sysInfo: string[] = [];
    if (hostInfo.sysDescr) sysInfo.push(`descr: ${hostInfo.sysDescr}`);
    if (hostInfo.sysName) sysInfo.push(`name: ${hostInfo.sysName}`);
    if (hostInfo.sysLocation) sysInfo.push(`location: ${hostInfo.sysLocation}`);
    if (sysInfo.length > 0) {
      kb.set(KB_KEYS.SERVICE_SNMP_SYSINFO(port), sysInfo, source, { host, confidence: 0.9 });
    }
    
    if (hostInfo.sysDescr) {
      kb.set(KB_KEYS.HOST_OS, hostInfo.sysDescr, source, { host, confidence: 0.6 });
    }
    
    if (hostInfo.sysName) {
      kb.set(KB_KEYS.HOST_FQDN, hostInfo.sysName, source, { host, confidence: 0.7 });
    }
    
    if (hostInfo.deviceType) {
      kb.set(`device/${host}/type`, hostInfo.deviceType, source, { host, confidence: 0.75 });
    }
  }
}
