/**
 * OT Protocol Analyzer
 *
 * Protocol-specific vulnerability analysis for ICS/OT protocols:
 * 1. Modbus TCP — function code abuse, unauthenticated read/write
 * 2. BACnet — object enumeration, unauthenticated property access
 * 3. DNP3 — unsolicited response injection, cleartext auth
 * 4. Siemens S7comm — CPU stop/start, memory read/write
 * 5. EtherNet/IP — CIP service enumeration, device identity disclosure
 * 6. MQTT — anonymous subscribe/publish, topic enumeration
 * 7. CoAP — resource discovery, unauthenticated access
 * 8. OPC-UA — security policy enumeration, anonymous access
 * 9. IEC 60870-5-104 — unauthenticated telecontrol
 */

// ─── Protocol Analysis Results ────────────────────────────────────────────────

export interface ProtocolVulnerability {
  protocol: string;
  findingType: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence: string;
  safetyImpact: boolean;
  processImpact: boolean;
  remediation: string;
  compensatingControls: string;
  relevantAptGroups: string[];
  relevantMitreTechniques: string[];
  cvssEstimate: number;
}

export interface ProtocolAnalysisResult {
  protocol: string;
  protocolName: string;
  port: number;
  vulnerabilities: ProtocolVulnerability[];
  riskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  summary: string;
  recommendations: string[];
}

// ─── Modbus TCP Analysis ──────────────────────────────────────────────────────

export function analyzeModbus(bannerData: string, port: number = 502): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  // Modbus has NO authentication by design
  vulns.push({
    protocol: "modbus",
    findingType: "unauthenticated_access",
    severity: "critical",
    title: "Modbus TCP: No Authentication",
    description: "Modbus TCP protocol has no built-in authentication mechanism. Any network-accessible client can read/write registers and coils, potentially manipulating physical processes.",
    evidence: `Modbus service detected on port ${port}. Protocol specification (Modbus Application Protocol V1.1b3) does not include authentication.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Implement network segmentation with firewall rules restricting Modbus access to authorized engineering workstations only. Deploy Modbus-aware IDS (e.g., Snort with ICS rules).",
    compensatingControls: "Network segmentation, Modbus-aware firewall, ICS IDS/IPS, physical safety interlocks independent of PLC logic",
    relevantAptGroups: ["SANDWORM", "CHERNOVITE", "XENOTIME"],
    relevantMitreTechniques: ["T0871", "T0831", "T0821"],
    cvssEstimate: 9.8,
  });

  vulns.push({
    protocol: "modbus",
    findingType: "cleartext_protocol",
    severity: "high",
    title: "Modbus TCP: Cleartext Communication",
    description: "All Modbus TCP traffic is transmitted in cleartext without encryption, allowing eavesdropping and man-in-the-middle attacks.",
    evidence: "Modbus TCP specification does not support TLS/SSL encryption. All function codes, register values, and coil states are visible to network sniffers.",
    safetyImpact: false,
    processImpact: true,
    remediation: "Implement Modbus/TCP security extensions (if supported by devices) or tunnel Modbus traffic through encrypted VPN connections.",
    compensatingControls: "Network segmentation, encrypted VPN tunnels for remote access, network traffic monitoring",
    relevantAptGroups: ["SANDWORM", "ELECTRUM"],
    relevantMitreTechniques: ["T0832", "T0882"],
    cvssEstimate: 7.5,
  });

  // Check for function code abuse potential
  vulns.push({
    protocol: "modbus",
    findingType: "unauthorized_write",
    severity: "critical",
    title: "Modbus TCP: Unrestricted Write Access to Registers/Coils",
    description: "Modbus function codes 05 (Write Single Coil), 06 (Write Single Register), 15 (Write Multiple Coils), and 16 (Write Multiple Registers) can be executed by any client without authorization, allowing direct manipulation of process control values.",
    evidence: "Standard Modbus implementation allows all function codes from any source IP. No access control lists or role-based restrictions.",
    safetyImpact: true,
    processImpact: true,
    remediation: "Deploy Modbus-aware deep packet inspection firewall that restricts write function codes (05, 06, 15, 16) to specific authorized IP addresses.",
    compensatingControls: "DPI firewall with Modbus function code filtering, read-only mode for monitoring connections, physical safety interlocks",
    relevantAptGroups: ["CHERNOVITE", "SANDWORM", "BENTONITE"],
    relevantMitreTechniques: ["T0831", "T0879", "T0827"],
    cvssEstimate: 10.0,
  });

  const riskScore = 95;
  return {
    protocol: "modbus",
    protocolName: "Modbus TCP",
    port,
    vulnerabilities: vulns,
    riskScore,
    riskLevel: "critical",
    summary: `Modbus TCP on port ${port} has ${vulns.length} findings. Protocol lacks authentication and encryption by design, allowing any network client to read/write PLC registers.`,
    recommendations: [
      "Implement strict network segmentation isolating Modbus devices",
      "Deploy Modbus-aware DPI firewall restricting write function codes",
      "Enable ICS-specific IDS rules for anomalous Modbus traffic",
      "Ensure physical safety interlocks are independent of PLC logic",
      "Consider migration to Modbus/TCP Security (TLS) where supported",
    ],
  };
}

// ─── Siemens S7comm Analysis ──────────────────────────────────────────────────

export function analyzeS7comm(bannerData: string, port: number = 102): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];
  const banner = bannerData.toLowerCase();

  vulns.push({
    protocol: "s7comm",
    findingType: "unauthenticated_access",
    severity: "critical",
    title: "S7comm: Unauthenticated CPU Control",
    description: "S7comm protocol allows unauthenticated CPU stop/start commands and memory read/write operations. An attacker can halt production or modify PLC logic remotely.",
    evidence: `S7comm service on port ${port}. Protocol allows CPU STOP (0x29), CPU START, and block upload/download without authentication in S7-300/400 series.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Enable S7comm+ (S7-1200/1500 with TLS) where possible. Implement network segmentation and access control lists.",
    compensatingControls: "Network segmentation, Siemens SCALANCE firewall with S7 inspection, physical key switch on PLC",
    relevantAptGroups: ["SANDWORM", "KAMACITE", "CHERNOVITE"],
    relevantMitreTechniques: ["T0871", "T0821", "T0826", "T0813"],
    cvssEstimate: 10.0,
  });

  vulns.push({
    protocol: "s7comm",
    findingType: "information_disclosure",
    severity: "high",
    title: "S7comm: Device Information Disclosure",
    description: "S7comm SZL (System Status List) requests reveal detailed device information including module type, serial number, firmware version, and hardware configuration.",
    evidence: "S7comm SZL ID 0x001C returns module identification, SZL ID 0x0011 returns module type, SZL ID 0x001A returns component identification.",
    safetyImpact: false,
    processImpact: false,
    remediation: "Restrict S7comm access via network segmentation. S7-1500 series supports access level protection.",
    compensatingControls: "Network segmentation, access level passwords on S7-1500",
    relevantAptGroups: ["KAMACITE", "SANDWORM"],
    relevantMitreTechniques: ["T0882", "T0871"],
    cvssEstimate: 5.3,
  });

  // Check for specific PLC model vulnerabilities
  if (banner.includes("s7-300") || banner.includes("s7-400")) {
    vulns.push({
      protocol: "s7comm",
      findingType: "firmware_vulnerability",
      severity: "critical",
      title: "S7-300/400: Legacy PLC Without Modern Security",
      description: "S7-300 and S7-400 PLCs use the original S7comm protocol without TLS support. These legacy devices cannot be secured at the protocol level.",
      evidence: `Detected S7-300/400 series PLC. These devices only support S7comm (not S7comm+) and have no built-in authentication mechanism.`,
      safetyImpact: true,
      processImpact: true,
      remediation: "Plan migration to S7-1500 series with S7comm+ (TLS). Until migration, implement strict network segmentation with Siemens SCALANCE firewall.",
      compensatingControls: "SCALANCE S firewall, network segmentation, physical key switch, ICS IDS monitoring",
      relevantAptGroups: ["SANDWORM", "KAMACITE"],
      relevantMitreTechniques: ["T0839", "T0821"],
      cvssEstimate: 9.8,
    });
  }

  const riskScore = banner.includes("s7-300") || banner.includes("s7-400") ? 98 : 85;
  return {
    protocol: "s7comm",
    protocolName: "Siemens S7",
    port,
    vulnerabilities: vulns,
    riskScore,
    riskLevel: "critical",
    summary: `S7comm on port ${port} has ${vulns.length} findings. Protocol allows unauthenticated CPU control and memory access.`,
    recommendations: [
      "Migrate to S7-1500 with S7comm+ (TLS) where possible",
      "Deploy Siemens SCALANCE S firewall with S7 deep inspection",
      "Enable access level protection on S7-1500 PLCs",
      "Set physical key switch to RUN mode to prevent remote STOP",
      "Monitor for anomalous S7comm traffic patterns",
    ],
  };
}

// ─── DNP3 Analysis ────────────────────────────────────────────────────────────

export function analyzeDnp3(bannerData: string, port: number = 20000): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  vulns.push({
    protocol: "dnp3",
    findingType: "unauthenticated_access",
    severity: "critical",
    title: "DNP3: Unauthenticated Telecontrol",
    description: "DNP3 without Secure Authentication (SA) allows unauthenticated control commands. Attackers can issue Direct Operate, Select-Before-Operate, and Cold/Warm Restart commands.",
    evidence: `DNP3 service on port ${port}. Standard DNP3 (without SA) does not authenticate command sources.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Enable DNP3 Secure Authentication (SA) v5 per IEEE 1815-2012. Implement challenge-response authentication for critical function codes.",
    compensatingControls: "Network segmentation, DNP3-aware firewall, function code filtering, ICS IDS",
    relevantAptGroups: ["SANDWORM", "ELECTRUM"],
    relevantMitreTechniques: ["T0871", "T0831", "T0826"],
    cvssEstimate: 9.8,
  });

  vulns.push({
    protocol: "dnp3",
    findingType: "replay_attack",
    severity: "high",
    title: "DNP3: Vulnerable to Replay Attacks",
    description: "Without Secure Authentication, DNP3 messages can be captured and replayed to execute previously observed commands.",
    evidence: "DNP3 messages without SA lack sequence numbers or timestamps for replay protection.",
    safetyImpact: true,
    processImpact: true,
    remediation: "Enable DNP3 Secure Authentication v5 with HMAC-based message authentication.",
    compensatingControls: "Encrypted VPN tunnels for DNP3 traffic, network monitoring for duplicate messages",
    relevantAptGroups: ["SANDWORM"],
    relevantMitreTechniques: ["T0831", "T0832"],
    cvssEstimate: 8.1,
  });

  return {
    protocol: "dnp3",
    protocolName: "DNP3",
    port,
    vulnerabilities: vulns,
    riskScore: 90,
    riskLevel: "critical",
    summary: `DNP3 on port ${port} has ${vulns.length} findings. Protocol used in electric/water SCADA is vulnerable without Secure Authentication.`,
    recommendations: [
      "Enable DNP3 Secure Authentication v5 (IEEE 1815-2012)",
      "Deploy DNP3-aware firewall with function code filtering",
      "Encrypt DNP3 traffic via VPN for remote connections",
      "Monitor for anomalous DNP3 source/destination addresses",
      "Implement bump-in-the-wire encryption for legacy devices",
    ],
  };
}

// ─── BACnet Analysis ──────────────────────────────────────────────────────────

export function analyzeBacnet(bannerData: string, port: number = 47808): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  vulns.push({
    protocol: "bacnet",
    findingType: "unauthenticated_access",
    severity: "high",
    title: "BACnet: Unauthenticated Object Access",
    description: "BACnet/IP allows unauthenticated read/write access to all objects (analog/binary values, schedules, trends). Attackers can manipulate HVAC, lighting, and fire systems.",
    evidence: `BACnet service on port ${port}. BACnet protocol does not include authentication in standard implementations.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Implement BACnet Secure Connect (BACnet/SC) per Addendum BJ. Segment BACnet networks from IT networks.",
    compensatingControls: "Network segmentation, BACnet-aware firewall, physical override capabilities for critical systems",
    relevantAptGroups: ["ERYTHRITE"],
    relevantMitreTechniques: ["T0871", "T0831"],
    cvssEstimate: 8.6,
  });

  vulns.push({
    protocol: "bacnet",
    findingType: "information_disclosure",
    severity: "medium",
    title: "BACnet: Building Information Disclosure via Who-Is/I-Am",
    description: "BACnet Who-Is broadcast discovers all devices on the network, revealing device names, locations, vendor IDs, and object lists that map the building automation system.",
    evidence: "BACnet Who-Is (service 0x08) and ReadPropertyMultiple enumerate complete building system topology.",
    safetyImpact: false,
    processImpact: false,
    remediation: "Restrict BACnet broadcast domains. Implement BACnet routers with access control.",
    compensatingControls: "VLAN segmentation for BACnet traffic, BACnet router ACLs",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0882"],
    cvssEstimate: 5.3,
  });

  return {
    protocol: "bacnet",
    protocolName: "BACnet",
    port,
    vulnerabilities: vulns,
    riskScore: 65,
    riskLevel: "high",
    summary: `BACnet on port ${port} has ${vulns.length} findings. Building automation protocol allows unauthenticated access to HVAC and fire systems.`,
    recommendations: [
      "Implement BACnet Secure Connect (BACnet/SC) where supported",
      "Segment BACnet networks from corporate IT networks",
      "Deploy BACnet-aware firewall with object access control",
      "Ensure fire and life safety systems have physical overrides",
      "Monitor for unauthorized BACnet Who-Is broadcasts",
    ],
  };
}

// ─── EtherNet/IP Analysis ─────────────────────────────────────────────────────

export function analyzeEthernetIp(bannerData: string, port: number = 44818): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  vulns.push({
    protocol: "ethernetip",
    findingType: "unauthenticated_access",
    severity: "critical",
    title: "EtherNet/IP: Unauthenticated CIP Access",
    description: "EtherNet/IP with CIP (Common Industrial Protocol) allows unauthenticated access to device configuration, I/O data, and program upload/download on Allen-Bradley/Rockwell PLCs.",
    evidence: `EtherNet/IP service on port ${port}. CIP protocol does not include authentication in standard mode.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Enable CIP Security (EtherNet/IP Confidentiality) on supported devices. Implement Rockwell Stratix firewall with CIP inspection.",
    compensatingControls: "Network segmentation, Rockwell Stratix managed switches, CIP-aware firewall, physical key switch",
    relevantAptGroups: ["CHERNOVITE"],
    relevantMitreTechniques: ["T0871", "T0821", "T0831"],
    cvssEstimate: 9.8,
  });

  vulns.push({
    protocol: "ethernetip",
    findingType: "information_disclosure",
    severity: "medium",
    title: "EtherNet/IP: Device Identity Disclosure via ListIdentity",
    description: "EtherNet/IP ListIdentity command reveals device type, vendor, product name, serial number, firmware revision, and device state.",
    evidence: "ListIdentity (command 0x0063) returns full device identification without authentication.",
    safetyImpact: false,
    processImpact: false,
    remediation: "Restrict EtherNet/IP access via network segmentation.",
    compensatingControls: "Network segmentation, managed switches with port security",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0882"],
    cvssEstimate: 5.3,
  });

  return {
    protocol: "ethernetip",
    protocolName: "EtherNet/IP",
    port,
    vulnerabilities: vulns,
    riskScore: 85,
    riskLevel: "critical",
    summary: `EtherNet/IP on port ${port} has ${vulns.length} findings. CIP protocol allows unauthenticated access to Rockwell/Allen-Bradley PLCs.`,
    recommendations: [
      "Enable CIP Security (EtherNet/IP Confidentiality) on supported devices",
      "Deploy Rockwell Stratix firewall with CIP deep inspection",
      "Implement zone-based segmentation per IEC 62443",
      "Set physical key switch to RUN on ControlLogix/CompactLogix",
      "Monitor for anomalous CIP service requests",
    ],
  };
}

// ─── MQTT Analysis ────────────────────────────────────────────────────────────

export function analyzeMqtt(bannerData: string, port: number = 1883): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];
  const isTls = port === 8883;

  if (!isTls) {
    vulns.push({
      protocol: "mqtt",
      findingType: "cleartext_protocol",
      severity: "high",
      title: "MQTT: Cleartext Communication",
      description: "MQTT on port 1883 transmits all messages including credentials and sensor data in cleartext.",
      evidence: `MQTT broker on port ${port} (non-TLS). All PUBLISH/SUBSCRIBE messages are unencrypted.`,
      safetyImpact: false,
      processImpact: true,
      remediation: "Enable MQTT over TLS (port 8883). Configure broker to reject non-TLS connections.",
      compensatingControls: "Network segmentation, VPN tunnels for remote MQTT access",
      relevantAptGroups: [],
      relevantMitreTechniques: ["T0882"],
      cvssEstimate: 7.5,
    });
  }

  vulns.push({
    protocol: "mqtt",
    findingType: "unauthenticated_access",
    severity: "high",
    title: "MQTT: Potential Anonymous Access",
    description: "Many MQTT brokers allow anonymous connections by default, enabling any client to subscribe to all topics (including sensor data) and publish commands to actuators.",
    evidence: `MQTT broker on port ${port}. Default Mosquitto/HiveMQ configurations allow anonymous access.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Disable anonymous access. Implement username/password or certificate-based authentication. Use MQTT v5 enhanced authentication.",
    compensatingControls: "Topic-based ACLs, network segmentation, MQTT broker monitoring",
    relevantAptGroups: ["BENTONITE"],
    relevantMitreTechniques: ["T0871", "T0831"],
    cvssEstimate: 8.6,
  });

  vulns.push({
    protocol: "mqtt",
    findingType: "information_disclosure",
    severity: "medium",
    title: "MQTT: Topic Enumeration via Wildcard Subscribe",
    description: "MQTT wildcard subscriptions (# or +) allow enumeration of all topics on the broker, revealing IoT device topology, sensor types, and data flows.",
    evidence: "MQTT SUBSCRIBE with topic '#' returns all published messages across all topics.",
    safetyImpact: false,
    processImpact: false,
    remediation: "Implement topic-based ACLs to restrict wildcard subscriptions. Use MQTT v5 topic aliases.",
    compensatingControls: "Topic ACLs, broker-level subscription filtering",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0882"],
    cvssEstimate: 5.3,
  });

  const riskScore = isTls ? 55 : 75;
  return {
    protocol: "mqtt",
    protocolName: "MQTT",
    port,
    vulnerabilities: vulns,
    riskScore,
    riskLevel: isTls ? "medium" : "high",
    summary: `MQTT on port ${port} has ${vulns.length} findings. IoT messaging protocol ${isTls ? "with TLS" : "without encryption"} may allow anonymous access.`,
    recommendations: [
      "Enable MQTT over TLS (port 8883)",
      "Disable anonymous access on the broker",
      "Implement topic-based access control lists",
      "Use MQTT v5 enhanced authentication where supported",
      "Monitor for wildcard subscription attempts",
    ],
  };
}

// ─── CoAP Analysis ────────────────────────────────────────────────────────────

export function analyzeCoap(bannerData: string, port: number = 5683): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  vulns.push({
    protocol: "coap",
    findingType: "unauthenticated_access",
    severity: "medium",
    title: "CoAP: Unauthenticated Resource Access",
    description: "CoAP resources are accessible without authentication by default. GET/PUT/POST/DELETE operations can read sensor data and control actuators.",
    evidence: `CoAP service on port ${port}. Standard CoAP (RFC 7252) does not mandate authentication.`,
    safetyImpact: false,
    processImpact: true,
    remediation: "Implement DTLS (CoAPs) for encrypted and authenticated CoAP communication. Use OSCORE for object-level security.",
    compensatingControls: "Network segmentation, CoAP proxy with authentication",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0871"],
    cvssEstimate: 6.5,
  });

  vulns.push({
    protocol: "coap",
    findingType: "information_disclosure",
    severity: "low",
    title: "CoAP: Resource Discovery via .well-known/core",
    description: "CoAP resource discovery endpoint (/.well-known/core) reveals all available resources, their types, and interfaces on the device.",
    evidence: "CoAP GET /.well-known/core returns CoRE Link Format listing all resources.",
    safetyImpact: false,
    processImpact: false,
    remediation: "Restrict resource discovery to authenticated clients. Implement DTLS.",
    compensatingControls: "Network segmentation",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0882"],
    cvssEstimate: 3.7,
  });

  return {
    protocol: "coap",
    protocolName: "CoAP",
    port,
    vulnerabilities: vulns,
    riskScore: 45,
    riskLevel: "medium",
    summary: `CoAP on port ${port} has ${vulns.length} findings. Lightweight IoT protocol with optional security.`,
    recommendations: [
      "Enable DTLS for CoAP communication (CoAPs)",
      "Implement OSCORE for object-level security",
      "Restrict .well-known/core discovery endpoint",
      "Segment CoAP devices from IT networks",
    ],
  };
}

// ─── OPC-UA Analysis ──────────────────────────────────────────────────────────

export function analyzeOpcUa(bannerData: string, port: number = 4840): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];
  const banner = bannerData.toLowerCase();

  if (banner.includes("none") || banner.includes("no security")) {
    vulns.push({
      protocol: "opcua",
      findingType: "configuration_weakness",
      severity: "critical",
      title: "OPC-UA: Security Policy Set to None",
      description: "OPC-UA server accepts connections with SecurityPolicy=None, allowing unauthenticated and unencrypted access to all nodes.",
      evidence: "OPC-UA GetEndpoints response includes SecurityPolicy=None endpoint.",
      safetyImpact: true,
      processImpact: true,
      remediation: "Disable SecurityPolicy=None. Require at minimum Basic256Sha256 security policy with SignAndEncrypt message security mode.",
      compensatingControls: "Network segmentation, OPC-UA firewall",
      relevantAptGroups: ["CHERNOVITE", "KAMACITE"],
      relevantMitreTechniques: ["T0871", "T0882"],
      cvssEstimate: 9.8,
    });
  }

  vulns.push({
    protocol: "opcua",
    findingType: "information_disclosure",
    severity: "medium",
    title: "OPC-UA: Server Endpoint Discovery",
    description: "OPC-UA GetEndpoints service reveals server configuration including supported security policies, authentication modes, and server certificates.",
    evidence: `OPC-UA server on port ${port}. GetEndpoints is accessible without authentication per specification.`,
    safetyImpact: false,
    processImpact: false,
    remediation: "This is by design in OPC-UA. Ensure strong security policies are enforced on all endpoints.",
    compensatingControls: "Network segmentation, restrict access to OPC-UA discovery port",
    relevantAptGroups: [],
    relevantMitreTechniques: ["T0882"],
    cvssEstimate: 3.7,
  });

  const hasNoneSecurity = banner.includes("none") || banner.includes("no security");
  return {
    protocol: "opcua",
    protocolName: "OPC-UA",
    port,
    vulnerabilities: vulns,
    riskScore: hasNoneSecurity ? 80 : 35,
    riskLevel: hasNoneSecurity ? "critical" : "low",
    summary: `OPC-UA on port ${port} has ${vulns.length} findings. ${hasNoneSecurity ? "CRITICAL: SecurityPolicy=None is enabled." : "Security policies appear configured."}`,
    recommendations: [
      "Disable SecurityPolicy=None on all OPC-UA servers",
      "Require Basic256Sha256 with SignAndEncrypt mode",
      "Implement certificate-based authentication",
      "Use OPC-UA Global Discovery Server for certificate management",
      "Monitor OPC-UA audit events for unauthorized access",
    ],
  };
}

// ─── IEC 60870-5-104 Analysis ─────────────────────────────────────────────────

export function analyzeIec104(bannerData: string, port: number = 2404): ProtocolAnalysisResult {
  const vulns: ProtocolVulnerability[] = [];

  vulns.push({
    protocol: "iec104",
    findingType: "unauthenticated_access",
    severity: "critical",
    title: "IEC 104: Unauthenticated Telecontrol Commands",
    description: "IEC 60870-5-104 allows unauthenticated telecontrol commands including single/double command, set point, and interrogation. Used extensively in European power grids.",
    evidence: `IEC 104 service on port ${port}. Protocol does not include authentication in base specification.`,
    safetyImpact: true,
    processImpact: true,
    remediation: "Implement IEC 62351-5 for authentication of IEC 104 messages. Deploy protocol-aware firewall.",
    compensatingControls: "Network segmentation, IEC 104-aware firewall, encrypted VPN for remote SCADA",
    relevantAptGroups: ["SANDWORM", "ELECTRUM"],
    relevantMitreTechniques: ["T0871", "T0831", "T0826", "T0827"],
    cvssEstimate: 10.0,
  });

  vulns.push({
    protocol: "iec104",
    findingType: "man_in_the_middle",
    severity: "high",
    title: "IEC 104: No Message Integrity Protection",
    description: "IEC 104 messages lack integrity protection, allowing man-in-the-middle modification of telecontrol commands and measurement values.",
    evidence: "IEC 104 APDU/ASDU messages are transmitted without cryptographic integrity checks.",
    safetyImpact: true,
    processImpact: true,
    remediation: "Implement IEC 62351-5 for message authentication. Use TLS tunneling per IEC 62351-3.",
    compensatingControls: "Encrypted VPN tunnels, network monitoring for anomalous IEC 104 traffic",
    relevantAptGroups: ["SANDWORM"],
    relevantMitreTechniques: ["T0832", "T0831"],
    cvssEstimate: 8.1,
  });

  return {
    protocol: "iec104",
    protocolName: "IEC 60870-5-104",
    port,
    vulnerabilities: vulns,
    riskScore: 95,
    riskLevel: "critical",
    summary: `IEC 104 on port ${port} has ${vulns.length} findings. Power grid telecontrol protocol lacks authentication — primary target of SANDWORM/Industroyer.`,
    recommendations: [
      "Implement IEC 62351-5 authentication for IEC 104",
      "Deploy IEC 104-aware firewall with ASDU type filtering",
      "Use TLS tunneling per IEC 62351-3 for remote connections",
      "Monitor for anomalous IEC 104 ASDU types and addresses",
      "Implement redundant communication paths with integrity checking",
    ],
  };
}

// ─── Master Protocol Analyzer ─────────────────────────────────────────────────

/**
 * Analyze a detected protocol and return vulnerability findings
 */
export function analyzeProtocol(
  protocol: string,
  bannerData: string,
  port?: number
): ProtocolAnalysisResult | null {
  const analyzers: Record<string, (banner: string, port: number) => ProtocolAnalysisResult> = {
    modbus: analyzeModbus,
    s7comm: analyzeS7comm,
    dnp3: analyzeDnp3,
    bacnet: analyzeBacnet,
    ethernetip: analyzeEthernetIp,
    mqtt: analyzeMqtt,
    coap: analyzeCoap,
    opcua: analyzeOpcUa,
    iec104: analyzeIec104,
  };

  const analyzer = analyzers[protocol.toLowerCase()];
  if (!analyzer) return null;

  const defaultPorts: Record<string, number> = {
    modbus: 502, s7comm: 102, dnp3: 20000, bacnet: 47808,
    ethernetip: 44818, mqtt: 1883, coap: 5683, opcua: 4840, iec104: 2404,
  };

  return analyzer(bannerData, port || defaultPorts[protocol.toLowerCase()] || 0);
}

/**
 * Analyze all protocols detected on a device
 */
export function analyzeAllProtocols(
  protocols: string[],
  bannerData: string = ""
): ProtocolAnalysisResult[] {
  return protocols
    .map(p => analyzeProtocol(p, bannerData))
    .filter((r): r is ProtocolAnalysisResult => r !== null);
}

/**
 * Get aggregate risk score across all protocol findings
 */
export function getAggregateProtocolRisk(results: ProtocolAnalysisResult[]): {
  overallScore: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  safetyImpactCount: number;
} {
  if (results.length === 0) {
    return { overallScore: 0, riskLevel: "low", totalVulnerabilities: 0, criticalCount: 0, highCount: 0, safetyImpactCount: 0 };
  }

  const allVulns = results.flatMap(r => r.vulnerabilities);
  const criticalCount = allVulns.filter(v => v.severity === "critical").length;
  const highCount = allVulns.filter(v => v.severity === "high").length;
  const safetyImpactCount = allVulns.filter(v => v.safetyImpact).length;

  // Weighted average of protocol risk scores
  const overallScore = Math.min(
    Math.round(results.reduce((sum, r) => sum + r.riskScore, 0) / results.length * 1.2),
    100
  );

  let riskLevel: "critical" | "high" | "medium" | "low" = "low";
  if (overallScore >= 80 || criticalCount > 0) riskLevel = "critical";
  else if (overallScore >= 60 || highCount > 0) riskLevel = "high";
  else if (overallScore >= 40) riskLevel = "medium";

  return { overallScore, riskLevel, totalVulnerabilities: allVulns.length, criticalCount, highCount, safetyImpactCount };
}
