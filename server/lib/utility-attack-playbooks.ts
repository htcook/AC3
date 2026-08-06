/**
 * Utility-Specific Attack Playbooks
 * 
 * Pre-built adversary emulation playbooks tailored to critical infrastructure sectors:
 * - Water Treatment / Distribution
 * - Wastewater / Sewage
 * - Electric Power (Generation, Transmission, Distribution)
 * 
 * Each playbook maps to:
 * - Real-world threat actors and campaigns
 * - MITRE ATT&CK for ICS techniques
 * - Specific PLC/SCADA targets
 * - CISA advisories and known vulnerabilities
 * - Physical impact scenarios
 * 
 * Author: Harrison Cook / AC3 Platform
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type UtilitySector = "water_treatment" | "water_distribution" | "wastewater" | "electric_generation" | "electric_transmission" | "electric_distribution";

export type PlaybookDifficulty = "basic" | "intermediate" | "advanced" | "nation_state";

export type PhysicalImpact = 
  | "service_disruption"
  | "equipment_damage"
  | "environmental_release"
  | "public_health_hazard"
  | "safety_system_bypass"
  | "cascading_failure"
  | "loss_of_view"
  | "loss_of_control";

export interface AttackPlaybook {
  id: string;
  name: string;
  sector: UtilitySector;
  difficulty: PlaybookDifficulty;
  description: string;
  threatActors: string[];
  realWorldPrecedent: string;
  cisaAdvisories: string[];
  targetedEquipment: TargetedEquipment[];
  phases: PlaybookPhase[];
  physicalImpacts: PhysicalImpact[];
  impactDescription: string;
  detectionOpportunities: DetectionOpportunity[];
  mitigations: string[];
  estimatedDuration: string;
  requiredAccess: string;
  calderaAbilities: string[]; // MITRE Caldera ability IDs for automation
}

export interface TargetedEquipment {
  type: string;
  vendor: string;
  model: string;
  protocol: string;
  commonPorts: number[];
  knownCves: string[];
}

export interface PlaybookPhase {
  phase: number;
  name: string;
  description: string;
  mitreIcsId: string;
  mitreTechnique: string;
  mitreTactic: string;
  tools: string[];
  indicators: string[];
  duration: string;
}

export interface DetectionOpportunity {
  phase: number;
  method: string;
  dataSource: string;
  confidence: "high" | "medium" | "low";
  snortRule?: string;
  yaraRule?: string;
}

// ─── Water Treatment Playbooks ──────────────────────────────────────────────────

const WATER_TREATMENT_PLAYBOOKS: AttackPlaybook[] = [
  {
    id: "WTR-001",
    name: "CyberAv3ngers Credential Lockout (Minnesota Pattern)",
    sector: "water_treatment",
    difficulty: "basic",
    description: "Replicates the July 2026 Minnesota water utility attacks: access internet-exposed MicroLogix PLCs, change IP addresses and passwords to lock out operators, causing loss of monitoring and control.",
    threatActors: ["CyberAv3ngers (IRGC-CEC)", "Storm-0784"],
    realWorldPrecedent: "July 26-27, 2026: 30+ Minnesota water systems attacked. FBI PSA 260730 confirms 7+ states affected. Operators locked out via credential and IP changes.",
    cisaAdvisories: ["AA26-097A", "FBI PSA 260730"],
    targetedEquipment: [
      { type: "PLC", vendor: "Rockwell Automation", model: "MicroLogix 1100", protocol: "EtherNet/IP", commonPorts: [44818, 80], knownCves: ["CVE-2021-22681"] },
      { type: "PLC", vendor: "Rockwell Automation", model: "MicroLogix 1400", protocol: "EtherNet/IP", commonPorts: [44818, 80, 2222], knownCves: ["CVE-2021-22681"] },
    ],
    phases: [
      { phase: 1, name: "Internet Reconnaissance", description: "Scan for internet-exposed MicroLogix PLCs using Shodan/Censys queries for EtherNet/IP on port 44818. Identify devices on cellular carrier IP space.", mitreIcsId: "T0883", mitreTechnique: "Internet Accessible Device", mitreTactic: "Initial Access", tools: ["Shodan", "Censys", "Nmap"], indicators: ["Shodan queries for 'Allen-Bradley'", "Port 44818 scans from foreign IPs"], duration: "1-4 hours" },
      { phase: 2, name: "Initial Access via Default Credentials", description: "Connect to exposed PLC web interface or EtherNet/IP port. Attempt default credentials (no password on MicroLogix by default). Use RSLogix 500 or compatible engineering software.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Initial Access", tools: ["RSLogix 500", "Connected Components Workbench", "Python EtherNet/IP library"], indicators: ["Engineering software connections from non-authorized IPs", "Multiple failed auth attempts"], duration: "Minutes" },
      { phase: 3, name: "IP Address Modification", description: "Change the PLC's IP address configuration to a different address. This causes the SCADA/HMI system to lose communication with the controller.", mitreIcsId: "T0836", mitreTechnique: "Modify Parameter", mitreTactic: "Impair Process Control", tools: ["RSLogix 500", "Vendor engineering software"], indicators: ["IP configuration change events", "Loss of SCADA polling"], duration: "Seconds" },
      { phase: 4, name: "Password Lockout", description: "Set or change the PLC password to lock out legitimate operators. On MicroLogix, enable password protection with an unknown value.", mitreIcsId: "T0859", mitreTechnique: "Valid Accounts", mitreTactic: "Persistence", tools: ["RSLogix 500"], indicators: ["Password change audit events", "Failed operator login attempts"], duration: "Seconds" },
      { phase: 5, name: "Operational Impact", description: "Operators lose all visibility and control. Automated processes continue without monitoring. Pressure may drop, pumps may flood, treatment may stop.", mitreIcsId: "T0826", mitreTechnique: "Loss of Availability", mitreTactic: "Impact", tools: ["None - impact is automatic"], indicators: ["SCADA communication timeouts", "Manual operations activated", "Pressure alarms"], duration: "Until manual recovery" },
    ],
    physicalImpacts: ["loss_of_view", "loss_of_control", "service_disruption"],
    impactDescription: "Operators cannot monitor or control water treatment processes. Automated systems continue running without oversight. May result in pressure loss, flooding, or treatment chemical imbalances. Recovery requires physical access to PLC LCD panel.",
    detectionOpportunities: [
      { phase: 1, method: "Monitor for Shodan/Censys scanning of OT ports", dataSource: "Firewall logs, IDS", confidence: "low" },
      { phase: 2, method: "Alert on engineering software connections from non-whitelisted IPs", dataSource: "Network flow data, PLC audit logs", confidence: "high" },
      { phase: 3, method: "Monitor PLC configuration change events via SNMP traps or syslog", dataSource: "SNMP, PLC audit trail", confidence: "high" },
      { phase: 4, method: "Alert on password change events on PLCs", dataSource: "PLC audit log, SIEM", confidence: "high" },
      { phase: 5, method: "SCADA communication loss alarm", dataSource: "SCADA/HMI system", confidence: "high" },
    ],
    mitigations: [
      "Remove PLCs from direct internet access (CISA primary recommendation)",
      "Place behind VPN/firewall with strict ACL",
      "Set physical key switch to RUN mode",
      "Apply firmware FRN 21.002+ on MicroLogix 1400 Series B",
      "Enable Enhanced Password Security",
      "Implement private APN for cellular connections",
      "Maintain offline project file backups (.RSS files)",
      "Configure SCADA polling timeout alerts",
    ],
    estimatedDuration: "30 minutes to 2 hours",
    requiredAccess: "Internet access to exposed PLC",
    calderaAbilities: ["ics-recon-shodan", "ics-plc-connect", "ics-modify-config", "ics-credential-change"],
  },
  {
    id: "WTR-002",
    name: "CyberAv3ngers Safety Logic Manipulation",
    sector: "water_treatment",
    difficulty: "advanced",
    description: "Replicates the advanced CyberAv3ngers capability documented in CISA AA26-097A July 2026 update: modify Add-On Instructions to disable safety shutdown and alarm systems while maintaining normal-appearing process behavior.",
    threatActors: ["CyberAv3ngers (IRGC-CEC)", "Storm-0784"],
    realWorldPrecedent: "CISA AA26-097A July 22, 2026 update: 'a malicious project file retained normal downstream ladder logic while inserting modified AOIs that disabled safety shutdown and alarm systems.'",
    cisaAdvisories: ["AA26-097A"],
    targetedEquipment: [
      { type: "PLC", vendor: "Rockwell Automation", model: "CompactLogix", protocol: "EtherNet/IP", commonPorts: [44818, 2222], knownCves: ["CVE-2021-22681", "CVE-2022-1159"] },
      { type: "PLC", vendor: "Rockwell Automation", model: "ControlLogix", protocol: "EtherNet/IP", commonPorts: [44818, 2222], knownCves: ["CVE-2021-22681"] },
      { type: "PLC", vendor: "Schneider Electric", model: "Modicon M340", protocol: "Modbus TCP", commonPorts: [502], knownCves: ["CVE-2022-45789"] },
    ],
    phases: [
      { phase: 1, name: "Access via Engineering Software", description: "Connect to PLC using legitimate vendor engineering software (Studio 5000 Logix Designer) from leased hosting infrastructure. Exploit CVE-2021-22681 authentication bypass.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Initial Access", tools: ["Studio 5000 Logix Designer", "RSLogix 5000"], indicators: ["Engineering software sessions from cloud hosting IPs", "CIP protocol connections from non-plant networks"], duration: "Minutes" },
      { phase: 2, name: "Project File Exfiltration", description: "Download the running PLC project file to understand the control logic, safety systems, and process parameters.", mitreIcsId: "T0882", mitreTechnique: "Theft of Operational Information", mitreTactic: "Collection", tools: ["Studio 5000", "Python CIP library"], indicators: ["Project upload events in PLC audit log", "Large data transfers on port 44818"], duration: "5-15 minutes" },
      { phase: 3, name: "AOI Modification (Safety Logic)", description: "Modify Add-On Instructions that handle safety shutdown and alarm functions. Retain normal ladder logic to avoid obvious detection. Disable safety interlocks while maintaining process appearance.", mitreIcsId: "T0821", mitreTechnique: "Modify Controller Tasking", mitreTactic: "Execution", tools: ["Studio 5000", "Custom tooling"], indicators: ["AOI hash changes", "Project file download followed by upload", "Safety interlock status changes"], duration: "1-4 hours (offline modification)" },
      { phase: 4, name: "Modified Project Upload", description: "Upload the modified project file to the PLC. The normal process logic continues to function, but safety systems are now disabled.", mitreIcsId: "T0839", mitreTechnique: "Module Firmware", mitreTactic: "Persistence", tools: ["Studio 5000"], indicators: ["Project download event", "Controller mode change to PROGRAM then back to RUN", "AOI checksum mismatch"], duration: "Minutes" },
      { phase: 5, name: "HMI/SCADA Display Manipulation", description: "Modify HMI display data to show normal readings to operators while actual process conditions deviate. Operators see safe values while equipment operates unsafely.", mitreIcsId: "T0832", mitreTechnique: "Manipulation of View", mitreTactic: "Impact", tools: ["HMI configuration tools", "OPC UA manipulation"], indicators: ["Discrepancy between HMI values and field instruments", "Historian data anomalies"], duration: "30 minutes" },
      { phase: 6, name: "Safety System Failure", description: "With safety logic disabled and operators seeing false data, equipment can reach unsafe conditions without triggering alarms or automatic shutdown.", mitreIcsId: "T0880", mitreTechnique: "Loss of Safety", mitreTactic: "Impact", tools: ["None - impact develops over time"], indicators: ["Physical instrument readings vs HMI discrepancy", "Process variable excursions without alarms", "Equipment operating beyond design limits"], duration: "Hours to days" },
    ],
    physicalImpacts: ["safety_system_bypass", "equipment_damage", "public_health_hazard", "environmental_release"],
    impactDescription: "Safety systems silently disabled while operators see normal readings. Water treatment chemicals could reach dangerous concentrations. Equipment could overpressure without shutdown. Environmental release possible. This is the most dangerous documented Iranian OT capability.",
    detectionOpportunities: [
      { phase: 1, method: "Whitelist authorized engineering workstation IPs; alert on any other CIP connections", dataSource: "Network IDS, firewall", confidence: "high" },
      { phase: 2, method: "Monitor for project file upload/download events", dataSource: "PLC audit log", confidence: "high" },
      { phase: 3, method: "Periodic AOI hash comparison against known-good baseline", dataSource: "Integrity monitoring system", confidence: "high" },
      { phase: 4, method: "Alert on controller mode changes (RUN→PROGRAM→RUN)", dataSource: "PLC status monitoring", confidence: "high" },
      { phase: 5, method: "Cross-reference HMI values with independent field instruments", dataSource: "Process historian, field instruments", confidence: "medium" },
      { phase: 6, method: "Independent safety system verification (separate from PLC)", dataSource: "Safety instrumented system (SIS)", confidence: "high" },
    ],
    mitigations: [
      "Implement CIP Security for authenticated communications",
      "Maintain separate Safety Instrumented System (SIS) independent of PLC",
      "Periodic integrity checks comparing running logic to known-good baseline",
      "Physical key switch in RUN mode to prevent unauthorized downloads",
      "Network segmentation between engineering workstations and PLCs",
      "Independent process safety verification (physical instruments)",
      "AOI change detection and alerting",
      "Restrict Studio 5000 installations to hardened engineering workstations",
    ],
    estimatedDuration: "4-24 hours",
    requiredAccess: "Network access to PLC (direct or via compromised engineering workstation)",
    calderaAbilities: ["ics-plc-connect", "ics-project-download", "ics-logic-modify", "ics-project-upload", "ics-hmi-manipulate"],
  },
  {
    id: "WTR-003",
    name: "Unitronics Default Credential Exploitation (Aliquippa Pattern)",
    sector: "water_distribution",
    difficulty: "basic",
    description: "Replicates the November 2023 Aliquippa, PA water authority attack: exploit default credentials on Unitronics Vision PLCs to deface HMI and disrupt operations.",
    threatActors: ["CyberAv3ngers (IRGC-CEC)"],
    realWorldPrecedent: "November 2023: CyberAv3ngers compromised Unitronics Vision PLC at Aliquippa Municipal Water Authority, PA. Defaced HMI with anti-Israel message. 75+ Unitronics devices compromised globally.",
    cisaAdvisories: ["AA23-335A"],
    targetedEquipment: [
      { type: "PLC/HMI", vendor: "Unitronics", model: "Vision V570", protocol: "PCOM", commonPorts: [20256, 22], knownCves: [] },
      { type: "PLC/HMI", vendor: "Unitronics", model: "Vision V130", protocol: "PCOM", commonPorts: [20256, 22], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "Shodan Reconnaissance", description: "Search Shodan for Unitronics devices with default port 20256 open. Many are water/wastewater booster stations.", mitreIcsId: "T0883", mitreTechnique: "Internet Accessible Device", mitreTactic: "Initial Access", tools: ["Shodan", "Censys"], indicators: ["Shodan queries for 'Unitronics'"], duration: "Minutes" },
      { phase: 2, name: "Default Credential Access", description: "Connect to Unitronics VisiLogic or via SSH (port 22) using default password '1111'. No authentication changes required on most deployed devices.", mitreIcsId: "T0859", mitreTechnique: "Valid Accounts", mitreTactic: "Initial Access", tools: ["VisiLogic", "SSH client"], indicators: ["SSH connections to PLC from external IPs", "PCOM protocol connections"], duration: "Seconds" },
      { phase: 3, name: "HMI Defacement / Process Disruption", description: "Modify HMI display, change setpoints, or disable the controller. In Aliquippa, attackers defaced the display with 'You have been hacked' message.", mitreIcsId: "T0832", mitreTechnique: "Manipulation of View", mitreTactic: "Impact", tools: ["VisiLogic", "SSH commands"], indicators: ["HMI display changes", "Setpoint modifications", "Operator reports of unusual displays"], duration: "Seconds" },
    ],
    physicalImpacts: ["loss_of_view", "service_disruption"],
    impactDescription: "Operators lose HMI visibility. Booster pump stations may stop functioning. Water pressure drops in distribution system. Primarily a disruption/propaganda attack.",
    detectionOpportunities: [
      { phase: 1, method: "Block external access to port 20256 and 22 on OT devices", dataSource: "Firewall", confidence: "high" },
      { phase: 2, method: "Alert on SSH login to PLC devices", dataSource: "SSH logs, network monitoring", confidence: "high" },
      { phase: 3, method: "HMI change detection, process variable monitoring", dataSource: "SCADA historian", confidence: "medium" },
    ],
    mitigations: [
      "Change default password from '1111' immediately",
      "Disable SSH access on Unitronics PLCs",
      "Remove from internet; place behind VPN",
      "Implement network monitoring for PCOM protocol",
      "Regular backup of PLC programs",
    ],
    estimatedDuration: "15-30 minutes",
    requiredAccess: "Internet access to exposed Unitronics PLC",
    calderaAbilities: ["ics-recon-shodan", "ics-default-creds", "ics-hmi-manipulate"],
  },
];

// ─── Wastewater / Sewage Playbooks ──────────────────────────────────────────────

const WASTEWATER_PLAYBOOKS: AttackPlaybook[] = [
  {
    id: "WW-001",
    name: "Sewage Overflow via Pump Station Manipulation",
    sector: "wastewater",
    difficulty: "intermediate",
    description: "Target wastewater lift station PLCs to disable pumps or manipulate level sensors, causing sewage overflow into the environment. Based on documented attacks against wastewater systems.",
    threatActors: ["CyberAv3ngers (IRGC-CEC)", "Handala"],
    realWorldPrecedent: "July 2026 Minnesota attacks affected wastewater lift stations (Plymouth). 2021 Oldsmar, FL water treatment (chemical manipulation). Multiple EPA/CISA warnings about wastewater sector targeting.",
    cisaAdvisories: ["AA26-097A", "AA21-042A"],
    targetedEquipment: [
      { type: "PLC", vendor: "Rockwell Automation", model: "MicroLogix 1400", protocol: "EtherNet/IP", commonPorts: [44818], knownCves: ["CVE-2021-22681"] },
      { type: "RTU", vendor: "Various", model: "Cellular RTU", protocol: "Modbus TCP", commonPorts: [502], knownCves: [] },
      { type: "Level Sensor", vendor: "Various", model: "Ultrasonic Level", protocol: "4-20mA (via PLC)", commonPorts: [], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "Identify Lift Station Controllers", description: "Locate internet-exposed lift station PLCs. These are often on cellular connections in remote locations with minimal physical security.", mitreIcsId: "T0883", mitreTechnique: "Internet Accessible Device", mitreTactic: "Initial Access", tools: ["Shodan", "Censys", "Cellular IP range scanning"], indicators: ["Scanning of cellular carrier IP ranges on OT ports"], duration: "1-4 hours" },
      { phase: 2, name: "Access Lift Station PLC", description: "Connect to PLC via exposed port. Wastewater lift stations frequently have weaker security than treatment plants due to remote locations and cellular connectivity.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Initial Access", tools: ["RSLogix 500", "Modbus client"], indicators: ["Engineering connections from non-authorized sources"], duration: "Minutes" },
      { phase: 3, name: "Disable Pump Controls", description: "Modify pump start/stop logic or setpoints. Disable high-level alarms. Pumps stop running, wet well fills, sewage overflows.", mitreIcsId: "T0836", mitreTechnique: "Modify Parameter", mitreTactic: "Impair Process Control", tools: ["RSLogix 500", "Modbus write commands"], indicators: ["Pump status changes", "Setpoint modifications", "Alarm suppression"], duration: "Minutes" },
      { phase: 4, name: "Mask Level Readings", description: "Modify level sensor readings sent to SCADA to show normal levels while actual wet well is overflowing.", mitreIcsId: "T0832", mitreTechnique: "Manipulation of View", mitreTactic: "Impact", tools: ["PLC logic modification"], indicators: ["Level reading anomalies", "Discrepancy between sites"], duration: "Minutes" },
      { phase: 5, name: "Environmental Release", description: "Sewage overflows from wet well into environment. May contaminate waterways, trigger EPA violations, and create public health hazard.", mitreIcsId: "T0879", mitreTechnique: "Damage to Property", mitreTactic: "Impact", tools: ["None - physical consequence"], indicators: ["Overflow alarms (if not suppressed)", "Environmental monitoring", "Public reports"], duration: "Hours until discovery" },
    ],
    physicalImpacts: ["environmental_release", "public_health_hazard", "service_disruption"],
    impactDescription: "Sewage overflow into environment. EPA violations. Public health hazard. Potential waterway contamination. Significant cleanup costs and regulatory consequences.",
    detectionOpportunities: [
      { phase: 1, method: "Monitor cellular modem connections for unauthorized access", dataSource: "Cellular gateway logs", confidence: "medium" },
      { phase: 2, method: "Engineering software connection whitelist", dataSource: "Network monitoring", confidence: "high" },
      { phase: 3, method: "Pump runtime monitoring - alert on unexpected stops", dataSource: "SCADA historian", confidence: "high" },
      { phase: 4, method: "Cross-reference level readings with pump runtime data", dataSource: "Process analytics", confidence: "medium" },
      { phase: 5, method: "Physical overflow sensors independent of PLC", dataSource: "Independent instrumentation", confidence: "high" },
    ],
    mitigations: [
      "Implement private APN for cellular-connected lift stations",
      "Independent high-level float switches that trigger local alarms",
      "Physical overflow prevention (weirs, emergency storage)",
      "Regular pump runtime analytics to detect anomalies",
      "Redundant level measurement independent of PLC",
      "Network segmentation between lift stations and central SCADA",
    ],
    estimatedDuration: "1-4 hours",
    requiredAccess: "Internet/cellular access to lift station PLC",
    calderaAbilities: ["ics-recon-shodan", "ics-plc-connect", "ics-modify-setpoint", "ics-suppress-alarm"],
  },
];

// ─── Electric Power Playbooks ───────────────────────────────────────────────────

const ELECTRIC_POWER_PLAYBOOKS: AttackPlaybook[] = [
  {
    id: "ELC-001",
    name: "Substation IED Manipulation (Ukraine 2015/2016 Pattern)",
    sector: "electric_distribution",
    difficulty: "nation_state",
    description: "Replicates the Sandworm/BlackEnergy attacks on Ukrainian power grid: compromise substation RTUs/IEDs to open breakers and cause widespread power outage. Adapted for U.S. grid equipment.",
    threatActors: ["Sandworm (GRU Unit 74455)", "ELECTRUM"],
    realWorldPrecedent: "December 2015: BlackEnergy3 attack on Prykarpattyaoblenergo (230,000 customers without power). December 2016: Industroyer/CrashOverride attack on Ukrenergo transmission substation.",
    cisaAdvisories: ["AA22-110A", "MAR-17-352-01"],
    targetedEquipment: [
      { type: "RTU/IED", vendor: "ABB", model: "REF615", protocol: "IEC 61850 MMS", commonPorts: [102], knownCves: [] },
      { type: "RTU", vendor: "Siemens", model: "SIPROTEC", protocol: "IEC 61850", commonPorts: [102, 4712], knownCves: ["CVE-2015-5374"] },
      { type: "Gateway", vendor: "Various", model: "IEC 104 Gateway", protocol: "IEC 60870-5-104", commonPorts: [2404], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "IT Network Compromise", description: "Gain access to corporate IT network via spearphishing or supply chain. Pivot toward OT network through dual-homed systems or jump hosts.", mitreIcsId: "T0866", mitreTechnique: "Exploitation of Remote Services", mitreTactic: "Initial Access", tools: ["Spearphishing", "Credential harvesting", "VPN exploitation"], indicators: ["Phishing emails targeting energy sector", "Lateral movement toward OT DMZ"], duration: "Days to weeks" },
      { phase: 2, name: "OT Network Reconnaissance", description: "Map substation network architecture. Identify IEDs, RTUs, and their communication protocols (IEC 61850, IEC 104, DNP3).", mitreIcsId: "T0846", mitreTechnique: "Remote System Discovery", mitreTactic: "Discovery", tools: ["Network scanning", "Protocol analysis", "Wireshark"], indicators: ["Unusual network scanning in OT segments", "Protocol enumeration traffic"], duration: "Days" },
      { phase: 3, name: "IED/RTU Access", description: "Connect to substation IEDs using discovered credentials or protocol-level access. IEC 61850 MMS and IEC 104 often lack authentication.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Lateral Movement", tools: ["IEC 61850 client", "IEC 104 master station", "Custom tooling"], indicators: ["Unauthorized MMS connections", "IEC 104 commands from non-SCADA sources"], duration: "Hours" },
      { phase: 4, name: "Breaker Operation", description: "Send trip commands to circuit breakers via IED control. Open multiple breakers simultaneously to maximize outage area.", mitreIcsId: "T0855", mitreTechnique: "Unauthorized Command Message", mitreTactic: "Impair Process Control", tools: ["Industroyer-style tooling", "IEC 61850 GOOSE injection", "IEC 104 command injection"], indicators: ["Unexpected breaker operations", "Control commands from unauthorized sources", "Multiple simultaneous trips"], duration: "Seconds" },
      { phase: 5, name: "Disable Auto-Reclosing", description: "Modify protection relay settings to prevent automatic reclosing. This extends the outage duration significantly.", mitreIcsId: "T0836", mitreTechnique: "Modify Parameter", mitreTactic: "Impair Process Control", tools: ["Relay configuration tools"], indicators: ["Protection setting changes", "Auto-reclose disabled events"], duration: "Minutes" },
      { phase: 6, name: "Wiper Deployment (Optional)", description: "Deploy wiper malware on HMI/SCADA workstations to destroy recovery capability. Industroyer2 included this phase.", mitreIcsId: "T0809", mitreTechnique: "Data Destruction", mitreTactic: "Impact", tools: ["CaddyWiper", "Industroyer2 wiper component"], indicators: ["Mass file deletion", "MBR overwrite", "System crashes"], duration: "Minutes" },
    ],
    physicalImpacts: ["service_disruption", "cascading_failure", "equipment_damage"],
    impactDescription: "Widespread power outage affecting thousands to millions of customers. Extended duration if auto-reclosing disabled. Potential equipment damage from uncontrolled switching. Cascading failures possible across interconnected grid.",
    detectionOpportunities: [
      { phase: 1, method: "Email security, endpoint detection on IT network", dataSource: "EDR, email gateway", confidence: "medium" },
      { phase: 2, method: "OT network anomaly detection", dataSource: "OT IDS (Dragos, Claroty, Nozomi)", confidence: "medium" },
      { phase: 3, method: "Unauthorized protocol connections to IEDs", dataSource: "Network monitoring, IED logs", confidence: "high" },
      { phase: 4, method: "Unexpected breaker operations without operator command", dataSource: "SCADA event log, SOE recorder", confidence: "high" },
      { phase: 5, method: "Protection setting change monitoring", dataSource: "Relay event logs", confidence: "high" },
      { phase: 6, method: "Endpoint protection, file integrity monitoring", dataSource: "EDR, FIM", confidence: "high" },
    ],
    mitigations: [
      "Network segmentation between IT and OT (IEC 62443 zones)",
      "IEC 62351 for protocol-level authentication",
      "Substation hardening per NERC CIP standards",
      "Independent protection systems not connected to network",
      "Physical interlocks on critical breakers",
      "Offline backup of all relay/IED configurations",
      "OT-specific intrusion detection (Dragos, Claroty)",
    ],
    estimatedDuration: "Weeks of preparation, seconds of execution",
    requiredAccess: "IT network access → lateral movement to OT",
    calderaAbilities: ["ics-lateral-movement", "ics-protocol-exploit", "ics-breaker-trip", "ics-wiper-deploy"],
  },
  {
    id: "ELC-002",
    name: "COSMICENERGY / CHERNOVITE IEC 104 Manipulation",
    sector: "electric_transmission",
    difficulty: "advanced",
    description: "Replicates the COSMICENERGY malware capability: use IEC 60870-5-104 protocol to send unauthorized commands to RTUs, toggling power line switches.",
    threatActors: ["CHERNOVITE", "COSMICENERGY (Russia-linked)"],
    realWorldPrecedent: "May 2023: Mandiant discovered COSMICENERGY malware designed to interact with IEC 104 devices. Assessed as Russian training tool that could be weaponized.",
    cisaAdvisories: [],
    targetedEquipment: [
      { type: "RTU", vendor: "Various", model: "IEC 104 compatible RTU", protocol: "IEC 60870-5-104", commonPorts: [2404], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "Access SCADA Network", description: "Gain access to the network where IEC 104 master station communicates with field RTUs. May be via compromised jump host or VPN.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Initial Access", tools: ["VPN exploitation", "Credential theft"], indicators: ["Unauthorized VPN connections", "New devices on SCADA network"], duration: "Variable" },
      { phase: 2, name: "IEC 104 Protocol Interaction", description: "Use Python-based tooling (like COSMICENERGY's Piehop) to connect to IEC 104 RTUs. Send interrogation commands to map available data points.", mitreIcsId: "T0846", mitreTechnique: "Remote System Discovery", mitreTactic: "Discovery", tools: ["Python IEC 104 library", "Piehop-style tool"], indicators: ["IEC 104 general interrogation from non-master sources", "New TCP connections on port 2404"], duration: "Minutes to hours" },
      { phase: 3, name: "Command Injection", description: "Send IEC 104 single/double command (C_SC_NA_1, C_DC_NA_1) to toggle switches/breakers. COSMICENERGY uses Lightwork component for this.", mitreIcsId: "T0855", mitreTechnique: "Unauthorized Command Message", mitreTactic: "Impair Process Control", tools: ["Lightwork-style tool", "Custom IEC 104 client"], indicators: ["IEC 104 commands from unauthorized source", "Unexpected switching operations"], duration: "Seconds" },
    ],
    physicalImpacts: ["service_disruption", "cascading_failure"],
    impactDescription: "Unauthorized switching of power line equipment. Potential for localized or widespread outage depending on targeted substations.",
    detectionOpportunities: [
      { phase: 1, method: "Network access control on SCADA segments", dataSource: "NAC, firewall", confidence: "high" },
      { phase: 2, method: "Monitor for IEC 104 connections from non-master station IPs", dataSource: "OT IDS", confidence: "high" },
      { phase: 3, method: "Validate all IEC 104 commands against operator actions", dataSource: "SCADA audit log, SOE recorder", confidence: "high" },
    ],
    mitigations: [
      "IEC 62351-5 for IEC 104 authentication",
      "Strict source IP filtering for IEC 104 connections",
      "Command validation against operator session state",
      "Network segmentation between master station and field",
      "OT protocol deep packet inspection",
    ],
    estimatedDuration: "Hours to days",
    requiredAccess: "Network access to IEC 104 communication path",
    calderaAbilities: ["ics-network-access", "ics-protocol-discover", "ics-command-inject"],
  },
];

// ─── Volt Typhoon (Living-off-the-Land in OT) ────────────────────────────────

const VOLT_TYPHOON_PLAYBOOKS: AttackPlaybook[] = [
  {
    id: "VT-001",
    name: "Volt Typhoon LOTL Pre-Positioning (Water/Electric)",
    sector: "water_distribution",
    difficulty: "nation_state",
    description: "Replicates Volt Typhoon's documented pre-positioning campaign: gain persistent access to utility OT networks using only built-in OS tools and legitimate credentials. No custom malware deployed — pure living-off-the-land to evade detection while maintaining access for future disruption.",
    threatActors: ["Volt Typhoon (PRC MSS)", "BRONZE SILHOUETTE", "Vanguard Panda"],
    realWorldPrecedent: "2023-2026: CISA confirmed Volt Typhoon compromised multiple U.S. water utilities and electric companies, maintaining access for 5+ years using LOTL techniques. CISA AA24-038A (Feb 2024) documented pre-positioning in critical infrastructure.",
    cisaAdvisories: ["AA24-038A", "AA23-144A"],
    targetedEquipment: [
      { type: "Router", vendor: "Various", model: "SOHO Routers (Cisco, Netgear, ASUS)", protocol: "SSH/HTTP", commonPorts: [22, 80, 443], knownCves: ["CVE-2024-21887", "CVE-2023-46805"] },
      { type: "VPN", vendor: "Fortinet", model: "FortiGate", protocol: "SSL VPN", commonPorts: [443, 10443], knownCves: ["CVE-2022-42475", "CVE-2023-27997"] },
      { type: "Server", vendor: "Microsoft", model: "Windows Server (AD, DNS, DHCP)", protocol: "RDP/SMB/WMI", commonPorts: [3389, 445, 135], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "Edge Device Compromise", description: "Exploit internet-facing SOHO routers and VPN appliances to establish initial access. Use compromised devices as operational relay boxes (ORBs) to proxy traffic and obscure origin.", mitreIcsId: "T0866", mitreTechnique: "Exploitation of Remote Services", mitreTactic: "Initial Access", tools: ["Public exploits for edge devices", "KV Botnet infrastructure"], indicators: ["Unusual outbound connections from edge devices", "Modified router firmware", "Unexpected SSH keys"], duration: "Days" },
      { phase: 2, name: "Credential Harvesting via LOTL", description: "Use ntdsutil, secretsdump, and comsvcs.dll MiniDump to extract Active Directory credentials. No malware — only built-in Windows tools.", mitreIcsId: "T0859", mitreTechnique: "Valid Accounts", mitreTactic: "Credential Access", tools: ["ntdsutil.exe", "comsvcs.dll", "reg.exe (SAM dump)", "PowerShell"], indicators: ["ntdsutil IFM creation", "LSASS memory access", "SAM/SYSTEM registry export", "Volume shadow copy creation"], duration: "Hours" },
      { phase: 3, name: "Lateral Movement to OT DMZ", description: "Move from IT to OT using legitimate RDP, WMI, and PowerShell remoting with harvested domain credentials. Target historian servers and engineering workstations as pivot points.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Lateral Movement", tools: ["RDP", "WMI", "PowerShell Remoting", "PsExec"], indicators: ["RDP sessions to OT DMZ from unusual sources", "WMI process creation on historian servers", "Service installations via PsExec"], duration: "Days to weeks" },
      { phase: 4, name: "OT Network Persistence", description: "Establish persistent access on OT-adjacent systems (historians, engineering workstations, HMI servers) using scheduled tasks, WMI event subscriptions, and legitimate remote access tools.", mitreIcsId: "T0859", mitreTechnique: "Valid Accounts", mitreTactic: "Persistence", tools: ["schtasks.exe", "WMI subscriptions", "Legitimate remote admin tools"], indicators: ["New scheduled tasks on OT systems", "WMI permanent event subscriptions", "Unusual service accounts accessing OT"], duration: "Ongoing" },
      { phase: 5, name: "Pre-Positioning for Disruption", description: "Map OT network architecture, identify critical PLCs/RTUs, and maintain dormant access for potential future activation during geopolitical crisis. No immediate destructive action.", mitreIcsId: "T0846", mitreTechnique: "Remote System Discovery", mitreTactic: "Discovery", tools: ["netstat", "arp", "nslookup", "Network scanning via legitimate tools"], indicators: ["Network discovery commands on OT systems", "Access to PLC documentation shares", "Enumeration of SCADA databases"], duration: "Months to years" },
    ],
    physicalImpacts: ["loss_of_control", "service_disruption", "cascading_failure"],
    impactDescription: "Pre-positioned access enables future disruption of water distribution or electric systems on command. The LOTL approach means traditional malware detection fails. Disruption could be timed to coincide with geopolitical events (e.g., Taiwan crisis).",
    detectionOpportunities: [
      { phase: 1, method: "Monitor edge device firmware integrity and SSH key changes", dataSource: "Device management, firmware hashing", confidence: "medium" },
      { phase: 2, method: "Detect LSASS access, ntdsutil IFM, SAM registry exports", dataSource: "EDR, Windows Security Event Log (4688, 4624)", confidence: "high" },
      { phase: 3, method: "Baseline RDP/WMI patterns, alert on IT→OT lateral movement", dataSource: "Network flow, Windows Event Logs", confidence: "medium" },
      { phase: 4, method: "Monitor scheduled task creation and WMI subscriptions on OT systems", dataSource: "Sysmon, WMI activity logs", confidence: "high" },
      { phase: 5, method: "Behavioral analytics on OT-adjacent systems (unusual commands, access patterns)", dataSource: "UEBA, OT IDS", confidence: "low" },
    ],
    mitigations: [
      "Patch and harden all internet-facing edge devices (SOHO routers, VPN appliances)",
      "Implement phishing-resistant MFA for all remote access",
      "Deploy EDR on OT DMZ systems (historians, engineering workstations)",
      "Baseline and monitor LOTL tool usage (ntdsutil, comsvcs.dll, PsExec)",
      "Strict network segmentation between IT and OT per IEC 62443",
      "Implement jump server with session recording for OT access",
      "Regular credential rotation for service accounts with OT access",
      "Hunt for dormant persistence mechanisms (scheduled tasks, WMI subscriptions)",
    ],
    estimatedDuration: "Months of persistent access, disruption in seconds when activated",
    requiredAccess: "Internet-facing edge device → IT network → OT DMZ",
    calderaAbilities: ["lotl-credential-dump", "lotl-lateral-movement", "lotl-persistence", "lotl-ot-recon"],
  },
];

// ─── XENOTIME / TRITON (Safety System Targeting) ──────────────────────────────

const XENOTIME_PLAYBOOKS: AttackPlaybook[] = [
  {
    id: "TRI-001",
    name: "TRITON/TRISIS Safety Instrumented System Attack",
    sector: "electric_generation",
    difficulty: "nation_state",
    description: "Replicates the XENOTIME group's TRITON malware attack: compromise Safety Instrumented Systems (SIS) to disable emergency shutdown capability, enabling potential catastrophic physical damage or loss of life.",
    threatActors: ["XENOTIME", "TEMP.Veles", "TsNIIKhM (Russian research institute)"],
    realWorldPrecedent: "August 2017: TRITON malware deployed against Schneider Electric Triconex SIS controllers at a Saudi Arabian petrochemical facility. Attempted to disable safety systems that prevent explosions and toxic releases. Discovered only because a bug in the malware triggered a safety shutdown.",
    cisaAdvisories: ["MAR-17-352-01", "AA22-083A"],
    targetedEquipment: [
      { type: "SIS Controller", vendor: "Schneider Electric", model: "Triconex 3008", protocol: "TriStation", commonPorts: [1502], knownCves: ["CVE-2018-7522"] },
      { type: "SIS Controller", vendor: "Schneider Electric", model: "Tricon CX", protocol: "TriStation", commonPorts: [1502], knownCves: [] },
      { type: "Engineering Workstation", vendor: "Schneider Electric", model: "TriStation 1131", protocol: "TriStation", commonPorts: [1502], knownCves: [] },
      { type: "SIS Controller", vendor: "HIMA", model: "HIMax", protocol: "Proprietary", commonPorts: [9000], knownCves: [] },
    ],
    phases: [
      { phase: 1, name: "IT Network Compromise", description: "Gain initial access to corporate IT network via spearphishing or supply chain compromise. Establish persistent foothold.", mitreIcsId: "T0866", mitreTechnique: "Exploitation of Remote Services", mitreTactic: "Initial Access", tools: ["Spearphishing", "Custom RAT", "Credential harvesting"], indicators: ["Phishing targeting plant engineers", "C2 beaconing from engineering workstations"], duration: "Weeks" },
      { phase: 2, name: "Pivot to DCS Network", description: "Move laterally from IT to the Distributed Control System (DCS) network. Target engineering workstations that have access to both DCS and SIS networks.", mitreIcsId: "T0886", mitreTechnique: "Remote Services", mitreTactic: "Lateral Movement", tools: ["RDP", "Credential reuse", "Custom implants"], indicators: ["Lateral movement toward DCS segment", "Credential use on engineering workstations"], duration: "Days to weeks" },
      { phase: 3, name: "SIS Network Reconnaissance", description: "From the engineering workstation, discover SIS controllers on the safety network. Map TriStation protocol communications and understand the safety logic.", mitreIcsId: "T0846", mitreTechnique: "Remote System Discovery", mitreTactic: "Discovery", tools: ["Network scanning", "TriStation protocol analysis", "Wireshark"], indicators: ["Port scanning on SIS network", "TriStation protocol enumeration", "Safety logic file access"], duration: "Days" },
      { phase: 4, name: "TRITON Framework Deployment", description: "Deploy TRITON malware framework on the engineering workstation. The framework communicates with Triconex controllers using the TriStation protocol to read/write safety programs.", mitreIcsId: "T0821", mitreTechnique: "Modify Controller Tasking", mitreTactic: "Execution", tools: ["TRITON framework (Python-based)", "TriStation protocol library", "Custom shellcode"], indicators: ["Python execution on engineering workstation", "TriStation writes from non-standard sources", "SIS controller mode changes"], duration: "Hours" },
      { phase: 5, name: "Safety Logic Replacement", description: "Replace legitimate safety logic with attacker-controlled code. The modified logic either disables safety functions entirely or raises setpoints beyond safe limits. Safety system appears operational but will not trigger on actual dangerous conditions.", mitreIcsId: "T0839", mitreTechnique: "Module Firmware", mitreTactic: "Inhibit Response Function", tools: ["TRITON", "Custom Triconex shellcode (INJECT.bin)"], indicators: ["SIS program changes without maintenance window", "Controller key switch not in PROGRAM mode during upload", "Safety logic checksum mismatch"], duration: "Minutes" },
      { phase: 6, name: "Catastrophic Failure Enablement", description: "With safety systems disabled, the DCS can be manipulated to push process conditions beyond safe limits (overpressure, overtemperature, toxic release) without triggering emergency shutdown. Physical destruction or loss of life becomes possible.", mitreIcsId: "T0880", mitreTechnique: "Loss of Safety", mitreTactic: "Impact", tools: ["DCS manipulation (separate attack chain)", "Process condition forcing"], indicators: ["Process variables approaching limits without SIS activation", "Discrepancy between DCS readings and independent safety sensors"], duration: "Hours to trigger conditions" },
    ],
    physicalImpacts: ["safety_system_bypass", "equipment_damage", "environmental_release", "public_health_hazard"],
    impactDescription: "Disabling Safety Instrumented Systems removes the last line of defense against catastrophic industrial accidents. Without SIS protection, overpressure events, toxic chemical releases, explosions, or reactor meltdowns become possible. The 2017 Saudi attack could have caused an explosion killing plant workers.",
    detectionOpportunities: [
      { phase: 1, method: "Email security, endpoint detection", dataSource: "EDR, email gateway", confidence: "medium" },
      { phase: 2, method: "Monitor lateral movement toward DCS/SIS segments", dataSource: "Network segmentation monitoring, firewall logs", confidence: "medium" },
      { phase: 3, method: "Alert on any scanning or enumeration of SIS network", dataSource: "SIS network IDS, firewall", confidence: "high" },
      { phase: 4, method: "Monitor for TriStation protocol writes from non-TriStation software", dataSource: "OT IDS with protocol awareness", confidence: "high" },
      { phase: 5, method: "SIS logic change detection — compare running logic hash against golden baseline", dataSource: "SIS integrity monitoring", confidence: "high" },
      { phase: 6, method: "Independent safety sensors that bypass SIS (hardwired trips)", dataSource: "Independent protection layer", confidence: "high" },
    ],
    mitigations: [
      "Air-gap SIS from DCS network (IEC 61511 requirement)",
      "Physical key switch on SIS controllers — PROGRAM mode only during maintenance",
      "Restrict TriStation protocol to dedicated engineering workstation with MFA",
      "SIS logic integrity monitoring with cryptographic hashing",
      "Independent Protection Layers (IPL) hardwired beyond SIS",
      "Regular SIS logic verification against offline golden copy",
      "Application whitelisting on SIS engineering workstations",
      "Network monitoring for TriStation protocol anomalies",
      "Implement IEC 62443 SL-3+ for SIS zones",
    ],
    estimatedDuration: "Months of preparation, minutes of SIS modification",
    requiredAccess: "IT network → DCS network → SIS network (multi-hop)",
    calderaAbilities: ["ics-lateral-to-dcs", "ics-sis-recon", "ics-tristation-exploit", "ics-safety-logic-replace"],
  },
];

// ─── All Playbooks Combined ─────────────────────────────────────────────────────

const ALL_PLAYBOOKS: AttackPlaybook[] = [
  ...WATER_TREATMENT_PLAYBOOKS,
  ...WASTEWATER_PLAYBOOKS,
  ...ELECTRIC_POWER_PLAYBOOKS,
  ...VOLT_TYPHOON_PLAYBOOKS,
  ...XENOTIME_PLAYBOOKS,
];

// ─── Query Functions ────────────────────────────────────────────────────────────

export function getAllPlaybooks(): AttackPlaybook[] {
  return ALL_PLAYBOOKS;
}

export function getPlaybookById(id: string): AttackPlaybook | undefined {
  return ALL_PLAYBOOKS.find(p => p.id === id);
}

export function getPlaybooksBySector(sector: UtilitySector): AttackPlaybook[] {
  return ALL_PLAYBOOKS.filter(p => p.sector === sector);
}

export function getPlaybooksByDifficulty(difficulty: PlaybookDifficulty): AttackPlaybook[] {
  return ALL_PLAYBOOKS.filter(p => p.difficulty === difficulty);
}

export function getPlaybooksByThreatActor(actor: string): AttackPlaybook[] {
  return ALL_PLAYBOOKS.filter(p =>
    p.threatActors.some(a => a.toLowerCase().includes(actor.toLowerCase()))
  );
}

export function getPlaybooksByCisaAdvisory(advisory: string): AttackPlaybook[] {
  return ALL_PLAYBOOKS.filter(p => p.cisaAdvisories.includes(advisory));
}

export function searchPlaybooks(query: string): AttackPlaybook[] {
  const q = query.toLowerCase();
  return ALL_PLAYBOOKS.filter(p =>
    p.name.toLowerCase().includes(q) ||
    p.description.toLowerCase().includes(q) ||
    p.threatActors.some(a => a.toLowerCase().includes(q)) ||
    p.realWorldPrecedent.toLowerCase().includes(q) ||
    p.targetedEquipment.some(e => e.vendor.toLowerCase().includes(q) || e.model.toLowerCase().includes(q))
  );
}

export function getPlaybookSummary(): {
  total: number;
  bySector: Record<string, number>;
  byDifficulty: Record<string, number>;
  byThreatActor: Record<string, number>;
  cisaAdvisories: string[];
} {
  const bySector: Record<string, number> = {};
  const byDifficulty: Record<string, number> = {};
  const byThreatActor: Record<string, number> = {};
  const advisories = new Set<string>();

  for (const p of ALL_PLAYBOOKS) {
    bySector[p.sector] = (bySector[p.sector] || 0) + 1;
    byDifficulty[p.difficulty] = (byDifficulty[p.difficulty] || 0) + 1;
    for (const actor of p.threatActors) {
      byThreatActor[actor] = (byThreatActor[actor] || 0) + 1;
    }
    for (const adv of p.cisaAdvisories) {
      advisories.add(adv);
    }
  }

  return {
    total: ALL_PLAYBOOKS.length,
    bySector,
    byDifficulty,
    byThreatActor,
    cisaAdvisories: [...advisories],
  };
}
