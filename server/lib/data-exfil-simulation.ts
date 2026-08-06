/**
 * Data Exfiltration Simulation Engine
 * ═══════════════════════════════════════════════════════════════
 * Simulates data exfiltration techniques used by real-world threat
 * actors to test DLP controls, network monitoring, and SOC detection
 * capabilities. All simulations use benign test data — no actual
 * sensitive data is exfiltrated.
 *
 * Techniques modeled after MITRE ATT&CK Exfiltration (TA0010):
 *   T1048 — Exfiltration Over Alternative Protocol
 *   T1041 — Exfiltration Over C2 Channel
 *   T1567 — Exfiltration to Cloud Storage
 *   T1537 — Transfer Data to Cloud Account
 *   T1029 — Scheduled Transfer
 *   T1030 — Data Transfer Size Limits
 *   T1052 — Exfiltration Over Physical Medium (simulated)
 *   T1020 — Automated Exfiltration
 */

// ═══════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════

export type ExfilChannel = 
  | "dns_tunneling"
  | "https_post"
  | "https_steganography"
  | "icmp_tunneling"
  | "smtp_attachment"
  | "cloud_storage"
  | "websocket"
  | "ftp_passive"
  | "custom_protocol";

export type ExfilSpeed = "slow_and_low" | "moderate" | "burst" | "scheduled";

export type DataType = 
  | "pii_sample"
  | "credit_card_sample"
  | "credentials_sample"
  | "source_code_sample"
  | "database_dump_sample"
  | "document_sample"
  | "custom";

export interface ExfilScenario {
  id: string;
  name: string;
  description: string;
  channel: ExfilChannel;
  speed: ExfilSpeed;
  dataType: DataType;
  mitreId: string;
  mitreName: string;
  difficulty: "basic" | "intermediate" | "advanced" | "expert";
  dlpBypassTechniques: string[];
  expectedDetections: string[];
  threatGroups: string[];
}

export interface ExfilSimulationConfig {
  scenarioId: string;
  targetHost: string;
  /** Size of test data to exfiltrate in KB */
  dataSizeKb: number;
  /** Duration of simulation in seconds */
  durationSeconds: number;
  /** Whether to use encryption on the exfil channel */
  encrypted: boolean;
  /** Whether to use encoding (base64, hex) to obfuscate data */
  encoded: boolean;
  /** Chunk size in bytes for data splitting */
  chunkSizeBytes: number;
  /** Delay between chunks in ms (for slow-and-low) */
  chunkDelayMs: number;
  /** Custom destination for exfil (e.g., DNS server, cloud bucket) */
  destination?: string;
  /** Whether to log all packets for analysis */
  captureTraffic: boolean;
}

export interface ExfilSimulationResult {
  simulationId: string;
  scenarioId: string;
  scenarioName: string;
  status: "completed" | "detected" | "blocked" | "partial" | "failed";
  startedAt: number;
  completedAt: number;
  durationMs: number;
  /** Amount of test data successfully exfiltrated */
  dataExfiltratedKb: number;
  /** Total data attempted */
  dataAttemptedKb: number;
  /** Exfiltration success rate */
  successRate: number;
  /** Transfer rate achieved */
  transferRateKbps: number;
  /** Number of chunks sent */
  chunksSent: number;
  /** Number of chunks that made it through */
  chunksSucceeded: number;
  /** Detection events triggered */
  detectionEvents: DetectionEvent[];
  /** DLP controls that fired */
  dlpEvents: DLPEvent[];
  /** Network anomalies observed */
  networkAnomalies: NetworkAnomaly[];
  /** Overall assessment */
  assessment: ExfilAssessment;
}

export interface DetectionEvent {
  timestamp: number;
  source: string;
  rule: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  detected: boolean;
}

export interface DLPEvent {
  timestamp: number;
  policy: string;
  action: "blocked" | "alerted" | "logged" | "none";
  dataPattern: string;
  description: string;
}

export interface NetworkAnomaly {
  timestamp: number;
  type: "dns_volume" | "unusual_port" | "large_upload" | "beaconing" | "protocol_anomaly" | "geo_anomaly";
  description: string;
  severity: "high" | "medium" | "low";
  detected: boolean;
}

export interface ExfilAssessment {
  overallRisk: "critical" | "high" | "medium" | "low";
  dlpEffectiveness: number; // 0-100
  networkMonitoringScore: number; // 0-100
  detectionCoverage: number; // 0-100
  recommendations: string[];
  gaps: string[];
  mitreMapping: Array<{ techniqueId: string; techniqueName: string; status: "detected" | "partially_detected" | "undetected" }>;
}

// ═══════════════════════════════════════════════════════════════
// §2 — SCENARIO CATALOG
// ═══════════════════════════════════════════════════════════════

export const EXFIL_SCENARIOS: ExfilScenario[] = [
  {
    id: "dns_tunnel_basic",
    name: "DNS Tunneling — Basic",
    description: "Encodes data in DNS TXT record queries to exfiltrate through DNS infrastructure. Most organizations allow outbound DNS, making this a common bypass technique.",
    channel: "dns_tunneling",
    speed: "slow_and_low",
    dataType: "credentials_sample",
    mitreId: "T1048.003",
    mitreName: "Exfiltration Over Alternative Protocol: DNS",
    difficulty: "intermediate",
    dlpBypassTechniques: ["DNS encoding", "Subdomain encoding", "TXT record abuse"],
    expectedDetections: ["Unusual DNS query volume", "Long subdomain names", "DNS TXT record anomalies", "Known DNS tunnel signatures"],
    threatGroups: ["APT29", "APT34", "Lazarus Group"],
  },
  {
    id: "https_chunked",
    name: "HTTPS Chunked Upload",
    description: "Splits data into small chunks and uploads via HTTPS POST requests to a legitimate-looking endpoint. Mimics normal web traffic patterns.",
    channel: "https_post",
    speed: "moderate",
    dataType: "document_sample",
    mitreId: "T1041",
    mitreName: "Exfiltration Over C2 Channel",
    difficulty: "basic",
    dlpBypassTechniques: ["TLS encryption", "Small chunk sizes", "Legitimate-looking URLs", "User-agent spoofing"],
    expectedDetections: ["Large outbound data volume", "Unusual upload patterns", "Beaconing behavior", "DLP content inspection"],
    threatGroups: ["APT28", "APT41", "FIN7"],
  },
  {
    id: "https_steganography",
    name: "Image Steganography via HTTPS",
    description: "Hides data within image files (LSB steganography) and uploads to image hosting services. Extremely difficult to detect with standard DLP.",
    channel: "https_steganography",
    speed: "slow_and_low",
    dataType: "source_code_sample",
    mitreId: "T1027.003",
    mitreName: "Obfuscated Files: Steganography",
    difficulty: "expert",
    dlpBypassTechniques: ["LSB steganography", "Image format abuse", "Legitimate hosting services", "No detectable patterns"],
    expectedDetections: ["Statistical analysis of image files", "Unusual image upload volume", "Known steganography tool signatures"],
    threatGroups: ["APT29", "Turla"],
  },
  {
    id: "icmp_tunnel",
    name: "ICMP Tunneling",
    description: "Encodes data in ICMP echo request/reply payloads. Often allowed through firewalls that permit ping traffic.",
    channel: "icmp_tunneling",
    speed: "slow_and_low",
    dataType: "credentials_sample",
    mitreId: "T1048.003",
    mitreName: "Exfiltration Over Alternative Protocol: ICMP",
    difficulty: "intermediate",
    dlpBypassTechniques: ["ICMP payload encoding", "Ping traffic mimicry", "Low data rate"],
    expectedDetections: ["Large ICMP payloads", "Unusual ICMP volume", "ICMP tunnel signatures"],
    threatGroups: ["APT28", "Sandworm"],
  },
  {
    id: "cloud_storage_exfil",
    name: "Cloud Storage Exfiltration",
    description: "Uploads data to legitimate cloud storage services (S3, Azure Blob, GCS). Blends with normal cloud traffic.",
    channel: "cloud_storage",
    speed: "burst",
    dataType: "database_dump_sample",
    mitreId: "T1567.002",
    mitreName: "Exfiltration to Cloud Storage",
    difficulty: "basic",
    dlpBypassTechniques: ["Legitimate cloud endpoints", "TLS encryption", "Authorized cloud services"],
    expectedDetections: ["Unusual cloud upload volume", "New cloud storage destinations", "DLP cloud monitoring", "CASB alerts"],
    threatGroups: ["APT41", "Scattered Spider", "LockBit"],
  },
  {
    id: "smtp_exfil",
    name: "Email Attachment Exfiltration",
    description: "Sends data as encrypted email attachments to external addresses. Leverages legitimate email infrastructure.",
    channel: "smtp_attachment",
    speed: "scheduled",
    dataType: "pii_sample",
    mitreId: "T1048.002",
    mitreName: "Exfiltration Over Alternative Protocol: Email",
    difficulty: "basic",
    dlpBypassTechniques: ["Password-protected attachments", "Encrypted ZIP files", "Legitimate email addresses", "Small attachment sizes"],
    expectedDetections: ["DLP email scanning", "Encrypted attachment policies", "Unusual recipient patterns", "Volume anomalies"],
    threatGroups: ["APT34", "FIN7", "Mustang Panda"],
  },
  {
    id: "websocket_exfil",
    name: "WebSocket Persistent Channel",
    description: "Establishes a WebSocket connection to an external server and streams data continuously. Difficult to distinguish from legitimate WebSocket traffic.",
    channel: "websocket",
    speed: "moderate",
    dataType: "source_code_sample",
    mitreId: "T1071.001",
    mitreName: "Application Layer Protocol: Web Protocols",
    difficulty: "advanced",
    dlpBypassTechniques: ["WebSocket protocol", "TLS encryption", "Legitimate-looking endpoints", "Persistent connection"],
    expectedDetections: ["Long-lived WebSocket connections", "Unusual data volume over WebSocket", "Beaconing patterns"],
    threatGroups: ["APT29", "APT41"],
  },
  {
    id: "scheduled_transfer",
    name: "Scheduled Low-Volume Transfer",
    description: "Exfiltrates small amounts of data on a regular schedule (e.g., every hour) to stay below detection thresholds. Mimics legitimate automated processes.",
    channel: "https_post",
    speed: "scheduled",
    dataType: "pii_sample",
    mitreId: "T1029",
    mitreName: "Scheduled Transfer",
    difficulty: "advanced",
    dlpBypassTechniques: ["Low volume per transfer", "Regular schedule mimicry", "Business hours only", "Legitimate user-agent"],
    expectedDetections: ["Long-term volume analysis", "Behavioral analytics", "Baseline deviation alerts"],
    threatGroups: ["APT29", "Salt Typhoon", "Volt Typhoon"],
  },
  {
    id: "multi_channel_exfil",
    name: "Multi-Channel Exfiltration",
    description: "Splits data across multiple exfiltration channels simultaneously (DNS + HTTPS + cloud) to reduce per-channel volume and evade detection.",
    channel: "custom_protocol",
    speed: "moderate",
    dataType: "database_dump_sample",
    mitreId: "T1048",
    mitreName: "Exfiltration Over Alternative Protocol",
    difficulty: "expert",
    dlpBypassTechniques: ["Channel splitting", "Volume distribution", "Protocol diversity", "Timing randomization"],
    expectedDetections: ["Correlated multi-protocol analysis", "Aggregate volume monitoring", "Advanced behavioral analytics"],
    threatGroups: ["APT29", "APT41", "Lazarus Group"],
  },
];

export function getScenario(scenarioId: string): ExfilScenario | undefined {
  return EXFIL_SCENARIOS.find(s => s.id === scenarioId);
}

export function getScenariosByDifficulty(difficulty: ExfilScenario["difficulty"]): ExfilScenario[] {
  return EXFIL_SCENARIOS.filter(s => s.difficulty === difficulty);
}

export function getScenariosByChannel(channel: ExfilChannel): ExfilScenario[] {
  return EXFIL_SCENARIOS.filter(s => s.channel === channel);
}

// ═══════════════════════════════════════════════════════════════
// §3 — TEST DATA GENERATOR
// ═══════════════════════════════════════════════════════════════

/**
 * Generate benign test data that mimics the structure of sensitive data
 * without containing any actual sensitive information.
 */
export function generateTestData(dataType: DataType, sizeKb: number): { data: string; description: string } {
  const targetBytes = sizeKb * 1024;

  switch (dataType) {
    case "pii_sample":
      return { data: generateFakePII(targetBytes), description: "Synthetic PII records (fake names, addresses, SSNs)" };
    case "credit_card_sample":
      return { data: generateFakeCreditCards(targetBytes), description: "Synthetic credit card numbers (Luhn-invalid test numbers)" };
    case "credentials_sample":
      return { data: generateFakeCredentials(targetBytes), description: "Synthetic credential pairs (fake usernames and passwords)" };
    case "source_code_sample":
      return { data: generateFakeSourceCode(targetBytes), description: "Synthetic source code (Lorem ipsum code patterns)" };
    case "database_dump_sample":
      return { data: generateFakeDatabaseDump(targetBytes), description: "Synthetic database dump (fake table data in SQL format)" };
    case "document_sample":
      return { data: generateFakeDocument(targetBytes), description: "Synthetic document content (Lorem ipsum business text)" };
    default:
      return { data: "A".repeat(targetBytes), description: "Generic test payload" };
  }
}

function generateFakePII(targetBytes: number): string {
  const firstNames = ["John", "Jane", "Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank"];
  const lastNames = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Moore"];
  const streets = ["123 Main St", "456 Oak Ave", "789 Pine Rd", "321 Elm Blvd", "654 Maple Dr"];
  const cities = ["Springfield", "Riverside", "Fairview", "Clinton", "Georgetown"];
  const states = ["CA", "TX", "NY", "FL", "IL", "PA", "OH", "GA", "NC", "MI"];

  let result = "# SYNTHETIC PII DATA — FOR TESTING ONLY\n# All data is fake and generated for DLP testing\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    const first = firstNames[i % firstNames.length];
    const last = lastNames[(i * 7) % lastNames.length];
    const ssn = `${String(100 + (i % 899)).padStart(3, "0")}-${String(10 + (i % 89)).padStart(2, "0")}-${String(1000 + i).padStart(4, "0")}`;
    const street = streets[i % streets.length];
    const city = cities[i % cities.length];
    const state = states[i % states.length];
    result += `${first} ${last}, SSN: ${ssn}, ${street}, ${city}, ${state} ${String(10000 + i).padStart(5, "0")}, DOB: ${1950 + (i % 50)}-${String(1 + (i % 12)).padStart(2, "0")}-${String(1 + (i % 28)).padStart(2, "0")}\n`;
    i++;
  }
  return result.slice(0, targetBytes);
}

function generateFakeCreditCards(targetBytes: number): string {
  let result = "# SYNTHETIC CREDIT CARD DATA — FOR TESTING ONLY\n# All numbers are Luhn-invalid test numbers\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    const num = `4111-0000-0000-${String(1000 + i).padStart(4, "0")}`;
    const exp = `${String(1 + (i % 12)).padStart(2, "0")}/${2025 + (i % 5)}`;
    const cvv = String(100 + (i % 900));
    result += `Card: ${num}, Exp: ${exp}, CVV: ${cvv}, Name: Test User ${i}\n`;
    i++;
  }
  return result.slice(0, targetBytes);
}

function generateFakeCredentials(targetBytes: number): string {
  const domains = ["example.com", "test.local", "corp.internal", "lab.test", "dev.null"];
  let result = "# SYNTHETIC CREDENTIALS — FOR TESTING ONLY\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    const domain = domains[i % domains.length];
    result += `user${i}@${domain}:P@ssw0rd_Test_${String(i).padStart(4, "0")}!${i % 100}\n`;
    i++;
  }
  return result.slice(0, targetBytes);
}

function generateFakeSourceCode(targetBytes: number): string {
  const lines = [
    "function processData(input: string): Result {",
    "  const validated = validateInput(input);",
    "  if (!validated) throw new Error('Invalid input');",
    "  const transformed = transform(validated);",
    "  return { success: true, data: transformed };",
    "}",
    "",
    "class DataProcessor {",
    "  private cache = new Map<string, unknown>();",
    "  async process(items: Item[]): Promise<Result[]> {",
    "    return Promise.all(items.map(i => this.processOne(i)));",
    "  }",
    "}",
    "",
  ];
  let result = "// SYNTHETIC SOURCE CODE — FOR TESTING ONLY\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    result += lines[i % lines.length] + "\n";
    i++;
  }
  return result.slice(0, targetBytes);
}

function generateFakeDatabaseDump(targetBytes: number): string {
  let result = "-- SYNTHETIC DATABASE DUMP — FOR TESTING ONLY\n\nCREATE TABLE test_users (id INT, name VARCHAR(100), email VARCHAR(100));\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    result += `INSERT INTO test_users VALUES (${i}, 'Test User ${i}', 'user${i}@example.com');\n`;
    i++;
  }
  return result.slice(0, targetBytes);
}

function generateFakeDocument(targetBytes: number): string {
  const paragraphs = [
    "This is a synthetic document generated for data loss prevention testing purposes. All content is fictional and does not represent any real business data.",
    "The quarterly financial projections indicate a nominal growth trajectory consistent with market expectations. Revenue streams remain diversified across multiple sectors.",
    "Strategic initiatives for the upcoming fiscal year include expansion into emerging markets, optimization of operational workflows, and investment in next-generation technology platforms.",
    "Risk assessment findings suggest moderate exposure to supply chain disruptions. Mitigation strategies have been documented and approved by the executive committee.",
  ];
  let result = "CONFIDENTIAL — SYNTHETIC DOCUMENT FOR DLP TESTING\n\n";
  let i = 0;
  while (Buffer.byteLength(result) < targetBytes) {
    result += paragraphs[i % paragraphs.length] + "\n\n";
    i++;
  }
  return result.slice(0, targetBytes);
}

// ═══════════════════════════════════════════════════════════════
// §4 — SIMULATION ENGINE
// ═══════════════════════════════════════════════════════════════

/**
 * Run a data exfiltration simulation. This generates test data,
 * simulates the exfiltration technique, and produces a detailed
 * assessment of detection capabilities.
 *
 * NOTE: This is a simulation — it generates synthetic traffic patterns
 * and detection events based on the scenario configuration. It does NOT
 * actually exfiltrate data over the network. For live testing against
 * actual DLP/SIEM, use the agent-based deployment with the exfil module.
 */
export async function runExfilSimulation(config: ExfilSimulationConfig): Promise<ExfilSimulationResult> {
  const scenario = getScenario(config.scenarioId);
  if (!scenario) throw new Error(`Unknown scenario: ${config.scenarioId}`);

  const startedAt = Date.now();
  const simulationId = `exfil-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Generate test data
  const testData = generateTestData(scenario.dataType, config.dataSizeKb);

  // Calculate simulation parameters
  const totalChunks = Math.ceil((config.dataSizeKb * 1024) / config.chunkSizeBytes);
  const transferTimeMs = config.durationSeconds * 1000;

  // Simulate detection events based on scenario
  const detectionEvents = simulateDetections(scenario, config, totalChunks);
  const dlpEvents = simulateDLPEvents(scenario, config);
  const networkAnomalies = simulateNetworkAnomalies(scenario, config, totalChunks);

  // Calculate success rate based on detection events
  const blockedChunks = dlpEvents.filter(e => e.action === "blocked").length * Math.ceil(totalChunks * 0.1);
  const detectedChunks = detectionEvents.filter(e => e.detected).length * Math.ceil(totalChunks * 0.05);
  const chunksSucceeded = Math.max(0, totalChunks - blockedChunks);
  const dataExfiltratedKb = Math.round((chunksSucceeded / totalChunks) * config.dataSizeKb * 100) / 100;
  const successRate = totalChunks > 0 ? Math.round((chunksSucceeded / totalChunks) * 100) / 100 : 0;

  // Determine overall status
  let status: ExfilSimulationResult["status"];
  if (successRate === 0) status = "blocked";
  else if (successRate < 0.5) status = "partial";
  else if (detectionEvents.some(e => e.detected && e.severity === "critical")) status = "detected";
  else status = "completed";

  const completedAt = Date.now();

  // Build assessment
  const assessment = buildAssessment(scenario, detectionEvents, dlpEvents, networkAnomalies, successRate);

  return {
    simulationId,
    scenarioId: config.scenarioId,
    scenarioName: scenario.name,
    status,
    startedAt,
    completedAt,
    durationMs: completedAt - startedAt,
    dataExfiltratedKb,
    dataAttemptedKb: config.dataSizeKb,
    successRate,
    transferRateKbps: transferTimeMs > 0 ? Math.round((dataExfiltratedKb / (transferTimeMs / 1000)) * 100) / 100 : 0,
    chunksSent: totalChunks,
    chunksSucceeded,
    detectionEvents,
    dlpEvents,
    networkAnomalies,
    assessment,
  };
}

function simulateDetections(scenario: ExfilScenario, config: ExfilSimulationConfig, totalChunks: number): DetectionEvent[] {
  const events: DetectionEvent[] = [];
  const now = Date.now();

  for (const expectedDetection of scenario.expectedDetections) {
    // Simulate whether each expected detection would fire
    // More sophisticated scenarios are harder to detect
    const difficultyModifier = { basic: 0.9, intermediate: 0.6, advanced: 0.3, expert: 0.1 }[scenario.difficulty];
    const encryptionModifier = config.encrypted ? 0.7 : 1.0;
    const sizeModifier = config.dataSizeKb > 100 ? 1.2 : config.dataSizeKb > 10 ? 1.0 : 0.8;
    const detectionProbability = Math.min(1, difficultyModifier * encryptionModifier * sizeModifier);
    const detected = Math.random() < detectionProbability;

    events.push({
      timestamp: now + Math.floor(Math.random() * config.durationSeconds * 1000),
      source: getDetectionSource(expectedDetection),
      rule: expectedDetection,
      severity: detected ? (scenario.difficulty === "basic" ? "high" : "medium") : "info",
      description: `${expectedDetection} — ${detected ? "DETECTED" : "NOT DETECTED"} during ${scenario.name} simulation`,
      detected,
    });
  }

  return events.sort((a, b) => a.timestamp - b.timestamp);
}

function getDetectionSource(detection: string): string {
  if (detection.toLowerCase().includes("dns")) return "DNS Security";
  if (detection.toLowerCase().includes("dlp")) return "DLP Engine";
  if (detection.toLowerCase().includes("volume")) return "Network Monitor";
  if (detection.toLowerCase().includes("casb")) return "CASB";
  if (detection.toLowerCase().includes("beacon")) return "EDR/NDR";
  if (detection.toLowerCase().includes("behavioral")) return "UEBA";
  return "SIEM";
}

function simulateDLPEvents(scenario: ExfilScenario, config: ExfilSimulationConfig): DLPEvent[] {
  const events: DLPEvent[] = [];
  const now = Date.now();

  // DLP is more effective against unencrypted, larger transfers
  const dlpEffectiveness = config.encrypted ? 0.2 : 0.7;

  const dlpPolicies = [
    { policy: "PII Detection", pattern: "SSN/Name/Address patterns", applicableTypes: ["pii_sample", "credentials_sample"] },
    { policy: "Credit Card Detection", pattern: "Card number patterns (Luhn check)", applicableTypes: ["credit_card_sample"] },
    { policy: "Source Code Detection", pattern: "Code syntax patterns", applicableTypes: ["source_code_sample"] },
    { policy: "Database Content Detection", pattern: "SQL/dump patterns", applicableTypes: ["database_dump_sample"] },
    { policy: "Sensitive Document Detection", pattern: "Confidential markers", applicableTypes: ["document_sample"] },
  ];

  for (const dlp of dlpPolicies) {
    if (dlp.applicableTypes.includes(scenario.dataType)) {
      const triggered = Math.random() < dlpEffectiveness;
      const action = triggered ? (Math.random() < 0.5 ? "blocked" : "alerted") : "none";
      events.push({
        timestamp: now + Math.floor(Math.random() * config.durationSeconds * 1000),
        policy: dlp.policy,
        action: action as DLPEvent["action"],
        dataPattern: dlp.pattern,
        description: `DLP policy "${dlp.policy}" ${action === "none" ? "did not trigger" : `triggered: ${action}`}`,
      });
    }
  }

  return events;
}

function simulateNetworkAnomalies(scenario: ExfilScenario, config: ExfilSimulationConfig, totalChunks: number): NetworkAnomaly[] {
  const anomalies: NetworkAnomaly[] = [];
  const now = Date.now();

  // DNS tunneling generates DNS volume anomalies
  if (scenario.channel === "dns_tunneling") {
    anomalies.push({
      timestamp: now + 5000,
      type: "dns_volume",
      description: `Unusual DNS query volume detected: ${totalChunks} queries in ${config.durationSeconds}s (${Math.round(totalChunks / config.durationSeconds)} queries/sec)`,
      severity: totalChunks > 100 ? "high" : "medium",
      detected: totalChunks > 50,
    });
  }

  // Large uploads trigger volume alerts
  if (config.dataSizeKb > 50) {
    anomalies.push({
      timestamp: now + Math.floor(config.durationSeconds * 500),
      type: "large_upload",
      description: `Large outbound data transfer: ${config.dataSizeKb}KB to ${config.targetHost}`,
      severity: config.dataSizeKb > 500 ? "high" : "medium",
      detected: config.dataSizeKb > 100,
    });
  }

  // Beaconing detection for scheduled transfers
  if (scenario.speed === "scheduled" || scenario.speed === "slow_and_low") {
    anomalies.push({
      timestamp: now + Math.floor(config.durationSeconds * 800),
      type: "beaconing",
      description: `Regular interval communication pattern detected: every ${config.chunkDelayMs}ms to ${config.targetHost}`,
      severity: "medium",
      detected: config.chunkDelayMs < 5000,
    });
  }

  // ICMP anomalies
  if (scenario.channel === "icmp_tunneling") {
    anomalies.push({
      timestamp: now + 3000,
      type: "protocol_anomaly",
      description: `ICMP packets with unusual payload sizes detected (avg ${config.chunkSizeBytes} bytes vs normal 64 bytes)`,
      severity: "high",
      detected: config.chunkSizeBytes > 128,
    });
  }

  return anomalies;
}

function buildAssessment(
  scenario: ExfilScenario,
  detections: DetectionEvent[],
  dlpEvents: DLPEvent[],
  anomalies: NetworkAnomaly[],
  successRate: number,
): ExfilAssessment {
  const detectedCount = detections.filter(e => e.detected).length;
  const totalDetections = detections.length;
  const detectionCoverage = totalDetections > 0 ? Math.round((detectedCount / totalDetections) * 100) : 0;

  const dlpBlocked = dlpEvents.filter(e => e.action === "blocked").length;
  const dlpTriggered = dlpEvents.filter(e => e.action !== "none").length;
  const dlpEffectiveness = dlpEvents.length > 0 ? Math.round((dlpTriggered / dlpEvents.length) * 100) : 0;

  const anomalyDetected = anomalies.filter(a => a.detected).length;
  const networkMonitoringScore = anomalies.length > 0 ? Math.round((anomalyDetected / anomalies.length) * 100) : 0;

  // Overall risk
  let overallRisk: ExfilAssessment["overallRisk"];
  if (successRate > 0.8 && detectionCoverage < 30) overallRisk = "critical";
  else if (successRate > 0.5 && detectionCoverage < 50) overallRisk = "high";
  else if (successRate > 0.2) overallRisk = "medium";
  else overallRisk = "low";

  // Recommendations
  const recommendations: string[] = [];
  const gaps: string[] = [];

  if (detectionCoverage < 50) {
    recommendations.push("Improve detection coverage — less than 50% of expected detection rules fired.");
    gaps.push("Insufficient detection rule coverage");
  }
  if (dlpEffectiveness < 50) {
    recommendations.push("Strengthen DLP policies — current policies failed to detect or block the simulated data patterns.");
    gaps.push("DLP policy gaps for " + scenario.dataType.replace("_sample", "") + " data");
  }
  if (networkMonitoringScore < 50) {
    recommendations.push("Enhance network monitoring — anomalous traffic patterns went undetected.");
    gaps.push("Network anomaly detection gaps");
  }
  if (successRate > 0.5) {
    recommendations.push(`${Math.round(successRate * 100)}% of data was successfully exfiltrated via ${scenario.channel} — consider blocking or monitoring this channel.`);
    gaps.push(`${scenario.channel} channel not adequately monitored`);
  }
  if (scenario.difficulty === "basic" && successRate > 0.3) {
    recommendations.push("Basic exfiltration technique succeeded — this indicates fundamental gaps in egress controls.");
    gaps.push("Basic egress controls missing");
  }

  if (recommendations.length === 0) {
    recommendations.push("Detection controls performed well against this scenario. Consider testing with more advanced techniques.");
  }

  const mitreMapping = [
    {
      techniqueId: scenario.mitreId,
      techniqueName: scenario.mitreName,
      status: (successRate === 0 ? "detected" : successRate < 0.5 ? "partially_detected" : "undetected") as ExfilAssessment["mitreMapping"][0]["status"],
    },
  ];

  return {
    overallRisk,
    dlpEffectiveness,
    networkMonitoringScore,
    detectionCoverage,
    recommendations,
    gaps,
    mitreMapping,
  };
}

// ═══════════════════════════════════════════════════════════════
// §5 — CAMPAIGN MANAGEMENT
// ═══════════════════════════════════════════════════════════════

export interface ExfilCampaign {
  id: string;
  name: string;
  description: string;
  scenarios: string[]; // scenario IDs
  status: "planned" | "running" | "completed" | "cancelled";
  results: ExfilSimulationResult[];
  overallAssessment: ExfilAssessment | null;
  createdAt: number;
  completedAt: number | null;
}

/**
 * Build an overall assessment from multiple simulation results.
 */
export function buildCampaignAssessment(results: ExfilSimulationResult[]): ExfilAssessment {
  if (results.length === 0) {
    return {
      overallRisk: "low",
      dlpEffectiveness: 100,
      networkMonitoringScore: 100,
      detectionCoverage: 100,
      recommendations: ["No simulations run yet."],
      gaps: [],
      mitreMapping: [],
    };
  }

  const avgDlp = Math.round(results.reduce((s, r) => s + r.assessment.dlpEffectiveness, 0) / results.length);
  const avgNetwork = Math.round(results.reduce((s, r) => s + r.assessment.networkMonitoringScore, 0) / results.length);
  const avgDetection = Math.round(results.reduce((s, r) => s + r.assessment.detectionCoverage, 0) / results.length);
  const avgSuccess = results.reduce((s, r) => s + r.successRate, 0) / results.length;

  let overallRisk: ExfilAssessment["overallRisk"];
  if (avgSuccess > 0.7 && avgDetection < 40) overallRisk = "critical";
  else if (avgSuccess > 0.4 && avgDetection < 60) overallRisk = "high";
  else if (avgSuccess > 0.2) overallRisk = "medium";
  else overallRisk = "low";

  const allGaps = [...new Set(results.flatMap(r => r.assessment.gaps))];
  const allRecommendations = [...new Set(results.flatMap(r => r.assessment.recommendations))];
  const allMitre = results.flatMap(r => r.assessment.mitreMapping);

  return {
    overallRisk,
    dlpEffectiveness: avgDlp,
    networkMonitoringScore: avgNetwork,
    detectionCoverage: avgDetection,
    recommendations: allRecommendations.slice(0, 10),
    gaps: allGaps,
    mitreMapping: allMitre,
  };
}
