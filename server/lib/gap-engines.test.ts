import { describe, it, expect } from "vitest";

// ─── Exploitation Bridge Tests ───────────────────────────────────────────────
import {
  deterministicGenerateExploitPlan,
  lookupExploitsForCve,
  getKnownExploitableCves,
} from "./exploitation-bridge";

describe("Exploitation Bridge", () => {
  describe("lookupExploitsForCve", () => {
    it("returns known exploits for EternalBlue CVE", () => {
      const exploits = lookupExploitsForCve("CVE-2017-0144");
      expect(exploits.length).toBeGreaterThan(0);
      expect(exploits[0].msfModule).toContain("eternalblue");
      expect(exploits[0].reliability).toBe("excellent");
    });

    it("returns known exploits for Log4Shell CVE", () => {
      const exploits = lookupExploitsForCve("CVE-2021-44228");
      expect(exploits.length).toBeGreaterThan(0);
      expect(exploits[0].msfModule).toContain("log4shell");
    });

    it("returns empty array for unknown CVE", () => {
      const exploits = lookupExploitsForCve("CVE-9999-9999");
      expect(exploits).toEqual([]);
    });
  });

  describe("getKnownExploitableCves", () => {
    it("returns list of CVEs with known exploits", () => {
      const cves = getKnownExploitableCves();
      expect(cves.length).toBeGreaterThan(5);
      expect(cves).toContain("CVE-2017-0144");
      expect(cves).toContain("CVE-2021-44228");
      expect(cves).toContain("CVE-2020-1472");
    });
  });

  describe("deterministicGenerateExploitPlan", () => {
    it("generates a plan for known CVE (EternalBlue)", () => {
      const plan = deterministicGenerateExploitPlan({
        cve: "CVE-2017-0144",
        title: "EternalBlue SMB RCE",
        cvss: 9.8,
        service: "smb",
        port: 445,
        targetIp: "10.0.0.5",
        targetOs: "Windows Server 2008",
      });
      expect(plan.selectedExploit.modulePath).toContain("eternalblue");
      expect(plan.selectedExploit.source).toBe("metasploit");
      expect(plan.confidence).toBeGreaterThanOrEqual(80);
      expect(plan.preflightChecks.length).toBeGreaterThan(0);
      expect(plan.executionSteps.length).toBeGreaterThan(0);
      expect(plan.payloadConfig.platform).toBe("windows");
    });

    it("generates a fallback plan for unknown CVE", () => {
      const plan = deterministicGenerateExploitPlan({
        cve: "CVE-9999-9999",
        title: "Unknown Vulnerability",
        cvss: 7.5,
        service: "http",
        port: 80,
        targetIp: "10.0.0.10",
        targetOs: "Linux",
      });
      expect(plan.confidence).toBeLessThan(80);
      expect(plan.selectedExploit.source).toBe("manual");
      expect(plan.payloadConfig.platform).toBe("linux");
    });

    it("selects correct payload for Windows targets", () => {
      const plan = deterministicGenerateExploitPlan({
        cve: "CVE-2021-34473",
        title: "ProxyShell",
        cvss: 9.8,
        service: "exchange",
        port: 443,
        targetIp: "10.0.0.1",
        targetOs: "Windows Server 2019",
      });
      expect(plan.payloadConfig.type).toContain("windows");
      expect(plan.payloadConfig.type).toContain("meterpreter");
    });

    it("includes evidence capture plan", () => {
      const plan = deterministicGenerateExploitPlan({
        cve: "CVE-2017-0144",
        title: "EternalBlue",
        cvss: 9.8,
        service: "smb",
        port: 445,
        targetIp: "10.0.0.5",
      });
      expect(plan.evidenceCapturePlan.consoleOutput).toBe(true);
      expect(plan.evidenceCapturePlan.systemInfo).toBe(true);
      expect(plan.evidenceCapturePlan.timestampAll).toBe(true);
    });

    it("includes OPSEC assessment", () => {
      const plan = deterministicGenerateExploitPlan({
        cve: "CVE-2017-0144",
        title: "EternalBlue",
        cvss: 9.8,
        service: "smb",
        port: 445,
        targetIp: "10.0.0.5",
      });
      expect(plan.opsecAssessment).toBeDefined();
      expect(plan.opsecAssessment.risk).toBeGreaterThan(0);
      expect(plan.opsecAssessment.detectionSignatures.length).toBeGreaterThan(0);
    });
  });
});

// ─── Privilege Escalation Engine Tests ───────────────────────────────────────
import {
  deterministicAnalyzePrivesc,
  getPrivescTechniques,
  getEnumerationTools,
  getKerberosAttacks,
  getCloudPrivescTechniques,
  PRIVESC_TECHNIQUES,
  ENUMERATION_TOOLS,
} from "./privesc-engine";

describe("Privilege Escalation Engine", () => {
  describe("PRIVESC_TECHNIQUES knowledge base", () => {
    it("has comprehensive technique coverage", () => {
      expect(PRIVESC_TECHNIQUES.length).toBeGreaterThanOrEqual(15);
    });

    it("includes Windows, Linux, and Cloud techniques", () => {
      const windows = PRIVESC_TECHNIQUES.filter(t => t.targetOs.includes("windows"));
      const linux = PRIVESC_TECHNIQUES.filter(t => t.targetOs.includes("linux"));
      const cloud = PRIVESC_TECHNIQUES.filter(t => t.targetOs.some(o => o.startsWith("cloud_")));
      expect(windows.length).toBeGreaterThan(0);
      expect(linux.length).toBeGreaterThan(0);
      expect(cloud.length).toBeGreaterThan(0);
    });

    it("all techniques have required fields", () => {
      for (const t of PRIVESC_TECHNIQUES) {
        expect(t.id).toBeTruthy();
        expect(t.name).toBeTruthy();
        expect(t.attackId).toBeTruthy();
        expect(t.enumerationCommand).toBeTruthy();
        expect(t.opsecRisk).toBeGreaterThanOrEqual(0);
        expect(t.reliability).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe("getPrivescTechniques", () => {
    it("returns all techniques when no filter", () => {
      const all = getPrivescTechniques();
      expect(all.length).toBe(PRIVESC_TECHNIQUES.length);
    });

    it("filters by target OS", () => {
      const linux = getPrivescTechniques({ targetOs: "linux" });
      expect(linux.every(t => t.targetOs.includes("linux"))).toBe(true);
    });

    it("filters by category", () => {
      const kerberos = getPrivescTechniques({ category: "kerberos" });
      expect(kerberos.every(t => t.category === "kerberos")).toBe(true);
      expect(kerberos.length).toBeGreaterThan(0);
    });

    it("filters by max OPSEC risk", () => {
      const lowRisk = getPrivescTechniques({ maxOpsecRisk: 3 });
      expect(lowRisk.every(t => t.opsecRisk <= 3)).toBe(true);
    });
  });

  describe("getKerberosAttacks", () => {
    it("returns Kerberos-specific techniques", () => {
      const kerberos = getKerberosAttacks();
      expect(kerberos.length).toBeGreaterThanOrEqual(4);
      expect(kerberos.some(t => t.id === "kerberoasting")).toBe(true);
      expect(kerberos.some(t => t.id === "golden_ticket")).toBe(true);
    });
  });

  describe("getCloudPrivescTechniques", () => {
    it("returns AWS techniques", () => {
      const aws = getCloudPrivescTechniques("aws");
      expect(aws.length).toBeGreaterThan(0);
      expect(aws.every(t => t.targetOs.includes("cloud_aws"))).toBe(true);
    });

    it("returns Azure techniques", () => {
      const azure = getCloudPrivescTechniques("azure");
      expect(azure.length).toBeGreaterThan(0);
    });
  });

  describe("deterministicAnalyzePrivesc", () => {
    it("detects SeImpersonatePrivilege", () => {
      const result = deterministicAnalyzePrivesc(
        "PRIVILEGES INFORMATION\n\nSeImpersonatePrivilege  Impersonate a client after authentication  Enabled",
        "service_account",
        "windows"
      );
      expect(result.identifiedVectors.some(v => v.technique.id === "win_potato_juicy")).toBe(true);
      expect(result.confidence).toBeGreaterThan(50);
    });

    it("detects SUID binaries on Linux", () => {
      const result = deterministicAnalyzePrivesc(
        "/usr/bin/find has SUID bit set\n-rwsr-xr-x 1 root root 233984 /usr/bin/find",
        "user",
        "linux"
      );
      expect(result.identifiedVectors.some(v => v.technique.id === "linux_suid")).toBe(true);
    });

    it("detects sudo NOPASSWD", () => {
      const result = deterministicAnalyzePrivesc(
        "User www-data may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim",
        "user",
        "linux"
      );
      expect(result.identifiedVectors.some(v => v.technique.id === "linux_sudo_misconfig")).toBe(true);
    });

    it("includes Kerberos workflow for AD environments", () => {
      const result = deterministicAnalyzePrivesc(
        "Domain: CORP.LOCAL\nServicePrincipalName found",
        "domain_user",
        "windows",
        true
      );
      expect(result.kerberosWorkflow).toBeDefined();
      expect(result.kerberosWorkflow?.applicable).toBe(true);
    });

    it("includes cloud privesc for cloud environments", () => {
      const result = deterministicAnalyzePrivesc(
        "AWS IAM user with iam:CreatePolicyVersion",
        "iam_user",
        "linux",
        false,
        "aws"
      );
      expect(result.cloudPrivesc).toBeDefined();
      expect(result.cloudPrivesc?.applicable).toBe(true);
      expect(result.cloudPrivesc?.provider).toBe("aws");
    });

    it("returns fallback when no vectors found", () => {
      const result = deterministicAnalyzePrivesc(
        "Nothing interesting found",
        "user",
        "linux"
      );
      expect(result.identifiedVectors.length).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(30);
    });
  });

  describe("getEnumerationTools", () => {
    it("returns all tools when no filter", () => {
      expect(getEnumerationTools().length).toBe(ENUMERATION_TOOLS.length);
    });

    it("filters by target OS", () => {
      const windowsTools = getEnumerationTools("windows");
      expect(windowsTools.every(t => t.targetOs.includes("windows"))).toBe(true);
    });
  });
});

// ─── OPSEC Risk Engine Tests ─────────────────────────────────────────────────
import {
  deterministicScoreActionRisk,
  checkBurnIndicators,
  calculateEngagementOpsecStatus,
  getDetectionTechnologies,
  getAllBurnIndicators,
  getActionRiskProfiles,
  DETECTION_TECHNOLOGIES,
} from "./opsec-risk-engine";

describe("OPSEC Risk Engine", () => {
  describe("DETECTION_TECHNOLOGIES knowledge base", () => {
    it("has comprehensive technology coverage", () => {
      expect(DETECTION_TECHNOLOGIES.length).toBeGreaterThanOrEqual(5);
    });

    it("includes EDR, SIEM, and NDR categories", () => {
      const categories = new Set(DETECTION_TECHNOLOGIES.map(t => t.category));
      expect(categories.has("edr")).toBe(true);
      expect(categories.has("siem")).toBe(true);
      expect(categories.has("ndr")).toBe(true);
    });
  });

  describe("deterministicScoreActionRisk", () => {
    it("scores credential dumping as high risk", () => {
      const score = deterministicScoreActionRisk("credential_dump", "Dumping LSASS memory with mimikatz");
      expect(score.riskScore).toBeGreaterThanOrEqual(80);
      expect(score.riskLevel).toMatch(/critical|high/);
    });

    it("scores port scanning as medium risk", () => {
      const score = deterministicScoreActionRisk("port_scan", "Nmap SYN scan on target subnet");
      expect(score.riskScore).toBeLessThan(70);
    });

    it("reduces risk for LOLBin techniques", () => {
      const normalScore = deterministicScoreActionRisk("privesc_attempt", "Running kernel exploit");
      const lolbinScore = deterministicScoreActionRisk("privesc_attempt", "Using lolbin living off the land technique");
      expect(lolbinScore.riskScore).toBeLessThan(normalScore.riskScore);
    });

    it("increases risk for PowerShell encoded commands", () => {
      const normalScore = deterministicScoreActionRisk("lateral_movement", "WinRM connection");
      const encodedScore = deterministicScoreActionRisk("lateral_movement", "PowerShell encoded command execution");
      expect(encodedScore.riskScore).toBeGreaterThan(normalScore.riskScore);
    });

    it("tracks cumulative exposure", () => {
      const score = deterministicScoreActionRisk("exploit_attempt", "Active exploitation", 50);
      expect(score.cumulativeExposure).toBeGreaterThan(50);
    });

    it("flags burn risk when cumulative exposure is high", () => {
      const score = deterministicScoreActionRisk("credential_dump", "LSASS dump with mimikatz", 75);
      expect(score.burnRisk).toBe(true);
    });

    it("provides safer alternatives", () => {
      const score = deterministicScoreActionRisk("credential_dump", "Dumping credentials");
      expect(score.mitigations.length).toBeGreaterThan(0);
    });
  });

  describe("checkBurnIndicators", () => {
    it("detects account lockout from failed logins", () => {
      const now = Date.now();
      const events = Array.from({ length: 6 }, (_, i) => ({
        type: "login",
        success: false,
        timestamp: now - i * 60000,
      }));
      const burns = checkBurnIndicators(events);
      expect(burns.some(b => b.id === "account_lockout")).toBe(true);
    });

    it("detects C2 channel blocking", () => {
      const now = Date.now();
      const events = Array.from({ length: 4 }, (_, i) => ({
        type: "c2_callback",
        success: false,
        timestamp: now - i * 60000,
      }));
      const burns = checkBurnIndicators(events);
      expect(burns.some(b => b.id === "c2_blocked")).toBe(true);
    });

    it("detects killed implant sessions", () => {
      const burns = checkBurnIndicators([
        { type: "session_died", success: false, timestamp: Date.now() },
      ]);
      expect(burns.some(b => b.id === "implant_killed")).toBe(true);
    });

    it("returns empty array when no burn indicators", () => {
      const burns = checkBurnIndicators([
        { type: "login", success: true, timestamp: Date.now() },
        { type: "c2_callback", success: true, timestamp: Date.now() },
      ]);
      expect(burns.length).toBe(0);
    });
  });

  describe("calculateEngagementOpsecStatus", () => {
    it("returns green for no actions", () => {
      expect(calculateEngagementOpsecStatus([])).toBe("green");
    });

    it("returns green for low-risk undetected actions", () => {
      const status = calculateEngagementOpsecStatus([
        { action: "dns_enum", risk: 20, timestamp: Date.now(), detected: false },
        { action: "port_scan", risk: 30, timestamp: Date.now(), detected: false },
      ]);
      expect(status).toBe("green");
    });

    it("returns red for high detection rate", () => {
      const status = calculateEngagementOpsecStatus([
        { action: "exploit", risk: 80, timestamp: Date.now(), detected: true },
        { action: "cred_dump", risk: 90, timestamp: Date.now(), detected: true },
        { action: "lateral", risk: 70, timestamp: Date.now(), detected: false },
      ]);
      expect(status).toBe("red");
    });
  });

  describe("getDetectionTechnologies", () => {
    it("returns all technologies when no filter", () => {
      expect(getDetectionTechnologies().length).toBe(DETECTION_TECHNOLOGIES.length);
    });

    it("filters by category", () => {
      const edrs = getDetectionTechnologies("edr");
      expect(edrs.every(t => t.category === "edr")).toBe(true);
    });
  });

  describe("getActionRiskProfiles", () => {
    it("returns all risk profiles", () => {
      const profiles = getActionRiskProfiles();
      expect(Object.keys(profiles).length).toBeGreaterThan(10);
      expect(profiles.credential_dump).toBeDefined();
      expect(profiles.port_scan).toBeDefined();
    });
  });
});

// ─── Lateral Movement Engine Tests ───────────────────────────────────────────
import {
  deterministicPlanLateralMovement,
  getAvailableTechniques,
  getTechnique,
  LATERAL_TECHNIQUES,
} from "./lateral-movement-engine";

describe("Lateral Movement Engine", () => {
  describe("LATERAL_TECHNIQUES knowledge base", () => {
    it("has comprehensive technique coverage", () => {
      expect(LATERAL_TECHNIQUES.length).toBeGreaterThanOrEqual(5);
    });

    it("all techniques have required fields", () => {
      for (const t of LATERAL_TECHNIQUES) {
        expect(t.id).toBeTruthy();
        expect(t.name).toBeTruthy();
        expect(t.targetOs.length).toBeGreaterThan(0);
        expect(t.opsecRisk).toBeGreaterThanOrEqual(0);
      }
    });
  });

  describe("getAvailableTechniques", () => {
    it("returns all techniques when no filter", () => {
      expect(getAvailableTechniques().length).toBe(LATERAL_TECHNIQUES.length);
    });

    it("filters by target OS", () => {
      const windows = getAvailableTechniques({ targetOs: "windows" });
      expect(windows.every(t => t.targetOs.includes("windows"))).toBe(true);
    });

    it("filters by max OPSEC risk", () => {
      const lowRisk = getAvailableTechniques({ maxOpsecRisk: 3 });
      expect(lowRisk.every(t => t.opsecRisk <= 3)).toBe(true);
    });
  });

  describe("getTechnique", () => {
    it("returns a technique by ID", () => {
      const firstId = LATERAL_TECHNIQUES[0].id;
      const technique = getTechnique(firstId);
      expect(technique).toBeDefined();
      expect(technique?.id).toBe(firstId);
    });

    it("returns undefined for unknown ID", () => {
      expect(getTechnique("nonexistent_technique")).toBeUndefined();
    });
  });

  describe("deterministicPlanLateralMovement", () => {
    it("generates a plan for Windows-to-Windows lateral movement", () => {
      const plan = deterministicPlanLateralMovement(
        { ip: "10.0.0.5", os: "windows", accessLevel: "admin" },
        { ip: "10.0.0.10", os: "windows" },
        [{ type: "ntlm_hash", username: "admin", domain: "CORP" }]
      );
      expect(plan).toBeDefined();
      expect(plan.reasoning).toBeTruthy();
    });

    it("generates a plan for Linux-to-Linux lateral movement", () => {
      const plan = deterministicPlanLateralMovement(
        { ip: "10.0.0.5", os: "linux", accessLevel: "root" },
        { ip: "10.0.0.10", os: "linux" },
        [{ type: "ssh_key", username: "root" }]
      );
      expect(plan).toBeDefined();
    });
  });
});

// ─── Engagement Workflow Engine Tests ────────────────────────────────────────
import {
  deterministicEvaluateState,
  validatePhaseTransition,
  createTimelineEvent,
  getAllPhaseDefinitions,
  getPhaseDefinition,
  calculateOverallProgress,
  KILL_CHAIN_PHASES,
  PHASE_DEFINITIONS,
} from "./engagement-workflow-engine";

describe("Engagement Workflow Engine", () => {
  describe("KILL_CHAIN_PHASES", () => {
    it("has all standard kill chain phases", () => {
      expect(KILL_CHAIN_PHASES.length).toBeGreaterThanOrEqual(7);
    });
  });

  describe("PHASE_DEFINITIONS", () => {
    it("has a definition for each phase", () => {
      for (const phase of KILL_CHAIN_PHASES) {
        expect(PHASE_DEFINITIONS[phase]).toBeDefined();
        expect(PHASE_DEFINITIONS[phase].name).toBeTruthy();
      }
    });
  });

  describe("getAllPhaseDefinitions", () => {
    it("returns all phase definitions", () => {
      const defs = getAllPhaseDefinitions();
      expect(defs.length).toBe(KILL_CHAIN_PHASES.length);
    });
  });

  describe("getPhaseDefinition", () => {
    it("returns a specific phase definition", () => {
      const phase = KILL_CHAIN_PHASES[0];
      const def = getPhaseDefinition(phase);
      expect(def).toBeDefined();
      expect(def.name).toBeTruthy();
    });
  });

  describe("validatePhaseTransition", () => {
    it("allows sequential phase transitions", () => {
      if (KILL_CHAIN_PHASES.length >= 2) {
        const result = validatePhaseTransition(KILL_CHAIN_PHASES[0], KILL_CHAIN_PHASES[1]);
        expect(result).toBeDefined();
      }
    });
  });

  describe("createTimelineEvent", () => {
    it("creates a timeline event with correct fields", () => {
      const event = createTimelineEvent(1, KILL_CHAIN_PHASES[0], "scan", "Ran nmap scan", "operator1");
      expect(event).toBeDefined();
      expect(event.engagementId).toBe(1);
      expect(event.phase).toBe(KILL_CHAIN_PHASES[0]);
    });
  });

  describe("calculateOverallProgress", () => {
    it("returns 0 for no progress", () => {
      const progress: Record<string, number> = {};
      for (const phase of KILL_CHAIN_PHASES) {
        progress[phase] = 0;
      }
      const result = calculateOverallProgress(progress as any);
      expect(result).toBe(0);
    });

    it("returns 100 for full progress", () => {
      const progress: Record<string, number> = {};
      for (const phase of KILL_CHAIN_PHASES) {
        progress[phase] = 100;
      }
      const result = calculateOverallProgress(progress as any);
      expect(result).toBe(100);
    });
  });

  describe("deterministicEvaluateState", () => {
    it("evaluates engagement state for first phase", () => {
      const phaseProgress: Record<string, number> = {} as any;
      const findingsCounts: Record<string, number> = {} as any;
      for (const p of KILL_CHAIN_PHASES) {
        phaseProgress[p] = 0;
        findingsCounts[p] = 0;
      }
      phaseProgress[KILL_CHAIN_PHASES[0]] = 50;
      const result = deterministicEvaluateState({
        engagementId: 1,
        currentPhase: KILL_CHAIN_PHASES[0],
        phaseProgress,
        findingsCounts,
        completedPhases: [],
        activeObjectives: [],
        completedObjectives: [],
        totalFindings: 0,
        shellsObtained: 0,
        credentialsFound: 0,
        pivotHostsEstablished: 0,
        overallProgress: 10,
      } as any);
      expect(result).toBeDefined();
    });
  });
});
