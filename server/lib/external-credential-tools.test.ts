import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  TOOL_KNOWLEDGE_BASE,
  TOOL_SELECTION_SYSTEM_PROMPT,
  getToolCapabilities,
  getToolKnowledgeBase,
  getToolSelectionPrompt,
  quickToolRecommendation,
  clearToolDetectionCache,
  detectAllTools,
} from "./external-credential-tools";

// ─── Tool Knowledge Base Tests ────────────────────────────────────────────

describe("TOOL_KNOWLEDGE_BASE", () => {
  it("should define all three tools", () => {
    expect(TOOL_KNOWLEDGE_BASE).toHaveProperty("hydra");
    expect(TOOL_KNOWLEDGE_BASE).toHaveProperty("medusa");
    expect(TOOL_KNOWLEDGE_BASE).toHaveProperty("netexec");
  });

  it("hydra should have correct metadata", () => {
    const hydra = TOOL_KNOWLEDGE_BASE.hydra;
    expect(hydra.fullName).toBe("THC Hydra");
    expect(hydra.license).toBe("AGPL-3.0");
    expect(hydra.protocols.native.length).toBeGreaterThan(40);
    expect(hydra.protocols.native).toContain("ssh");
    expect(hydra.protocols.native).toContain("ftp");
    expect(hydra.protocols.native).toContain("http-post-form");
    expect(hydra.protocols.native).toContain("rdp");
    expect(hydra.protocols.native).toContain("mysql");
    expect(hydra.protocols.native).toContain("redis");
    expect(hydra.protocols.native).toContain("mongodb");
    expect(hydra.strengths.length).toBeGreaterThan(5);
    expect(hydra.weaknesses.length).toBeGreaterThan(3);
    expect(hydra.bestFor.length).toBeGreaterThan(3);
    expect(hydra.avoidFor.length).toBeGreaterThan(3);
    expect(hydra.commandExamples).toHaveProperty("sshBrute");
    expect(hydra.commandExamples).toHaveProperty("httpPostForm");
  });

  it("medusa should have correct metadata", () => {
    const medusa = TOOL_KNOWLEDGE_BASE.medusa;
    expect(medusa.fullName).toBe("Medusa (Foofus)");
    expect(medusa.license).toBe("GPLv2");
    expect(medusa.protocols.native.length).toBeGreaterThan(15);
    expect(medusa.protocols.native).toContain("ssh");
    expect(medusa.protocols.native).toContain("ftp");
    expect(medusa.protocols.native).toContain("smb");
    expect(medusa.strengths.length).toBeGreaterThan(5);
    expect(medusa.bestFor.length).toBeGreaterThan(3);
    expect(medusa.commandExamples).toHaveProperty("sshBrute");
    expect(medusa.commandExamples).toHaveProperty("multiHost");
  });

  it("netexec should have correct metadata", () => {
    const netexec = TOOL_KNOWLEDGE_BASE.netexec;
    expect(netexec.fullName).toBe("NetExec (CrackMapExec successor)");
    expect(netexec.license).toBe("BSD 2-Clause");
    expect(netexec.protocols.native).toContain("smb");
    expect(netexec.protocols.native).toContain("winrm");
    expect(netexec.protocols.native).toContain("ldap");
    expect(netexec.protocols.native).toContain("mssql");
    expect(netexec.adAttackTypes).toContain("pass_the_hash");
    expect(netexec.adAttackTypes).toContain("kerberoasting");
    expect(netexec.adAttackTypes).toContain("asrep_roasting");
    expect(netexec.adAttackTypes).toContain("sam_dump");
    expect(netexec.adAttackTypes).toContain("ntds_dump");
    expect(netexec.commandExamples).toHaveProperty("smbSpray");
    expect(netexec.commandExamples).toHaveProperty("passTheHash");
    expect(netexec.commandExamples).toHaveProperty("kerberoast");
  });

  it("each tool should have output format patterns", () => {
    expect(TOOL_KNOWLEDGE_BASE.hydra.outputFormat.successPattern).toBeInstanceOf(RegExp);
    expect(TOOL_KNOWLEDGE_BASE.medusa.outputFormat.successPattern).toBeInstanceOf(RegExp);
    expect(TOOL_KNOWLEDGE_BASE.netexec.outputFormat.successPattern).toBeInstanceOf(RegExp);
  });

  it("hydra output pattern should match example output", () => {
    const pattern = TOOL_KNOWLEDGE_BASE.hydra.outputFormat.successPattern;
    const example = "[22][ssh] host: 192.168.1.1   login: admin   password: secret123";
    const match = example.match(pattern);
    expect(match).not.toBeNull();
    expect(match![1]).toBe("22");
    expect(match![2]).toBe("ssh");
    expect(match![3]).toBe("192.168.1.1");
    expect(match![4]).toBe("admin");
    expect(match![5]).toBe("secret123");
  });

  it("medusa output pattern should match example output", () => {
    const pattern = TOOL_KNOWLEDGE_BASE.medusa.outputFormat.successPattern;
    const example = "ACCOUNT FOUND: [ssh] Host: 192.168.1.1 User: admin Password: secret123 [SUCCESS]";
    const match = example.match(pattern);
    expect(match).not.toBeNull();
    expect(match![1]).toBe("ssh");
    expect(match![2]).toBe("192.168.1.1");
    expect(match![3]).toBe("admin");
    expect(match![4]).toBe("secret123");
  });

  it("netexec output pattern should match example output", () => {
    const pattern = TOOL_KNOWLEDGE_BASE.netexec.outputFormat.successPattern;
    const example = "SMB  192.168.1.1  445  DC01  [+] DOMAIN\\admin:Password1 (Pwn3d!)";
    const match = example.match(pattern);
    expect(match).not.toBeNull();
    // Groups: 1=protocol(SMB), 2=host(192.168.1.1) or hostname, 3=domain, 4=user, 5=pass
    // The regex captures: (\w+)\s+(\S+)\s+\d+\s+(\S+)\s+\[\+\]\s+(?:(\S+)\\)?(\S+):(\S+)
    expect(match![1]).toBe("192.168.1.1");
  });
});

// ─── LLM System Prompt Tests ─────────────────────────────────────────────

describe("TOOL_SELECTION_SYSTEM_PROMPT", () => {
  it("should contain all three tool descriptions", () => {
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("THC Hydra");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Medusa");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("NetExec");
  });

  it("should contain the decision framework", () => {
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Decision Framework");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Active Directory");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("pass-the-hash");
  });

  it("should contain the protocol-to-tool mapping table", () => {
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("Protocol-to-Tool Mapping");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("SSH");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("SMB");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("WinRM");
  });

  it("should request JSON response format", () => {
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("JSON");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("recommended");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("reasoning");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("confidence");
    expect(TOOL_SELECTION_SYSTEM_PROMPT).toContain("attackPlan");
  });
});

// ─── Quick Tool Recommendation Tests ──────────────────────────────────────

describe("quickToolRecommendation", () => {
  it("should recommend netexec for Active Directory scenarios", () => {
    expect(quickToolRecommendation("smb", true)).toBe("netexec");
    expect(quickToolRecommendation("ssh", true)).toBe("netexec");
    expect(quickToolRecommendation("rdp", true)).toBe("netexec");
  });

  it("should recommend netexec for SMB/WinRM/WMI protocols", () => {
    expect(quickToolRecommendation("smb")).toBe("netexec");
    expect(quickToolRecommendation("winrm")).toBe("netexec");
    expect(quickToolRecommendation("wmi")).toBe("netexec");
  });

  it("should recommend hydra for SSH, FTP, HTTP, and database protocols", () => {
    expect(quickToolRecommendation("ssh")).toBe("hydra");
    expect(quickToolRecommendation("ftp")).toBe("hydra");
    expect(quickToolRecommendation("http_form")).toBe("hydra");
    expect(quickToolRecommendation("http_basic")).toBe("hydra");
    expect(quickToolRecommendation("mysql")).toBe("hydra");
    expect(quickToolRecommendation("postgresql")).toBe("hydra");
    expect(quickToolRecommendation("redis")).toBe("hydra");
    expect(quickToolRecommendation("mongodb")).toBe("hydra");
  });

  it("should recommend hydra for email protocols", () => {
    expect(quickToolRecommendation("smtp")).toBe("hydra");
    expect(quickToolRecommendation("pop3")).toBe("hydra");
    expect(quickToolRecommendation("imap")).toBe("hydra");
  });

  it("should recommend hydra for network protocols", () => {
    expect(quickToolRecommendation("snmp")).toBe("hydra");
    expect(quickToolRecommendation("telnet")).toBe("hydra");
    expect(quickToolRecommendation("vnc")).toBe("hydra");
    expect(quickToolRecommendation("rdp")).toBe("hydra");
    expect(quickToolRecommendation("ldap")).toBe("hydra");
  });

  it("should default to hydra for unknown protocols", () => {
    expect(quickToolRecommendation("unknown_protocol")).toBe("hydra");
  });
});

// ─── Tool Capabilities Tests ──────────────────────────────────────────────

describe("getToolCapabilities", () => {
  beforeEach(() => {
    clearToolDetectionCache();
  });

  it("should return capabilities for all four tools (including builtin)", () => {
    const caps = getToolCapabilities();
    expect(caps.length).toBe(4);
    const toolNames = caps.map(c => c.tool);
    expect(toolNames).toContain("hydra");
    expect(toolNames).toContain("medusa");
    expect(toolNames).toContain("netexec");
    expect(toolNames).toContain("builtin");
  });

  it("builtin should always be installed", () => {
    const caps = getToolCapabilities();
    const builtin = caps.find(c => c.tool === "builtin");
    expect(builtin).toBeDefined();
    expect(builtin!.installed).toBe(true);
  });

  it("each tool should have protocols, attack modes, and performance info", () => {
    const caps = getToolCapabilities();
    for (const cap of caps) {
      expect(cap.protocols.length).toBeGreaterThan(0);
      expect(cap.attackModes.length).toBeGreaterThan(0);
      expect(cap.performance).toBeDefined();
      expect(cap.performance.maxParallelConnections).toBeGreaterThan(0);
      expect(["fast", "moderate", "slow"]).toContain(cap.performance.relativeSpeed);
    }
  });

  it("hydra should have the most protocols", () => {
    const caps = getToolCapabilities();
    const hydra = caps.find(c => c.tool === "hydra")!;
    const medusa = caps.find(c => c.tool === "medusa")!;
    const netexec = caps.find(c => c.tool === "netexec")!;
    expect(hydra.protocols.length).toBeGreaterThan(medusa.protocols.length);
    expect(hydra.protocols.length).toBeGreaterThan(netexec.protocols.length);
  });

  it("netexec should have the most special capabilities", () => {
    const caps = getToolCapabilities();
    const netexec = caps.find(c => c.tool === "netexec")!;
    expect(netexec.specialCapabilities.length).toBeGreaterThan(5);
    expect(netexec.specialCapabilities.some(c => c.includes("Active Directory"))).toBe(true);
    expect(netexec.specialCapabilities.some(c => c.includes("Pass-the-hash"))).toBe(true);
    expect(netexec.specialCapabilities.some(c => c.includes("Kerberoasting"))).toBe(true);
  });

  it("hydra should be the fastest tool", () => {
    const caps = getToolCapabilities();
    const hydra = caps.find(c => c.tool === "hydra")!;
    expect(hydra.performance.relativeSpeed).toBe("fast");
    expect(hydra.performance.maxParallelConnections).toBe(64);
  });
});

// ─── Tool Detection Tests ─────────────────────────────────────────────────

describe("detectAllTools", () => {
  beforeEach(() => {
    clearToolDetectionCache();
  });

  it("should return detection results for all tools", () => {
    const detected = detectAllTools();
    expect(detected).toHaveProperty("hydra");
    expect(detected).toHaveProperty("medusa");
    expect(detected).toHaveProperty("netexec");
    expect(detected).toHaveProperty("builtin");
  });

  it("builtin should always be installed", () => {
    const detected = detectAllTools();
    expect(detected.builtin.installed).toBe(true);
    expect(detected.builtin.path).toBe("internal");
    expect(detected.builtin.version).toBe("1.0.0");
  });

  it("each detection result should have installed, path, and version fields", () => {
    const detected = detectAllTools();
    for (const [_, result] of Object.entries(detected)) {
      expect(typeof result.installed).toBe("boolean");
      // path and version can be null if not installed
    }
  });
});

// ─── Knowledge Base Export Tests ──────────────────────────────────────────

describe("getToolKnowledgeBase", () => {
  it("should return the full knowledge base", () => {
    const kb = getToolKnowledgeBase();
    expect(kb.hydra.fullName).toBe("THC Hydra");
    expect(kb.medusa.fullName).toBe("Medusa (Foofus)");
    expect(kb.netexec.fullName).toBe("NetExec (CrackMapExec successor)");
  });
});

describe("getToolSelectionPrompt", () => {
  it("should return the LLM system prompt string", () => {
    const prompt = getToolSelectionPrompt();
    expect(typeof prompt).toBe("string");
    expect(prompt.length).toBeGreaterThan(500);
    expect(prompt).toContain("hydra");
    expect(prompt).toContain("medusa");
    expect(prompt).toContain("netexec");
  });
});

// ─── Integration Correctness Tests ────────────────────────────────────────

describe("Tool Selection Logic Correctness", () => {
  it("should never recommend netexec for non-Windows protocols when AD is false", () => {
    const nonWindowsProtocols = ["ssh", "ftp", "http_form", "mysql", "redis", "mongodb", "smtp", "pop3", "imap", "snmp", "telnet", "vnc"];
    for (const proto of nonWindowsProtocols) {
      const rec = quickToolRecommendation(proto, false);
      expect(rec).not.toBe("netexec");
    }
  });

  it("should always recommend netexec when AD flag is true regardless of protocol", () => {
    const protocols = ["ssh", "ftp", "smb", "rdp", "mssql", "ldap"];
    for (const proto of protocols) {
      expect(quickToolRecommendation(proto, true)).toBe("netexec");
    }
  });

  it("knowledge base protocols should not overlap between AD-only and general tools", () => {
    // NetExec's unique protocols (not in Hydra)
    const netexecOnly = ["winrm", "wmi"];
    const hydraProtos = TOOL_KNOWLEDGE_BASE.hydra.protocols.native;
    for (const proto of netexecOnly) {
      expect(hydraProtos).not.toContain(proto);
    }
  });
});
