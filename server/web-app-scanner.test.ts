import { describe, expect, it, vi, beforeEach } from "vitest";
import { mapToMitre, findMsfModules } from "./lib/zap-scanner";

// ─── MITRE ATT&CK Mapping Tests ────────────────────────────────────────────

describe("mapToMitre", () => {
  it("maps SQL Injection CWE-89 to T1190 Initial Access", () => {
    const result = mapToMitre(89, "SQL Injection");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1190");
    expect(result!.techniqueName).toBe("Exploit Public-Facing Application");
    expect(result!.tactic).toBe("Initial Access");
  });

  it("maps XSS CWE-79 to T1189 Drive-by Compromise", () => {
    const result = mapToMitre(79, "Cross Site Scripting");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1189");
    expect(result!.tactic).toBe("Initial Access");
  });

  it("maps Command Injection CWE-78 to T1059 Execution", () => {
    const result = mapToMitre(78, "Remote OS Command Injection");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1059");
    expect(result!.tactic).toBe("Execution");
  });

  it("maps Path Traversal CWE-22 to T1005 Collection", () => {
    const result = mapToMitre(22, "Path Traversal");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1005");
    expect(result!.tactic).toBe("Collection");
  });

  it("maps SSRF CWE-918 to T1090 Command and Control", () => {
    const result = mapToMitre(918, "Server Side Request Forgery");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1090");
    expect(result!.tactic).toBe("Command and Control");
  });

  it("maps CSRF CWE-352 to T1185 Browser Session Hijacking", () => {
    const result = mapToMitre(352, "Missing Anti-CSRF Tokens");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1185");
    expect(result!.tactic).toBe("Collection");
  });

  it("maps Session Fixation CWE-384 to T1078 Valid Accounts", () => {
    const result = mapToMitre(384, "Session Fixation");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1078");
    expect(result!.tactic).toBe("Defense Evasion");
  });

  it("maps XXE CWE-611 to T1190 Initial Access", () => {
    const result = mapToMitre(611, "XML External Entity");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1190");
    expect(result!.tactic).toBe("Initial Access");
  });

  it("maps Deserialization CWE-502 to T1059 Execution", () => {
    const result = mapToMitre(502, "Insecure Deserialization");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1059");
    expect(result!.tactic).toBe("Execution");
  });

  it("maps File Upload CWE-434 to T1105 Command and Control", () => {
    const result = mapToMitre(434, "Unrestricted File Upload");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1105");
    expect(result!.tactic).toBe("Command and Control");
  });

  it("maps Open Redirect CWE-601 to T1189 Initial Access", () => {
    const result = mapToMitre(601, "Open Redirect");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1189");
    expect(result!.tactic).toBe("Initial Access");
  });

  it("falls back to alert name matching when CWE is null", () => {
    const result = mapToMitre(null, "SQL Injection");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1190");
  });

  it("falls back to alert name matching when CWE is unknown", () => {
    const result = mapToMitre(99999, "Cross Site Scripting (Reflected)");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1189");
  });

  it("matches alert name case-insensitively", () => {
    const result = mapToMitre(null, "remote code execution");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1059");
  });

  it("matches partial alert names", () => {
    const result = mapToMitre(null, "Directory Browsing Enabled on /uploads/");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1083");
  });

  it("returns null for unmapped CWE and unrecognized alert name", () => {
    const result = mapToMitre(99999, "Some Unknown Alert Type");
    expect(result).toBeNull();
  });

  it("returns null for null CWE and empty alert name", () => {
    const result = mapToMitre(null, "");
    expect(result).toBeNull();
  });

  it("maps CORS Misconfiguration via alert name", () => {
    const result = mapToMitre(null, "CORS Misconfiguration");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1557");
  });

  it("maps Cookie Without Secure Flag via alert name", () => {
    const result = mapToMitre(null, "Cookie Without Secure Flag");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1539");
  });

  it("maps CSP via alert name", () => {
    const result = mapToMitre(null, "Content Security Policy Header Not Set");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1189");
  });

  it("maps Source Code Disclosure via alert name", () => {
    const result = mapToMitre(null, "Source Code Disclosure - /src/config.php");
    expect(result).not.toBeNull();
    expect(result!.techniqueId).toBe("T1552");
  });
});

// ─── Metasploit Module Correlation Tests ────────────────────────────────────

describe("findMsfModules", () => {
  it("finds SQLi modules for CWE-89", () => {
    const modules = findMsfModules(89);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules[0]).toContain("sqli");
  });

  it("finds command injection modules for CWE-78", () => {
    const modules = findMsfModules(78);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules[0]).toContain("oscommand");
  });

  it("finds path traversal modules for CWE-22", () => {
    const modules = findMsfModules(22);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules.some(m => m.includes("lfi") || m.includes("traversal"))).toBe(true);
  });

  it("finds XXE modules for CWE-611", () => {
    const modules = findMsfModules(611);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules.some(m => m.includes("xxe"))).toBe(true);
  });

  it("finds file upload modules for CWE-434", () => {
    const modules = findMsfModules(434);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules.some(m => m.includes("upload"))).toBe(true);
  });

  it("finds deserialization modules for CWE-502", () => {
    const modules = findMsfModules(502);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules.some(m => m.includes("deserialization") || m.includes("rmi"))).toBe(true);
  });

  it("finds SSRF modules for CWE-918", () => {
    const modules = findMsfModules(918);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules[0]).toContain("ssrf");
  });

  it("finds LDAP injection modules for CWE-90", () => {
    const modules = findMsfModules(90);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules[0]).toContain("ldap");
  });

  it("finds RFI modules for CWE-98", () => {
    const modules = findMsfModules(98);
    expect(modules.length).toBeGreaterThan(0);
    expect(modules.some(m => m.includes("rfi") || m.includes("include"))).toBe(true);
  });

  it("returns empty array for null CWE", () => {
    const modules = findMsfModules(null);
    expect(modules).toEqual([]);
  });

  it("returns empty array for unmapped CWE", () => {
    const modules = findMsfModules(99999);
    expect(modules).toEqual([]);
  });

  it("returns empty array for XSS CWE-79 (no direct exploit module)", () => {
    const modules = findMsfModules(79);
    expect(modules).toEqual([]);
  });
});
