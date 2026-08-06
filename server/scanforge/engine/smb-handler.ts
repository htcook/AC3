/**
 * ScanForge SMB/CIFS Protocol Handler
 * 
 * Inspired by OpenVAS nasl_smb.c — provides Windows network scanning
 * capabilities via the scan-server-executor SSH bridge.
 * 
 * Features:
 * - SMB share enumeration (null session + authenticated)
 * - NetBIOS name resolution
 * - SMB signing detection
 * - SMB version detection (SMBv1/v2/v3)
 * - Anonymous access detection
 * - Common share permission checks
 * - Windows OS version fingerprinting via SMB
 * - Populates KB with SMB-specific findings
 * 
 * Implementation: Generates shell commands executed on the scan server
 * via SSH, using smbclient, rpcclient, enum4linux, crackmapexec, etc.
 */

import { ScanForgeKB, KB_KEYS } from "./knowledge-base";

export interface SMBScanConfig {
  host: string;
  port?: number;          // Default 445
  username?: string;       // For authenticated scans
  password?: string;
  domain?: string;
  timeout?: number;        // Seconds
}

export interface SMBShareInfo {
  name: string;
  type: string;            // DISK, IPC, PRINTER
  comment: string;
  readable: boolean;
  writable: boolean;
  anonymousAccess: boolean;
}

export interface SMBHostInfo {
  host: string;
  port: number;
  smbVersion: string[];    // ["1", "2", "3"]
  signing: "required" | "enabled" | "disabled";
  os?: string;
  domain?: string;
  hostname?: string;
  shares: SMBShareInfo[];
  nullSession: boolean;
  guestAccess: boolean;
}

export interface SMBVuln {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  remediation: string;
  cve?: string[];
  evidence: string;
}

/**
 * SMB Protocol Handler
 * Generates scan commands for execution on the scan server
 */
export class SMBHandler {
  
  /**
   * Generate all SMB enumeration commands for a host
   * Returns commands to be executed via scan-server-executor
   */
  buildScanCommands(config: SMBScanConfig): Array<{
    id: string;
    command: string;
    parser: string;  // Parser function name to process output
    timeout: number;
  }> {
    const host = config.host;
    const port = config.port || 445;
    const timeout = config.timeout || 30;
    const creds = config.username 
      ? `-U '${config.domain ? config.domain + "\\\\" : ""}${config.username}%${config.password || ""}'`
      : "-N"; // Null session
    
    return [
      // 1. SMB Version Detection
      {
        id: "smb-version",
        command: `timeout ${timeout} scanforge-discovery -p ${port} --script smb-protocols ${host} 2>/dev/null || echo "TIMEOUT"`,
        parser: "parseSMBVersion",
        timeout,
      },
      
      // 2. SMB Signing Detection
      {
        id: "smb-signing",
        command: `timeout ${timeout} scanforge-discovery -p ${port} --script smb-security-mode ${host} 2>/dev/null || echo "TIMEOUT"`,
        parser: "parseSMBSigning",
        timeout,
      },
      
      // 3. Share Enumeration (null session)
      {
        id: "smb-shares-null",
        command: `timeout ${timeout} smbclient -L //${host} -N -p ${port} 2>/dev/null || echo "DENIED"`,
        parser: "parseSMBShares",
        timeout,
      },
      
      // 4. Share Enumeration (authenticated if creds provided)
      ...(config.username ? [{
        id: "smb-shares-auth",
        command: `timeout ${timeout} smbclient -L //${host} ${creds} -p ${port} 2>/dev/null || echo "DENIED"`,
        parser: "parseSMBShares" as const,
        timeout,
      }] : []),
      
      // 5. NetBIOS Name Resolution
      {
        id: "smb-netbios",
        command: `timeout ${timeout} nmblookup -A ${host} 2>/dev/null || echo "TIMEOUT"`,
        parser: "parseNetBIOS",
        timeout,
      },
      
      // 6. OS Detection via SMB
      {
        id: "smb-os",
        command: `timeout ${timeout} scanforge-discovery -p ${port} --script smb-os-discovery ${host} 2>/dev/null || echo "TIMEOUT"`,
        parser: "parseSMBOS",
        timeout,
      },
      
      // 7. Enum4linux comprehensive enumeration
      {
        id: "smb-enum4linux",
        command: `timeout ${timeout * 2} enum4linux -a ${host} 2>/dev/null | head -200 || echo "TIMEOUT"`,
        parser: "parseEnum4linux",
        timeout: timeout * 2,
      },
      
      // 8. SMBv1 (EternalBlue) check
      {
        id: "smb-vuln-ms17-010",
        command: `timeout ${timeout} scanforge-discovery -p ${port} --script smb-vuln-ms17-010 ${host} 2>/dev/null || echo "TIMEOUT"`,
        parser: "parseSMBVuln",
        timeout,
      },
      
      // 9. Anonymous share access test
      {
        id: "smb-anon-access",
        command: `for share in IPC$ ADMIN$ C$ NETLOGON SYSVOL; do echo "=== $share ==="; timeout 5 smbclient //${host}/$share -N -p ${port} -c "ls" 2>&1 | head -5; done`,
        parser: "parseAnonAccess",
        timeout: timeout * 2,
      },
      
      // 10. Guest access test
      {
        id: "smb-guest-access",
        command: `timeout ${timeout} smbclient -L //${host} -U 'guest%' -p ${port} 2>/dev/null || echo "DENIED"`,
        parser: "parseSMBShares",
        timeout,
      },
    ];
  }
  
  // ─── Output Parsers ────────────────────────────────────────────
  
  parseSMBVersion(output: string): string[] {
    const versions: string[] = [];
    if (/SMBv1/i.test(output) || /dialects.*NT LM/i.test(output)) versions.push("1");
    if (/SMBv2/i.test(output) || /2\.0\.2|2\.1/i.test(output)) versions.push("2");
    if (/SMBv3/i.test(output) || /3\.0|3\.1\.1/i.test(output)) versions.push("3");
    return versions;
  }
  
  parseSMBSigning(output: string): "required" | "enabled" | "disabled" {
    if (/message_signing:\s*required/i.test(output)) return "required";
    if (/message_signing:\s*enabled/i.test(output) || /signing.*enabled/i.test(output)) return "enabled";
    return "disabled";
  }
  
  parseSMBShares(output: string): SMBShareInfo[] {
    const shares: SMBShareInfo[] = [];
    const lines = output.split("\n");
    
    for (const line of lines) {
      // Match smbclient share listing format: "ShareName    Disk    Comment"
      const match = line.match(/^\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)/i);
      if (match) {
        shares.push({
          name: match[1],
          type: match[2].toUpperCase(),
          comment: match[3]?.trim() || "",
          readable: false,  // Will be tested separately
          writable: false,
          anonymousAccess: output.includes("-N") || !output.includes("DENIED"),
        });
      }
    }
    
    return shares;
  }
  
  parseNetBIOS(output: string): { hostname?: string; domain?: string; mac?: string } {
    const result: { hostname?: string; domain?: string; mac?: string } = {};
    
    const hostnameMatch = output.match(/(\S+)\s+<00>\s+-\s+.*<ACTIVE>/i);
    if (hostnameMatch) result.hostname = hostnameMatch[1];
    
    const domainMatch = output.match(/(\S+)\s+<1e>\s+-\s+<GROUP>/i);
    if (domainMatch) result.domain = domainMatch[1];
    
    const macMatch = output.match(/MAC Address = ([0-9A-F:-]+)/i);
    if (macMatch) result.mac = macMatch[1];
    
    return result;
  }
  
  parseSMBOS(output: string): { os?: string; domain?: string; hostname?: string } {
    const result: { os?: string; domain?: string; hostname?: string } = {};
    
    const osMatch = output.match(/OS:\s*(.+)/i);
    if (osMatch) result.os = osMatch[1].trim();
    
    const domainMatch = output.match(/Domain name:\s*(.+)/i) || output.match(/Workgroup:\s*(.+)/i);
    if (domainMatch) result.domain = domainMatch[1].trim();
    
    const hostMatch = output.match(/Computer name:\s*(.+)/i);
    if (hostMatch) result.hostname = hostMatch[1].trim();
    
    return result;
  }
  
  parseAnonAccess(output: string): Array<{ share: string; accessible: boolean }> {
    const results: Array<{ share: string; accessible: boolean }> = [];
    const sections = output.split("===").filter(s => s.trim());
    
    for (let i = 0; i < sections.length; i += 2) {
      const share = sections[i]?.trim();
      const response = sections[i + 1] || "";
      if (share) {
        results.push({
          share,
          accessible: !response.includes("NT_STATUS_ACCESS_DENIED") && 
                       !response.includes("NT_STATUS_LOGON_FAILURE") &&
                       !response.includes("DENIED"),
        });
      }
    }
    
    return results;
  }
  
  // ─── Vulnerability Detection ───────────────────────────────────
  
  detectVulnerabilities(hostInfo: SMBHostInfo): SMBVuln[] {
    const vulns: SMBVuln[] = [];
    
    // SMBv1 enabled (EternalBlue risk)
    if (hostInfo.smbVersion.includes("1")) {
      vulns.push({
        id: "smb-v1-enabled",
        title: "SMBv1 Protocol Enabled",
        severity: "high",
        description: "SMBv1 is enabled on this host. SMBv1 is vulnerable to multiple critical exploits including EternalBlue (MS17-010), EternalRomance, and EternalSynergy.",
        remediation: "Disable SMBv1 protocol. On Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false. On Linux: add 'min protocol = SMB2' to smb.conf.",
        cve: ["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0143"],
        evidence: `SMBv1 detected on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // SMB signing not required
    if (hostInfo.signing === "disabled" || hostInfo.signing === "enabled") {
      vulns.push({
        id: "smb-signing-not-required",
        title: "SMB Signing Not Required",
        severity: hostInfo.signing === "disabled" ? "high" : "medium",
        description: `SMB message signing is ${hostInfo.signing} but not required. This allows man-in-the-middle attacks and SMB relay attacks.`,
        remediation: "Enable and require SMB signing. On Windows: Set RequireSecuritySignature to 1 in Group Policy. On Linux: add 'server signing = mandatory' to smb.conf.",
        evidence: `SMB signing: ${hostInfo.signing} on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // Null session access
    if (hostInfo.nullSession) {
      vulns.push({
        id: "smb-null-session",
        title: "SMB Null Session Allowed",
        severity: "medium",
        description: "The SMB server allows null session connections (anonymous access without credentials). This can leak user lists, share names, and other sensitive information.",
        remediation: "Disable null session access. On Windows: Set RestrictAnonymous and RestrictAnonymousSAM to 1 in the registry.",
        evidence: `Null session successful on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // Guest access
    if (hostInfo.guestAccess) {
      vulns.push({
        id: "smb-guest-access",
        title: "SMB Guest Access Allowed",
        severity: "medium",
        description: "The SMB server allows guest account access. This can provide unauthorized access to shared resources.",
        remediation: "Disable guest access to SMB shares. On Windows: Disable the Guest account and remove it from share permissions.",
        evidence: `Guest access successful on ${hostInfo.host}:${hostInfo.port}`,
      });
    }
    
    // Writable shares
    for (const share of hostInfo.shares) {
      if (share.writable && share.anonymousAccess) {
        vulns.push({
          id: `smb-writable-share-${share.name}`,
          title: `Anonymous Writable SMB Share: ${share.name}`,
          severity: "critical",
          description: `The SMB share '${share.name}' is writable with anonymous access. This could be used to upload malware, ransomware, or establish persistence.`,
          remediation: `Remove anonymous write access from the '${share.name}' share. Review and restrict share permissions.`,
          evidence: `Share '${share.name}' is writable anonymously on ${hostInfo.host}:${hostInfo.port}`,
        });
      }
    }
    
    // Default admin shares accessible
    const adminShares = hostInfo.shares.filter(s => 
      ["ADMIN$", "C$", "D$", "IPC$"].includes(s.name) && s.anonymousAccess
    );
    if (adminShares.length > 0) {
      vulns.push({
        id: "smb-admin-shares-exposed",
        title: "Administrative SMB Shares Accessible",
        severity: "high",
        description: `Administrative shares (${adminShares.map(s => s.name).join(", ")}) are accessible. This indicates weak access controls on the Windows system.`,
        remediation: "Restrict access to administrative shares. Consider disabling default admin shares if not needed.",
        evidence: `Admin shares accessible on ${hostInfo.host}:${hostInfo.port}: ${adminShares.map(s => s.name).join(", ")}`,
      });
    }
    
    return vulns;
  }
  
  // ─── KB Population ─────────────────────────────────────────────
  
  populateKB(kb: ScanForgeKB, hostInfo: SMBHostInfo): void {
    const source = "smb-handler";
    const host = hostInfo.host;
    const port = hostInfo.port;
    
    kb.set(KB_KEYS.PORT_SERVICE(port, "tcp"), "smb", source, { host, confidence: 1.0 });
    
    if (hostInfo.os) {
      kb.set(KB_KEYS.SERVICE_SMB_OS(port), hostInfo.os, source, { host, confidence: 0.8 });
      kb.set(KB_KEYS.HOST_OS, hostInfo.os, source, { host, confidence: 0.7 });
    }
    
    if (hostInfo.shares.length > 0) {
      kb.set(
        KB_KEYS.SERVICE_SMB_SHARES(port),
        hostInfo.shares.map(s => s.name),
        source,
        { host, confidence: 1.0 }
      );
    }
    
    if (hostInfo.hostname) {
      kb.set(KB_KEYS.HOST_FQDN, hostInfo.hostname, source, { host, confidence: 0.8 });
    }
  }
}
