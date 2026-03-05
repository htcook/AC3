// Test SSH via the actual app code path (getScanServerConfig + executeTool)
import 'dotenv/config';

// Import the actual scan server executor
const { executeTool, checkScanServerStatus } = await import('./server/lib/scan-server-executor.ts');

console.log('=== Testing SSH via app code path ===');

// Test 1: Check scan server status
console.log('\n--- Test 1: checkScanServerStatus ---');
try {
  const status = await checkScanServerStatus();
  console.log('Connected:', status.connected);
  console.log('Uptime:', status.uptime);
  console.log('Disk Free:', status.diskFree);
  console.log('Memory Free:', status.memoryFree);
  if (status.error) console.log('Error:', status.error);
  console.log('Tools installed:', Object.entries(status.tools || {}).filter(([, v]) => v.installed).map(([k]) => k).join(', '));
} catch (e) {
  console.log('Status check failed:', e.message);
}

// Test 2: Run a simple command
console.log('\n--- Test 2: executeTool (whoami) ---');
try {
  const result = await executeTool({
    tool: 'bash',
    args: '-c "whoami && uname -a"',
    timeoutSeconds: 15,
  });
  console.log('Exit code:', result.exitCode);
  console.log('Stdout:', result.stdout.trim());
  console.log('Stderr:', result.stderr?.trim() || '(none)');
  console.log('Duration:', result.durationMs + 'ms');
  if (result.error) console.log('Error:', result.error);
} catch (e) {
  console.log('executeTool failed:', e.message);
}

// Test 3: Run nmap version check
console.log('\n--- Test 3: executeTool (nmap --version) ---');
try {
  const result = await executeTool({
    tool: 'nmap',
    args: '--version',
    timeoutSeconds: 15,
  });
  console.log('Exit code:', result.exitCode);
  console.log('Stdout (first 200):', result.stdout.substring(0, 200).trim());
  if (result.error) console.log('Error:', result.error);
} catch (e) {
  console.log('nmap check failed:', e.message);
}

process.exit(0);
