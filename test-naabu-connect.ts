import { executeTool, executeRawCommand } from './server/lib/scan-server-executor';

async function test() {
  // Test 1: Check if sudo works at all
  console.log('=== Test 1: Check sudo access ===');
  const sudo = await executeRawCommand('sudo whoami 2>&1', 10);
  console.log('sudo whoami:', sudo.stdout.trim(), 'exit:', sudo.exitCode);
  
  // Test 2: naabu with connect scan mode (no root needed)
  console.log('\n=== Test 2: naabu -s connect (no root needed) ===');
  const r2 = await executeTool({ 
    tool: 'naabu', 
    args: '-host scanme.nmap.org -top-ports 100 -json -silent -s connect', 
    timeoutSeconds: 60 
  });
  console.log('Exit:', r2.exitCode, 'Timed out:', r2.timedOut, 'Duration:', r2.durationMs + 'ms');
  console.log('Output:', r2.stdout.slice(0, 500));
  if (r2.stderr) console.log('Stderr:', r2.stderr.slice(0, 300));
  
  // Parse ports
  const ports: number[] = [];
  for (const line of r2.stdout.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t);
      if (obj.port) ports.push(obj.port);
    } catch {
      const m = t.match(/:(\d+)$/);
      if (m) ports.push(parseInt(m[1]));
    }
  }
  console.log('Ports found:', ports);
}

test().catch(console.error);
