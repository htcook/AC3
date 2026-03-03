import { executeRawCommand } from './server/lib/scan-server-executor';

async function test() {
  // Test 1: naabu version
  console.log('=== naabu version ===');
  const v = await executeRawCommand('naabu -version 2>&1', 10);
  console.log(v.stdout.trim());
  
  // Test 2: naabu help to check available flags
  console.log('\n=== naabu flags check ===');
  const h = await executeRawCommand('naabu -h 2>&1 | grep -E "silent|json|connect|host" | head -10', 10);
  console.log(h.stdout.trim());
  
  // Test 3: Simple naabu scan with timeout and explicit output
  console.log('\n=== naabu scan (timeout 30s, bash wrapper) ===');
  const r = await executeRawCommand(
    'timeout 25 naabu -host scanme.nmap.org -p 22,80,443 -json -silent 2>&1; echo "EXIT_CODE=$?"',
    30
  );
  console.log('Output:', r.stdout.slice(0, 500));
  console.log('Exit:', r.exitCode);
  
  // Test 4: naabu with just a few ports, no json
  console.log('\n=== naabu scan (simple, no json) ===');
  const r2 = await executeRawCommand(
    'timeout 25 naabu -host scanme.nmap.org -p 22,80,443 2>&1; echo "EXIT_CODE=$?"',
    30
  );
  console.log('Output:', r2.stdout.slice(0, 500));
  console.log('Exit:', r2.exitCode);
}

test().catch(console.error);
