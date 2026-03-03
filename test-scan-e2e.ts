import { executeTool } from './server/lib/scan-server-executor';

async function test() {
  // Test 1: naabu quick scan
  console.log('=== Test 1: naabu port scan on scanme.nmap.org ===');
  const naabu = await executeTool({ tool: 'naabu', args: '-host scanme.nmap.org -top-ports 100 -json -silent', timeoutSeconds: 30 });
  console.log('Exit code:', naabu.exitCode);
  console.log('Output:', naabu.stdout.slice(0, 500));
  console.log('Timed out:', naabu.timedOut);
  console.log('Duration:', naabu.durationMs, 'ms');
  
  // Parse ports
  const ports: number[] = [];
  for (const line of naabu.stdout.split('\n')) {
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
  
  // Test 2: nmap on discovered ports
  if (ports.length > 0) {
    console.log('\n=== Test 2: nmap fingerprint on naabu ports ===');
    const portList = ports.join(',');
    const nmap = await executeTool({ tool: 'nmap', args: `-Pn -sV -sC -p ${portList} scanme.nmap.org`, timeoutSeconds: 60 });
    console.log('Exit code:', nmap.exitCode);
    console.log('Output:', nmap.stdout.slice(0, 800));
    console.log('Duration:', nmap.durationMs, 'ms');
  } else {
    console.log('\nNo ports found by naabu - testing nmap with --top-ports 100 fallback');
    const nmap = await executeTool({ tool: 'nmap', args: '-Pn -sV -sC --top-ports 100 scanme.nmap.org', timeoutSeconds: 60 });
    console.log('Exit code:', nmap.exitCode);
    console.log('Output:', nmap.stdout.slice(0, 800));
    console.log('Duration:', nmap.durationMs, 'ms');
  }
}

test().catch(console.error);
