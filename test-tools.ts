import { executeTool, executeRawCommand } from './server/lib/scan-server-executor';

async function test() {
  // === Test 1: httpx availability and basic scan ===
  console.log('=== Test 1: httpx version ===');
  const hv = await executeRawCommand('httpx -version 2>&1', 10);
  console.log(hv.stdout.trim());
  console.log('Exit:', hv.exitCode);

  console.log('\n=== Test 2: httpx scan on scanme.nmap.org ===');
  const h = await executeTool({
    tool: 'bash',
    args: `-c "echo 'http://scanme.nmap.org:80' | httpx -json -tech-detect -status-code -title -web-server -silent 2>/dev/null"`,
    timeoutSeconds: 30
  });
  console.log('Exit:', h.exitCode, 'Timed out:', h.timedOut, 'Duration:', h.durationMs + 'ms');
  console.log('Output:', h.stdout.slice(0, 1000));
  if (h.stderr) console.log('Stderr:', h.stderr.slice(0, 300));

  // === Test 3: nuclei availability ===
  console.log('\n=== Test 3: nuclei version ===');
  const nv = await executeRawCommand('nuclei -version 2>&1', 10);
  console.log(nv.stdout.trim());
  console.log('Exit:', nv.exitCode);

  // === Test 4: nuclei templates check ===
  console.log('\n=== Test 4: nuclei templates ===');
  const nt = await executeRawCommand('nuclei -tl 2>&1 | wc -l', 15);
  console.log('Template count:', nt.stdout.trim());

  // === Test 5: nuclei scan on scanme.nmap.org (quick, limited templates) ===
  console.log('\n=== Test 5: nuclei scan (quick) ===');
  const ns = await executeTool({
    tool: 'nuclei',
    args: '-u http://scanme.nmap.org -t http/technologies/ -json -silent -timeout 10 -retries 1 -bulk-size 5 -rate-limit 10',
    timeoutSeconds: 60
  });
  console.log('Exit:', ns.exitCode, 'Timed out:', ns.timedOut, 'Duration:', ns.durationMs + 'ms');
  console.log('Output:', ns.stdout.slice(0, 1500));
  if (ns.stderr) console.log('Stderr:', ns.stderr.slice(0, 300));

  // === Test 6: Check all available tools ===
  console.log('\n=== Test 6: Available tools ===');
  const tools = ['nmap', 'httpx', 'nuclei', 'nikto', 'gobuster', 'subfinder', 'dig', 'whois'];
  for (const tool of tools) {
    const r = await executeRawCommand(`which ${tool} 2>&1`, 5);
    console.log(`${tool}: ${r.stdout.trim() || 'NOT FOUND'}`);
  }
}

test().catch(console.error);
