// Quick diagnostic: test scan server connectivity
import { checkScanServerStatus, executeTool } from './server/lib/scan-server-executor';

async function main() {
  console.log('=== Testing Scan Server Connectivity ===\n');
  
  try {
    console.log('1. Checking server status...');
    const status = await checkScanServerStatus();
    console.log('Connected:', status.connected);
    if (status.error) console.log('Error:', status.error);
    if (status.uptime) console.log('Uptime:', status.uptime);
    if (status.diskFree) console.log('Disk Free:', status.diskFree);
    if (status.memoryFree) console.log('Memory Free:', status.memoryFree);
    console.log('Tools:', JSON.stringify(status.tools, null, 2));
  } catch (e: any) {
    console.error('Status check failed:', e.message);
  }

  try {
    console.log('\n2. Testing nmap execution...');
    const result = await executeTool({ tool: 'nmap', args: '--version', timeoutSeconds: 15 });
    console.log('nmap version output:', result.stdout.slice(0, 200));
    console.log('Exit code:', result.exitCode);
    console.log('Error:', result.error || 'none');
  } catch (e: any) {
    console.error('nmap test failed:', e.message);
  }

  try {
    console.log('\n3. Testing naabu...');
    const result = await executeTool({ tool: 'naabu', args: '-version', timeoutSeconds: 15 });
    console.log('naabu output:', result.stdout.slice(0, 200));
    console.log('Exit code:', result.exitCode);
    console.log('Error:', result.error || 'none');
  } catch (e: any) {
    console.error('naabu test failed:', e.message);
  }

  try {
    console.log('\n4. Quick nmap scan test (scanme.nmap.org, port 80 only)...');
    const result = await executeTool({ tool: 'nmap', args: '-Pn -p 80 --open scanme.nmap.org', timeoutSeconds: 30 });
    console.log('nmap output:', result.stdout.slice(0, 500));
    console.log('Exit code:', result.exitCode);
    console.log('Duration:', result.durationMs, 'ms');
    console.log('Timed out:', result.timedOut);
    console.log('Error:', result.error || 'none');
  } catch (e: any) {
    console.error('nmap scan test failed:', e.message);
  }
}

main().catch(console.error);
