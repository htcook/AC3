import http from 'http';

const engId = 1350014;
const url = `http://localhost:3000/api/trpc/engagementOps.getState?input=${encodeURIComponent(JSON.stringify({ engagementId: engId }))}`;

http.get(url, (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    try {
      const parsed = JSON.parse(data);
      const state = parsed?.result?.data?.json;
      if (!state) {
        console.log('No state found - checking raw response:');
        console.log(data.slice(0, 500));
        return;
      }
      console.log('Phase:', state.phase);
      console.log('vulnsFound:', state.stats?.vulnsFound);
      console.log('Assets:', state.assets?.length);
      for (const a of (state.assets || [])) {
        console.log(`  Asset: ${a.hostname} | vulns: ${(a.vulns || []).length} | toolResults: ${(a.toolResults || []).length} | status: ${a.status}`);
        if ((a.vulns || []).length > 0) {
          for (const v of a.vulns.slice(0, 5)) {
            console.log(`    - [${v.severity}] ${v.title} ${v.cve || ''}`);
          }
          if (a.vulns.length > 5) console.log(`    ... and ${a.vulns.length - 5} more`);
        }
      }
      // Check log for nuclei entries
      const nucleiLogs = (state.log || []).filter(l => l.title?.includes('Nuclei'));
      console.log('\nNuclei log entries:', nucleiLogs.length);
      for (const l of nucleiLogs) {
        console.log(`  [${l.type}] ${l.title}: ${l.detail}`);
      }
    } catch (e) {
      console.error('Parse error:', e.message);
      console.log('Raw:', data.slice(0, 500));
    }
  });
}).on('error', e => console.error(e.message));
