/**
 * End-to-End Pipeline Test: testphp.vulnweb.com
 * 
 * This script tests the full scan pipeline against Acunetix's intentionally
 * vulnerable web application. Known vulnerabilities include:
 * - SQL Injection (multiple endpoints)
 * - Cross-Site Scripting (XSS)
 * - File Inclusion (LFI/RFI)
 * - CRLF Injection
 * - Server-Side Request Forgery
 * - Directory Traversal
 * - Weak Authentication
 * - Information Disclosure
 */

import jwt from 'jsonwebtoken';

const BASE = 'http://localhost:3000';
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';
const TARGET = 'testphp.vulnweb.com';

// Known vulns in testphp.vulnweb.com that a good scanner should find
const EXPECTED_VULNS = [
  { category: 'sql_injection', description: 'SQL Injection in search, login, or artist parameters' },
  { category: 'xss', description: 'Cross-Site Scripting in various input fields' },
  { category: 'directory_listing', description: 'Directory listing enabled' },
  { category: 'info_disclosure', description: 'Server version disclosure, error messages' },
  { category: 'weak_auth', description: 'Default or weak credentials' },
  { category: 'file_inclusion', description: 'Local/Remote File Inclusion' },
  { category: 'crlf_injection', description: 'CRLF injection in headers' },
  { category: 'open_ports', description: 'HTTP (80) and possibly other services' },
];

const token = jwt.sign(
  { username: 'admin', role: 'admin', loginTime: Date.now() },
  CALDERA_JWT_SECRET,
  { expiresIn: '2h' }
);

const headers = {
  'Content-Type': 'application/json',
  'Cookie': `caldera_session=${token}`,
};

async function query(proc, input) {
  const url = input !== undefined
    ? `${BASE}/api/trpc/${proc}?input=${encodeURIComponent(JSON.stringify({ json: input }))}`
    : `${BASE}/api/trpc/${proc}`;
  const res = await fetch(url, { headers });
  const data = await res.json();
  if (data.error) throw new Error(`${proc}: ${JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

async function mutate(proc, input) {
  const res = await fetch(`${BASE}/api/trpc/${proc}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ json: input }),
  });
  const data = await res.json();
  if (data.error) throw new Error(`${proc}: ${JSON.stringify(data.error)}`);
  return data.result?.data?.json ?? data.result?.data;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function log(emoji, msg) { console.log(`${emoji} [${new Date().toISOString().slice(11, 19)}] ${msg}`); }

// ─── Step 1: Check scan server health ───────────────────────────────────────
async function checkScanServer() {
  log('🔧', 'Checking scan server connectivity...');
  try {
    const health = await query('scanServer.health');
    log('✅', `Scan server: ${health.status} (${health.host})`);
    if (health.tools) {
      log('🛠️', `Available tools: ${Object.entries(health.tools).filter(([,v]) => v).map(([k]) => k).join(', ')}`);
    }
    return health.status === 'online';
  } catch (e) {
    log('❌', `Scan server check failed: ${e.message}`);
    return false;
  }
}

// ─── Step 2: Find or create engagement for testphp.vulnweb.com ─────────────
async function getOrCreateEngagement() {
  log('📋', `Looking for existing engagement with target ${TARGET}...`);
  
  // Check the Vianova engagement (ID 1350014) which includes testphp.vulnweb.com
  try {
    const state = await query('engagementOps.getState', { engagementId: 1350014 });
    if (state) {
      log('✅', `Found Vianova engagement #1350014 with ${state.assets?.length || 0} assets`);
      // Check if testphp.vulnweb.com is in the assets
      const hasTarget = state.assets?.some(a => a.hostname?.includes('vulnweb'));
      if (hasTarget) {
        log('✅', `Target ${TARGET} is in the engagement assets`);
      }
      return { engagementId: 1350014, state };
    }
  } catch (e) {
    log('⚠️', `Vianova engagement not found: ${e.message}`);
  }
  
  return null;
}

// ─── Step 3: Start passive scan ─────────────────────────────────────────────
async function startPassiveScan(engagementId) {
  log('🔍', `Starting passive scan for engagement #${engagementId}...`);
  try {
    const result = await mutate('engagementOps.startPassiveScan', { engagementId });
    log('✅', `Passive scan started: ${JSON.stringify(result).slice(0, 200)}`);
    return true;
  } catch (e) {
    if (e.message.includes('already running') || e.message.includes('already active')) {
      log('⚠️', `Scan already running, continuing...`);
      return true;
    }
    log('❌', `Passive scan failed: ${e.message}`);
    return false;
  }
}

// ─── Step 4: Start active scan ──────────────────────────────────────────────
async function startActiveScan(engagementId) {
  log('🎯', `Starting active scan for engagement #${engagementId}...`);
  try {
    const result = await mutate('engagementOps.startActiveScan', { engagementId });
    log('✅', `Active scan started: ${JSON.stringify(result).slice(0, 200)}`);
    return true;
  } catch (e) {
    if (e.message.includes('already running') || e.message.includes('already active')) {
      log('⚠️', `Active scan already running, continuing...`);
      return true;
    }
    log('❌', `Active scan failed: ${e.message}`);
    return false;
  }
}

// ─── Step 5: Poll state until scans complete ────────────────────────────────
async function pollUntilPhase(engagementId, targetPhases, maxWaitMs = 600000) {
  const startTime = Date.now();
  let lastPhase = '';
  let lastProgress = 0;
  let lastVulns = 0;
  let lastPorts = 0;
  
  while (Date.now() - startTime < maxWaitMs) {
    try {
      const state = await query('engagementOps.getState', { engagementId });
      if (!state) {
        log('⚠️', 'State is null, waiting...');
        await sleep(10000);
        continue;
      }
      
      const phase = state.phase || 'unknown';
      const progress = state.progress || 0;
      const vulns = state.stats?.vulnsFound || 0;
      const ports = state.stats?.portsFound || 0;
      const hosts = state.stats?.hostsScanned || 0;
      
      if (phase !== lastPhase || progress !== lastProgress || vulns !== lastVulns || ports !== lastPorts) {
        log('📊', `Phase: ${phase} | Progress: ${progress}% | Hosts: ${hosts} | Ports: ${ports} | Vulns: ${vulns}`);
        
        // Log recent log entries
        const recentLogs = (state.log || []).slice(-3);
        for (const l of recentLogs) {
          if (l.title && !l.title.includes('heartbeat')) {
            log('  📝', `${l.title}`);
          }
        }
        
        lastPhase = phase;
        lastProgress = progress;
        lastVulns = vulns;
        lastPorts = ports;
      }
      
      if (targetPhases.includes(phase) || phase === 'complete' || phase === 'error' || phase === 'idle') {
        log('✅', `Reached target phase: ${phase}`);
        return state;
      }
      
      // If not running and not in target phase, it might have stopped
      if (!state.isRunning && phase !== 'idle' && progress > 0) {
        log('⚠️', `Pipeline stopped at phase ${phase} (${progress}%)`);
        return state;
      }
    } catch (e) {
      log('⚠️', `Poll error: ${e.message}`);
    }
    
    await sleep(15000);
  }
  
  log('⏰', `Timeout waiting for phase ${targetPhases.join('/')}`);
  return null;
}

// ─── Step 6: Run LLM vulnerability analysis ────────────────────────────────
async function runLLMAnalysis(engagementId) {
  log('🧠', `Running LLM vulnerability analysis for engagement #${engagementId}...`);
  try {
    const result = await mutate('engagementOps.runVulnAnalysis', { engagementId });
    log('✅', `LLM analysis result: ${JSON.stringify(result).slice(0, 300)}`);
    return result;
  } catch (e) {
    log('❌', `LLM analysis failed: ${e.message}`);
    return null;
  }
}

// ─── Step 7: Generate functional exploits ───────────────────────────────────
async function generateExploits(engagementId) {
  log('💥', `Generating functional exploits for engagement #${engagementId}...`);
  try {
    const result = await mutate('engagementOps.generateFunctionalExploit', { engagementId });
    log('✅', `Exploit generation result: ${JSON.stringify(result).slice(0, 500)}`);
    return result;
  } catch (e) {
    log('❌', `Exploit generation failed: ${e.message}`);
    return null;
  }
}

// ─── Step 8: Get generated exploits ─────────────────────────────────────────
async function getExploits(engagementId) {
  log('📋', `Getting generated exploits for engagement #${engagementId}...`);
  try {
    const exploits = await query('engagementOps.getGeneratedExploits', { engagementId });
    log('✅', `Found ${exploits?.length || 0} generated exploits`);
    return exploits || [];
  } catch (e) {
    log('❌', `Get exploits failed: ${e.message}`);
    return [];
  }
}

// ─── Step 9: Validate results against expected vulns ────────────────────────
function validateResults(state, exploits) {
  log('📊', '═══════════════════════════════════════════════════════════');
  log('📊', '         PIPELINE VALIDATION RESULTS');
  log('📊', '═══════════════════════════════════════════════════════════');
  
  const assets = state?.assets || [];
  const allVulns = assets.flatMap(a => a.vulns || []);
  const allPorts = assets.flatMap(a => a.ports || []);
  const allToolResults = assets.flatMap(a => a.toolResults || []);
  
  log('📊', `Total assets: ${assets.length}`);
  log('📊', `Total ports found: ${allPorts.length}`);
  log('📊', `Total vulns found: ${allVulns.length}`);
  log('📊', `Total tool results: ${allToolResults.length}`);
  log('📊', `Generated exploits: ${exploits.length}`);
  
  // List all found vulns
  if (allVulns.length > 0) {
    log('🔥', '\nVulnerabilities Found:');
    for (const v of allVulns) {
      log('  🔴', `[${v.severity?.toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ''}`);
    }
  }
  
  // List all ports
  if (allPorts.length > 0) {
    log('🔌', '\nOpen Ports:');
    for (const p of allPorts) {
      log('  📡', `${p.port}/${p.service || 'unknown'}${p.version ? ` (${p.version})` : ''}`);
    }
  }
  
  // List tool results
  if (allToolResults.length > 0) {
    log('🛠️', '\nTool Results:');
    for (const tr of allToolResults) {
      log('  🔧', `${tr.tool}: ${tr.findingCount || 0} findings (exit: ${tr.exitCode}, ${tr.durationMs ? Math.round(tr.durationMs / 1000) + 's' : 'N/A'})`);
    }
  }
  
  // List exploits
  if (exploits.length > 0) {
    log('💥', '\nGenerated Exploits:');
    for (const ex of exploits) {
      log('  ⚡', `${ex.title || ex.vulnTitle || 'Unnamed'} (${ex.language || 'unknown'}) - ${ex.validated ? 'Validated' : 'Unvalidated'}`);
    }
  }
  
  // Check against expected vulns
  log('📊', '\n═══════════════════════════════════════════════════════════');
  log('📊', '         EXPECTED VULNERABILITY COVERAGE');
  log('📊', '═══════════════════════════════════════════════════════════');
  
  let found = 0;
  let missed = 0;
  const vulnText = allVulns.map(v => `${v.title} ${v.cve || ''}`).join(' ').toLowerCase();
  const toolText = allToolResults.map(tr => `${tr.outputPreview || ''} ${(tr.findings || []).map(f => f.title).join(' ')}`).join(' ').toLowerCase();
  const combinedText = `${vulnText} ${toolText}`;
  
  for (const expected of EXPECTED_VULNS) {
    const keywords = {
      sql_injection: ['sql injection', 'sqli', 'sql', 'blind sql'],
      xss: ['xss', 'cross-site scripting', 'cross site scripting', 'script injection'],
      directory_listing: ['directory listing', 'directory indexing', 'index of', 'dir listing'],
      info_disclosure: ['information disclosure', 'server version', 'version disclosure', 'error message', 'stack trace', 'phpinfo'],
      weak_auth: ['weak auth', 'default credential', 'brute force', 'login', 'authentication'],
      file_inclusion: ['file inclusion', 'lfi', 'rfi', 'path traversal', 'directory traversal', 'traversal'],
      crlf_injection: ['crlf', 'header injection', 'http response splitting'],
      open_ports: ['80/tcp', 'http', 'open port', '80/http'],
    };
    
    const kws = keywords[expected.category] || [];
    const isFound = kws.some(kw => combinedText.includes(kw));
    
    if (isFound) {
      found++;
      log('  ✅', `${expected.category}: ${expected.description}`);
    } else {
      missed++;
      log('  ❌', `${expected.category}: ${expected.description} (NOT FOUND)`);
    }
  }
  
  const accuracy = Math.round((found / EXPECTED_VULNS.length) * 100);
  log('📊', `\nAccuracy: ${found}/${EXPECTED_VULNS.length} (${accuracy}%)`);
  log('📊', `Found: ${found} | Missed: ${missed}`);
  
  return { accuracy, found, missed, totalVulns: allVulns.length, totalPorts: allPorts.length, totalExploits: exploits.length };
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function main() {
  log('🚀', '═══════════════════════════════════════════════════════════');
  log('🚀', '  E2E Pipeline Test: testphp.vulnweb.com');
  log('🚀', '═══════════════════════════════════════════════════════════');
  
  // Step 1: Check scan server
  const scanServerOk = await checkScanServer();
  if (!scanServerOk) {
    log('⚠️', 'Scan server offline — active scans will not work. Continuing with passive only...');
  }
  
  // Step 2: Get engagement
  const eng = await getOrCreateEngagement();
  if (!eng) {
    log('❌', 'No engagement found. Cannot proceed.');
    process.exit(1);
  }
  const { engagementId } = eng;
  
  // Check current state
  const currentState = eng.state;
  const currentPhase = currentState?.phase || 'idle';
  const currentVulns = currentState?.stats?.vulnsFound || 0;
  const currentPorts = currentState?.stats?.portsFound || 0;
  
  log('📊', `Current state: phase=${currentPhase}, ports=${currentPorts}, vulns=${currentVulns}, assets=${currentState?.assets?.length || 0}`);
  
  // If already has results, skip to analysis
  if (currentVulns > 0 || currentPorts > 0) {
    log('✅', 'Engagement already has scan results. Proceeding to analysis...');
  } else {
    // Step 3: Start passive scan
    await startPassiveScan(engagementId);
    
    // Step 4: Wait for passive scan to complete (up to 3 min)
    log('⏳', 'Waiting for passive scan to complete...');
    const afterPassive = await pollUntilPhase(engagementId, ['enumeration', 'scanning', 'exploitation', 'analysis', 'complete'], 180000);
    
    if (afterPassive) {
      log('📊', `After passive: ${afterPassive.assets?.length || 0} assets, ${afterPassive.stats?.portsFound || 0} ports`);
    }
    
    // Step 5: Start active scan
    if (scanServerOk) {
      await startActiveScan(engagementId);
      
      // Step 6: Wait for active scan to complete (up to 8 min)
      log('⏳', 'Waiting for active scan to complete...');
      const afterActive = await pollUntilPhase(engagementId, ['analysis', 'exploitation', 'complete'], 480000);
      
      if (afterActive) {
        log('📊', `After active: ${afterActive.stats?.portsFound || 0} ports, ${afterActive.stats?.vulnsFound || 0} vulns`);
      }
    }
  }
  
  // Step 7: Run LLM analysis
  const llmResult = await runLLMAnalysis(engagementId);
  
  // Step 8: Generate exploits
  const exploitResult = await generateExploits(engagementId);
  
  // Step 9: Get all exploits
  const exploits = await getExploits(engagementId);
  
  // Step 10: Get final state and validate
  const finalState = await query('engagementOps.getState', { engagementId });
  const results = validateResults(finalState, exploits);
  
  log('🏁', '═══════════════════════════════════════════════════════════');
  log('🏁', `  FINAL: ${results.accuracy}% accuracy | ${results.totalVulns} vulns | ${results.totalPorts} ports | ${results.totalExploits} exploits`);
  log('🏁', '═══════════════════════════════════════════════════════════');
  
  // Write results to file
  const report = {
    target: TARGET,
    timestamp: new Date().toISOString(),
    scanServerOnline: scanServerOk,
    results,
    assets: (finalState?.assets || []).map(a => ({
      hostname: a.hostname,
      ip: a.ip,
      ports: a.ports?.length || 0,
      vulns: a.vulns?.length || 0,
      toolResults: a.toolResults?.length || 0,
    })),
    exploits: exploits.map(e => ({
      title: e.title || e.vulnTitle,
      language: e.language,
      validated: e.validated,
    })),
  };
  
  const fs = await import('fs');
  fs.writeFileSync('/home/ubuntu/caldera-dashboard/pipeline-test-results.json', JSON.stringify(report, null, 2));
  log('💾', 'Results saved to pipeline-test-results.json');
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
