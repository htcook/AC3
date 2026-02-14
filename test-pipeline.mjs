/**
 * E2E Test: Run Domain Intel Pipeline on AceofCloud.com
 * This script tests the full pipeline via the tRPC endpoint
 */

const BASE_URL = 'http://localhost:3000';

async function testPipeline() {
  console.log('=== Domain Intel Pipeline E2E Test ===');
  console.log('Target: AceofCloud.com');
  console.log('');

  // Step 1: Start a scan via the tRPC endpoint
  console.log('[1/3] Starting domain intel scan...');
  
  const startRes = await fetch(`${BASE_URL}/api/trpc/domainIntel.startScan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      json: {
        customerName: 'AceofCloud',
        primaryDomain: 'aceofcloud.com',
        additionalDomains: [],
        sector: 'Technology',
        clientType: 'msp',
        criticalFunctions: ['Cloud Management', 'Security Operations', 'Client Infrastructure'],
        complianceFlags: ['SOC2', 'NIST'],
        notes: 'MSP providing cloud and security services'
      }
    })
  });

  if (!startRes.ok) {
    const errText = await startRes.text();
    console.error('Start scan failed:', startRes.status, errText.substring(0, 500));
    return;
  }

  const startData = await startRes.json();
  console.log('Start scan response:', JSON.stringify(startData, null, 2).substring(0, 500));
  
  const scanId = startData?.result?.data?.json?.scanId || startData?.result?.data?.scanId;
  if (!scanId) {
    console.error('No scanId returned. Full response:', JSON.stringify(startData, null, 2).substring(0, 1000));
    return;
  }
  
  console.log(`Scan ID: ${scanId}`);
  console.log('');

  // Step 2: Poll for scan completion
  console.log('[2/3] Polling for scan completion...');
  
  let attempts = 0;
  const maxAttempts = 60; // 5 minutes max
  let scanResult = null;

  while (attempts < maxAttempts) {
    attempts++;
    await new Promise(r => setTimeout(r, 5000)); // 5 second intervals
    
    const statusRes = await fetch(`${BASE_URL}/api/trpc/domainIntel.getScan?input=${encodeURIComponent(JSON.stringify({ json: { scanId } }))}`);
    
    if (!statusRes.ok) {
      console.error(`  Poll ${attempts}: HTTP ${statusRes.status}`);
      continue;
    }
    
    const statusData = await statusRes.json();
    const scan = statusData?.result?.data?.json || statusData?.result?.data;
    
    if (!scan) {
      console.log(`  Poll ${attempts}: No data yet...`);
      continue;
    }
    
    const status = scan.status;
    console.log(`  Poll ${attempts}: Status = ${status}`);
    
    if (status === 'completed') {
      scanResult = scan;
      break;
    } else if (status === 'failed') {
      console.error('  Scan FAILED:', scan.error || 'Unknown error');
      return;
    }
  }

  if (!scanResult) {
    console.error('Scan timed out after 5 minutes');
    return;
  }

  // Step 3: Analyze results
  console.log('');
  console.log('[3/3] Analyzing results...');
  console.log('');
  
  const results = scanResult.results ? (typeof scanResult.results === 'string' ? JSON.parse(scanResult.results) : scanResult.results) : null;
  
  if (!results) {
    console.error('No results in scan data');
    console.log('Full scan:', JSON.stringify(scanResult, null, 2).substring(0, 2000));
    return;
  }

  console.log('=== PIPELINE RESULTS ===');
  console.log(`Customer: ${results.orgProfile?.customerName || 'N/A'}`);
  console.log(`Domain: ${results.orgProfile?.primaryDomain || 'N/A'}`);
  console.log(`Total Assets Discovered: ${results.totalAssets || results.assets?.length || 0}`);
  console.log(`Total Findings: ${results.totalFindings || 0}`);
  console.log(`Overall Risk Score: ${results.overallRiskScore || 'N/A'}`);
  console.log(`Overall Risk Band: ${results.overallRiskBand || 'N/A'}`);
  console.log('');
  
  console.log('--- Executive Summary ---');
  console.log(results.executiveSummary?.substring(0, 500) || 'N/A');
  console.log('');
  
  console.log('--- Threat Model Summary ---');
  console.log(results.threatModelSummary?.substring(0, 500) || 'N/A');
  console.log('');
  
  if (results.assets && results.assets.length > 0) {
    console.log(`--- Assets (${results.assets.length}) ---`);
    for (const asset of results.assets.slice(0, 10)) {
      console.log(`  [${asset.riskBand || 'N/A'}] ${asset.hostname || asset.assetId} - ${asset.assetType || 'unknown'} (Risk: ${asset.hybridRiskScore?.toFixed(1) || 'N/A'})`);
    }
    if (results.assets.length > 10) {
      console.log(`  ... and ${results.assets.length - 10} more`);
    }
    console.log('');
  }
  
  if (results.campaignRecommendations && results.campaignRecommendations.length > 0) {
    console.log(`--- Campaign Recommendations (${results.campaignRecommendations.length}) ---`);
    for (const camp of results.campaignRecommendations) {
      console.log(`  [${camp.priority || 'N/A'}] ${camp.name} - ${camp.type || 'N/A'}`);
      console.log(`    ${camp.description?.substring(0, 100) || 'No description'}`);
    }
    console.log('');
  }

  console.log('=== E2E TEST PASSED ===');
  console.log(`Pipeline completed all stages successfully for AceofCloud.com`);
}

testPipeline().catch(err => {
  console.error('Test failed with error:', err.message);
  process.exit(1);
});
