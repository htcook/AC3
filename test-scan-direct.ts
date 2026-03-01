import { runDomainIntelPipeline } from './server/domainIntel';
import fs from 'fs';

async function main() {
  console.log('=== Direct Pipeline Test ===');
  console.log('Target: example.com');
  console.log('Mode: quick / passive');
  console.log('');
  
  const startTime = Date.now();
  
  try {
    // The function signature is: (org, onProgress?, options?)
    const org = {
      customerName: 'Example Inc',
      primaryDomain: 'example.com',
      sector: 'Technology',
      clientType: 'enterprise',
      criticalFunctions: ['web services', 'email'],
      complianceFlags: ['SOC2'],
    };
    
    const onProgress = (stage: string) => {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  [${elapsed}s] Stage: ${stage}`);
    };
    
    const result = await runDomainIntelPipeline(
      org as any,
      onProgress as any,
      { scanMode: 'quick' }
    );
    
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`\n[COMPLETE] Pipeline finished in ${elapsed}s\n`);
    
    // Write full result to file for analysis
    fs.writeFileSync('/home/ubuntu/scan-result.json', JSON.stringify(result, null, 2));
    console.log('Full result written to /home/ubuntu/scan-result.json');
    
    // Summary - use correct field names from PipelineResult
    console.log('\n[SUMMARY]');
    console.log(`  Domain: ${result.orgProfile?.primaryDomain}`);
    console.log(`  Risk Score: ${result.overallRiskScore}`);
    console.log(`  Risk Band: ${result.overallRiskBand}`);
    console.log(`  Total Assets: ${result.totalAssets}`);
    console.log(`  Total Findings: ${result.totalFindings}`);
    console.log(`  Confirmed: ${result.confirmedFindingsCount}, Probable: ${result.probableFindingsCount}, Potential: ${result.potentialFindingsCount}`);
    console.log(`  Executive Summary: ${result.executiveSummary?.substring(0, 150)}...`);
    
    // New module outputs
    console.log('\n[NEW MODULES]');
    console.log(`  orgDiscovery: ${result.orgDiscovery ? 'present (' + (result.orgDiscovery.candidates?.length ?? 0) + ' candidates)' : 'MISSING'}`);
    console.log(`  complianceScan: ${result.complianceScan ? 'present (score: ' + (result.complianceScan.complianceScore ?? 'N/A') + ')' : 'MISSING'}`);
    console.log(`  containerExposure: ${result.containerExposure ? 'present (' + (result.containerExposure.totalProbes ?? 0) + ' probes, ' + (result.containerExposure.totalHits ?? 0) + ' hits)' : 'MISSING'}`);
    
    // Data quality checks on assets
    console.log('\n[DATA QUALITY CHECKS]');
    const issues: string[] = [];
    
    if (result.assets) {
      result.assets.forEach((a: any, i: number) => {
        if (!a.asset?.hostname) issues.push(`Asset ${i}: missing hostname`);
        if (a.hybridRiskScore === undefined) issues.push(`Asset ${i}: missing hybridRiskScore`);
        if (a.riskBand === undefined) issues.push(`Asset ${i}: missing riskBand`);
        
        // Check posture findings
        if (a.postureFindings) {
          a.postureFindings.forEach((f: any, fi: number) => {
            if (!f.title) issues.push(`Asset ${i} Finding ${fi}: missing title`);
            if (f.severity === undefined) issues.push(`Asset ${i} Finding ${fi}: missing severity`);
            // Email findings on non-mail assets
            if (f.title && /dmarc|spf|dkim|email.*security/i.test(f.title)) {
              if (a.asset?.hostname && !/mail|mx|smtp/i.test(a.asset.hostname)) {
                issues.push(`Asset ${i} Finding ${fi}: Email finding "${f.title}" on non-mail asset "${a.asset.hostname}"`);
              }
            }
          });
          
          // Severity distribution per asset
          const sevDist: Record<string, number> = {};
          a.postureFindings.forEach((f: any) => {
            const s = String(f.severity ?? 'unknown');
            sevDist[s] = (sevDist[s] || 0) + 1;
          });
          console.log(`  Asset ${i} (${a.asset?.hostname}): ${a.postureFindings.length} findings, severity: ${JSON.stringify(sevDist)}, risk: ${a.hybridRiskScore} (${a.riskBand})`);
        }
      });
    }
    
    // Check compliance scan
    if (result.complianceScan) {
      const cs = result.complianceScan as any;
      console.log(`  Compliance: ${cs.passed}/${cs.totalChecks} passed (${cs.complianceScore}%)`);
      if (cs.failed > 0) {
        const failedChecks = cs.checks?.filter((c: any) => c.status === 'fail') || [];
        console.log(`  Failed checks: ${failedChecks.map((c: any) => c.checkId).join(', ')}`);
      }
    }
    
    if (issues.length > 0) {
      console.log(`\n  ⚠ ${issues.length} DATA QUALITY ISSUES FOUND:`);
      issues.forEach(issue => console.log(`    - ${issue}`));
    } else {
      console.log('\n  ✓ No data quality issues found');
    }
    
  } catch (err: any) {
    console.log('[ERROR]', err.message);
    console.log(err.stack);
  }
}

main();
