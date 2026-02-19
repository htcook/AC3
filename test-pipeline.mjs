import 'dotenv/config';

// Simulate what the scan procedure does — call runDomainIntelPipeline directly
// to capture the actual error

async function testPipeline() {
  // We need to use tsx to import TypeScript
  const { runDomainIntelPipeline } = await import('./server/domainIntel.ts');
  
  console.log('=== Testing Pipeline with databank.com ===');
  try {
    const result = await runDomainIntelPipeline(
      {
        customerName: 'Test',
        primaryDomain: 'databank.com',
        additionalDomains: [],
        sector: 'technology',
        clientType: 'enterprise',
        criticalFunctions: ['data hosting'],
        complianceFlags: [],
        notes: '',
      },
      async (stage) => {
        console.log(`[Progress] Stage: ${stage}`);
      },
      { scanMode: 'standard', skipEngagement: true }
    );
    console.log(`=== Pipeline completed: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore} ===`);
  } catch (err) {
    console.error('=== PIPELINE CRASHED ===');
    console.error('Error:', err.message);
    console.error('Stack:', err.stack);
  }
}

testPipeline().then(() => process.exit(0)).catch(e => { console.error('Fatal:', e); process.exit(1); });
