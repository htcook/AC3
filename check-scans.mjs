import mysql2 from 'mysql2/promise';

const conn = await mysql2.createConnection({
  uri: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }
});

// Check scans
const [scans] = await conn.execute(
  `SELECT id, primaryDomain, status, totalAssets, totalFindings, overallRiskScore, discoveryCoverageScore 
   FROM domain_intel_scans 
   WHERE primaryDomain LIKE '%vianova%' OR primaryDomain LIKE '%aceofcloud%' OR primaryDomain LIKE '%databank%'
   ORDER BY createdAt DESC LIMIT 10`
);
console.log('=== SCANS ===');
console.table(scans);

// Check discovered assets for those scans
if (scans.length > 0) {
  const scanIds = scans.map(s => s.id);
  for (const scanId of scanIds.slice(0, 3)) {
    const scan = scans.find(s => s.id === scanId);
    const [assets] = await conn.execute(
      `SELECT id, scanId, hostname, assetType, hybridRiskScore, riskBand, 
              JSON_LENGTH(technologies) as techCount,
              JSON_LENGTH(postureFindings) as findingCount
       FROM discovered_assets 
       WHERE scanId = ?
       LIMIT 10`,
      [scanId]
    );
    console.log(`\n=== ASSETS for scan ${scanId} (${scan?.primaryDomain}) ===`);
    console.table(assets);
  }
}

// Check pipelineOutput for discoveredPorts and discoveredSubdomains
const [pipelineData] = await conn.execute(
  `SELECT id, primaryDomain, 
          JSON_LENGTH(pipelineOutput->'$.discoveredSubdomains') as subdomainCount,
          JSON_LENGTH(pipelineOutput->'$.discoveredPorts') as portCount,
          JSON_EXTRACT(pipelineOutput, '$.passiveRecon.summary.totalObservations') as totalObs,
          JSON_EXTRACT(pipelineOutput, '$.passiveRecon.summary.totalSignals') as totalSignals,
          JSON_LENGTH(pipelineOutput->'$.passiveRecon.riskSignals') as riskSignalCount,
          JSON_LENGTH(pipelineOutput->'$.passiveRecon.connectorResults') as connectorCount
   FROM domain_intel_scans 
   WHERE status IN ('completed', 'scan_complete') AND pipelineOutput IS NOT NULL
   ORDER BY createdAt DESC LIMIT 5`
);
console.log('\n=== PIPELINE OUTPUT SUMMARY (latest 5 completed scans) ===');
console.table(pipelineData);

// Check if risk signals have proper fields
const [riskSignalSample] = await conn.execute(
  `SELECT id, primaryDomain,
          JSON_EXTRACT(pipelineOutput, '$.passiveRecon.riskSignals[0]') as firstRiskSignal,
          JSON_EXTRACT(pipelineOutput, '$.passiveRecon.riskSignals[1]') as secondRiskSignal
   FROM domain_intel_scans 
   WHERE status IN ('completed', 'scan_complete') AND pipelineOutput IS NOT NULL
   ORDER BY createdAt DESC LIMIT 2`
);
console.log('\n=== RISK SIGNAL SAMPLES ===');
for (const row of riskSignalSample) {
  console.log(`Scan ${row.id} (${row.primaryDomain}):`);
  console.log('  Signal 1:', row.firstRiskSignal);
  console.log('  Signal 2:', row.secondRiskSignal);
}

// Check a sample of discovered ports
const [portSample] = await conn.execute(
  `SELECT id, primaryDomain,
          JSON_EXTRACT(pipelineOutput, '$.discoveredPorts[0]') as port1,
          JSON_EXTRACT(pipelineOutput, '$.discoveredPorts[1]') as port2,
          JSON_EXTRACT(pipelineOutput, '$.discoveredPorts[2]') as port3
   FROM domain_intel_scans 
   WHERE status IN ('completed', 'scan_complete') AND pipelineOutput IS NOT NULL
     AND JSON_LENGTH(pipelineOutput->'$.discoveredPorts') > 0
   ORDER BY createdAt DESC LIMIT 2`
);
console.log('\n=== DISCOVERED PORT SAMPLES ===');
for (const row of portSample) {
  console.log(`Scan ${row.id} (${row.primaryDomain}):`);
  console.log('  Port 1:', row.port1);
  console.log('  Port 2:', row.port2);
  console.log('  Port 3:', row.port3);
}

// Check discovered subdomain samples
const [subdomainSample] = await conn.execute(
  `SELECT id, primaryDomain,
          JSON_EXTRACT(pipelineOutput, '$.discoveredSubdomains[0]') as sub1,
          JSON_EXTRACT(pipelineOutput, '$.discoveredSubdomains[1]') as sub2
   FROM domain_intel_scans 
   WHERE status IN ('completed', 'scan_complete') AND pipelineOutput IS NOT NULL
     AND JSON_LENGTH(pipelineOutput->'$.discoveredSubdomains') > 0
   ORDER BY createdAt DESC LIMIT 2`
);
console.log('\n=== DISCOVERED SUBDOMAIN SAMPLES ===');
for (const row of subdomainSample) {
  console.log(`Scan ${row.id} (${row.primaryDomain}):`);
  console.log('  Sub 1:', row.sub1);
  console.log('  Sub 2:', row.sub2);
}

await conn.end();
