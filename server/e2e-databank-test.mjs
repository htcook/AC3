/**
 * End-to-end test: databank.com
 * Tests the full domain discovery → passive scanning → hybrid scoring pipeline
 * Run: node server/e2e-databank-test.mjs
 */

const BASE = 'http://localhost:3000/api/trpc';

// We need a valid auth cookie. We'll call the pipeline directly via import instead.
// Since we can't easily get auth, we'll test the modules directly.

async function main() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  END-TO-END TEST: databank.com — Discovery, Scanning & Scoring');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const results = {
    passiveRecon: null,
    discoveredAssets: null,
    scoring: null,
    errors: [],
    connectorStats: [],
  };

  // ─── PHASE 1: Passive Reconnaissance ─────────────────────────────────
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  PHASE 1: PASSIVE RECONNAISSANCE                           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  try {
    const { runPassiveRecon } = await import('./lib/passive/index.ts');
    
    const apiKeys = {};
    if (process.env.SHODAN_API_KEY) apiKeys.shodan = process.env.SHODAN_API_KEY;
    if (process.env.CENSYS_API_ID) apiKeys.censys_id = process.env.CENSYS_API_ID;
    if (process.env.CENSYS_API_SECRET) apiKeys.censys_secret = process.env.CENSYS_API_SECRET;
    if (process.env.URLSCAN_API_KEY) apiKeys.urlscan = process.env.URLSCAN_API_KEY;
    if (process.env.SECURITYTRAILS_API_KEY) apiKeys.securitytrails = process.env.SECURITYTRAILS_API_KEY;
    if (process.env.DEHASHED_API_KEY) apiKeys.dehashed = process.env.DEHASHED_API_KEY;
    if (process.env.DEHASHED_EMAIL) apiKeys.dehashed_email = process.env.DEHASHED_EMAIL;

    console.log('API Keys configured:');
    console.log(`  SHODAN_API_KEY: ${process.env.SHODAN_API_KEY ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  CENSYS_API_ID: ${process.env.CENSYS_API_ID ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  CENSYS_API_SECRET: ${process.env.CENSYS_API_SECRET ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  URLSCAN_API_KEY: ${process.env.URLSCAN_API_KEY ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  SECURITYTRAILS_API_KEY: ${process.env.SECURITYTRAILS_API_KEY ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  DEHASHED_API_KEY: ${process.env.DEHASHED_API_KEY ? '✓ SET' : '✗ MISSING'}`);
    console.log(`  DEHASHED_EMAIL: ${process.env.DEHASHED_EMAIL ? '✓ SET' : '✗ MISSING'}`);
    console.log('');

    console.log('Running passive recon against databank.com (standard mode)...\n');
    const passiveResult = await runPassiveRecon('databank.com', {
      scanMode: 'standard',
      apiKeys,
      timeout: 30000,
      maxConcurrent: 5,
    });

    results.passiveRecon = passiveResult;

    // Print connector results
    console.log('┌─────────────────────────────────────────────────────────────┐');
    console.log('│  CONNECTOR RESULTS                                          │');
    console.log('├──────────────────────┬──────────┬────────┬─────────┬────────┤');
    console.log('│ Connector            │ Obs      │ Errors │ Time(ms)│ Status │');
    console.log('├──────────────────────┼──────────┼────────┼─────────┼────────┤');

    for (const cr of passiveResult.connectorResults) {
      const status = cr.skipped ? `SKIP: ${cr.skipReason || 'unknown'}` :
                     cr.rateLimited ? 'RATE-LTD' :
                     cr.errors > 0 ? 'ERROR' : 
                     cr.observations.length > 0 ? 'OK' : 'EMPTY';
      const name = cr.connector.padEnd(20);
      const obs = String(cr.observations.length).padStart(6);
      const errs = String(cr.errors).padStart(5);
      const time = String(cr.durationMs).padStart(7);
      console.log(`│ ${name} │ ${obs}   │ ${errs}  │ ${time} │ ${status.padEnd(6)} │`);
      
      results.connectorStats.push({
        name: cr.connector,
        observations: cr.observations.length,
        errors: cr.errors,
        durationMs: cr.durationMs,
        status,
        rateLimited: cr.rateLimited,
        skipped: cr.skipped,
      });
    }
    console.log('└──────────────────────┴──────────┴────────┴─────────┴────────┘\n');

    // Summary
    console.log('PASSIVE RECON SUMMARY:');
    console.log(`  Total observations: ${passiveResult.summary.totalObservations}`);
    console.log(`  Total risk signals: ${passiveResult.summary.totalSignals}`);
    console.log(`  Duration: ${passiveResult.summary.durationMs}ms`);
    console.log(`  Connectors with data: ${passiveResult.connectorResults.filter(r => r.observations.length > 0).length}/${passiveResult.connectorResults.length}`);
    console.log(`  Connectors skipped: ${passiveResult.connectorResults.filter(r => r.skipped).length}`);
    console.log(`  Connectors rate-limited: ${passiveResult.connectorResults.filter(r => r.rateLimited).length}`);
    console.log(`  Connectors with errors: ${passiveResult.connectorResults.filter(r => r.errors > 0).length}\n`);

    // Asset type breakdown
    const assetTypes = {};
    for (const obs of passiveResult.allObservations) {
      assetTypes[obs.assetType] = (assetTypes[obs.assetType] || 0) + 1;
    }
    console.log('ASSET TYPE BREAKDOWN:');
    for (const [type, count] of Object.entries(assetTypes).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${type}: ${count}`);
    }
    console.log('');

    // Risk signals
    if (passiveResult.riskSignals && passiveResult.riskSignals.length > 0) {
      console.log(`RISK SIGNALS (${passiveResult.riskSignals.length}):`);
      for (const sig of passiveResult.riskSignals.slice(0, 20)) {
        console.log(`  [${sig.severity}] ${sig.title} (${sig.source})`);
      }
      console.log('');
    }

    // Sample observations
    console.log('SAMPLE OBSERVATIONS (first 15):');
    for (const obs of passiveResult.allObservations.slice(0, 15)) {
      console.log(`  [${obs.assetType}] ${obs.name} — source: ${obs.source}, confidence: ${obs.confidence}`);
      if (obs.tags.length > 0) console.log(`    tags: ${obs.tags.slice(0, 5).join(', ')}`);
    }
    console.log('');

  } catch (err) {
    console.error('PASSIVE RECON FAILED:', err.message);
    results.errors.push({ phase: 'passive_recon', error: err.message });
  }

  // ─── PHASE 2: Full Domain Intel Pipeline ─────────────────────────────
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  PHASE 2: FULL DOMAIN INTEL PIPELINE                       ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  try {
    const { runDomainIntelPipeline } = await import('./domainIntel.ts');

    const orgProfile = {
      customerName: 'Databank',
      primaryDomain: 'databank.com',
      additionalDomains: [],
      sector: 'Technology / Data Centers',
      clientType: 'enterprise',
      criticalFunctions: ['data hosting', 'cloud services', 'disaster recovery', 'managed services'],
      complianceFlags: ['SOC2', 'HIPAA', 'PCI-DSS'],
      notes: 'Major US data center and managed services provider',
    };

    console.log('Running full domain intel pipeline...');
    console.log(`  Target: ${orgProfile.primaryDomain}`);
    console.log(`  Sector: ${orgProfile.sector}`);
    console.log(`  Compliance: ${orgProfile.complianceFlags.join(', ')}\n`);

    let currentStage = '';
    const pipelineResult = await runDomainIntelPipeline(orgProfile, (stage) => {
      currentStage = stage;
      console.log(`  → Stage: ${stage}`);
    }, { scanMode: 'standard', skipEngagement: true });

    results.discoveredAssets = pipelineResult;

    console.log('\nPIPELINE RESULTS:');
    console.log(`  Total assets discovered: ${pipelineResult.totalAssets}`);
    console.log(`  Total findings: ${pipelineResult.totalFindings}`);
    console.log(`  Overall risk score: ${pipelineResult.overallRiskScore}`);
    console.log(`  Risk level: ${pipelineResult.riskLevel}`);
    console.log('');

    // Asset details
    if (pipelineResult.assets && pipelineResult.assets.length > 0) {
      console.log(`DISCOVERED ASSETS (${pipelineResult.assets.length}):`);
      for (const asset of pipelineResult.assets.slice(0, 20)) {
        console.log(`  [${asset.assetType || 'unknown'}] ${asset.hostname || asset.assetId}`);
        if (asset.technologies && asset.technologies.length > 0) {
          console.log(`    Tech: ${asset.technologies.slice(0, 5).join(', ')}`);
        }
        if (asset.riskScore !== undefined) {
          console.log(`    Risk: ${asset.riskScore} (${asset.riskLevel || 'unscored'})`);
        }
      }
      console.log('');
    }

    // Findings
    if (pipelineResult.findings && pipelineResult.findings.length > 0) {
      console.log(`FINDINGS (${pipelineResult.findings.length}):`);
      const severityCounts = {};
      for (const f of pipelineResult.findings) {
        const sev = f.severity || 'info';
        severityCounts[sev] = (severityCounts[sev] || 0) + 1;
      }
      console.log('  Severity breakdown:');
      for (const [sev, count] of Object.entries(severityCounts)) {
        console.log(`    ${sev}: ${count}`);
      }
      console.log('\n  Top findings:');
      for (const f of pipelineResult.findings.slice(0, 15)) {
        console.log(`    [${f.severity}] ${f.title}`);
      }
      console.log('');
    }

    // Rescoring timeline
    if (pipelineResult.rescoringTimeline && pipelineResult.rescoringTimeline.length > 0) {
      console.log(`RESCORING TIMELINE (${pipelineResult.rescoringTimeline.length} events):`);
      for (const evt of pipelineResult.rescoringTimeline.slice(0, 10)) {
        console.log(`  ${evt.trigger}: ${evt.assetId} — ${evt.previousScore} → ${evt.newScore} (${evt.reason})`);
      }
      console.log('');
    }

    // Campaign recommendations
    if (pipelineResult.campaignRecommendations && pipelineResult.campaignRecommendations.length > 0) {
      console.log(`CAMPAIGN RECOMMENDATIONS (${pipelineResult.campaignRecommendations.length}):`);
      for (const rec of pipelineResult.campaignRecommendations.slice(0, 5)) {
        console.log(`  ${rec.name || rec.title}: ${rec.description || ''}`);
      }
      console.log('');
    }

  } catch (err) {
    console.error('DOMAIN INTEL PIPELINE FAILED:', err.message);
    console.error(err.stack);
    results.errors.push({ phase: 'domain_intel', error: err.message });
  }

  // ─── PHASE 3: Hybrid Scoring Engine ──────────────────────────────────
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  PHASE 3: HYBRID SCORING ENGINE TEST                       ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  try {
    const { computeHybridRisk, SCORING_PRESETS, dbProfileToScoringProfile } = await import('./lib/scoring-engine.ts');

    // Test with a simulated high-risk asset (web server with known vulns)
    const testAssets = [
      {
        name: 'databank.com (Main Web)',
        input: {
          carver: { criticality: 4, accessibility: 4, recuperability: 3, vulnerability: 4, effect: 3, recognizability: 5 },
          shock: { scope: 4, handling: 3, operationalImpact: 4, cascadingEffects: 3, knowledge: 4 },
          cvssEstimate: 7.5,
          exposure: 0.8,
          confidence: 0.85,
          businessImpactLevel: 'mission_critical',
          cvssV4Vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N',
        },
      },
      {
        name: 'mail.databank.com (Email)',
        input: {
          carver: { criticality: 3, accessibility: 3, recuperability: 3, vulnerability: 3, effect: 3, recognizability: 3 },
          shock: { scope: 3, handling: 3, operationalImpact: 3, cascadingEffects: 2, knowledge: 3 },
          cvssEstimate: 5.0,
          exposure: 0.6,
          confidence: 0.7,
          businessImpactLevel: 'business_essential',
        },
      },
      {
        name: 'vpn.databank.com (VPN)',
        input: {
          carver: { criticality: 5, accessibility: 5, recuperability: 2, vulnerability: 4, effect: 5, recognizability: 4 },
          shock: { scope: 5, handling: 2, operationalImpact: 5, cascadingEffects: 4, knowledge: 3 },
          cvssEstimate: 9.0,
          exposure: 0.9,
          confidence: 0.9,
          confirmedVulnScore: 9.8,
          businessImpactLevel: 'mission_critical',
          cvssV4Vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
        },
      },
      {
        name: 'api.databank.com (API)',
        input: {
          carver: { criticality: 4, accessibility: 4, recuperability: 3, vulnerability: 3, effect: 4, recognizability: 3 },
          shock: { scope: 3, handling: 3, operationalImpact: 4, cascadingEffects: 3, knowledge: 3 },
          cvssEstimate: 6.5,
          exposure: 0.7,
          confidence: 0.75,
          businessImpactLevel: 'business_essential',
        },
      },
    ];

    // Use default profile
    const defaultProfile = {
      carverWeight: 0.4,
      shockWeight: 0.3,
      cvssWeight: 0.3,
      carverWeights: { criticality: 0.25, accessibility: 0.15, recuperability: 0.15, vulnerability: 0.20, effect: 0.15, recognizability: 0.10 },
      shockWeights: { scope: 0.25, handling: 0.20, operationalImpact: 0.25, cascadingEffects: 0.15, knowledge: 0.15 },
    };

    console.log('Testing hybrid scoring with simulated databank.com assets:\n');
    const scoringResults = [];

    for (const testAsset of testAssets) {
      const result = computeHybridRisk(testAsset.input, defaultProfile);
      scoringResults.push({ ...testAsset, result });

      console.log(`  ── ${testAsset.name} ──`);
      console.log(`    Hybrid Risk Score: ${result.hybridRiskScore.toFixed(1)}`);
      console.log(`    Risk Band: ${result.riskBand.toUpperCase()}`);
      console.log(`    CARVER Composite: ${result.carverComposite.toFixed(2)}`);
      console.log(`    Shock Composite: ${result.shockComposite.toFixed(2)}`);
      console.log(`    Mission Impact: ${result.missionImpactScore.toFixed(2)}`);
      console.log(`    Impact Score: ${result.impactScore.toFixed(2)}`);
      console.log(`    Likelihood Score: ${result.likelihoodScore.toFixed(2)}`);
      if (result.cvssV4Parsed) {
        console.log(`    CVSS v4.0 Parsed: ✓ (AV:${result.cvssV4Parsed.attackVector}, AC:${result.cvssV4Parsed.attackComplexity})`);
      }
      if (result.cvssCarverAdjustments) {
        const adjustments = Object.entries(result.cvssCarverAdjustments).filter(([, v]) => v > 0);
        if (adjustments.length > 0) {
          console.log(`    CVSS→CARVER Adjustments: ${adjustments.map(([k, v]) => `${k}:${v}`).join(', ')}`);
        }
      }
      console.log(`    Top 3 Contributing Factors:`);
      const sorted = [...result.factorContributions].sort((a, b) => b.weightedScore - a.weightedScore);
      for (const fc of sorted.slice(0, 3)) {
        console.log(`      ${fc.category}.${fc.factor}: ${fc.rawScore} × ${fc.weight.toFixed(2)} = ${fc.weightedScore.toFixed(3)}`);
      }
      console.log('');
    }

    results.scoring = scoringResults;

    // Test presets
    console.log('SCORING PRESETS AVAILABLE:');
    if (SCORING_PRESETS) {
      for (const [name, preset] of Object.entries(SCORING_PRESETS)) {
        console.log(`  ${name}: ${preset.description || 'No description'}`);
      }
    }
    console.log('');

  } catch (err) {
    console.error('SCORING ENGINE FAILED:', err.message);
    console.error(err.stack);
    results.errors.push({ phase: 'scoring', error: err.message });
  }

  // ─── PHASE 4: Discovery Engine Individual Tools ──────────────────────
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  PHASE 4: INDIVIDUAL DISCOVERY TOOLS                       ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // Test Shodan InternetDB (free, no key needed)
  try {
    console.log('Testing Shodan InternetDB lookup for databank.com IPs...');
    const dns = await import('dns');
    const { promisify } = await import('util');
    const resolve4 = promisify(dns.resolve4);
    
    try {
      const ips = await resolve4('databank.com');
      console.log(`  DNS resolved: ${ips.join(', ')}`);
      
      for (const ip of ips.slice(0, 3)) {
        try {
          const resp = await fetch(`https://internetdb.shodan.io/${ip}`);
          if (resp.ok) {
            const data = await resp.json();
            console.log(`  Shodan InternetDB for ${ip}:`);
            console.log(`    Ports: ${data.ports?.join(', ') || 'none'}`);
            console.log(`    Hostnames: ${data.hostnames?.join(', ') || 'none'}`);
            console.log(`    CPEs: ${data.cpes?.join(', ') || 'none'}`);
            console.log(`    Vulns: ${data.vulns?.join(', ') || 'none'}`);
            console.log(`    Tags: ${data.tags?.join(', ') || 'none'}`);
          }
        } catch (e) {
          console.log(`  InternetDB lookup failed for ${ip}: ${e.message}`);
        }
      }
    } catch (e) {
      console.log(`  DNS resolution failed: ${e.message}`);
    }
    console.log('');
  } catch (err) {
    console.error('Shodan InternetDB test failed:', err.message);
  }

  // Test crt.sh (free, no key)
  try {
    console.log('Testing crt.sh certificate transparency for databank.com...');
    const resp = await fetch('https://crt.sh/?q=%25.databank.com&output=json', { 
      signal: AbortSignal.timeout(15000) 
    });
    if (resp.ok) {
      const certs = await resp.json();
      const uniqueNames = new Set();
      for (const cert of certs) {
        if (cert.name_value) {
          for (const name of cert.name_value.split('\n')) {
            uniqueNames.add(name.trim().toLowerCase());
          }
        }
      }
      console.log(`  Found ${certs.length} certificates, ${uniqueNames.size} unique names`);
      console.log(`  Sample subdomains: ${[...uniqueNames].slice(0, 10).join(', ')}`);
    } else {
      console.log(`  crt.sh returned ${resp.status}`);
    }
    console.log('');
  } catch (err) {
    console.error('crt.sh test failed:', err.message);
  }

  // ─── FINAL SUMMARY ──────────────────────────────────────────────────
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  FINAL SUMMARY                                             ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const workingConnectors = results.connectorStats.filter(c => c.observations > 0);
  const skippedConnectors = results.connectorStats.filter(c => c.skipped);
  const errorConnectors = results.connectorStats.filter(c => c.errors > 0 && !c.skipped);
  const emptyConnectors = results.connectorStats.filter(c => c.observations === 0 && !c.skipped && c.errors === 0);

  console.log(`CONNECTORS: ${workingConnectors.length} producing data, ${skippedConnectors.length} skipped, ${errorConnectors.length} errors, ${emptyConnectors.length} empty`);
  if (workingConnectors.length > 0) {
    console.log(`  Working: ${workingConnectors.map(c => c.name).join(', ')}`);
  }
  if (skippedConnectors.length > 0) {
    console.log(`  Skipped: ${skippedConnectors.map(c => `${c.name} (${c.status})`).join(', ')}`);
  }
  if (errorConnectors.length > 0) {
    console.log(`  Errors: ${errorConnectors.map(c => c.name).join(', ')}`);
  }
  if (emptyConnectors.length > 0) {
    console.log(`  Empty: ${emptyConnectors.map(c => c.name).join(', ')}`);
  }
  console.log('');

  if (results.passiveRecon) {
    console.log(`PASSIVE RECON: ${results.passiveRecon.summary.totalObservations} observations, ${results.passiveRecon.summary.totalSignals} risk signals`);
  }
  if (results.discoveredAssets) {
    console.log(`DOMAIN INTEL: ${results.discoveredAssets.totalAssets} assets, ${results.discoveredAssets.totalFindings} findings, risk score: ${results.discoveredAssets.overallRiskScore}`);
  }
  if (results.scoring) {
    console.log(`HYBRID SCORING: ${results.scoring.length} assets scored`);
    for (const s of results.scoring) {
      console.log(`  ${s.name}: ${s.result.hybridRiskScore.toFixed(1)} (${s.result.riskBand})`);
    }
  }
  if (results.errors.length > 0) {
    console.log(`\nERRORS (${results.errors.length}):`);
    for (const e of results.errors) {
      console.log(`  [${e.phase}] ${e.error}`);
    }
  }

  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  TEST COMPLETE');
  console.log('═══════════════════════════════════════════════════════════════');
}

main().catch(err => {
  console.error('FATAL ERROR:', err);
  process.exit(1);
});
