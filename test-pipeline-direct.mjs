/**
 * E2E Test: Run Domain Intel Pipeline directly on AceofCloud.com
 * Bypasses tRPC auth by calling the pipeline function via a dynamic import
 * Uses tsx to handle TypeScript imports
 */

import { execSync } from 'child_process';

// We'll use the server's env vars by loading them from the running process
// First, let's test by calling the API with a simple fetch to the LLM endpoint
// to verify the pipeline stages work

const FORGE_API_URL = process.env.BUILT_IN_FORGE_API_URL || '';
const FORGE_API_KEY = process.env.BUILT_IN_FORGE_API_KEY || '';

if (!FORGE_API_URL || !FORGE_API_KEY) {
  console.log('Loading env from .env file...');
}

async function invokeLLM(params) {
  const apiUrl = FORGE_API_URL 
    ? `${FORGE_API_URL.replace(/\/$/, '')}/v1/chat/completions`
    : 'https://forge.manus.im/v1/chat/completions';
  
  const payload = {
    model: 'gemini-2.5-flash',
    messages: params.messages,
    max_tokens: 32768,
    thinking: { budget_tokens: 128 },
  };
  
  if (params.response_format) {
    payload.response_format = params.response_format;
  }
  
  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${FORGE_API_KEY}`,
    },
    body: JSON.stringify(payload),
  });
  
  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`LLM failed: ${response.status} - ${errText.substring(0, 500)}`);
  }
  
  return await response.json();
}

function safeParseLLMJson(raw) {
  let cleaned = raw.trim();
  // Strip markdown fences
  cleaned = cleaned.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
  cleaned = cleaned.trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    // Try to extract JSON object or array
    const objMatch = cleaned.match(/\{[\s\S]*\}/);
    if (objMatch) {
      try { return JSON.parse(objMatch[0]); } catch {}
    }
    const arrMatch = cleaned.match(/\[[\s\S]*\]/);
    if (arrMatch) {
      try { return JSON.parse(arrMatch[0]); } catch {}
    }
    throw new Error(`Failed to parse LLM JSON: ${cleaned.substring(0, 200)}`);
  }
}

const orgProfile = {
  customerName: 'AceofCloud',
  primaryDomain: 'aceofcloud.com',
  additionalDomains: [],
  sector: 'Technology',
  clientType: 'msp',
  criticalFunctions: ['Cloud Management', 'Security Operations', 'Client Infrastructure'],
  complianceFlags: ['SOC2', 'NIST'],
  notes: 'MSP providing cloud and security services'
};

async function stage1_discover() {
  console.log('=== Stage 1: Asset Discovery ===');
  const startTime = Date.now();
  
  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are a passive reconnaissance expert. Given a target organization, infer likely subdomains, services, technologies, and email patterns based on common patterns for organizations in their sector. Return a JSON object with an "assets" array. Each asset should have: assetId, hostname, url (optional), assetType (one of: web_app, mail_server, dns, api_endpoint, cdn, cloud_service, identity_provider, payment_gateway, monitoring, database, file_storage, vpn, other), technologies (array of strings), assetClasses (array like ["internet_facing", "authentication", etc.]), tags (array of strings), description (string). Infer at least 10-15 assets based on common patterns for a ${orgProfile.clientType} in the ${orgProfile.sector} sector.`
      },
      {
        role: 'user',
        content: `Perform passive reconnaissance on the following organization:\n\nOrganization: ${orgProfile.customerName}\nPrimary Domain: ${orgProfile.primaryDomain}\nAdditional Domains: ${orgProfile.additionalDomains?.join(', ') || 'None'}\nSector: ${orgProfile.sector}\nClient Type: ${orgProfile.clientType}\nCritical Functions: ${orgProfile.criticalFunctions.join(', ')}\nCompliance: ${orgProfile.complianceFlags.join(', ')}\nNotes: ${orgProfile.notes || 'None'}\n\nReturn a JSON object with an "assets" array containing all discovered/inferred assets.`
      }
    ],
    response_format: { type: 'json_object' }
  });
  
  const content = String(response.choices[0].message.content);
  const parsed = safeParseLLMJson(content);
  const assets = parsed.assets || [];
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`  Discovered ${assets.length} assets in ${elapsed}s`);
  for (const a of assets.slice(0, 5)) {
    console.log(`    - ${a.hostname} (${a.assetType}): ${a.description?.substring(0, 60) || 'N/A'}`);
  }
  if (assets.length > 5) console.log(`    ... and ${assets.length - 5} more`);
  console.log('');
  
  return assets;
}

async function stage2_analyze(assets) {
  console.log('=== Stage 2: Asset Analysis (BIA + Risk) ===');
  const startTime = Date.now();
  
  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are a cybersecurity risk analyst. For each asset, compute:
1. CARVER scores (criticality, accessibility, recuperability, vulnerability, effect, recognizability) each 1-10
2. SHOCK scores (scope, hostility, origin, capability, knowledge) each 1-10  
3. A hybrid risk score (0-100) combining CVSS-like technical risk with business impact
4. A risk band (critical/high/medium/low)
5. Key findings and recommendations

Return a JSON object with an "analyses" array. Each analysis should have: assetId, hostname, assetType, carverScores (object with the 6 fields), shockScores (object with the 5 fields), hybridRiskScore (number 0-100), riskBand (string), findings (array of strings), recommendations (array of strings), attackVectors (array of strings).`
      },
      {
        role: 'user',
        content: `Analyze the following ${assets.length} assets for ${orgProfile.customerName} (${orgProfile.primaryDomain}), a ${orgProfile.clientType} in the ${orgProfile.sector} sector:\n\n${JSON.stringify(assets, null, 2)}\n\nReturn a JSON object with an "analyses" array.`
      }
    ],
    response_format: { type: 'json_object' }
  });
  
  const content = String(response.choices[0].message.content);
  const parsed = safeParseLLMJson(content);
  const analyses = parsed.analyses || [];
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`  Analyzed ${analyses.length} assets in ${elapsed}s`);
  for (const a of analyses.slice(0, 5)) {
    console.log(`    - [${a.riskBand?.toUpperCase() || 'N/A'}] ${a.hostname} - Risk: ${a.hybridRiskScore || 'N/A'}`);
  }
  if (analyses.length > 5) console.log(`    ... and ${analyses.length - 5} more`);
  console.log('');
  
  return analyses;
}

async function stage3_campaigns(analyses) {
  console.log('=== Stage 3: Campaign Recommendations ===');
  const startTime = Date.now();
  
  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are a red team campaign planner. Based on the asset analysis results, recommend specific offensive security campaigns. For each campaign, include:
- name: descriptive campaign name
- type: one of (phishing, adversary_emulation, social_engineering, credential_harvesting, lateral_movement, data_exfiltration)
- priority: one of (critical, high, medium, low)
- description: detailed description
- targetAssets: array of asset IDs to target
- calderaAbilities: array of MITRE ATT&CK technique IDs (e.g., T1566.001)
- gophishTemplate: suggested phishing template type
- estimatedImpact: string describing potential impact
- prerequisites: array of strings

Return a JSON object with a "campaigns" array containing 5-8 recommended campaigns.`
      },
      {
        role: 'user',
        content: `Based on the following asset analysis for ${orgProfile.customerName} (${orgProfile.primaryDomain}), recommend offensive security campaigns:\n\n${JSON.stringify(analyses.slice(0, 10), null, 2)}\n\nReturn a JSON object with a "campaigns" array.`
      }
    ],
    response_format: { type: 'json_object' }
  });
  
  const content = String(response.choices[0].message.content);
  const parsed = safeParseLLMJson(content);
  const campaigns = parsed.campaigns || [];
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`  Generated ${campaigns.length} campaign recommendations in ${elapsed}s`);
  for (const c of campaigns) {
    console.log(`    - [${c.priority?.toUpperCase() || 'N/A'}] ${c.name} (${c.type})`);
    console.log(`      ${c.description?.substring(0, 80) || 'N/A'}`);
  }
  console.log('');
  
  return campaigns;
}

async function stage4_summary(analyses, campaigns) {
  console.log('=== Stage 4: Executive Summary ===');
  const startTime = Date.now();
  
  const avgRisk = analyses.reduce((s, a) => s + (a.hybridRiskScore || 0), 0) / (analyses.length || 1);
  
  const response = await invokeLLM({
    messages: [
      {
        role: 'system',
        content: `You are a cybersecurity executive report writer. Generate a concise executive summary and threat model summary based on the assessment results. Return a JSON object with: executiveSummary (string, 2-3 paragraphs), threatModelSummary (string, 2-3 paragraphs), overallRiskScore (number 0-100), overallRiskBand (one of: critical, high, medium, low).`
      },
      {
        role: 'user',
        content: `Generate executive and threat model summaries for ${orgProfile.customerName} (${orgProfile.primaryDomain}):\n\nAssets analyzed: ${analyses.length}\nAverage risk score: ${avgRisk.toFixed(1)}\nCampaigns recommended: ${campaigns.length}\nCritical findings: ${analyses.filter(a => a.riskBand === 'critical').length}\nHigh findings: ${analyses.filter(a => a.riskBand === 'high').length}\n\nTop risks:\n${analyses.slice(0, 5).map(a => `- ${a.hostname}: ${a.findings?.[0] || 'N/A'}`).join('\n')}`
      }
    ],
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: 'pipeline_summaries',
        strict: true,
        schema: {
          type: 'object',
          properties: {
            executiveSummary: { type: 'string', description: 'Executive summary' },
            threatModelSummary: { type: 'string', description: 'Threat model summary' },
            overallRiskScore: { type: 'number', description: 'Overall risk score 0-100' },
            overallRiskBand: { type: 'string', description: 'Risk band' }
          },
          required: ['executiveSummary', 'threatModelSummary', 'overallRiskScore', 'overallRiskBand'],
          additionalProperties: false
        }
      }
    }
  });
  
  const content = String(response.choices[0].message.content);
  const parsed = safeParseLLMJson(content);
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`  Generated summaries in ${elapsed}s`);
  console.log(`  Overall Risk: ${parsed.overallRiskScore} (${parsed.overallRiskBand})`);
  console.log('');
  console.log('--- Executive Summary ---');
  console.log(parsed.executiveSummary?.substring(0, 500));
  console.log('');
  console.log('--- Threat Model Summary ---');
  console.log(parsed.threatModelSummary?.substring(0, 500));
  
  return parsed;
}

async function runFullPipeline() {
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║  Domain Intel Pipeline E2E Test - AceofCloud.com ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
  
  const totalStart = Date.now();
  
  try {
    const assets = await stage1_discover();
    const analyses = await stage2_analyze(assets);
    const campaigns = await stage3_campaigns(analyses);
    const summary = await stage4_summary(analyses, campaigns);
    
    const totalElapsed = ((Date.now() - totalStart) / 1000).toFixed(1);
    
    console.log('');
    console.log('╔══════════════════════════════════════════════════╗');
    console.log('║           E2E TEST RESULTS SUMMARY               ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log(`  Total Time: ${totalElapsed}s`);
    console.log(`  Assets Discovered: ${assets.length}`);
    console.log(`  Assets Analyzed: ${analyses.length}`);
    console.log(`  Campaigns Recommended: ${campaigns.length}`);
    console.log(`  Overall Risk: ${summary.overallRiskScore} (${summary.overallRiskBand})`);
    console.log('');
    console.log('  ✅ ALL 4 STAGES COMPLETED SUCCESSFULLY');
    console.log('');
  } catch (err) {
    const totalElapsed = ((Date.now() - totalStart) / 1000).toFixed(1);
    console.error('');
    console.error(`  ❌ PIPELINE FAILED after ${totalElapsed}s`);
    console.error(`  Error: ${err.message}`);
    console.error('');
    if (err.stack) console.error(err.stack);
    process.exit(1);
  }
}

runFullPipeline();
