/**
 * Script to:
 * 1. Enrich the 20 matched threat actors from AceofCloud scan with deep TTP analysis
 * 2. Generate detection rules for their techniques
 * 3. Build the Identity Provider Compromise campaign
 */
import jwt from "jsonwebtoken";

const BASE_URL = "http://localhost:3000";
const JWT_SECRET = process.env.CALDERA_JWT_SECRET || "caldera-dashboard-secret-key-2024";
const token = jwt.sign({ username: "admin", role: "admin", loginTime: Date.now() }, JWT_SECRET, { expiresIn: "4h" });
const COOKIE = `caldera_session=${token}`;

async function callTrpc(path, input = {}, timeout = 180000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(`${BASE_URL}/api/trpc/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: COOKIE },
      body: JSON.stringify({ json: input }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (resp.status >= 400) {
      const t = await resp.text();
      throw new Error(`HTTP ${resp.status}: ${t.slice(0, 300)}`);
    }
    const data = await resp.json();
    return data.result?.data?.json || data.result?.data || data;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// The 20 matched actors from the AceofCloud scan
const MATCHED_ACTORS = [
  "chimera", "redcurl", "apt29-g0016", "apt29-vcd-cloud-compromise-enhanced",
  "apt39-g0087", "apt5-g1023", "dragonfly-g0035", "ember-bear-g1003",
  "fox-kitten-g0117", "indrik-spider-g0119", "leviathan-g0065",
  "scattered-spider-g1015", "blue-mockingbird-g0108",
  "msp-target-complete-apt29-vcd-crowdstrike", "sandworm-team-g0034",
  "turla-g0010", "wizard-spider-g0102", "hafnium-g0125",
  "lazarus-group-g0032", "muddywater-g0069"
];

// ========== STEP 1: Enrich each matched actor via LLM ==========
console.log("╔══════════════════════════════════════════════════════════╗");
console.log("║  STEP 1: Enrich 20 Matched Threat Actors via LLM       ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

let enrichedCount = 0;
let enrichErrors = [];
let allTechniqueIds = new Set();

for (let i = 0; i < MATCHED_ACTORS.length; i++) {
  const actorId = MATCHED_ACTORS[i];
  console.log(`[${i+1}/${MATCHED_ACTORS.length}] Enriching: ${actorId}...`);
  
  try {
    const result = await callTrpc("threatActorDb.enrich", { actorId }, 120000);
    enrichedCount++;
    const tools = result.enriched?.tools?.length || 0;
    const malware = result.enriched?.malware?.length || 0;
    const timeline = result.enriched?.activityTimeline?.length || 0;
    console.log(`  ✅ Enriched (${tools} tools, ${malware} malware, ${timeline} timeline events)`);
  } catch (e) {
    const msg = e.message.slice(0, 120);
    if (msg.includes("NOT_FOUND")) {
      console.log(`  ⏭️  Actor not found in DB, skipping`);
    } else {
      console.log(`  ⚠️ ${msg}`);
    }
    enrichErrors.push(actorId);
  }
  
  // Brief pause between LLM calls
  if (i < MATCHED_ACTORS.length - 1) {
    await new Promise(r => setTimeout(r, 500));
  }
}

console.log(`\n✅ Enrichment Complete: ${enrichedCount}/${MATCHED_ACTORS.length} actors enriched`);
if (enrichErrors.length > 0) {
  console.log(`⚠️ ${enrichErrors.length} skipped: ${enrichErrors.join(", ")}`);
}

// ========== STEP 2: Collect techniques and generate detection rules ==========
console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log("║  STEP 2: Generate Detection Rules (Sigma/YARA/etc)     ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

// First, get all actors and collect their technique IDs
console.log("Collecting techniques from all enriched actors...");
for (const actorId of MATCHED_ACTORS) {
  try {
    const actor = await callTrpc("threatActorDb.get", { actorId }, 10000);
    if (actor?.techniques && Array.isArray(actor.techniques)) {
      actor.techniques.forEach(t => {
        if (t.id) allTechniqueIds.add(t.id);
      });
    }
  } catch (e) {
    // skip
  }
}

const techniqueIds = Array.from(allTechniqueIds);
console.log(`Found ${techniqueIds.length} unique techniques across all matched actors`);

if (techniqueIds.length > 0) {
  // Process in batches of 10
  const BATCH = 10;
  let rulesGenerated = 0;
  for (let i = 0; i < techniqueIds.length; i += BATCH) {
    const batch = techniqueIds.slice(i, i + BATCH);
    console.log(`Generating rules for techniques ${i+1}-${Math.min(i+BATCH, techniqueIds.length)}/${techniqueIds.length}...`);
    try {
      const rules = await callTrpc("ttpEngine.detectionRules", { techniqueIds: batch }, 120000);
      rulesGenerated += batch.length;
      console.log(`  ✅ ${batch.length} technique rules generated`);
    } catch (e) {
      console.log(`  ⚠️ ${e.message.slice(0, 100)}`);
    }
    await new Promise(r => setTimeout(r, 500));
  }
  console.log(`\n✅ Detection rules generated for ${rulesGenerated}/${techniqueIds.length} techniques`);
} else {
  console.log("No techniques found to generate rules for");
}

// ========== STEP 3: Build the Identity Provider Compromise Campaign ==========
console.log("\n╔══════════════════════════════════════════════════════════╗");
console.log("║  STEP 3: Build Identity Provider Compromise Campaign    ║");
console.log("╚══════════════════════════════════════════════════════════╝\n");

try {
  // Create the engagement
  console.log("Creating engagement for AceofCloud...");
  const engagement = await callTrpc("engagements.create", {
    name: "AceofCloud - Identity Provider Compromise Assessment",
    customerName: "AceofCloud",
    description: "Purple team exercise targeting AceofCloud SSO/OWA infrastructure based on Domain Intel scan results (Risk 89/100). Simulates APT29-style Identity Provider Compromise via sophisticated phishing targeting Okta SSO and Outlook Web Access portals.",
    engagementType: "purple_team",
    status: "planning",
    targetDomain: "aceofcloud.com",
    notes: "Campaign targets: login.aceofcloud.com (Okta SSO), mail.aceofcloud.com (OWA). Based on scan ID 30122. Top matched actors: APT29, Scattered Spider, Fox Kitten.",
  }, 60000);
  
  const engagementId = engagement?.id || engagement?.engagementId;
  console.log(`✅ Engagement created: ID ${engagementId}`);

  // Generate SSO phishing template
  console.log("\nGenerating SSO phishing template (APT29 style)...");
  try {
    const ssoTemplate = await callTrpc("templateGenerator.generateFromThreatActor", {
      threatActorId: "apt29-g0016",
      threatActorName: "APT29 (Cozy Bear)",
      phishingType: "credential_harvest",
      sophistication: "advanced",
      targetOrg: "AceofCloud",
      targetSector: "Cloud & Cybersecurity Services",
      techniques: [
        { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
        { id: "T1078", name: "Valid Accounts", tactic: "defense-evasion" },
        { id: "T1556", name: "Modify Authentication Process", tactic: "credential-access" },
      ],
    }, 120000);
    console.log(`✅ SSO phishing template generated`);
    if (ssoTemplate?.emailSubject) console.log(`   Subject: ${ssoTemplate.emailSubject}`);
  } catch (e) {
    console.log(`⚠️ SSO template: ${e.message.slice(0, 120)}`);
  }

  // Generate OWA phishing template
  console.log("\nGenerating OWA phishing template (Scattered Spider style)...");
  try {
    const owaTemplate = await callTrpc("templateGenerator.generateFromThreatActor", {
      threatActorId: "scattered-spider-g1015",
      threatActorName: "Scattered Spider",
      phishingType: "mfa_fatigue",
      sophistication: "advanced",
      targetOrg: "AceofCloud",
      targetSector: "Cloud & Cybersecurity Services",
      techniques: [
        { id: "T1621", name: "Multi-Factor Authentication Request Generation", tactic: "credential-access" },
        { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access" },
        { id: "T1078.004", name: "Cloud Accounts", tactic: "defense-evasion" },
      ],
    }, 120000);
    console.log(`✅ OWA phishing template generated`);
    if (owaTemplate?.emailSubject) console.log(`   Subject: ${owaTemplate.emailSubject}`);
  } catch (e) {
    console.log(`⚠️ OWA template: ${e.message.slice(0, 120)}`);
  }

  // Create Caldera adversary for this campaign
  console.log("\nCreating Caldera adversary profile for campaign...");
  try {
    // Get APT29 abilities from the DB
    const apt29 = await callTrpc("threatActorDb.get", { actorId: "apt29-g0016" }, 10000);
    const calderaProfile = apt29?.calderaProfile;
    const atomicOrdering = calderaProfile?.atomicOrdering || [];
    
    const adversary = await callTrpc("calderaProxy.createAdversary", {
      adversary_id: "aceofcloud-idp-compromise-2026",
      name: "AceofCloud IDP Compromise - APT29 Profile",
      description: "Custom adversary profile for AceofCloud Identity Provider Compromise purple team exercise. Based on APT29 TTPs targeting SSO/OWA infrastructure.",
      atomic_ordering: atomicOrdering.slice(0, 30), // Top 30 abilities
      objective: "Compromise identity providers (Okta SSO, OWA) to gain persistent access to AceofCloud infrastructure",
    }, 30000);
    
    if (adversary?.success) {
      console.log(`✅ Caldera adversary created: aceofcloud-idp-compromise-2026`);
    } else {
      console.log(`⚠️ Caldera adversary: ${adversary?.error || "unknown error"}`);
    }
  } catch (e) {
    console.log(`⚠️ Caldera adversary: ${e.message.slice(0, 120)}`);
  }

  console.log("\n✅ Campaign setup complete!");
  console.log(`   Engagement ID: ${engagementId}`);
  console.log("   Templates: SSO (APT29) + OWA (Scattered Spider)");
  console.log("   Caldera Adversary: aceofcloud-idp-compromise-2026");

} catch (e) {
  console.error(`❌ Campaign creation failed: ${e.message}`);
}

console.log("\n" + "=".repeat(60));
console.log("ALL OPERATIONS COMPLETE");
console.log("=".repeat(60));
