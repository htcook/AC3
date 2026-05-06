import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/ember-catalog-intelligence.ts
import { sql } from "drizzle-orm";
async function buildEmberThreatContext(params) {
  const { getDb } = await import("./db-D773P4Y2.js");
  const db = await getDb();
  const context = {
    matchedActors: [],
    attackChains: [],
    playbooks: [],
    dfirTechniques: [],
    phishingOptions: [],
    iocIntelligence: [],
    recommendedModules: [],
    systemPromptContext: ""
  };
  if (!db) return context;
  const maxActors = params.maxActors || 5;
  const maxPlaybooks = params.maxPlaybooks || 15;
  const maxChains = params.maxChains || 10;
  try {
    let actorRows;
    if (params.actorIds && params.actorIds.length > 0) {
      const [rows] = await db.execute(
        sql`SELECT a.*, 
            (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) as abilityCount,
            (SELECT COUNT(*) FROM exploit_playbooks pb WHERE pb.actorId = a.actorId) as playbookCount,
            (SELECT COUNT(*) FROM attack_chains_catalog ac WHERE ac.actorId = a.actorId) as chainCount
          FROM threat_actors a 
          WHERE a.actorId IN (${sql.join(params.actorIds.map((id) => sql`${id}`), sql`,`)})
          LIMIT ${maxActors}`
      );
      actorRows = rows;
    } else {
      const [rows] = await db.execute(
        sql`SELECT a.*, 
            (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) as abilityCount,
            (SELECT COUNT(*) FROM exploit_playbooks pb WHERE pb.actorId = a.actorId) as playbookCount,
            (SELECT COUNT(*) FROM attack_chains_catalog ac WHERE ac.actorId = a.actorId) as chainCount
          FROM threat_actors a 
          WHERE a.active = 1
          ORDER BY (SELECT COUNT(*) FROM threat_actor_abilities ab WHERE ab.actorId = a.actorId) DESC
          LIMIT ${maxActors}`
      );
      actorRows = rows;
    }
    for (const actor of actorRows) {
      const aliases = actor.aliases ? typeof actor.aliases === "string" ? JSON.parse(actor.aliases) : actor.aliases : [];
      const targetSectors = actor.targetSectors ? typeof actor.targetSectors === "string" ? JSON.parse(actor.targetSectors) : actor.targetSectors : [];
      const tools = actor.tools ? typeof actor.tools === "string" ? JSON.parse(actor.tools) : actor.tools : [];
      const cves = actor.exploitedCves ? typeof actor.exploitedCves === "string" ? JSON.parse(actor.exploitedCves) : actor.exploitedCves : [];
      context.matchedActors.push({
        actorId: actor.actorId,
        name: actor.name,
        aliases: aliases.slice(0, 5),
        origin: actor.origin || "Unknown",
        motivation: actor.motivation || "Unknown",
        targetSectors: targetSectors.slice(0, 5),
        primaryTactics: actor.primaryTactics ? typeof actor.primaryTactics === "string" ? JSON.parse(actor.primaryTactics) : actor.primaryTactics : [],
        signatureTools: (Array.isArray(tools) ? tools : tools.map?.((t) => t.name || t) || []).slice(0, 10),
        knownCVEs: cves.slice(0, 10),
        abilityCount: Number(actor.abilityCount) || 0,
        playbookCount: Number(actor.playbookCount) || 0,
        chainCount: Number(actor.chainCount) || 0
      });
    }
    const actorIds = context.matchedActors.map((a) => a.actorId);
    if (actorIds.length > 0) {
      try {
        const [chainRows] = await db.execute(
          sql`SELECT ac.*, ta.name as actorName 
            FROM attack_chains_catalog ac 
            LEFT JOIN threat_actors ta ON ac.actorId = ta.actorId
            WHERE ac.actorId IN (${sql.join(actorIds.map((id) => sql`${id}`), sql`,`)})
            ORDER BY ac.confidence DESC
            LIMIT ${maxChains}`
        );
        for (const chain of chainRows) {
          const steps = typeof chain.steps === "string" ? JSON.parse(chain.steps) : chain.steps || [];
          const techniques = steps.map((s) => s.techniqueId).filter(Boolean);
          const phases = [...new Set(steps.map((s) => s.tactic || s.phase).filter(Boolean))];
          context.attackChains.push({
            chainName: chain.chainName || "Unnamed Chain",
            actorName: chain.actorName || "Unknown",
            objective: chain.objective || "",
            stepCount: steps.length,
            killChainPhases: phases,
            techniques,
            estimatedDuration: chain.estimatedDuration || `${steps.length * 5}m`,
            confidence: chain.confidence || "medium"
          });
        }
      } catch {
      }
    }
    if (actorIds.length > 0) {
      try {
        let platformFilter = "";
        if (params.targetPlatform) {
          platformFilter = params.targetPlatform;
        }
        const [pbRows] = await db.execute(
          sql`SELECT pb.*, ta.name as actorName 
            FROM exploit_playbooks pb 
            LEFT JOIN threat_actors ta ON pb.actorId = ta.actorId
            WHERE pb.actorId IN (${sql.join(actorIds.map((id) => sql`${id}`), sql`,`)})
            ORDER BY pb.confidence DESC, pb.successRate DESC
            LIMIT ${maxPlaybooks}`
        );
        for (const pb of pbRows) {
          const tools = typeof pb.toolsUsed === "string" ? JSON.parse(pb.toolsUsed) : pb.toolsUsed || [];
          const steps = typeof pb.steps === "string" ? JSON.parse(pb.steps) : pb.steps || [];
          const primaryStep = steps.find((s) => s.command || s.code) || steps[0];
          context.playbooks.push({
            name: pb.name || "Unnamed Playbook",
            actorName: pb.actorName || "Unknown",
            vulnClass: pb.vulnClass || "",
            techniqueId: pb.techniqueId || "",
            platform: pb.targetPlatform || "unknown",
            toolsUsed: tools.slice(0, 5),
            command: (primaryStep?.command || primaryStep?.code || "").substring(0, 200),
            confidence: pb.confidence || "medium"
          });
        }
      } catch {
      }
    }
    try {
      const [dfirRows] = await db.execute(
        sql`SELECT d.*, ta.name as actorName 
          FROM dfir_observations d 
          LEFT JOIN threat_actors ta ON d.actorId = ta.actorId
          ORDER BY d.confidence DESC
          LIMIT 20`
      );
      for (const obs of dfirRows) {
        const tools = typeof obs.toolsObserved === "string" ? JSON.parse(obs.toolsObserved) : obs.toolsObserved || [];
        context.dfirTechniques.push({
          techniqueId: obs.techniqueId || "",
          techniqueName: obs.techniqueName || "",
          tactic: obs.tactic || "",
          actorName: obs.actorName || "Unknown",
          description: (obs.description || "").substring(0, 200),
          toolsObserved: tools.slice(0, 5),
          reportSource: obs.reportSource || "Unknown",
          confidence: obs.confidence || "medium"
        });
      }
    } catch {
    }
    try {
      const [iocRows] = await db.execute(
        sql`SELECT * FROM ioc_ttp_mappings 
          WHERE confidence IN ('high', 'medium')
          ORDER BY confidence DESC
          LIMIT 15`
      );
      for (const mapping of iocRows) {
        context.iocIntelligence.push({
          iocType: mapping.iocType || "",
          techniqueId: mapping.techniqueId || "",
          techniqueName: mapping.techniqueName || "",
          tactic: mapping.tactic || "",
          reasoning: (mapping.reasoning || "").substring(0, 150),
          confidence: mapping.confidence || "medium"
        });
      }
    } catch {
    }
    try {
      const { matchPhishingExploits, getPhishingMitreTechniques } = await import("./phishing-exploits-X776TSMO.js");
      const techniques = getPhishingMitreTechniques();
      const matches = matchPhishingExploits({
        targetIndustry: params.targetSector,
        targetTechnology: params.targetTechStack,
        difficulty: "intermediate"
      });
      for (const match of (matches || []).slice(0, 5)) {
        context.phishingOptions.push({
          name: match.exploit.name,
          category: match.exploit.category,
          mitreId: match.exploit.mitreId,
          effectiveness: match.exploit.effectiveness,
          description: match.exploit.description.substring(0, 150),
          deliveryMethod: match.exploit.target === "email_template" ? "email" : match.exploit.target === "landing_page" ? "web" : "both"
        });
      }
    } catch {
    }
    const allTactics = /* @__PURE__ */ new Set();
    context.attackChains.forEach((c) => c.killChainPhases.forEach((p) => allTactics.add(p)));
    context.playbooks.forEach((p) => {
      if (p.techniqueId) allTactics.add(p.techniqueId.split(".")[0]);
    });
    context.dfirTechniques.forEach((d) => {
      if (d.tactic) allTactics.add(d.tactic);
    });
    context.matchedActors.forEach((a) => a.primaryTactics.forEach((t) => allTactics.add(t)));
    const recommendedModules = /* @__PURE__ */ new Set();
    for (const tactic of allTactics) {
      const modules = TACTIC_TO_EMBER_MODULES[tactic.toLowerCase()] || [];
      modules.forEach((m) => recommendedModules.add(m));
    }
    recommendedModules.add("ember.cognitive.attack_planner");
    recommendedModules.add("ember.cognitive.env_analyzer");
    recommendedModules.add("ember.cognitive.evasion_adapter");
    context.recommendedModules = [...recommendedModules];
    context.systemPromptContext = buildSystemPromptContext(context);
  } catch (err) {
    console.error(`[EmberCatalogIntel] Error building threat context: ${err.message}`);
  }
  return context;
}
function buildSystemPromptContext(ctx) {
  const sections = [];
  if (ctx.matchedActors.length > 0) {
    sections.push("=== THREAT ACTOR INTELLIGENCE ===");
    for (const actor of ctx.matchedActors) {
      sections.push(`Actor: ${actor.name} (${actor.origin})`);
      if (actor.aliases.length > 0) sections.push(`  Aliases: ${actor.aliases.join(", ")}`);
      sections.push(`  Motivation: ${actor.motivation}`);
      if (actor.targetSectors.length > 0) sections.push(`  Target Sectors: ${actor.targetSectors.join(", ")}`);
      if (actor.primaryTactics.length > 0) sections.push(`  Primary Tactics: ${actor.primaryTactics.join(", ")}`);
      if (actor.signatureTools.length > 0) sections.push(`  Signature Tools: ${actor.signatureTools.join(", ")}`);
      if (actor.knownCVEs.length > 0) sections.push(`  Known CVEs: ${actor.knownCVEs.join(", ")}`);
      sections.push(`  Catalog Data: ${actor.abilityCount} abilities, ${actor.playbookCount} playbooks, ${actor.chainCount} chains`);
      sections.push("");
    }
  }
  if (ctx.attackChains.length > 0) {
    sections.push("=== KNOWN ATTACK CHAINS ===");
    sections.push("Use these real-world attack chains to guide your operation planning:");
    for (const chain of ctx.attackChains) {
      sections.push(`Chain: ${chain.chainName} (${chain.actorName})`);
      sections.push(`  Objective: ${chain.objective}`);
      sections.push(`  Phases: ${chain.killChainPhases.join(" \u2192 ")}`);
      sections.push(`  Techniques: ${chain.techniques.join(", ")}`);
      sections.push(`  Steps: ${chain.stepCount}, Duration: ${chain.estimatedDuration}, Confidence: ${chain.confidence}`);
      sections.push("");
    }
  }
  if (ctx.playbooks.length > 0) {
    sections.push("=== EXPLOIT PLAYBOOKS (Real-World Commands) ===");
    sections.push("These are actual commands/scripts used by threat actors in the wild:");
    for (const pb of ctx.playbooks) {
      sections.push(`Playbook: ${pb.name} (${pb.actorName})`);
      sections.push(`  Vuln Class: ${pb.vulnClass} | Technique: ${pb.techniqueId} | Platform: ${pb.platform}`);
      if (pb.toolsUsed.length > 0) sections.push(`  Tools: ${pb.toolsUsed.join(", ")}`);
      if (pb.command) sections.push(`  Command: ${pb.command}`);
      sections.push("");
    }
  }
  if (ctx.dfirTechniques.length > 0) {
    sections.push("=== DFIR-OBSERVED TECHNIQUES ===");
    sections.push("These techniques were observed in real incident response investigations:");
    for (const dfir of ctx.dfirTechniques.slice(0, 10)) {
      sections.push(`${dfir.techniqueId} ${dfir.techniqueName} (${dfir.tactic}) \u2014 ${dfir.actorName}`);
      sections.push(`  ${dfir.description}`);
      if (dfir.toolsObserved.length > 0) sections.push(`  Tools: ${dfir.toolsObserved.join(", ")}`);
      sections.push(`  Source: ${dfir.reportSource} | Confidence: ${dfir.confidence}`);
    }
    sections.push("");
  }
  if (ctx.phishingOptions.length > 0) {
    sections.push("=== PHISHING INITIAL ACCESS OPTIONS ===");
    for (const phish of ctx.phishingOptions) {
      sections.push(`${phish.name} (${phish.mitreId}) \u2014 Effectiveness: ${phish.effectiveness}/10`);
      sections.push(`  ${phish.description}`);
      sections.push(`  Delivery: ${phish.deliveryMethod}`);
    }
    sections.push("");
  }
  if (ctx.iocIntelligence.length > 0) {
    sections.push("=== IOC-DERIVED TECHNIQUE INTELLIGENCE ===");
    for (const ioc of ctx.iocIntelligence.slice(0, 8)) {
      sections.push(`${ioc.techniqueId} ${ioc.techniqueName} (from ${ioc.iocType} analysis)`);
      sections.push(`  ${ioc.reasoning}`);
    }
    sections.push("");
  }
  if (sections.length === 0) {
    return "No threat actor intelligence available from catalog. Proceed with standard methodology.";
  }
  return [
    "THREAT ACTOR INTELLIGENCE BRIEFING",
    "Use this intelligence to emulate real-world adversary behavior.",
    "Prioritize techniques and tools that match the threat actors below.",
    "Your operation should be indistinguishable from a real attack by these actors.",
    "",
    ...sections
  ].join("\n");
}
async function generateActorEmulationPlan(params) {
  const ctx = await buildEmberThreatContext({
    actorIds: [params.actorId],
    targetPlatform: params.targetPlatform,
    maxPlaybooks: 20,
    maxChains: 5
  });
  if (ctx.matchedActors.length === 0) return null;
  const actor = ctx.matchedActors[0];
  const phases = [];
  if (ctx.attackChains.length > 0) {
    const chain = ctx.attackChains[0];
    for (const phase of chain.killChainPhases) {
      const matchingPlaybook = ctx.playbooks.find(
        (p) => p.techniqueId && chain.techniques.includes(p.techniqueId)
      );
      const modules = TACTIC_TO_EMBER_MODULES[phase] || [];
      phases.push({
        phase,
        technique: matchingPlaybook?.vulnClass || phase,
        techniqueId: matchingPlaybook?.techniqueId || "",
        tool: matchingPlaybook?.toolsUsed[0] || "manual",
        command: matchingPlaybook?.command || "",
        emberModule: modules[0] || "ember.cognitive.attack_planner",
        riskLevel: ["initial-access", "execution", "privilege-escalation"].includes(phase) ? "high" : "medium"
      });
    }
  } else {
    for (const tactic of actor.primaryTactics.slice(0, 6)) {
      const modules = TACTIC_TO_EMBER_MODULES[tactic] || [];
      const matchingPlaybook = ctx.playbooks.find((p) => p.platform === params.targetPlatform);
      phases.push({
        phase: tactic,
        technique: matchingPlaybook?.vulnClass || tactic,
        techniqueId: matchingPlaybook?.techniqueId || "",
        tool: matchingPlaybook?.toolsUsed[0] || "manual",
        command: matchingPlaybook?.command || "",
        emberModule: modules[0] || "ember.cognitive.attack_planner",
        riskLevel: "medium"
      });
    }
  }
  return {
    operationName: `${actor.name} Emulation \u2014 ${params.objective}`,
    actorName: actor.name,
    phases,
    estimatedDuration: `${phases.length * 10}m`,
    recommendedModules: ctx.recommendedModules
  };
}
async function getEmberThreatPromptEnhancement(params) {
  const ctx = await buildEmberThreatContext(params);
  return ctx.systemPromptContext;
}
var TACTIC_TO_EMBER_MODULES;
var init_ember_catalog_intelligence = __esm({
  "server/lib/ember-catalog-intelligence.ts"() {
    TACTIC_TO_EMBER_MODULES = {
      "reconnaissance": ["ember.cognitive.env_analyzer"],
      "initial-access": ["ember.cognitive.attack_planner"],
      "execution": ["ember.exec.shell", "ember.exec.powershell"],
      "persistence": ["ember.persist.registry", "ember.persist.scheduled_task", "ember.persist.startup_folder"],
      "privilege-escalation": ["ember.privesc.token_manipulation", "ember.privesc.uac_bypass", "ember.privesc.suid_exploiter", "ember.privesc.kernel_exploit"],
      "defense-evasion": ["ember.evasion.amsi_bypass", "ember.evasion.etw_patch", "ember.evasion.log_cleaner", "ember.evasion.timestomp"],
      "credential-access": ["ember.cred.lsass_dump", "ember.cred.sam_extract", "ember.cred.kerberoast", "ember.cred.token_steal"],
      "discovery": ["ember.cognitive.env_analyzer"],
      "lateral-movement": ["ember.lateral.psexec", "ember.lateral.wmi_exec", "ember.lateral.ssh_pivot", "ember.lateral.pass_the_hash", "ember.lateral.rdp_hijack"],
      "collection": ["ember.collect.file_harvest", "ember.collect.screenshot", "ember.collect.keylogger", "ember.collect.clipboard"],
      "command-and-control": [],
      "exfiltration": ["ember.exfil.https_chunked", "ember.exfil.dns_tunnel", "ember.exfil.steganographic"],
      "impact": []
    };
  }
});
init_ember_catalog_intelligence();
export {
  buildEmberThreatContext,
  generateActorEmulationPlan,
  getEmberThreatPromptEnhancement
};
