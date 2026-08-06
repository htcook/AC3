/**
 * Phishing Catalog Integration
 * 
 * Bridges the phishing-exploits knowledge base and GoPhish campaign generator
 * into the enriched threat actor catalog, enabling:
 * 1. Actor-attributed phishing TTPs (lure themes, delivery mechanisms, payload types)
 * 2. GoPhish campaign generation informed by actor-specific social engineering patterns
 * 3. IOC-to-TTP reverse engineering for phishing indicators (domains, sender patterns)
 * 4. Ember integration for actor-emulated phishing exercises
 */

import { sql, eq } from "drizzle-orm";
import {
  exploitPlaybooks,
  dfirObservations,
  iocTtpMappings,
  threatActors,
  threatActorAbilities,
  threatActorIocs,
} from "../../drizzle/schema";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface ActorPhishingProfile {
  actorId: string;
  actorName: string;
  /** Preferred lure themes (e.g., "invoice", "password reset", "HR notification") */
  lureThemes: string[];
  /** Delivery mechanisms (e.g., "spearphishing attachment", "link-based", "watering hole") */
  deliveryMechanisms: string[];
  /** Payload types (e.g., "macro-enabled doc", "HTML smuggling", "ISO file") */
  payloadTypes: string[];
  /** MITRE techniques used in phishing campaigns */
  mitreTechniques: Array<{ id: string; name: string; tactic: string }>;
  /** Known phishing tools (e.g., "Gophish", "Evilginx", "Modlishka") */
  tools: string[];
  /** Historical campaign patterns */
  campaignPatterns: CampaignPattern[];
  /** Matching phishing exploits from the knowledge base */
  matchingExploits: Array<{ id: string; name: string; category: string; effectiveness: number }>;
}

export interface CampaignPattern {
  name: string;
  description: string;
  lureTheme: string;
  deliveryMethod: string;
  payloadType: string;
  targetProfile: string;
  successIndicators: string[];
  detectionIndicators: string[];
}

export interface PhishingIOCAnalysis {
  iocType: "domain" | "email" | "url" | "file_hash" | "sender_pattern";
  iocValue: string;
  impliedTechniques: Array<{
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    confidence: string;
    reasoning: string;
  }>;
  actorAttribution: string[];
  campaignIndicators: string[];
}

// ─── Actor Phishing TTP Knowledge Base ───────────────────────────────────────

const ACTOR_PHISHING_PATTERNS: Record<string, Partial<ActorPhishingProfile>> = {
  "APT28": {
    lureThemes: ["military intelligence", "NATO documents", "government policy", "security conference invitations"],
    deliveryMechanisms: ["spearphishing attachment", "spearphishing link", "OAuth consent phishing"],
    payloadTypes: ["macro-enabled Word docs", "RTF exploits", "HTML Application (HTA)", "LNK files"],
    tools: ["Gophish", "custom phishing framework"],
    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access" },
      { id: "T1598.003", name: "Spearphishing Service", tactic: "reconnaissance" },
    ],
  },
  "APT29": {
    lureThemes: ["diplomatic communications", "COVID-19 updates", "embassy notifications", "think tank reports"],
    deliveryMechanisms: ["spearphishing link", "compromised legitimate sites", "supply chain via email"],
    payloadTypes: ["ISO files with LNK", "HTML smuggling", "encoded PowerShell droppers"],
    tools: ["custom phishing infrastructure", "Cobalt Strike"],
    mitreTechniques: [
      { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access" },
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1204.001", name: "Malicious Link", tactic: "execution" },
      { id: "T1204.002", name: "Malicious File", tactic: "execution" },
    ],
  },
  "Lazarus Group": {
    lureThemes: ["job offers", "cryptocurrency opportunities", "blockchain developer positions", "salary documents"],
    deliveryMechanisms: ["spearphishing attachment", "social media outreach", "fake job portals"],
    payloadTypes: ["trojanized applications", "macro-enabled Excel", "weaponized PDFs"],
    tools: ["custom tools", "social engineering via LinkedIn"],
    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1566.003", name: "Spearphishing via Service", tactic: "initial-access" },
      { id: "T1204.002", name: "Malicious File", tactic: "execution" },
    ],
  },
  "FIN7": {
    lureThemes: ["restaurant orders", "SEC filings", "legal complaints", "vendor invoices"],
    deliveryMechanisms: ["spearphishing attachment", "phone call + email follow-up"],
    payloadTypes: ["macro-enabled Word/Excel", "JavaScript droppers", "LNK files"],
    tools: ["Carbanak", "custom phishing framework"],
    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1204.002", name: "Malicious File", tactic: "execution" },
      { id: "T1059.007", name: "JavaScript", tactic: "execution" },
    ],
  },
  "Kimsuky": {
    lureThemes: ["academic research", "North Korea policy", "think tank invitations", "conference papers"],
    deliveryMechanisms: ["spearphishing attachment", "credential harvesting pages", "Webmail phishing"],
    payloadTypes: ["macro-enabled documents", "CHM files", "BabyShark scripts"],
    tools: ["custom credential harvesters", "modified phishing kits"],
    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1566.002", name: "Spearphishing Link", tactic: "initial-access" },
      { id: "T1598.003", name: "Spearphishing Service", tactic: "reconnaissance" },
    ],
  },
  "Emotet": {
    lureThemes: ["payment reminders", "shipping notifications", "invoice attachments", "reply-chain hijacking"],
    deliveryMechanisms: ["mass spearphishing", "thread hijacking", "malicious URLs in emails"],
    payloadTypes: ["macro-enabled Word/Excel", "password-protected ZIP", "XLS 4.0 macros"],
    tools: ["Emotet loader", "mass mailer infrastructure"],
    mitreTechniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access" },
      { id: "T1204.002", name: "Malicious File", tactic: "execution" },
      { id: "T1059.005", name: "Visual Basic", tactic: "execution" },
    ],
  },
};

// ─── Phishing IOC Pattern Analysis ───────────────────────────────────────────

const PHISHING_IOC_PATTERNS: Array<{
  pattern: RegExp;
  iocType: "domain" | "email" | "url" | "sender_pattern";
  impliedTechniques: Array<{ techniqueId: string; techniqueName: string; tactic: string }>;
  confidence: string;
  reasoning: string;
}> = [
  {
    pattern: /\.(tk|ml|ga|cf|gq|xyz|top|buzz|click|link)$/i,
    iocType: "domain",
    impliedTechniques: [{ techniqueId: "T1566.002", techniqueName: "Spearphishing Link", tactic: "initial-access" }],
    confidence: "medium",
    reasoning: "Free/cheap TLD commonly used in phishing infrastructure",
  },
  {
    pattern: /login|signin|verify|secure|account|update|confirm/i,
    iocType: "domain",
    impliedTechniques: [
      { techniqueId: "T1566.002", techniqueName: "Spearphishing Link", tactic: "initial-access" },
      { techniqueId: "T1598.003", techniqueName: "Spearphishing Service", tactic: "reconnaissance" },
    ],
    confidence: "high",
    reasoning: "Credential harvesting domain pattern — mimics legitimate login pages",
  },
  {
    pattern: /noreply|no-reply|donotreply|notification|alert/i,
    iocType: "sender_pattern",
    impliedTechniques: [{ techniqueId: "T1566.001", techniqueName: "Spearphishing Attachment", tactic: "initial-access" }],
    confidence: "low",
    reasoning: "Automated notification sender pattern — may be spoofed for phishing",
  },
  {
    pattern: /\.html?\.zip$|\.iso$|\.img$|\.vhd$/i,
    iocType: "url",
    impliedTechniques: [
      { techniqueId: "T1204.002", techniqueName: "Malicious File", tactic: "execution" },
      { techniqueId: "T1553.005", techniqueName: "Mark-of-the-Web Bypass", tactic: "defense-evasion" },
    ],
    confidence: "high",
    reasoning: "Container file delivery — bypasses Mark-of-the-Web protections",
  },
];

// ─── Core Functions ──────────────────────────────────────────────────────────

/**
 * Build an actor-specific phishing profile by combining:
 * 1. Hardcoded actor phishing patterns (known TTPs)
 * 2. Phishing IOCs from the threat actor catalog
 * 3. Matching exploits from the phishing-exploits knowledge base
 * 4. DFIR observations related to phishing
 */
export async function buildActorPhishingProfile(actorId: string): Promise<ActorPhishingProfile | null> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return null;
  
  // Get actor info
  const [actor] = await db.select().from(threatActors).where(eq(threatActors.actorId, actorId)).limit(1);
  if (!actor) return null;
  
  const actorName = actor.name || actorId;
  
  // Start with known patterns
  const knownPatterns = ACTOR_PHISHING_PATTERNS[actorName] || {};
  
  const profile: ActorPhishingProfile = {
    actorId,
    actorName,
    lureThemes: knownPatterns.lureThemes || [],
    deliveryMechanisms: knownPatterns.deliveryMechanisms || [],
    payloadTypes: knownPatterns.payloadTypes || [],
    mitreTechniques: knownPatterns.mitreTechniques || [],
    tools: knownPatterns.tools || [],
    campaignPatterns: [],
    matchingExploits: [],
  };
  
  // Enrich from phishing-related IOCs
  try {
    const [iocRows] = await db.execute(
      sql`SELECT * FROM threat_actor_iocs 
        WHERE actorId = ${actorId} 
        AND (type LIKE '%phish%' OR type LIKE '%domain%' OR type LIKE '%email%' OR type LIKE '%url%')
        LIMIT 50`
    );
    
    for (const ioc of (iocRows as any[])) {
      // Analyze each IOC for phishing patterns
      for (const pattern of PHISHING_IOC_PATTERNS) {
        if (pattern.pattern.test(ioc.value || "")) {
          for (const tech of pattern.impliedTechniques) {
            if (!profile.mitreTechniques.find(t => t.id === tech.techniqueId)) {
              profile.mitreTechniques.push({ id: tech.techniqueId, name: tech.techniqueName, tactic: tech.tactic });
            }
          }
        }
      }
    }
  } catch { /* IOC table may be empty */ }
  
  // Enrich from DFIR observations related to phishing
  try {
    const [dfirRows] = await db.execute(
      sql`SELECT * FROM dfir_observations 
        WHERE actorId = ${actorId} 
        AND (tactic = 'initial-access' OR techniqueId LIKE 'T1566%' OR techniqueId LIKE 'T1598%')
        LIMIT 20`
    );
    
    for (const obs of (dfirRows as any[])) {
      const tools = typeof obs.toolsObserved === "string" ? JSON.parse(obs.toolsObserved) : (obs.toolsObserved || []);
      for (const tool of tools) {
        if (!profile.tools.includes(tool)) profile.tools.push(tool);
      }
    }
  } catch { /* DFIR table may be empty */ }
  
  // Match phishing exploits from the knowledge base
  try {
    const { matchPhishingExploits } = await import("./phishing-exploits");
    const matches = matchPhishingExploits({
      targetIndustry: actor.targetSectors ? 
        (typeof actor.targetSectors === "string" ? JSON.parse(actor.targetSectors) : actor.targetSectors)[0] : undefined,
    });
    
    for (const match of (matches || []).slice(0, 10)) {
      profile.matchingExploits.push({
        id: match.exploit.id,
        name: match.exploit.name,
        category: match.exploit.category,
        effectiveness: match.exploit.effectiveness,
      });
    }
  } catch { /* phishing module may not be available */ }
  
  // Build campaign patterns from combined data
  for (const lure of profile.lureThemes.slice(0, 3)) {
    for (const delivery of profile.deliveryMechanisms.slice(0, 2)) {
      profile.campaignPatterns.push({
        name: `${actorName} — ${lure}`,
        description: `${actorName}-style campaign using ${lure} lure via ${delivery}`,
        lureTheme: lure,
        deliveryMethod: delivery,
        payloadType: profile.payloadTypes[0] || "document",
        targetProfile: (actor.targetSectors ? 
          (typeof actor.targetSectors === "string" ? JSON.parse(actor.targetSectors) : actor.targetSectors).join(", ") : "general"),
        successIndicators: ["credential capture", "payload execution", "callback to C2"],
        detectionIndicators: ["suspicious sender domain", "URL reputation check", "attachment analysis"],
      });
    }
  }
  
  return profile;
}

/**
 * Analyze phishing IOCs and reverse-engineer the implied TTPs.
 */
export function analyzePhishingIOCs(iocs: Array<{ type: string; value: string }>): PhishingIOCAnalysis[] {
  const results: PhishingIOCAnalysis[] = [];
  
  for (const ioc of iocs) {
    const analysis: PhishingIOCAnalysis = {
      iocType: (ioc.type as any) || "domain",
      iocValue: ioc.value,
      impliedTechniques: [],
      actorAttribution: [],
      campaignIndicators: [],
    };
    
    // Match against known patterns
    for (const pattern of PHISHING_IOC_PATTERNS) {
      if (pattern.pattern.test(ioc.value)) {
        for (const tech of pattern.impliedTechniques) {
          if (!analysis.impliedTechniques.find(t => t.techniqueId === tech.techniqueId)) {
            analysis.impliedTechniques.push({
              ...tech,
              confidence: pattern.confidence,
              reasoning: pattern.reasoning,
            });
          }
        }
      }
    }
    
    // Check against known actor patterns
    for (const [actorName, patterns] of Object.entries(ACTOR_PHISHING_PATTERNS)) {
      const allPatterns = [
        ...(patterns.lureThemes || []),
        ...(patterns.payloadTypes || []),
        ...(patterns.tools || []),
      ];
      const iocLower = ioc.value.toLowerCase();
      if (allPatterns.some(p => iocLower.includes(p.toLowerCase().split(" ")[0]))) {
        analysis.actorAttribution.push(actorName);
      }
    }
    
    if (analysis.impliedTechniques.length > 0 || analysis.actorAttribution.length > 0) {
      results.push(analysis);
    }
  }
  
  return results;
}

/**
 * Generate a GoPhish campaign configuration informed by actor-specific phishing TTPs.
 */
export async function generateActorPhishingCampaign(params: {
  actorId: string;
  targetEmails?: string[];
  targetOrg?: string;
  campaignObjective?: string;
}): Promise<{
  campaignName: string;
  actorProfile: ActorPhishingProfile | null;
  emailTemplate: {
    subject: string;
    body: string;
    senderName: string;
    senderEmail: string;
  };
  landingPage: {
    url: string;
    type: string;
  };
  deliverySchedule: {
    sendAt: string;
    batchSize: number;
    intervalMinutes: number;
  };
  mitreTechniques: string[];
  detectionIndicators: string[];
} | null> {
  const profile = await buildActorPhishingProfile(params.actorId);
  if (!profile) return null;
  
  const lureTheme = profile.lureThemes[0] || "security update notification";
  const deliveryMethod = profile.deliveryMechanisms[0] || "spearphishing link";
  
  return {
    campaignName: `${profile.actorName} Emulation — ${lureTheme}`,
    actorProfile: profile,
    emailTemplate: {
      subject: `[Action Required] ${lureTheme.charAt(0).toUpperCase() + lureTheme.slice(1)}`,
      body: `This is a template for a ${profile.actorName}-style phishing campaign using "${lureTheme}" as the lure theme. The delivery method is "${deliveryMethod}". Customize with target-specific details.`,
      senderName: "IT Security Team",
      senderEmail: "security@${targetDomain}",
    },
    landingPage: {
      url: "/phishing/landing/${campaignId}",
      type: deliveryMethod.includes("link") ? "credential_harvest" : "file_download",
    },
    deliverySchedule: {
      sendAt: "business_hours",
      batchSize: 10,
      intervalMinutes: 15,
    },
    mitreTechniques: profile.mitreTechniques.map(t => t.id),
    detectionIndicators: [
      "Suspicious sender domain mismatch",
      "URL reputation check failure",
      "Attachment sandbox analysis",
      "Email header anomalies",
    ],
  };
}

/**
 * Store actor phishing profile data into the catalog tables for persistence.
 */
export async function persistActorPhishingProfile(profile: ActorPhishingProfile): Promise<boolean> {
  const { getDb } = await import("../db");
  const db = await getDb();
  if (!db) return false;
  
  try {
    // Store phishing playbooks
    for (const pattern of profile.campaignPatterns) {
      await db.insert(exploitPlaybooks).values({
        actorId: profile.actorId,
        name: pattern.name,
        description: pattern.description,
        vulnClass: "social-engineering",
        techniqueId: profile.mitreTechniques[0]?.id || "T1566",
        techniqueName: profile.mitreTechniques[0]?.name || "Phishing",
        tactic: "initial-access",
        targetPlatform: "cross-platform",
        steps: JSON.stringify([
          { phase: "preparation", description: `Prepare ${pattern.lureTheme} lure` },
          { phase: "delivery", description: `Send via ${pattern.deliveryMethod}` },
          { phase: "exploitation", description: `Deploy ${pattern.payloadType} payload` },
        ]),
        toolsUsed: JSON.stringify(profile.tools),
        prerequisites: JSON.stringify(["target email addresses", "phishing infrastructure"]),
        confidence: "high",
        source: "actor-phishing-profile",
      }).onDuplicateKeyUpdate({ set: { updatedAt: new Date() } });
    }
    
    // Store phishing-related abilities
    for (const technique of profile.mitreTechniques) {
      const existingAbility = await db.execute(
        sql`SELECT 1 FROM threat_actor_abilities 
          WHERE actorId = ${profile.actorId} AND techniqueId = ${technique.id} 
          LIMIT 1`
      );
      
      if (!(existingAbility[0] as any[])?.length) {
        await db.insert(threatActorAbilities).values({
          actorId: profile.actorId,
          abilityId: `phish-${profile.actorId}-${technique.id}`,
          name: `${profile.actorName}: ${technique.name}`,
          tactic: technique.tactic,
          techniqueId: technique.id,
          platforms: JSON.stringify(["cross-platform"]),
        });
      }
    }
    
    return true;
  } catch (err: any) {
    console.error(`[PhishingCatalog] Error persisting profile for ${profile.actorId}: ${err.message}`);
    return false;
  }
}
