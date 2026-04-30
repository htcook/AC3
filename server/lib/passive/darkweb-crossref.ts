/**
 * Dark Web Cross-Reference Module
 * 
 * Queries local underground intel tables (populated by feed scheduler)
 * for domain-specific matches during DI scans. This bridges the gap
 * between the ongoing feed ingestion and per-domain intelligence.
 * 
 * Tables queried:
 *   - underground_intel_events: ransomware victims, IAB listings, data leaks, exploit mentions
 *   - credential_exposures: breach databases with domain-specific credential counts
 *   - threat_actors + threat_group_events: threat group attribution history
 *   - threat_actor_iocs: IOC cross-reference against discovered assets
 * 
 * No external API calls — queries only the local database.
 */
import { createHash } from "crypto";
import { getDb } from "../../db";
import {
  undergroundIntelEvents,
  credentialExposures,
  threatActors,
  threatGroupEvents,
  threatActorIocs,
} from "../../../drizzle/schema";
import { sql, like, or, eq, inArray } from "drizzle-orm";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// ─── Credential Source Classification ────────────────────────────────────────
// Determines if a leaked credential came from a breach of the target's own
// infrastructure (1st-party) or from an employee reusing their corporate
// email on an external service that was breached (3rd-party).

interface CredentialSourceClassification {
  type: "first_party" | "third_party" | "unknown";
  confidence: number;
  reasoning: string;
}

function classifyCredentialSource(
  targetDomain: string,
  breachName: string,
  breachDomain?: string | null,
  description?: string | null,
): CredentialSourceClassification {
  const baseDomain = targetDomain.replace(/^www\./, "").toLowerCase();
  const orgName = baseDomain.split(".")[0];
  const breachLower = (breachName || "").toLowerCase();
  const descLower = (description || "").toLowerCase();
  const breachDomainLower = (breachDomain || "").toLowerCase();

  // ── 1st-party indicators: breach of the target's own systems ──
  // Direct domain match in breach name or breach domain
  if (breachDomainLower.includes(baseDomain) || breachLower.includes(baseDomain)) {
    return {
      type: "first_party",
      confidence: 90,
      reasoning: `Breach "${breachName}" directly references target domain ${baseDomain}`,
    };
  }

  // Org name exact match in breach name (e.g., "Acme Corp" breach for acme.com)
  if (orgName.length > 3 && breachLower.includes(orgName)) {
    // Check it's not a substring of a longer word
    const idx = breachLower.indexOf(orgName);
    const before = idx > 0 ? breachLower[idx - 1] : " ";
    const after = idx + orgName.length < breachLower.length ? breachLower[idx + orgName.length] : " ";
    if (/[\s\-_.,]/.test(before) && /[\s\-_.,]/.test(after)) {
      return {
        type: "first_party",
        confidence: 75,
        reasoning: `Breach "${breachName}" matches organization name "${orgName}" — likely a breach of the target's own systems`,
      };
    }
  }

  // ── 3rd-party indicators: employee credential reuse on external service ──
  // Well-known third-party services
  const thirdPartyServices = [
    "linkedin", "facebook", "adobe", "dropbox", "myspace", "tumblr",
    "canva", "zynga", "dubsmash", "myfitnesspal", "chegg", "animoto",
    "evite", "coffeemeetsbagel", "500px", "sharelatex", "verifications.io",
    "collection #", "antipublic", "exploit.in", "combolist", "naz.api",
    "telegram", "discord", "twitter", "snapchat", "instagram", "tiktok",
    "spotify", "netflix", "hulu", "lastfm", "last.fm", "dailymotion",
    "bitly", "imgur", "patreon", "kickstarter", "wattpad", "mathway",
    "livejournal", "habbo", "neopets", "gaia online", "xsplit",
    "deezer", "appen", "gravatar", "pixlr", "123rf", "stockx",
    "wyzant", "poshmark", "minted", "shein", "slickdeals",
    "marriott", "equifax", "experian", "t-mobile", "att", "verizon",
    "yahoo", "hotmail", "gmail", "outlook", "aol",
  ];

  for (const svc of thirdPartyServices) {
    if (breachLower.includes(svc)) {
      return {
        type: "third_party",
        confidence: 95,
        reasoning: `Breach "${breachName}" is a known third-party service (${svc}) — employee credential reuse, not a breach of ${baseDomain}`,
      };
    }
  }

  // Generic combo lists / aggregated dumps are always 3rd-party
  const comboIndicators = ["combo", "collection", "compilation", "aggregated", "antipublic", "exploit.in", "naz.api", "stealer log"];
  for (const indicator of comboIndicators) {
    if (breachLower.includes(indicator) || descLower.includes(indicator)) {
      return {
        type: "third_party",
        confidence: 85,
        reasoning: `Breach "${breachName}" appears to be an aggregated credential dump — credentials likely harvested from multiple third-party breaches`,
      };
    }
  }

  // If breach domain is set and doesn't match target, it's 3rd-party
  if (breachDomainLower && !breachDomainLower.includes(baseDomain) && !breachDomainLower.includes(orgName)) {
    return {
      type: "third_party",
      confidence: 80,
      reasoning: `Breach "${breachName}" originated from ${breachDomain}, not from ${baseDomain} — employee credential reuse`,
    };
  }

  return {
    type: "unknown",
    confidence: 40,
    reasoning: `Unable to determine if "${breachName}" is a direct breach of ${baseDomain} or a third-party service — manual review recommended`,
  };
}

// ─── Threat Group Profile Builder ────────────────────────────────────────────

interface ThreatGroupProfile {
  actorId: string;
  name: string;
  aliases: string[];
  actorType: string;
  origin: string | null;
  description: string | null;
  motivation: string | null;
  threatLevel: string | null;
  sophistication: string | null;
  targetSectors: any;
  targetRegions: any;
  techniques: any;
  tools: any;
  malware: any;
  firstSeen: string | null;
  lastActive: string | null;
  // Events attributed to this group that mention the target domain
  attributedEvents: Array<{
    eventType: string;
    title: string;
    description: string | null;
    severity: string | null;
    victimName: string | null;
    victimSector: string | null;
    victimCountry: string | null;
    mitreTechniques: any;
    eventDate: string | null;
    source: string | null;
  }>;
  // IOCs associated with this group
  relevantIocs: Array<{
    iocType: string;
    value: string;
    description: string | null;
    confidence: string | null;
    firstSeen: string | null;
    lastSeen: string | null;
  }>;
}

export const darkwebCrossrefConnector: PassiveConnector = {
  name: "darkweb_crossref",
  description: "Cross-references target domain against local underground intel database — ransomware listings, data leaks, credential breaches, IAB access sales, threat group attribution",
  requiresApiKey: false,
  freeUrl: undefined,

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const now = new Date();
    const source = "darkweb_crossref";
    const signal = config?.signal;

    // Early abort check
    if (signal?.aborted) {
      return { connector: source, domain, observations: [], errors: ['Aborted before start'], durationMs: 0, rateLimited: false };
    }

    try {
      const db = await getDb();
      if (!db) {
        errors.push("Database not available for darkweb cross-reference");
        return { connector: source, domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
      }

      const baseDomain = domain.replace(/^www\./, "");
      const orgName = baseDomain.split(".")[0];

      // ═══════════════════════════════════════════════════════════════
      // STAGE 1: Underground Intel Events
      // ═══════════════════════════════════════════════════════════════
      const uieResults = await db
        .select({
          id: undergroundIntelEvents.id,
          category: undergroundIntelEvents.uieCategory,
          source: undergroundIntelEvents.uieSource,
          title: undergroundIntelEvents.uieTitle,
          description: undergroundIntelEvents.uieDescription,
          severity: undergroundIntelEvents.uieSeverity,
          actorName: undergroundIntelEvents.uieActorName,
          actorAliases: undergroundIntelEvents.uieActorAliases,
          victimName: undergroundIntelEvents.uieVictimName,
          victimSector: undergroundIntelEvents.uieVictimSector,
          victimCountry: undergroundIntelEvents.uieVictimCountry,
          eventDate: undergroundIntelEvents.uieEventDate,
          ingestedAt: undergroundIntelEvents.uieIngestedAt,
          tags: undergroundIntelEvents.uieTags,
          mitreTechniques: undergroundIntelEvents.uieMitreTechniques,
        })
        .from(undergroundIntelEvents)
        .where(
          or(
            like(undergroundIntelEvents.uieVictimName, `%${baseDomain}%`),
            like(undergroundIntelEvents.uieVictimName, `%${orgName}%`),
            like(undergroundIntelEvents.uieTitle, `%${baseDomain}%`),
            like(undergroundIntelEvents.uieDescription, `%${baseDomain}%`),
            like(undergroundIntelEvents.uieIocValue, `%${baseDomain}%`),
          )
        )
        .limit(100);

      // Abort check between stages
      if (signal?.aborted) {
        return { connector: source, domain, observations, errors: ['Aborted after stage 1'], durationMs: Date.now() - start, rateLimited: false };
      }

      // ═══════════════════════════════════════════════════════════════
      // STAGE 2: Credential Exposures (with source classification)
      // ═══════════════════════════════════════════════════════════════
      const ceResults = await db
        .select({
          id: credentialExposures.id,
          source: credentialExposures.ceSource,
          breachName: credentialExposures.ceBreachName,
          breachDate: credentialExposures.ceBreachDate,
          breachDomain: credentialExposures.ceDomain,
          emailCount: credentialExposures.ceEmailCount,
          totalRecords: credentialExposures.ceTotalRecords,
          dataClasses: credentialExposures.ceDataClasses,
          actorName: credentialExposures.ceActorName,
          severity: credentialExposures.ceSeverity,
          isVerified: credentialExposures.ceIsVerified,
          isSpamList: credentialExposures.ceIsSpamList,
          description: credentialExposures.ceDescription,
        })
        .from(credentialExposures)
        .where(
          or(
            like(credentialExposures.ceDomain, `%${baseDomain}%`),
            like(credentialExposures.ceBreachName, `%${orgName}%`),
          )
        )
        .limit(100);

      // Abort check between stages
      if (signal?.aborted) {
        return { connector: source, domain, observations, errors: ['Aborted after stage 2'], durationMs: Date.now() - start, rateLimited: false };
      }

      // ═══════════════════════════════════════════════════════════════
      // STAGE 3: Threat Group Attribution History
      // ═══════════════════════════════════════════════════════════════
      // Collect unique actor names from underground intel events
      const actorNames = Array.from(new Set(
        uieResults.map(e => e.actorName).filter(Boolean) as string[]
      ));

      const threatGroupProfiles: ThreatGroupProfile[] = [];

      if (actorNames.length > 0) {
        // Look up threat actors by name match
        const actorRows = await db
          .select({
            actorId: threatActors.actorId,
            name: threatActors.name,
            aliases: threatActors.aliases,
            actorType: threatActors.actorType,
            origin: threatActors.origin,
            description: threatActors.description,
            motivation: threatActors.motivation,
            threatLevel: threatActors.threatLevel,
            sophistication: threatActors.sophistication,
            targetSectors: threatActors.targetSectors,
            targetRegions: threatActors.targetRegions,
            techniques: threatActors.techniques,
            tools: threatActors.tools,
            malware: threatActors.malware,
            firstSeen: threatActors.firstSeen,
            lastActive: threatActors.lastActive,
          })
          .from(threatActors)
          .where(
            or(
              ...actorNames.map(name => like(threatActors.name, `%${name}%`)),
              ...actorNames.flatMap(name => {
                // Also search aliases JSON column
                return [like(sql`CAST(${threatActors.aliases} AS CHAR)`, `%${name}%`)];
              }),
            )
          )
          .limit(20);

        // For each matched actor, get their event history and IOCs
        for (const actor of actorRows) {
          // Get events attributed to this group
          const events = await db
            .select({
              eventType: threatGroupEvents.eventType,
              title: threatGroupEvents.tgeTitle,
              description: threatGroupEvents.tgeDescription,
              severity: threatGroupEvents.tgeSeverity,
              victimName: threatGroupEvents.tgeVictimName,
              victimSector: threatGroupEvents.tgeVictimSector,
              victimCountry: threatGroupEvents.tgeVictimCountry,
              mitreTechniques: threatGroupEvents.tgeMitreTechniques,
              eventDate: threatGroupEvents.eventDate,
              source: threatGroupEvents.tgeSource,
            })
            .from(threatGroupEvents)
            .where(eq(threatGroupEvents.tgeActorId, actor.actorId))
            .limit(50);

          // Get IOCs for this group
          const iocs = await db
            .select({
              iocType: threatActorIocs.iocType,
              value: threatActorIocs.value,
              description: threatActorIocs.description,
              confidence: threatActorIocs.iocConfidence,
              firstSeen: threatActorIocs.iocFirstSeen,
              lastSeen: threatActorIocs.iocLastSeen,
            })
            .from(threatActorIocs)
            .where(eq(threatActorIocs.actorId, actor.actorId))
            .limit(30);

          // Filter events that mention the target domain/org
          const domainRelatedEvents = events.filter(e => {
            const text = `${e.victimName || ""} ${e.title || ""} ${e.description || ""}`.toLowerCase();
            return text.includes(baseDomain) || text.includes(orgName);
          });

          // Filter IOCs that reference the target domain
          const domainRelatedIocs = iocs.filter(i => {
            const val = (i.value || "").toLowerCase();
            return val.includes(baseDomain);
          });

          threatGroupProfiles.push({
            actorId: actor.actorId,
            name: actor.name,
            aliases: Array.isArray(actor.aliases) ? actor.aliases : [],
            actorType: actor.actorType,
            origin: actor.origin,
            description: actor.description,
            motivation: actor.motivation,
            threatLevel: actor.threatLevel,
            sophistication: actor.sophistication,
            targetSectors: actor.targetSectors,
            targetRegions: actor.targetRegions,
            techniques: actor.techniques,
            tools: actor.tools,
            malware: actor.malware,
            firstSeen: actor.firstSeen,
            lastActive: actor.lastActive,
            attributedEvents: domainRelatedEvents.length > 0 ? domainRelatedEvents : events.slice(0, 10),
            relevantIocs: domainRelatedIocs.length > 0 ? domainRelatedIocs : iocs.slice(0, 10),
          });
        }
      }

      // ═══════════════════════════════════════════════════════════════
      // EMIT OBSERVATIONS
      // ═══════════════════════════════════════════════════════════════

      // ─── Classify underground intel events ─────────────────────────
      const ransomwareListings = uieResults.filter(e => e.category === "ransomware");
      const dataLeaks = uieResults.filter(e => e.category === "data_leak" || e.category === "credential");
      const iabListings = uieResults.filter(e => e.category === "iab");
      const otherMentions = uieResults.filter(e => !["ransomware", "data_leak", "credential", "iab"].includes(e.category));

      // Ransomware listings — CRITICAL
      for (const listing of ransomwareListings) {
        observations.push({
          assetId: makeAssetId(domain, `ransomware:${listing.id}`, source),
          domain,
          assetType: "breach",
          name: `Ransomware listing: ${listing.title}`,
          source,
          observedAt: now,
          firstSeen: listing.eventDate ? new Date(listing.eventDate) : undefined,
          tags: ["darkweb", "ransomware_listing", "critical_threat", "underground_intel"],
          evidence: {
            severity: 10,
            confidence: listing.victimName?.toLowerCase().includes(baseDomain) ? 90 : 65,
            category: "ransomware",
            actor_name: listing.actorName,
            actor_aliases: listing.actorAliases,
            victim_name: listing.victimName,
            victim_sector: listing.victimSector,
            victim_country: listing.victimCountry,
            event_date: listing.eventDate,
            ingested_at: listing.ingestedAt,
            source_feed: listing.source,
            title: listing.title,
            description: listing.description?.substring(0, 500),
            mitre_techniques: listing.mitreTechniques,
            match_type: listing.victimName?.toLowerCase().includes(baseDomain) ? "direct_domain" : "fuzzy_org_name",
          },
          attribution: {
            provider: `Underground Intel (${listing.source})`,
            url: "https://ransomware.live",
            method: "local_db_crossref",
          },
        });
      }

      // Data leak / credential dump mentions
      for (const leak of dataLeaks.slice(0, 15)) {
        observations.push({
          assetId: makeAssetId(domain, `leak:${leak.id}`, source),
          domain,
          assetType: "breach",
          name: `Data leak mention: ${leak.title}`,
          source,
          observedAt: now,
          firstSeen: leak.eventDate ? new Date(leak.eventDate) : undefined,
          tags: ["darkweb", "data_leak", "underground_intel"],
          evidence: {
            severity: 8,
            confidence: 75,
            category: leak.category,
            actor_name: leak.actorName,
            event_date: leak.eventDate,
            source_feed: leak.source,
            title: leak.title,
            description: leak.description?.substring(0, 500),
            mitre_techniques: leak.mitreTechniques,
          },
          attribution: {
            provider: `Underground Intel (${leak.source})`,
            url: "",
            method: "local_db_crossref",
          },
        });
      }

      // IAB (Initial Access Broker) listings — someone selling access
      for (const iab of iabListings) {
        observations.push({
          assetId: makeAssetId(domain, `iab:${iab.id}`, source),
          domain,
          assetType: "breach",
          name: `IAB access listing: ${iab.title}`,
          source,
          observedAt: now,
          firstSeen: iab.eventDate ? new Date(iab.eventDate) : undefined,
          tags: ["darkweb", "iab_listing", "critical_threat", "access_sale", "underground_intel"],
          evidence: {
            severity: 10,
            confidence: 70,
            category: "iab",
            actor_name: iab.actorName,
            event_date: iab.eventDate,
            source_feed: iab.source,
            title: iab.title,
            description: iab.description?.substring(0, 500),
            mitre_techniques: iab.mitreTechniques,
          },
          attribution: {
            provider: `Underground Intel (${iab.source})`,
            url: "",
            method: "local_db_crossref",
          },
        });
      }

      // ─── Credential Breaches with Source Classification ────────────
      let firstPartyBreachCount = 0;
      let thirdPartyBreachCount = 0;
      let unknownBreachCount = 0;

      for (const breach of ceResults.slice(0, 30)) {
        if (breach.isSpamList === 1) continue; // Skip spam lists

        const classification = classifyCredentialSource(
          domain,
          breach.breachName,
          breach.breachDomain,
          breach.description,
        );

        if (classification.type === "first_party") firstPartyBreachCount++;
        else if (classification.type === "third_party") thirdPartyBreachCount++;
        else unknownBreachCount++;

        // Severity adjusts based on source: 1st-party breaches are more critical
        const baseSeverity = breach.severity === "critical" ? 9 : breach.severity === "high" ? 7 : 5;
        const adjustedSeverity = classification.type === "first_party"
          ? Math.min(baseSeverity + 2, 10)
          : classification.type === "third_party"
            ? Math.max(baseSeverity - 1, 3)
            : baseSeverity;

        observations.push({
          assetId: makeAssetId(domain, `cebreach:${breach.id}`, source),
          domain,
          assetType: "credential",
          name: `${classification.type === "first_party" ? "🔴 1st-Party" : classification.type === "third_party" ? "3rd-Party" : "Unclassified"} Breach: ${breach.breachName}`,
          source,
          observedAt: now,
          firstSeen: breach.breachDate ? new Date(breach.breachDate) : undefined,
          tags: [
            "credential_breach",
            "breach_database",
            "underground_intel",
            `breach_source:${classification.type}`,
            ...(classification.type === "first_party" ? ["first_party_breach", "critical_threat"] : []),
            ...(classification.type === "third_party" ? ["third_party_breach", "credential_reuse"] : []),
          ],
          evidence: {
            severity: adjustedSeverity,
            confidence: Math.max(breach.isVerified ? 90 : 70, classification.confidence),
            breach_name: breach.breachName,
            breach_date: breach.breachDate,
            breach_domain: breach.breachDomain,
            email_count: breach.emailCount,
            total_records: breach.totalRecords,
            data_classes: breach.dataClasses,
            actor_name: breach.actorName,
            is_verified: !!breach.isVerified,
            source_feed: breach.source,
            description: breach.description?.substring(0, 300),
            // Credential source classification
            credential_source: classification.type,
            credential_source_confidence: classification.confidence,
            credential_source_reasoning: classification.reasoning,
          },
          attribution: {
            provider: `Credential Intel (${breach.source})`,
            url: "",
            method: "local_db_crossref",
          },
        });
      }

      // Other underground mentions (malware, botnet, phishing, exploit, influence)
      for (const mention of otherMentions.slice(0, 10)) {
        observations.push({
          assetId: makeAssetId(domain, `uie:${mention.id}`, source),
          domain,
          assetType: "breach",
          name: `Underground mention: ${mention.title}`,
          source,
          observedAt: now,
          firstSeen: mention.eventDate ? new Date(mention.eventDate) : undefined,
          tags: ["darkweb", `category:${mention.category}`, "underground_intel"],
          evidence: {
            severity: mention.severity === "critical" ? 9 : mention.severity === "high" ? 7 : 5,
            confidence: 65,
            category: mention.category,
            actor_name: mention.actorName,
            event_date: mention.eventDate,
            source_feed: mention.source,
            title: mention.title,
            description: mention.description?.substring(0, 500),
            mitre_techniques: mention.mitreTechniques,
          },
          attribution: {
            provider: `Underground Intel (${mention.source})`,
            url: "",
            method: "local_db_crossref",
          },
        });
      }

      // ─── Threat Group Attribution Observations ─────────────────────
      for (const profile of threatGroupProfiles) {
        // Main threat group profile observation
        observations.push({
          assetId: makeAssetId(domain, `threat_group:${profile.actorId}`, source),
          domain,
          assetType: "breach",
          name: `Threat group attributed: ${profile.name}`,
          source,
          observedAt: now,
          tags: [
            "threat_group",
            "attribution",
            `actor_type:${profile.actorType}`,
            ...(profile.threatLevel === "critical" ? ["critical_threat"] : []),
            "underground_intel",
          ],
          evidence: {
            severity: profile.threatLevel === "critical" ? 10
              : profile.threatLevel === "high" ? 8
              : profile.threatLevel === "medium" ? 6 : 4,
            confidence: 75,
            // Group profile
            actor_id: profile.actorId,
            actor_name: profile.name,
            actor_aliases: profile.aliases,
            actor_type: profile.actorType,
            origin: profile.origin,
            motivation: profile.motivation,
            threat_level: profile.threatLevel,
            sophistication: profile.sophistication,
            first_seen: profile.firstSeen,
            last_active: profile.lastActive,
            description: profile.description?.substring(0, 500),
            // Targeting profile
            target_sectors: profile.targetSectors,
            target_regions: profile.targetRegions,
            // TTPs
            techniques: profile.techniques,
            tools: profile.tools,
            malware: profile.malware,
            // Attribution evidence
            attributed_events_count: profile.attributedEvents.length,
            attributed_events: profile.attributedEvents.slice(0, 10).map(e => ({
              type: e.eventType,
              title: e.title,
              severity: e.severity,
              victim: e.victimName,
              sector: e.victimSector,
              country: e.victimCountry,
              date: e.eventDate,
              mitre: e.mitreTechniques,
            })),
            relevant_iocs_count: profile.relevantIocs.length,
            relevant_iocs: profile.relevantIocs.slice(0, 10).map(i => ({
              type: i.iocType,
              value: i.value.substring(0, 200),
              confidence: i.confidence,
              first_seen: i.firstSeen,
              last_seen: i.lastSeen,
            })),
          },
          attribution: {
            provider: "Threat Actor Intelligence Database",
            url: "",
            method: "local_db_crossref",
          },
        });

        // Individual event observations for domain-specific incidents
        const domainEvents = profile.attributedEvents.filter(e => {
          const text = `${e.victimName || ""} ${e.title || ""}`.toLowerCase();
          return text.includes(baseDomain) || text.includes(orgName);
        });

        for (const event of domainEvents.slice(0, 5)) {
          observations.push({
            assetId: makeAssetId(domain, `tge:${profile.actorId}:${event.title}`, source),
            domain,
            assetType: "breach",
            name: `${profile.name} incident: ${event.title}`,
            source,
            observedAt: now,
            firstSeen: event.eventDate ? new Date(event.eventDate) : undefined,
            tags: [
              "threat_group_event",
              `event_type:${event.eventType}`,
              "attribution",
              "underground_intel",
            ],
            evidence: {
              severity: event.severity === "critical" ? 10 : event.severity === "high" ? 8 : 6,
              confidence: 85,
              actor_name: profile.name,
              actor_type: profile.actorType,
              event_type: event.eventType,
              title: event.title,
              description: event.description?.substring(0, 500),
              victim_name: event.victimName,
              victim_sector: event.victimSector,
              victim_country: event.victimCountry,
              event_date: event.eventDate,
              mitre_techniques: event.mitreTechniques,
              source: event.source,
            },
            attribution: {
              provider: `Threat Group Events (${profile.name})`,
              url: "",
              method: "local_db_crossref",
            },
          });
        }
      }

      // ─── Summary Observation ───────────────────────────────────────
      const totalMentions = uieResults.length + ceResults.length;
      const activeBreaches = ceResults.filter(c => c.isSpamList !== 1);

      if (totalMentions > 0 || threatGroupProfiles.length > 0) {
        observations.push({
          assetId: makeAssetId(domain, "darkweb_summary", source),
          domain,
          assetType: "breach",
          name: `Dark web intelligence summary for ${domain}`,
          source,
          observedAt: now,
          tags: ["darkweb", "summary", "underground_intel"],
          evidence: {
            total_mentions: totalMentions,
            ransomware_listings: ransomwareListings.length,
            data_leak_mentions: dataLeaks.length,
            iab_listings: iabListings.length,
            credential_breaches: activeBreaches.length,
            first_party_breaches: firstPartyBreachCount,
            third_party_breaches: thirdPartyBreachCount,
            unclassified_breaches: unknownBreachCount,
            other_mentions: otherMentions.length,
            threat_groups_attributed: threatGroupProfiles.length,
            threat_group_names: threatGroupProfiles.map(p => p.name),
            threat_group_types: Array.from(new Set(threatGroupProfiles.map(p => p.actorType))),
            unique_actors: Array.from(new Set([
              ...ransomwareListings.map(r => r.actorName),
              ...iabListings.map(r => r.actorName),
              ...dataLeaks.map(r => r.actorName),
            ].filter(Boolean))),
            severity: ransomwareListings.length > 0 || iabListings.length > 0 ? 10
              : threatGroupProfiles.some(p => p.threatLevel === "critical") ? 9
              : dataLeaks.length > 0 ? 8
              : firstPartyBreachCount > 0 ? 7
              : activeBreaches.length > 0 ? 6 : 4,
            confidence: 80,
          },
          attribution: {
            provider: "Local Underground Intel Database",
            url: "",
            method: "local_db_crossref",
          },
        });
      }

    } catch (err: any) {
      errors.push(`Darkweb cross-reference error: ${err.message}`);
    }

    return {
      connector: source,
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
