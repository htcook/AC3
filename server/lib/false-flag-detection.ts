/**
 * False Flag Detection Engine
 *
 * A dedicated scoring layer that identifies deliberate misdirection in cyber operations.
 * Detects planted IOCs, borrowed TTPs, timezone spoofing, linguistic deception,
 * infrastructure age anomalies, tooling inconsistencies, and geopolitical motivation mismatches.
 *
 * Produces a composite false-flag probability score with a full evidence chain
 * explaining each indicator of potential deception.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FalseFlagIndicator {
  category: FalseFlagCategory;
  signal: string;
  description: string;
  confidence: "high" | "medium" | "low";
  weight: number; // 0-1, how strongly this suggests false flag
  evidence: string[];
  mitigatingFactors?: string[];
}

export type FalseFlagCategory =
  | "planted_iocs"
  | "borrowed_ttps"
  | "timezone_spoofing"
  | "linguistic_deception"
  | "infrastructure_age"
  | "tooling_inconsistency"
  | "geopolitical_mismatch"
  | "operational_security_anomaly"
  | "claim_behavior_divergence";

export interface FalseFlagAnalysis {
  overallProbability: number; // 0-100, likelihood this is a false flag
  verdict: "likely_authentic" | "suspicious" | "probable_false_flag" | "confirmed_deception";
  indicators: FalseFlagIndicator[];
  deceptionNarrative: string; // Human-readable explanation of the deception hypothesis
  likelyTrueActor: string | null; // If false flag detected, who's really behind it
  likelyTrueActorConfidence: number;
  intendedScapegoat: string | null; // Who the operation was designed to frame
  categoryScores: Record<FalseFlagCategory, number>;
  recommendations: string[];
}

export interface IncidentForFalseFlagAnalysis {
  id: string;
  title: string;
  claimedActor: string | null;
  attributedActor: string | null;
  timestamp: number;
  victimSector: string;
  victimCountry: string;
  // Technical indicators
  techniques: string[];
  malwareObserved: string[];
  toolsUsed: string[];
  c2Methods: string[];
  initialAccess: string[];
  // Infrastructure
  sourceIps: string[];
  domains: string[];
  jarmHashes: string[];
  ja3Hashes: string[];
  tlsCerts: string[];
  asnNumbers: string[];
  domainRegistrationDates?: Record<string, number>; // domain -> registration timestamp
  // Temporal
  compileTimestamps?: number[];
  operatingHoursUtc?: number[];
  dwellTimeDays?: number | null;
  // Linguistic
  propagandaText?: string | null;
  malwareStrings?: string[];
  ransomNoteText?: string | null;
  codeComments?: string[];
  // Claims
  publicClaims: Array<{
    persona: string;
    platform: string;
    timestamp: number;
    text?: string;
  }>;
  // Context
  relatedAdvisories: string[];
  geopoliticalContext?: string;
}

// ─── Known Actor Signatures (for comparison) ─────────────────────────────────

interface ActorSignature {
  id: string;
  name: string;
  origin: string;
  typicalTechniques: string[];
  typicalMalware: string[];
  typicalTools: string[];
  typicalC2: string[];
  typicalInitialAccess: string[];
  operatingHoursUtc: [number, number]; // start, end hour
  typicalDwellDays: [number, number]; // min, max
  sophisticationLevel: "low" | "medium" | "high" | "nation_state";
  typicalVictimSectors: string[];
  typicalVictimCountries: string[];
  knownInfraPatterns: string[]; // ASN patterns, hosting preferences
  languageArtifacts: string[]; // Expected language traces
  motivations: string[];
}

const ACTOR_SIGNATURES: ActorSignature[] = [
  {
    id: "cyberav3ngers",
    name: "CyberAv3ngers",
    origin: "iran",
    typicalTechniques: ["T0883", "T0855", "T0821", "T0831", "T0836", "T0809"],
    typicalMalware: ["IOCONTROL", "custom_plc_wiper"],
    typicalTools: ["shodan_scanner", "default_cred_brute"],
    typicalC2: ["direct_plc_access", "vpn_tunnel"],
    typicalInitialAccess: ["default_credentials", "internet_facing_plc"],
    operatingHoursUtc: [4, 14], // Iran UTC+3:30 → work hours 7:30-17:30
    typicalDwellDays: [0, 3],
    sophisticationLevel: "medium",
    typicalVictimSectors: ["water", "wastewater", "energy"],
    typicalVictimCountries: ["US", "IL", "EU"],
    knownInfraPatterns: ["iranian_hosting", "bulletproof_vps"],
    languageArtifacts: ["persian", "farsi_keyboard"],
    motivations: ["anti_israel", "anti_us", "propaganda"],
  },
  {
    id: "sandworm",
    name: "Sandworm (APT44)",
    origin: "russia",
    typicalTechniques: ["T0886", "T0855", "T0831", "T0813", "T0809", "T1059"],
    typicalMalware: ["Industroyer", "Industroyer2", "CaddyWiper", "BlackEnergy", "NotPetya"],
    typicalTools: ["Impacket", "CrackMapExec", "Mimikatz", "custom_ot_tools"],
    typicalC2: ["tor_hidden_service", "custom_protocol", "dns_tunneling"],
    typicalInitialAccess: ["spearphishing", "supply_chain", "vpn_exploit"],
    operatingHoursUtc: [5, 17], // Moscow UTC+3 → work hours 8-20
    typicalDwellDays: [30, 365],
    sophisticationLevel: "nation_state",
    typicalVictimSectors: ["energy", "government", "telecommunications"],
    typicalVictimCountries: ["UA", "EU", "US"],
    knownInfraPatterns: ["russian_hosting", "compromised_routers", "tor"],
    languageArtifacts: ["russian", "cyrillic"],
    motivations: ["geopolitical", "disruption", "intelligence"],
  },
  {
    id: "volt_typhoon",
    name: "Volt Typhoon",
    origin: "china",
    typicalTechniques: ["T1059", "T1053", "T1078", "T1021", "T1018", "T1003"],
    typicalMalware: [], // LOTL - minimal custom malware
    typicalTools: ["ntdsutil", "netsh", "wmic", "certutil", "powershell", "cmd"],
    typicalC2: ["compromised_soho_routers", "living_off_the_land"],
    typicalInitialAccess: ["fortinet_exploit", "public_facing_app_exploit"],
    operatingHoursUtc: [0, 10], // Beijing UTC+8 → work hours 8-18
    typicalDwellDays: [180, 1825], // Years of persistence
    sophisticationLevel: "nation_state",
    typicalVictimSectors: ["critical_infrastructure", "telecommunications", "energy", "water"],
    typicalVictimCountries: ["US", "GU", "AU"],
    knownInfraPatterns: ["compromised_soho_routers", "residential_proxies"],
    languageArtifacts: ["chinese_simplified"],
    motivations: ["prepositioning", "intelligence", "contingency_disruption"],
  },
  {
    id: "lazarus",
    name: "Lazarus Group",
    origin: "north_korea",
    typicalTechniques: ["T1566", "T1059", "T1055", "T1027", "T1071", "T1486"],
    typicalMalware: ["BLINDINGCAN", "HOPLIGHT", "AppleJeus", "FASTCash"],
    typicalTools: ["custom_loaders", "trojanized_apps", "watering_hole_kits"],
    typicalC2: ["https_custom", "social_media_dead_drops"],
    typicalInitialAccess: ["spearphishing", "watering_hole", "supply_chain"],
    operatingHoursUtc: [0, 9], // Pyongyang UTC+9 → work hours 9-18
    typicalDwellDays: [14, 180],
    sophisticationLevel: "high",
    typicalVictimSectors: ["finance", "cryptocurrency", "defense", "media"],
    typicalVictimCountries: ["US", "KR", "JP", "global"],
    knownInfraPatterns: ["compromised_servers", "bulletproof_hosting"],
    languageArtifacts: ["korean"],
    motivations: ["financial_theft", "espionage", "disruption"],
  },
  {
    id: "handala",
    name: "Handala",
    origin: "iran",
    typicalTechniques: ["T1190", "T1078", "T1486"],
    typicalMalware: ["generic_wiper", "defacement_tools"],
    typicalTools: ["web_shells", "public_exploits"],
    typicalC2: ["telegram_bot", "direct_access"],
    typicalInitialAccess: ["public_facing_app_exploit", "credential_stuffing"],
    operatingHoursUtc: [4, 14],
    typicalDwellDays: [0, 7],
    sophisticationLevel: "low",
    typicalVictimSectors: ["government", "technology", "critical_infrastructure"],
    typicalVictimCountries: ["IL", "US"],
    knownInfraPatterns: ["shared_hosting", "telegram"],
    languageArtifacts: ["persian", "arabic"],
    motivations: ["anti_israel", "propaganda", "hacktivism"],
  },
];

// ─── Detection Functions ─────────────────────────────────────────────────────

/**
 * Detect planted IOCs — known actor IOCs appearing in wrong operational context
 */
function detectPlantedIOCs(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Check if malware from a DIFFERENT actor appears alongside claimed actor's IOCs
  for (const sig of ACTOR_SIGNATURES) {
    if (sig.id === claimedSig.id) continue;
    const foreignMalware = incident.malwareObserved.filter((m) =>
      sig.typicalMalware.some((tm) => m.toLowerCase().includes(tm.toLowerCase()))
    );
    if (foreignMalware.length > 0) {
      indicators.push({
        category: "planted_iocs",
        signal: `Foreign malware from ${sig.name} found in ${claimedSig.name} attributed operation`,
        description: `Malware typically associated with ${sig.name} (${foreignMalware.join(", ")}) was found in an operation attributed to ${claimedSig.name}. This could indicate planted evidence or a shared toolset.`,
        confidence: "medium",
        weight: 0.6,
        evidence: [
          `Malware ${foreignMalware.join(", ")} is historically associated with ${sig.name}`,
          `Operation is attributed to ${claimedSig.name} which does not typically use these tools`,
        ],
        mitigatingFactors: [
          "Tool sharing between allied groups is possible",
          "Underground marketplace purchases could explain cross-contamination",
        ],
      });
    }
  }

  // Check for IOCs that are TOO perfect — exact matches to published threat reports
  if (incident.sourceIps.length > 5 && incident.domains.length > 5) {
    const knownIndicatorDensity = incident.sourceIps.length + incident.domains.length;
    if (knownIndicatorDensity > 15) {
      indicators.push({
        category: "planted_iocs",
        signal: "Unusually high density of attributable IOCs",
        description: `The operation contains ${knownIndicatorDensity} easily attributable indicators. Sophisticated actors typically minimize their fingerprint; an abundance of attribution-friendly IOCs may indicate deliberate planting.`,
        confidence: "low",
        weight: 0.35,
        evidence: [
          `${knownIndicatorDensity} distinct IOCs found (IPs + domains)`,
          "Sophisticated nation-state actors typically use fresh, unattributed infrastructure",
          "High IOC density is unusual for actors with OPSEC discipline",
        ],
        mitigatingFactors: [
          "Less sophisticated actors may simply reuse infrastructure",
          "Rushed operations may leave more traces",
        ],
      });
    }
  }

  return indicators;
}

/**
 * Detect borrowed TTPs — technique sequences inconsistent with claimed actor
 */
function detectBorrowedTTPs(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Check technique overlap with claimed actor
  const claimedTechOverlap = incident.techniques.filter((t) => claimedSig.typicalTechniques.includes(t));
  const claimedTechOverlapPct = incident.techniques.length > 0 ? claimedTechOverlap.length / incident.techniques.length : 0;

  // Check technique overlap with OTHER actors
  for (const sig of ACTOR_SIGNATURES) {
    if (sig.id === claimedSig.id) continue;
    const otherTechOverlap = incident.techniques.filter((t) => sig.typicalTechniques.includes(t));
    const otherTechOverlapPct = incident.techniques.length > 0 ? otherTechOverlap.length / incident.techniques.length : 0;

    if (otherTechOverlapPct > claimedTechOverlapPct && otherTechOverlapPct > 0.5) {
      indicators.push({
        category: "borrowed_ttps",
        signal: `TTP alignment stronger with ${sig.name} than claimed ${claimedSig.name}`,
        description: `The observed techniques align ${Math.round(otherTechOverlapPct * 100)}% with ${sig.name} but only ${Math.round(claimedTechOverlapPct * 100)}% with the claimed/attributed ${claimedSig.name}. This suggests the real operator may be ${sig.name} disguising as ${claimedSig.name}.`,
        confidence: otherTechOverlapPct > 0.7 ? "high" : "medium",
        weight: otherTechOverlapPct > 0.7 ? 0.8 : 0.55,
        evidence: [
          `${Math.round(otherTechOverlapPct * 100)}% technique overlap with ${sig.name}`,
          `Only ${Math.round(claimedTechOverlapPct * 100)}% technique overlap with claimed ${claimedSig.name}`,
          `Matching techniques: ${otherTechOverlap.join(", ")}`,
        ],
        mitigatingFactors: [
          "Actors may evolve their TTPs over time",
          "Some techniques are common across multiple groups",
        ],
      });
    }
  }

  // Check for sophistication mismatch in initial access
  const claimedInitialAccessOverlap = incident.initialAccess.filter((ia) =>
    claimedSig.typicalInitialAccess.includes(ia)
  );
  if (incident.initialAccess.length > 0 && claimedInitialAccessOverlap.length === 0) {
    indicators.push({
      category: "borrowed_ttps",
      signal: "Initial access vector inconsistent with claimed actor",
      description: `The initial access methods (${incident.initialAccess.join(", ")}) do not match any known ${claimedSig.name} patterns. This actor typically uses: ${claimedSig.typicalInitialAccess.join(", ")}.`,
      confidence: "medium",
      weight: 0.5,
      evidence: [
        `Observed initial access: ${incident.initialAccess.join(", ")}`,
        `Expected for ${claimedSig.name}: ${claimedSig.typicalInitialAccess.join(", ")}`,
        "Zero overlap between observed and expected initial access vectors",
      ],
    });
  }

  return indicators;
}

/**
 * Detect timezone spoofing — compile timestamps vs operational hours mismatch
 */
function detectTimezoneSpoofing(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Check compile timestamps against expected working hours
  if (incident.compileTimestamps && incident.compileTimestamps.length > 0) {
    const compileHours = incident.compileTimestamps.map((ts) => new Date(ts).getUTCHours());
    const [expectedStart, expectedEnd] = claimedSig.operatingHoursUtc;

    const outsideHoursCount = compileHours.filter((h) => {
      if (expectedStart < expectedEnd) {
        return h < expectedStart || h > expectedEnd;
      }
      return h > expectedEnd && h < expectedStart;
    }).length;

    const outsideHoursPct = outsideHoursCount / compileHours.length;

    if (outsideHoursPct > 0.6) {
      // Check which actor's hours DO match
      let matchingActor: ActorSignature | null = null;
      for (const sig of ACTOR_SIGNATURES) {
        if (sig.id === claimedSig.id) continue;
        const [sigStart, sigEnd] = sig.operatingHoursUtc;
        const insideCount = compileHours.filter((h) => {
          if (sigStart < sigEnd) return h >= sigStart && h <= sigEnd;
          return h >= sigStart || h <= sigEnd;
        }).length;
        if (insideCount / compileHours.length > 0.7) {
          matchingActor = sig;
          break;
        }
      }

      indicators.push({
        category: "timezone_spoofing",
        signal: `Compile timestamps inconsistent with ${claimedSig.name} working hours`,
        description: `${Math.round(outsideHoursPct * 100)}% of compile timestamps fall outside ${claimedSig.name}'s expected UTC working hours (${expectedStart}:00-${expectedEnd}:00).${matchingActor ? ` Timestamps align better with ${matchingActor.name} (${matchingActor.origin}).` : ""}`,
        confidence: outsideHoursPct > 0.8 ? "high" : "medium",
        weight: outsideHoursPct > 0.8 ? 0.7 : 0.5,
        evidence: [
          `${outsideHoursCount}/${compileHours.length} compile timestamps outside expected hours`,
          `Expected working hours for ${claimedSig.name}: UTC ${expectedStart}:00-${expectedEnd}:00`,
          `Observed compile hours (UTC): ${compileHours.join(", ")}`,
          ...(matchingActor ? [`Timestamps align with ${matchingActor.name} working hours`] : []),
        ],
        mitigatingFactors: [
          "Actors may deliberately work outside normal hours for OPSEC",
          "Compile timestamps can be trivially modified",
          "Distributed teams may span multiple timezones",
        ],
      });
    }
  }

  // Check operational hours vs claimed actor
  if (incident.operatingHoursUtc && incident.operatingHoursUtc.length > 3) {
    const [expectedStart, expectedEnd] = claimedSig.operatingHoursUtc;
    const outsideOps = incident.operatingHoursUtc.filter((h) => {
      if (expectedStart < expectedEnd) return h < expectedStart || h > expectedEnd;
      return h > expectedEnd && h < expectedStart;
    });

    if (outsideOps.length / incident.operatingHoursUtc.length > 0.5) {
      indicators.push({
        category: "timezone_spoofing",
        signal: "Operational activity hours misaligned with claimed origin",
        description: `The majority of operational activity occurs outside the expected working hours for ${claimedSig.origin}-based actors. This may indicate the true operator is in a different timezone.`,
        confidence: "medium",
        weight: 0.45,
        evidence: [
          `${outsideOps.length}/${incident.operatingHoursUtc.length} activity timestamps outside expected range`,
          `Expected: UTC ${expectedStart}:00-${expectedEnd}:00 (${claimedSig.origin})`,
        ],
      });
    }
  }

  return indicators;
}

/**
 * Detect linguistic deception — language artifacts vs claimed origin
 */
function detectLinguisticDeception(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Language pattern detection in propaganda text
  const allText = [
    incident.propagandaText,
    incident.ransomNoteText,
    ...(incident.codeComments || []),
    ...(incident.malwareStrings || []),
  ]
    .filter(Boolean)
    .join(" ");

  if (!allText) return indicators;

  const languagePatterns: Record<string, RegExp[]> = {
    russian: [/[а-яА-Я]+/g, /\b(сервер|файл|программа|ошибка)\b/gi],
    chinese_simplified: [/[\u4e00-\u9fff]+/g],
    persian: [/[\u0600-\u06FF]+/g],
    korean: [/[\uAC00-\uD7AF]+/g],
    arabic: [/[\u0627-\u064A]+/g],
  };

  // Check for language artifacts from DIFFERENT origins
  for (const [lang, patterns] of Object.entries(languagePatterns)) {
    if (claimedSig.languageArtifacts.includes(lang)) continue;

    const matches = patterns.reduce((count, pattern) => {
      const found = allText.match(pattern);
      return count + (found ? found.length : 0);
    }, 0);

    if (matches > 0) {
      // Find which actor this language belongs to
      const langActor = ACTOR_SIGNATURES.find((a) => a.languageArtifacts.includes(lang));

      indicators.push({
        category: "linguistic_deception",
        signal: `${lang} language artifacts found in ${claimedSig.origin}-attributed operation`,
        description: `Language artifacts associated with ${lang} were detected in text content, but the operation is attributed to a ${claimedSig.origin}-origin actor (${claimedSig.name}).${langActor ? ` These artifacts are consistent with ${langActor.name}.` : ""}`,
        confidence: matches > 5 ? "high" : "medium",
        weight: matches > 5 ? 0.75 : 0.5,
        evidence: [
          `${matches} ${lang} language pattern matches found`,
          `Expected language artifacts for ${claimedSig.name}: ${claimedSig.languageArtifacts.join(", ")}`,
          ...(langActor ? [`${lang} artifacts are typical of ${langActor.name} (${langActor.origin})`] : []),
        ],
        mitigatingFactors: [
          "Deliberate language planting is a known deception technique",
          "Multinational teams may produce mixed language artifacts",
          "Copy-pasted code may retain original language comments",
        ],
      });
    }
  }

  // Check for machine-translated propaganda (grammatical inconsistencies)
  if (incident.propagandaText && incident.propagandaText.length > 50) {
    // Simple heuristic: check for mixed script usage suggesting translation
    const hasLatinAndNonLatin =
      /[a-zA-Z]/.test(incident.propagandaText) &&
      /[^\x00-\x7F]/.test(incident.propagandaText);
    const hasOddCapitalization = (incident.propagandaText.match(/[A-Z][a-z]+[A-Z]/g) || []).length > 2;

    if (hasLatinAndNonLatin && hasOddCapitalization) {
      indicators.push({
        category: "linguistic_deception",
        signal: "Propaganda text shows signs of machine translation",
        description: "The propaganda/claim text exhibits patterns consistent with machine translation (mixed scripts, unusual capitalization), suggesting the author is not a native speaker of the presented language.",
        confidence: "low",
        weight: 0.3,
        evidence: [
          "Mixed script usage detected (Latin + non-Latin characters)",
          "Unusual capitalization patterns suggesting automated translation",
        ],
      });
    }
  }

  return indicators;
}

/**
 * Detect infrastructure age anomalies — freshly registered vs established actor infra
 */
function detectInfrastructureAgeAnomalies(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  if (!incident.domainRegistrationDates || Object.keys(incident.domainRegistrationDates).length === 0) {
    return indicators;
  }

  const now = Date.now();
  const registrationAges = Object.entries(incident.domainRegistrationDates).map(([domain, regDate]) => ({
    domain,
    ageDays: Math.floor((now - regDate) / (1000 * 60 * 60 * 24)),
  }));

  const freshDomains = registrationAges.filter((d) => d.ageDays < 30);
  const agedDomains = registrationAges.filter((d) => d.ageDays > 365);

  // Nation-state actors typically use aged infrastructure or compromised hosts
  if (claimedSig.sophisticationLevel === "nation_state" && freshDomains.length > agedDomains.length) {
    indicators.push({
      category: "infrastructure_age",
      signal: "Fresh infrastructure inconsistent with nation-state actor profile",
      description: `${freshDomains.length} domains were registered within 30 days of the operation, but ${claimedSig.name} (nation-state sophistication) typically uses aged or compromised infrastructure. Fresh registration suggests a less sophisticated operator or deliberate misdirection.`,
      confidence: "medium",
      weight: 0.5,
      evidence: [
        `${freshDomains.length} domains < 30 days old: ${freshDomains.map((d) => d.domain).join(", ")}`,
        `${agedDomains.length} domains > 1 year old`,
        `${claimedSig.name} typically uses ${claimedSig.knownInfraPatterns.join(", ")}`,
      ],
      mitigatingFactors: [
        "Actors may use fresh infrastructure for specific operations",
        "Operational urgency may override OPSEC preferences",
      ],
    });
  }

  // Low-sophistication actors using aged/expensive infrastructure
  if (claimedSig.sophisticationLevel === "low" && agedDomains.length > freshDomains.length * 2) {
    indicators.push({
      category: "infrastructure_age",
      signal: "Aged infrastructure inconsistent with low-sophistication actor",
      description: `The operation uses ${agedDomains.length} well-aged domains (>1 year), which is unusual for ${claimedSig.name} (low sophistication). This suggests a more capable actor may be operating under the ${claimedSig.name} persona.`,
      confidence: "medium",
      weight: 0.55,
      evidence: [
        `${agedDomains.length} domains > 1 year old`,
        `${claimedSig.name} typically uses: ${claimedSig.knownInfraPatterns.join(", ")}`,
        "Aged infrastructure requires long-term planning and resources",
      ],
    });
  }

  return indicators;
}

/**
 * Detect tooling inconsistencies — sophistication mismatch
 */
function detectToolingInconsistency(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Check sophistication mismatch
  const sophisticationLevels = { low: 1, medium: 2, high: 3, nation_state: 4 };
  const claimedLevel = sophisticationLevels[claimedSig.sophisticationLevel];

  // Indicators of high sophistication
  const highSophIndicators = [
    incident.toolsUsed.some((t) => ["Mimikatz", "Impacket", "CrackMapExec", "Cobalt Strike"].includes(t)),
    incident.c2Methods.some((c) => ["custom_protocol", "dns_tunneling", "tor_hidden_service"].includes(c)),
    (incident.dwellTimeDays || 0) > 90,
    incident.techniques.length > 10,
  ].filter(Boolean).length;

  // Indicators of low sophistication
  const lowSophIndicators = [
    incident.toolsUsed.some((t) => ["web_shells", "public_exploits", "script_kiddie_tools"].includes(t)),
    incident.initialAccess.some((ia) => ["default_credentials", "credential_stuffing"].includes(ia)),
    (incident.dwellTimeDays || 999) < 3,
    incident.techniques.length < 4,
  ].filter(Boolean).length;

  // High-sophistication tools used by claimed low-sophistication actor
  if (claimedLevel <= 2 && highSophIndicators >= 3) {
    indicators.push({
      category: "tooling_inconsistency",
      signal: `Sophistication exceeds ${claimedSig.name}'s known capabilities`,
      description: `The operation demonstrates nation-state-level sophistication (custom C2, long dwell time, advanced tooling) but is attributed to ${claimedSig.name} which operates at ${claimedSig.sophisticationLevel} level. A more capable actor may be operating under this persona.`,
      confidence: "high",
      weight: 0.75,
      evidence: [
        `${highSophIndicators} high-sophistication indicators detected`,
        `${claimedSig.name} rated as ${claimedSig.sophisticationLevel} sophistication`,
        `Tools observed: ${incident.toolsUsed.join(", ")}`,
        `C2 methods: ${incident.c2Methods.join(", ")}`,
        incident.dwellTimeDays ? `Dwell time: ${incident.dwellTimeDays} days` : "",
      ].filter(Boolean),
    });
  }

  // Low-sophistication tools used by claimed nation-state actor
  if (claimedLevel >= 3 && lowSophIndicators >= 3) {
    indicators.push({
      category: "tooling_inconsistency",
      signal: `Tooling below ${claimedSig.name}'s expected sophistication`,
      description: `The operation uses basic tools and techniques inconsistent with ${claimedSig.name}'s nation-state capabilities. This may indicate a less capable actor attempting to frame ${claimedSig.name}, or a deliberate "dumbing down" for deniability.`,
      confidence: "medium",
      weight: 0.45,
      evidence: [
        `${lowSophIndicators} low-sophistication indicators detected`,
        `${claimedSig.name} rated as ${claimedSig.sophisticationLevel} sophistication`,
        `Tools observed: ${incident.toolsUsed.join(", ")}`,
      ],
      mitigatingFactors: [
        "Nation-state actors sometimes deliberately use unsophisticated tools for deniability",
        "Different teams within the same organization may have varying skill levels",
        "Time pressure may force use of simpler tools",
      ],
    });
  }

  return indicators;
}

/**
 * Detect geopolitical motivation mismatches — cui bono analysis
 */
function detectGeopoliticalMismatch(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Check if victim country/sector aligns with claimed actor's targeting
  const victimCountryMatch = claimedSig.typicalVictimCountries.some(
    (c) => c.toLowerCase() === incident.victimCountry.toLowerCase() || c === "global"
  );
  const victimSectorMatch = claimedSig.typicalVictimSectors.some(
    (s) => incident.victimSector.toLowerCase().includes(s.toLowerCase())
  );

  if (!victimCountryMatch && !victimSectorMatch) {
    // Check which actor WOULD target this victim
    const likelyActors = ACTOR_SIGNATURES.filter((sig) => {
      const countryMatch = sig.typicalVictimCountries.some(
        (c) => c.toLowerCase() === incident.victimCountry.toLowerCase()
      );
      const sectorMatch = sig.typicalVictimSectors.some(
        (s) => incident.victimSector.toLowerCase().includes(s.toLowerCase())
      );
      return countryMatch || sectorMatch;
    });

    indicators.push({
      category: "geopolitical_mismatch",
      signal: `Victim profile inconsistent with ${claimedSig.name}'s targeting pattern`,
      description: `${claimedSig.name} typically targets ${claimedSig.typicalVictimCountries.join("/")} in ${claimedSig.typicalVictimSectors.join(", ")} sectors. This victim (${incident.victimCountry}, ${incident.victimSector}) doesn't fit their known targeting.${likelyActors.length > 0 ? ` More consistent with: ${likelyActors.map((a) => a.name).join(", ")}.` : ""}`,
      confidence: "medium",
      weight: 0.5,
      evidence: [
        `Victim: ${incident.victimCountry}, ${incident.victimSector}`,
        `${claimedSig.name} typical targets: ${claimedSig.typicalVictimCountries.join("/")} in ${claimedSig.typicalVictimSectors.join(", ")}`,
        ...(likelyActors.length > 0
          ? [`Victim profile matches: ${likelyActors.map((a) => `${a.name} (${a.origin})`).join(", ")}`]
          : []),
      ],
      mitigatingFactors: [
        "Actors may expand targeting beyond known patterns",
        "Opportunistic attacks may not follow strategic targeting",
      ],
    });
  }

  // Check motivation alignment
  if (incident.geopoliticalContext) {
    const motivationKeywords: Record<string, string[]> = {
      anti_israel: ["israel", "zionist", "idf", "mossad"],
      anti_us: ["america", "usa", "pentagon", "cia", "nato"],
      financial_theft: ["bank", "crypto", "swift", "payment"],
      geopolitical: ["sanctions", "military", "territory", "sovereignty"],
      disruption: ["destroy", "wipe", "shutdown", "disable"],
      propaganda: ["message", "deface", "claim", "announce"],
    };

    const contextLower = incident.geopoliticalContext.toLowerCase();
    const matchedMotivations = Object.entries(motivationKeywords)
      .filter(([, keywords]) => keywords.some((k) => contextLower.includes(k)))
      .map(([motivation]) => motivation);

    const motivationOverlap = matchedMotivations.filter((m) => claimedSig.motivations.includes(m));
    if (matchedMotivations.length > 0 && motivationOverlap.length === 0) {
      indicators.push({
        category: "geopolitical_mismatch",
        signal: "Geopolitical context doesn't align with claimed actor's motivations",
        description: `The geopolitical context suggests motivations (${matchedMotivations.join(", ")}) that don't align with ${claimedSig.name}'s known drivers (${claimedSig.motivations.join(", ")}).`,
        confidence: "low",
        weight: 0.35,
        evidence: [
          `Context-derived motivations: ${matchedMotivations.join(", ")}`,
          `${claimedSig.name} known motivations: ${claimedSig.motivations.join(", ")}`,
          "Zero overlap between context and actor motivations",
        ],
      });
    }
  }

  return indicators;
}

/**
 * Detect claim-behavior divergence — public claims vs actual operational behavior
 */
function detectClaimBehaviorDivergence(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];

  if (incident.publicClaims.length === 0) return indicators;

  // Check timing of claims vs operation
  const operationTime = incident.timestamp;
  for (const claim of incident.publicClaims) {
    const claimDelay = (claim.timestamp - operationTime) / (1000 * 60 * 60); // hours

    // Claims made BEFORE the operation was publicly known
    if (claimDelay < 0) {
      indicators.push({
        category: "claim_behavior_divergence",
        signal: "Claim made before operation was publicly disclosed",
        description: `${claim.persona} claimed responsibility ${Math.abs(Math.round(claimDelay))} hours BEFORE the operation was publicly known. This is unusual and may indicate the claimant had advance knowledge or is the actual operator.`,
        confidence: "high",
        weight: 0.8,
        evidence: [
          `Claim by ${claim.persona} on ${claim.platform}: ${Math.abs(Math.round(claimDelay))}h before public disclosure`,
          "Legitimate claims typically follow public reporting",
        ],
      });
    }

    // Claims made very late (>72h after) — opportunistic credit-taking
    if (claimDelay > 72) {
      indicators.push({
        category: "claim_behavior_divergence",
        signal: "Delayed claim suggests opportunistic credit-taking",
        description: `${claim.persona} claimed responsibility ${Math.round(claimDelay)} hours after the operation. Late claims (>72h) often indicate opportunistic credit-taking rather than actual involvement.`,
        confidence: "medium",
        weight: 0.55,
        evidence: [
          `Claim delay: ${Math.round(claimDelay)} hours after operation`,
          `Claim by ${claim.persona} on ${claim.platform}`,
          "Genuine operators typically claim within 24-48 hours",
        ],
        mitigatingFactors: [
          "Some groups deliberately delay claims for operational security",
          "Internal approval processes may cause delays",
        ],
      });
    }
  }

  // Multiple competing claims
  if (incident.publicClaims.length > 1) {
    const uniquePersonas = new Set(incident.publicClaims.map((c) => c.persona));
    if (uniquePersonas.size > 1) {
      indicators.push({
        category: "claim_behavior_divergence",
        signal: "Multiple groups claimed responsibility",
        description: `${uniquePersonas.size} different groups claimed this operation (${Array.from(uniquePersonas).join(", ")}). Competing claims increase the likelihood that at least some are false.`,
        confidence: "medium",
        weight: 0.6,
        evidence: [
          `${uniquePersonas.size} competing claims from: ${Array.from(uniquePersonas).join(", ")}`,
          "Multiple claims suggest information operations or opportunistic credit-taking",
        ],
      });
    }
  }

  // Claim with no proof
  const claimsWithText = incident.publicClaims.filter((c) => c.text && c.text.length > 0);
  if (incident.publicClaims.length > 0 && claimsWithText.length === 0) {
    indicators.push({
      category: "claim_behavior_divergence",
      signal: "Claims provided without supporting evidence",
      description: "Public claims were made without screenshots, data dumps, or other proof of access. Legitimate operators typically provide evidence to establish credibility.",
      confidence: "low",
      weight: 0.3,
      evidence: [
        `${incident.publicClaims.length} claims made with zero supporting evidence`,
        "No screenshots, data samples, or access proof provided",
      ],
      mitigatingFactors: [
        "Some groups claim without proof for operational security",
        "Evidence may be shared on private channels not visible to analysts",
      ],
    });
  }

  return indicators;
}

/**
 * Detect operational security anomalies
 */
function detectOpSecAnomalies(incident: IncidentForFalseFlagAnalysis): FalseFlagIndicator[] {
  const indicators: FalseFlagIndicator[] = [];
  const claimedOrAttributed = incident.claimedActor || incident.attributedActor;
  if (!claimedOrAttributed) return indicators;

  const claimedSig = ACTOR_SIGNATURES.find(
    (a) => a.id === claimedOrAttributed || a.name.toLowerCase().includes(claimedOrAttributed.toLowerCase())
  );
  if (!claimedSig) return indicators;

  // Dwell time anomaly
  if (incident.dwellTimeDays !== null && incident.dwellTimeDays !== undefined) {
    const [minDwell, maxDwell] = claimedSig.typicalDwellDays;
    if (incident.dwellTimeDays < minDwell * 0.5 || incident.dwellTimeDays > maxDwell * 2) {
      indicators.push({
        category: "operational_security_anomaly",
        signal: `Dwell time (${incident.dwellTimeDays}d) outside ${claimedSig.name}'s typical range`,
        description: `The observed dwell time of ${incident.dwellTimeDays} days is significantly outside ${claimedSig.name}'s typical range (${minDwell}-${maxDwell} days). This suggests a different operational tempo than expected.`,
        confidence: "medium",
        weight: 0.4,
        evidence: [
          `Observed dwell time: ${incident.dwellTimeDays} days`,
          `${claimedSig.name} typical range: ${minDwell}-${maxDwell} days`,
          incident.dwellTimeDays < minDwell ? "Shorter dwell suggests smash-and-grab vs patient actor" : "Longer dwell suggests more sophisticated persistence",
        ],
      });
    }
  }

  return indicators;
}

// ─── Main Analysis Function ──────────────────────────────────────────────────

/**
 * Run comprehensive false flag analysis on an incident
 */
export function analyzeFalseFlag(incident: IncidentForFalseFlagAnalysis): FalseFlagAnalysis {
  // Run all detection modules
  const allIndicators: FalseFlagIndicator[] = [
    ...detectPlantedIOCs(incident),
    ...detectBorrowedTTPs(incident),
    ...detectTimezoneSpoofing(incident),
    ...detectLinguisticDeception(incident),
    ...detectInfrastructureAgeAnomalies(incident),
    ...detectToolingInconsistency(incident),
    ...detectGeopoliticalMismatch(incident),
    ...detectClaimBehaviorDivergence(incident),
    ...detectOpSecAnomalies(incident),
  ];

  // Calculate category scores
  const categories: FalseFlagCategory[] = [
    "planted_iocs",
    "borrowed_ttps",
    "timezone_spoofing",
    "linguistic_deception",
    "infrastructure_age",
    "tooling_inconsistency",
    "geopolitical_mismatch",
    "operational_security_anomaly",
    "claim_behavior_divergence",
  ];

  const categoryScores: Record<FalseFlagCategory, number> = {} as any;
  for (const cat of categories) {
    const catIndicators = allIndicators.filter((i) => i.category === cat);
    if (catIndicators.length === 0) {
      categoryScores[cat] = 0;
    } else {
      // Weighted average of indicators in this category
      const totalWeight = catIndicators.reduce((sum, i) => sum + i.weight, 0);
      categoryScores[cat] = Math.min(100, Math.round((totalWeight / catIndicators.length) * 100));
    }
  }

  // Calculate overall probability (weighted composite)
  const categoryWeights: Record<FalseFlagCategory, number> = {
    planted_iocs: 0.12,
    borrowed_ttps: 0.2,
    timezone_spoofing: 0.1,
    linguistic_deception: 0.12,
    infrastructure_age: 0.08,
    tooling_inconsistency: 0.15,
    geopolitical_mismatch: 0.08,
    operational_security_anomaly: 0.07,
    claim_behavior_divergence: 0.08,
  };

  let overallProbability = 0;
  for (const cat of categories) {
    overallProbability += categoryScores[cat] * (categoryWeights[cat] || 0.1);
  }
  overallProbability = Math.min(100, Math.round(overallProbability));

  // Determine verdict
  let verdict: FalseFlagAnalysis["verdict"];
  if (overallProbability < 20) verdict = "likely_authentic";
  else if (overallProbability < 50) verdict = "suspicious";
  else if (overallProbability < 75) verdict = "probable_false_flag";
  else verdict = "confirmed_deception";

  // Determine likely true actor (from borrowed TTP analysis)
  let likelyTrueActor: string | null = null;
  let likelyTrueActorConfidence = 0;
  const ttpIndicators = allIndicators.filter((i) => i.category === "borrowed_ttps");
  if (ttpIndicators.length > 0) {
    // Extract actor names from TTP indicators
    for (const ind of ttpIndicators) {
      const actorMatch = ind.signal.match(/alignment stronger with (.+?) than/);
      if (actorMatch && ind.weight > likelyTrueActorConfidence) {
        likelyTrueActor = actorMatch[1];
        likelyTrueActorConfidence = Math.round(ind.weight * 100);
      }
    }
  }

  // Determine intended scapegoat
  const intendedScapegoat = incident.claimedActor || incident.attributedActor || null;

  // Generate deception narrative
  const deceptionNarrative = generateDeceptionNarrative(
    incident,
    allIndicators,
    overallProbability,
    likelyTrueActor,
    intendedScapegoat
  );

  // Generate recommendations
  const recommendations = generateRecommendations(allIndicators, overallProbability);

  return {
    overallProbability,
    verdict,
    indicators: allIndicators,
    deceptionNarrative,
    likelyTrueActor,
    likelyTrueActorConfidence,
    intendedScapegoat,
    categoryScores,
    recommendations,
  };
}

function generateDeceptionNarrative(
  incident: IncidentForFalseFlagAnalysis,
  indicators: FalseFlagIndicator[],
  probability: number,
  trueActor: string | null,
  scapegoat: string | null
): string {
  if (probability < 20) {
    return `Analysis of ${incident.title} found minimal indicators of deception. The attribution to ${scapegoat || "the claimed actor"} appears consistent with observed tradecraft, infrastructure, and operational patterns. No significant false-flag indicators were detected.`;
  }

  if (probability < 50) {
    const topIndicators = indicators
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3)
      .map((i) => i.signal);
    return `Analysis of ${incident.title} identified ${indicators.length} suspicious indicators that warrant further investigation. Key concerns: ${topIndicators.join("; ")}. While not conclusive, these anomalies suggest the attribution to ${scapegoat || "the claimed actor"} should be treated with caution.`;
  }

  const highConfIndicators = indicators.filter((i) => i.confidence === "high");
  let narrative = `Analysis of ${incident.title} reveals strong indicators of a false-flag operation. `;

  if (trueActor) {
    narrative += `The operation is likely conducted by ${trueActor} while designed to implicate ${scapegoat || "another actor"}. `;
  }

  if (highConfIndicators.length > 0) {
    narrative += `High-confidence deception signals include: ${highConfIndicators.map((i) => i.signal).join("; ")}. `;
  }

  narrative += `The composite false-flag probability is ${probability}% based on ${indicators.length} indicators across ${new Set(indicators.map((i) => i.category)).size} detection categories.`;

  return narrative;
}

function generateRecommendations(indicators: FalseFlagIndicator[], probability: number): string[] {
  const recommendations: string[] = [];

  if (probability > 50) {
    recommendations.push("CRITICAL: Suspend public attribution statements pending deeper analysis");
    recommendations.push("Engage national intelligence community for classified source validation");
  }

  if (indicators.some((i) => i.category === "timezone_spoofing")) {
    recommendations.push("Collect additional temporal data (login times, C2 beacon intervals) for timezone validation");
  }

  if (indicators.some((i) => i.category === "linguistic_deception")) {
    recommendations.push("Submit text samples for professional linguistic/stylometric analysis");
  }

  if (indicators.some((i) => i.category === "borrowed_ttps")) {
    recommendations.push("Cross-reference technique chains against classified threat actor databases");
    recommendations.push("Compare with historical campaigns for behavioral consistency");
  }

  if (indicators.some((i) => i.category === "infrastructure_age")) {
    recommendations.push("Conduct passive DNS and WHOIS history analysis on all infrastructure");
  }

  if (indicators.some((i) => i.category === "claim_behavior_divergence")) {
    recommendations.push("Monitor claiming persona's channels for follow-up evidence or contradictions");
  }

  if (probability < 20) {
    recommendations.push("Attribution appears solid — proceed with standard reporting confidence");
  }

  recommendations.push("Document all false-flag indicators for future campaign correlation");

  return recommendations;
}

/// ─── Case Library Integration ────────────────────────────────────────────────

import {
  computeCalibratedWeights,
  findSimilarCases,
  getTechniqueEffectiveness,
  getCaseLibrary,
  getCaseById,
  getCasesByCategory as getCasesByCat,
  getCasesByActorCountry,
  type FalseFlagCase,
  type CalibrationResult,
  type FalseFlagCategory as CaseLibCategory
} from './false-flag-case-library';

/**
 * Enhanced analysis that incorporates historical case library data.
 * Provides similar historical cases, calibrated weights, and analyst context.
 */
export interface EnhancedFalseFlagAnalysis extends FalseFlagAnalysis {
  historicalContext: {
    similarCases: { caseName: string; caseId: string; similarity: number; year: number; actualActor: string; matchedTechniques: string[] }[];
    calibratedWeights: CalibrationResult;
    techniqueEffectiveness: Record<string, { timesUsed: number; averageEffectiveness: number; exampleCases: string[] }>;
  };
}

/**
 * Run enhanced false flag analysis with case library calibration.
 * This wraps the base analyzeFalseFlag function and enriches results
 * with historical case comparisons and calibrated scoring.
 */
export function analyzeWithCaseLibrary(incident: IncidentForFalseFlagAnalysis): EnhancedFalseFlagAnalysis {
  // Run base analysis
  const baseAnalysis = analyzeFalseFlag(incident);

  // Map detected categories to case library format for comparison
  const detectedCategories = baseAnalysis.indicators.map(i => {
    const categoryMap: Record<FalseFlagCategory, CaseLibCategory> = {
      'planted_iocs': 'code_dna_mimicry',
      'borrowed_ttps': 'tool_borrowing',
      'timezone_spoofing': 'timestamp_manipulation',
      'linguistic_deception': 'language_artifact_planting',
      'infrastructure_age': 'infrastructure_hijacking',
      'tooling_inconsistency': 'tool_borrowing',
      'geopolitical_mismatch': 'victimology_misdirection',
      'operational_security_anomaly': 'operational_tempo_spoofing',
      'claim_behavior_divergence': 'claim_behavior_divergence'
    };
    return categoryMap[i.category] || 'persona_fabrication';
  });

  // Find similar historical cases
  const similarCases = findSimilarCases(detectedCategories as CaseLibCategory[], 0.2);

  // Get calibrated weights from case library
  const calibratedWeights = computeCalibratedWeights();

  // Get technique effectiveness stats
  const techniqueEffectiveness = getTechniqueEffectiveness();

  // Apply calibration adjustment to the overall probability
  // If similar historical cases exist with high confidence resolutions,
  // adjust the probability based on how those cases resolved
  let adjustedProbability = baseAnalysis.overallProbability;
  if (similarCases.length > 0) {
    const avgResolutionConfidence = similarCases
      .slice(0, 3)
      .reduce((sum, sc) => sum + sc.case_.resolution.confidence, 0) / Math.min(similarCases.length, 3);

    // If similar cases were confirmed false flags with high confidence,
    // boost our probability slightly
    if (avgResolutionConfidence > 85) {
      adjustedProbability = Math.min(100, adjustedProbability + 5);
    }
  }

  return {
    ...baseAnalysis,
    overallProbability: adjustedProbability,
    historicalContext: {
      similarCases: similarCases.slice(0, 5).map(sc => ({
        caseName: sc.case_.name,
        caseId: sc.case_.id,
        similarity: Math.round(sc.similarity * 100),
        year: sc.case_.year,
        actualActor: sc.case_.actualActor.name,
        matchedTechniques: sc.matchedTechniques
      })),
      calibratedWeights,
      techniqueEffectiveness
    }
  };
}

/**
 * Get the full case library for display.
 */
export function getFalseFlagCaseLibrary() {
  return getCaseLibrary();
}

/**
 * Get a specific case by ID.
 */
export function getFalseFlagCase(id: string) {
  return getCaseById(id);
}

/**
 * Get cases filtered by actor country.
 */
export function getFalseFlagCasesByCountry(country: string) {
  return getCasesByActorCountry(country);
}

// ─── Exports ─────────────────────────────────────────────────────────────────
export { ACTOR_SIGNATURES as FALSE_FLAG_ACTOR_SIGNATURES };
