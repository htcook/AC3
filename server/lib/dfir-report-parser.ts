/**
 * DFIR Report Parser Library
 * 
 * Parses threat intelligence reports from multiple sources:
 * - The DFIR Report (thedfirreport.com) — HTML scraping
 * - CISA Advisories — STIX 2.1 JSON
 * - AlienVault OTX — API JSON
 * - Manual uploads — Markdown/text with LLM extraction
 */

export interface ParsedDfirReport {
  externalId: string;
  source: 'dfir_report' | 'cisa' | 'otx' | 'mandiant' | 'unit42' | 'recorded_future' | 'manual';
  title: string;
  url?: string;
  publishedAt?: string;
  summary?: string;
  threatActors: string[];
  malwareFamilies: string[];
  mitreAttackTechniques: { techniqueId: string; name: string; tactic: string }[];
  iocs: ParsedIoc[];
  diamondModel?: { adversary?: string; capability?: string; infrastructure?: string; victim?: string };
  timeline?: { timestamp?: string; event: string; detail?: string }[];
  detections?: { sigma?: string[]; suricata?: string[]; yara?: string[] };
  killChainPhases: string[];
  tags: string[];
  rawContent: string;
}

export interface ParsedIoc {
  type: 'ip' | 'domain' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'url' | 'email' | 'cve' | 'filename' | 'registry_key' | 'mutex';
  value: string;
  context?: string;
}

// ─── IOC Extraction Patterns ────────────────────────────────────────────────

const IOC_PATTERNS = {
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|xyz|top|info|biz|cc|ru|cn|tk|ml|ga|cf|gq|pw|club|online|site|tech|space|pro|work|live|store|ltd|group|click|link|download|stream)\b/gi,
  hash_md5: /\b[a-fA-F0-9]{32}\b/g,
  hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
  hash_sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /CVE-\d{4}-\d{4,}/gi,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
  url: /https?:\/\/[^\s"'<>\]]+/gi,
};

// Common false-positive IPs to exclude
const FP_IPS = new Set(['0.0.0.0', '127.0.0.1', '255.255.255.255', '192.168.1.1', '10.0.0.1', '172.16.0.1']);

export function extractIocs(text: string): ParsedIoc[] {
  const iocs: ParsedIoc[] = [];
  const seen = new Set<string>();

  function addIoc(type: ParsedIoc['type'], value: string, context?: string) {
    const key = `${type}:${value.toLowerCase()}`;
    if (!seen.has(key)) {
      seen.add(key);
      iocs.push({ type, value, context });
    }
  }

  // Extract CVEs first (they contain numbers that could match other patterns)
  for (const m of text.matchAll(IOC_PATTERNS.cve)) {
    addIoc('cve', m[0].toUpperCase());
  }

  // SHA-256 (64 hex chars)
  for (const m of text.matchAll(IOC_PATTERNS.hash_sha256)) {
    addIoc('hash_sha256', m[0].toLowerCase());
  }

  // SHA-1 (40 hex chars) — exclude if already matched as part of SHA-256
  for (const m of text.matchAll(IOC_PATTERNS.hash_sha1)) {
    if (!seen.has(`hash_sha256:${m[0].toLowerCase()}`)) {
      addIoc('hash_sha1', m[0].toLowerCase());
    }
  }

  // MD5 (32 hex chars) — exclude if part of longer hash
  for (const m of text.matchAll(IOC_PATTERNS.hash_md5)) {
    if (!seen.has(`hash_sha1:${m[0].toLowerCase()}`) && !seen.has(`hash_sha256:${m[0].toLowerCase()}`)) {
      addIoc('hash_md5', m[0].toLowerCase());
    }
  }

  // IPs
  for (const m of text.matchAll(IOC_PATTERNS.ip)) {
    if (!FP_IPS.has(m[0])) {
      addIoc('ip', m[0]);
    }
  }

  // Domains
  for (const m of text.matchAll(IOC_PATTERNS.domain)) {
    // Skip common non-IOC domains
    if (!/\.(google|microsoft|github|mozilla|w3|wikipedia|cloudflare|amazonaws|azure)\./i.test(m[0])) {
      addIoc('domain', m[0].toLowerCase());
    }
  }

  // URLs
  for (const m of text.matchAll(IOC_PATTERNS.url)) {
    const url = m[0].replace(/[.,;)}\]]+$/, ''); // trim trailing punctuation
    if (!/\.(google|microsoft|github|mozilla|w3|wikipedia)\./i.test(url)) {
      addIoc('url', url);
    }
  }

  return iocs;
}

// ─── MITRE ATT&CK Technique Extraction ─────────────────────────────────────

const TECHNIQUE_PATTERN = /T\d{4}(?:\.\d{3})?/g;

const TACTIC_MAP: Record<string, string> = {
  'reconnaissance': 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral-movement': 'Lateral Movement',
  'collection': 'Collection',
  'command-and-control': 'Command and Control',
  'exfiltration': 'Exfiltration',
  'impact': 'Impact',
};

export function extractMitreTechniques(text: string): { techniqueId: string; name: string; tactic: string }[] {
  const techniques: { techniqueId: string; name: string; tactic: string }[] = [];
  const seen = new Set<string>();

  // Pattern: "Technique Name - T1234.001" or "T1234 - Technique Name"
  const namedPattern = /([A-Z][A-Za-z\s/&-]+)\s*[-–—]\s*(T\d{4}(?:\.\d{3})?)|(T\d{4}(?:\.\d{3})?)\s*[-–—]\s*([A-Z][A-Za-z\s/&-]+)/g;
  for (const m of text.matchAll(namedPattern)) {
    const id = (m[2] || m[3]).trim();
    const name = (m[1] || m[4]).trim();
    if (!seen.has(id)) {
      seen.add(id);
      techniques.push({ techniqueId: id, name, tactic: guessTacticFromContext(text, id) });
    }
  }

  // Standalone technique IDs
  for (const m of text.matchAll(TECHNIQUE_PATTERN)) {
    if (!seen.has(m[0])) {
      seen.add(m[0]);
      techniques.push({ techniqueId: m[0], name: m[0], tactic: guessTacticFromContext(text, m[0]) });
    }
  }

  return techniques;
}

function guessTacticFromContext(text: string, techniqueId: string): string {
  // Look for the technique ID near a tactic heading
  const idx = text.indexOf(techniqueId);
  if (idx === -1) return 'Unknown';

  const contextBefore = text.slice(Math.max(0, idx - 500), idx).toLowerCase();
  for (const [key, value] of Object.entries(TACTIC_MAP)) {
    if (contextBefore.includes(key) || contextBefore.includes(value.toLowerCase())) {
      return value;
    }
  }
  return 'Unknown';
}

// ─── The DFIR Report HTML Parser ────────────────────────────────────────────

export function parseDfirReportHtml(html: string, url: string): ParsedDfirReport {
  // Extract title
  const titleMatch = html.match(/<h1[^>]*class="[^"]*entry-title[^"]*"[^>]*>(.*?)<\/h1>/is)
    || html.match(/<title>(.*?)(?:\s*[-|].*)?<\/title>/i);
  const title = titleMatch ? stripHtml(titleMatch[1]) : 'Unknown Report';

  // Extract date
  const dateMatch = html.match(/<time[^>]*datetime="([^"]+)"/i)
    || html.match(/(\w+ \d{1,2}, \d{4})/);
  const publishedAt = dateMatch ? dateMatch[1] : undefined;

  // Extract main content
  const contentMatch = html.match(/<div[^>]*class="[^"]*entry-content[^"]*"[^>]*>([\s\S]*?)<\/div>\s*(?:<footer|<div[^>]*class="[^"]*(?:post-navigation|comments))/i);
  const rawContent = contentMatch ? stripHtml(contentMatch[1]) : stripHtml(html);

  // Extract case summary
  const summaryMatch = rawContent.match(/(?:Case Summary|Overview|Summary)\s*\n([\s\S]*?)(?:\n(?:Services|Analysts|Initial Access|Key Takeaways))/i);
  const summary = summaryMatch ? summaryMatch[1].trim().slice(0, 2000) : rawContent.slice(0, 1000);

  // Extract threat actors from tags and content
  const threatActors = extractThreatActors(html, rawContent);

  // Extract malware families from tags
  const malwareFamilies = extractMalwareFamilies(html, rawContent);

  // Extract MITRE ATT&CK techniques
  const mitreAttackTechniques = extractMitreTechniques(rawContent);

  // Extract IOCs
  const iocs = extractIocs(rawContent);

  // Extract Diamond Model
  const diamondModel = extractDiamondModel(rawContent);

  // Extract timeline
  const timeline = extractTimeline(rawContent);

  // Extract tags from HTML
  const tags = extractTags(html);

  // Determine kill chain phases from ATT&CK tactics
  const killChainPhases = [...new Set(mitreAttackTechniques.map(t => t.tactic).filter(t => t !== 'Unknown'))];

  // Generate external ID from URL
  const externalId = url.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);

  return {
    externalId,
    source: 'dfir_report',
    title,
    url,
    publishedAt,
    summary,
    threatActors,
    malwareFamilies,
    mitreAttackTechniques,
    iocs,
    diamondModel,
    timeline,
    killChainPhases,
    tags,
    rawContent: rawContent.slice(0, 100000), // cap at 100KB
  };
}

// ─── CISA STIX 2.1 Parser ──────────────────────────────────────────────────

export function parseCisaStix(stixBundle: any): ParsedDfirReport {
  const objects = stixBundle.objects || [];

  // Find the report object
  const report = objects.find((o: any) => o.type === 'report') || {};
  const title = report.name || 'CISA Advisory';
  const summary = report.description || '';
  const publishedAt = report.published || report.created;
  const externalId = report.id || `cisa-${Date.now()}`;

  // Extract attack patterns (ATT&CK techniques)
  const attackPatterns = objects.filter((o: any) => o.type === 'attack-pattern');
  const mitreAttackTechniques = attackPatterns.map((ap: any) => {
    const extRef = (ap.external_references || []).find((r: any) => r.source_name === 'mitre-attack');
    return {
      techniqueId: extRef?.external_id || ap.name,
      name: ap.name || '',
      tactic: (ap.kill_chain_phases || []).map((k: any) => TACTIC_MAP[k.phase_name] || k.phase_name).join(', ') || 'Unknown',
    };
  });

  // Extract indicators (IOCs)
  const indicators = objects.filter((o: any) => o.type === 'indicator');
  const iocs: ParsedIoc[] = [];
  for (const ind of indicators) {
    const pattern = ind.pattern || '';
    // Parse STIX patterns like [ipv4-addr:value = '1.2.3.4']
    const ipMatch = pattern.match(/ipv4-addr:value\s*=\s*'([^']+)'/);
    if (ipMatch) iocs.push({ type: 'ip', value: ipMatch[1] });

    const domainMatch = pattern.match(/domain-name:value\s*=\s*'([^']+)'/);
    if (domainMatch) iocs.push({ type: 'domain', value: domainMatch[1] });

    const hashMatch = pattern.match(/file:hashes\.'([^']+)'\s*=\s*'([^']+)'/);
    if (hashMatch) {
      const hashType = hashMatch[1].toLowerCase();
      const hashValue = hashMatch[2];
      if (hashType.includes('sha-256') || hashType.includes('sha256')) iocs.push({ type: 'hash_sha256', value: hashValue });
      else if (hashType.includes('sha-1') || hashType.includes('sha1')) iocs.push({ type: 'hash_sha1', value: hashValue });
      else if (hashType.includes('md5')) iocs.push({ type: 'hash_md5', value: hashValue });
    }

    const urlMatch = pattern.match(/url:value\s*=\s*'([^']+)'/);
    if (urlMatch) iocs.push({ type: 'url', value: urlMatch[1] });
  }

  // Also extract IOCs from text content
  iocs.push(...extractIocs(summary));

  // Extract threat actors
  const threatActorObjs = objects.filter((o: any) => o.type === 'threat-actor' || o.type === 'intrusion-set');
  const threatActors = threatActorObjs.map((ta: any) => ta.name).filter(Boolean);

  // Extract malware
  const malwareObjs = objects.filter((o: any) => o.type === 'malware' || o.type === 'tool');
  const malwareFamilies = malwareObjs.map((m: any) => m.name).filter(Boolean);

  // Extract tags from labels
  const tags = [...new Set(objects.flatMap((o: any) => o.labels || []))];

  const killChainPhases = [...new Set(mitreAttackTechniques.map((t: any) => t.tactic).filter((t: string) => t !== 'Unknown'))];

  return {
    externalId,
    source: 'cisa',
    title,
    url: (report.external_references || []).find((r: any) => r.url)?.url,
    publishedAt,
    summary: summary.slice(0, 2000),
    threatActors,
    malwareFamilies,
    mitreAttackTechniques,
    iocs,
    killChainPhases,
    tags,
    rawContent: JSON.stringify(stixBundle).slice(0, 100000),
  };
}

// ─── AlienVault OTX Pulse Parser ────────────────────────────────────────────

export function parseOtxPulse(pulse: any): ParsedDfirReport {
  const title = pulse.name || 'OTX Pulse';
  const summary = pulse.description || '';
  const publishedAt = pulse.created || pulse.modified;
  const externalId = `otx-${pulse.id || Date.now()}`;

  // Extract IOCs from indicators
  const iocs: ParsedIoc[] = [];
  for (const ind of (pulse.indicators || [])) {
    const typeMap: Record<string, ParsedIoc['type']> = {
      'IPv4': 'ip',
      'IPv6': 'ip',
      'domain': 'domain',
      'hostname': 'domain',
      'URL': 'url',
      'FileHash-MD5': 'hash_md5',
      'FileHash-SHA1': 'hash_sha1',
      'FileHash-SHA256': 'hash_sha256',
      'email': 'email',
      'CVE': 'cve',
      'Mutex': 'mutex',
      'FilePath': 'filename',
    };
    const iocType = typeMap[ind.type];
    if (iocType) {
      iocs.push({ type: iocType, value: ind.indicator, context: ind.description });
    }
  }

  // Extract ATT&CK techniques from attack_ids
  const mitreAttackTechniques = (pulse.attack_ids || []).map((a: any) => ({
    techniqueId: a.id || a.name,
    name: a.display_name || a.name || a.id,
    tactic: 'Unknown',
  }));

  // Extract threat actors and malware from tags
  const tags = pulse.tags || [];
  const threatActors = (pulse.adversary || '').split(',').map((s: string) => s.trim()).filter(Boolean);
  const malwareFamilies = (pulse.malware_families || []).map((m: any) => typeof m === 'string' ? m : m.display_name || m.name).filter(Boolean);

  const killChainPhases = [...new Set(mitreAttackTechniques.map((t: any) => t.tactic).filter((t: string) => t !== 'Unknown'))];

  return {
    externalId,
    source: 'otx',
    title,
    url: `https://otx.alienvault.com/pulse/${pulse.id}`,
    publishedAt,
    summary: summary.slice(0, 2000),
    threatActors,
    malwareFamilies,
    mitreAttackTechniques,
    iocs,
    killChainPhases,
    tags,
    rawContent: JSON.stringify(pulse).slice(0, 100000),
  };
}

// ─── Manual / Markdown Report Parser ────────────────────────────────────────

export function parseManualReport(content: string, title: string, url?: string): ParsedDfirReport {
  const iocs = extractIocs(content);
  const mitreAttackTechniques = extractMitreTechniques(content);
  const threatActors = extractThreatActors('', content);
  const malwareFamilies = extractMalwareFamilies('', content);
  const timeline = extractTimeline(content);
  const killChainPhases = [...new Set(mitreAttackTechniques.map(t => t.tactic).filter(t => t !== 'Unknown'))];

  return {
    externalId: `manual-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    source: 'manual',
    title,
    url,
    summary: content.slice(0, 2000),
    threatActors,
    malwareFamilies,
    mitreAttackTechniques,
    iocs,
    timeline,
    killChainPhases,
    tags: [],
    rawContent: content.slice(0, 100000),
  };
}

// ─── Auto-detect and parse ──────────────────────────────────────────────────

export function autoDetectAndParse(content: string, fileName?: string, url?: string): ParsedDfirReport {
  // Try STIX JSON
  try {
    const json = JSON.parse(content);
    if (json.type === 'bundle' && json.objects) {
      return parseCisaStix(json);
    }
    if (json.id && json.indicators) {
      return parseOtxPulse(json);
    }
  } catch {
    // Not JSON
  }

  // Try DFIR Report HTML
  if (content.includes('<!doctype html') || content.includes('<html') || content.includes('entry-content')) {
    return parseDfirReportHtml(content, url || '');
  }

  // Fallback to manual
  return parseManualReport(content, fileName || 'Uploaded Report', url);
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function stripHtml(html: string): string {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractThreatActors(html: string, text: string): string[] {
  const actors: Set<string> = new Set();

  // Known APT/threat group patterns
  const aptPattern = /\b(APT\d{1,3}|FIN\d{1,2}|UNC\d{3,4}|TA\d{3,4}|DEV-\d{4}|Storm-\d{4}|Scattered Spider|Lazarus|Kimsuky|Turla|Sandworm|Fancy Bear|Cozy Bear|Charming Kitten|MuddyWater|OilRig|Volt Typhoon|Salt Typhoon|Flax Typhoon|BlackSuit|LockBit|BlackCat|ALPHV|Cl0p|RansomHub|Akira|Play|Royal|BianLian|Medusa|Rhysida|NoEscape|8Base|Hunters International|DragonForce|Fog|ELPACO|Lunar Spider|KongTuke)\b/gi;

  for (const m of text.matchAll(aptPattern)) {
    actors.add(m[0]);
  }

  // Extract from HTML tags/categories
  const tagPattern = /rel="tag"[^>]*>([^<]+)</gi;
  for (const m of html.matchAll(tagPattern)) {
    const tag = m[1].trim();
    if (/^(APT|FIN|UNC|TA\d|DEV-|Storm-)/i.test(tag) || /ransomware|spider|bear|kitten|typhoon/i.test(tag)) {
      actors.add(tag);
    }
  }

  return [...actors];
}

function extractMalwareFamilies(html: string, text: string): string[] {
  const families: Set<string> = new Set();

  const malwarePattern = /\b(Cobalt Strike|CobaltStrike|Brute Ratel|BruteRatel|Sliver|Metasploit|Meterpreter|Mimikatz|BloodHound|Rubeus|SharpHound|Impacket|PsExec|SectopRAT|QakBot|Qbot|IcedID|BumbleBee|Emotet|TrickBot|BazarLoader|SystemBC|Beacon|Nighthawk|Havoc|Mythic|AdaptixC2|IDAT loader|d3f@ck loader|Latrodectus|AsyncRAT|RemcosRAT|NjRAT|DarkComet|AgentTesla|FormBook|RedLine|Raccoon|Vidar|Lumma|StealC|SmokeLoader|GuLoader|Pikabot|DarkGate|NetSupport|AnyDesk|TeamViewer|ConnectWise|Splashtop|Atera|ScreenConnect|RustDesk|MeshAgent|ngrok|Chisel|ligolo|frp|cloudflared)\b/gi;

  for (const m of text.matchAll(malwarePattern)) {
    families.add(m[0]);
  }

  // From HTML tags
  const tagPattern = /rel="tag"[^>]*>([^<]+)</gi;
  for (const m of html.matchAll(tagPattern)) {
    const tag = m[1].trim();
    if (/strike|ratel|sliver|loader|rat|bot|stealer|ransom/i.test(tag)) {
      families.add(tag);
    }
  }

  return [...families];
}

function extractDiamondModel(text: string): { adversary?: string; capability?: string; infrastructure?: string; victim?: string } | undefined {
  const dmSection = text.match(/Diamond Model[\s\S]*?(?=\n(?:Indicators|Detections|MITRE|Timeline|$))/i);
  if (!dmSection) return undefined;

  const section = dmSection[0];
  const adversary = section.match(/Adversary[:\s]+([^\n]+)/i)?.[1]?.trim();
  const capability = section.match(/Capability[:\s]+([^\n]+)/i)?.[1]?.trim();
  const infrastructure = section.match(/Infrastructure[:\s]+([^\n]+)/i)?.[1]?.trim();
  const victim = section.match(/Victim[:\s]+([^\n]+)/i)?.[1]?.trim();

  if (adversary || capability || infrastructure || victim) {
    return { adversary, capability, infrastructure, victim };
  }
  return undefined;
}

function extractTimeline(text: string): { timestamp?: string; event: string; detail?: string }[] {
  const timeline: { timestamp?: string; event: string; detail?: string }[] = [];

  // Pattern: "HH:MM:SS" or "YYYY-MM-DD HH:MM" followed by event description
  const timelinePattern = /(\d{1,2}:\d{2}(?::\d{2})?(?:\s*(?:AM|PM|UTC))?|\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2})?)\s*[-–—:]\s*(.+?)(?=\n\d{1,2}:\d{2}|\n\d{4}-\d{2}-\d{2}|\n\n|$)/gm;

  const timelineSection = text.match(/Timeline[\s\S]*?(?=\n(?:Diamond Model|Indicators|Detections|MITRE|$))/i);
  const searchText = timelineSection ? timelineSection[0] : text;

  for (const m of searchText.matchAll(timelinePattern)) {
    timeline.push({
      timestamp: m[1].trim(),
      event: m[2].trim().slice(0, 500),
    });
    if (timeline.length >= 100) break; // cap at 100 events
  }

  return timeline;
}

function extractTags(html: string): string[] {
  const tags: Set<string> = new Set();
  const tagPattern = /rel="tag"[^>]*>([^<]+)</gi;
  for (const m of html.matchAll(tagPattern)) {
    tags.add(m[1].trim().toLowerCase());
  }
  return [...tags];
}
