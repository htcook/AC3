/**
 * Knowledge Store — License-Aware Dataset Ingestion Pipeline & RAG Store
 * 
 * Manages the ingestion, chunking, indexing, and retrieval of pentest/red team
 * training data for LLM context enrichment. Implements the dataset blueprint
 * with strict license compliance (CC BY-SA 4.0, MITRE ATT&CK TOU, GPL-3.0).
 * 
 * Architecture:
 * - Source Registry: YAML-like config defining allowed sources and their licenses
 * - Document Store: JSONL-compatible records with provenance metadata
 * - Chunk Store: RAG-ready chunks with citation tracking
 * - Retrieval: Keyword + semantic search for context injection
 */

import crypto from "crypto";

// ─── License Compliance Types ───────────────────────────────────────────────

export type LicenseType =
  | "CC-BY-SA-4.0"
  | "MITRE-ATTACK-TOU"
  | "GPL-3.0"
  | "Apache-2.0"
  | "MIT"
  | "PortSwigger-Website-ToU"
  | "custom-open"
  | "reference-only";

export type AllowedUse = "train" | "rag" | "reference_only";

export interface SourceRegistryEntry {
  name: string;
  type: "git" | "web" | "api" | "manual";
  uri: string;
  license: LicenseType;
  allowedUse: AllowedUse[];
  parser: "markdown" | "html" | "json" | "text";
  attributionRequired: boolean;
  attributionText?: string;
  lastUpdated?: string;
}

// ─── Source Registry ────────────────────────────────────────────────────────

export const SOURCE_REGISTRY: SourceRegistryEntry[] = [
  {
    name: "OWASP Cheat Sheet Series",
    type: "git",
    uri: "https://github.com/OWASP/CheatSheetSeries.git",
    license: "CC-BY-SA-4.0",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "OWASP Cheat Sheet Series, licensed under CC BY-SA 4.0. https://cheatsheetseries.owasp.org/",
  },
  {
    name: "MITRE ATT&CK",
    type: "web",
    uri: "https://attack.mitre.org/",
    license: "MITRE-ATTACK-TOU",
    allowedUse: ["train", "rag"],
    parser: "json",
    attributionRequired: true,
    attributionText: "© 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
  },
  {
    name: "GTFOBins",
    type: "git",
    uri: "https://github.com/GTFOBins/GTFOBins.github.io.git",
    license: "GPL-3.0",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "GTFOBins, licensed under GPL-3.0. https://gtfobins.github.io/",
  },
  {
    name: "HackTricks",
    type: "git",
    uri: "https://github.com/HackTricks-wiki/hacktricks.git",
    license: "CC-BY-SA-4.0",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "HackTricks by Carlos Polop, licensed under CC BY-SA 4.0.",
  },
  {
    name: "PayloadsAllTheThings",
    type: "git",
    uri: "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    license: "MIT",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "PayloadsAllTheThings by swisskyrepo, MIT License.",
  },
  {
    name: "NIST NVD",
    type: "api",
    uri: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    license: "custom-open",
    allowedUse: ["train", "rag"],
    parser: "json",
    attributionRequired: true,
    attributionText: "National Vulnerability Database, NIST. Public domain.",
  },
  {
    name: "PortSwigger Web Security Academy",
    type: "web",
    uri: "https://portswigger.net/web-security",
    license: "PortSwigger-Website-ToU",
    allowedUse: ["reference_only"],
    parser: "html",
    attributionRequired: false,
    attributionText: "PortSwigger Web Security Academy. Reference only — commercial reuse restricted per Terms of Use.",
  },
  {
    name: "Atomic Red Team",
    type: "git",
    uri: "https://github.com/redcanaryco/atomic-red-team.git",
    license: "MIT",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "Atomic Red Team by Red Canary, MIT License.",
  },
  {
    name: "LOLBAS",
    type: "git",
    uri: "https://github.com/LOLBAS-Project/LOLBAS.git",
    license: "GPL-3.0",
    allowedUse: ["train", "rag"],
    parser: "markdown",
    attributionRequired: true,
    attributionText: "LOLBAS Project, licensed under GPL-3.0.",
  },
];

// ─── Document & Chunk Types ─────────────────────────────────────────────────

export interface KnowledgeDocument {
  docId: string;
  sourceName: string;
  sourceUrl: string;
  retrievedAt: string;
  license: LicenseType;
  allowedUse: AllowedUse[];
  attributionRequired: boolean;
  contentType: "md" | "html" | "json" | "text";
  topics: string[];
  skillLevel: "beginner" | "intermediate" | "advanced";
  skillAlignment: string[];    // ["pentest_fundamentals", "exploit_dev", "advanced_pentest", "red_team_ops"]
  tactics: string[];           // MITRE ATT&CK tactics
  text: string;
  hashSha256: string;
}

export interface KnowledgeChunk {
  chunkId: string;
  docId: string;
  chunkIndex: number;
  charStart: number;
  charEnd: number;
  topics: string[];
  text: string;
  citations: Array<{ sourceUrl: string; license: LicenseType }>;
  embedding?: number[];        // For vector search (future)
}

// ─── License Gate ───────────────────────────────────────────────────────────

/**
 * Enforces license compliance — prevents reference-only sources from
 * being included in training datasets.
 */
export function isAllowedForUse(source: SourceRegistryEntry, intendedUse: AllowedUse): boolean {
  return source.allowedUse.includes(intendedUse);
}

export function getTrainableSources(): SourceRegistryEntry[] {
  return SOURCE_REGISTRY.filter(s => s.allowedUse.includes("train"));
}

export function getRagSources(): SourceRegistryEntry[] {
  return SOURCE_REGISTRY.filter(s => s.allowedUse.includes("rag") || s.allowedUse.includes("train"));
}

export function getReferenceOnlySources(): SourceRegistryEntry[] {
  return SOURCE_REGISTRY.filter(s => s.allowedUse.includes("reference_only") && !s.allowedUse.includes("train"));
}

// ─── Content Processing ─────────────────────────────────────────────────────

/**
 * Hash content for integrity verification and deduplication.
 */
export function hashContent(content: string): string {
  return crypto.createHash("sha256").update(content, "utf-8").digest("hex");
}

/**
 * Normalize raw content by stripping boilerplate, nav bars, and cookie banners.
 * Preserves headings and code blocks (critical for tool literacy).
 */
export function normalizeContent(raw: string, contentType: "md" | "html" | "json" | "text"): string {
  let text = raw;

  if (contentType === "html") {
    // Strip HTML tags but preserve code blocks and headings
    text = text
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
      .replace(/<nav[^>]*>[\s\S]*?<\/nav>/gi, "")
      .replace(/<footer[^>]*>[\s\S]*?<\/footer>/gi, "")
      .replace(/<header[^>]*>[\s\S]*?<\/header>/gi, "")
      .replace(/<h([1-6])[^>]*>(.*?)<\/h\1>/gi, (_, level, content) => `${"#".repeat(parseInt(level))} ${content.replace(/<[^>]+>/g, "")}`)
      .replace(/<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi, "```\n$1\n```")
      .replace(/<code[^>]*>(.*?)<\/code>/gi, "`$1`")
      .replace(/<li[^>]*>(.*?)<\/li>/gi, "- $1")
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
  }

  // Clean up whitespace
  text = text
    .replace(/\r\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]+$/gm, "")
    .trim();

  return text;
}

/**
 * Chunk text by headings first, then by token length.
 * Preserves semantic boundaries for better retrieval.
 */
export function chunkText(
  text: string,
  maxChars: number = 2400,
  overlap: number = 200
): Array<{ start: number; end: number; text: string }> {
  const chunks: Array<{ start: number; end: number; text: string }> = [];

  // Try to split by headings first
  const headingPattern = /^#{1,3}\s+.+$/gm;
  const sections: Array<{ start: number; text: string }> = [];
  let lastEnd = 0;

  let match;
  while ((match = headingPattern.exec(text)) !== null) {
    if (match.index > lastEnd) {
      sections.push({ start: lastEnd, text: text.substring(lastEnd, match.index) });
    }
    lastEnd = match.index;
  }
  if (lastEnd < text.length) {
    sections.push({ start: lastEnd, text: text.substring(lastEnd) });
  }

  // If no headings found, fall back to character-based chunking
  if (sections.length <= 1) {
    let i = 0;
    while (i < text.length) {
      const end = Math.min(text.length, i + maxChars);
      chunks.push({ start: i, end, text: text.substring(i, end) });
      if (end >= text.length) break;
      i = Math.max(end - overlap, end);
    }
    return chunks;
  }

  // Process heading-based sections
  for (const section of sections) {
    if (section.text.length <= maxChars) {
      chunks.push({
        start: section.start,
        end: section.start + section.text.length,
        text: section.text.trim(),
      });
    } else {
      // Sub-chunk large sections
      let i = 0;
      while (i < section.text.length) {
        const end = Math.min(section.text.length, i + maxChars);
        chunks.push({
          start: section.start + i,
          end: section.start + end,
          text: section.text.substring(i, end).trim(),
        });
        if (end >= section.text.length) break;
        i = Math.max(end - overlap, end);
      }
    }
  }

  return chunks.filter(c => c.text.length > 50); // Filter out tiny chunks
}

/**
 * Create a KnowledgeDocument from raw content.
 */
export function createDocument(
  source: SourceRegistryEntry,
  rawContent: string,
  topics: string[] = [],
  skillLevel: "beginner" | "intermediate" | "advanced" = "intermediate",
  examAlignment: string[] = [],
  tactics: string[] = []
): KnowledgeDocument {
  const text = normalizeContent(rawContent, source.parser === "markdown" ? "md" : source.parser);
  const contentType = source.parser === "markdown" ? "md" : source.parser as "md" | "html" | "json" | "text";

  return {
    docId: `${source.name.replace(/\s+/g, "_")}:${hashContent(rawContent).substring(0, 12)}`,
    sourceName: source.name,
    sourceUrl: source.uri,
    retrievedAt: new Date().toISOString(),
    license: source.license,
    allowedUse: source.allowedUse,
    attributionRequired: source.attributionRequired,
    contentType,
    topics,
    skillLevel,
    examAlignment,
    tactics,
    text,
    hashSha256: hashContent(text),
  };
}

/**
 * Create chunks from a document for RAG retrieval.
 */
export function createChunks(doc: KnowledgeDocument): KnowledgeChunk[] {
  const rawChunks = chunkText(doc.text);

  return rawChunks.map((chunk, idx) => ({
    chunkId: `${doc.docId}#c${String(idx).padStart(4, "0")}`,
    docId: doc.docId,
    chunkIndex: idx,
    charStart: chunk.start,
    charEnd: chunk.end,
    topics: doc.topics,
    text: chunk.text,
    citations: [{ sourceUrl: doc.sourceUrl, license: doc.license }],
  }));
}

// ─── Attribution Builder ────────────────────────────────────────────────────

/**
 * Auto-generate NOTICE.md content with required attributions.
 * MITRE's license requires reproducing their copyright notice.
 * CC BY-SA requires attribution.
 */
export function buildAttributionNotice(): string {
  const trainableSources = getTrainableSources();
  const lines: string[] = [
    "# NOTICE — Third-Party Content Attributions",
    "",
    "This knowledge base includes content from the following sources.",
    "All content is used in compliance with its respective license terms.",
    "",
  ];

  for (const source of trainableSources) {
    if (source.attributionRequired && source.attributionText) {
      lines.push(`## ${source.name}`);
      lines.push(`- License: ${source.license}`);
      lines.push(`- URI: ${source.uri}`);
      lines.push(`- Attribution: ${source.attributionText}`);
      lines.push("");
    }
  }

  lines.push("## Reference-Only Sources (NOT included in training data)");
  lines.push("");
  for (const source of getReferenceOnlySources()) {
    lines.push(`- ${source.name}: ${source.uri} (${source.license})`);
  }

  return lines.join("\n");
}

// ─── In-Memory Knowledge Index ──────────────────────────────────────────────

/**
 * Simple keyword-based retrieval index for the knowledge store.
 * In production, this would be backed by a vector database.
 */
export class KnowledgeIndex {
  private documents: KnowledgeDocument[] = [];
  private chunks: KnowledgeChunk[] = [];
  private invertedIndex: Map<string, Set<string>> = new Map();

  addDocument(doc: KnowledgeDocument): void {
    this.documents.push(doc);
    const docChunks = createChunks(doc);
    this.chunks.push(...docChunks);

    // Build inverted index
    for (const chunk of docChunks) {
      const words = chunk.text.toLowerCase().split(/\W+/).filter(w => w.length > 2);
      for (const word of words) {
        if (!this.invertedIndex.has(word)) {
          this.invertedIndex.set(word, new Set());
        }
        this.invertedIndex.get(word)!.add(chunk.chunkId);
      }
    }
  }

  /**
   * Search for relevant chunks by keyword query.
   * Returns top-k chunks sorted by relevance score.
   */
  search(query: string, topK: number = 5, allowedUse: AllowedUse = "rag"): KnowledgeChunk[] {
    const queryWords = query.toLowerCase().split(/\W+/).filter(w => w.length > 2);
    const scores: Map<string, number> = new Map();

    for (const word of queryWords) {
      const matchingChunks = this.invertedIndex.get(word);
      if (matchingChunks) {
        for (const chunkId of matchingChunks) {
          scores.set(chunkId, (scores.get(chunkId) || 0) + 1);
        }
      }
    }

    // Sort by score descending
    const sortedChunkIds = Array.from(scores.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, topK)
      .map(([id]) => id);

    // Filter by allowed use
    return sortedChunkIds
      .map(id => this.chunks.find(c => c.chunkId === id))
      .filter((c): c is KnowledgeChunk => {
        if (!c) return false;
        const doc = this.documents.find(d => d.docId === c.docId);
        return doc ? doc.allowedUse.includes(allowedUse) : false;
      });
  }

  getStats(): {
    totalDocuments: number;
    totalChunks: number;
    totalTerms: number;
    sourceBreakdown: Record<string, number>;
    licenseBreakdown: Record<string, number>;
  } {
    const sourceBreakdown: Record<string, number> = {};
    const licenseBreakdown: Record<string, number> = {};

    for (const doc of this.documents) {
      sourceBreakdown[doc.sourceName] = (sourceBreakdown[doc.sourceName] || 0) + 1;
      licenseBreakdown[doc.license] = (licenseBreakdown[doc.license] || 0) + 1;
    }

    return {
      totalDocuments: this.documents.length,
      totalChunks: this.chunks.length,
      totalTerms: this.invertedIndex.size,
      sourceBreakdown,
      licenseBreakdown,
    };
  }
}

// ─── Offensive Security Skill Tags Taxonomy ────────────────────────────────────

export const SKILL_TAXONOMY = {
  corePhases: [
    "recon", "enumeration", "initial_access", "lateral_movement",
    "privilege_escalation", "persistence", "exfiltration", "cleanup", "reporting",
  ] as const,

  pentestTechniques: [
    "nmap", "web_enum", "smb_enum", "ad_enum", "password_attacks",
    "file_inclusion", "sqli", "xss", "ssrf", "upload_bypass",
    "deserialization", "privesc_linux", "privesc_windows",
    "command_injection", "path_traversal", "ssti", "xxe",
    "dns_enum", "snmp_enum", "ldap_enum", "kerberos",
  ] as const,

  exploitDevTechniques: [
    "debugging", "win32", "seh", "rop", "shellcoding",
    "heap", "fuzzing", "egghunter", "badchars", "dep_aslr",
    "format_string", "use_after_free", "type_confusion",
  ] as const,

  skillAlignments: [
    "pentest_fundamentals", "advanced_pentest", "exploit_development",
    "web_app_security", "red_team_operations", "network_pentest",
    "active_directory_attacks", "cloud_security_testing",
    "mobile_app_security", "wireless_security",
  ] as const,
};

/**
 * Tag a document with relevant skill taxonomy labels.
 */
export function autoTagDocument(text: string): {
  phases: string[];
  pentestTags: string[];
  exploitDevTags: string[];
  skillAlignment: string[];
} {
  const lower = text.toLowerCase();
  const phases = SKILL_TAXONOMY.corePhases.filter(p => lower.includes(p.replace("_", " ")));
  const pentestTags = SKILL_TAXONOMY.pentestTechniques.filter(t => lower.includes(t.replace("_", " ")));
  const exploitDevTags = SKILL_TAXONOMY.exploitDevTechniques.filter(t => lower.includes(t.replace("_", " ")));
  const skillAlignment = SKILL_TAXONOMY.skillAlignments.filter(c => lower.includes(c.replace("_", " ")));

  return { phases, pentestTags, exploitDevTags, skillAlignment };
}
