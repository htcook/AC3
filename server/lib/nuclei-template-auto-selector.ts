/**
 * Nuclei Template Auto-Selection from Exploit Knowledge Store
 * ────────────────────────────────────────────────────────────
 * After addExploitRecipe() records a successful CVE exploit, this module
 * auto-maps it to a Nuclei template for future fast-path verification.
 *
 * Resolution order:
 *   1. Static KNOWN_NUCLEI_CVES map (hardcoded, highest confidence)
 *   2. Dynamic DB mappings from nuclei_template_mappings table
 *   3. Knowledge store search (ExploitDB/MSF/GitHub PoCs with Nuclei tags)
 *   4. Vuln-class fallback tags from NUCLEI_VULN_CLASS_TAGS
 *
 * The auto-mapper runs after successful exploits and stores new CVE→template
 * mappings in the DB for future encounters.
 */

import { KNOWN_NUCLEI_CVES, NUCLEI_VULN_CLASS_TAGS } from './exploit-selection-intelligence';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface NucleiTemplateResolution {
  templatePath: string | null;
  tags: string[];
  source: 'static_map' | 'dynamic_db' | 'knowledge_store' | 'vuln_class_tags' | 'none';
  confidence: number; // 0-100
  cveId?: string;
}

export interface AutoMapResult {
  mapped: boolean;
  cveId: string;
  templatePath: string | null;
  source: string;
}

// ─── In-Memory Cache ────────────────────────────────────────────────────────

/**
 * In-memory cache of dynamic CVE→template mappings.
 * Populated from DB on first lookup, updated on new mappings.
 */
const dynamicMappingCache = new Map<string, { templatePath: string; successCount: number; lastUsedAt: number }>();
let cacheInitialized = false;

/**
 * Initialize the dynamic mapping cache from DB.
 */
async function initDynamicCache(): Promise<void> {
  if (cacheInitialized) return;
  try {
    const { getAllTemplateMappings } = await import('./nuclei-findings-persistence');
    const mappings = await getAllTemplateMappings();
    for (const m of mappings) {
      dynamicMappingCache.set(m.cveId, {
        templatePath: m.templatePath,
        successCount: m.successCount || 1,
        lastUsedAt: m.lastUsedAt,
      });
    }
    cacheInitialized = true;
    if (mappings.length > 0) {
      console.log(`[NucleiAutoSelector] Loaded ${mappings.length} dynamic template mappings from DB`);
    }
  } catch (err: any) {
    // DB not available — will use static mappings only
    console.warn(`[NucleiAutoSelector] Could not load dynamic mappings: ${err.message}`);
    cacheInitialized = true; // Don't retry on every call
  }
}

// ─── Template Resolution ────────────────────────────────────────────────────

/**
 * Resolve the best Nuclei template for a given CVE and vuln class.
 * Checks static map → dynamic DB → knowledge store → vuln class tags.
 */
export async function resolveNucleiTemplate(params: {
  cve?: string;
  vulnClass?: string;
  service?: string;
}): Promise<NucleiTemplateResolution> {
  const { cve, vulnClass, service } = params;

  // Priority 1: Static KNOWN_NUCLEI_CVES map
  if (cve && KNOWN_NUCLEI_CVES[cve]) {
    return {
      templatePath: KNOWN_NUCLEI_CVES[cve],
      tags: [cve],
      source: 'static_map',
      confidence: 95,
      cveId: cve,
    };
  }

  // Priority 2: Dynamic DB mappings
  await initDynamicCache();
  if (cve && dynamicMappingCache.has(cve)) {
    const cached = dynamicMappingCache.get(cve)!;
    // Confidence scales with success count (min 60, max 90)
    const confidence = Math.min(90, 60 + (cached.successCount * 5));
    return {
      templatePath: cached.templatePath,
      tags: [cve],
      source: 'dynamic_db',
      confidence,
      cveId: cve,
    };
  }

  // Priority 3: DB lookup (in case cache is stale)
  if (cve) {
    try {
      const { lookupDynamicTemplateMapping } = await import('./nuclei-findings-persistence');
      const dbTemplate = await lookupDynamicTemplateMapping(cve);
      if (dbTemplate) {
        // Update cache
        dynamicMappingCache.set(cve, {
          templatePath: dbTemplate,
          successCount: 1,
          lastUsedAt: Date.now(),
        });
        return {
          templatePath: dbTemplate,
          tags: [cve],
          source: 'dynamic_db',
          confidence: 65,
          cveId: cve,
        };
      }
    } catch {
      // DB not available
    }
  }

  // Priority 4: Vuln-class tags fallback
  if (vulnClass) {
    const tags = NUCLEI_VULN_CLASS_TAGS[vulnClass];
    if (tags && tags.length > 0) {
      return {
        templatePath: null,
        tags,
        source: 'vuln_class_tags',
        confidence: 50,
        cveId: cve,
      };
    }
  }

  // No resolution
  return {
    templatePath: null,
    tags: [],
    source: 'none',
    confidence: 0,
    cveId: cve,
  };
}

// ─── Auto-Map After Successful Exploit ──────────────────────────────────────

/**
 * After a successful CVE exploit, auto-map it to a Nuclei template.
 * Called from the enhanced-exploit-orchestration after exploit success.
 *
 * Logic:
 *   - If the exploit was confirmed by Nuclei (direct or verification), extract the template ID
 *   - If the CVE has a known static mapping, record it as a dynamic mapping too (for stats)
 *   - If no template is known, try to infer from the CVE pattern (cves/YYYY/CVE-YYYY-NNNNN)
 */
export async function autoMapExploitToNucleiTemplate(params: {
  cveId: string;
  vulnClass?: string;
  service?: string;
  nucleiTemplateId?: string; // From Nuclei direct execution or verification
  exploitSuccess: boolean;
}): Promise<AutoMapResult> {
  const { cveId, vulnClass, service, nucleiTemplateId, exploitSuccess } = params;

  if (!cveId || !exploitSuccess) {
    return { mapped: false, cveId: cveId || '', templatePath: null, source: 'none' };
  }

  // If Nuclei already found a template, record that mapping
  if (nucleiTemplateId) {
    try {
      const { recordTemplateMapping } = await import('./nuclei-findings-persistence');
      await recordTemplateMapping({
        cveId,
        templatePath: nucleiTemplateId,
        vulnClass,
        service,
        discoveredFrom: 'exploit_success',
      });

      // Update in-memory cache
      const existing = dynamicMappingCache.get(cveId);
      dynamicMappingCache.set(cveId, {
        templatePath: nucleiTemplateId,
        successCount: (existing?.successCount || 0) + 1,
        lastUsedAt: Date.now(),
      });

      return { mapped: true, cveId, templatePath: nucleiTemplateId, source: 'exploit_success' };
    } catch (err: any) {
      console.warn(`[NucleiAutoSelector] Failed to record mapping: ${err.message}`);
    }
  }

  // If CVE has a static mapping, record it as dynamic too (for stats tracking)
  if (KNOWN_NUCLEI_CVES[cveId]) {
    try {
      const { recordTemplateMapping } = await import('./nuclei-findings-persistence');
      await recordTemplateMapping({
        cveId,
        templatePath: KNOWN_NUCLEI_CVES[cveId],
        vulnClass,
        service,
        discoveredFrom: 'knowledge_store',
      });
      return { mapped: true, cveId, templatePath: KNOWN_NUCLEI_CVES[cveId], source: 'static_map' };
    } catch {
      // Fire and forget
    }
  }

  // Try to infer template path from CVE pattern: cves/YYYY/CVE-YYYY-NNNNN
  const cveMatch = cveId.match(/^CVE-(\d{4})-\d+$/);
  if (cveMatch) {
    const year = cveMatch[1];
    const inferredPath = `cves/${year}/${cveId}`;

    try {
      const { recordTemplateMapping } = await import('./nuclei-findings-persistence');
      await recordTemplateMapping({
        cveId,
        templatePath: inferredPath,
        vulnClass,
        service,
        discoveredFrom: 'knowledge_store',
      });

      dynamicMappingCache.set(cveId, {
        templatePath: inferredPath,
        successCount: 1,
        lastUsedAt: Date.now(),
      });

      return { mapped: true, cveId, templatePath: inferredPath, source: 'inferred' };
    } catch {
      // Fire and forget
    }
  }

  return { mapped: false, cveId, templatePath: null, source: 'none' };
}

/**
 * Clear the in-memory cache (for testing).
 */
export function clearAutoSelectorCache(): void {
  dynamicMappingCache.clear();
  cacheInitialized = false;
}
