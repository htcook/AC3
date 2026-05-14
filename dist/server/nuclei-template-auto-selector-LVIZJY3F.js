import {
  KNOWN_NUCLEI_CVES,
  NUCLEI_VULN_CLASS_TAGS,
  init_exploit_selection_intelligence
} from "./chunk-5NGBKC7L.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/nuclei-template-auto-selector.ts
async function initDynamicCache() {
  if (cacheInitialized) return;
  try {
    const { getAllTemplateMappings } = await import("./nuclei-findings-persistence-5OBQ7RLM.js");
    const mappings = await getAllTemplateMappings();
    for (const m of mappings) {
      dynamicMappingCache.set(m.cveId, {
        templatePath: m.templatePath,
        successCount: m.successCount || 1,
        lastUsedAt: m.lastUsedAt
      });
    }
    cacheInitialized = true;
    if (mappings.length > 0) {
      console.log(`[NucleiAutoSelector] Loaded ${mappings.length} dynamic template mappings from DB`);
    }
  } catch (err) {
    console.warn(`[NucleiAutoSelector] Could not load dynamic mappings: ${err.message}`);
    cacheInitialized = true;
  }
}
async function resolveNucleiTemplate(params) {
  const { cve, vulnClass, service } = params;
  if (cve && KNOWN_NUCLEI_CVES[cve]) {
    return {
      templatePath: KNOWN_NUCLEI_CVES[cve],
      tags: [cve],
      source: "static_map",
      confidence: 95,
      cveId: cve
    };
  }
  await initDynamicCache();
  if (cve && dynamicMappingCache.has(cve)) {
    const cached = dynamicMappingCache.get(cve);
    const confidence = Math.min(90, 60 + cached.successCount * 5);
    return {
      templatePath: cached.templatePath,
      tags: [cve],
      source: "dynamic_db",
      confidence,
      cveId: cve
    };
  }
  if (cve) {
    try {
      const { lookupDynamicTemplateMapping } = await import("./nuclei-findings-persistence-5OBQ7RLM.js");
      const dbTemplate = await lookupDynamicTemplateMapping(cve);
      if (dbTemplate) {
        dynamicMappingCache.set(cve, {
          templatePath: dbTemplate,
          successCount: 1,
          lastUsedAt: Date.now()
        });
        return {
          templatePath: dbTemplate,
          tags: [cve],
          source: "dynamic_db",
          confidence: 65,
          cveId: cve
        };
      }
    } catch {
    }
  }
  if (vulnClass) {
    const VULN_CLASS_ALIASES = {
      command_injection: "cmdi",
      cmd_injection: "cmdi",
      rce: "cmdi",
      remote_code_execution: "cmdi",
      path_traversal: "lfi",
      directory_traversal: "lfi",
      file_inclusion: "lfi",
      sql_injection: "sqli",
      cross_site_scripting: "xss",
      server_side_request_forgery: "ssrf",
      template_injection: "ssti",
      server_side_template_injection: "ssti",
      insecure_deserialization: "deserialization",
      unrestricted_file_upload: "file_upload",
      authentication_bypass: "auth_bypass"
    };
    const normalizedVulnClass = VULN_CLASS_ALIASES[vulnClass] || vulnClass;
    const tags = NUCLEI_VULN_CLASS_TAGS[normalizedVulnClass];
    if (tags && tags.length > 0) {
      return {
        templatePath: null,
        tags,
        source: "vuln_class_tags",
        confidence: 50,
        cveId: cve
      };
    }
  }
  return {
    templatePath: null,
    tags: [],
    source: "none",
    confidence: 0,
    cveId: cve
  };
}
async function autoMapExploitToNucleiTemplate(params) {
  const { cveId, vulnClass, service, nucleiTemplateId, exploitSuccess } = params;
  if (!cveId || !exploitSuccess) {
    return { mapped: false, cveId: cveId || "", templatePath: null, source: "none" };
  }
  if (nucleiTemplateId) {
    try {
      const { recordTemplateMapping } = await import("./nuclei-findings-persistence-5OBQ7RLM.js");
      await recordTemplateMapping({
        cveId,
        templatePath: nucleiTemplateId,
        vulnClass,
        service,
        discoveredFrom: "exploit_success"
      });
      const existing = dynamicMappingCache.get(cveId);
      dynamicMappingCache.set(cveId, {
        templatePath: nucleiTemplateId,
        successCount: (existing?.successCount || 0) + 1,
        lastUsedAt: Date.now()
      });
      return { mapped: true, cveId, templatePath: nucleiTemplateId, source: "exploit_success" };
    } catch (err) {
      console.warn(`[NucleiAutoSelector] Failed to record mapping: ${err.message}`);
    }
  }
  if (KNOWN_NUCLEI_CVES[cveId]) {
    try {
      const { recordTemplateMapping } = await import("./nuclei-findings-persistence-5OBQ7RLM.js");
      await recordTemplateMapping({
        cveId,
        templatePath: KNOWN_NUCLEI_CVES[cveId],
        vulnClass,
        service,
        discoveredFrom: "knowledge_store"
      });
      return { mapped: true, cveId, templatePath: KNOWN_NUCLEI_CVES[cveId], source: "static_map" };
    } catch {
    }
  }
  const cveMatch = cveId.match(/^CVE-(\d{4})-\d+$/);
  if (cveMatch) {
    const year = cveMatch[1];
    const inferredPath = `cves/${year}/${cveId}`;
    try {
      const { recordTemplateMapping } = await import("./nuclei-findings-persistence-5OBQ7RLM.js");
      await recordTemplateMapping({
        cveId,
        templatePath: inferredPath,
        vulnClass,
        service,
        discoveredFrom: "knowledge_store"
      });
      dynamicMappingCache.set(cveId, {
        templatePath: inferredPath,
        successCount: 1,
        lastUsedAt: Date.now()
      });
      return { mapped: true, cveId, templatePath: inferredPath, source: "inferred" };
    } catch {
    }
  }
  return { mapped: false, cveId, templatePath: null, source: "none" };
}
function clearAutoSelectorCache() {
  dynamicMappingCache.clear();
  cacheInitialized = false;
}
var dynamicMappingCache, cacheInitialized;
var init_nuclei_template_auto_selector = __esm({
  "server/lib/nuclei-template-auto-selector.ts"() {
    init_exploit_selection_intelligence();
    dynamicMappingCache = /* @__PURE__ */ new Map();
    cacheInitialized = false;
  }
});
init_nuclei_template_auto_selector();
export {
  autoMapExploitToNucleiTemplate,
  clearAutoSelectorCache,
  resolveNucleiTemplate
};
