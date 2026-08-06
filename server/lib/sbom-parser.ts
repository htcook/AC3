/**
 * SBOM (Software Bill of Materials) Parser
 * Supports CycloneDX (JSON/XML) and SPDX (JSON/tag-value) formats
 * Extracts component inventory for supplier tech stack population
 */

import { getDb } from "../db";
import { supplierTechStacks } from "../../drizzle/schema";
import { randomUUID } from "crypto";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SBOMComponent {
  name: string;
  vendor: string;
  version: string;
  type: "application" | "library" | "framework" | "operating-system" | "device" | "firmware" | "container" | "other";
  purl?: string; // Package URL
  cpe?: string; // Common Platform Enumeration
  licenses?: string[];
  description?: string;
}

export interface SBOMParseResult {
  format: "cyclonedx" | "spdx" | "unknown";
  specVersion: string;
  bomRef?: string;
  subject?: string; // Primary component name
  components: SBOMComponent[];
  errors: string[];
}

export interface SBOMImportResult {
  supplierId: string;
  totalComponents: number;
  imported: number;
  skipped: number;
  duplicates: number;
  errors: string[];
}

// ─── CycloneDX Parser ───────────────────────────────────────────────────────

function parseCycloneDXJSON(data: any): SBOMParseResult {
  const result: SBOMParseResult = {
    format: "cyclonedx",
    specVersion: data.specVersion || data.bomFormat || "unknown",
    bomRef: data.serialNumber,
    subject: data.metadata?.component?.name,
    components: [],
    errors: [],
  };

  const components = data.components || [];
  for (const comp of components) {
    try {
      const component: SBOMComponent = {
        name: comp.name || "unknown",
        vendor: comp.publisher || comp.author || extractVendorFromPurl(comp.purl) || "unknown",
        version: comp.version || "unknown",
        type: mapCycloneDXType(comp.type),
        purl: comp.purl,
        cpe: comp.cpe,
        licenses: extractCycloneDXLicenses(comp.licenses),
        description: comp.description,
      };
      result.components.push(component);
    } catch (err: any) {
      result.errors.push(`Failed to parse component: ${comp.name || "unknown"} - ${err.message}`);
    }
  }

  return result;
}

function parseCycloneDXXML(xmlContent: string): SBOMParseResult {
  const result: SBOMParseResult = {
    format: "cyclonedx",
    specVersion: "xml",
    components: [],
    errors: [],
  };

  // Simple XML parsing for CycloneDX components
  const componentRegex = /<component[^>]*type="([^"]*)"[^>]*>([\s\S]*?)<\/component>/g;
  const nameRegex = /<name>(.*?)<\/name>/;
  const versionRegex = /<version>(.*?)<\/version>/;
  const publisherRegex = /<publisher>(.*?)<\/publisher>/;
  const purlRegex = /<purl>(.*?)<\/purl>/;

  let match;
  while ((match = componentRegex.exec(xmlContent)) !== null) {
    const type = match[1];
    const content = match[2];

    const name = nameRegex.exec(content)?.[1] || "unknown";
    const version = versionRegex.exec(content)?.[1] || "unknown";
    const publisher = publisherRegex.exec(content)?.[1] || "unknown";
    const purl = purlRegex.exec(content)?.[1];

    result.components.push({
      name,
      vendor: publisher || extractVendorFromPurl(purl) || "unknown",
      version,
      type: mapCycloneDXType(type),
      purl: purl || undefined,
    });
  }

  if (result.components.length === 0) {
    result.errors.push("No components found in CycloneDX XML. File may be malformed.");
  }

  return result;
}

// ─── SPDX Parser ────────────────────────────────────────────────────────────

function parseSPDXJSON(data: any): SBOMParseResult {
  const result: SBOMParseResult = {
    format: "spdx",
    specVersion: data.spdxVersion || "unknown",
    bomRef: data.SPDXID,
    subject: data.name,
    components: [],
    errors: [],
  };

  const packages = data.packages || [];
  for (const pkg of packages) {
    // Skip the document-level package
    if (pkg.SPDXID === "SPDXRef-DOCUMENT") continue;

    try {
      const component: SBOMComponent = {
        name: pkg.name || "unknown",
        vendor: pkg.supplier?.replace(/^Organization:\s*/, "") || pkg.originator?.replace(/^Organization:\s*/, "") || "unknown",
        version: pkg.versionInfo || "unknown",
        type: mapSPDXType(pkg.primaryPackagePurpose),
        purl: extractPurlFromExternalRefs(pkg.externalRefs),
        cpe: extractCPEFromExternalRefs(pkg.externalRefs),
        licenses: pkg.licenseConcluded ? [pkg.licenseConcluded] : [],
        description: pkg.description,
      };
      result.components.push(component);
    } catch (err: any) {
      result.errors.push(`Failed to parse package: ${pkg.name || "unknown"} - ${err.message}`);
    }
  }

  return result;
}

function parseSPDXTagValue(content: string): SBOMParseResult {
  const result: SBOMParseResult = {
    format: "spdx",
    specVersion: "tag-value",
    components: [],
    errors: [],
  };

  const lines = content.split("\n");
  let currentPkg: Partial<SBOMComponent> | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("PackageName:")) {
      if (currentPkg && currentPkg.name) {
        result.components.push(currentPkg as SBOMComponent);
      }
      currentPkg = {
        name: trimmed.replace("PackageName:", "").trim(),
        vendor: "unknown",
        version: "unknown",
        type: "application",
      };
    } else if (currentPkg) {
      if (trimmed.startsWith("PackageVersion:")) {
        currentPkg.version = trimmed.replace("PackageVersion:", "").trim();
      } else if (trimmed.startsWith("PackageSupplier:")) {
        currentPkg.vendor = trimmed.replace("PackageSupplier:", "").trim().replace(/^Organization:\s*/, "");
      } else if (trimmed.startsWith("ExternalRef:") && trimmed.includes("purl")) {
        const purlMatch = trimmed.match(/pkg:[^\s]+/);
        if (purlMatch) currentPkg.purl = purlMatch[0];
      }
    }
  }

  // Push last package
  if (currentPkg && currentPkg.name) {
    result.components.push(currentPkg as SBOMComponent);
  }

  return result;
}

// ─── Main Parse Function ────────────────────────────────────────────────────

export function parseSBOM(content: string, filename?: string): SBOMParseResult {
  const trimmed = content.trim();

  // Try JSON first
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const data = JSON.parse(trimmed);

      // CycloneDX JSON
      if (data.bomFormat === "CycloneDX" || data.specVersion || data.$schema?.includes("cyclonedx")) {
        return parseCycloneDXJSON(data);
      }

      // SPDX JSON
      if (data.spdxVersion || data.SPDXID || data.$schema?.includes("spdx")) {
        return parseSPDXJSON(data);
      }

      // Try to detect by structure
      if (data.components && Array.isArray(data.components)) {
        return parseCycloneDXJSON(data);
      }
      if (data.packages && Array.isArray(data.packages)) {
        return parseSPDXJSON(data);
      }

      return { format: "unknown", specVersion: "unknown", components: [], errors: ["Unable to detect SBOM format from JSON structure"] };
    } catch {
      // Not valid JSON, try other formats
    }
  }

  // Try CycloneDX XML
  if (trimmed.includes("<bom") || trimmed.includes("cyclonedx") || trimmed.includes("xmlns=\"http://cyclonedx.org")) {
    return parseCycloneDXXML(trimmed);
  }

  // Try SPDX tag-value
  if (trimmed.includes("SPDXVersion:") || trimmed.includes("PackageName:")) {
    return parseSPDXTagValue(trimmed);
  }

  return { format: "unknown", specVersion: "unknown", components: [], errors: ["Unable to detect SBOM format. Supported: CycloneDX (JSON/XML), SPDX (JSON/tag-value)"] };
}

// ─── Import to Database ─────────────────────────────────────────────────────

export async function importSBOMToSupplier(
  supplierId: string,
  sbomContent: string,
  options: {
    filename?: string;
    overwrite?: boolean;
    minCriticality?: string;
    filterTypes?: string[];
  } = {}
): Promise<SBOMImportResult> {
  const db = await getDb();
  const parseResult = parseSBOM(sbomContent, options.filename);

  const result: SBOMImportResult = {
    supplierId,
    totalComponents: parseResult.components.length,
    imported: 0,
    skipped: 0,
    duplicates: 0,
    errors: [...parseResult.errors],
  };

  if (parseResult.components.length === 0) {
    result.errors.push("No components found in SBOM file");
    return result;
  }

  // Filter by type if specified
  let components = parseResult.components;
  if (options.filterTypes && options.filterTypes.length > 0) {
    components = components.filter(c => options.filterTypes!.includes(c.type));
  }

  // Get existing tech stack for deduplication
  const [existingRows] = await db.execute(
    `SELECT product, vendor, version FROM supplier_tech_stacks WHERE supplier_id = ?`,
    [supplierId]
  ) as any;
  const existingSet = new Set(
    (existingRows || []).map((r: any) => `${r.vendor}:${r.product}:${r.version}`.toLowerCase())
  );

  // Import components
  for (const component of components) {
    const key = `${component.vendor}:${component.name}:${component.version}`.toLowerCase();

    if (existingSet.has(key) && !options.overwrite) {
      result.duplicates++;
      continue;
    }

    // Determine criticality based on type
    const criticality = inferCriticality(component);
    if (options.minCriticality && criticalityRank(criticality) < criticalityRank(options.minCriticality)) {
      result.skipped++;
      continue;
    }

    try {
      const stackId = randomUUID().replace(/-/g, "").substring(0, 16);
      await db.execute(
        `INSERT INTO supplier_tech_stacks (stack_id, supplier_id, product, vendor, version, category, criticality, deployment_scope, notes, last_verified, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'production', ?, NOW(), NOW())
         ON DUPLICATE KEY UPDATE version = VALUES(version), last_verified = NOW()`,
        [
          stackId,
          supplierId,
          component.name,
          component.vendor,
          component.version,
          component.type,
          criticality,
          component.purl ? `PURL: ${component.purl}` : (component.description || null),
        ]
      );
      result.imported++;
      existingSet.add(key);
    } catch (err: any) {
      result.errors.push(`Failed to import ${component.name}: ${err.message}`);
    }
  }

  return result;
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function extractVendorFromPurl(purl?: string): string | undefined {
  if (!purl) return undefined;
  // pkg:npm/@vendor/name or pkg:maven/group/artifact
  const match = purl.match(/pkg:[^/]+\/(@?[^/]+)/);
  return match?.[1]?.replace("@", "");
}

function extractPurlFromExternalRefs(refs?: any[]): string | undefined {
  if (!refs) return undefined;
  const purlRef = refs.find(r => r.referenceType === "purl");
  return purlRef?.referenceLocator;
}

function extractCPEFromExternalRefs(refs?: any[]): string | undefined {
  if (!refs) return undefined;
  const cpeRef = refs.find(r => r.referenceType === "cpe23Type" || r.referenceType === "cpe22Type");
  return cpeRef?.referenceLocator;
}

function extractCycloneDXLicenses(licenses?: any[]): string[] {
  if (!licenses) return [];
  return licenses.map(l => l.license?.id || l.license?.name || l.expression || "unknown").filter(Boolean);
}

function mapCycloneDXType(type?: string): SBOMComponent["type"] {
  switch (type?.toLowerCase()) {
    case "application": return "application";
    case "library": return "library";
    case "framework": return "framework";
    case "operating-system": return "operating-system";
    case "device": return "device";
    case "firmware": return "firmware";
    case "container": return "container";
    default: return "other";
  }
}

function mapSPDXType(purpose?: string): SBOMComponent["type"] {
  switch (purpose?.toUpperCase()) {
    case "APPLICATION": return "application";
    case "LIBRARY": return "library";
    case "FRAMEWORK": return "framework";
    case "OPERATING-SYSTEM": return "operating-system";
    case "DEVICE": return "device";
    case "FIRMWARE": return "firmware";
    case "CONTAINER": return "container";
    default: return "application";
  }
}

function inferCriticality(component: SBOMComponent): string {
  // OS and firmware are always critical
  if (component.type === "operating-system" || component.type === "firmware") return "critical";
  // Frameworks that handle auth/crypto are high
  if (component.type === "framework") return "high";
  // Applications are medium-high
  if (component.type === "application") return "medium";
  // Libraries default to low unless they match known critical patterns
  const criticalPatterns = /openssl|crypto|auth|jwt|oauth|saml|kerberos|pam|sudo|ssh/i;
  if (criticalPatterns.test(component.name)) return "high";
  return "low";
}

function criticalityRank(criticality: string): number {
  switch (criticality) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}
