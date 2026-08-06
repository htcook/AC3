/**
 * Supply Chain Threat Intelligence — Correlation Engine
 * 
 * Correlates incoming threat feeds (CISA advisories, CVEs, threat actor campaigns)
 * with defense supplier technology stacks to automatically generate alerts when
 * a supplier is potentially exposed.
 * 
 * Flow:
 * 1. New advisory/CVE ingested → extract affected products/vendors/versions
 * 2. Query supplierTechStacks for matching product+vendor+version
 * 3. Generate supplierThreatAlerts for each matched supplier
 * 4. Calculate cascade risk based on supply chain relationships
 * 5. Notify via platform notification system
 */

import { getDbRequired } from "../db";
import { eq, like, and, or, sql, inArray, desc } from "drizzle-orm";
import {
  defenseSuppliers,
  supplierTechStacks,
  supplyChainRelationships,
  supplierThreatAlerts,
  supplierAssessmentHistory,
} from "../../drizzle/schema";
import crypto from "crypto";

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

export interface ThreatIndicator {
  type: 'cve' | 'advisory' | 'threat_actor' | 'breach';
  id: string; // CVE-2025-66376, AA26-204A, etc.
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  // Affected products (extracted from advisory text or CVE data)
  affectedProducts: AffectedProduct[];
  // Threat actor attribution
  threatActorName?: string;
  // Exploitation status
  exploitAvailable?: boolean;
  activeExploitation?: boolean; // in CISA KEV or active campaigns
  // Source
  sourceUrl?: string;
  incidentReportId?: number;
  publishedAt?: string;
}

export interface AffectedProduct {
  vendor: string; // "Zimbra", "Microsoft", "Apache"
  product: string; // "Collaboration Suite", "Exchange Server", "Log4j"
  versions?: string[]; // ["8.8.15", "9.0.0"] — empty means all versions
  cpe?: string; // CPE string if available
}

export interface CorrelationResult {
  supplierId: string;
  supplierName: string;
  matchedTechStack: {
    product: string;
    vendor: string;
    version: string | null;
    category: string;
    criticality: string;
    confidence: number;
  };
  alertSeverity: 'critical' | 'high' | 'medium' | 'low';
  cascadeRisk: 'critical' | 'high' | 'medium' | 'low';
  impactedPrograms: string[];
  matchConfidence: number; // 0-1 how confident the match is
}

export interface CorrelationSummary {
  indicator: ThreatIndicator;
  totalSuppliersAffected: number;
  criticalSuppliers: number;
  highSuppliers: number;
  results: CorrelationResult[];
  alertsGenerated: number;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCT MATCHING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Normalize product/vendor names for fuzzy matching
 * Handles variations like "Zimbra Collaboration Suite" vs "Zimbra" vs "zimbra-collaboration"
 */
function normalizeProductName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Check if a version string matches a range or specific version
 * Supports: exact match, prefix match, and wildcard
 */
function versionMatches(techVersion: string | null, affectedVersions?: string[]): boolean {
  // If no specific versions listed, ALL versions are affected
  if (!affectedVersions || affectedVersions.length === 0) return true;
  // If tech stack has no version recorded, assume potentially affected (lower confidence)
  if (!techVersion) return true;
  
  const normalizedTech = techVersion.toLowerCase().trim();
  
  for (const affected of affectedVersions) {
    const normalizedAffected = affected.toLowerCase().trim();
    
    // Exact match
    if (normalizedTech === normalizedAffected) return true;
    
    // Prefix match (e.g., "8.8" matches "8.8.15")
    if (normalizedTech.startsWith(normalizedAffected + '.') || 
        normalizedAffected.startsWith(normalizedTech + '.')) return true;
    
    // Wildcard (e.g., "8.x" or "8.*")
    if (normalizedAffected.includes('x') || normalizedAffected.includes('*')) {
      const pattern = normalizedAffected.replace(/[x*]/g, '\\d+');
      if (new RegExp(`^${pattern}$`).test(normalizedTech)) return true;
    }
    
    // Range notation: "< 9.0.0" or "<= 8.8.15"
    const rangeMatch = normalizedAffected.match(/^([<>]=?)\s*(.+)$/);
    if (rangeMatch) {
      const [, op, ver] = rangeMatch;
      const cmp = compareVersions(normalizedTech, ver);
      if (op === '<' && cmp < 0) return true;
      if (op === '<=' && cmp <= 0) return true;
      if (op === '>' && cmp > 0) return true;
      if (op === '>=' && cmp >= 0) return true;
    }
  }
  
  return false;
}

/**
 * Simple semantic version comparison
 * Returns: -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.split('.').map(p => parseInt(p, 10) || 0);
  const partsB = b.split('.').map(p => parseInt(p, 10) || 0);
  const maxLen = Math.max(partsA.length, partsB.length);
  
  for (let i = 0; i < maxLen; i++) {
    const numA = partsA[i] || 0;
    const numB = partsB[i] || 0;
    if (numA < numB) return -1;
    if (numA > numB) return 1;
  }
  return 0;
}

/**
 * Calculate match confidence between an affected product and a tech stack entry
 */
function calculateMatchConfidence(
  affected: AffectedProduct,
  techEntry: { product: string; vendor: string; version: string | null }
): number {
  let confidence = 0;
  
  const normalizedAffectedVendor = normalizeProductName(affected.vendor);
  const normalizedAffectedProduct = normalizeProductName(affected.product);
  const normalizedTechVendor = normalizeProductName(techEntry.vendor);
  const normalizedTechProduct = normalizeProductName(techEntry.product);
  
  // Vendor match (0.3 weight)
  if (normalizedTechVendor === normalizedAffectedVendor) {
    confidence += 0.3;
  } else if (normalizedTechVendor.includes(normalizedAffectedVendor) || 
             normalizedAffectedVendor.includes(normalizedTechVendor)) {
    confidence += 0.2;
  }
  
  // Product match (0.4 weight)
  if (normalizedTechProduct === normalizedAffectedProduct) {
    confidence += 0.4;
  } else if (normalizedTechProduct.includes(normalizedAffectedProduct) || 
             normalizedAffectedProduct.includes(normalizedTechProduct)) {
    confidence += 0.25;
  } else {
    // Check individual words overlap
    const affectedWords = normalizedAffectedProduct.split(' ');
    const techWords = normalizedTechProduct.split(' ');
    const overlap = affectedWords.filter(w => techWords.includes(w) && w.length > 2);
    if (overlap.length > 0) {
      confidence += 0.15 * (overlap.length / affectedWords.length);
    }
  }
  
  // Version match (0.3 weight)
  if (techEntry.version && affected.versions && affected.versions.length > 0) {
    if (versionMatches(techEntry.version, affected.versions)) {
      confidence += 0.3;
    }
  } else if (!techEntry.version) {
    // Unknown version — partial confidence
    confidence += 0.1;
  } else if (!affected.versions || affected.versions.length === 0) {
    // All versions affected
    confidence += 0.3;
  }
  
  return Math.min(confidence, 1.0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Main correlation function: given a threat indicator, find all affected suppliers
 */
export async function correlateThreats(
  indicator: ThreatIndicator,
  options: { minConfidence?: number; generateAlerts?: boolean } = {}
): Promise<CorrelationSummary> {
  const db = await getDbRequired();
  const { minConfidence = 0.5, generateAlerts = true } = options;
  const results: CorrelationResult[] = [];
  
  // For each affected product in the indicator, search supplier tech stacks
  for (const affected of indicator.affectedProducts) {
    const normalizedVendor = normalizeProductName(affected.vendor);
    const normalizedProduct = normalizeProductName(affected.product);
    
    // Build search terms for SQL LIKE queries
    const searchTerms = [
      normalizedVendor,
      normalizedProduct,
      ...normalizedProduct.split(' ').filter(w => w.length > 3),
    ].filter(Boolean);
    
    // Query tech stacks that might match
    const conditions = searchTerms.map(term => 
      or(
        sql`LOWER(${supplierTechStacks.product}) LIKE ${`%${term}%`}`,
        sql`LOWER(${supplierTechStacks.vendor}) LIKE ${`%${term}%`}`
      )
    );
    
    if (conditions.length === 0) continue;
    
    const matchingStacks = await db.select()
      .from(supplierTechStacks)
      .where(or(...conditions))
      .limit(500);
    
    // Score each match
    for (const stack of matchingStacks) {
      const matchConfidence = calculateMatchConfidence(affected, {
        product: stack.product,
        vendor: stack.vendor,
        version: stack.version,
      });
      
      if (matchConfidence < minConfidence) continue;
      
      // Check version match
      if (!versionMatches(stack.version, affected.versions)) continue;
      
      // Get supplier details
      const [supplier] = await db.select()
        .from(defenseSuppliers)
        .where(eq(defenseSuppliers.supplierId, stack.supplierId))
        .limit(1);
      
      if (!supplier || supplier.status === 'inactive') continue;
      
      // Get impacted programs through supply chain relationships
      const relationships = await db.select()
        .from(supplyChainRelationships)
        .where(
          and(
            or(
              eq(supplyChainRelationships.subcontractorId, stack.supplierId),
              eq(supplyChainRelationships.primeContractorId, stack.supplierId)
            ),
            eq(supplyChainRelationships.status, 'active')
          )
        );
      
      const impactedPrograms = relationships
        .map(r => r.programName)
        .filter((p): p is string => !!p);
      
      // Calculate cascade risk based on relationships
      const cascadeRisk = calculateCascadeRisk(supplier, relationships, stack);
      
      // Calculate alert severity (combines indicator severity + tech criticality + cascade)
      const alertSeverity = calculateAlertSeverity(
        indicator.severity,
        stack.criticality,
        cascadeRisk,
        matchConfidence
      );
      
      results.push({
        supplierId: supplier.supplierId,
        supplierName: supplier.name,
        matchedTechStack: {
          product: stack.product,
          vendor: stack.vendor,
          version: stack.version,
          category: stack.category,
          criticality: stack.criticality,
          confidence: stack.confidence,
        },
        alertSeverity,
        cascadeRisk,
        impactedPrograms,
        matchConfidence,
      });
    }
  }
  
  // Deduplicate by supplier (keep highest severity match per supplier)
  const deduped = deduplicateResults(results);
  
  // Generate alerts if requested
  let alertsGenerated = 0;
  if (generateAlerts && deduped.length > 0) {
    alertsGenerated = await generateThreatAlerts(indicator, deduped);
  }
  
  return {
    indicator,
    totalSuppliersAffected: deduped.length,
    criticalSuppliers: deduped.filter(r => r.alertSeverity === 'critical').length,
    highSuppliers: deduped.filter(r => r.alertSeverity === 'high').length,
    results: deduped,
    alertsGenerated,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Calculate cascade risk: how much downstream impact if this supplier is compromised
 */
function calculateCascadeRisk(
  supplier: typeof defenseSuppliers.$inferSelect,
  relationships: (typeof supplyChainRelationships.$inferSelect)[],
  techStack: typeof supplierTechStacks.$inferSelect
): 'critical' | 'high' | 'medium' | 'low' {
  let score = 0;
  
  // Supplier tier weight
  if (supplier.tier === 'prime') score += 40;
  else if (supplier.tier === 'tier1') score += 30;
  else if (supplier.tier === 'tier2') score += 20;
  else score += 10;
  
  // Number of downstream relationships
  score += Math.min(relationships.length * 5, 25);
  
  // Single source risk
  const singleSourceCount = relationships.filter(r => r.singleSourceRisk === 1).length;
  score += singleSourceCount * 15;
  
  // Critical programs
  const criticalPrograms = relationships.filter(r => r.criticalityToProgram === 'critical').length;
  score += criticalPrograms * 10;
  
  // Tech criticality
  if (techStack.criticality === 'critical') score += 15;
  else if (techStack.criticality === 'high') score += 10;
  
  if (score >= 70) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

/**
 * Calculate final alert severity combining multiple factors
 */
function calculateAlertSeverity(
  indicatorSeverity: string,
  techCriticality: string,
  cascadeRisk: string,
  matchConfidence: number
): 'critical' | 'high' | 'medium' | 'low' {
  const severityMap: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  
  const indicatorScore = severityMap[indicatorSeverity] || 2;
  const techScore = severityMap[techCriticality] || 2;
  const cascadeScore = severityMap[cascadeRisk] || 2;
  
  // Weighted combination
  const combined = (indicatorScore * 0.4) + (techScore * 0.25) + (cascadeScore * 0.25) + (matchConfidence * 0.1 * 4);
  
  if (combined >= 3.5) return 'critical';
  if (combined >= 2.5) return 'high';
  if (combined >= 1.5) return 'medium';
  return 'low';
}

/**
 * Deduplicate results — keep highest severity per supplier
 */
function deduplicateResults(results: CorrelationResult[]): CorrelationResult[] {
  const bySupplier = new Map<string, CorrelationResult>();
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  
  for (const result of results) {
    const existing = bySupplier.get(result.supplierId);
    if (!existing || severityOrder[result.alertSeverity] > severityOrder[existing.alertSeverity]) {
      bySupplier.set(result.supplierId, result);
    }
  }
  
  return Array.from(bySupplier.values())
    .sort((a, b) => severityOrder[b.alertSeverity] - severityOrder[a.alertSeverity]);
}

/**
 * Generate and persist threat alerts for correlated results
 */
async function generateThreatAlerts(
  indicator: ThreatIndicator,
  results: CorrelationResult[]
): Promise<number> {
  let count = 0;
  
  for (const result of results) {
    const alertId = `sta-${crypto.randomBytes(8).toString('hex')}`;
    
    try {
      await db.insert(supplierThreatAlerts).values({
        alertId,
        supplierId: result.supplierId,
        alertType: indicator.type === 'cve' ? 'cve_match' : 
                   indicator.type === 'advisory' ? 'advisory_match' :
                   indicator.type === 'threat_actor' ? 'threat_actor_targeting' : 'breach_detected',
        severity: result.alertSeverity,
        title: `${indicator.title} — affects ${result.supplierName}`,
        description: `${indicator.description || ''}\n\nMatched tech stack: ${result.matchedTechStack.vendor} ${result.matchedTechStack.product} ${result.matchedTechStack.version || '(version unknown)'}. Match confidence: ${(result.matchConfidence * 100).toFixed(0)}%.`,
        cveId: indicator.type === 'cve' ? indicator.id : null,
        advisoryId: indicator.type === 'advisory' ? indicator.id : null,
        threatActorName: indicator.threatActorName || null,
        affectedProduct: result.matchedTechStack.product,
        affectedVersion: result.matchedTechStack.version || null,
        exploitAvailable: indicator.exploitAvailable ? 1 : 0,
        activeExploitation: indicator.activeExploitation ? 1 : 0,
        impactedPrograms: result.impactedPrograms.length > 0 ? JSON.stringify(result.impactedPrograms) : null,
        cascadeRisk: result.cascadeRisk,
        mitigationStatus: 'unmitigated',
        sourceUrl: indicator.sourceUrl || null,
        incidentReportId: indicator.incidentReportId || null,
      });
      count++;
    } catch (err) {
      console.error(`[SupplyChainCorrelation] Failed to create alert for ${result.supplierId}:`, err);
    }
  }
  
  return count;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADVISORY PARSER — Extract affected products from advisory text
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Extract affected products from an advisory/incident report using keyword matching
 * This is the fast path — LLM extraction is used for complex advisories
 */
export function extractAffectedProducts(
  title: string,
  description: string,
  cveIds?: string[]
): AffectedProduct[] {
  const products: AffectedProduct[] = [];
  const text = `${title} ${description}`.toLowerCase();
  
  // Known product patterns (vendor → products)
  const PRODUCT_PATTERNS: Record<string, { vendor: string; keywords: string[] }[]> = {
    'zimbra': [{ vendor: 'Zimbra/Synacor', keywords: ['zimbra', 'zimbra collaboration'] }],
    'microsoft exchange': [{ vendor: 'Microsoft', keywords: ['exchange server', 'exchange online'] }],
    'microsoft 365': [{ vendor: 'Microsoft', keywords: ['microsoft 365', 'office 365', 'm365'] }],
    'apache log4j': [{ vendor: 'Apache', keywords: ['log4j', 'log4shell'] }],
    'apache struts': [{ vendor: 'Apache', keywords: ['struts'] }],
    'fortinet': [{ vendor: 'Fortinet', keywords: ['fortigate', 'fortios', 'fortimanager', 'fortianalyzer'] }],
    'palo alto': [{ vendor: 'Palo Alto Networks', keywords: ['pan-os', 'globalprotect', 'cortex'] }],
    'cisco': [{ vendor: 'Cisco', keywords: ['ios', 'asa', 'firepower', 'webex', 'anyconnect'] }],
    'vmware': [{ vendor: 'VMware/Broadcom', keywords: ['vcenter', 'esxi', 'vsphere', 'horizon'] }],
    'citrix': [{ vendor: 'Citrix', keywords: ['netscaler', 'adc', 'gateway', 'xenapp'] }],
    'solarwinds': [{ vendor: 'SolarWinds', keywords: ['orion', 'serv-u', 'solarwinds'] }],
    'ivanti': [{ vendor: 'Ivanti', keywords: ['pulse secure', 'connect secure', 'policy secure', 'epmm'] }],
    'atlassian': [{ vendor: 'Atlassian', keywords: ['confluence', 'jira', 'bitbucket', 'bamboo'] }],
    'progress': [{ vendor: 'Progress Software', keywords: ['moveit', 'whatsup gold', 'telerik'] }],
    'barracuda': [{ vendor: 'Barracuda', keywords: ['email security gateway', 'esg'] }],
    'sophos': [{ vendor: 'Sophos', keywords: ['sophos firewall', 'xg firewall'] }],
    'juniper': [{ vendor: 'Juniper Networks', keywords: ['junos', 'srx', 'ex series'] }],
    'f5': [{ vendor: 'F5 Networks', keywords: ['big-ip', 'nginx'] }],
    'oracle': [{ vendor: 'Oracle', keywords: ['weblogic', 'java', 'database'] }],
    'sap': [{ vendor: 'SAP', keywords: ['sap netweaver', 'sap hana', 's/4hana'] }],
    'wordpress': [{ vendor: 'WordPress', keywords: ['wordpress', 'wp plugin'] }],
    'linux kernel': [{ vendor: 'Linux', keywords: ['linux kernel', 'kernel vulnerability'] }],
    'openssl': [{ vendor: 'OpenSSL', keywords: ['openssl'] }],
    'qnap': [{ vendor: 'QNAP', keywords: ['qnap', 'qts'] }],
    'zyxel': [{ vendor: 'Zyxel', keywords: ['zyxel', 'zywall'] }],
    'sonicwall': [{ vendor: 'SonicWall', keywords: ['sonicwall', 'sma', 'sra'] }],
  };
  
  for (const [key, patterns] of Object.entries(PRODUCT_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.keywords.some(kw => text.includes(kw))) {
        // Try to extract version from text
        const versions = extractVersions(text, key);
        products.push({
          vendor: pattern.vendor,
          product: key.charAt(0).toUpperCase() + key.slice(1),
          versions: versions.length > 0 ? versions : undefined,
        });
        break; // Only add once per vendor group
      }
    }
  }
  
  return products;
}

/**
 * Extract version numbers near a product mention in text
 */
function extractVersions(text: string, productName: string): string[] {
  const versions: string[] = [];
  const productIdx = text.indexOf(productName.toLowerCase());
  if (productIdx === -1) return versions;
  
  // Look within 100 chars of the product mention for version patterns
  const context = text.substring(Math.max(0, productIdx - 20), productIdx + 150);
  const versionPattern = /(?:version|v|ver\.?)\s*(\d+(?:\.\d+)+)/gi;
  const bareVersionPattern = /(\d+\.\d+(?:\.\d+)*)/g;
  
  let match;
  while ((match = versionPattern.exec(context)) !== null) {
    versions.push(match[1]);
  }
  
  // If no explicit version found, try bare version numbers
  if (versions.length === 0) {
    while ((match = bareVersionPattern.exec(context)) !== null) {
      // Filter out things that look like dates or IPs
      if (!match[1].match(/^20\d{2}/) && match[1].split('.').length <= 4) {
        versions.push(match[1]);
      }
    }
  }
  
  return [...new Set(versions)].slice(0, 5);
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH CORRELATION — Run against all recent advisories
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Run correlation against a batch of incident reports (called by daily ingest pipeline)
 */
export async function correlateRecentAdvisories(
  reports: Array<{ id: number; title: string; description: string; severity: string; sourceUrl?: string; cveIds?: string[] }>
): Promise<{ processed: number; alertsGenerated: number; errors: number }> {
  const db = await getDbRequired();
  let processed = 0;
  let alertsGenerated = 0;
  let errors = 0;
  
  for (const report of reports) {
    try {
      const affectedProducts = extractAffectedProducts(
        report.title,
        report.description,
        report.cveIds
      );
      
      if (affectedProducts.length === 0) {
        processed++;
        continue;
      }
      
      const indicator: ThreatIndicator = {
        type: report.cveIds && report.cveIds.length > 0 ? 'cve' : 'advisory',
        id: report.cveIds?.[0] || `IR-${report.id}`,
        title: report.title,
        description: report.description,
        severity: (report.severity as any) || 'medium',
        affectedProducts,
        activeExploitation: report.title.toLowerCase().includes('actively exploited') || 
                           report.description.toLowerCase().includes('kev'),
        sourceUrl: report.sourceUrl,
        incidentReportId: report.id,
      };
      
      const result = await correlateThreats(indicator);
      alertsGenerated += result.alertsGenerated;
      processed++;
    } catch (err) {
      console.error(`[SupplyChainCorrelation] Error processing report ${report.id}:`, err);
      errors++;
    }
  }
  
  console.log(`[SupplyChainCorrelation] Batch complete: ${processed} processed, ${alertsGenerated} alerts, ${errors} errors`);
  return { processed, alertsGenerated, errors };
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK SCORING
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Recalculate a supplier's composite risk score based on their open alerts
 */
export async function recalculateSupplierRisk(supplierId: string): Promise<{ score: number; band: string }> {
  const db = await getDbRequired();
  const openAlerts = await db.select()
    .from(supplierThreatAlerts)
    .where(
      and(
        eq(supplierThreatAlerts.supplierId, supplierId),
        eq(supplierThreatAlerts.mitigationStatus, 'unmitigated')
      )
    );
  
  let score = 0;
  const severityWeights = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
  
  for (const alert of openAlerts) {
    const weight = severityWeights[alert.severity as keyof typeof severityWeights] || 5;
    const exploitMultiplier = alert.activeExploitation ? 1.5 : (alert.exploitAvailable ? 1.2 : 1.0);
    score += weight * exploitMultiplier;
  }
  
  // Cap at 100
  score = Math.min(Math.round(score), 100);
  
  const band = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
  
  // Update supplier record
  await db.update(defenseSuppliers)
    .set({ riskScore: score, riskBand: band, lastAssessedAt: new Date().toISOString() })
    .where(eq(defenseSuppliers.supplierId, supplierId));
  
  return { score, band };
}

/**
 * Get supply chain impact summary for a specific CVE or advisory
 */
export async function getSupplyChainImpact(params: {
  cveId?: string;
  advisoryId?: string;
  threatActorName?: string;
}): Promise<{
  totalAlerts: number;
  bySeverity: Record<string, number>;
  byMitigation: Record<string, number>;
  affectedSuppliers: Array<{ supplierId: string; name: string; tier: string; severity: string; programs: string[] }>;
}> {
  const db = await getDbRequired();
  const conditions = [];
  if (params.cveId) conditions.push(eq(supplierThreatAlerts.cveId, params.cveId));
  if (params.advisoryId) conditions.push(eq(supplierThreatAlerts.advisoryId, params.advisoryId));
  if (params.threatActorName) conditions.push(eq(supplierThreatAlerts.threatActorName, params.threatActorName));
  
  if (conditions.length === 0) {
    return { totalAlerts: 0, bySeverity: {}, byMitigation: {}, affectedSuppliers: [] };
  }
  
  const alerts = await db.select()
    .from(supplierThreatAlerts)
    .where(or(...conditions))
    .orderBy(desc(supplierThreatAlerts.detectedAt));
  
  const bySeverity: Record<string, number> = {};
  const byMitigation: Record<string, number> = {};
  const supplierIds = new Set<string>();
  
  for (const alert of alerts) {
    bySeverity[alert.severity] = (bySeverity[alert.severity] || 0) + 1;
    byMitigation[alert.mitigationStatus] = (byMitigation[alert.mitigationStatus] || 0) + 1;
    supplierIds.add(alert.supplierId);
  }
  
  // Get supplier details
  const affectedSuppliers: Array<{ supplierId: string; name: string; tier: string; severity: string; programs: string[] }> = [];
  
  for (const sid of supplierIds) {
    const [supplier] = await db.select()
      .from(defenseSuppliers)
      .where(eq(defenseSuppliers.supplierId, sid))
      .limit(1);
    
    if (supplier) {
      const supplierAlerts = alerts.filter(a => a.supplierId === sid);
      const highestSeverity = supplierAlerts.reduce((max, a) => {
        const order = { critical: 4, high: 3, medium: 2, low: 1 };
        return (order[a.severity as keyof typeof order] || 0) > (order[max as keyof typeof order] || 0) ? a.severity : max;
      }, 'low');
      
      const programs = supplierAlerts
        .flatMap(a => {
          try { return JSON.parse(a.impactedPrograms as any || '[]'); } catch { return []; }
        })
        .filter((p, i, arr) => arr.indexOf(p) === i);
      
      affectedSuppliers.push({
        supplierId: supplier.supplierId,
        name: supplier.name,
        tier: supplier.tier,
        severity: highestSeverity,
        programs,
      });
    }
  }
  
  return {
    totalAlerts: alerts.length,
    bySeverity,
    byMitigation,
    affectedSuppliers,
  };
}
