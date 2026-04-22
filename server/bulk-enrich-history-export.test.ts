import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Tests for three features:
 * 1. Bulk Enrichment for incomplete actors
 * 2. Enrichment History log with timeline
 * 3. CSV/STIX Export for filtered catalog
 */

const routerPath = join(__dirname, 'routers/threat-intel.ts');
const routerContent = readFileSync(routerPath, 'utf-8');
const schemaPath = join(__dirname, '../drizzle/schema.ts');
const schemaContent = readFileSync(schemaPath, 'utf-8');
const catalogPagePath = join(__dirname, '../client/src/pages/ThreatCatalog.tsx');
const catalogPageContent = readFileSync(catalogPagePath, 'utf-8');
const detailPagePath = join(__dirname, '../client/src/pages/ThreatActorCatalogDetail.tsx');
const detailPageContent = readFileSync(detailPagePath, 'utf-8');

// ─── Feature 1: Bulk Enrichment ─────────────────────────────────────────

describe('Bulk Enrichment Backend', () => {
  it('should have enrichment_history table in schema', () => {
    expect(schemaContent).toContain('enrichment_history');
    expect(schemaContent).toContain('enrichmentHistory');
  });

  it('enrichment_history table should have required columns', () => {
    expect(schemaContent).toContain('actor_id');
    expect(schemaContent).toContain('actor_name');
    expect(schemaContent).toContain('triggered_by');
    expect(schemaContent).toContain('fields_updated');
    expect(schemaContent).toContain('fields_discovered');
    expect(schemaContent).toContain('sources_used');
    expect(schemaContent).toContain('data_quality_before');
    expect(schemaContent).toContain('data_quality_after');
    expect(schemaContent).toContain('duration_ms');
    expect(schemaContent).toContain('error_message');
  });

  it('triggered_by should support manual, bulk, and scheduled types', () => {
    expect(schemaContent).toMatch(/triggered_by.*manual.*bulk.*scheduled/s);
  });

  it('should have incompleteActors query endpoint', () => {
    expect(routerContent).toContain('incompleteActors');
    expect(routerContent).toContain('protectedProcedure');
  });

  it('incompleteActors should accept threshold and limit params', () => {
    expect(routerContent).toContain('threshold');
    expect(routerContent).toContain('limit');
  });

  it('incompleteActors should compute completeness percentage', () => {
    expect(routerContent).toContain('completeness');
    expect(routerContent).toContain('missing');
  });

  it('should have bulkEnrich mutation endpoint', () => {
    expect(routerContent).toContain('bulkEnrich');
    expect(routerContent).toContain('actorIds');
  });

  it('bulkEnrich should accept array of actor IDs (max 2000)', () => {
    expect(routerContent).toMatch(/actorIds.*z\.array.*z\.string.*min\(1\).*max\(2000\)/);
  });

  it('bulkEnrich should record history for each actor', () => {
    // Should insert into enrichmentHistory
    expect(routerContent).toContain("db.insert(enrichmentHistory)");
    expect(routerContent).toContain("triggeredBy: 'bulk'");
  });

  it('bulkEnrich should track success and failure counts', () => {
    expect(routerContent).toContain('succeeded');
    expect(routerContent).toContain('failed');
  });

  it('bulkEnrich should handle errors gracefully per actor', () => {
    expect(routerContent).toContain("status: 'failed'");
    expect(routerContent).toContain('errorMessage');
  });

  it('enrichActor (manual) should also record history', () => {
    expect(routerContent).toContain("triggeredBy: 'manual'");
  });

  it('should have computeCompleteness helper function', () => {
    expect(routerContent).toContain('function computeCompleteness');
  });
});

describe('Bulk Enrichment Frontend', () => {
  it('should have BULK ENRICH button on Threat Catalog page', () => {
    expect(catalogPageContent).toContain('BULK ENRICH');
  });

  it('should have Sparkles icon for bulk enrich button', () => {
    expect(catalogPageContent).toContain('Sparkles');
  });

  it('should have showBulkEnrich state toggle', () => {
    expect(catalogPageContent).toContain('showBulkEnrich');
    expect(catalogPageContent).toContain('setShowBulkEnrich');
  });

  it('should call incompleteActors query when dialog opens', () => {
    expect(catalogPageContent).toContain('incompleteActors');
  });

  it('should call bulkEnrich mutation', () => {
    expect(catalogPageContent).toContain('bulkEnrich');
    expect(catalogPageContent).toContain('bulkEnrichMutation');
  });

  it('should show completeness bars for each actor in dialog', () => {
    expect(catalogPageContent).toContain('actor.completeness');
  });

  it('should show success/failure results after bulk enrichment', () => {
    expect(catalogPageContent).toContain('bulkEnrichMutation');
    expect(catalogPageContent).toContain('succeeded');
  });
});

// ─── Feature 2: Enrichment History Timeline ─────────────────────────────

describe('Enrichment History Backend', () => {
  it('should have enrichmentHistoryList query endpoint', () => {
    expect(routerContent).toContain('enrichmentHistoryList');
  });

  it('enrichmentHistoryList should accept optional actorId filter', () => {
    expect(routerContent).toContain('actorId: z.string().optional()');
  });

  it('enrichmentHistoryList should support pagination', () => {
    expect(routerContent).toContain('limit');
    expect(routerContent).toContain('page');
    expect(routerContent).toContain('offset');
  });

  it('enrichmentHistoryList should order by createdAt desc', () => {
    expect(routerContent).toContain('desc(enrichmentHistory.createdAt)');
  });

  it('enrichmentHistoryList should return total count', () => {
    expect(routerContent).toContain('count(*)');
  });

  it('enrichmentHistoryList should parse JSON fields', () => {
    expect(routerContent).toContain('safeParseArr(r.fieldsUpdated)');
    expect(routerContent).toContain('safeParseArr(r.fieldsDiscovered)');
    expect(routerContent).toContain('safeParseArr(r.sourcesUsed)');
  });
});

describe('Enrichment History Timeline Frontend', () => {
  it('should have EnrichmentHistoryTimeline component', () => {
    expect(detailPageContent).toContain('EnrichmentHistoryTimeline');
  });

  it('should call enrichmentHistoryList query with actorId', () => {
    expect(detailPageContent).toContain('enrichmentHistoryList');
  });

  it('should render timeline with vertical line', () => {
    expect(detailPageContent).toContain('Timeline line');
    expect(detailPageContent).toContain('Timeline dot');
  });

  it('should show triggered_by badge (manual/bulk/scheduled)', () => {
    expect(detailPageContent).toContain('triggeredByColors');
    expect(detailPageContent).toContain('entry.triggeredBy');
  });

  it('should show status with color coding', () => {
    expect(detailPageContent).toContain('statusColors');
    expect(detailPageContent).toContain('entry.status');
  });

  it('should show quality change (before → after)', () => {
    expect(detailPageContent).toContain('dataQualityBefore');
    expect(detailPageContent).toContain('dataQualityAfter');
  });

  it('should show duration in seconds', () => {
    expect(detailPageContent).toContain('durationMs');
  });

  it('should show error message for failed enrichments', () => {
    expect(detailPageContent).toContain('errorMessage');
  });

  it('should show empty state when no history', () => {
    expect(detailPageContent).toContain('No enrichment history yet');
  });

  it('should show sources used as tags', () => {
    expect(detailPageContent).toContain('sourcesUsed');
  });
});

// ─── Feature 3: CSV/STIX Export ─────────────────────────────────────────

describe('CSV Export Backend', () => {
  it('should have exportCsv query endpoint', () => {
    expect(routerContent).toContain('exportCsv');
  });

  it('exportCsv should accept filter parameters', () => {
    // Should accept same filters as list query
    expect(routerContent).toMatch(/exportCsv.*type.*threatLevel/s);
  });

  it('exportCsv should support updatedLast24h filter', () => {
    expect(routerContent).toContain('updatedLast24h');
  });

  it('exportCsv should generate CSV with proper headers', () => {
    expect(routerContent).toContain('Actor ID');
    expect(routerContent).toContain('Name');
    expect(routerContent).toContain('Type');
    expect(routerContent).toContain('Threat Level');
    expect(routerContent).toContain('STIX ID');
  });

  it('exportCsv should return CSV content and count', () => {
    expect(routerContent).toContain('csv: csvContent');
    expect(routerContent).toContain('count: actors.length');
  });

  it('exportCsv should properly escape CSV values', () => {
    expect(routerContent).toContain('replace(/"/g');
  });
});

describe('STIX Export Backend', () => {
  it('should have exportStix query endpoint', () => {
    expect(routerContent).toContain('exportStix');
  });

  it('exportStix should generate STIX 2.1 bundle', () => {
    expect(routerContent).toContain("spec_version: '2.1'");
    expect(routerContent).toContain("type: 'bundle'");
  });

  it('exportStix should create threat-actor objects', () => {
    expect(routerContent).toContain("type: 'threat-actor'");
  });

  it('exportStix should create attack-pattern objects for techniques', () => {
    expect(routerContent).toContain("type: 'attack-pattern'");
  });

  it('exportStix should create relationship objects', () => {
    expect(routerContent).toContain("type: 'relationship'");
    expect(routerContent).toContain("relationship_type: 'uses'");
  });

  it('exportStix should map actor types to STIX threat-actor-types', () => {
    expect(routerContent).toContain('typeMap');
    expect(routerContent).toContain("apt: 'nation-state'");
    expect(routerContent).toContain("ransomware: 'criminal'");
    expect(routerContent).toContain("hacktivist: 'activist'");
  });

  it('exportStix should map sophistication levels', () => {
    expect(routerContent).toContain('sophisticationMap');
  });

  it('exportStix should return STIX JSON, actor count, and object count', () => {
    expect(routerContent).toContain('stix: JSON.stringify(bundle');
    expect(routerContent).toContain('actorCount');
    expect(routerContent).toContain('objectCount');
  });

  it('exportStix should include external references for MITRE techniques', () => {
    expect(routerContent).toContain("source_name: 'mitre-attack'");
    expect(routerContent).toContain('external_id');
  });
});

describe('Export Frontend', () => {
  it('should have EXPORT CSV button', () => {
    expect(catalogPageContent).toContain('EXPORT CSV');
  });

  it('should have EXPORT STIX button', () => {
    expect(catalogPageContent).toContain('EXPORT STIX');
  });

  it('should have FileDown icon for CSV export', () => {
    expect(catalogPageContent).toContain('FileDown');
  });

  it('should have FileText icon for STIX export', () => {
    expect(catalogPageContent).toContain('FileText');
  });

  it('should use exportCsv query on demand', () => {
    expect(catalogPageContent).toContain('exportCsvQuery');
    expect(catalogPageContent).toContain('enabled: false');
  });

  it('should use exportStix query on demand', () => {
    expect(catalogPageContent).toContain('exportStixQuery');
  });

  it('should create downloadable CSV blob', () => {
    expect(catalogPageContent).toContain("type: 'text/csv'");
    expect(catalogPageContent).toContain('.csv');
  });

  it('should create downloadable STIX JSON blob', () => {
    expect(catalogPageContent).toContain("type: 'application/json'");
    expect(catalogPageContent).toContain('.json');
  });

  it('should pass current filters to export queries', () => {
    expect(catalogPageContent).toContain('typeFilter');
    expect(catalogPageContent).toContain('threatLevelFilter');
    expect(catalogPageContent).toContain('updatedLast24h');
  });

  it('should show loading state during export', () => {
    expect(catalogPageContent).toContain('exportingCsv');
    expect(catalogPageContent).toContain('exportingStix');
  });

  it('should show toast with export count on success', () => {
    expect(catalogPageContent).toContain('Exported');
    expect(catalogPageContent).toContain('actors to CSV');
    expect(catalogPageContent).toContain('STIX objects');
  });
});
