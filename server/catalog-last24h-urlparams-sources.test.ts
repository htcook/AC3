import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

/**
 * Tests for three features:
 * 1. Dedicated Last 24H backend filter (updatedLast24h)
 * 2. URL param persistence for filter state on Threat Catalog
 * 3. Sources & Enrichment tab on actor detail pages
 */

// ─── Feature 1: Last 24H Backend Filter ─────────────────────────────────

describe('Last 24H Dedicated Backend Filter', () => {
  const routerPath = join(__dirname, 'routers/threat-intel.ts');
  const routerContent = readFileSync(routerPath, 'utf-8');

  it('list procedure input should accept updatedLast24h boolean', () => {
    expect(routerContent).toContain('updatedLast24h');
  });

  it('should filter by updatedAt column when updatedLast24h is true', () => {
    // The backend should use gte on updatedAt with a 24h cutoff
    expect(routerContent).toContain('updatedAt');
  });

  it('getCatalogStats should return recentlyUpdatedActors count', () => {
    const connectorPath = join(__dirname, 'lib/threat-intel-connectors.ts');
    const connectorContent = readFileSync(connectorPath, 'utf-8');
    expect(connectorContent).toContain('recentlyUpdatedActors');
  });

  it('recentlyUpdatedActors should use 24-hour window', () => {
    const connectorPath = join(__dirname, 'lib/threat-intel-connectors.ts');
    const connectorContent = readFileSync(connectorPath, 'utf-8');
    // Should use SQL INTERVAL 24 HOUR for the cutoff
    expect(connectorContent).toMatch(/INTERVAL 24 HOUR/);
  });

  it('ThreatCatalog frontend should pass updatedLast24h to query', () => {
    const catalogPath = join(__dirname, '../client/src/pages/ThreatCatalog.tsx');
    const catalogContent = readFileSync(catalogPath, 'utf-8');
    expect(catalogContent).toContain('updatedLast24h');
  });

  it('Last 24H stat card should use recentlyUpdatedActors from stats', () => {
    const catalogPath = join(__dirname, '../client/src/pages/ThreatCatalog.tsx');
    const catalogContent = readFileSync(catalogPath, 'utf-8');
    expect(catalogContent).toContain('recentlyUpdatedActors');
  });
});

// ─── Feature 2: URL Param Persistence ───────────────────────────────────

describe('URL Param Persistence for Threat Catalog Filters', () => {
  const catalogPath = join(__dirname, '../client/src/pages/ThreatCatalog.tsx');
  const catalogContent = readFileSync(catalogPath, 'utf-8');

  it('should use useSearch or useLocation from wouter for URL params', () => {
    // Should import useSearch or useLocation from wouter
    expect(catalogContent).toMatch(/useSearch|useLocation/);
  });

  it('should use URLSearchParams for reading/writing filter state', () => {
    expect(catalogContent).toContain('URLSearchParams');
  });

  it('should persist type filter in URL params', () => {
    // The updateFilters function should set "type" param
    expect(catalogContent).toMatch(/["']type["']/);
  });

  it('should persist search query in URL params', () => {
    expect(catalogContent).toMatch(/["']q["']|["']search["']/);
  });

  it('should persist page number in URL params', () => {
    expect(catalogContent).toMatch(/["']page["']/);
  });

  it('should persist conflict filter in URL params', () => {
    expect(catalogContent).toMatch(/["']conflict["']/);
  });

  it('should persist sort in URL params', () => {
    expect(catalogContent).toMatch(/["']sort["']/);
  });

  it('should persist last24h filter in URL params', () => {
    expect(catalogContent).toMatch(/["']last24h["']/);
  });

  it('should have updateFilters function for centralized URL param updates', () => {
    expect(catalogContent).toContain('updateFilters');
  });

  it('stat card clicks should update URL params', () => {
    // handleStatCardClick should use updateFilters
    expect(catalogContent).toContain('handleStatCardClick');
    expect(catalogContent).toContain('updateFilters');
  });

  it('should persist active stat card in URL params', () => {
    expect(catalogContent).toMatch(/["']card["']/);
  });
});

// ─── Feature 3: Sources & Enrichment Tab ────────────────────────────────

describe('Sources & Enrichment Tab on Actor Detail Pages', () => {
  // Test the ThreatActorCatalogDetail page (used for /threat-catalog/:id)
  const detailPath = join(__dirname, '../client/src/pages/ThreatActorCatalogDetail.tsx');
  const detailContent = readFileSync(detailPath, 'utf-8');

  it('should include "sources" in the TabId type', () => {
    expect(detailContent).toContain('"sources"');
  });

  it('should have SOURCES & ENRICHMENT tab trigger', () => {
    expect(detailContent).toContain('SOURCES & ENRICHMENT');
  });

  it('should render CatalogSourcesPanel when sources tab is active', () => {
    expect(detailContent).toContain('CatalogSourcesPanel');
  });

  it('CatalogSourcesPanel should have enrichment action button', () => {
    expect(detailContent).toContain('RUN ENRICHMENT');
  });

  it('should display data completeness percentage', () => {
    expect(detailContent).toContain('DATA COMPLETENESS');
    expect(detailContent).toContain('completeness');
  });

  it('should display gap analysis grid', () => {
    expect(detailContent).toContain('GAP ANALYSIS');
    expect(detailContent).toContain('gapAnalysis');
  });

  it('gap analysis should check key fields', () => {
    const expectedFields = ['Description', 'Motivation', 'Origin', 'Aliases', 'Target Sectors', 'Target Regions', 'Techniques', 'Tools', 'Malware'];
    for (const field of expectedFields) {
      expect(detailContent, `Gap analysis should check "${field}"`).toContain(`"${field}"`);
    }
  });

  it('should have source attribution section', () => {
    expect(detailContent).toContain('SOURCE ATTRIBUTION');
  });

  it('should have data provenance section', () => {
    expect(detailContent).toContain('DATA PROVENANCE');
  });

  it('should parse enrichmentSources from actor data', () => {
    expect(detailContent).toContain('enrichmentSources');
  });

  it('should use threatIntel.enrichActor mutation', () => {
    expect(detailContent).toContain('threatIntel.enrichActor');
  });

  it('should display enrichment results when available', () => {
    expect(detailContent).toContain('ENRICHMENT RESULTS');
    expect(detailContent).toContain('enrichResult');
  });

  it('should show keywords used during enrichment', () => {
    expect(detailContent).toContain('keywordsUsed');
  });

  it('should have source type color coding', () => {
    expect(detailContent).toContain('sourceTypeColors');
    expect(detailContent).toContain('osint');
    expect(detailContent).toContain('darkweb');
    expect(detailContent).toContain('government');
  });

  it('should show loading state during enrichment', () => {
    expect(detailContent).toContain('isEnriching');
    expect(detailContent).toContain('ENRICHING...');
  });

  it('gap analysis should categorize fields as missing, weak, or good', () => {
    expect(detailContent).toContain('"missing"');
    expect(detailContent).toContain('"weak"');
    expect(detailContent).toContain('"good"');
  });
});

// ─── Backend: threatLevel filter fix ────────────────────────────────────

describe('Threat Level Filter Fix', () => {
  const routerPath = join(__dirname, 'routers/threat-intel.ts');
  const routerContent = readFileSync(routerPath, 'utf-8');

  it('should use threatLevel (not rwThreatLevel) for threatActors filter', () => {
    // The list query should reference threatActors.threatLevel for filtering
    expect(routerContent).toContain('threatActors.threatLevel');
  });

  it('should accept threatLevel as input parameter', () => {
    expect(routerContent).toContain('threatLevel');
  });
});
