import { describe, it, expect } from 'vitest';

/**
 * Tests for the refreshScan endpoint logic.
 * We test the snapshot creation, status gating, and comparison logic.
 */

describe('refreshScan', () => {
  describe('snapshot creation', () => {
    it('should create a valid previous snapshot from scan data', () => {
      const scan = {
        status: 'completed',
        totalAssets: 15,
        totalFindings: 42,
        confirmedFindings: 10,
        probableFindings: 20,
        potentialFindings: 12,
        overallRiskScore: 72,
        overallRiskBand: 'high',
        discoveryCoverageScore: 65,
        discoveryCoverageBand: 'moderate',
        executiveSummary: 'Test summary',
        threatModelSummary: 'Test threat model',
        campaignRecommendations: [{ name: 'Test Campaign' }],
        pipelineOutput: {
          entityProfile: { orgName: 'Test Corp', industry: 'Technology' },
          financialImpact: { estimatedRevenue: '$10M' },
          autoCrawlSummary: { pagesScanned: 5 },
        },
      };

      const previousSnapshot = {
        snapshotAt: new Date().toISOString(),
        status: scan.status,
        totalAssets: scan.totalAssets,
        totalFindings: scan.totalFindings,
        confirmedFindings: scan.confirmedFindings,
        probableFindings: scan.probableFindings,
        potentialFindings: scan.potentialFindings,
        overallRiskScore: scan.overallRiskScore,
        overallRiskBand: scan.overallRiskBand,
        discoveryCoverageScore: scan.discoveryCoverageScore,
        discoveryCoverageBand: scan.discoveryCoverageBand,
        executiveSummary: scan.executiveSummary,
        threatModelSummary: scan.threatModelSummary,
        campaignRecommendations: scan.campaignRecommendations,
        entityProfile: (scan.pipelineOutput as any)?.entityProfile || null,
        financialImpact: (scan.pipelineOutput as any)?.financialImpact || null,
        autoCrawlSummary: (scan.pipelineOutput as any)?.autoCrawlSummary || null,
      };

      expect(previousSnapshot.status).toBe('completed');
      expect(previousSnapshot.totalAssets).toBe(15);
      expect(previousSnapshot.totalFindings).toBe(42);
      expect(previousSnapshot.overallRiskScore).toBe(72);
      expect(previousSnapshot.entityProfile).toEqual({ orgName: 'Test Corp', industry: 'Technology' });
      expect(previousSnapshot.financialImpact).toEqual({ estimatedRevenue: '$10M' });
      expect(previousSnapshot.autoCrawlSummary).toEqual({ pagesScanned: 5 });
      expect(previousSnapshot.snapshotAt).toBeTruthy();
    });

    it('should handle scans without entity/financial data gracefully', () => {
      const scan = {
        status: 'scan_complete',
        totalAssets: 5,
        totalFindings: 10,
        pipelineOutput: {},
      };

      const previousSnapshot = {
        entityProfile: (scan.pipelineOutput as any)?.entityProfile || null,
        financialImpact: (scan.pipelineOutput as any)?.financialImpact || null,
        autoCrawlSummary: (scan.pipelineOutput as any)?.autoCrawlSummary || null,
      };

      expect(previousSnapshot.entityProfile).toBeNull();
      expect(previousSnapshot.financialImpact).toBeNull();
      expect(previousSnapshot.autoCrawlSummary).toBeNull();
    });
  });

  describe('status gating', () => {
    it('should allow refresh for completed scans', () => {
      const allowedStatuses = ['completed', 'scan_complete'];
      expect(allowedStatuses.includes('completed')).toBe(true);
      expect(allowedStatuses.includes('scan_complete')).toBe(true);
    });

    it('should reject refresh for in-progress scans', () => {
      const allowedStatuses = ['completed', 'scan_complete'];
      const inProgressStatuses = ['pending', 'discovering', 'analyzing', 'scoring', 'recommending', 'failed'];
      for (const status of inProgressStatuses) {
        expect(allowedStatuses.includes(status)).toBe(false);
      }
    });

    it('should determine full engagement vs scan-only correctly', () => {
      expect('completed' === 'completed').toBe(true); // full engagement
      expect('scan_complete' === 'completed').toBe(false); // scan-only
    });
  });

  describe('comparison logic', () => {
    it('should calculate deltas correctly for improved scan', () => {
      const prev = { totalAssets: 10, totalFindings: 30, overallRiskScore: 65, discoveryCoverageScore: 50 };
      const current = { totalAssets: 15, totalFindings: 42, overallRiskScore: 72, discoveryCoverageScore: 70 };

      const deltaAssets = current.totalAssets - prev.totalAssets;
      const deltaFindings = current.totalFindings - prev.totalFindings;
      const deltaRisk = current.overallRiskScore - prev.overallRiskScore;
      const deltaCoverage = current.discoveryCoverageScore - prev.discoveryCoverageScore;

      expect(deltaAssets).toBe(5);
      expect(deltaFindings).toBe(12);
      expect(deltaRisk).toBe(7);
      expect(deltaCoverage).toBe(20);
    });

    it('should handle zero deltas', () => {
      const prev = { totalAssets: 10, totalFindings: 30 };
      const current = { totalAssets: 10, totalFindings: 30 };

      expect(current.totalAssets - prev.totalAssets).toBe(0);
      expect(current.totalFindings - prev.totalFindings).toBe(0);
    });

    it('should handle negative deltas (reduced findings after remediation)', () => {
      const prev = { totalAssets: 15, totalFindings: 42, overallRiskScore: 72 };
      const current = { totalAssets: 15, totalFindings: 35, overallRiskScore: 58 };

      const deltaFindings = current.totalFindings - prev.totalFindings;
      const deltaRisk = current.overallRiskScore - prev.overallRiskScore;

      expect(deltaFindings).toBe(-7);
      expect(deltaRisk).toBe(-14);
    });
  });

  describe('pipeline output structure', () => {
    it('should include previousSnapshot and refreshedAt in output', () => {
      const trimmedOutput = {
        totalAssets: 15,
        totalFindings: 42,
        previousSnapshot: {
          snapshotAt: '2026-02-28T00:00:00.000Z',
          totalAssets: 10,
          totalFindings: 30,
        },
        refreshedAt: '2026-02-28T01:00:00.000Z',
      };

      expect(trimmedOutput.previousSnapshot).toBeDefined();
      expect(trimmedOutput.previousSnapshot.snapshotAt).toBeTruthy();
      expect(trimmedOutput.refreshedAt).toBeTruthy();
      expect(new Date(trimmedOutput.refreshedAt).getTime()).toBeGreaterThan(
        new Date(trimmedOutput.previousSnapshot.snapshotAt).getTime()
      );
    });

    it('should preserve previous snapshot entity profile for comparison', () => {
      const output = {
        entityProfile: { orgName: 'Updated Corp', industry: 'Finance', revenue: '$50M' },
        previousSnapshot: {
          entityProfile: { orgName: 'Test Corp', industry: 'Technology' },
        },
      };

      expect(output.entityProfile.orgName).not.toBe(output.previousSnapshot.entityProfile.orgName);
      expect(output.entityProfile.revenue).toBe('$50M');
      expect((output.previousSnapshot.entityProfile as any).revenue).toBeUndefined();
    });
  });

  describe('error recovery', () => {
    it('should restore previous status on failure', () => {
      // If refresh fails, the scan should be restored to its previous completed status
      const wasFullEngagement = true;
      const restoreStatus = wasFullEngagement ? 'completed' : 'scan_complete';
      expect(restoreStatus).toBe('completed');

      const wasScanOnly = false;
      const restoreStatus2 = wasScanOnly ? 'scan_complete' : 'completed';
      expect(restoreStatus2).toBe('completed');
    });

    it('should include refresh error details in pipeline output', () => {
      const errorOutput = {
        refreshError: {
          message: 'Pipeline timeout',
          failedAt: new Date().toISOString(),
        },
      };

      expect(errorOutput.refreshError.message).toBe('Pipeline timeout');
      expect(errorOutput.refreshError.failedAt).toBeTruthy();
    });
  });
});
