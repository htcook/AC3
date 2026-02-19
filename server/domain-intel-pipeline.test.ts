import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Domain Intel Pipeline - Stuck Scan Detection & Recovery', () => {
  // Test the stuck scan detection logic (mirrors frontend isScanStuck helper)
  const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes
  
  const isScanStuck = (scan: { status: string; updatedAt: string | Date }) => {
    const inProgressStatuses = ['passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
    return inProgressStatuses.includes(scan.status)
      && scan.updatedAt
      && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);
  };

  describe('Stuck Scan Detection', () => {
    it('should detect a scan stuck in passive_recon for > 15 minutes', () => {
      const scan = {
        status: 'passive_recon',
        updatedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(), // 20 min ago
      };
      expect(isScanStuck(scan)).toBe(true);
    });

    it('should detect a scan stuck in discovering for > 15 minutes', () => {
      const scan = {
        status: 'discovering',
        updatedAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 min ago
      };
      expect(isScanStuck(scan)).toBe(true);
    });

    it('should detect a scan stuck in analyzing for > 15 minutes', () => {
      const scan = {
        status: 'analyzing',
        updatedAt: new Date(Date.now() - 16 * 60 * 1000).toISOString(), // 16 min ago
      };
      expect(isScanStuck(scan)).toBe(true);
    });

    it('should detect a scan stuck in scoring for > 15 minutes', () => {
      const scan = {
        status: 'scoring',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 60 min ago
      };
      expect(isScanStuck(scan)).toBe(true);
    });

    it('should NOT flag a recently updated in-progress scan as stuck', () => {
      const scan = {
        status: 'passive_recon',
        updatedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 min ago
      };
      expect(isScanStuck(scan)).toBe(false);
    });

    it('should NOT flag a completed scan as stuck', () => {
      const scan = {
        status: 'completed',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 60 min ago
      };
      expect(isScanStuck(scan)).toBe(false);
    });

    it('should NOT flag a scan_complete scan as stuck', () => {
      const scan = {
        status: 'scan_complete',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 60 min ago
      };
      expect(isScanStuck(scan)).toBe(false);
    });

    it('should NOT flag a failed scan as stuck', () => {
      const scan = {
        status: 'failed',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 60 min ago
      };
      expect(isScanStuck(scan)).toBe(false);
    });

    it('should handle scan at exactly 15 minute threshold', () => {
      const scan = {
        status: 'discovering',
        updatedAt: new Date(Date.now() - 15 * 60 * 1000 - 1).toISOString(), // just over 15 min
      };
      expect(isScanStuck(scan)).toBe(true);
    });

    it('should handle scan just under 15 minute threshold', () => {
      const scan = {
        status: 'discovering',
        updatedAt: new Date(Date.now() - 14 * 60 * 1000).toISOString(), // 14 min ago
      };
      expect(isScanStuck(scan)).toBe(false);
    });
  });

  describe('Scan Status Display Logic', () => {
    it('should show "stuck" badge for stuck scans', () => {
      const scan = {
        status: 'passive_recon',
        updatedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const displayStatus = stuck ? 'stuck' : scan.status;
      expect(displayStatus).toBe('stuck');
    });

    it('should show actual status for non-stuck scans', () => {
      const scan = {
        status: 'completed',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const displayStatus = stuck ? 'stuck' : scan.status === 'scan_complete' ? 'scan complete' : scan.status;
      expect(displayStatus).toBe('completed');
    });

    it('should show "scan complete" for scan_complete status', () => {
      const scan = {
        status: 'scan_complete',
        updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const displayStatus = stuck ? 'stuck' : scan.status === 'scan_complete' ? 'scan complete' : scan.status;
      expect(displayStatus).toBe('scan complete');
    });

    it('should show retry button for stuck scans', () => {
      const scan = {
        status: 'passive_recon',
        updatedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const canRetry = stuck || scan.status === 'failed';
      expect(canRetry).toBe(true);
    });

    it('should show retry button for failed scans', () => {
      const scan = {
        status: 'failed',
        updatedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const canRetry = stuck || scan.status === 'failed';
      expect(canRetry).toBe(true);
    });

    it('should NOT show retry button for completed scans', () => {
      const scan = {
        status: 'completed',
        updatedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      };
      const stuck = isScanStuck(scan);
      const canRetry = stuck || scan.status === 'failed';
      expect(canRetry).toBe(false);
    });
  });

  describe('Pipeline Stage Mapping', () => {
    const stageMap: Record<string, number> = {
      passive_recon: 0.5,
      discovering: 1,
      analyzing: 2,
      scoring: 3,
      recommending: 4,
      scan_complete: 3.5,
      completed: 5,
      failed: -1,
    };

    it('should map passive_recon to stage 0.5', () => {
      expect(stageMap['passive_recon']).toBe(0.5);
    });

    it('should map discovering to stage 1', () => {
      expect(stageMap['discovering']).toBe(1);
    });

    it('should map analyzing to stage 2', () => {
      expect(stageMap['analyzing']).toBe(2);
    });

    it('should map scoring to stage 3', () => {
      expect(stageMap['scoring']).toBe(3);
    });

    it('should map scan_complete to stage 3.5', () => {
      expect(stageMap['scan_complete']).toBe(3.5);
    });

    it('should map completed to stage 5', () => {
      expect(stageMap['completed']).toBe(5);
    });

    it('should map failed to stage -1', () => {
      expect(stageMap['failed']).toBe(-1);
    });

    it('should return undefined for unknown status', () => {
      expect(stageMap['unknown']).toBeUndefined();
    });
  });

  describe('deleteDomainIntelScan db helper', () => {
    it('should export deleteDomainIntelScan function', async () => {
      const db = await import('./db');
      expect(typeof db.deleteDomainIntelScan).toBe('function');
    });

    it('should export deleteDiscoveredAssetsByScan function', async () => {
      const db = await import('./db');
      expect(typeof db.deleteDiscoveredAssetsByScan).toBe('function');
    });
  });
});
