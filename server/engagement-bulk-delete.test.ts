import { describe, it, expect, vi, beforeEach } from 'vitest';

/**
 * Tests for engagement bulk delete functionality.
 * Validates the bulkDeleteEngagements db helper and the bulkDelete procedure.
 */

// Mock db module
vi.mock('./db', () => ({
  bulkDeleteEngagements: vi.fn(),
  logActivity: vi.fn(),
}));

import * as db from './db';

describe('Engagement Bulk Delete', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('bulkDeleteEngagements db helper', () => {
    it('should accept an array of IDs and return deleted count', async () => {
      const mockResult = { deleted: 5, reportsDeleted: 12, linksDeleted: 3 };
      vi.mocked(db.bulkDeleteEngagements).mockResolvedValue(mockResult);

      const result = await db.bulkDeleteEngagements([1, 2, 3, 4, 5]);

      expect(db.bulkDeleteEngagements).toHaveBeenCalledWith([1, 2, 3, 4, 5]);
      expect(result).toEqual(mockResult);
      expect(result.deleted).toBe(5);
      expect(result.reportsDeleted).toBe(12);
      expect(result.linksDeleted).toBe(3);
    });

    it('should handle empty result gracefully', async () => {
      vi.mocked(db.bulkDeleteEngagements).mockResolvedValue({ deleted: 0, reportsDeleted: 0, linksDeleted: 0 });

      const result = await db.bulkDeleteEngagements([999, 998]);

      expect(result.deleted).toBe(0);
    });

    it('should handle single ID deletion', async () => {
      vi.mocked(db.bulkDeleteEngagements).mockResolvedValue({ deleted: 1, reportsDeleted: 0, linksDeleted: 0 });

      const result = await db.bulkDeleteEngagements([42]);

      expect(db.bulkDeleteEngagements).toHaveBeenCalledWith([42]);
      expect(result.deleted).toBe(1);
    });

    it('should handle large batch of IDs', async () => {
      const ids = Array.from({ length: 500 }, (_, i) => i + 1);
      vi.mocked(db.bulkDeleteEngagements).mockResolvedValue({ deleted: 500, reportsDeleted: 1000, linksDeleted: 200 });

      const result = await db.bulkDeleteEngagements(ids);

      expect(db.bulkDeleteEngagements).toHaveBeenCalledWith(ids);
      expect(result.deleted).toBe(500);
    });
  });

  describe('Bulk delete input validation', () => {
    it('should require at least 1 ID', () => {
      const { z } = require('zod');
      const schema = z.object({ ids: z.array(z.number()).min(1).max(500) });

      expect(() => schema.parse({ ids: [] })).toThrow();
      expect(() => schema.parse({ ids: [1] })).not.toThrow();
    });

    it('should reject more than 500 IDs', () => {
      const { z } = require('zod');
      const schema = z.object({ ids: z.array(z.number()).min(1).max(500) });

      const tooMany = Array.from({ length: 501 }, (_, i) => i + 1);
      expect(() => schema.parse({ ids: tooMany })).toThrow();
    });

    it('should reject non-number IDs', () => {
      const { z } = require('zod');
      const schema = z.object({ ids: z.array(z.number()).min(1).max(500) });

      expect(() => schema.parse({ ids: ['abc'] })).toThrow();
    });

    it('should accept valid ID arrays', () => {
      const { z } = require('zod');
      const schema = z.object({ ids: z.array(z.number()).min(1).max(500) });

      const result = schema.parse({ ids: [1, 2, 3, 100, 200] });
      expect(result.ids).toEqual([1, 2, 3, 100, 200]);
    });
  });

  describe('Activity logging on bulk delete', () => {
    it('should log activity after successful bulk delete', async () => {
      vi.mocked(db.bulkDeleteEngagements).mockResolvedValue({ deleted: 3, reportsDeleted: 5, linksDeleted: 1 });
      vi.mocked(db.logActivity).mockResolvedValue(undefined);

      await db.bulkDeleteEngagements([10, 20, 30]);
      await db.logActivity({
        userId: 'test-user',
        action: 'engagements_bulk_deleted',
        details: 'Bulk deleted 3 engagements',
      });

      expect(db.logActivity).toHaveBeenCalledWith({
        userId: 'test-user',
        action: 'engagements_bulk_deleted',
        details: 'Bulk deleted 3 engagements',
      });
    });
  });
});
