import { describe, it, expect, vi } from 'vitest';
import * as db from './db';

describe('Threat Actor Database Operations', () => {
  it('should list threat actors from the database', async () => {
    const result = await db.listThreatActors({});
    expect(result).toBeDefined();
    expect(result.actors).toBeDefined();
    expect(result.total).toBeDefined();
    expect(result.total).toBeGreaterThan(0);
    expect(Array.isArray(result.actors)).toBe(true);
  });

  it('should list threat actors with pagination', async () => {
    const page1 = await db.listThreatActors({ limit: 10, offset: 0 });
    const page2 = await db.listThreatActors({ limit: 10, offset: 10 });
    expect(page1.actors.length).toBeLessThanOrEqual(10);
    expect(page2.actors.length).toBeLessThanOrEqual(10);
    // Pages should have different actors
    if (page1.actors.length > 0 && page2.actors.length > 0) {
      expect(page1.actors[0].id).not.toBe(page2.actors[0].id);
    }
  });

  it('should filter threat actors by type', async () => {
    const aptActors = await db.listThreatActors({ type: 'apt' });
    expect(aptActors.actors.length).toBeGreaterThan(0);
    aptActors.actors.forEach((actor: any) => {
      expect(actor.type).toBe('apt');
    });
  });

  it('should filter threat actors by origin', async () => {
    const chinaActors = await db.listThreatActors({ origin: 'China' });
    expect(chinaActors.actors.length).toBeGreaterThan(0);
    chinaActors.actors.forEach((actor: any) => {
      expect(actor.origin).toBe('China');
    });
  });

  it('should search threat actors by name', async () => {
    const result = await db.listThreatActors({ search: 'APT28' });
    expect(result.actors.length).toBeGreaterThan(0);
    const hasMatch = result.actors.some((a: any) =>
      a.name.toLowerCase().includes('apt28') ||
      (a.aliases && JSON.stringify(a.aliases).toLowerCase().includes('apt28'))
    );
    expect(hasMatch).toBe(true);
  });

  it('should get a specific threat actor by actorId', async () => {
    // First get any actor
    const list = await db.listThreatActors({ limit: 1 });
    expect(list.actors.length).toBeGreaterThan(0);
    const actorId = list.actors[0].actorId;

    const actor = await db.getThreatActor(actorId);
    expect(actor).toBeDefined();
    expect(actor).not.toBeNull();
    expect(actor!.actorId).toBe(actorId);
    expect(actor!.name).toBeDefined();
  });

  it('should get a specific threat actor by numeric id', async () => {
    const list = await db.listThreatActors({ limit: 1 });
    expect(list.actors.length).toBeGreaterThan(0);
    const numericId = list.actors[0].id;

    const actor = await db.getThreatActorById(numericId);
    expect(actor).toBeDefined();
    expect(actor).not.toBeNull();
  });

  it('should return null for non-existent threat actor', async () => {
    const actor = await db.getThreatActor('non-existent-actor-id-12345');
    expect(actor).toBeNull();
  });

  it('should get threat actor stats', async () => {
    const stats = await db.getThreatActorStats();
    expect(stats).toBeDefined();
    expect(stats.total).toBeGreaterThan(0);
    expect(stats.byType).toBeDefined();
    expect(stats.byOrigin).toBeDefined();
  });

  it('should have actors from multiple origins', async () => {
    const stats = await db.getThreatActorStats();
    // byOrigin is an array of { origin, count }
    expect(stats.byOrigin.length).toBeGreaterThan(3);
    const origins = stats.byOrigin.map((o: any) => o.origin || '');
    const hasChina = origins.some((o: string) => o.toLowerCase().includes('china'));
    const hasRussia = origins.some((o: string) => o.toLowerCase().includes('russia'));
    expect(hasChina || hasRussia).toBe(true);
  });

  it('should have actors of multiple types', async () => {
    const stats = await db.getThreatActorStats();
    // byType is an array of { type, count }
    expect(stats.byType.length).toBeGreaterThan(1);
    const types = stats.byType.map((t: any) => t.type);
    expect(types.length).toBeGreaterThanOrEqual(2);
  });

  it('should have at least 400 total actors', async () => {
    const stats = await db.getThreatActorStats();
    expect(stats.total).toBeGreaterThanOrEqual(400);
  });
});

describe('IOC Feed Database Operations', () => {
  it('should list IOC feed entries', async () => {
    const result = await db.listIocFeedEntries({});
    expect(result).toBeDefined();
    expect(result.entries).toBeDefined();
    expect(result.total).toBeDefined();
    expect(Array.isArray(result.entries)).toBe(true);
  });

  it('should get IOC feed stats', async () => {
    const stats = await db.getIocFeedStats();
    expect(stats).toBeDefined();
    expect(typeof stats.total).toBe('number');
  });

  it('should create and list IOC feed entries', async () => {
    const testEntry = {
      feedSource: 'test_source',
      feedType: 'test',
      title: 'Test IOC Entry',
      description: 'Test description',
      severity: 'high' as const,
      iocType: 'domain',
      iocValue: `test-${Date.now()}.example.com`,
      tags: ['test'],
      rawData: { test: true },
    };

    await db.bulkCreateIocFeedEntries([testEntry]);

    const result = await db.listIocFeedEntries({ feedSource: 'test_source' });
    expect(result.entries.length).toBeGreaterThan(0);
    const found = result.entries.find((e: any) => e.iocValue === testEntry.iocValue);
    expect(found).toBeDefined();
    expect(found!.title).toBe('Test IOC Entry');
  });

  it('should filter IOC entries by severity', async () => {
    const result = await db.listIocFeedEntries({ severity: 'high' });
    result.entries.forEach((e: any) => {
      expect(e.severity).toBe('high');
    });
  });
});

describe('Engagement Pipeline Database Operations', () => {
  it('should create an engagement pipeline', async () => {
    const id = await db.createEngagementPipeline({
      userId: 1,
      name: 'Test Pipeline',
      status: 'pending',
      targetDomains: ['example.com'],
      clientType: 'enterprise',
      totalSteps: 6,
      currentStep: 0,
      stepLog: [{ step: 1, name: 'Test Step', status: 'pending' }],
    });
    expect(id).toBeDefined();
    expect(typeof id).toBe('number');
  });

  it('should get an engagement pipeline', async () => {
    const id = await db.createEngagementPipeline({
      userId: 1,
      name: 'Test Pipeline Get',
      status: 'pending',
      targetDomains: ['test.com'],
      clientType: 'msp',
      totalSteps: 6,
      currentStep: 0,
      stepLog: [],
    });

    const pipeline = await db.getEngagementPipeline(id);
    expect(pipeline).toBeDefined();
    expect(pipeline!.name).toBe('Test Pipeline Get');
    expect(pipeline!.clientType).toBe('msp');
  });

  it('should update an engagement pipeline', async () => {
    const id = await db.createEngagementPipeline({
      userId: 1,
      name: 'Test Pipeline Update',
      status: 'pending',
      targetDomains: ['update.com'],
      clientType: 'saas',
      totalSteps: 6,
      currentStep: 0,
      stepLog: [],
    });

    await db.updateEngagementPipeline(id, {
      status: 'running',
      currentStep: 3,
    });

    const updated = await db.getEngagementPipeline(id);
    expect(updated!.status).toBe('running');
    expect(updated!.currentStep).toBe(3);
  });

  it('should list engagement pipelines', async () => {
    const result = await db.listEngagementPipelines();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
  });

  it('should support all client types', async () => {
    const clientTypes = ['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting'];
    for (const ct of clientTypes) {
      const id = await db.createEngagementPipeline({
        userId: 1,
        name: `Pipeline ${ct}`,
        status: 'pending',
        targetDomains: [`${ct}.example.com`],
        clientType: ct,
        totalSteps: 6,
        currentStep: 0,
        stepLog: [],
      });
      const pipeline = await db.getEngagementPipeline(id);
      expect(pipeline!.clientType).toBe(ct);
    }
  });
});

describe('Ransomware Abilities Data', () => {
  it('should have all ransomware profiles loaded', async () => {
    const { RANSOMWARE_PROFILES } = await import('../client/src/data/ransomware-abilities');
    expect(RANSOMWARE_PROFILES.length).toBe(9);
  });

  it('should have abilities for each ransomware group', async () => {
    const { RANSOMWARE_PROFILES } = await import('../client/src/data/ransomware-abilities');
    for (const profile of RANSOMWARE_PROFILES) {
      expect(profile.abilities.length).toBeGreaterThan(0);
      expect(profile.groupName).toBeDefined();
      expect(profile.groupId).toBeDefined();
    }
  });

  it('should have IOCs for each ransomware group', async () => {
    const { RANSOMWARE_PROFILES } = await import('../client/src/data/ransomware-abilities');
    for (const profile of RANSOMWARE_PROFILES) {
      expect(profile.iocs.length).toBeGreaterThan(0);
    }
  });

  it('should have getAllAbilities returning all abilities', async () => {
    const { getAllAbilities } = await import('../client/src/data/ransomware-abilities');
    const abilities = getAllAbilities();
    expect(abilities.length).toBeGreaterThanOrEqual(45);
  });

  it('should have getAllIOCs returning all IOCs', async () => {
    const { getAllIOCs } = await import('../client/src/data/ransomware-abilities');
    const iocs = getAllIOCs();
    expect(iocs.length).toBeGreaterThanOrEqual(40);
  });
});
