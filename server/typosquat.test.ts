import { describe, it, expect, vi } from 'vitest';

// Test the typosquat domain generation logic
describe('Typosquat Domain Generation', () => {
  it('should generate homoglyph variants for a domain', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('example.com', {
      checkAvailability: false,
      maxVariants: 10,
      includeAllTechniques: false,
    });

    expect(result).toBeDefined();
    expect(result.targetDomain).toBe('example.com');
    expect(result.variants).toBeDefined();
    expect(Array.isArray(result.variants)).toBe(true);
    expect(result.variants.length).toBeGreaterThan(0);
    expect(result.recommendedVariants).toBeDefined();
    expect(result.recommendedVariants.length).toBeLessThanOrEqual(10);
    expect(result.generatedAt).toBeDefined();
  });

  it('should include effectiveness scores for each variant', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('google.com', {
      checkAvailability: false,
      maxVariants: 5,
      includeAllTechniques: false,
    });

    for (const variant of result.recommendedVariants) {
      expect(variant.domain).toBeDefined();
      expect(typeof variant.domain).toBe('string');
      expect(variant.technique).toBeDefined();
      expect(variant.effectiveness).toBeGreaterThanOrEqual(0);
      expect(variant.effectiveness).toBeLessThanOrEqual(10);
      expect(variant.description).toBeDefined();
      expect(variant.tld).toBeDefined();
    }
  });

  it('should sort recommended variants by effectiveness descending', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('microsoft.com', {
      checkAvailability: false,
      maxVariants: 10,
      includeAllTechniques: false,
    });

    const scores = result.recommendedVariants.map(v => v.effectiveness);
    for (let i = 1; i < scores.length; i++) {
      expect(scores[i]).toBeLessThanOrEqual(scores[i - 1]);
    }
  });

  it('should include spoofability assessment', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('example.com', {
      checkAvailability: false,
      maxVariants: 5,
      includeAllTechniques: false,
    });

    expect(typeof result.canSpoof).toBe('boolean');
    expect(typeof result.spoofabilityScore).toBe('number');
    expect(result.spoofabilityScore).toBeGreaterThanOrEqual(0);
    expect(result.spoofabilityScore).toBeLessThanOrEqual(100);
    expect(typeof result.spoofabilityReason).toBe('string');
  });

  it('should generate different technique types', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('aceofcloud.com', {
      checkAvailability: false,
      maxVariants: 20,
      includeAllTechniques: true,
    });

    const techniques = new Set(result.variants.map(v => v.technique));
    // Should have at least 3 different techniques
    expect(techniques.size).toBeGreaterThanOrEqual(3);
  });

  it('should not include the original domain in variants', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('test.com', {
      checkAvailability: false,
      maxVariants: 10,
      includeAllTechniques: false,
    });

    for (const variant of result.variants) {
      expect(variant.domain).not.toBe('test.com');
    }
  });

  it('should generate valid domain names', async () => {
    const { generateTyposquatVariants } = await import('./lib/typosquat');
    const result = await generateTyposquatVariants('example.com', {
      checkAvailability: false,
      maxVariants: 10,
      includeAllTechniques: false,
    });

    const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/;
    for (const variant of result.variants) {
      expect(variant.domain).toMatch(domainRegex);
    }
  });
});

describe('Typosquat DigitalOcean Integration', () => {
  it('should export configureDomainForEmail function', async () => {
    const mod = await import('./lib/typosquat');
    expect(typeof mod.configureDomainForEmail).toBe('function');
  });

  it('should export addDomainToDO function', async () => {
    const mod = await import('./lib/typosquat');
    expect(typeof mod.addDomainToDO).toBe('function');
  });

  it('should export listDODomains function', async () => {
    const mod = await import('./lib/typosquat');
    expect(typeof mod.listDODomains).toBe('function');
  });

  it('should export getDomainRecords function', async () => {
    const mod = await import('./lib/typosquat');
    expect(typeof mod.getDomainRecords).toBe('function');
  });
});
