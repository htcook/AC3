import { describe, it, expect, vi, beforeEach } from 'vitest';

// Test the cachedFetch utility
describe('Server-side Response Cache', () => {
  let cachedFetch: typeof import('../server/lib/api-helpers').cachedFetch;
  let invalidateCache: typeof import('../server/lib/api-helpers').invalidateCache;
  let clearAllCache: typeof import('../server/lib/api-helpers').clearAllCache;

  beforeEach(async () => {
    // Re-import to get fresh module state
    const mod = await import('../server/lib/api-helpers');
    cachedFetch = mod.cachedFetch;
    invalidateCache = mod.invalidateCache;
    clearAllCache = mod.clearAllCache;
    // Clear all cache entries between tests
    clearAllCache();
  });

  it('should return fetched data on first call', async () => {
    const fetcher = vi.fn().mockResolvedValue({ count: 42 });
    const result = await cachedFetch('test:first', fetcher, 30_000);
    expect(result).toEqual({ count: 42 });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('should return cached data on subsequent calls within TTL', async () => {
    const fetcher = vi.fn().mockResolvedValue({ count: 42 });
    
    // First call - fetches
    await cachedFetch('test:cached', fetcher, 30_000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    
    // Second call - should use cache
    const result2 = await cachedFetch('test:cached', fetcher, 30_000);
    expect(result2).toEqual({ count: 42 });
    expect(fetcher).toHaveBeenCalledTimes(1); // Still 1, not 2
  });

  it('should deduplicate concurrent requests for the same key', async () => {
    let resolvePromise: (v: any) => void;
    const slowFetcher = vi.fn().mockImplementation(() => 
      new Promise(resolve => { resolvePromise = resolve; })
    );
    
    // Fire two concurrent requests
    const p1 = cachedFetch('test:dedup', slowFetcher, 30_000);
    const p2 = cachedFetch('test:dedup', slowFetcher, 30_000);
    
    // Only one fetch should have been initiated
    expect(slowFetcher).toHaveBeenCalledTimes(1);
    
    // Resolve the single fetch
    resolvePromise!({ value: 'shared' });
    
    const [r1, r2] = await Promise.all([p1, p2]);
    expect(r1).toEqual({ value: 'shared' });
    expect(r2).toEqual({ value: 'shared' });
  });

  it('should invalidate specific cache keys', async () => {
    const fetcher = vi.fn().mockResolvedValue({ v: 1 });
    
    await cachedFetch('test:invalidate', fetcher, 30_000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    
    // Invalidate the key
    invalidateCache('test:invalidate');
    
    // Next call should re-fetch
    const fetcher2 = vi.fn().mockResolvedValue({ v: 2 });
    const result = await cachedFetch('test:invalidate', fetcher2, 30_000);
    expect(result).toEqual({ v: 2 });
    expect(fetcher2).toHaveBeenCalledTimes(1);
  });

  it('should use different cache entries for different keys', async () => {
    const fetcherA = vi.fn().mockResolvedValue({ key: 'A' });
    const fetcherB = vi.fn().mockResolvedValue({ key: 'B' });
    
    const resultA = await cachedFetch('test:keyA', fetcherA, 30_000);
    const resultB = await cachedFetch('test:keyB', fetcherB, 30_000);
    
    expect(resultA).toEqual({ key: 'A' });
    expect(resultB).toEqual({ key: 'B' });
    expect(fetcherA).toHaveBeenCalledTimes(1);
    expect(fetcherB).toHaveBeenCalledTimes(1);
  });

  it('should clear all cache entries', async () => {
    const fetcher1 = vi.fn().mockResolvedValue({ v: 1 });
    const fetcher2 = vi.fn().mockResolvedValue({ v: 2 });
    
    await cachedFetch('test:clear1', fetcher1, 30_000);
    await cachedFetch('test:clear2', fetcher2, 30_000);
    
    clearAllCache();
    
    // Both should re-fetch
    const fetcher3 = vi.fn().mockResolvedValue({ v: 3 });
    const fetcher4 = vi.fn().mockResolvedValue({ v: 4 });
    
    await cachedFetch('test:clear1', fetcher3, 30_000);
    await cachedFetch('test:clear2', fetcher4, 30_000);
    
    expect(fetcher3).toHaveBeenCalledTimes(1);
    expect(fetcher4).toHaveBeenCalledTimes(1);
  });
});

describe('Caldera Proxy Router Caching', () => {
  it('should export cachedFetch from api-helpers', async () => {
    const mod = await import('../server/lib/api-helpers');
    expect(typeof mod.cachedFetch).toBe('function');
    expect(typeof mod.invalidateCache).toBe('function');
    expect(typeof mod.clearAllCache).toBe('function');
  });

  it('caldera-proxy should import cachedFetch', async () => {
    // Verify the import exists by checking the file content
    const fs = await import('fs');
    const content = fs.readFileSync('server/routers/caldera-proxy.ts', 'utf-8');
    expect(content).toContain("cachedFetch");
    expect(content).toContain("cachedFetch('caldera:stats'");
    expect(content).toContain("cachedFetch('caldera:health'");
  });

  it('gophish-proxy should import cachedFetch', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('server/routers/gophish-proxy.ts', 'utf-8');
    expect(content).toContain("cachedFetch");
    expect(content).toContain("cachedFetch('gophish:stats'");
  });
});

describe('Health Status Banner', () => {
  it('Dashboard.tsx should include health banner markup', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('client/src/pages/Dashboard.tsx', 'utf-8');
    expect(content).toContain('CALDERA C2 SERVER UNREACHABLE');
    expect(content).toContain('GOPHISH SERVER UNREACHABLE');
    expect(content).toContain('CALDERA C2 & GOPHISH SERVERS UNREACHABLE');
    expect(content).toContain("serverStatus === 'offline'");
    expect(content).toContain("gophishStatus === 'offline'");
  });

  it('Analytics script should be conditional', async () => {
    const fs = await import('fs');
    const content = fs.readFileSync('client/index.html', 'utf-8');
    // Should NOT have raw %VITE_ANALYTICS_ENDPOINT% as a src attribute
    expect(content).not.toContain('src="%VITE_ANALYTICS_ENDPOINT%/umami"');
    // Should have the conditional check
    expect(content).toContain("!endpoint.includes('VITE_ANALYTICS')");
    expect(content).toContain("!websiteId.includes('VITE_ANALYTICS')");
  });
});
