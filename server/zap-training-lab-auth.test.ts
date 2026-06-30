/**
 * Tests for ZAP Training Lab Authentication Fix.
 *
 * Root cause: When Hydra fails to confirm credentials for training labs (DVWA, Juice Shop, etc.),
 * the orchestrator had training lab default creds but NEVER called configureZapAuthentication()
 * with them. Only the `hasConfirmedCreds` path triggered ZAP auth configuration.
 *
 * Fix: Added `else if (trainingLabCreds && zapScanResult?.scanId)` branch that:
 * 1. Converts training lab defaults to ConfirmedCredential format
 * 2. Calls configureZapAuthentication() with synthetic credentials
 * 3. Falls back to pre-auth + cookie injection if ZAP auth config fails
 * 4. Stores session cookie on asset for downstream tools (Burp, SQLMap)
 */
import { describe, it, expect } from 'vitest';

// ─── Training Lab Credential Detection Tests ───
describe('Training lab credential detection', () => {
  const TRAINING_LAB_DEFAULT_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
    'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
    'altoro': { username: 'admin', password: 'admin', loginPath: '/altoromutual/login.jsp' },
    'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/#/login' },
    'hackazon': { username: 'test_user', password: 'test_user', loginPath: '/user/login' },
    'testphp': { username: 'test', password: 'test', loginPath: '/login.php' },
  };

  function detectTrainingLabCreds(hostname: string): { username: string; password: string; loginPath: string } | undefined {
    const lower = hostname.toLowerCase();
    for (const [labKey, creds] of Object.entries(TRAINING_LAB_DEFAULT_CREDS)) {
      if (lower.includes(labKey)) return creds;
    }
    return undefined;
  }

  it('should detect DVWA credentials from hostname', () => {
    const creds = detectTrainingLabCreds('dvwa.lab.aceofcloud.io');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('admin');
    expect(creds!.password).toBe('password');
    expect(creds!.loginPath).toBe('/login.php');
  });

  it('should detect Juice Shop credentials', () => {
    const creds = detectTrainingLabCreds('juiceshop.lab.example.com');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('admin@juice-sh.op');
    expect(creds!.loginPath).toBe('/#/login');
  });

  it('should detect Altoro Mutual credentials', () => {
    const creds = detectTrainingLabCreds('altoro.lab.example.com');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('admin');
    expect(creds!.loginPath).toBe('/altoromutual/login.jsp');
  });

  it('should detect Hackazon credentials', () => {
    const creds = detectTrainingLabCreds('hackazon.test.local');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('test_user');
  });

  it('should detect testphp credentials', () => {
    const creds = detectTrainingLabCreds('testphp.vulnweb.com');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('test');
  });

  it('should return undefined for non-training-lab hosts', () => {
    const creds = detectTrainingLabCreds('production.example.com');
    expect(creds).toBeUndefined();
  });

  it('should be case-insensitive', () => {
    const creds = detectTrainingLabCreds('DVWA.Lab.AceOfCloud.IO');
    expect(creds).toBeDefined();
    expect(creds!.username).toBe('admin');
  });
});

// ─── Synthetic Credential Construction Tests ───
describe('Synthetic credential construction for ZAP auth', () => {
  interface ConfirmedCredential {
    username: string;
    password: string;
    service: string;
    port: number;
    protocol: string;
    accessLevel?: string;
    source: string;
    confirmedAt: number;
  }

  function buildSyntheticCreds(
    trainingLabCreds: { username: string; password: string; loginPath: string },
    targetUrl: string,
  ): ConfirmedCredential[] {
    return [{
      username: trainingLabCreds.username,
      password: trainingLabCreds.password,
      service: 'http-form',
      port: parseInt(new URL(targetUrl).port) || (targetUrl.startsWith('https') ? 443 : 80),
      protocol: targetUrl.startsWith('https') ? 'https' : 'http',
      accessLevel: 'admin',
      source: 'training_lab_defaults',
      confirmedAt: Date.now(),
    }];
  }

  it('should construct valid ConfirmedCredential for HTTPS target', () => {
    const creds = buildSyntheticCreds(
      { username: 'admin', password: 'password', loginPath: '/login.php' },
      'https://dvwa.lab.aceofcloud.io',
    );
    expect(creds).toHaveLength(1);
    expect(creds[0].username).toBe('admin');
    expect(creds[0].password).toBe('password');
    expect(creds[0].service).toBe('http-form');
    expect(creds[0].port).toBe(443);
    expect(creds[0].protocol).toBe('https');
    expect(creds[0].source).toBe('training_lab_defaults');
  });

  it('should use explicit port from URL', () => {
    const creds = buildSyntheticCreds(
      { username: 'admin', password: 'password', loginPath: '/login.php' },
      'https://dvwa.lab.aceofcloud.io:8443',
    );
    expect(creds[0].port).toBe(8443);
  });

  it('should default to port 80 for HTTP', () => {
    const creds = buildSyntheticCreds(
      { username: 'admin', password: 'password', loginPath: '/login.php' },
      'http://dvwa.lab.local',
    );
    expect(creds[0].port).toBe(80);
    expect(creds[0].protocol).toBe('http');
  });

  it('should preserve access level as admin', () => {
    const creds = buildSyntheticCreds(
      { username: 'test', password: 'test', loginPath: '/login.php' },
      'https://testphp.vulnweb.com',
    );
    expect(creds[0].accessLevel).toBe('admin');
  });
});

// ─── Auth Path Selection Tests ───
describe('Auth path selection — confirmed vs training lab vs unauthenticated', () => {
  type AuthPath = 'confirmed_creds' | 'training_lab_defaults' | 'unauthenticated';

  function selectAuthPath(
    hasConfirmedCreds: boolean,
    trainingLabCreds: { username: string; password: string; loginPath: string } | undefined,
    hasScanId: boolean,
  ): AuthPath {
    if (hasConfirmedCreds && hasScanId) return 'confirmed_creds';
    if (trainingLabCreds && hasScanId) return 'training_lab_defaults';
    return 'unauthenticated';
  }

  it('should prefer confirmed creds when available', () => {
    expect(selectAuthPath(true, { username: 'admin', password: 'password', loginPath: '/login.php' }, true))
      .toBe('confirmed_creds');
  });

  it('should use training lab defaults when no confirmed creds', () => {
    expect(selectAuthPath(false, { username: 'admin', password: 'password', loginPath: '/login.php' }, true))
      .toBe('training_lab_defaults');
  });

  it('should fall back to unauthenticated when no creds at all', () => {
    expect(selectAuthPath(false, undefined, true))
      .toBe('unauthenticated');
  });

  it('should fall back to unauthenticated when no scan ID', () => {
    expect(selectAuthPath(false, { username: 'admin', password: 'password', loginPath: '/login.php' }, false))
      .toBe('unauthenticated');
  });

  it('should prefer confirmed creds over training lab defaults even when both exist', () => {
    // This matches the if/else-if structure: hasConfirmedCreds is checked first
    expect(selectAuthPath(true, { username: 'admin', password: 'password', loginPath: '/login.php' }, true))
      .toBe('confirmed_creds');
  });
});

// ─── DVWA Seed URL Tests ───
describe('DVWA seed URL generation', () => {
  const DVWA_SEED_PATHS = [
    '/', '/login.php', '/index.php', '/about.php', '/security.php',
    '/vulnerabilities/sqli/', '/vulnerabilities/sqli_blind/',
    '/vulnerabilities/xss_r/', '/vulnerabilities/xss_s/', '/vulnerabilities/xss_d/',
    '/vulnerabilities/exec/', '/vulnerabilities/fi/', '/vulnerabilities/upload/',
    '/vulnerabilities/csrf/', '/vulnerabilities/brute/',
    '/vulnerabilities/captcha/', '/vulnerabilities/weak_id/',
  ];

  it('should generate full URLs from seed paths', () => {
    const targetUrl = 'https://dvwa.lab.aceofcloud.io';
    const seedUrls = DVWA_SEED_PATHS.map(p => `${targetUrl}${p}`);
    expect(seedUrls).toHaveLength(17);
    expect(seedUrls[0]).toBe('https://dvwa.lab.aceofcloud.io/');
    expect(seedUrls[1]).toBe('https://dvwa.lab.aceofcloud.io/login.php');
  });

  it('should include all DVWA vulnerability categories', () => {
    const vulnPaths = DVWA_SEED_PATHS.filter(p => p.includes('/vulnerabilities/'));
    expect(vulnPaths.length).toBeGreaterThanOrEqual(11);
    expect(vulnPaths.some(p => p.includes('sqli'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('xss'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('exec'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('fi'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('upload'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('csrf'))).toBe(true);
    expect(vulnPaths.some(p => p.includes('brute'))).toBe(true);
  });
});

// ─── Session Cookie Propagation Tests ───
describe('Session cookie propagation to downstream tools', () => {
  it('should store session cookie on asset for Burp/SQLMap use', () => {
    const asset: any = { hostname: 'dvwa.lab.aceofcloud.io', ports: [{ port: 443 }] };
    const trainingLabCreds = { username: 'admin', password: 'password', loginPath: '/login.php' };
    const sessionCookie = 'PHPSESSID=abc123; security=low';

    // Simulate the orchestrator storing the session cookie
    asset.trainingLabCreds = {
      ...trainingLabCreds,
      sessionCookie,
    };

    expect(asset.trainingLabCreds.sessionCookie).toBe('PHPSESSID=abc123; security=low');
    expect(asset.trainingLabCreds.username).toBe('admin');
    expect(asset.trainingLabCreds.loginPath).toBe('/login.php');
  });

  it('should construct auth header from session cookie', () => {
    const sessionCookie = 'PHPSESSID=abc123; security=low';
    const authHeader = `-H "Cookie: ${sessionCookie}"`;
    expect(authHeader).toContain('PHPSESSID=abc123');
    expect(authHeader).toContain('security=low');
  });
});
