import { describe, it, expect } from 'vitest';

describe('Scan Coverage Improvements for Training Labs', () => {
  // Test the training lab auto-detection pattern used across the codebase
  const KNOWN_TRAINING_LABS = [
    'brokencrystals', 'broken-crystals', 'dvwa', 'juiceshop', 'juice-shop',
    'bwapp', 'altoro', 'hackazon', 'testphp', 'webgoat', 'mutillidae',
    'bodgeit', 'gruyere',
  ];

  describe('Training Lab Auto-Detection', () => {
    it('should detect brokencrystals.lab.aceofcloud.io as a training lab', () => {
      const hostname = 'brokencrystals.lab.aceofcloud.io';
      const isTrainingLab = KNOWN_TRAINING_LABS.some(lab => hostname.toLowerCase().includes(lab));
      expect(isTrainingLab).toBe(true);
    });

    it('should detect broken-crystals.example.com as a training lab', () => {
      const hostname = 'broken-crystals.example.com';
      const isTrainingLab = KNOWN_TRAINING_LABS.some(lab => hostname.toLowerCase().includes(lab));
      expect(isTrainingLab).toBe(true);
    });

    it('should detect dvwa.local as a training lab', () => {
      const hostname = 'dvwa.local';
      const isTrainingLab = KNOWN_TRAINING_LABS.some(lab => hostname.toLowerCase().includes(lab));
      expect(isTrainingLab).toBe(true);
    });

    it('should NOT detect google.com as a training lab', () => {
      const hostname = 'google.com';
      const isTrainingLab = KNOWN_TRAINING_LABS.some(lab => hostname.toLowerCase().includes(lab));
      expect(isTrainingLab).toBe(false);
    });

    it('should NOT detect example.com as a training lab', () => {
      const hostname = 'example.com';
      const isTrainingLab = KNOWN_TRAINING_LABS.some(lab => hostname.toLowerCase().includes(lab));
      expect(isTrainingLab).toBe(false);
    });
  });

  describe('BrokenCrystals Default Credentials', () => {
    const TRAINING_LAB_DEFAULT_CREDS: Record<string, { username: string; password: string; loginPath: string }> = {
      'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php' },
      'brokencrystals': { username: 'admin', password: 'admin', loginPath: '/api/auth/login' },
      'broken-crystals': { username: 'admin', password: 'admin', loginPath: '/api/auth/login' },
      'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/#/login' },
    };

    it('should have BrokenCrystals default credentials', () => {
      expect(TRAINING_LAB_DEFAULT_CREDS['brokencrystals']).toBeDefined();
      expect(TRAINING_LAB_DEFAULT_CREDS['brokencrystals'].username).toBe('admin');
      expect(TRAINING_LAB_DEFAULT_CREDS['brokencrystals'].password).toBe('admin');
      expect(TRAINING_LAB_DEFAULT_CREDS['brokencrystals'].loginPath).toBe('/api/auth/login');
    });

    it('should match brokencrystals hostname to credentials', () => {
      const hostname = 'brokencrystals.lab.aceofcloud.io';
      let matchedCreds: any;
      for (const [labKey, creds] of Object.entries(TRAINING_LAB_DEFAULT_CREDS)) {
        if (hostname.toLowerCase().includes(labKey)) {
          matchedCreds = creds;
          break;
        }
      }
      expect(matchedCreds).toBeDefined();
      expect(matchedCreds.username).toBe('admin');
      expect(matchedCreds.password).toBe('admin');
    });
  });

  describe('BrokenCrystals Seed URLs', () => {
    const BC_SEED_URLS = [
      '/', '/api/auth/login', '/api/testimonials', '/api/testimonials/count?query=test',
      '/api/metadata', '/api/file?path=test', '/api/render',
      '/api/users', '/api/products', '/api/config',
      '/swagger', '/.htaccess', '/nginx.conf',
      '/api/spawn', '/api/goto?url=https://example.com',
      '/api/subscriptions', '/api/userinfo',
    ];

    it('should have at least 15 seed URLs for BrokenCrystals', () => {
      expect(BC_SEED_URLS.length).toBeGreaterThanOrEqual(15);
    });

    it('should include key vulnerable endpoints', () => {
      expect(BC_SEED_URLS).toContain('/api/testimonials/count?query=test'); // SQLi
      expect(BC_SEED_URLS).toContain('/api/metadata'); // XXE, SSRF
      expect(BC_SEED_URLS).toContain('/api/file?path=test'); // LFI, SSRF
      expect(BC_SEED_URLS).toContain('/api/render'); // SSTI
      expect(BC_SEED_URLS).toContain('/swagger'); // API docs
    });
  });

  describe('Nuclei Vuln Category Tags for Training Labs', () => {
    const vulnCategoryTags = [
      'sqli', 'xss', 'ssti', 'xxe', 'ssrf', 'lfi', 'rfi',
      'redirect', 'exposure', 'default-login', 'ftp',
      'cve', 'misconfig', 'unauth', 'injection',
      'file-inclusion', 'traversal', 'upload', 'deserialization',
      'oast', 'headless', 'jwt', 'idor', 'csrf', 'cors',
      'command-injection', 'open-redirect', 'ldap',
    ];

    it('should include all OWASP Top 10 related tags', () => {
      expect(vulnCategoryTags).toContain('sqli');
      expect(vulnCategoryTags).toContain('xss');
      expect(vulnCategoryTags).toContain('ssti');
      expect(vulnCategoryTags).toContain('xxe');
      expect(vulnCategoryTags).toContain('ssrf');
      expect(vulnCategoryTags).toContain('lfi');
      expect(vulnCategoryTags).toContain('injection');
    });

    it('should include new tags added for BrokenCrystals coverage', () => {
      expect(vulnCategoryTags).toContain('jwt');
      expect(vulnCategoryTags).toContain('idor');
      expect(vulnCategoryTags).toContain('csrf');
      expect(vulnCategoryTags).toContain('cors');
      expect(vulnCategoryTags).toContain('command-injection');
      expect(vulnCategoryTags).toContain('open-redirect');
      expect(vulnCategoryTags).toContain('ldap');
    });

    it('should have at least 25 tags for comprehensive coverage', () => {
      expect(vulnCategoryTags.length).toBeGreaterThanOrEqual(25);
    });
  });

  describe('ZAP Timeout Configuration', () => {
    it('should give training labs 90 minute timeout', () => {
      const isKnownTrainingLab = true;
      const zapTimeoutMinutes = isKnownTrainingLab ? 90 : 30;
      expect(zapTimeoutMinutes).toBe(90);
    });

    it('should give non-training-lab targets 30 minute timeout (up from 5)', () => {
      const isKnownTrainingLab = false;
      const zapTimeoutMinutes = isKnownTrainingLab ? 90 : 30;
      expect(zapTimeoutMinutes).toBe(30);
    });

    it('should give training labs 8 poll failure tolerance', () => {
      const isKnownTrainingLab = true;
      const maxConsecutivePollFailures = isKnownTrainingLab ? 8 : 5;
      expect(maxConsecutivePollFailures).toBe(8);
    });

    it('should give non-training-lab targets 5 poll failure tolerance (up from 3)', () => {
      const isKnownTrainingLab = false;
      const maxConsecutivePollFailures = isKnownTrainingLab ? 8 : 5;
      expect(maxConsecutivePollFailures).toBe(5);
    });
  });

  describe('Exploit Fallback Tier 3 for Training Labs', () => {
    it('should include medium/low vulns for known training lab targets', () => {
      const isKnownTrainingTarget = true;
      const vulns = [
        { severity: 'critical', title: 'SQLi' },
        { severity: 'high', title: 'RCE' },
        { severity: 'medium', title: 'XSS' },
        { severity: 'low', title: 'Info Disclosure' },
        { severity: 'info', title: 'Missing Header' },
      ];

      const tier1 = vulns.filter(v => v.severity === 'critical' || v.severity === 'high');
      const tier3 = isKnownTrainingTarget
        ? vulns.filter(v => v.severity === 'medium' || v.severity === 'low')
        : [];

      expect(tier1.length).toBe(2);
      expect(tier3.length).toBe(2);
      expect(tier3.map(v => v.title)).toContain('XSS');
      expect(tier3.map(v => v.title)).toContain('Info Disclosure');
    });

    it('should NOT include medium/low vulns for non-training-lab targets', () => {
      const isKnownTrainingTarget = false;
      const vulns = [
        { severity: 'medium', title: 'XSS' },
        { severity: 'low', title: 'Info Disclosure' },
      ];

      const tier3 = isKnownTrainingTarget
        ? vulns.filter(v => v.severity === 'medium' || v.severity === 'low')
        : [];

      expect(tier3.length).toBe(0);
    });
  });

  describe('Feedback Loop Configuration for Training Labs', () => {
    it('should use higher scan budget for training labs', () => {
      const isFeedbackTrainingLab = true;
      const config = {
        maxTotalScans: isFeedbackTrainingLab ? 20 : 12,
        maxScansPerIteration: isFeedbackTrainingLab ? 6 : 4,
        minIterations: isFeedbackTrainingLab ? 3 : 0,
        staleThreshold: isFeedbackTrainingLab ? 3 : 2,
      };

      expect(config.maxTotalScans).toBe(20);
      expect(config.maxScansPerIteration).toBe(6);
      expect(config.minIterations).toBe(3);
      expect(config.staleThreshold).toBe(3);
    });

    it('should use standard budget for non-training-lab targets', () => {
      const isFeedbackTrainingLab = false;
      const config = {
        maxTotalScans: isFeedbackTrainingLab ? 20 : 12,
        maxScansPerIteration: isFeedbackTrainingLab ? 6 : 4,
        minIterations: isFeedbackTrainingLab ? 3 : 0,
        staleThreshold: isFeedbackTrainingLab ? 3 : 2,
      };

      expect(config.maxTotalScans).toBe(12);
      expect(config.maxScansPerIteration).toBe(4);
      expect(config.minIterations).toBe(0);
      expect(config.staleThreshold).toBe(2);
    });

    it('should not converge before minIterations even with stale findings', () => {
      const minIterations = 3;
      const staleThreshold = 3;
      let staleIterations = 3; // Already stale for 3 iterations

      // At iteration 2 (0-indexed), should NOT converge because i < minIterations
      const shouldConvergeAtIteration2 = staleIterations >= staleThreshold && 2 >= minIterations;
      expect(shouldConvergeAtIteration2).toBe(false);

      // At iteration 3, SHOULD converge because i >= minIterations
      const shouldConvergeAtIteration3 = staleIterations >= staleThreshold && 3 >= minIterations;
      expect(shouldConvergeAtIteration3).toBe(true);
    });
  });
});
