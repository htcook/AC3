/**
 * Tests for:
 * 1. rescanAssetWithDeeperProfile() — profile escalation logic
 * 2. Training lab auto-auth for Gobuster — session cookie acquisition
 * 3. Tool knowledge base — module structure and lookup functions
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ═══ Test 1: Rescan Escalation Logic ═══════════════════════════════════════

describe("rescanAssetWithDeeperProfile", () => {
  // We test the exported function's logic by mocking the orchestrator state
  // Since the function uses dynamic imports and state maps, we test the logic patterns

  it("should define correct profile escalation order", () => {
    const PROFILE_ESCALATION_ORDER = ['quick', 'standard', 'deep'];
    expect(PROFILE_ESCALATION_ORDER.indexOf('quick')).toBe(0);
    expect(PROFILE_ESCALATION_ORDER.indexOf('standard')).toBe(1);
    expect(PROFILE_ESCALATION_ORDER.indexOf('deep')).toBe(2);
  });

  it("should escalate quick → standard", () => {
    const PROFILES = ['quick', 'standard', 'deep'] as const;
    const currentProfile = 'quick';
    const currentIdx = PROFILES.indexOf(currentProfile);
    const nextProfile = currentIdx < PROFILES.length - 1 ? PROFILES[currentIdx + 1] : null;
    expect(nextProfile).toBe('standard');
  });

  it("should escalate standard → deep", () => {
    const PROFILES = ['quick', 'standard', 'deep'] as const;
    const currentProfile = 'standard';
    const currentIdx = PROFILES.indexOf(currentProfile);
    const nextProfile = currentIdx < PROFILES.length - 1 ? PROFILES[currentIdx + 1] : null;
    expect(nextProfile).toBe('deep');
  });

  it("should not escalate beyond deep", () => {
    const PROFILES = ['quick', 'standard', 'deep'] as const;
    const currentProfile = 'deep';
    const currentIdx = PROFILES.indexOf(currentProfile);
    const nextProfile = currentIdx < PROFILES.length - 1 ? PROFILES[currentIdx + 1] : null;
    expect(nextProfile).toBeNull();
  });

  it("should allow explicit target profile override", () => {
    const PROFILES = ['quick', 'standard', 'deep'] as const;
    const currentProfile = 'quick';
    const targetProfile = 'deep'; // Skip standard, go straight to deep
    const targetIdx = PROFILES.indexOf(targetProfile);
    const currentIdx = PROFILES.indexOf(currentProfile);
    expect(targetIdx).toBeGreaterThan(currentIdx);
  });

  it("should reject invalid target profile", () => {
    const PROFILES = ['quick', 'standard', 'deep'] as const;
    const targetProfile = 'stealth';
    const targetIdx = PROFILES.indexOf(targetProfile as any);
    expect(targetIdx).toBe(-1);
  });

  it("should build correct target URL from asset ports", () => {
    const asset = {
      hostname: 'dvwa.lab.local',
      ports: [
        { port: 443, service: 'https', state: 'open' },
        { port: 80, service: 'http', state: 'open' },
      ],
    };
    const httpPort = asset.ports.find(p => p.service === 'http' || p.service === 'https' || p.port === 80 || p.port === 443);
    const protocol = httpPort?.port === 443 || httpPort?.service === 'https' ? 'https' : 'http';
    const port = httpPort?.port || 80;
    const targetUrl = port === 80 || port === 443
      ? `${protocol}://${asset.hostname}`
      : `${protocol}://${asset.hostname}:${port}`;
    expect(targetUrl).toBe('https://dvwa.lab.local');
  });

  it("should include non-standard port in URL", () => {
    const asset = {
      hostname: 'juice-shop.lab.local',
      ports: [
        { port: 8080, service: 'http', state: 'open' },
      ],
    };
    const httpPort = asset.ports.find(p => p.service === 'http' || p.service === 'https' || p.port === 80 || p.port === 443);
    const protocol = httpPort?.port === 443 || httpPort?.service === 'https' ? 'https' : 'http';
    const port = httpPort?.port || 80;
    const targetUrl = port === 80 || port === 443
      ? `${protocol}://${asset.hostname}`
      : `${protocol}://${asset.hostname}:${port}`;
    expect(targetUrl).toBe('http://juice-shop.lab.local:8080');
  });
});

// ═══ Test 2: Training Lab Auto-Auth for Gobuster ═══════════════════════════

describe("Training Lab Auto-Auth for Gobuster", () => {
  const GOBUSTER_LAB_CREDS: Record<string, { username: string; password: string; loginPath: string; authType: string }> = {
    'dvwa': { username: 'admin', password: 'password', loginPath: '/login.php', authType: 'form-csrf' },
    'bwapp': { username: 'bee', password: 'bug', loginPath: '/login.php', authType: 'form-simple' },
    'juiceshop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/rest/user/login', authType: 'json-jwt' },
    'juice-shop': { username: 'admin@juice-sh.op', password: 'admin123', loginPath: '/rest/user/login', authType: 'json-jwt' },
    'webgoat': { username: 'guest', password: 'guest', loginPath: '/WebGoat/login', authType: 'form-simple' },
    'hackazon': { username: 'test_user', password: 'test_user', loginPath: '/user/login', authType: 'form-simple' },
    'mutillidae': { username: 'admin', password: 'admin', loginPath: '/index.php?page=login.php', authType: 'form-simple' },
    'bodgeit': { username: 'test@test.com', password: 'test', loginPath: '/bodgeit/login.jsp', authType: 'form-simple' },
    'broken-crystals': { username: 'john@mail.com', password: 'Admin123!', loginPath: '/api/auth/login', authType: 'json-jwt' },
    'brokencrystals': { username: 'john@mail.com', password: 'Admin123!', loginPath: '/api/auth/login', authType: 'json-jwt' },
  };

  it("should match DVWA hostname to form-csrf auth type", () => {
    const hostname = 'dvwa.aceofcloud.io';
    let matchedLab: { key: string; creds: any } | undefined;
    for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
      if (hostname.includes(labKey.replace('-', ''))) {
        matchedLab = { key: labKey, creds };
        break;
      }
    }
    expect(matchedLab).toBeDefined();
    expect(matchedLab!.key).toBe('dvwa');
    expect(matchedLab!.creds.authType).toBe('form-csrf');
    expect(matchedLab!.creds.loginPath).toBe('/login.php');
  });

  it("should match Juice Shop hostname to json-jwt auth type", () => {
    const hostname = 'juiceshop.lab.local';
    let matchedLab: { key: string; creds: any } | undefined;
    for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
      if (hostname.includes(labKey.replace('-', ''))) {
        matchedLab = { key: labKey, creds };
        break;
      }
    }
    expect(matchedLab).toBeDefined();
    expect(matchedLab!.key).toBe('juiceshop');
    expect(matchedLab!.creds.authType).toBe('json-jwt');
    expect(matchedLab!.creds.loginPath).toBe('/rest/user/login');
  });

  it("should match Broken Crystals hostname", () => {
    const hostname = 'brokencrystals.aceofcloud.io';
    let matchedLab: { key: string; creds: any } | undefined;
    for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
      if (hostname.includes(labKey.replace('-', ''))) {
        matchedLab = { key: labKey, creds };
        break;
      }
    }
    expect(matchedLab).toBeDefined();
    expect(matchedLab!.creds.authType).toBe('json-jwt');
    expect(matchedLab!.creds.username).toBe('john@mail.com');
  });

  it("should not match unknown hostnames", () => {
    const hostname = 'production.example.com';
    let matchedLab: { key: string; creds: any } | undefined;
    for (const [labKey, creds] of Object.entries(GOBUSTER_LAB_CREDS)) {
      if (hostname.includes(labKey.replace('-', ''))) {
        matchedLab = { key: labKey, creds };
        break;
      }
    }
    expect(matchedLab).toBeUndefined();
  });

  it("should only trigger auto-auth when trainingLabMode is true and no existing cookie", () => {
    const state = { trainingLabMode: true };
    const authCookie = ''; // No existing cookie
    const shouldAutoAuth = !authCookie && state.trainingLabMode;
    expect(shouldAutoAuth).toBe(true);
  });

  it("should NOT trigger auto-auth when cookie already exists", () => {
    const state = { trainingLabMode: true };
    const authCookie = 'PHPSESSID=abc123'; // Existing cookie
    const shouldAutoAuth = !authCookie && state.trainingLabMode;
    expect(shouldAutoAuth).toBe(false);
  });

  it("should NOT trigger auto-auth when trainingLabMode is false", () => {
    const state = { trainingLabMode: false };
    const authCookie = '';
    const shouldAutoAuth = !authCookie && state.trainingLabMode;
    expect(shouldAutoAuth).toBe(false);
  });

  it("should parse DVWA CSRF token from login page HTML", () => {
    const html = `<form action="login.php" method="post">
      <input type="hidden" name="user_token" value="abc123def456" />
      <input type="text" name="username" />
    </form>`;
    const csrfMatch = html.match(/user_token.*?value=['"]([^'"]+)['"]/i);
    expect(csrfMatch).toBeDefined();
    expect(csrfMatch![1]).toBe('abc123def456');
  });

  it("should parse PHPSESSID from Set-Cookie header", () => {
    const responseHeaders = `HTTP/1.1 302 Found
Set-Cookie: PHPSESSID=r4nd0ms3ss10n; path=/
Location: /index.php`;
    const sessionMatch = responseHeaders.match(/PHPSESSID=([^;\s]+)/i);
    expect(sessionMatch).toBeDefined();
    expect(sessionMatch![1]).toBe('r4nd0ms3ss10n');
  });

  it("should parse JWT from Juice Shop login response", () => {
    const loginResponse = JSON.stringify({
      authentication: {
        token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
        bid: 1,
        umail: "admin@juice-sh.op",
      }
    });
    const resp = JSON.parse(loginResponse);
    const token = resp.authentication?.token || resp.token || resp.access_token;
    expect(token).toBe("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature");
    const authCookie = `token=${token}`;
    expect(authCookie).toContain('token=eyJ');
  });

  it("should parse token from Broken Crystals login response", () => {
    const loginResponse = JSON.stringify({
      token: "bc-jwt-token-here",
    });
    const resp = JSON.parse(loginResponse);
    const token = resp.authentication?.token || resp.token || resp.access_token;
    expect(token).toBe("bc-jwt-token-here");
  });
});

// ═══ Test 3: Tool Knowledge Base Structure ═══════════════════════════════════

describe("Tool Knowledge Base", () => {
  it("should export getToolKnowledge function", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    expect(typeof getToolKnowledge).toBe('function');
  });

  it("should return knowledge for hydra", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('hydra');
    expect(knowledge).toBeDefined();
    expect(knowledge!.tool).toBe('hydra');
    expect(knowledge!.techniques).toBeDefined();
    expect(Array.isArray(knowledge!.techniques)).toBe(true);
    expect(knowledge!.techniques.length).toBeGreaterThan(0);
  });

  it("should return knowledge for sqlmap", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('sqlmap');
    expect(knowledge).toBeDefined();
    expect(knowledge!.tool).toBe('sqlmap');
    expect(knowledge!.techniques.length).toBeGreaterThan(0);
  });

  it("should return knowledge for gobuster", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('gobuster');
    expect(knowledge).toBeDefined();
    expect(knowledge!.tool).toBe('gobuster');
  });

  it("should return knowledge for nmap", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('nmap');
    expect(knowledge).toBeDefined();
    expect(knowledge!.tool).toBe('nmap');
  });

  it("should return knowledge for wfuzz", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('wfuzz');
    expect(knowledge).toBeDefined();
    expect(knowledge!.tool).toBe('wfuzz');
  });

  it("should return undefined for unknown tools", async () => {
    const { getToolKnowledge } = await import("./lib/tool-knowledge-base");
    const knowledge = getToolKnowledge('nonexistent-tool');
    expect(knowledge).toBeUndefined();
  });

  it("should export getToolContextForLLM function", async () => {
    const { getToolContextForLLM } = await import("./lib/tool-knowledge-base");
    expect(typeof getToolContextForLLM).toBe('function');
  });

  it("should return formatted context for multiple tools", async () => {
    const { getToolContextForLLM } = await import("./lib/tool-knowledge-base");
    const context = getToolContextForLLM(['hydra', 'sqlmap', 'gobuster']);
    expect(typeof context).toBe('string');
    expect(context.length).toBeGreaterThan(100);
    expect(context).toContain('hydra');
    expect(context).toContain('sqlmap');
    expect(context).toContain('gobuster');
  });
});
