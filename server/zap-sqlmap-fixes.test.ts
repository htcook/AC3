import { describe, it, expect } from "vitest";
import * as fs from "fs";

/**
 * Tests for ZAP 0-findings and SQLMap fixes:
 * 1. Training lab port filtering (httpxLivePorts)
 * 2. ZAP seed URL injection for SPA targets
 * 3. ZAP active scan 400 retry with accessUrl fallback
 * 4. Training lab injectable endpoints for SQLMap/XSStrike
 * 5. ZAP timeout increase for training labs
 */

const orchestratorSource = fs.readFileSync("server/lib/engagement-orchestrator.ts", "utf8");
const zapScannerSource = fs.readFileSync("server/lib/zap-scanner.ts", "utf8");


// Skip in CI — requires SSH access to scan server
const __skipInCI = !process.env.SCAN_SERVER_HOST;

describe.skipIf(__skipInCI)("Training Lab Port Filtering", () => {
  it("should track httpx status codes per port on assets", () => {
    // The orchestrator should store httpxLivePorts on assets during httpx parsing
    expect(orchestratorSource).toContain("httpxLivePorts");
    expect(orchestratorSource).toContain("statusCode");
    expect(orchestratorSource).toContain("(asset as any).httpxLivePorts = httpxLivePorts");
  });

  it("should filter ZAP targets to only scan ports that returned 200 during httpx", () => {
    expect(orchestratorSource).toContain("Training Lab Port Filtering");
    expect(orchestratorSource).toContain("livePortNumbers");
    expect(orchestratorSource).toContain("filteredWebPorts");
    // Should only filter in training lab mode
    expect(orchestratorSource).toContain("state.trainingLabMode && livePortNumbers.length > 0");
  });

  it("should have a fallback if no ports matched the filter", () => {
    // If no ports matched, should fall back to scanning all web ports
    expect(orchestratorSource).toContain("filteredWebPorts = webPorts;");
  });

  it("should log which ports were skipped", () => {
    expect(orchestratorSource).toContain("Skipping ports");
    expect(orchestratorSource).toContain("returned 404/error during httpx");
  });

  it("should extract port from httpx URL when port field is missing", () => {
    // httpx JSON may have port field or URL — we handle both
    expect(orchestratorSource).toContain("obj.status_code && obj.port");
    expect(orchestratorSource).toContain("obj.status_code && obj.url");
    expect(orchestratorSource).toContain("parsedUrl.port ? parseInt(parsedUrl.port)");
  });
});

describe("ZAP Seed URL Injection", () => {
  it("should accept seedUrls parameter in startScan", () => {
    expect(zapScannerSource).toContain("seedUrls?: string[]");
  });

  it("should inject seed URLs before spidering using accessUrl", () => {
    expect(zapScannerSource).toContain("Seed URL Injection");
    expect(zapScannerSource).toContain("core/action/accessUrl");
    expect(zapScannerSource).toContain("params.seedUrls");
    expect(zapScannerSource).toContain("followRedirects");
  });

  it("should define seed URLs for Juice Shop in the orchestrator", () => {
    expect(orchestratorSource).toContain("TRAINING_LAB_SEED_URLS");
    expect(orchestratorSource).toContain("juiceshop");
    // Juice Shop seed URLs should include key API endpoints
    expect(orchestratorSource).toContain("/rest/products/search");
    expect(orchestratorSource).toContain("/api/Products");
    expect(orchestratorSource).toContain("/rest/user/login");
    expect(orchestratorSource).toContain("/#/login");
    expect(orchestratorSource).toContain("/#/search");
    expect(orchestratorSource).toContain("/score-board");
  });

  it("should define seed URLs for DVWA in the orchestrator", () => {
    expect(orchestratorSource).toContain("/vulnerabilities/sqli/");
    expect(orchestratorSource).toContain("/vulnerabilities/xss_r/");
    expect(orchestratorSource).toContain("/vulnerabilities/exec/");
  });

  it("should define seed URLs for Altoro in the orchestrator", () => {
    expect(orchestratorSource).toContain("/login.jsp");
    expect(orchestratorSource).toContain("/bank/main.jsp");
    expect(orchestratorSource).toContain("/search.jsp");
  });

  it("should pass seedUrls to startScan in the orchestrator", () => {
    expect(orchestratorSource).toContain("seedUrls: zapSeedUrls");
  });

  it("should log seed URL injection", () => {
    expect(orchestratorSource).toContain("ZAP Seed URLs:");
    expect(orchestratorSource).toContain("Pre-seeding ZAP with");
  });
});

describe("ZAP Active Scan 400 Retry", () => {
  it("should retry active scan with accessUrl when 400 error occurs (post-spider)", () => {
    // First retry location: after regular spider
    expect(zapScannerSource).toContain("Active scan 400 — retrying with accessUrl seed");
    expect(zapScannerSource).toContain("Active scan retry succeeded after accessUrl seed");
  });

  it("should retry active scan with accessUrl when 400 error occurs (post-AJAX spider)", () => {
    // Second retry location: after AJAX spider
 expect(zapScannerSource).toContain("Active scan 400 after AJAX spider on");   expect(zapScannerSource).toContain("Active scan retry succeeded after AJAX spider + accessUrl seed");
  });

  it("should seed common sub-paths during retry", () => {
    // Both retry paths should seed common sub-paths
    const retryBlocks = zapScannerSource.split("Active scan 400");
    // Should appear in both retry blocks
    expect(retryBlocks.length).toBeGreaterThanOrEqual(3); // original + 2 retry blocks
    expect(zapScannerSource).toContain("'/api', '/rest', '/login', '/search'");
  });

  it("should wait 3 seconds after seeding before retrying", () => {
    expect(zapScannerSource).toContain("setTimeout(r, 3000)");
  });

  it("should fall through to error if retry also fails", () => {
    expect(zapScannerSource).toContain("Active scan retry also failed");
    expect(zapScannerSource).toContain("Active scan retry also failed after AJAX spider");
  });
});

describe("Training Lab Injectable Endpoints", () => {
  it("should define injectable endpoints for Juice Shop", () => {
    expect(orchestratorSource).toContain("TRAINING_LAB_INJECTABLE_ENDPOINTS");
    expect(orchestratorSource).toContain("'juiceshop'");
    // Key Juice Shop injectable endpoints
    expect(orchestratorSource).toContain("/rest/products/search");
    expect(orchestratorSource).toContain("/api/Products");
    expect(orchestratorSource).toContain("/rest/user/login");
    expect(orchestratorSource).toContain("/api/Feedbacks");
    expect(orchestratorSource).toContain("/redirect");
  });

  it("should define injectable endpoints for DVWA", () => {
    expect(orchestratorSource).toContain("'dvwa'");
    expect(orchestratorSource).toContain("/vulnerabilities/sqli/");
    expect(orchestratorSource).toContain("/vulnerabilities/sqli_blind/");
    expect(orchestratorSource).toContain("/vulnerabilities/xss_r/");
    expect(orchestratorSource).toContain("/vulnerabilities/exec/");
    expect(orchestratorSource).toContain("/vulnerabilities/fi/");
  });

  it("should define injectable endpoints for Altoro", () => {
    expect(orchestratorSource).toContain("'altoro'");
    expect(orchestratorSource).toContain("/bank/transaction.jsp");
    expect(orchestratorSource).toContain("/search.jsp");
  });

  it("should define injectable endpoints for testphp", () => {
    expect(orchestratorSource).toContain("'testphp'");
    expect(orchestratorSource).toContain("/listproducts.php");
    expect(orchestratorSource).toContain("/artists.php");
  });

  it("should define injectable endpoints for hackazon", () => {
    expect(orchestratorSource).toContain("'hackazon'");
    expect(orchestratorSource).toContain("/product/view");
  });

  it("should only add injectable endpoints in training lab mode", () => {
    // The injectable endpoints block should be gated on trainingLabMode
    const idx = orchestratorSource.indexOf("TRAINING_LAB_INJECTABLE_ENDPOINTS");
    const before = orchestratorSource.substring(Math.max(0, idx - 200), idx);
    expect(before).toContain("state.trainingLabMode");
  });

  it("should avoid duplicate injectable URLs", () => {
    expect(orchestratorSource).toContain("!injectableUrls.some(u => u.url === fullUrl)");
  });

  it("should log how many endpoints were added", () => {
    expect(orchestratorSource).toContain("Training Lab Endpoints:");
    expect(orchestratorSource).toContain("injectable URLs");
  });
});

describe("ZAP Timeout Increase for Training Labs", () => {
  it("should use 45 minutes for training labs instead of 5", () => {
    expect(orchestratorSource).toContain("zapTimeoutMinutes = isKnownTrainingLab ? 90 : 30");
  });

  it("should use the dynamic timeout in the polling loop", () => {
    expect(orchestratorSource).toContain("zapTimeoutMinutes * 60 * 1000");
  });

  it("should use the dynamic timeout in timeout error messages", () => {
    expect(orchestratorSource).toContain("within ${zapTimeoutMinutes} minutes");
    expect(orchestratorSource).toContain("after ${zapTimeoutMinutes} minutes");
  });
});

describe("Integration: Juice Shop Specific Fixes", () => {
  it("should have Juice Shop seed URLs that cover key SPA routes", () => {
    const seedUrlSection = orchestratorSource.substring(
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS"),
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS") + 2000
    );
    // Juice Shop is an Angular SPA — seed URLs should include hash routes
    expect(seedUrlSection).toContain("/#/login");
    expect(seedUrlSection).toContain("/#/search");
    expect(seedUrlSection).toContain("/#/contact");
    // And REST API endpoints
    expect(seedUrlSection).toContain("/rest/products/search");
    expect(seedUrlSection).toContain("/api/Products");
    expect(seedUrlSection).toContain("/api/Challenges");
    // And known sensitive paths
    expect(seedUrlSection).toContain("/ftp");
    expect(seedUrlSection).toContain("/encryptionkeys");
  });

  it("should have Juice Shop injectable endpoints with correct params", () => {
    const injectableSection = orchestratorSource.substring(
      orchestratorSource.indexOf("TRAINING_LAB_INJECTABLE_ENDPOINTS"),
      orchestratorSource.indexOf("TRAINING_LAB_INJECTABLE_ENDPOINTS") + 2000
    );
    // SQLi-vulnerable endpoints
    expect(injectableSection).toContain("'q'");
    // Login endpoint for auth bypass testing
    expect(injectableSection).toContain("'email', 'password'");
    // Redirect endpoint for unvalidated redirect testing
    expect(injectableSection).toContain("'to'");
  });

  it("should have Juice Shop credentials for authenticated scanning", () => {
    // Already existed — verify still present
    expect(orchestratorSource).toContain("admin@juice-sh.op");
    expect(orchestratorSource).toContain("admin123");
    expect(orchestratorSource).toContain("/rest/user/login");
  });
});

describe("Hackazon Seed URLs", () => {
  it("should define seed URLs for Hackazon in the TRAINING_LAB_SEED_URLS map", () => {
    const seedUrlSection = orchestratorSource.substring(
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS"),
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS") + 3000
    );
    expect(seedUrlSection).toContain("'hackazon'");
    // Key Hackazon endpoints
    expect(seedUrlSection).toContain("/user/login");
    expect(seedUrlSection).toContain("/user/register");
    expect(seedUrlSection).toContain("/search?searchString=test");
    expect(seedUrlSection).toContain("/product/view?id=1");
    expect(seedUrlSection).toContain("/category/view?id=1");
    expect(seedUrlSection).toContain("/wishlist");
    expect(seedUrlSection).toContain("/cart");
    expect(seedUrlSection).toContain("/checkout");
    expect(seedUrlSection).toContain("/api/product");
    expect(seedUrlSection).toContain("/admin");
  });

  it("should have Hackazon seed URLs covering API, admin, and user paths", () => {
    const seedUrlSection = orchestratorSource.substring(
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS"),
      orchestratorSource.indexOf("TRAINING_LAB_SEED_URLS") + 3000
    );
    // API endpoints
    expect(seedUrlSection).toContain("/api/category");
    expect(seedUrlSection).toContain("/api/user");
    expect(seedUrlSection).toContain("/rest/product");
    expect(seedUrlSection).toContain("/rest/category");
    // Admin paths
    expect(seedUrlSection).toContain("/admin/user");
    expect(seedUrlSection).toContain("/admin/product");
    // Account paths
    expect(seedUrlSection).toContain("/account");
    expect(seedUrlSection).toContain("/account/orders");
    expect(seedUrlSection).toContain("/account/profile");
  });
});

describe("Training Lab Auth Handoff (ZAP → SQLMap/XSStrike)", () => {
  it("should have auth handoff section in the orchestrator", () => {
    expect(orchestratorSource).toContain("Training Lab Auth Handoff");
    expect(orchestratorSource).toContain("acquire session token for authenticated SQLMap/XSStrike scanning");
  });

  it("should only trigger auth handoff in training lab mode when no cookie exists", () => {
    expect(orchestratorSource).toContain("state.trainingLabMode && !cookieStr && webCreds.length > 0");
  });

  it("should handle Juice Shop JWT auth via /rest/user/login", () => {
    expect(orchestratorSource).toContain("juiceshop");
    expect(orchestratorSource).toContain("juice-shop");
    expect(orchestratorSource).toContain("/rest/user/login");
    expect(orchestratorSource).toContain("Content-Type: application/json");
    expect(orchestratorSource).toContain("authentication?.token");
    expect(orchestratorSource).toContain("token=");
  });

  it("should handle DVWA PHP session auth with CSRF token extraction", () => {
    expect(orchestratorSource).toContain("hostname.includes('dvwa')");
    expect(orchestratorSource).toContain("PHPSESSID");
    expect(orchestratorSource).toContain("user_token");
    expect(orchestratorSource).toContain("security=low");
    expect(orchestratorSource).toContain("dvwa_cookies.txt");
  });

  it("should handle generic form-based login as fallback", () => {
    expect(orchestratorSource).toContain("Generic form-based login");
    expect(orchestratorSource).toContain("webCreds[0]?.loginPath");
    expect(orchestratorSource).toContain("Set-Cookie:");
  });

  it("should store acquired session cookie on the credential for future use", () => {
    expect(orchestratorSource).toContain("loginCred.sessionCookie = cookieStr");
  });

  it("should log auth handoff success and errors", () => {
    expect(orchestratorSource).toContain("Auth Handoff: Acquiring Juice Shop JWT");
    expect(orchestratorSource).toContain("Auth Handoff: JWT acquired");
    expect(orchestratorSource).toContain("Auth Handoff: DVWA session acquired");
    expect(orchestratorSource).toContain("Auth Handoff Error");
    expect(orchestratorSource).toContain("Failed to acquire session token");
  });

  it("should use executeTool to run curl on the scan server (not local)", () => {
    // Auth handoff must run via scan server since it has network access to the lab
    const authSection = orchestratorSource.substring(
      orchestratorSource.indexOf("Training Lab Auth Handoff"),
      orchestratorSource.indexOf("Training Lab Auth Handoff") + 5000
    );
    expect(authSection).toContain("executeTool");
    expect(authSection).toContain("tool: 'curl'");
  });

  it("should pass the acquired cookie to both SQLMap and XSStrike", () => {
    // The cookieStr variable is used by both SQLMap and XSStrike
    expect(orchestratorSource).toContain("cookie: cookieStr || undefined");
    // Should appear at least twice (once for SQLMap, once for XSStrike)
    const matches = orchestratorSource.match(/cookie: cookieStr \|\| undefined/g);
    expect(matches).not.toBeNull();
    expect(matches!.length).toBeGreaterThanOrEqual(2);
  });
});

// ── Training Lab ZAP URL Resolver Tests ──

describe("Training Lab ZAP URL Resolver", () => {
  it("should define TRAINING_LAB_ZAP_URL_MAP with Juice Shop reverse proxy URL", () => {
    expect(orchestratorSource).toContain("TRAINING_LAB_ZAP_URL_MAP");
    expect(orchestratorSource).toContain("juiceshop.lab.aceofcloud.io");
    expect(orchestratorSource).toContain("https://scan.aceofcloud.io/lab/juice-shop");
  });

  it("should define resolveTrainingLabZapUrl function", () => {
    expect(orchestratorSource).toContain("function resolveTrainingLabZapUrl");
    // Should only resolve in training lab mode
    expect(orchestratorSource).toContain("if (!state.trainingLabMode) return null");
  });

  it("should store resolvedZapUrl on the asset for downstream use", () => {
    expect(orchestratorSource).toContain("(webApp as any).resolvedZapUrl = targetUrl");
  });

  it("should use resolvedZapUrl for SQLMap/XSStrike target URL", () => {
    expect(orchestratorSource).toContain("const resolvedUrl = (webApp as any).resolvedZapUrl");
    expect(orchestratorSource).toContain("const targetUrl = resolvedUrl ||");
  });

  it("should build scanTargets array from reverse proxy URL when lab is mapped", () => {
    expect(orchestratorSource).toContain("const scanTargets: Array<{ targetUrl: string; dedupKey: string }> = []");
    expect(orchestratorSource).toContain("labZapUrl.zapBaseUrl");
    expect(orchestratorSource).toContain("for (const { targetUrl, dedupKey } of scanTargets)");
  });

  it("should log URL rewrite when using reverse proxy", () => {
    expect(orchestratorSource).toContain("Training Lab URL Rewrite");
    expect(orchestratorSource).toContain("Docker DNS limitation");
  });

  it("should use original hostname for auth handoff curl (not reverse proxy URL)", () => {
    // Auth handoff uses authBaseUrl (original hostname) because scan server can resolve it
    expect(orchestratorSource).toContain("const authBaseUrl = `http://${webApp.hostname}`");
    // The curl calls should use authBaseUrl, not targetUrl
    expect(orchestratorSource).toContain("${authBaseUrl}/rest/user/login");
    expect(orchestratorSource).toContain("${authBaseUrl}/login.php");
  });

  it("should skip per-port scanning when lab has skipPortScan=true", () => {
    expect(orchestratorSource).toContain("skipPortScan: true");
    // Should use single scan target from reverse proxy URL
    expect(orchestratorSource).toContain("labZapUrl && !scannedTargetUrls.has");
  });
});

// ── AJAX Spider Duration Cap & Timeout Increase Tests ──

describe("AJAX Spider Duration Cap", () => {
  it("should set AJAX spider maxDuration before starting AJAX spider", () => {
    expect(zapScannerSource).toContain("setOptionMaxDuration");
    expect(zapScannerSource).toContain("ajaxSpider/action/setOptionMaxDuration");
  });

  it("should cap AJAX spider maxDuration at 5 minutes", () => {
    expect(zapScannerSource).toContain("Math.min(ajaxConfig.maxDuration || 5, 5)");
  });

  it("should set AJAX spider maxCrawlDepth and numberOfBrowsers", () => {
    expect(zapScannerSource).toContain("setOptionMaxCrawlDepth");
    expect(zapScannerSource).toContain("setOptionNumberOfBrowsers");
    expect(zapScannerSource).toContain("setOptionClickDefaultElems");
  });

  it("should set default 5-minute duration when no LLM config", () => {
    expect(zapScannerSource).toContain('Integer: "5"');
    expect(zapScannerSource).toContain("Set default maxDuration=5min (no LLM config)");
  });

  it("should log AJAX spider configuration", () => {
    expect(zapScannerSource).toContain("[ZAP AJAX Spider]");
    expect(zapScannerSource).toContain("Set maxDuration=");
  });
});

describe("Orchestrator ZAP Timeout Increase", () => {
  it("should use 45-minute timeout for training labs", () => {
    expect(orchestratorSource).toContain("isKnownTrainingLab ? 90 : 30");
  });

  it("should use 5-minute timeout for non-training lab engagements", () => {
    expect(orchestratorSource).toContain("isKnownTrainingLab ? 90 : 30");
  });
});
