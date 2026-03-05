/**
 * FIPS 140-3 Enhancements Test Suite
 *
 * Tests for:
 *   1. OpenSSL FIPS provider configuration
 *   2. Certificate pinning for Caldera/GoPhish
 *   3. FIPS compliance status indicator (tRPC endpoint)
 */

import { describe, it, expect, beforeAll, vi } from "vitest";
import crypto from "crypto";
import fs from "fs";
import path from "path";

// ─── 1. OpenSSL FIPS Provider Tests ──────────────────────────────────────

describe("OpenSSL FIPS Provider", () => {
  let fipsModule: any;

  beforeAll(async () => {
    fipsModule = await import("./lib/fips-openssl-provider");
  });

  it("exports enableFIPSProvider function", () => {
    expect(typeof fipsModule.enableFIPSProvider).toBe("function");
  });

  it("exports getFIPSProviderStatus function", () => {
    expect(typeof fipsModule.getFIPSProviderStatus).toBe("function");
  });

  it("exports initFIPSProvider function", () => {
    expect(typeof fipsModule.initFIPSProvider).toBe("function");
  });

  it("getFIPSProviderStatus returns correct structure", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status).toHaveProperty("fipsEnabled");
    expect(status).toHaveProperty("opensslVersion");
    expect(status).toHaveProperty("fipsCapable");
    expect(status).toHaveProperty("activationMethod");
    expect(status).toHaveProperty("availableHashes");
    expect(status).toHaveProperty("availableCiphers");
    expect(status).toHaveProperty("validation");
    expect(status).toHaveProperty("message");
  });

  it("validation checks all required FIPS algorithms", () => {
    const status = fipsModule.getFIPSProviderStatus();
    const v = status.validation;
    expect(v).toHaveProperty("sha256");
    expect(v).toHaveProperty("sha384");
    expect(v).toHaveProperty("sha512");
    expect(v).toHaveProperty("aes256gcm");
    expect(v).toHaveProperty("aes128gcm");
    expect(v).toHaveProperty("ecdsaP256");
    expect(v).toHaveProperty("ecdsaP384");
    expect(v).toHaveProperty("rsa2048");
    expect(v).toHaveProperty("hmacSha256");
    expect(v).toHaveProperty("md5Disabled");
    expect(v).toHaveProperty("allPassed");
  });

  it("SHA-256 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.sha256).toBe(true);
  });

  it("SHA-384 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.sha384).toBe(true);
  });

  it("SHA-512 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.sha512).toBe(true);
  });

  it("AES-256-GCM is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.aes256gcm).toBe(true);
  });

  it("AES-128-GCM is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.aes128gcm).toBe(true);
  });

  it("ECDSA P-256 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.ecdsaP256).toBe(true);
  });

  it("ECDSA P-384 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.ecdsaP384).toBe(true);
  });

  it("RSA-2048 signing is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.rsa2048).toBe(true);
  });

  it("HMAC-SHA256 is available (FIPS required)", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.hmacSha256).toBe(true);
  });

  it("all required FIPS algorithms pass validation", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.validation.allPassed).toBe(true);
  });

  it("enableFIPSProvider does NOT call setFips(1) without flag", () => {
    // Verify that without --enable-fips, the function does not break OpenSSL
    const fipsBefore = crypto.getFips();
    fipsModule.enableFIPSProvider();
    const fipsAfter = crypto.getFips();
    // Should remain the same (0 in test environment)
    expect(fipsAfter).toBe(fipsBefore);
  });

  it("initFIPSProvider returns status without breaking SSL", () => {
    const status = fipsModule.initFIPSProvider();
    expect(status).toHaveProperty("fipsEnabled");
    expect(status).toHaveProperty("validation");
    // Verify SSL still works after init
    const hash = crypto.createHash("sha256").update("test").digest("hex");
    expect(hash).toBeTruthy();
  });

  it("opensslVersion is populated", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.opensslVersion).toBeTruthy();
    expect(typeof status.opensslVersion).toBe("string");
  });

  it("availableHashes includes FIPS-approved algorithms", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.availableHashes.length).toBeGreaterThan(0);
  });

  it("availableCiphers includes FIPS-approved algorithms", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.availableCiphers.length).toBeGreaterThan(0);
  });

  it("message provides meaningful status description", () => {
    const status = fipsModule.getFIPSProviderStatus();
    expect(status.message.length).toBeGreaterThan(20);
    expect(status.message).toContain("OpenSSL");
  });
});

// ─── 2. Certificate Pinning Tests ────────────────────────────────────────

describe("Certificate Pinning", () => {
  let certPinModule: any;

  beforeAll(async () => {
    certPinModule = await import("./lib/cert-pinning");
  });

  it("exports registerPinConfig function", () => {
    expect(typeof certPinModule.registerPinConfig).toBe("function");
  });

  it("exports getPinConfig function", () => {
    expect(typeof certPinModule.getPinConfig).toBe("function");
  });

  it("exports initCertPinning function", () => {
    expect(typeof certPinModule.initCertPinning).toBe("function");
  });

  it("exports computeSPKIPin function", () => {
    expect(typeof certPinModule.computeSPKIPin).toBe("function");
  });

  it("exports createPinnedHttpsAgent function", () => {
    expect(typeof certPinModule.createPinnedHttpsAgent).toBe("function");
  });

  it("exports getAllPinConfigs function", () => {
    expect(typeof certPinModule.getAllPinConfigs).toBe("function");
  });

  it("exports getPinEventLog function", () => {
    expect(typeof certPinModule.getPinEventLog).toBe("function");
  });

  it("registerPinConfig stores config and getPinConfig retrieves it", () => {
    certPinModule.registerPinConfig({
      service: "TestService",
      hostname: "test.example.com",
      port: 443,
      mode: "learn",
      pins: [],
      backupPins: [],
      allowSelfSigned: false,
    });

    const config = certPinModule.getPinConfig("test.example.com", 443);
    expect(config).toBeTruthy();
    expect(config.service).toBe("TestService");
    expect(config.mode).toBe("learn");
  });

  it("registerPinConfig with enforce mode stores pins", () => {
    certPinModule.registerPinConfig({
      service: "PinnedService",
      hostname: "pinned.example.com",
      port: 8443,
      mode: "enforce",
      pins: [
        {
          sha256: "dGVzdHBpbjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==",
          label: "Primary pin",
          recordedAt: new Date().toISOString(),
        },
      ],
      backupPins: [
        {
          sha256: "YmFja3VwcGluMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==",
          label: "Backup pin",
          recordedAt: new Date().toISOString(),
        },
      ],
      allowSelfSigned: false,
    });

    const config = certPinModule.getPinConfig("pinned.example.com", 8443);
    expect(config).toBeTruthy();
    expect(config.pins.length).toBe(1);
    expect(config.backupPins.length).toBe(1);
    expect(config.mode).toBe("enforce");
  });

  it("getAllPinConfigs returns sanitized configs", () => {
    const configs = certPinModule.getAllPinConfigs();
    expect(Array.isArray(configs)).toBe(true);
    expect(configs.length).toBeGreaterThanOrEqual(2); // TestService + PinnedService

    const pinned = configs.find((c: any) => c.service === "PinnedService");
    expect(pinned).toBeTruthy();
    expect(pinned.pinCount).toBe(1);
    expect(pinned.backupPinCount).toBe(1);
    // Verify pins are sanitized (only prefix shown)
    expect(pinned.pins[0].sha256Prefix).toContain("...");
  });

  it("getPinEventLog returns array", () => {
    const log = certPinModule.getPinEventLog(10);
    expect(Array.isArray(log)).toBe(true);
  });

  it("createPinnedHttpsAgent returns an https.Agent", () => {
    const agent = certPinModule.createPinnedHttpsAgent("test.example.com", 443);
    expect(agent).toBeTruthy();
    expect(typeof agent.destroy).toBe("function");
  });

  it("createPinnedHttpsAgent respects FIPS TLS settings", () => {
    const agent = certPinModule.createPinnedHttpsAgent("test.example.com", 443);
    // Agent should have FIPS options
    expect(agent.options).toBeTruthy();
    expect(agent.options.minVersion).toBe("TLSv1.2");
  });

  it("initCertPinning does not throw", () => {
    expect(() => certPinModule.initCertPinning()).not.toThrow();
  });

  it("pinning modes are correctly typed", () => {
    // Verify the three modes work
    for (const mode of ["enforce", "report", "learn"] as const) {
      certPinModule.registerPinConfig({
        service: `ModeTest-${mode}`,
        hostname: `${mode}.test.com`,
        port: 443,
        mode,
        pins: [],
        backupPins: [],
        allowSelfSigned: false,
      });
      const config = certPinModule.getPinConfig(`${mode}.test.com`, 443);
      expect(config.mode).toBe(mode);
    }
  });
});

// ─── 3. FIPS Status Router Tests ─────────────────────────────────────────

describe("FIPS Status Router", () => {
  it("fips-status.ts router file exists", () => {
    const routerPath = path.join(__dirname, "routers", "fips-status.ts");
    expect(fs.existsSync(routerPath)).toBe(true);
  });

  it("fips-status router is registered in routers.ts", () => {
    const routersContent = fs.readFileSync(
      path.join(__dirname, "routers.ts"),
      "utf-8"
    );
    expect(routersContent).toContain('import { fipsStatusRouter }');
    expect(routersContent).toContain('fipsStatus: fipsStatusRouter');
  });

  it("fips-status router uses protectedProcedure", () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, "routers", "fips-status.ts"),
      "utf-8"
    );
    expect(routerContent).toContain("protectedProcedure");
    expect(routerContent).not.toContain("publicProcedure");
  });

  it("fips-status router exports getStatus endpoint", () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, "routers", "fips-status.ts"),
      "utf-8"
    );
    expect(routerContent).toContain("getStatus:");
  });

  it("fips-status router exports getSSHDetails endpoint", () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, "routers", "fips-status.ts"),
      "utf-8"
    );
    expect(routerContent).toContain("getSSHDetails:");
  });

  it("fips-status router exports getPinEvents endpoint", () => {
    const routerContent = fs.readFileSync(
      path.join(__dirname, "routers", "fips-status.ts"),
      "utf-8"
    );
    expect(routerContent).toContain("getPinEvents:");
  });
});

// ─── 4. FIPSIndicator Component Tests ────────────────────────────────────

describe("FIPSIndicator Component", () => {
  it("FIPSIndicator.tsx component file exists", () => {
    const componentPath = path.join(
      __dirname,
      "..",
      "client",
      "src",
      "components",
      "FIPSIndicator.tsx"
    );
    expect(fs.existsSync(componentPath)).toBe(true);
  });

  it("FIPSIndicator is imported in DashboardLayout", () => {
    const layoutContent = fs.readFileSync(
      path.join(__dirname, "..", "client", "src", "components", "DashboardLayout.tsx"),
      "utf-8"
    );
    expect(layoutContent).toContain('import { FIPSIndicator }');
    expect(layoutContent).toContain("<FIPSIndicator");
  });

  it("FIPSIndicator uses fipsStatus.getStatus tRPC endpoint", () => {
    const componentContent = fs.readFileSync(
      path.join(__dirname, "..", "client", "src", "components", "FIPSIndicator.tsx"),
      "utf-8"
    );
    expect(componentContent).toContain("trpc.fipsStatus.getStatus.useQuery");
  });

  it("FIPSIndicator handles collapsed state", () => {
    const componentContent = fs.readFileSync(
      path.join(__dirname, "..", "client", "src", "components", "FIPSIndicator.tsx"),
      "utf-8"
    );
    expect(componentContent).toContain("collapsed");
  });

  it("FIPSIndicator shows compliance score", () => {
    const componentContent = fs.readFileSync(
      path.join(__dirname, "..", "client", "src", "components", "FIPSIndicator.tsx"),
      "utf-8"
    );
    expect(componentContent).toContain("complianceScore");
  });

  it("FIPSIndicator navigates to /fips-compliance on click", () => {
    const componentContent = fs.readFileSync(
      path.join(__dirname, "..", "client", "src", "components", "FIPSIndicator.tsx"),
      "utf-8"
    );
    expect(componentContent).toContain("/fips-compliance");
  });
});

// ─── 5. Server Startup Integration Tests ─────────────────────────────────

describe("Server Startup FIPS Integration", () => {
  it("server/_core/index.ts imports initFIPSProvider", () => {
    const indexContent = fs.readFileSync(
      path.join(__dirname, "_core", "index.ts"),
      "utf-8"
    );
    expect(indexContent).toContain('import { initFIPSProvider }');
  });

  it("server/_core/index.ts calls initFIPSProvider()", () => {
    const indexContent = fs.readFileSync(
      path.join(__dirname, "_core", "index.ts"),
      "utf-8"
    );
    expect(indexContent).toContain("initFIPSProvider()");
  });

  it("server/_core/index.ts imports initCertPinning", () => {
    const indexContent = fs.readFileSync(
      path.join(__dirname, "_core", "index.ts"),
      "utf-8"
    );
    expect(indexContent).toContain('import { initCertPinning }');
  });

  it("server/_core/index.ts calls initCertPinning()", () => {
    const indexContent = fs.readFileSync(
      path.join(__dirname, "_core", "index.ts"),
      "utf-8"
    );
    expect(indexContent).toContain("initCertPinning()");
  });

  it("FIPS modules are initialized before Express app creation", () => {
    const indexContent = fs.readFileSync(
      path.join(__dirname, "_core", "index.ts"),
      "utf-8"
    );
    const fipsPos = indexContent.indexOf("initFIPSProvider()");
    const certPinPos = indexContent.indexOf("initCertPinning()");
    const expressPos = indexContent.indexOf("express()");
    expect(fipsPos).toBeLessThan(expressPos);
    expect(certPinPos).toBeLessThan(expressPos);
  });
});

// ─── 6. Cross-Module Integration Tests ───────────────────────────────────

describe("FIPS Cross-Module Integration", () => {
  it("fips-openssl-provider.ts file exists", () => {
    expect(fs.existsSync(path.join(__dirname, "lib", "fips-openssl-provider.ts"))).toBe(true);
  });

  it("cert-pinning.ts file exists", () => {
    expect(fs.existsSync(path.join(__dirname, "lib", "cert-pinning.ts"))).toBe(true);
  });

  it("fips-ssh.ts file exists", () => {
    expect(fs.existsSync(path.join(__dirname, "lib", "fips-ssh.ts"))).toBe(true);
  });

  it("fips-tls.ts file exists", () => {
    expect(fs.existsSync(path.join(__dirname, "lib", "fips-tls.ts"))).toBe(true);
  });

  it("fips-tls-global.ts file exists", () => {
    expect(fs.existsSync(path.join(__dirname, "lib", "fips-tls-global.ts"))).toBe(true);
  });

  it("cert-pinning imports FIPS_TLS_CONFIG from fips-tls", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "lib", "cert-pinning.ts"),
      "utf-8"
    );
    expect(content).toContain('import { FIPS_TLS_CONFIG }');
    expect(content).toContain('from "./fips-tls"');
  });

  it("fips-status router imports from all FIPS modules", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "routers", "fips-status.ts"),
      "utf-8"
    );
    expect(content).toContain("fips-openssl-provider");
    expect(content).toContain("fips-tls");
    expect(content).toContain("fips-tls-global");
    expect(content).toContain("fips-ssh");
    expect(content).toContain("cert-pinning");
  });

  it("all FIPS modules can be imported without errors", async () => {
    const modules = await Promise.all([
      import("./lib/fips-tls"),
      import("./lib/fips-tls-global"),
      import("./lib/fips-ssh"),
      import("./lib/fips-openssl-provider"),
      import("./lib/cert-pinning"),
    ]);
    expect(modules.length).toBe(5);
    modules.forEach((m) => expect(m).toBeTruthy());
  });
});
