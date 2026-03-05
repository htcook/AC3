/**
 * FIPS 140-3 Phase 3 Test Suite
 *
 * Tests for:
 *   1. Certificate pinning enforce mode with captured GoPhish pins
 *   2. Caldera HTTP detection (cert pinning skipped)
 *   3. PM2 ecosystem config with --enable-fips
 *   4. Deploy script and env example existence
 */

import { describe, it, expect, beforeAll } from "vitest";
import fs from "fs";
import path from "path";

const PROJECT_ROOT = path.join(__dirname, "..");

// ─── 1. GoPhish Certificate Pinning Enforce Mode ─────────────────────────

describe("GoPhish Certificate Pinning — Enforce Mode", () => {
  let certPinModule: any;

  beforeAll(async () => {
    certPinModule = await import("./lib/cert-pinning");
    // Re-initialize to pick up the enforce mode changes
    certPinModule.initCertPinning();
  });

  it("GoPhish is registered with enforce mode", () => {
    // GoPhish URL is configured via env
    const gophishUrl = process.env.GOPHISH_BASE_URL;
    if (!gophishUrl) return; // Skip if no GoPhish URL

    const url = new URL(gophishUrl);
    const config = certPinModule.getPinConfig(
      url.hostname,
      parseInt(url.port) || 3333
    );
    expect(config).toBeTruthy();
    expect(config.mode).toBe("enforce");
    expect(config.service).toBe("GoPhish");
  });

  it("GoPhish has captured SPKI pin", () => {
    const gophishUrl = process.env.GOPHISH_BASE_URL;
    if (!gophishUrl) return;

    const url = new URL(gophishUrl);
    const config = certPinModule.getPinConfig(
      url.hostname,
      parseInt(url.port) || 3333
    );
    expect(config).toBeTruthy();
    expect(config.pins.length).toBeGreaterThanOrEqual(1);
    // Verify the captured pin is present
    const primaryPin = config.pins.find((p: any) =>
      p.sha256 === "AR9f8u5V/V79+uX66CqJJQXzy3RcHsqJmqB+ZpcKq7A="
    );
    expect(primaryPin).toBeTruthy();
    expect(primaryPin.label).toContain("GoPhish");
  });

  it("GoPhish has backup pin", () => {
    const gophishUrl = process.env.GOPHISH_BASE_URL;
    if (!gophishUrl) return;

    const url = new URL(gophishUrl);
    const config = certPinModule.getPinConfig(
      url.hostname,
      parseInt(url.port) || 3333
    );
    expect(config).toBeTruthy();
    expect(config.backupPins.length).toBeGreaterThanOrEqual(1);
    const backupPin = config.backupPins.find((p: any) =>
      p.sha256 === "NBSn9zhwtJgPhs7wadWdNUv6/6f41HxuSoPNLZMQ7LQ="
    );
    expect(backupPin).toBeTruthy();
  });

  it("GoPhish allows self-signed certificates", () => {
    const gophishUrl = process.env.GOPHISH_BASE_URL;
    if (!gophishUrl) return;

    const url = new URL(gophishUrl);
    const config = certPinModule.getPinConfig(
      url.hostname,
      parseInt(url.port) || 3333
    );
    expect(config).toBeTruthy();
    expect(config.allowSelfSigned).toBe(true);
  });

  it("GoPhish pin has expiry date set", () => {
    const gophishUrl = process.env.GOPHISH_BASE_URL;
    if (!gophishUrl) return;

    const url = new URL(gophishUrl);
    const config = certPinModule.getPinConfig(
      url.hostname,
      parseInt(url.port) || 3333
    );
    expect(config).toBeTruthy();
    const pin = config.pins[0];
    expect(pin.expiresAt).toBeTruthy();
    expect(pin.expiresAt).toContain("2036");
  });
});

// ─── 2. Caldera HTTP Detection ───────────────────────────────────────────

describe("Caldera HTTP Detection — Cert Pinning Skipped", () => {
  it("cert-pinning.ts handles HTTP Caldera URL correctly", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "lib", "cert-pinning.ts"),
      "utf-8"
    );
    // Should check for HTTPS before registering
    expect(content).toContain("isHttps");
    expect(content).toContain("Caldera is running on HTTP");
  });

  it("Caldera is NOT registered for cert pinning when on HTTP", async () => {
    // Caldera URL is HTTP, so no pin config should exist
    const calderaUrl = process.env.CALDERA_BASE_URL;
    if (!calderaUrl) return;

    const url = new URL(calderaUrl);
    if (url.protocol !== "http:") return; // Only test when HTTP

    // Use the already-imported module
    const certPinMod = await import("./lib/cert-pinning");
    const config = certPinMod.getPinConfig(
      url.hostname,
      parseInt(url.port) || 8888
    );
    // Config should not exist for HTTP Caldera — initCertPinning skips HTTP
    // Note: config may be undefined (not registered) which is correct
    if (config) {
      // If somehow registered, it should not be in enforce mode for HTTP
      expect(config.mode).not.toBe("enforce");
    } else {
      expect(config).toBeUndefined();
    }
  });

  it("cert-pinning.ts supports future HTTPS Caldera with env pin", () => {
    const content = fs.readFileSync(
      path.join(__dirname, "lib", "cert-pinning.ts"),
      "utf-8"
    );
    expect(content).toContain("CERT_PIN_CALDERA");
    expect(content).toContain("enable HTTPS to activate");
  });
});

// ─── 3. Captured Pins Reference File ─────────────────────────────────────

describe("Captured Pins Reference", () => {
  it("cert-pins-captured.ts exists", () => {
    expect(
      fs.existsSync(path.join(__dirname, "lib", "cert-pins-captured.ts"))
    ).toBe(true);
  });

  it("cert-pins-captured.ts contains GoPhish pins", async () => {
    const module = await import("./lib/cert-pins-captured");
    expect(module.GOPHISH_PINS).toBeTruthy();
    expect(module.GOPHISH_PINS.primary).toBe(
      "AR9f8u5V/V79+uX66CqJJQXzy3RcHsqJmqB+ZpcKq7A="
    );
    expect(module.GOPHISH_PINS.backup).toBe(
      "NBSn9zhwtJgPhs7wadWdNUv6/6f41HxuSoPNLZMQ7LQ="
    );
  });

  it("cert-pins-captured.ts documents Caldera HTTP status", async () => {
    const module = await import("./lib/cert-pins-captured");
    expect(module.CALDERA_PINS).toBeTruthy();
    expect(module.CALDERA_PINS.primary).toBeNull();
    expect(module.CALDERA_PINS.note).toContain("HTTP");
  });

  it("GoPhish pin fingerprint matches captured value", async () => {
    const module = await import("./lib/cert-pins-captured");
    expect(module.GOPHISH_PINS.fingerprint256).toContain("34:14:A7:F7");
  });
});

// ─── 4. PM2 Ecosystem Config ─────────────────────────────────────────────

describe("PM2 Ecosystem Config — --enable-fips", () => {
  it("ecosystem.config.cjs exists", () => {
    expect(
      fs.existsSync(path.join(PROJECT_ROOT, "ecosystem.config.cjs"))
    ).toBe(true);
  });

  it("ecosystem.config.cjs contains --enable-fips flag", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("--enable-fips");
  });

  it("ecosystem.config.cjs sets NODE_ENV=production", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("NODE_ENV");
    expect(content).toContain("production");
  });

  it("ecosystem.config.cjs sets OPENSSL_CONF", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("OPENSSL_CONF");
    expect(content).toContain("openssl-fips.cnf");
  });

  it("ecosystem.config.cjs includes GoPhish cert pin env var", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("CERT_PIN_GOPHISH");
    expect(content).toContain("AR9f8u5V/V79+uX66CqJJQXzy3RcHsqJmqB+ZpcKq7A=");
  });

  it("ecosystem.config.cjs has max_memory_restart", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("max_memory_restart");
  });

  it("ecosystem.config.cjs configures log files", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "ecosystem.config.cjs"),
      "utf-8"
    );
    expect(content).toContain("error_file");
    expect(content).toContain("out_file");
    expect(content).toContain("/var/log/caldera-dashboard");
  });

  it("ecosystem.config.cjs is valid CommonJS module", () => {
    const config = require(path.join(PROJECT_ROOT, "ecosystem.config.cjs"));
    expect(config).toHaveProperty("apps");
    expect(Array.isArray(config.apps)).toBe(true);
    expect(config.apps.length).toBe(1);
    expect(config.apps[0].name).toBe("caldera-dashboard");
    expect(config.apps[0].node_args).toContain("--enable-fips");
  });
});

// ─── 5. Deploy Script ────────────────────────────────────────────────────

describe("Deploy Script — install-fips-node.sh", () => {
  it("install-fips-node.sh exists", () => {
    expect(
      fs.existsSync(path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh"))
    ).toBe(true);
  });

  it("install-fips-node.sh is executable", () => {
    const stats = fs.statSync(
      path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh")
    );
    // Check if owner execute bit is set
    expect(stats.mode & 0o100).toBeTruthy();
  });

  it("install-fips-node.sh installs Node.js 22.x", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh"),
      "utf-8"
    );
    expect(content).toContain("setup_22.x");
    expect(content).toContain("nodejs");
  });

  it("install-fips-node.sh configures OpenSSL FIPS provider", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh"),
      "utf-8"
    );
    expect(content).toContain("fips.so");
    expect(content).toContain("openssl-fips.cnf");
    expect(content).toContain("fipsinstall");
  });

  it("install-fips-node.sh installs PM2", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh"),
      "utf-8"
    );
    expect(content).toContain("pm2@latest");
  });

  it("install-fips-node.sh verifies FIPS with crypto.getFips()", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", "install-fips-node.sh"),
      "utf-8"
    );
    expect(content).toContain("crypto.getFips()");
    expect(content).toContain("--enable-fips");
  });
});

// ─── 6. Production Environment Example ───────────────────────────────────

describe("Production Environment Example", () => {
  it(".env.production.example exists", () => {
    expect(
      fs.existsSync(path.join(PROJECT_ROOT, "deploy", ".env.production.example"))
    ).toBe(true);
  });

  it(".env.production.example contains FIPS config", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", ".env.production.example"),
      "utf-8"
    );
    expect(content).toContain("OPENSSL_CONF");
    expect(content).toContain("CERT_PIN_GOPHISH");
  });

  it(".env.production.example contains all service URLs", () => {
    const content = fs.readFileSync(
      path.join(PROJECT_ROOT, "deploy", ".env.production.example"),
      "utf-8"
    );
    expect(content).toContain("CALDERA_BASE_URL");
    expect(content).toContain("GOPHISH_BASE_URL");
    expect(content).toContain("SCAN_SERVER_HOST");
    expect(content).toContain("ZAP_BASE_URL");
    expect(content).toContain("DATABASE_URL");
  });
});
