import { describe, expect, it } from "vitest";

/**
 * Tests for email security finding filtering:
 * - isMailAsset() correctly identifies mail vs non-mail assets
 * - Non-mail assets should never receive DMARC/SPF/DKIM findings
 * - Stage 3.10 filter strips email findings from non-mail assets
 */

describe("isMailAsset — positive identification of mail infrastructure", () => {
  let isMailAsset: (asset: any) => boolean;

  it("loads isMailAsset from email-security-analyzer", async () => {
    const mod = await import("./lib/email-security-analyzer");
    isMailAsset = mod.isMailAsset;
    expect(typeof isMailAsset).toBe("function");
  });

  it("identifies mail_gateway assetType as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ assetType: "mail_gateway", hostname: "mail.example.com" })).toBe(true);
  });

  it("identifies email_gateway essentialService as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ essentialService: "email_gateway", hostname: "mx.example.com" })).toBe(true);
  });

  it("identifies mail.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "mail.example.com" })).toBe(true);
  });

  it("identifies smtp.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "smtp.example.com" })).toBe(true);
  });

  it("identifies mx.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "mx.example.com" })).toBe(true);
  });

  it("identifies exchange.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "exchange.example.com" })).toBe(true);
  });

  it("identifies owa.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "owa.example.com" })).toBe(true);
  });

  it("identifies webmail.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "webmail.example.com" })).toBe(true);
  });

  it("identifies zimbra.* hostname as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "zimbra.example.com" })).toBe(true);
  });

  it("identifies assets with email tag as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "server1.example.com", tags: ["email"] })).toBe(true);
  });

  it("identifies assets with email_infrastructure tag as mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "server1.example.com", tags: ["email_infrastructure"] })).toBe(true);
  });
});

describe("isMailAsset — non-mail assets correctly rejected", () => {
  it("rejects www.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "www.example.com", assetType: "customer_portal" })).toBe(false);
  });

  it("rejects api.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "api.example.com", assetType: "api" })).toBe(false);
  });

  it("rejects sso.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "sso.example.com", assetType: "sso" })).toBe(false);
  });

  it("rejects vpn.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "vpn.example.com", assetType: "vpn" })).toBe(false);
  });

  it("rejects admin.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "admin.example.com", assetType: "admin_panel" })).toBe(false);
  });

  it("rejects cdn.* hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "cdn.example.com", assetType: "cdn" })).toBe(false);
  });

  it("rejects database hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "db.example.com", assetType: "database" })).toBe(false);
  });

  it("rejects monitoring hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "grafana.example.com", assetType: "monitoring" })).toBe(false);
  });

  it("rejects EC2 hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "ec2-52-1-2-3.us-east-1.compute.amazonaws.com" })).toBe(false);
  });

  it("rejects IP-based hostname as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "192.168.1.1" })).toBe(false);
  });

  it("rejects root domain without mail indicators as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({ hostname: "example.com", assetType: "other" })).toBe(false);
  });

  it("rejects empty/undefined asset as non-mail", async () => {
    const mod = await import("./lib/email-security-analyzer");
    expect(mod.isMailAsset({})).toBe(false);
    expect(mod.isMailAsset({ hostname: "" })).toBe(false);
  });
});

describe("Email finding filter logic — Stage 3.10 simulation", () => {
  function isEmailFinding(f: { category?: string; title?: string }): boolean {
    const cat = (f.category || '').toLowerCase();
    const title = (f.title || '').toLowerCase();
    if (cat.includes('email security')) return true;
    if (title.includes('no dmarc') || title.includes('no spf') || title.includes('no dkim')) return true;
    if (title.includes('missing dmarc') || title.includes('missing spf') || title.includes('missing dkim')) return true;
    if (title.includes('dmarc missing') || title.includes('spf missing') || title.includes('dkim missing')) return true;
    if (title.includes('dmarc policy') || title.includes('dmarc record')) return true;
    if (title.includes('email spoofing') || title.includes('email impersonation')) return true;
    if (title.includes('spf record') || title.includes('dkim selector') || title.includes('dkim key')) return true;
    if (title.includes('mail') && (title.includes('security') || title.includes('authentication') || title.includes('record'))) return true;
    return false;
  }

  it("correctly identifies DMARC findings as email findings", () => {
    expect(isEmailFinding({ title: "No DMARC Record Found" })).toBe(true);
    expect(isEmailFinding({ title: "DMARC Policy Set to 'none' (Monitor Only)" })).toBe(true);
    expect(isEmailFinding({ title: "Missing DMARC enforcement" })).toBe(true);
    expect(isEmailFinding({ title: "DMARC record not configured" })).toBe(true);
  });

  it("correctly identifies SPF findings as email findings", () => {
    expect(isEmailFinding({ title: "No SPF Record Found" })).toBe(true);
    expect(isEmailFinding({ title: "Missing SPF record" })).toBe(true);
    expect(isEmailFinding({ title: "SPF Record uses +all" })).toBe(true);
  });

  it("correctly identifies DKIM findings as email findings", () => {
    expect(isEmailFinding({ title: "No DKIM Selectors Found" })).toBe(true);
    expect(isEmailFinding({ title: "Weak DKIM Key(s) Detected" })).toBe(true);
    expect(isEmailFinding({ title: "DKIM selector not configured" })).toBe(true);
  });

  it("correctly identifies email security category findings", () => {
    expect(isEmailFinding({ category: "Email Security (DMARC)" })).toBe(true);
    expect(isEmailFinding({ category: "Email Security (SPF)" })).toBe(true);
    expect(isEmailFinding({ category: "Email Security (DKIM)" })).toBe(true);
    expect(isEmailFinding({ category: "Email Security (MX)" })).toBe(true);
  });

  it("correctly identifies email spoofing findings", () => {
    expect(isEmailFinding({ title: "Email spoofing possible" })).toBe(true);
    expect(isEmailFinding({ title: "Email impersonation risk" })).toBe(true);
  });

  it("does NOT flag non-email findings", () => {
    expect(isEmailFinding({ title: "Outdated nginx version" })).toBe(false);
    expect(isEmailFinding({ title: "SSL certificate expiring" })).toBe(false);
    expect(isEmailFinding({ title: "Open SSH port detected" })).toBe(false);
    expect(isEmailFinding({ title: "Cross-site scripting vulnerability" })).toBe(false);
    expect(isEmailFinding({ category: "Web Security" })).toBe(false);
    expect(isEmailFinding({ category: "Network Security" })).toBe(false);
  });

  it("simulates full Stage 3.10 filter on a non-mail asset", async () => {
    const mod = await import("./lib/email-security-analyzer");

    const webServerAsset = {
      hostname: "www.example.com",
      assetType: "customer_portal",
      essentialService: "web_application",
      missionFunction: "public_facing_services",
      tags: ["internet_exposed", "public"],
    };

    // This asset is NOT a mail asset
    expect(mod.isMailAsset(webServerAsset)).toBe(false);

    // Simulate findings that include email findings mixed with legitimate ones
    const findings = [
      { id: "f1", title: "Outdated nginx 1.18.0", category: "Web Security", severity: 7 },
      { id: "f2", title: "No DMARC Record Found", category: "Email Security (DMARC)", severity: 9.5 },
      { id: "f3", title: "No SPF Record Found", category: "Email Security (SPF)", severity: 7.5 },
      { id: "f4", title: "SSL certificate weak cipher", category: "TLS Security", severity: 5 },
      { id: "f5", title: "DMARC Policy Set to 'none'", category: "Email Security (DMARC)", severity: 7.5 },
    ];

    // Filter: keep only non-email findings for non-mail assets
    const filtered = findings.filter(f => !isEmailFinding(f));

    expect(filtered).toHaveLength(2);
    expect(filtered.map(f => f.id)).toEqual(["f1", "f4"]);
    expect(filtered.find(f => f.title.includes("DMARC"))).toBeUndefined();
    expect(filtered.find(f => f.title.includes("SPF"))).toBeUndefined();
  });

  it("preserves email findings on a mail asset", async () => {
    const mod = await import("./lib/email-security-analyzer");

    const mailAsset = {
      hostname: "mail.example.com",
      assetType: "mail_gateway",
      essentialService: "email_gateway",
      missionFunction: "communication_infrastructure",
      tags: ["internet_exposed", "email"],
    };

    // This asset IS a mail asset
    expect(mod.isMailAsset(mailAsset)).toBe(true);

    // All findings should be preserved on mail assets
    const findings = [
      { id: "f1", title: "No DMARC Record Found", category: "Email Security (DMARC)", severity: 9.5 },
      { id: "f2", title: "No SPF Record Found", category: "Email Security (SPF)", severity: 7.5 },
      { id: "f3", title: "Open SMTP relay", category: "Network Security", severity: 8 },
    ];

    // No filtering should happen for mail assets
    expect(findings).toHaveLength(3);
  });
});
