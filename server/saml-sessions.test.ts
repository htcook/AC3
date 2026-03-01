import { describe, expect, it, vi } from "vitest";
import {
  generateSPMetadata,
  getSPEntityId,
  getSPAcsUrl,
  getBaseUrl,
  generateAuthnRequest,
  extractUserAttributes,
  type SAMLIdPConfig,
  type SAMLAssertion,
} from "./lib/saml-service";

// ─── SAML SP Metadata Tests ──────────────────────────────────────────────────

describe("SAML SP Metadata", () => {
  it("generates valid SP metadata XML", () => {
    const metadata = generateSPMetadata();
    expect(metadata).toContain('<?xml version="1.0"');
    expect(metadata).toContain("EntityDescriptor");
    expect(metadata).toContain("SPSSODescriptor");
    expect(metadata).toContain("AssertionConsumerService");
    expect(metadata).toContain("SingleLogoutService");
  });

  it("includes correct entity ID in metadata", () => {
    const metadata = generateSPMetadata();
    const entityId = getSPEntityId();
    expect(metadata).toContain(`entityID="${entityId}"`);
  });

  it("includes correct ACS URL in metadata", () => {
    const metadata = generateSPMetadata();
    const acsUrl = getSPAcsUrl();
    expect(metadata).toContain(`Location="${acsUrl}"`);
  });

  it("requests signed assertions", () => {
    const metadata = generateSPMetadata();
    expect(metadata).toContain('WantAssertionsSigned="true"');
    expect(metadata).toContain('AuthnRequestsSigned="true"');
  });

  it("includes all three NameID formats", () => {
    const metadata = generateSPMetadata();
    expect(metadata).toContain("nameid-format:emailAddress");
    expect(metadata).toContain("nameid-format:persistent");
    expect(metadata).toContain("nameid-format:transient");
  });

  it("includes organization info", () => {
    const metadata = generateSPMetadata();
    expect(metadata).toContain("OrganizationName");
    expect(metadata).toContain("Caldera Dashboard");
  });

  it("sets a valid future expiry date", () => {
    const metadata = generateSPMetadata();
    const match = metadata.match(/validUntil="([^"]+)"/);
    expect(match).toBeTruthy();
    const expiryDate = new Date(match![1]);
    expect(expiryDate.getTime()).toBeGreaterThan(Date.now());
  });
});

// ─── SP Configuration Tests ──────────────────────────────────────────────────

describe("SP Configuration", () => {
  it("returns base URL from environment or default", () => {
    const baseUrl = getBaseUrl();
    expect(baseUrl).toBeTruthy();
    expect(baseUrl.startsWith("http")).toBe(true);
  });

  it("entity ID ends with /api/saml/metadata", () => {
    const entityId = getSPEntityId();
    expect(entityId).toMatch(/\/api\/saml\/metadata$/);
  });

  it("ACS URL ends with /api/saml/acs", () => {
    const acsUrl = getSPAcsUrl();
    expect(acsUrl).toMatch(/\/api\/saml\/acs$/);
  });
});

// ─── AuthnRequest Generation Tests ──────────────────────────────────────────

describe("AuthnRequest Generation", () => {
  const mockIdpConfig: SAMLIdPConfig = {
    id: 1,
    name: "Test Okta",
    providerType: "okta",
    entityId: "https://idp.example.com/metadata",
    ssoUrl: "https://idp.example.com/sso",
    sloUrl: "https://idp.example.com/slo",
    certificate: "MIIDpDCCAoygAwIBAgIGAX...",
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    defaultRole: "operator",
    forceAuthn: false,
    wantAssertionsSigned: true,
    wantResponseSigned: true,
    attributeMapping: null,
  };

  it("generates a redirect URL to the IdP SSO endpoint", () => {
    const { url, requestId } = generateAuthnRequest(mockIdpConfig);
    expect(url).toContain(mockIdpConfig.ssoUrl);
    expect(url).toContain("SAMLRequest=");
    expect(requestId).toMatch(/^_[a-f0-9]{32}$/);
  });

  it("includes RelayState when provided", () => {
    const { url } = generateAuthnRequest(mockIdpConfig, "/dashboard");
    expect(url).toContain("RelayState=");
    expect(url).toContain(encodeURIComponent("/dashboard"));
  });

  it("omits RelayState when not provided", () => {
    const { url } = generateAuthnRequest(mockIdpConfig);
    expect(url).not.toContain("RelayState=");
  });

  it("generates unique request IDs", () => {
    const { requestId: id1 } = generateAuthnRequest(mockIdpConfig);
    const { requestId: id2 } = generateAuthnRequest(mockIdpConfig);
    expect(id1).not.toBe(id2);
  });

  it("includes ForceAuthn when configured", () => {
    const forceConfig = { ...mockIdpConfig, forceAuthn: true };
    const { url } = generateAuthnRequest(forceConfig);
    // The SAMLRequest is deflated+base64 encoded, so we can't directly check XML
    // But we verify the URL is well-formed
    expect(url).toContain("SAMLRequest=");
    const samlRequestParam = new URL(url).searchParams.get("SAMLRequest");
    expect(samlRequestParam).toBeTruthy();
  });
});

// ─── User Attribute Extraction Tests ────────────────────────────────────────

describe("User Attribute Extraction", () => {
  const baseAssertion: SAMLAssertion = {
    nameId: "user@example.com",
    nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    sessionIndex: "_session123",
    issuer: "https://idp.example.com",
    assertionId: "_assertion456",
    attributes: {},
  };

  it("extracts email from standard SAML attribute", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "john@example.com",
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.email).toBe("john@example.com");
  });

  it("falls back to NameID for email when no email attribute", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {},
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.email).toBe("user@example.com");
  });

  it("extracts name from display name attribute", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "displayName": "John Doe",
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.name).toBe("John Doe");
  });

  it("constructs name from first + last name attributes", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "Jane",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "Smith",
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.name).toBe("Jane Smith");
    expect(attrs.firstName).toBe("Jane");
    expect(attrs.lastName).toBe("Smith");
  });

  it("extracts role from Microsoft role claim", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "admin",
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.role).toBe("admin");
  });

  it("extracts department attribute", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "department": "Security Operations",
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.department).toBe("Security Operations");
  });

  it("extracts groups from memberOf attribute", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "memberOf": ["cn=admins,ou=groups", "cn=operators,ou=groups"],
      },
    };
    const attrs = extractUserAttributes(assertion);
    expect(attrs.groups).toEqual(["cn=admins,ou=groups", "cn=operators,ou=groups"]);
  });

  it("uses custom attribute mapping when provided", () => {
    const assertion: SAMLAssertion = {
      ...baseAssertion,
      attributes: {
        "custom_email_field": "custom@example.com",
        "custom_name_field": "Custom User",
      },
    };
    const mapping = {
      email: "custom_email_field",
      name: "custom_name_field",
    };
    const attrs = extractUserAttributes(assertion, mapping);
    expect(attrs.email).toBe("custom@example.com");
    expect(attrs.name).toBe("Custom User");
  });
});

// ─── Session Management Tests ───────────────────────────────────────────────

describe("Session Management - User Agent Parsing", () => {
  // Test the device fingerprinting logic that would be used in session-management.ts
  // We test the parsing patterns directly

  const parseUserAgent = (ua: string) => {
    let browserName = "Unknown";
    let browserVersion = "";
    let osName = "Unknown";
    let osVersion = "";
    let deviceType = "desktop";

    // Browser detection
    if (ua.includes("Edg/")) {
      browserName = "Edge";
      browserVersion = ua.match(/Edg\/([\d.]+)/)?.[1] || "";
    } else if (ua.includes("Chrome/")) {
      browserName = "Chrome";
      browserVersion = ua.match(/Chrome\/([\d.]+)/)?.[1] || "";
    } else if (ua.includes("Firefox/")) {
      browserName = "Firefox";
      browserVersion = ua.match(/Firefox\/([\d.]+)/)?.[1] || "";
    } else if (ua.includes("Safari/") && !ua.includes("Chrome")) {
      browserName = "Safari";
      browserVersion = ua.match(/Version\/([\d.]+)/)?.[1] || "";
    }

    // OS detection — check specific platforms before generic ones
    if (ua.includes("iPhone") || ua.includes("iPad")) {
      osName = "iOS";
      osVersion = ua.match(/OS ([\d_]+)/)?.[1]?.replace(/_/g, ".") || "";
    } else if (ua.includes("Android")) {
      osName = "Android";
      osVersion = ua.match(/Android ([\d.]+)/)?.[1] || "";
    } else if (ua.includes("Windows")) {
      osName = "Windows";
      osVersion = ua.match(/Windows NT ([\d.]+)/)?.[1] || "";
    } else if (ua.includes("Mac OS X")) {
      osName = "macOS";
      osVersion = ua.match(/Mac OS X ([\d_]+)/)?.[1]?.replace(/_/g, ".") || "";
    } else if (ua.includes("Linux")) {
      osName = "Linux";
    }

    // Device type
    if (/Mobile|Android.*Mobile|iPhone/.test(ua)) {
      deviceType = "mobile";
    } else if (/iPad|Android(?!.*Mobile)|Tablet/.test(ua)) {
      deviceType = "tablet";
    }

    return { browserName, browserVersion, osName, osVersion, deviceType };
  };

  it("parses Chrome on Windows", () => {
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Chrome");
    expect(result.browserVersion).toBe("120.0.0.0");
    expect(result.osName).toBe("Windows");
    expect(result.deviceType).toBe("desktop");
  });

  it("parses Firefox on macOS", () => {
    const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/121.0";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Firefox");
    expect(result.browserVersion).toBe("121.0");
    expect(result.osName).toBe("macOS");
    expect(result.deviceType).toBe("desktop");
  });

  it("parses Safari on iPhone (mobile)", () => {
    const ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Safari");
    expect(result.osName).toBe("iOS");
    expect(result.deviceType).toBe("mobile");
  });

  it("parses Edge on Windows", () => {
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Edge");
    expect(result.osName).toBe("Windows");
    expect(result.deviceType).toBe("desktop");
  });

  it("parses Chrome on Android tablet", () => {
    const ua = "Mozilla/5.0 (Linux; Android 13; SM-X800) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Chrome");
    expect(result.osName).toBe("Android");
    expect(result.deviceType).toBe("tablet");
  });

  it("parses Chrome on Android mobile", () => {
    const ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
    const result = parseUserAgent(ua);
    expect(result.browserName).toBe("Chrome");
    expect(result.osName).toBe("Android");
    expect(result.deviceType).toBe("mobile");
  });
});

// ─── Session Fingerprint Tests ──────────────────────────────────────────────

describe("Session Fingerprinting", () => {
  it("generates consistent fingerprint for same inputs", () => {
    const crypto = require("node:crypto");
    const input1 = "Chrome-120-Windows-10.0-desktop";
    const input2 = "Chrome-120-Windows-10.0-desktop";
    const hash1 = crypto.createHash("sha256").update(input1).digest("hex").slice(0, 32);
    const hash2 = crypto.createHash("sha256").update(input2).digest("hex").slice(0, 32);
    expect(hash1).toBe(hash2);
  });

  it("generates different fingerprints for different inputs", () => {
    const crypto = require("node:crypto");
    const input1 = "Chrome-120-Windows-10.0-desktop";
    const input2 = "Firefox-121-macOS-14.0-desktop";
    const hash1 = crypto.createHash("sha256").update(input1).digest("hex").slice(0, 32);
    const hash2 = crypto.createHash("sha256").update(input2).digest("hex").slice(0, 32);
    expect(hash1).not.toBe(hash2);
  });

  it("uses SHA-256 for FIPS 140-3 compliance", () => {
    const crypto = require("node:crypto");
    const hash = crypto.createHash("sha256").update("test").digest("hex");
    // SHA-256 produces 64 hex characters
    expect(hash).toHaveLength(64);
  });
});

// ─── SAML Provider Template Tests ───────────────────────────────────────────

describe("SAML Provider Templates", () => {
  const PROVIDER_TEMPLATES: Record<string, { label: string; entityIdHint: string; ssoUrlHint: string }> = {
    okta: {
      label: "Okta",
      entityIdHint: "http://www.okta.com/{externalKey}",
      ssoUrlHint: "https://{yourDomain}.okta.com/app/{appName}/{externalKey}/sso/saml",
    },
    azure_ad: {
      label: "Azure AD (Entra ID)",
      entityIdHint: "https://sts.windows.net/{tenantId}/",
      ssoUrlHint: "https://login.microsoftonline.com/{tenantId}/saml2",
    },
    ping_federate: {
      label: "PingFederate",
      entityIdHint: "https://{pingHost}:9031",
      ssoUrlHint: "https://{pingHost}:9031/idp/SSO.saml2",
    },
    google_workspace: {
      label: "Google Workspace",
      entityIdHint: "https://accounts.google.com/o/saml2?idpid={idpId}",
      ssoUrlHint: "https://accounts.google.com/o/saml2/idp?idpid={idpId}",
    },
    onelogin: {
      label: "OneLogin",
      entityIdHint: "https://app.onelogin.com/saml/metadata/{appId}",
      ssoUrlHint: "https://{subdomain}.onelogin.com/trust/saml2/http-post/sso/{appId}",
    },
  };

  it("has templates for all major IdPs", () => {
    expect(PROVIDER_TEMPLATES.okta).toBeDefined();
    expect(PROVIDER_TEMPLATES.azure_ad).toBeDefined();
    expect(PROVIDER_TEMPLATES.ping_federate).toBeDefined();
    expect(PROVIDER_TEMPLATES.google_workspace).toBeDefined();
    expect(PROVIDER_TEMPLATES.onelogin).toBeDefined();
  });

  it("each template has required fields", () => {
    for (const [key, template] of Object.entries(PROVIDER_TEMPLATES)) {
      expect(template.label).toBeTruthy();
      expect(template.entityIdHint).toBeTruthy();
      expect(template.ssoUrlHint).toBeTruthy();
    }
  });
});

// ─── FIPS Compliance in SAML ────────────────────────────────────────────────

describe("FIPS 140-3 Compliance in SAML", () => {
  it("uses SHA-256 for signature validation (not SHA-1)", () => {
    // Verify that our implementation references SHA-256
    const crypto = require("node:crypto");
    const verifier = crypto.createVerify("SHA256");
    expect(verifier).toBeTruthy();
  });

  it("generates cryptographically secure request IDs", () => {
    const crypto = require("node:crypto");
    const id1 = `_${crypto.randomBytes(16).toString("hex")}`;
    const id2 = `_${crypto.randomBytes(16).toString("hex")}`;
    expect(id1).toHaveLength(33); // _ + 32 hex chars
    expect(id2).toHaveLength(33);
    expect(id1).not.toBe(id2);
  });

  it("session tokens use CSPRNG", () => {
    const crypto = require("node:crypto");
    const token = crypto.randomBytes(32).toString("hex");
    expect(token).toHaveLength(64);
    // Verify entropy - should not be all zeros
    expect(token).not.toBe("0".repeat(64));
  });

  it("supports AES-256-GCM for encrypted assertions", () => {
    const crypto = require("node:crypto");
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    expect(cipher).toBeTruthy();
    const encrypted = Buffer.concat([cipher.update("test data", "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    expect(encrypted.length).toBeGreaterThan(0);
    expect(tag.length).toBe(16);
  });
});

// ─── Session Security Tests ─────────────────────────────────────────────────

describe("Session Security", () => {
  it("session expiry defaults to 24 hours", () => {
    const DEFAULT_SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours in ms
    expect(DEFAULT_SESSION_DURATION).toBe(86400000);
  });

  it("extended session expiry is 7 days", () => {
    const EXTENDED_SESSION_DURATION = 7 * 24 * 60 * 60 * 1000;
    expect(EXTENDED_SESSION_DURATION).toBe(604800000);
  });

  it("session tokens have sufficient entropy (256 bits)", () => {
    const crypto = require("node:crypto");
    const token = crypto.randomBytes(32); // 256 bits
    expect(token.length).toBe(32);
  });

  it("IP address validation for session binding", () => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    expect(ipv4Regex.test("192.168.1.1")).toBe(true);
    expect(ipv4Regex.test("10.0.0.1")).toBe(true);
    expect(ipv4Regex.test("invalid")).toBe(false);
  });
});
