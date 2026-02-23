import { describe, expect, it, beforeAll } from "vitest";
import {
  encryptCredential,
  decryptCredential,
  encryptCredentialObject,
  decryptCredentialObject,
  maskCredential,
} from "./lib/credential-crypto";
import type {
  CloudIdentityResult,
  CloudEnumerationResult,
  AWSCredentials,
  AzureCredentials,
  GCPCredentials,
} from "./lib/cloud-iam-enumerator";
import type {
  LDAPConnectionConfig,
  ADObject,
  ADEnumerationResult,
} from "./lib/ad-domain-connector";

// ── Credential Encryption Tests ────────────────────────────────────────────

describe("credential-crypto", () => {
  beforeAll(() => {
    // Ensure JWT_SECRET is set for encryption
    process.env.JWT_SECRET = "test-secret-for-encryption-key-derivation-12345";
  });

  it("encrypts and decrypts a plaintext credential correctly", () => {
    const plaintext = "AKIAIOSFODNN7EXAMPLE";
    const encrypted = encryptCredential(plaintext);

    expect(encrypted).toHaveProperty("encryptedData");
    expect(encrypted).toHaveProperty("iv");
    expect(encrypted).toHaveProperty("tag");
    expect(encrypted.encryptedData).not.toBe(plaintext);
    expect(encrypted.iv).toHaveLength(32); // 16 bytes hex = 32 chars
    expect(encrypted.tag).toHaveLength(32);

    const decrypted = decryptCredential(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it("produces different ciphertext for the same plaintext (unique IVs)", () => {
    const plaintext = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const enc1 = encryptCredential(plaintext);
    const enc2 = encryptCredential(plaintext);

    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.encryptedData).not.toBe(enc2.encryptedData);

    // Both should decrypt to the same value
    expect(decryptCredential(enc1)).toBe(plaintext);
    expect(decryptCredential(enc2)).toBe(plaintext);
  });

  it("encrypts and decrypts a JSON credential object", () => {
    const credObj = {
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
    };

    const encrypted = encryptCredentialObject(credObj);
    const decrypted = decryptCredentialObject<typeof credObj>(encrypted);

    expect(decrypted).toEqual(credObj);
  });

  it("fails to decrypt with a tampered ciphertext", () => {
    const plaintext = "sensitive-credential";
    const encrypted = encryptCredential(plaintext);

    // Tamper with the ciphertext
    const tampered = {
      ...encrypted,
      encryptedData: encrypted.encryptedData.replace(/[a-f0-9]/, "0"),
    };

    // If the tampered data is the same (unlikely but possible), skip
    if (tampered.encryptedData === encrypted.encryptedData) return;

    expect(() => decryptCredential(tampered)).toThrow();
  });

  it("handles empty string encryption", () => {
    const encrypted = encryptCredential("");
    const decrypted = decryptCredential(encrypted);
    expect(decrypted).toBe("");
  });

  it("handles large credential payloads (GCP service account key)", () => {
    const largeKey = JSON.stringify({
      type: "service_account",
      project_id: "my-project-123456",
      private_key_id: "key-id-" + "x".repeat(40),
      private_key: "-----BEGIN RSA PRIVATE KEY-----\n" + "A".repeat(2000) + "\n-----END RSA PRIVATE KEY-----\n",
      client_email: "sa@my-project-123456.iam.gserviceaccount.com",
      client_id: "123456789012345678901",
      auth_uri: "https://accounts.google.com/o/oauth2/auth",
      token_uri: "https://oauth2.googleapis.com/token",
    });

    const encrypted = encryptCredentialObject({ serviceAccountKey: largeKey });
    const decrypted = decryptCredentialObject<{ serviceAccountKey: string }>(encrypted);
    expect(decrypted.serviceAccountKey).toBe(largeKey);
  });
});

describe("maskCredential", () => {
  it("masks a long credential showing first 4 and last 4 chars", () => {
    const masked = maskCredential("AKIAIOSFODNN7EXAMPLE");
    expect(masked).toMatch(/^AKIA/);
    expect(masked).toMatch(/MPLE$/);
    expect(masked).toContain("*");
    expect(masked).not.toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("masks a short credential completely", () => {
    const masked = maskCredential("abc");
    expect(masked).toBe("****");
  });

  it("masks an 8-char credential completely", () => {
    const masked = maskCredential("12345678");
    expect(masked).toBe("****");
  });

  it("masks a 9-char credential showing first 4 and last 4", () => {
    const masked = maskCredential("123456789");
    expect(masked).toBe("1234*6789");
  });
});

// ── Cloud IAM Enumerator Type Tests ────────────────────────────────────────

describe("cloud-iam-enumerator types", () => {
  it("validates CloudIdentityResult structure", () => {
    const identity: CloudIdentityResult = {
      identityType: "user",
      arn: "arn:aws:iam::123456789012:user/admin",
      name: "admin",
      email: "admin@example.com",
      isPrivileged: true,
      lastActivity: new Date(),
      permissions: ["iam:*"],
      policies: ["AdministratorAccess"],
      metadata: { hasConsoleAccess: true },
    };

    expect(identity.identityType).toBe("user");
    expect(identity.isPrivileged).toBe(true);
    expect(identity.arn).toContain("arn:aws");
  });

  it("validates CloudEnumerationResult structure", () => {
    const result: CloudEnumerationResult = {
      provider: "aws",
      users: [],
      roles: [],
      groups: [],
      serviceAccounts: [],
      policies: [],
      misconfigurations: [],
      summary: {
        totalUsers: 0,
        totalRoles: 0,
        totalGroups: 0,
        totalPolicies: 0,
        totalServiceAccounts: 0,
        totalMisconfigs: 0,
        privilegedIdentities: 0,
      },
      errors: [],
    };

    expect(result.provider).toBe("aws");
    expect(result.summary.totalUsers).toBe(0);
    expect(result.errors).toHaveLength(0);
  });

  it("validates AWSCredentials structure", () => {
    const creds: AWSCredentials = {
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      roleArn: "arn:aws:iam::123456789012:role/PentestRole",
    };

    expect(creds.accessKeyId).toMatch(/^AKIA/);
    expect(creds.region).toBe("us-east-1");
  });

  it("validates AzureCredentials structure", () => {
    const creds: AzureCredentials = {
      clientId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      clientSecret: "~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      subscriptionId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    };

    expect(creds.clientId).toHaveLength(36);
    expect(creds.tenantId).toHaveLength(36);
  });

  it("validates GCPCredentials structure", () => {
    const creds: GCPCredentials = {
      projectId: "my-project-123456",
      serviceAccountKey: JSON.stringify({ type: "service_account" }),
    };

    expect(creds.projectId).toContain("my-project");
    expect(JSON.parse(creds.serviceAccountKey).type).toBe("service_account");
  });
});

// ── AD Domain Connector Type Tests ─────────────────────────────────────────

describe("ad-domain-connector types", () => {
  it("validates LDAPConnectionConfig structure", () => {
    const config: LDAPConnectionConfig = {
      serverHost: "dc01.corp.acme.com",
      serverPort: 636,
      useTls: true,
      tlsRejectUnauthorized: false,
      baseDn: "DC=corp,DC=acme,DC=com",
      bindDn: "CN=svc-pentest,OU=Service Accounts,DC=corp,DC=acme,DC=com",
      bindPassword: "P@ssw0rd!",
    };

    expect(config.serverHost).toBe("dc01.corp.acme.com");
    expect(config.serverPort).toBe(636);
    expect(config.useTls).toBe(true);
    expect(config.baseDn).toContain("DC=");
  });

  it("validates ADObject structure for a user", () => {
    const user: ADObject = {
      objectType: "user",
      distinguishedName: "CN=John Doe,OU=Users,DC=corp,DC=acme,DC=com",
      samAccountName: "jdoe",
      displayName: "John Doe",
      isPrivileged: true,
      isEnabled: true,
      memberOf: ["CN=Domain Admins,CN=Users,DC=corp,DC=acme,DC=com"],
      properties: {
        servicePrincipalName: ["MSSQLSvc/sql01.corp.acme.com:1433"],
        userAccountControl: 66048,
      },
    };

    expect(user.objectType).toBe("user");
    expect(user.isPrivileged).toBe(true);
    expect(user.memberOf).toContain("CN=Domain Admins,CN=Users,DC=corp,DC=acme,DC=com");
  });

  it("validates ADObject structure for a computer", () => {
    const computer: ADObject = {
      objectType: "computer",
      distinguishedName: "CN=DC01,OU=Domain Controllers,DC=corp,DC=acme,DC=com",
      samAccountName: "DC01$",
      displayName: "DC01",
      isPrivileged: true,
      isEnabled: true,
      properties: {
        operatingSystem: "Windows Server 2022",
        operatingSystemVersion: "10.0 (20348)",
        dNSHostName: "dc01.corp.acme.com",
      },
    };

    expect(computer.objectType).toBe("computer");
    expect(computer.samAccountName).toContain("$");
    expect(computer.properties?.operatingSystem).toContain("Windows");
  });

  it("validates ADEnumerationResult structure", () => {
    const result: ADEnumerationResult = {
      users: [],
      groups: [],
      computers: [],
      gpos: [],
      ous: [],
      trusts: [],
      spns: [],
      certificateTemplates: [],
      summary: {
        totalUsers: 0,
        totalGroups: 0,
        totalComputers: 0,
        totalGpos: 0,
        totalOus: 0,
        totalTrusts: 0,
        totalSpns: 0,
        privilegedUsers: 0,
        kerberoastableUsers: 0,
        asrepRoastableUsers: 0,
        disabledAccounts: 0,
      },
      errors: [],
    };

    expect(result.summary.totalUsers).toBe(0);
    expect(result.summary.kerberoastableUsers).toBe(0);
    expect(result.certificateTemplates).toHaveLength(0);
  });

  it("validates ADObject structure for a GPO", () => {
    const gpo: ADObject = {
      objectType: "gpo",
      distinguishedName: "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=acme,DC=com",
      displayName: "Default Domain Policy",
      isPrivileged: false,
      isEnabled: true,
      properties: {
        gPCFileSysPath: "\\\\corp.acme.com\\sysvol\\corp.acme.com\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}",
        versionNumber: 12,
      },
    };

    expect(gpo.objectType).toBe("gpo");
    expect(gpo.displayName).toBe("Default Domain Policy");
  });

  it("validates ADObject structure for a trust", () => {
    const trust: ADObject = {
      objectType: "trust",
      distinguishedName: "CN=partner.com,CN=System,DC=corp,DC=acme,DC=com",
      displayName: "partner.com",
      isPrivileged: false,
      isEnabled: true,
      properties: {
        trustDirection: "bidirectional",
        trustType: "forest",
        trustAttributes: 8,
        sidFilteringEnabled: false,
      },
    };

    expect(trust.objectType).toBe("trust");
    expect(trust.properties?.trustDirection).toBe("bidirectional");
    expect(trust.properties?.sidFilteringEnabled).toBe(false);
  });

  it("validates Kerberoastable user detection pattern", () => {
    // A user is Kerberoastable if they have SPNs and are enabled
    const kerberoastableUser: ADObject = {
      objectType: "user",
      distinguishedName: "CN=svc-sql,OU=Service Accounts,DC=corp,DC=acme,DC=com",
      samAccountName: "svc-sql",
      isPrivileged: false,
      isEnabled: true,
      properties: {
        servicePrincipalName: ["MSSQLSvc/sql01.corp.acme.com:1433"],
        userAccountControl: 66048, // NORMAL_ACCOUNT + DONT_EXPIRE_PASSWD
      },
    };

    const hasSpn = kerberoastableUser.properties?.servicePrincipalName?.length > 0;
    const isEnabled = kerberoastableUser.isEnabled;
    const isKerberoastable = hasSpn && isEnabled;

    expect(isKerberoastable).toBe(true);
  });

  it("validates AS-REP Roastable user detection pattern", () => {
    // A user is AS-REP Roastable if DONT_REQUIRE_PREAUTH (0x400000) is set
    const DONT_REQUIRE_PREAUTH = 0x400000;
    const asrepUser: ADObject = {
      objectType: "user",
      distinguishedName: "CN=legacy-svc,OU=Service Accounts,DC=corp,DC=acme,DC=com",
      samAccountName: "legacy-svc",
      isPrivileged: false,
      isEnabled: true,
      properties: {
        userAccountControl: 0x400200, // NORMAL_ACCOUNT + DONT_REQUIRE_PREAUTH
      },
    };

    const uac = asrepUser.properties?.userAccountControl || 0;
    const isAsrepRoastable = (uac & DONT_REQUIRE_PREAUTH) !== 0;

    expect(isAsrepRoastable).toBe(true);
  });
});
