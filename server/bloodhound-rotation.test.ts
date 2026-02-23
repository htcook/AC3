import { describe, expect, it } from "vitest";
import {
  rotateAwsAccessKey,
  rotateAzureClientSecret,
  rotateGcpServiceAccountKey,
  isPolicyDueForRotation,
  calculateNextRotation,
  evaluatePolicies,
  generateRotationSummary,
  DEFAULT_ROTATION_INTERVALS,
  type RotationPolicy,
  type RotationAuditEntry,
} from "./lib/credential-auto-rotation";
import {
  parseSharpHoundJSON,
  detectCollectionType,
  parseUsers,
  parseGroups,
  parseComputers,
  mergeCollections,
  type BloodHoundCollection,
} from "./lib/bloodhound-parser";

// ─── Credential Auto-Rotation Tests ──────────────────────────────────────────

describe("Credential Auto-Rotation", () => {
  describe("AWS IAM Key Rotation", () => {
    it("rotates AWS access key successfully", async () => {
      const result = await rotateAwsAccessKey({
        accessKeyId: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
      });

      expect(result.success).toBe(true);
      expect(result.provider).toBe("aws");
      expect(result.oldKeyId).toBe("AKIAIOSFODNN7EXAMPLE");
      expect(result.newKeyId).toBeTruthy();
      expect(result.newKeyId).toMatch(/^AKIA/);
      expect(result.newCredentials).toBeTruthy();
      expect(result.newCredentials!.accessKeyId).toBe(result.newKeyId);
      expect(result.newCredentials!.secretAccessKey).toBeTruthy();
      expect(result.newCredentials!.region).toBe("us-east-1");
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
      expect(result.error).toBeNull();
    });

    it("fails with incomplete AWS credentials", async () => {
      const result = await rotateAwsAccessKey({
        accessKeyId: "",
        secretAccessKey: "",
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("incomplete");
      expect(result.newCredentials).toBeNull();
    });
  });

  describe("Azure Credential Reset", () => {
    it("rotates Azure client secret successfully", async () => {
      const result = await rotateAzureClientSecret({
        tenantId: "12345678-1234-1234-1234-123456789012",
        clientId: "abcdefgh-abcd-abcd-abcd-abcdefghijkl",
        clientSecret: "old-secret-value",
      });

      expect(result.success).toBe(true);
      expect(result.provider).toBe("azure");
      expect(result.newCredentials).toBeTruthy();
      expect(result.newCredentials!.tenantId).toBe("12345678-1234-1234-1234-123456789012");
      expect(result.newCredentials!.clientId).toBe("abcdefgh-abcd-abcd-abcd-abcdefghijkl");
      expect(result.newCredentials!.clientSecret).toBeTruthy();
      expect(result.newCredentials!.clientSecret).not.toBe("old-secret-value");
      expect(result.error).toBeNull();
    });

    it("fails with incomplete Azure credentials", async () => {
      const result = await rotateAzureClientSecret({
        tenantId: "",
        clientId: "",
        clientSecret: "",
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("incomplete");
    });
  });

  describe("GCP Service Account Key Rotation", () => {
    it("rotates GCP service account key successfully", async () => {
      const result = await rotateGcpServiceAccountKey({
        projectId: "my-project-123",
        clientEmail: "sa@my-project-123.iam.gserviceaccount.com",
        privateKey: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----",
        privateKeyId: "old-key-id-123",
      });

      expect(result.success).toBe(true);
      expect(result.provider).toBe("gcp");
      expect(result.oldKeyId).toBe("old-key-id-123");
      expect(result.newKeyId).toMatch(/^gcp-key-/);
      expect(result.newCredentials).toBeTruthy();
      expect(result.newCredentials!.projectId).toBe("my-project-123");
      expect(result.newCredentials!.clientEmail).toBe("sa@my-project-123.iam.gserviceaccount.com");
      expect(result.newCredentials!.privateKey).toContain("BEGIN RSA PRIVATE KEY");
      expect(result.error).toBeNull();
    });

    it("fails with incomplete GCP credentials", async () => {
      const result = await rotateGcpServiceAccountKey({
        projectId: "",
        clientEmail: "",
        privateKey: "",
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("incomplete");
    });
  });

  describe("Policy Evaluation", () => {
    const basePolicy: RotationPolicy = {
      id: 1,
      credentialId: 1,
      provider: "aws",
      credentialName: "Test Credential",
      enabled: true,
      rotationIntervalDays: 90,
      lastRotatedAt: null,
      nextRotationAt: null,
      maxRetries: 3,
      retryCount: 0,
      createdBy: "test",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    it("marks never-rotated policy as due", () => {
      expect(isPolicyDueForRotation(basePolicy)).toBe(true);
    });

    it("marks disabled policy as not due", () => {
      expect(isPolicyDueForRotation({ ...basePolicy, enabled: false })).toBe(false);
    });

    it("marks recently-rotated policy as not due", () => {
      const recentlyRotated = {
        ...basePolicy,
        lastRotatedAt: new Date(),
        nextRotationAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      };
      expect(isPolicyDueForRotation(recentlyRotated)).toBe(false);
    });

    it("marks overdue policy as due", () => {
      const overdue = {
        ...basePolicy,
        lastRotatedAt: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
        nextRotationAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000),
      };
      expect(isPolicyDueForRotation(overdue)).toBe(true);
    });

    it("evaluates batch policies correctly", () => {
      const policies: RotationPolicy[] = [
        basePolicy, // due (never rotated)
        { ...basePolicy, id: 2, enabled: false }, // not due (disabled)
        {
          ...basePolicy,
          id: 3,
          lastRotatedAt: new Date(),
          nextRotationAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
        }, // not due (recently rotated)
      ];

      const due = evaluatePolicies(policies);
      expect(due).toHaveLength(1);
      expect(due[0].id).toBe(1);
    });
  });

  describe("Rotation Scheduling", () => {
    it("calculates next rotation date correctly", () => {
      const lastRotated = new Date("2026-01-01T00:00:00Z");
      const next = calculateNextRotation(lastRotated, 90);
      expect(next.toISOString().split("T")[0]).toBe("2026-03-31");
    });

    it("uses correct default intervals per provider", () => {
      expect(DEFAULT_ROTATION_INTERVALS.aws).toBe(90);
      expect(DEFAULT_ROTATION_INTERVALS.azure).toBe(180);
      expect(DEFAULT_ROTATION_INTERVALS.gcp).toBe(90);
    });
  });

  describe("Rotation Summary", () => {
    it("generates accurate summary", () => {
      const policies: RotationPolicy[] = [
        {
          id: 1, credentialId: 1, provider: "aws", credentialName: "AWS Key",
          enabled: true, rotationIntervalDays: 90, lastRotatedAt: null,
          nextRotationAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
          maxRetries: 3, retryCount: 0, createdBy: "test",
          createdAt: new Date(), updatedAt: new Date(),
        },
        {
          id: 2, credentialId: 2, provider: "azure", credentialName: "Azure Secret",
          enabled: false, rotationIntervalDays: 180, lastRotatedAt: new Date(),
          nextRotationAt: null, maxRetries: 3, retryCount: 0, createdBy: "test",
          createdAt: new Date(), updatedAt: new Date(),
        },
      ];

      const auditEntries: RotationAuditEntry[] = [
        {
          id: 1, policyId: 1, credentialId: 1, provider: "aws",
          status: "success", oldKeyIdentifier: "old", newKeyIdentifier: "new",
          errorMessage: null, durationMs: 150, initiatedBy: "test",
          createdAt: new Date(),
        },
      ];

      const summary = generateRotationSummary(policies, auditEntries);
      expect(summary.totalPolicies).toBe(2);
      expect(summary.enabledPolicies).toBe(1);
      expect(summary.duePolicies).toBe(1); // first policy never rotated
      expect(summary.recentRotations).toBe(1);
      expect(summary.failedRotations).toBe(0);
      expect(summary.nextRotationDate).toBeTruthy();
    });
  });
});

// ─── BloodHound Parser Tests ─────────────────────────────────────────────────

describe("BloodHound Parser", () => {
  describe("parseSharpHoundJSON", () => {
    it("parses valid JSON collection", () => {
      const json = JSON.stringify({
        data: [{ ObjectIdentifier: "S-1-5-21-1234" }],
        meta: { type: "users", count: 1, methods: 0, version: 5 },
      });
      const result = parseSharpHoundJSON(json);
      expect(result).toBeTruthy();
      expect(result!.meta.type).toBe("users");
      expect(result!.data).toHaveLength(1);
    });

    it("returns null for invalid JSON", () => {
      expect(parseSharpHoundJSON("not json")).toBeNull();
    });

    it("returns null for JSON without meta/data", () => {
      expect(parseSharpHoundJSON(JSON.stringify({ foo: "bar" }))).toBeNull();
    });
  });

  describe("detectCollectionType", () => {
    it("detects type from meta", () => {
      expect(detectCollectionType("file.json", { type: "users", count: 1, methods: 0, version: 5 })).toBe("users");
      expect(detectCollectionType("file.json", { type: "groups", count: 1, methods: 0, version: 5 })).toBe("groups");
      expect(detectCollectionType("file.json", { type: "computers", count: 1, methods: 0, version: 5 })).toBe("computers");
      expect(detectCollectionType("file.json", { type: "domains", count: 1, methods: 0, version: 5 })).toBe("domains");
      expect(detectCollectionType("file.json", { type: "gpos", count: 1, methods: 0, version: 5 })).toBe("gpos");
      expect(detectCollectionType("file.json", { type: "ous", count: 1, methods: 0, version: 5 })).toBe("ous");
    });

    it("detects type from filename when no meta", () => {
      expect(detectCollectionType("20260101_users.json")).toBe("users");
      expect(detectCollectionType("groups_corp.json")).toBe("groups");
      expect(detectCollectionType("computers.json")).toBe("computers");
    });

    it("returns unknown for unrecognized data", () => {
      expect(detectCollectionType("random.json")).toBe("unknown");
    });
  });

  describe("parseUsers", () => {
    it("parses user objects into nodes", () => {
      const users = [
        {
          ObjectIdentifier: "S-1-5-21-1234-5678-9012-1001",
          Properties: {
            name: "admin@CORP.LOCAL",
            displayname: "Admin User",
            enabled: true,
            admincount: true,
            hasspn: true,
            dontreqpreauth: false,
            unconstraineddelegation: false,
            highvalue: true,
          },
          Aces: [
            {
              PrincipalSID: "S-1-5-21-1234-5678-9012-512",
              PrincipalType: "Group",
              RightName: "GenericAll",
              IsInherited: false,
            },
          ],
        },
      ];

      const result = parseUsers(users);

      expect(result.nodes).toHaveLength(1);
      expect(result.nodes[0].id).toBe("S-1-5-21-1234-5678-9012-1001");
      expect(result.nodes[0].label).toBe("admin@CORP.LOCAL");
      expect(result.nodes[0].isHighValue).toBe(true);
      expect(result.nodes[0].riskScore).toBeGreaterThan(0);
    });

    it("generates ACE edges", () => {
      const users = [
        {
          ObjectIdentifier: "S-1-5-21-1234-5678-9012-1001",
          Properties: { name: "admin@CORP.LOCAL", enabled: true },
          Aces: [
            {
              PrincipalSID: "S-1-5-21-1234-5678-9012-512",
              PrincipalType: "Group",
              RightName: "WriteDacl",
              IsInherited: false,
            },
            {
              PrincipalSID: "S-1-5-21-1234-5678-9012-513",
              PrincipalType: "Group",
              RightName: "WriteOwner",
              IsInherited: false,
            },
          ],
        },
      ];

      const result = parseUsers(users);
      expect(result.edges.length).toBeGreaterThanOrEqual(2);

      const writeDaclEdge = result.edges.find(
        e => e.source === "S-1-5-21-1234-5678-9012-512" && e.type === "writeDacl"
      );
      expect(writeDaclEdge).toBeTruthy();
    });
  });

  describe("parseGroups", () => {
    it("parses group objects with members", () => {
      const groups = [
        {
          ObjectIdentifier: "S-1-5-21-1234-5678-9012-512",
          Properties: {
            name: "Domain Admins@CORP.LOCAL",
            admincount: true,
            highvalue: true,
          },
          Members: [
            { ObjectIdentifier: "S-1-5-21-1234-5678-9012-1001", ObjectType: "User" },
          ],
          Aces: [],
        },
      ];

      const result = parseGroups(groups);

      expect(result.nodes).toHaveLength(1);
      expect(result.nodes[0].type).toBe("group");
      expect(result.nodes[0].isHighValue).toBe(true);

      const memberEdge = result.edges.find(
        e => e.source === "S-1-5-21-1234-5678-9012-1001" && e.target === "S-1-5-21-1234-5678-9012-512"
      );
      expect(memberEdge).toBeTruthy();
      expect(memberEdge!.type).toBe("memberOf");
    });
  });

  describe("parseComputers", () => {
    it("parses computer objects", () => {
      const computers = [
        {
          ObjectIdentifier: "S-1-5-21-1234-5678-9012-1000",
          Properties: {
            name: "DC01.CORP.LOCAL",
            operatingsystem: "Windows Server 2019",
            enabled: true,
            unconstraineddelegation: true,
            highvalue: true,
          },
          Aces: [],
        },
      ];

      const result = parseComputers(computers);

      expect(result.nodes).toHaveLength(1);
      // DC01 should be detected as DC
      expect(result.nodes[0].type).toBe("dc");
      expect(result.nodes[0].isHighValue).toBe(true);
    });
  });

  describe("mergeCollections", () => {
    it("merges multiple collections and deduplicates", () => {
      const collections: { filename: string; collection: BloodHoundCollection }[] = [
        {
          filename: "users.json",
          collection: {
            meta: { type: "users", count: 1, methods: 0, version: 5 },
            data: [
              {
                ObjectIdentifier: "S-1-5-21-1234-5678-9012-1001",
                Properties: { name: "admin@CORP.LOCAL", enabled: true, hasspn: true, dontreqpreauth: true },
                Aces: [{ PrincipalSID: "S-1-5-21-1234-5678-9012-512", PrincipalType: "Group", RightName: "GenericAll", IsInherited: false }],
              },
            ],
          },
        },
        {
          filename: "groups.json",
          collection: {
            meta: { type: "groups", count: 1, methods: 0, version: 5 },
            data: [
              {
                ObjectIdentifier: "S-1-5-21-1234-5678-9012-512",
                Properties: { name: "Domain Admins@CORP.LOCAL", admincount: true, highvalue: true },
                Members: [{ ObjectIdentifier: "S-1-5-21-1234-5678-9012-1001", ObjectType: "User" }],
                Aces: [],
              },
            ],
          },
        },
      ];

      const result = mergeCollections(collections);

      expect(result.stats.totalUsers).toBe(1);
      expect(result.stats.totalGroups).toBe(1);
      expect(result.stats.kerberoastableUsers).toBe(1);
      expect(result.stats.asrepRoastableUsers).toBe(1);
      expect(result.stats.filesParsed).toBe(2);
      expect(result.nodes.length).toBeGreaterThanOrEqual(2);
      expect(result.edges.length).toBeGreaterThanOrEqual(1);
    });

    it("handles empty collections gracefully", () => {
      const result = mergeCollections([]);
      expect(result.nodes).toHaveLength(0);
      expect(result.edges).toHaveLength(0);
      expect(result.stats.filesParsed).toBe(0);
    });
  });
});
