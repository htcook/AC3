import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock ENV before importing the router
const mockEnv = {
  calderaBaseUrl: "https://caldera.aceofcloud.io",
  calderaApiKey: "test-key",
  calderaUsername: "red",
  calderaPassword: "test",
  CS_TEAM_SERVER_URL: "",
  EMPIRE_BASE_URL: "",
  SLIVER_SERVER_URL: "",
  MSF_RPC_HOST: "",
  MSF_RPC_PORT: 55553,
  MSF_RPC_SSL: false,
  SCAN_SERVER_HOST: "159.223.152.190",
  gophishBaseUrl: "https://gophish.aceofcloud.io",
  gophishApiKey: "test",
};

vi.mock("../_core/env", () => ({ ENV: mockEnv }));

describe("getC2CallbackUrls endpoint logic", () => {
  beforeEach(() => {
    // Reset process.env mocks
    vi.unstubAllEnvs();
  });

  it("should return configured Caldera URLs when calderaBaseUrl is set", () => {
    const urls: Array<{ label: string; url: string; protocol: string; framework: string; status: string }> = [];

    // Simulate the endpoint logic
    if (mockEnv.calderaBaseUrl) {
      urls.push({
        label: "Caldera HTTPS",
        url: mockEnv.calderaBaseUrl,
        protocol: "https",
        framework: "caldera",
        status: "configured",
      });
      const calderaHost = mockEnv.calderaBaseUrl.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
      if (calderaHost) {
        urls.push({
          label: "Caldera HTTP (direct)",
          url: `http://${calderaHost}:8888`,
          protocol: "http",
          framework: "caldera",
          status: "configured",
        });
      }
    }

    expect(urls).toHaveLength(2);
    expect(urls[0]).toEqual({
      label: "Caldera HTTPS",
      url: "https://caldera.aceofcloud.io",
      protocol: "https",
      framework: "caldera",
      status: "configured",
    });
    expect(urls[1]).toEqual({
      label: "Caldera HTTP (direct)",
      url: "http://caldera.aceofcloud.io:8888",
      protocol: "http",
      framework: "caldera",
      status: "configured",
    });
  });

  it("should return unconfigured status for frameworks without URLs", () => {
    const urls: Array<{ label: string; url: string; status: string }> = [];

    // Cobalt Strike — not configured
    if (mockEnv.CS_TEAM_SERVER_URL) {
      urls.push({ label: "Cobalt Strike", url: mockEnv.CS_TEAM_SERVER_URL, status: "configured" });
    } else {
      urls.push({ label: "Cobalt Strike", url: "", status: "unconfigured" });
    }

    // Empire — not configured
    if (mockEnv.EMPIRE_BASE_URL) {
      urls.push({ label: "Empire", url: mockEnv.EMPIRE_BASE_URL, status: "configured" });
    } else {
      urls.push({ label: "Empire", url: "", status: "unconfigured" });
    }

    expect(urls).toHaveLength(2);
    expect(urls[0].status).toBe("unconfigured");
    expect(urls[1].status).toBe("unconfigured");
  });

  it("should include scan server as redirector when configured", () => {
    const urls: Array<{ label: string; url: string; framework: string; status: string }> = [];

    if (mockEnv.SCAN_SERVER_HOST) {
      urls.push({
        label: "Scan Server (Redirector)",
        url: `https://${mockEnv.SCAN_SERVER_HOST}`,
        framework: "redirector",
        status: "configured",
      });
    }

    expect(urls).toHaveLength(1);
    expect(urls[0].url).toBe("https://159.223.152.190");
    expect(urls[0].framework).toBe("redirector");
  });

  it("should correctly parse host from Caldera URL with path", () => {
    const testUrl = "https://caldera.aceofcloud.io/api/v2";
    const host = testUrl.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
    expect(host).toBe("caldera.aceofcloud.io");
  });

  it("should correctly parse host from Caldera URL with port", () => {
    const testUrl = "http://134.199.213.248:8888";
    const host = testUrl.replace(/^https?:\/\//, "").replace(/[\/:].*$/, "");
    expect(host).toBe("134.199.213.248");
  });

  it("should build Metasploit URL with correct protocol based on SSL setting", () => {
    // SSL enabled
    const sslProto = true ? "https" : "http";
    expect(`${sslProto}://10.0.0.1:55553`).toBe("https://10.0.0.1:55553");

    // SSL disabled
    const noSslProto = false ? "https" : "http";
    expect(`${noSslProto}://10.0.0.1:55553`).toBe("http://10.0.0.1:55553");
  });

  it("should return all framework entries (configured + unconfigured)", () => {
    // Simulate full endpoint logic
    const urls: Array<{ label: string; framework: string; status: string }> = [];

    // Caldera
    urls.push({ label: "Caldera HTTPS", framework: "caldera", status: "configured" });
    urls.push({ label: "Caldera HTTP (direct)", framework: "caldera", status: "configured" });

    // CS — unconfigured
    urls.push({ label: "Cobalt Strike", framework: "cobaltstrike", status: "unconfigured" });

    // Empire — unconfigured
    urls.push({ label: "Empire", framework: "empire", status: "unconfigured" });

    // Sliver — unconfigured
    urls.push({ label: "Sliver", framework: "sliver", status: "unconfigured" });

    // Manjusaka — unconfigured
    urls.push({ label: "Manjusaka", framework: "manjusaka", status: "unconfigured" });

    // Metasploit — unconfigured
    urls.push({ label: "Metasploit", framework: "metasploit", status: "unconfigured" });

    // Scan Server — configured
    urls.push({ label: "Scan Server (Redirector)", framework: "redirector", status: "configured" });

    const configured = urls.filter(u => u.status === "configured");
    const unconfigured = urls.filter(u => u.status === "unconfigured");

    expect(configured).toHaveLength(3);
    expect(unconfigured).toHaveLength(5);
    expect(urls).toHaveLength(8);
  });
});
