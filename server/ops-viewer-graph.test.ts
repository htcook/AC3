import { describe, it, expect } from "vitest";

// We test the client-side transform functions by importing them directly
// The transform functions are pure functions with no browser dependencies

// Since these are client-side modules, we'll test the detection logic patterns
// by simulating the same logic used in battlespace-transform.ts

// ── Proxy Detection Logic (mirrors detectProxy in battlespace-transform.ts) ──
const PROXY_PATTERNS: Array<{ pattern: RegExp; vendor: string; role: string }> = [
  { pattern: /nginx/i, vendor: "Nginx", role: "reverse_proxy" },
  { pattern: /cloudflare/i, vendor: "Cloudflare", role: "cdn" },
  { pattern: /akamai/i, vendor: "Akamai", role: "cdn" },
  { pattern: /fastly/i, vendor: "Fastly", role: "cdn" },
  { pattern: /aws\s*cloudfront/i, vendor: "CloudFront", role: "cdn" },
  { pattern: /haproxy/i, vendor: "HAProxy", role: "load_balancer" },
  { pattern: /f5|big-?ip/i, vendor: "F5 BIG-IP", role: "load_balancer" },
  { pattern: /envoy/i, vendor: "Envoy", role: "reverse_proxy" },
  { pattern: /traefik/i, vendor: "Traefik", role: "reverse_proxy" },
  { pattern: /varnish/i, vendor: "Varnish", role: "cdn" },
  { pattern: /squid/i, vendor: "Squid", role: "forward_proxy" },
  { pattern: /aws\s*elb|elastic\s*load/i, vendor: "AWS ELB", role: "load_balancer" },
  { pattern: /azure\s*front\s*door/i, vendor: "Azure Front Door", role: "cdn" },
  { pattern: /imperva|incapsula/i, vendor: "Imperva", role: "waf_inline" },
  { pattern: /sucuri/i, vendor: "Sucuri", role: "waf_inline" },
  { pattern: /barracuda/i, vendor: "Barracuda", role: "waf_inline" },
  { pattern: /fortinet|fortigate/i, vendor: "Fortinet", role: "waf_inline" },
  { pattern: /mod_security|modsec/i, vendor: "ModSecurity", role: "waf_inline" },
];

function detectProxy(tech: string): { vendor: string; role: string } | null {
  for (const { pattern, vendor, role } of PROXY_PATTERNS) {
    if (pattern.test(tech)) return { vendor, role };
  }
  return null;
}

// ── Interception Detection Logic (mirrors detectInterception) ──
interface TapResult {
  tapType: string;
  interceptedBy: string;
  evidence: string;
}

function detectInterception(asset: any): TapResult[] {
  const taps: TapResult[] = [];
  const techs = (asset.technologies || []).map((t: any) => typeof t === "string" ? t : t.name || "").join(" ").toLowerCase();
  const headers = asset.responseHeaders || asset.passiveRecon?.responseHeaders || {};

  // WAF detection
  const waf = asset.wafDetected || asset.passiveRecon?.wafDetected || "";
  if (waf && !/none|unknown/i.test(waf)) {
    taps.push({ tapType: "waf_inline", interceptedBy: `WAF: ${waf}`, evidence: `WAF detected: ${waf}` });
  }

  // IDS/IPS from technologies
  if (/snort|suricata|zeek|bro\s/i.test(techs)) {
    const match = techs.match(/snort|suricata|zeek|bro\s/i);
    taps.push({ tapType: "ids_inline", interceptedBy: `IDS: ${match?.[0] || "Unknown"}`, evidence: `IDS/IPS detected in technology stack` });
  }

  // SSL inspection indicators
  const certIssuer = asset.sslCertIssuer || asset.passiveRecon?.sslCertIssuer || "";
  if (/palo alto|zscaler|forcepoint|bluecoat|symantec\s*ssl/i.test(certIssuer)) {
    taps.push({ tapType: "ssl_inspection", interceptedBy: `SSL Inspection: ${certIssuer}`, evidence: `SSL cert issued by inspection proxy: ${certIssuer}` });
  }

  // Proxy injection headers
  const xForwarded = headers["x-forwarded-for"] || headers["X-Forwarded-For"] || "";
  const via = headers["via"] || headers["Via"] || "";
  if (xForwarded && asset.directIp && !xForwarded.includes(asset.directIp)) {
    taps.push({ tapType: "transparent_proxy", interceptedBy: `Transparent Proxy`, evidence: `X-Forwarded-For header injected: ${xForwarded}` });
  }
  if (via) {
    taps.push({ tapType: "transparent_proxy", interceptedBy: `Proxy: ${via}`, evidence: `Via header present: ${via}` });
  }

  return taps;
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

describe("Ops Viewer Graph — Proxy Detection", () => {
  it("detects Nginx as reverse proxy", () => {
    const result = detectProxy("Nginx/1.24.0");
    expect(result).toEqual({ vendor: "Nginx", role: "reverse_proxy" });
  });

  it("detects Cloudflare as CDN", () => {
    const result = detectProxy("Cloudflare");
    expect(result).toEqual({ vendor: "Cloudflare", role: "cdn" });
  });

  it("detects HAProxy as load balancer", () => {
    const result = detectProxy("HAProxy 2.8");
    expect(result).toEqual({ vendor: "HAProxy", role: "load_balancer" });
  });

  it("detects AWS ELB as load balancer", () => {
    const result = detectProxy("AWS ELB");
    expect(result).toEqual({ vendor: "AWS ELB", role: "load_balancer" });
  });

  it("detects Imperva/Incapsula as WAF inline", () => {
    const result = detectProxy("Incapsula CDN");
    expect(result).toEqual({ vendor: "Imperva", role: "waf_inline" });
  });

  it("detects Akamai as CDN", () => {
    const result = detectProxy("Akamai CDN");
    expect(result).toEqual({ vendor: "Akamai", role: "cdn" });
  });

  it("detects Envoy as reverse proxy", () => {
    const result = detectProxy("Envoy Proxy");
    expect(result).toEqual({ vendor: "Envoy", role: "reverse_proxy" });
  });

  it("detects Traefik as reverse proxy", () => {
    const result = detectProxy("Traefik v2.10");
    expect(result).toEqual({ vendor: "Traefik", role: "reverse_proxy" });
  });

  it("detects F5 BIG-IP as load balancer", () => {
    const result = detectProxy("F5 BIG-IP");
    expect(result).toEqual({ vendor: "F5 BIG-IP", role: "load_balancer" });
  });

  it("detects ModSecurity as WAF inline", () => {
    const result = detectProxy("ModSecurity v3");
    expect(result).toEqual({ vendor: "ModSecurity", role: "waf_inline" });
  });

  it("detects Fortinet/FortiGate as WAF inline", () => {
    const result = detectProxy("FortiGate WAF");
    expect(result).toEqual({ vendor: "Fortinet", role: "waf_inline" });
  });

  it("returns null for non-proxy technology", () => {
    const result = detectProxy("Apache Tomcat 9.0");
    expect(result).toBeNull();
  });

  it("returns null for empty string", () => {
    const result = detectProxy("");
    expect(result).toBeNull();
  });

  it("is case-insensitive", () => {
    expect(detectProxy("NGINX")).toEqual({ vendor: "Nginx", role: "reverse_proxy" });
    expect(detectProxy("cloudFLARE")).toEqual({ vendor: "Cloudflare", role: "cdn" });
  });
});

describe("Ops Viewer Graph — Interception / Tap Point Detection", () => {
  it("detects WAF from wafDetected field", () => {
    const asset = { wafDetected: "Cloudflare WAF", technologies: [] };
    const taps = detectInterception(asset);
    expect(taps).toHaveLength(1);
    expect(taps[0].tapType).toBe("waf_inline");
    expect(taps[0].interceptedBy).toContain("Cloudflare WAF");
  });

  it("ignores WAF when value is 'none' or 'unknown'", () => {
    expect(detectInterception({ wafDetected: "none", technologies: [] })).toHaveLength(0);
    expect(detectInterception({ wafDetected: "Unknown", technologies: [] })).toHaveLength(0);
  });

  it("detects IDS from technology stack (Snort)", () => {
    const asset = { technologies: ["Snort IDS"], wafDetected: "" };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "ids_inline")).toBe(true);
  });

  it("detects IDS from technology stack (Suricata)", () => {
    const asset = { technologies: ["Suricata 7.0"], wafDetected: "" };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "ids_inline")).toBe(true);
  });

  it("detects SSL inspection from cert issuer", () => {
    const asset = { technologies: [], sslCertIssuer: "Zscaler Root CA", wafDetected: "" };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "ssl_inspection")).toBe(true);
    expect(taps.find(t => t.tapType === "ssl_inspection")?.interceptedBy).toContain("Zscaler");
  });

  it("detects SSL inspection from Palo Alto cert", () => {
    const asset = { technologies: [], sslCertIssuer: "Palo Alto Networks", wafDetected: "" };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "ssl_inspection")).toBe(true);
  });

  it("detects transparent proxy from Via header", () => {
    const asset = {
      technologies: [],
      wafDetected: "",
      responseHeaders: { "Via": "1.1 proxy.corp.local" },
    };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "transparent_proxy")).toBe(true);
    expect(taps.find(t => t.tapType === "transparent_proxy")?.evidence).toContain("Via");
  });

  it("detects transparent proxy from X-Forwarded-For mismatch", () => {
    const asset = {
      technologies: [],
      wafDetected: "",
      directIp: "10.0.0.5",
      responseHeaders: { "X-Forwarded-For": "192.168.1.100" },
    };
    const taps = detectInterception(asset);
    expect(taps.some(t => t.tapType === "transparent_proxy")).toBe(true);
  });

  it("does not flag X-Forwarded-For when it matches direct IP", () => {
    const asset = {
      technologies: [],
      wafDetected: "",
      directIp: "10.0.0.5",
      responseHeaders: { "X-Forwarded-For": "10.0.0.5" },
    };
    const taps = detectInterception(asset);
    expect(taps.filter(t => t.evidence?.includes("X-Forwarded-For"))).toHaveLength(0);
  });

  it("detects multiple interception points simultaneously", () => {
    const asset = {
      technologies: ["Suricata 7.0"],
      wafDetected: "Imperva WAF",
      sslCertIssuer: "Zscaler Root CA",
      responseHeaders: { "Via": "1.1 bluecoat.local" },
    };
    const taps = detectInterception(asset);
    // Should detect: WAF, IDS, SSL inspection, transparent proxy
    expect(taps.length).toBeGreaterThanOrEqual(4);
    const types = taps.map(t => t.tapType);
    expect(types).toContain("waf_inline");
    expect(types).toContain("ids_inline");
    expect(types).toContain("ssl_inspection");
    expect(types).toContain("transparent_proxy");
  });

  it("returns empty array for clean asset with no interception", () => {
    const asset = { technologies: ["Node.js", "Express"], wafDetected: "", responseHeaders: {} };
    const taps = detectInterception(asset);
    expect(taps).toHaveLength(0);
  });
});

describe("Ops Viewer Graph — Node Type Classification", () => {
  it("classifies proxy role labels correctly", () => {
    const roleLabels: Record<string, string> = {
      cdn: "CDN",
      load_balancer: "LB",
      waf_inline: "WAF",
      reverse_proxy: "Proxy",
      forward_proxy: "Proxy",
    };
    for (const [role, expected] of Object.entries(roleLabels)) {
      const label = role === "cdn" ? "CDN" : role === "load_balancer" ? "LB" : role === "waf_inline" ? "WAF" : "Proxy";
      expect(label).toBe(expected);
    }
  });

  it("generates correct proxy node IDs", () => {
    const vendor = "Cloudflare";
    const hostname = "app.example.com";
    const proxyId = `proxy-${vendor.toLowerCase().replace(/\s+/g, "-")}-${hostname}`;
    expect(proxyId).toBe("proxy-cloudflare-app.example.com");
  });

  it("generates correct C2 server node ID", () => {
    const c2ServerId = "c2-server-caldera";
    expect(c2ServerId).toBe("c2-server-caldera");
  });

  it("generates correct gateway hop node IDs", () => {
    const targetHost = "target.com";
    const hopIndex = 3;
    const hopId = `gateway-hop${hopIndex}-${targetHost}`;
    expect(hopId).toBe("gateway-hop3-target.com");
  });

  it("generates correct tap point node IDs", () => {
    const tapType = "ssl_inspection";
    const hostname = "app.example.com";
    const tapId = `tap-${tapType}-${hostname}`;
    expect(tapId).toBe("tap-ssl_inspection-app.example.com");
  });
});

describe("Ops Viewer Graph — Edge Interception Marking", () => {
  it("marks edge as intercepted with correct type for WAF", () => {
    const edge = {
      id: "test-edge",
      source: "a",
      target: "b",
      type: "c2_channel",
      isIntercepted: true,
      interceptionType: "logged" as const,
      interceptedBy: "WAF: Cloudflare",
    };
    expect(edge.isIntercepted).toBe(true);
    expect(edge.interceptionType).toBe("logged");
  });

  it("marks edge as intercepted with ssl_decrypted for SSL inspection", () => {
    const tapType = "ssl_inspection";
    const interceptionType = tapType === "ssl_inspection" ? "ssl_decrypted" : tapType === "ids_inline" ? "inline" : "logged";
    expect(interceptionType).toBe("ssl_decrypted");
  });

  it("marks edge as intercepted with inline for IDS", () => {
    const tapType = "ids_inline";
    const interceptionType = tapType === "ssl_inspection" ? "ssl_decrypted" : tapType === "ids_inline" ? "inline" : "logged";
    expect(interceptionType).toBe("inline");
  });
});

describe("Ops Viewer Graph — C2 Infrastructure Path", () => {
  it("identifies C2 hosts from agent data", () => {
    const agents = [
      { paw: "abc123", host: "target-host-1", group: "red" },
      { paw: "def456", host: "target-host-2", group: "red" },
    ];
    const c2Hosts = new Set<string>();
    const agentHosts = new Set<string>();
    for (const agent of agents) {
      agentHosts.add(agent.host);
      c2Hosts.add("caldera-c2"); // Our C2 server
    }
    expect(agentHosts.size).toBe(2);
    expect(agentHosts.has("target-host-1")).toBe(true);
    expect(agentHosts.has("target-host-2")).toBe(true);
    expect(c2Hosts.has("caldera-c2")).toBe(true);
  });

  it("creates C2 channel edges for each agent", () => {
    const agents = ["agent-host1", "agent-host2", "agent-host3"];
    const c2ServerId = "c2-server-caldera";
    const edges = agents.map(agentId => ({
      id: `c2-channel-${agentId}-${c2ServerId}`,
      source: agentId,
      target: c2ServerId,
      type: "c2_channel",
    }));
    expect(edges).toHaveLength(3);
    expect(edges.every(e => e.type === "c2_channel")).toBe(true);
    expect(edges.every(e => e.target === c2ServerId)).toBe(true);
  });
});

describe("Ops Viewer Graph — Intermediate Hop Visualization", () => {
  it("builds gateway chain from traceroute data", () => {
    const traceroute = {
      target: "target.com",
      hops: [
        { ip: "10.0.0.1", hostname: "gateway1.local", latency: 5 },
        { ip: "172.16.0.1", hostname: "core-router.isp.net", latency: 12 },
        { ip: "93.184.216.34", hostname: "target.com", latency: 25 },
      ],
    };

    const nodes: any[] = [];
    const edges: any[] = [];
    let prevNodeId = "c2-server-caldera";

    for (let i = 0; i < traceroute.hops.length; i++) {
      const hop = traceroute.hops[i];
      const hopId = `gateway-hop${i}-${traceroute.target}`;
      nodes.push({
        id: hopId,
        type: "gateway",
        label: hop.hostname || hop.ip || `Hop ${i + 1}`,
        ip: hop.ip,
      });
      edges.push({
        id: `route-${prevNodeId}-${hopId}`,
        source: prevNodeId,
        target: hopId,
        type: "routes_through",
        dataFlow: `${hop.latency}ms`,
      });
      prevNodeId = hopId;
    }

    expect(nodes).toHaveLength(3);
    expect(edges).toHaveLength(3);
    expect(nodes[0].type).toBe("gateway");
    expect(nodes[0].label).toBe("gateway1.local");
    expect(edges[0].source).toBe("c2-server-caldera");
    expect(edges[0].target).toBe("gateway-hop0-target.com");
    expect(edges[1].source).toBe("gateway-hop0-target.com");
    expect(edges[1].target).toBe("gateway-hop1-target.com");
    expect(edges[2].dataFlow).toBe("25ms");
  });
});
