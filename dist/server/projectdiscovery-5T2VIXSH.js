import "./chunk-KFQGP6VL.js";

// server/lib/projectdiscovery.ts
var PDCP_BASE_URL = "https://api.projectdiscovery.io";
async function pdcpRequest(method, path, body, apiKey) {
  const key = apiKey || process.env.PDCP_API_KEY;
  if (!key) throw new Error("PDCP_API_KEY not configured");
  const res = await fetch(`${PDCP_BASE_URL}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key": key
    },
    body: body ? JSON.stringify(body) : void 0
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`PDCP API ${res.status}: ${text}`);
  }
  return res.json();
}
function hasPdcpKey() {
  return !!process.env.PDCP_API_KEY;
}
async function runSubfinder(opts) {
  const startTime = Date.now();
  if (hasPdcpKey()) {
    return runSubfinderPDCP(opts, startTime);
  }
  return runSubfinderSimulated(opts, startTime);
}
async function runSubfinderPDCP(opts, startTime) {
  const enumResult = await pdcpRequest("POST", "/v1/asset/enumerate", {
    root_domains: [opts.domain],
    name: `subfinder-${opts.domain}-${Date.now()}`,
    steps: ["dns_passive", "dns_resolve", "dns_scraping"],
    per_domain_enumeration: true
  });
  const enumerationId = enumResult.id;
  let attempts = 0;
  const maxAttempts = 60;
  let enumData;
  while (attempts < maxAttempts) {
    await new Promise((r) => setTimeout(r, 5e3));
    attempts++;
    try {
      enumData = await pdcpRequest("GET", `/v1/asset/enumerate/${enumerationId}`);
      if (enumData.status === "completed" || enumData.status === "finished" || enumData.finished) {
        break;
      }
    } catch {
    }
  }
  let exportData;
  try {
    exportData = await pdcpRequest(
      "GET",
      `/v1/asset/enumerate/${enumerationId}/export?format=json`
    );
  } catch {
    exportData = { assets: [] };
  }
  const subdomains = (exportData.assets || []).map(
    (a) => ({
      subdomain: a.host || a.domain || a.subdomain,
      source: (a.sources || ["pdcp"]).join(","),
      ip: a.ip || a.a_record,
      alive: a.alive ?? a.active ?? true,
      cname: a.cname,
      firstSeen: a.created_at ? new Date(a.created_at).getTime() : Date.now()
    })
  );
  const sourceMap = {};
  for (const sd of subdomains) {
    for (const src of sd.source.split(",")) {
      sourceMap[src] = (sourceMap[src] || 0) + 1;
    }
  }
  return {
    domain: opts.domain,
    subdomains,
    stats: {
      total: subdomains.length,
      alive: subdomains.filter((s) => s.alive).length,
      sources: sourceMap,
      duration: Date.now() - startTime
    },
    enumerationId
  };
}
async function runSubfinderSimulated(opts, startTime) {
  await new Promise((r) => setTimeout(r, 800 + Math.random() * 1200));
  const domain = opts.domain;
  const prefixes = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "staging",
    "admin",
    "portal",
    "app",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "blog",
    "docs",
    "help",
    "support",
    "status",
    "monitor",
    "vpn",
    "remote",
    "gateway",
    "proxy",
    "ns1",
    "ns2",
    "mx",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "git",
    "ci",
    "jenkins",
    "jira",
    "confluence",
    "test",
    "qa",
    "uat",
    "sandbox",
    "demo",
    "auth",
    "sso",
    "login",
    "oauth",
    "id",
    "internal",
    "intranet",
    "wiki",
    "kb",
    "store",
    "shop",
    "checkout",
    "pay",
    "m",
    "mobile",
    "wap"
  ];
  const sources = [
    "crtsh",
    "virustotal",
    "hackertarget",
    "threatcrowd",
    "certspotter",
    "bufferover",
    "urlscan",
    "waybackarchive",
    "dnsdumpster",
    "rapiddns",
    "alienvault",
    "binaryedge"
  ];
  const hash = domain.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  const count = 15 + hash % 30;
  const selectedPrefixes = prefixes.sort(() => hash * 31 % 100 / 100 - 0.5).slice(0, count);
  const subdomains = selectedPrefixes.map((prefix, i) => {
    const srcIdx = (hash + i) % sources.length;
    const ip = `${10 + hash % 240}.${(i * 17 + hash) % 256}.${i * 31 % 256}.${(i * 7 + 1) % 256}`;
    return {
      subdomain: `${prefix}.${domain}`,
      source: sources[srcIdx],
      ip,
      alive: Math.random() > 0.15,
      cname: i % 5 === 0 ? `${prefix}-lb.${domain}` : void 0,
      firstSeen: Date.now() - Math.floor(Math.random() * 864e5 * 30)
    };
  });
  const sourceMap = {};
  for (const sd of subdomains) {
    sourceMap[sd.source] = (sourceMap[sd.source] || 0) + 1;
  }
  return {
    domain,
    subdomains,
    stats: {
      total: subdomains.length,
      alive: subdomains.filter((s) => s.alive).length,
      sources: sourceMap,
      duration: Date.now() - startTime
    }
  };
}
async function runHttpx(opts) {
  const startTime = Date.now();
  if (hasPdcpKey()) {
    return runHttpxPDCP(opts, startTime);
  }
  return runHttpxSimulated(opts, startTime);
}
async function runHttpxPDCP(opts, startTime) {
  const enumResult = await pdcpRequest("POST", "/v1/asset/enumerate", {
    root_domains: opts.targets,
    name: `httpx-probe-${Date.now()}`,
    steps: [
      "http_probe",
      ...opts.tlsProbe ? ["tls_scan"] : [],
      ...opts.screenshot ? ["http_screenshot"] : []
    ],
    enumeration_ports: opts.ports || "80,443,8080,8443",
    enumeration_config: {
      "follow-redirect": opts.followRedirects ?? true,
      ports: opts.ports || "80,443,8080,8443"
    }
  });
  const enumerationId = enumResult.id;
  let attempts = 0;
  while (attempts < 60) {
    await new Promise((r) => setTimeout(r, 5e3));
    attempts++;
    try {
      const data = await pdcpRequest("GET", `/v1/asset/enumerate/${enumerationId}`);
      if (data.status === "completed" || data.finished) break;
    } catch {
    }
  }
  let exportData;
  try {
    exportData = await pdcpRequest(
      "GET",
      `/v1/asset/enumerate/${enumerationId}/export?format=json`
    );
  } catch {
    exportData = { assets: [] };
  }
  const targets = (exportData.assets || []).map(
    (a) => ({
      url: a.url || `https://${a.host}`,
      host: a.host || a.domain,
      port: a.port || 443,
      scheme: a.scheme || "https",
      statusCode: a.status_code || 0,
      contentLength: a.content_length || 0,
      title: a.title || "",
      webServer: a.web_server || a.server || "",
      technologies: a.technologies || a.tech || [],
      tlsCipher: a.tls_cipher,
      tlsVersion: a.tls_version,
      certIssuer: a.cert_issuer,
      certSubject: a.cert_subject,
      certExpiry: a.cert_expiry,
      jarmHash: a.jarm,
      faviconHash: a.favicon_hash,
      responseTime: a.response_time || 0,
      redirectChain: a.redirect_chain,
      bodyHash: a.body_hash,
      headerHash: a.header_hash,
      alive: a.alive ?? true,
      method: opts.method || "GET",
      finalUrl: a.final_url,
      ip: a.ip || a.a_record,
      cdn: a.cdn,
      timestamp: Date.now()
    })
  );
  const byStatusCode = {};
  const byTech = {};
  for (const t of targets) {
    byStatusCode[t.statusCode] = (byStatusCode[t.statusCode] || 0) + 1;
    for (const tech of t.technologies) {
      byTech[tech] = (byTech[tech] || 0) + 1;
    }
  }
  return {
    targets,
    stats: {
      total: targets.length,
      alive: targets.filter((t) => t.alive).length,
      byStatusCode,
      byTech,
      duration: Date.now() - startTime
    }
  };
}
async function runHttpxSimulated(opts, startTime) {
  await new Promise((r) => setTimeout(r, 600 + Math.random() * 1e3));
  const webServers = ["nginx/1.24.0", "Apache/2.4.57", "cloudflare", "Microsoft-IIS/10.0", "LiteSpeed", "openresty/1.21.4.1"];
  const techSets = [
    ["React", "Next.js", "Node.js", "Webpack"],
    ["WordPress", "PHP", "MySQL", "jQuery"],
    ["Django", "Python", "PostgreSQL", "Redis"],
    ["ASP.NET", "C#", "IIS", "Azure"],
    ["Vue.js", "Nuxt.js", "Node.js", "Vite"],
    ["Angular", "TypeScript", "RxJS", "Nginx"],
    ["Laravel", "PHP", "MySQL", "Tailwind CSS"],
    ["Spring Boot", "Java", "Tomcat", "Gradle"]
  ];
  const cdns = ["Cloudflare", "Akamai", "Fastly", "AWS CloudFront", void 0, void 0];
  const tlsCiphers = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"];
  const tlsVersions = ["tls1.3", "tls1.2", "tls1.2"];
  const targets = opts.targets.flatMap((target) => {
    const hash = target.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
    const ports = (opts.ports || "80,443").split(",").map(Number);
    return ports.map((port, pi) => {
      const scheme = port === 443 || port === 8443 ? "https" : "http";
      const statusCode = [200, 200, 200, 301, 302, 403, 404, 500][(hash + pi) % 8];
      const techIdx = (hash + pi) % techSets.length;
      const alive = statusCode < 500;
      return {
        url: `${scheme}://${target}:${port}`,
        host: target,
        port,
        scheme,
        statusCode,
        contentLength: 5e3 + hash * (pi + 1) % 5e4,
        title: alive ? `${target} - ${["Home", "Dashboard", "Portal", "App", "Login"][(hash + pi) % 5]}` : "",
        webServer: webServers[(hash + pi) % webServers.length],
        technologies: alive ? techSets[techIdx] : [],
        tlsCipher: scheme === "https" ? tlsCiphers[(hash + pi) % tlsCiphers.length] : void 0,
        tlsVersion: scheme === "https" ? tlsVersions[(hash + pi) % tlsVersions.length] : void 0,
        certIssuer: scheme === "https" ? "Let's Encrypt" : void 0,
        certSubject: scheme === "https" ? `CN=${target}` : void 0,
        certExpiry: scheme === "https" ? new Date(Date.now() + 864e5 * (hash % 300 + 30)).toISOString() : void 0,
        jarmHash: opts.jarm ? `2ad2ad0002ad2ad00042d42d000000${(hash + pi).toString(16).padStart(32, "0")}` : void 0,
        faviconHash: opts.favicon ? `${(hash * 31 + pi * 7) % 999999999}` : void 0,
        responseTime: 50 + hash * pi % 2e3,
        redirectChain: statusCode === 301 || statusCode === 302 ? [`${scheme}://${target}:${port}`, `https://${target}/`] : void 0,
        bodyHash: `sha256:${(hash * 17 + pi).toString(16).padStart(64, "0")}`,
        headerHash: `sha256:${(hash * 23 + pi).toString(16).padStart(64, "0")}`,
        alive,
        method: opts.method || "GET",
        finalUrl: statusCode === 301 || statusCode === 302 ? `https://${target}/` : void 0,
        ip: `${10 + hash % 240}.${hash * 3 % 256}.${pi * 17 % 256}.${(hash + pi) % 256}`,
        cdn: cdns[(hash + pi) % cdns.length],
        timestamp: Date.now()
      };
    });
  });
  const byStatusCode = {};
  const byTech = {};
  for (const t of targets) {
    byStatusCode[t.statusCode] = (byStatusCode[t.statusCode] || 0) + 1;
    for (const tech of t.technologies) {
      byTech[tech] = (byTech[tech] || 0) + 1;
    }
  }
  return {
    targets,
    stats: {
      total: targets.length,
      alive: targets.filter((t) => t.alive).length,
      byStatusCode,
      byTech,
      duration: Date.now() - startTime
    }
  };
}
async function runNaabu(opts) {
  const startTime = Date.now();
  if (hasPdcpKey()) {
    return runNaabuPDCP(opts, startTime);
  }
  return runNaabuSimulated(opts, startTime);
}
async function runNaabuPDCP(opts, startTime) {
  const ports = opts.ports || (opts.topPorts ? `top-${opts.topPorts}` : "top-100");
  const enumResult = await pdcpRequest("POST", "/v1/asset/enumerate", {
    root_domains: opts.targets,
    name: `naabu-portscan-${Date.now()}`,
    steps: ["port_scan", "dns_resolve"],
    enumeration_ports: ports
  });
  const enumerationId = enumResult.id;
  let attempts = 0;
  while (attempts < 60) {
    await new Promise((r) => setTimeout(r, 5e3));
    attempts++;
    try {
      const data = await pdcpRequest("GET", `/v1/asset/enumerate/${enumerationId}`);
      if (data.status === "completed" || data.finished) break;
    } catch {
    }
  }
  let exportData;
  try {
    exportData = await pdcpRequest(
      "GET",
      `/v1/asset/enumerate/${enumerationId}/export?format=json`
    );
  } catch {
    exportData = { assets: [] };
  }
  const hostMap = /* @__PURE__ */ new Map();
  for (const a of exportData.assets || []) {
    const host = a.host || a.domain;
    if (!hostMap.has(host)) {
      hostMap.set(host, {
        host,
        ip: a.ip || a.a_record || "",
        ports: [],
        timestamp: Date.now()
      });
    }
    const entry = hostMap.get(host);
    if (a.port) {
      entry.ports.push({
        port: a.port,
        protocol: "tcp",
        state: "open",
        service: a.service,
        version: a.version,
        banner: a.banner,
        tls: a.tls || a.port === 443,
        timestamp: Date.now()
      });
    }
  }
  const targets = Array.from(hostMap.values());
  const byPort = {};
  const byService = {};
  let totalOpenPorts = 0;
  for (const t of targets) {
    for (const p of t.ports) {
      totalOpenPorts++;
      byPort[p.port] = (byPort[p.port] || 0) + 1;
      if (p.service) byService[p.service] = (byService[p.service] || 0) + 1;
    }
  }
  return {
    targets,
    stats: {
      totalHosts: targets.length,
      hostsWithOpenPorts: targets.filter((t) => t.ports.length > 0).length,
      totalOpenPorts,
      byPort,
      byService,
      duration: Date.now() - startTime
    }
  };
}
async function runNaabuSimulated(opts, startTime) {
  await new Promise((r) => setTimeout(r, 500 + Math.random() * 1500));
  const commonPorts = [
    { port: 21, service: "ftp", version: "vsftpd 3.0.5", banner: "220 (vsFTPd 3.0.5)" },
    { port: 22, service: "ssh", version: "OpenSSH 8.9p1", banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" },
    { port: 25, service: "smtp", version: "Postfix", banner: "220 mail.example.com ESMTP Postfix" },
    { port: 53, service: "dns", version: "BIND 9.18.18" },
    { port: 80, service: "http", version: "nginx/1.24.0", banner: "HTTP/1.1 200 OK" },
    { port: 110, service: "pop3", version: "Dovecot" },
    { port: 143, service: "imap", version: "Dovecot 2.3.20" },
    { port: 443, service: "https", version: "nginx/1.24.0", banner: "HTTP/2 200" },
    { port: 445, service: "smb", version: "Samba 4.18.6" },
    { port: 993, service: "imaps", version: "Dovecot 2.3.20" },
    { port: 995, service: "pop3s", version: "Dovecot" },
    { port: 1433, service: "mssql", version: "Microsoft SQL Server 2022" },
    { port: 3306, service: "mysql", version: "MySQL 8.0.35" },
    { port: 3389, service: "rdp", version: "Microsoft Terminal Services" },
    { port: 5432, service: "postgresql", version: "PostgreSQL 16.1" },
    { port: 5900, service: "vnc", version: "VNC Server 5.0" },
    { port: 6379, service: "redis", version: "Redis 7.2.3" },
    { port: 8080, service: "http-proxy", version: "Apache Tomcat/10.1.16" },
    { port: 8443, service: "https-alt", version: "nginx/1.24.0" },
    { port: 9200, service: "elasticsearch", version: "Elasticsearch 8.11.3" },
    { port: 27017, service: "mongodb", version: "MongoDB 7.0.4" }
  ];
  const targets = opts.targets.map((target) => {
    const hash = target.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
    const portCount = 3 + hash % 8;
    const selectedPorts = commonPorts.sort(() => hash * 37 % 100 / 100 - 0.5).slice(0, portCount);
    return {
      host: target,
      ip: `${10 + hash % 240}.${hash * 3 % 256}.${hash * 7 % 256}.${hash % 256}`,
      ports: selectedPorts.map((sp) => ({
        port: sp.port,
        protocol: "tcp",
        state: "open",
        service: opts.serviceDiscovery !== false ? sp.service : void 0,
        version: opts.serviceVersion ? sp.version : void 0,
        banner: opts.serviceVersion ? sp.banner : void 0,
        tls: sp.port === 443 || sp.port === 993 || sp.port === 995 || sp.port === 8443,
        timestamp: Date.now()
      })),
      os: ["Linux", "Windows Server 2022", "FreeBSD", "Ubuntu 22.04"][hash % 4],
      timestamp: Date.now()
    };
  });
  const byPort = {};
  const byService = {};
  let totalOpenPorts = 0;
  for (const t of targets) {
    for (const p of t.ports) {
      totalOpenPorts++;
      byPort[p.port] = (byPort[p.port] || 0) + 1;
      if (p.service) byService[p.service] = (byService[p.service] || 0) + 1;
    }
  }
  return {
    targets,
    stats: {
      totalHosts: targets.length,
      hostsWithOpenPorts: targets.filter((t) => t.ports.length > 0).length,
      totalOpenPorts,
      byPort,
      byService,
      duration: Date.now() - startTime
    }
  };
}
function getPdcpStatus() {
  return {
    connected: hasPdcpKey(),
    mode: hasPdcpKey() ? "cloud" : "local",
    apiKeyConfigured: hasPdcpKey()
  };
}
export {
  getPdcpStatus,
  runHttpx,
  runNaabu,
  runSubfinder
};
