import "./chunk-KFQGP6VL.js";

// server/lib/cicd-sbom-generator.ts
function extractComponents(findings) {
  const componentMap = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const techs = extractTechnologies(finding);
    for (const tech of techs) {
      const key = `${tech.name}@${tech.version}`;
      if (!componentMap.has(key)) {
        componentMap.set(key, {
          type: tech.type || "library",
          name: tech.name,
          version: tech.version,
          purl: buildPurl(tech.name, tech.version, tech.ecosystem),
          group: tech.group,
          scope: "required"
        });
      }
    }
    if (finding.cve) {
      const cveComponents = extractFromCve(finding);
      for (const comp of cveComponents) {
        const key = `${comp.name}@${comp.version}`;
        if (!componentMap.has(key)) {
          componentMap.set(key, comp);
        }
      }
    }
  }
  return Array.from(componentMap.values());
}
function extractTechnologies(finding) {
  const techs = [];
  const desc = (finding.description || finding.info?.description || "").toLowerCase();
  const name = (finding.name || finding.info?.name || "").toLowerCase();
  const tags = finding.tags || finding.info?.tags || [];
  const matched = finding.matched || finding.matchedAt || "";
  const techPatterns = [
    { regex: /apache\s+([\d.]+)/i, name: "apache-httpd", type: "application", ecosystem: "apache" },
    { regex: /nginx[\/\s]+([\d.]+)/i, name: "nginx", type: "application" },
    { regex: /openssl[\/\s]+([\d.a-z]+)/i, name: "openssl", type: "library" },
    { regex: /php[\/\s]+([\d.]+)/i, name: "php", type: "framework" },
    { regex: /jquery[\/\s]+([\d.]+)/i, name: "jquery", type: "library", ecosystem: "npm" },
    { regex: /wordpress[\/\s]+([\d.]+)/i, name: "wordpress", type: "application" },
    { regex: /react[\/\s]+([\d.]+)/i, name: "react", type: "library", ecosystem: "npm" },
    { regex: /node\.?js[\/\s]+([\d.]+)/i, name: "node.js", type: "framework" },
    { regex: /python[\/\s]+([\d.]+)/i, name: "python", type: "framework" },
    { regex: /tomcat[\/\s]+([\d.]+)/i, name: "apache-tomcat", type: "application", ecosystem: "apache" },
    { regex: /iis[\/\s]+([\d.]+)/i, name: "microsoft-iis", type: "application" },
    { regex: /mysql[\/\s]+([\d.]+)/i, name: "mysql", type: "application" },
    { regex: /postgresql[\/\s]+([\d.]+)/i, name: "postgresql", type: "application" },
    { regex: /redis[\/\s]+([\d.]+)/i, name: "redis", type: "application" },
    { regex: /docker[\/\s]+([\d.]+)/i, name: "docker", type: "container" },
    { regex: /kubernetes[\/\s]+([\d.]+)/i, name: "kubernetes", type: "container" },
    { regex: /spring[- ]boot[\/\s]+([\d.]+)/i, name: "spring-boot", type: "framework", ecosystem: "maven" },
    { regex: /django[\/\s]+([\d.]+)/i, name: "django", type: "framework", ecosystem: "pypi" },
    { regex: /express[\/\s]+([\d.]+)/i, name: "express", type: "framework", ecosystem: "npm" },
    { regex: /laravel[\/\s]+([\d.]+)/i, name: "laravel", type: "framework", ecosystem: "composer" }
  ];
  const fullText = `${desc} ${name} ${matched} ${tags.join(" ")}`;
  for (const pattern of techPatterns) {
    const match = fullText.match(pattern.regex);
    if (match) {
      techs.push({
        name: pattern.name,
        version: match[1],
        type: pattern.type,
        ecosystem: pattern.ecosystem
      });
    }
  }
  const serverHeader = finding.extractedResults?.server || finding.headers?.server || "";
  if (serverHeader) {
    const serverMatch = serverHeader.match(/^([a-zA-Z-]+)[\/\s]+([\d.]+)/);
    if (serverMatch) {
      techs.push({
        name: serverMatch[1].toLowerCase(),
        version: serverMatch[2],
        type: "application"
      });
    }
  }
  return techs;
}
function extractFromCve(finding) {
  const components = [];
  const cve = finding.cve || finding.info?.cve || {};
  if (cve.cpe) {
    const cpes = Array.isArray(cve.cpe) ? cve.cpe : [cve.cpe];
    for (const cpeStr of cpes) {
      const parsed = parseCpe(cpeStr);
      if (parsed) {
        components.push({
          type: parsed.part === "a" ? "application" : parsed.part === "o" ? "operating-system" : "library",
          name: parsed.product,
          version: parsed.version || "unknown",
          cpe: cpeStr,
          group: parsed.vendor
        });
      }
    }
  }
  return components;
}
function parseCpe(cpe) {
  const parts = cpe.split(":");
  if (parts.length >= 6 && parts[0] === "cpe" && parts[1] === "2.3") {
    return {
      part: parts[2],
      vendor: parts[3],
      product: parts[4],
      version: parts[5] !== "*" ? parts[5] : void 0
    };
  }
  if (parts.length >= 4 && parts[0].startsWith("cpe")) {
    const partChar = parts[0].replace("cpe:/", "");
    return {
      part: partChar,
      vendor: parts[1],
      product: parts[2],
      version: parts[3] !== "*" ? parts[3] : void 0
    };
  }
  return null;
}
function buildPurl(name, version, ecosystem) {
  const type = ecosystem || "generic";
  const encodedName = encodeURIComponent(name);
  const encodedVersion = encodeURIComponent(version);
  return `pkg:${type}/${encodedName}@${encodedVersion}`;
}
function mapVulnerabilities(findings, components) {
  const vulnMap = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const cveId = finding.cve?.id || finding.cveId || extractCveId(finding.name || finding.info?.name || "");
    if (!cveId) continue;
    if (vulnMap.has(cveId)) continue;
    const severity = normalizeSeverity(finding.severity || finding.info?.severity || "medium");
    const cvss = finding.cvss || finding.info?.cvss || finding.cve?.cvss || 0;
    const vuln = {
      id: cveId,
      source: { name: "Nuclei Scanner", url: `https://nvd.nist.gov/vuln/detail/${cveId}` },
      ratings: [{
        score: typeof cvss === "number" ? cvss : parseFloat(cvss) || 0,
        severity,
        method: "CVSSv3"
      }],
      description: finding.description || finding.info?.description || `Vulnerability ${cveId} detected`,
      recommendation: finding.remediation || finding.info?.remediation || "Apply vendor patches"
    };
    const affectedComponents = findAffectedComponents(finding, components);
    if (affectedComponents.length > 0) {
      vuln.affects = affectedComponents.map((comp) => ({
        ref: `${comp.name}@${comp.version}`,
        versions: [{ version: comp.version, status: "affected" }]
      }));
    }
    const cwes = finding.cwe || finding.info?.cwe || finding.cve?.cwe || [];
    if (cwes.length > 0) {
      vuln.cwes = cwes.map((c) => typeof c === "number" ? c : parseInt(String(c).replace(/\D/g, "")) || 0).filter((c) => c > 0);
    }
    if (finding.threatContext) {
      vuln.analysis = {
        state: finding.threatContext.activelyExploited ? "exploitable" : "in_triage",
        justification: finding.threatContext.actors?.length ? `Exploited by: ${finding.threatContext.actors.map((a) => a.name || a).join(", ")}` : void 0
      };
    }
    vulnMap.set(cveId, vuln);
  }
  return Array.from(vulnMap.values());
}
function extractCveId(text) {
  const match = text.match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0].toUpperCase() : null;
}
function normalizeSeverity(sev) {
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  if (s === "info" || s === "informational") return "info";
  return "unknown";
}
function findAffectedComponents(finding, components) {
  const desc = (finding.description || finding.info?.description || "").toLowerCase();
  const name = (finding.name || finding.info?.name || "").toLowerCase();
  const fullText = `${desc} ${name}`;
  return components.filter(
    (comp) => fullText.includes(comp.name.toLowerCase()) || comp.cpe && finding.cve?.cpe?.includes(comp.cpe)
  );
}
function generateSbom(params) {
  const { pipelineId, pipelineName, runId, targetUrl, branch, commitSha, findings } = params;
  const components = extractComponents(findings);
  const vulnerabilities = mapVulnerabilities(findings, components);
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${generateUuid()}`,
    version: 1,
    metadata: {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      tools: [
        { vendor: "Ace C3", name: "CI/CD Security Scanner", version: "1.0.0" },
        { vendor: "ProjectDiscovery", name: "Nuclei", version: "3.x" }
      ],
      component: {
        type: "application",
        name: pipelineName,
        version: commitSha || "latest"
      },
      properties: [
        { name: "ace:pipeline:id", value: String(pipelineId) },
        { name: "ace:run:id", value: String(runId) },
        ...targetUrl ? [{ name: "ace:target:url", value: targetUrl }] : [],
        ...branch ? [{ name: "ace:git:branch", value: branch }] : [],
        ...commitSha ? [{ name: "ace:git:commit", value: commitSha }] : [],
        ...params.scanStarted ? [{ name: "ace:scan:started", value: params.scanStarted }] : [],
        ...params.scanCompleted ? [{ name: "ace:scan:completed", value: params.scanCompleted }] : []
      ]
    },
    components,
    vulnerabilities,
    dependencies: buildDependencies(components)
  };
  const stats = {
    totalComponents: components.length,
    totalVulnerabilities: vulnerabilities.length,
    criticalVulns: vulnerabilities.filter((v) => v.ratings?.[0]?.severity === "critical").length,
    highVulns: vulnerabilities.filter((v) => v.ratings?.[0]?.severity === "high").length,
    mediumVulns: vulnerabilities.filter((v) => v.ratings?.[0]?.severity === "medium").length,
    lowVulns: vulnerabilities.filter((v) => v.ratings?.[0]?.severity === "low").length,
    componentTypes: components.reduce((acc, c) => {
      acc[c.type] = (acc[c.type] || 0) + 1;
      return acc;
    }, {}),
    licenseSummary: components.reduce((acc, c) => {
      const lic = c.licenses?.[0]?.id || c.licenses?.[0]?.name || "Unknown";
      acc[lic] = (acc[lic] || 0) + 1;
      return acc;
    }, {})
  };
  return { sbom, stats };
}
function buildDependencies(components) {
  return components.map((comp) => ({
    ref: `${comp.name}@${comp.version}`
  }));
}
function generateUuid() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
function compareSboms(baseline, current) {
  const baseCompKeys = new Set(baseline.components.map((c) => `${c.name}@${c.version}`));
  const currCompKeys = new Set(current.components.map((c) => `${c.name}@${c.version}`));
  const baseVulnKeys = new Set(baseline.vulnerabilities.map((v) => v.id));
  const currVulnKeys = new Set(current.vulnerabilities.map((v) => v.id));
  return {
    addedComponents: current.components.filter((c) => !baseCompKeys.has(`${c.name}@${c.version}`)),
    removedComponents: baseline.components.filter((c) => !currCompKeys.has(`${c.name}@${c.version}`)),
    addedVulnerabilities: current.vulnerabilities.filter((v) => !baseVulnKeys.has(v.id)),
    removedVulnerabilities: baseline.vulnerabilities.filter((v) => !currVulnKeys.has(v.id)),
    unchangedComponents: [...baseCompKeys].filter((k) => currCompKeys.has(k)).length,
    unchangedVulnerabilities: [...baseVulnKeys].filter((k) => currVulnKeys.has(k)).length
  };
}
export {
  buildPurl,
  compareSboms,
  extractComponents,
  generateSbom,
  mapVulnerabilities
};
