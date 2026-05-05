import "./chunk-KFQGP6VL.js";

// server/lib/passive/active-handoff.ts
var TECH_TO_NUCLEI_TAGS = {
  // Web servers
  "apache": ["apache", "cve", "misconfig"],
  "nginx": ["nginx", "cve", "misconfig"],
  "iis": ["iis", "cve", "misconfig"],
  "tomcat": ["tomcat", "cve", "default-login"],
  "jetty": ["jetty", "cve"],
  // Frameworks
  "wordpress": ["wordpress", "wp-plugin", "cve"],
  "drupal": ["drupal", "cve"],
  "joomla": ["joomla", "cve"],
  "laravel": ["laravel", "cve"],
  "django": ["django", "cve"],
  "spring": ["spring", "springboot", "cve"],
  "struts": ["struts", "cve"],
  "rails": ["rails", "cve"],
  "express": ["express", "nodejs", "cve"],
  "nextjs": ["nextjs", "cve"],
  "react": ["react", "cve"],
  "angular": ["angular", "cve"],
  "vue": ["vue", "cve"],
  // CMS / Platforms
  "sharepoint": ["sharepoint", "cve"],
  "confluence": ["confluence", "cve"],
  "jira": ["jira", "cve"],
  "gitlab": ["gitlab", "cve"],
  "jenkins": ["jenkins", "cve", "default-login"],
  "grafana": ["grafana", "cve", "default-login"],
  "kibana": ["kibana", "cve"],
  "elasticsearch": ["elasticsearch", "cve", "misconfig"],
  // Languages
  "php": ["php", "cve"],
  "java": ["java", "cve", "log4j"],
  "python": ["python", "cve"],
  "dotnet": ["dotnet", "cve"],
  // Databases
  "mysql": ["mysql", "cve", "default-login"],
  "postgresql": ["postgresql", "cve"],
  "mongodb": ["mongodb", "cve", "misconfig"],
  "redis": ["redis", "cve", "misconfig"],
  "mssql": ["mssql", "cve", "default-login"],
  // Cloud / Infrastructure
  "aws": ["aws", "cloud", "misconfig"],
  "azure": ["azure", "cloud", "misconfig"],
  "gcp": ["gcp", "cloud", "misconfig"],
  "docker": ["docker", "cve", "misconfig"],
  "kubernetes": ["kubernetes", "cve", "misconfig"],
  // Security
  "cloudflare": ["cloudflare", "waf"],
  "fortinet": ["fortinet", "cve"],
  "paloalto": ["paloalto", "cve"],
  "citrix": ["citrix", "cve"],
  "f5": ["f5", "bigip", "cve"],
  // Mail
  "exchange": ["exchange", "cve"],
  "zimbra": ["zimbra", "cve"]
};
function isInScope(target, roe) {
  if (roe.excludedAssets.some((e) => target.includes(e) || e.includes(target))) {
    return { inScope: false, reason: `Explicitly excluded by RoE: ${target}` };
  }
  if (roe.exclusionPatterns) {
    for (const pattern of roe.exclusionPatterns) {
      try {
        if (new RegExp(pattern, "i").test(target)) {
          return { inScope: false, reason: `Matches exclusion pattern: ${pattern}` };
        }
      } catch {
      }
    }
  }
  if (roe.scopedAssets.length > 0) {
    const targetWithoutPort = target.includes(":") ? target.split(":")[0] : target;
    const isScoped = roe.scopedAssets.some((s) => {
      const scopeWithoutPort = s.includes(":") ? s.split(":")[0] : s;
      if (s === target || scopeWithoutPort === targetWithoutPort) return true;
      if (s.startsWith("*.") && (target.endsWith(s.slice(1)) || targetWithoutPort.endsWith(s.slice(1)))) return true;
      if (target.endsWith(`.${s}`) || targetWithoutPort.endsWith(`.${scopeWithoutPort}`)) return true;
      return false;
    });
    if (!isScoped) {
      return { inScope: false, reason: `Not in RoE scoped assets list` };
    }
  }
  return { inScope: true };
}
function computeAssetPriority(hostname, observations, riskSignals) {
  let score = 50;
  for (const signal of riskSignals) {
    switch (signal.severity) {
      case "critical":
        score += 15;
        break;
      case "high":
        score += 10;
        break;
      case "medium":
        score += 5;
        break;
      case "low":
        score += 2;
        break;
    }
  }
  score += Math.min(20, observations.length * 2);
  const techTags = /* @__PURE__ */ new Set();
  for (const obs of observations) {
    for (const tag of obs.tags) {
      if (tag.startsWith("tech:")) techTags.add(tag);
    }
  }
  score += Math.min(10, techTags.size * 2);
  const portTags = observations.filter((o) => o.tags.some((t) => t.startsWith("port:")));
  score += Math.min(10, portTags.length);
  return Math.min(100, score);
}
function generateScanForgeConfig(target, roe) {
  const flags = [];
  const rationale = [];
  flags.push("-sV");
  flags.push("-sC");
  const timing = Math.min(roe.maxIntensity, 4);
  flags.push(`-T${timing}`);
  if (target.knownPorts.length > 0) {
    const knownPortNums = target.knownPorts.map((p) => p.port);
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443];
    const allPorts = [.../* @__PURE__ */ new Set([...knownPortNums, ...commonPorts])].sort((a, b) => a - b);
    flags.push(`-p ${allPorts.join(",")}`);
    rationale.push(`Targeting ${knownPortNums.length} known ports + ${commonPorts.length} common ports`);
  } else {
    flags.push("--top-ports 1000");
    rationale.push("No ports from passive recon; scanning top 1000");
  }
  if (roe.maxIntensity >= 3) {
    flags.push("-O");
    rationale.push("OS detection enabled (intensity >= 3)");
  }
  if (roe.maxIntensity >= 4) {
    flags.push("--script=vuln");
    rationale.push("Vulnerability scripts enabled (intensity >= 4)");
  }
  return {
    target: target.hostname,
    flags: flags.join(" "),
    portSpec: target.knownPorts.length > 0 ? target.knownPorts.map((p) => p.port).join(",") : void 0,
    timeout: 300,
    rationale: rationale.join("; ")
  };
}
function generateNucleiConfig(target, roe) {
  const tags = /* @__PURE__ */ new Set(["cve"]);
  const rationale = [];
  for (const tech of target.technologies) {
    const techLower = tech.toLowerCase();
    for (const [key, nucleiTags] of Object.entries(TECH_TO_NUCLEI_TAGS)) {
      if (techLower.includes(key)) {
        for (const tag of nucleiTags) tags.add(tag);
        rationale.push(`${tech} detected \u2192 adding ${nucleiTags.join(", ")} templates`);
      }
    }
  }
  tags.add("sqli");
  tags.add("xss");
  tags.add("lfi");
  tags.add("rce");
  tags.add("ssrf");
  tags.add("ssti");
  tags.add("crlf");
  tags.add("traversal");
  if (target.wafDetected) {
    tags.add("waf");
    rationale.push("WAF detected \u2014 including bypass templates");
  }
  const isSPA = target.technologies.some(
    (t) => /react|angular|vue|nextjs|nuxt|svelte|ember/i.test(t)
  );
  const dastMode = isSPA && roe.maxIntensity >= 3;
  if (dastMode) {
    rationale.push("SPA detected \u2014 enabling DAST mode with headless crawling");
  }
  const rateLimit = roe.maxIntensity >= 4 ? 100 : roe.maxIntensity >= 3 ? 50 : 25;
  return {
    target: target.hostname,
    tags: Array.from(tags),
    severityFilter: "critical,high,medium",
    dastMode,
    crawlDepth: dastMode ? 3 : 0,
    rateLimit,
    headless: dastMode,
    rationale: rationale.length > 0 ? rationale.join("; ") : "Standard vulnerability scan with common templates"
  };
}
function generateZapConfig(target, roe) {
  const hasWebPorts = target.knownPorts.some(
    (p) => [80, 443, 8080, 8443, 3e3, 5e3, 8e3, 8888].includes(p.port)
  );
  const hasWebTech = target.technologies.some(
    (t) => /apache|nginx|iis|wordpress|drupal|laravel|django|spring|express|react|angular|vue|nextjs/i.test(t)
  );
  if (!hasWebPorts && !hasWebTech) return null;
  const isSPA = target.technologies.some(
    (t) => /react|angular|vue|nextjs|nuxt|svelte/i.test(t)
  );
  const strengthMap = {
    1: "low",
    2: "medium",
    3: "high",
    4: "insane",
    5: "insane"
  };
  return {
    target: target.hostname,
    useAjaxSpider: isSPA,
    scanStrength: strengthMap[roe.maxIntensity] || "medium",
    enabledRules: [],
    // Will be populated by ZAP scanner based on tech
    rationale: `Web application detected (${isSPA ? "SPA" : "traditional"}). ${target.wafDetected ? "WAF present \u2014 using evasion techniques." : ""}`
  };
}
function generateActiveScanPlan(passiveResults, roe) {
  const provenance = [];
  const excludedByRoE = [];
  const targetMap = /* @__PURE__ */ new Map();
  for (const obs of passiveResults.observations) {
    const hostname = obs.name || obs.domain || obs.hostname || obs.assetId || "";
    if (!hostname) continue;
    if (!targetMap.has(hostname)) {
      targetMap.set(hostname, {
        observations: [],
        signals: [],
        technologies: passiveResults.technologies[hostname] || [],
        ports: passiveResults.services.filter((s) => s.hostname === hostname).map((s) => ({ port: s.port, service: s.service, version: s.version })),
        wafDetected: passiveResults.wafDetected?.[hostname] || false
      });
    }
    targetMap.get(hostname).observations.push(obs);
  }
  for (const signal of passiveResults.riskSignals) {
    const assetId = signal.assetId || "";
    for (const [hostname, data] of targetMap) {
      if (assetId.includes(hostname) || hostname.includes(assetId)) {
        data.signals.push(signal);
      }
    }
  }
  const targets = [];
  for (const [hostname, data] of targetMap) {
    const scopeCheck = isInScope(hostname, roe);
    if (!scopeCheck.inScope) {
      excludedByRoE.push({ hostname, reason: scopeCheck.reason || "Out of scope" });
      continue;
    }
    const priority = computeAssetPriority(hostname, data.observations, data.signals);
    const triggeringSignals = data.signals.map((s) => s.rationale).slice(0, 5);
    targets.push({
      hostname,
      ip: data.observations.find((o) => o.ip)?.ip,
      priority,
      rationale: `${data.signals.length} risk signals, ${data.observations.length} observations, ${data.technologies.length} technologies detected`,
      technologies: data.technologies,
      knownPorts: data.ports,
      triggeringSignals,
      wafDetected: data.wafDetected
    });
  }
  targets.sort((a, b) => b.priority - a.priority);
  const scanConfigs = [];
  const nucleiConfigs = [];
  const zapConfigs = [];
  for (const target of targets) {
    if (roe.allowedScanTypes.includes("scanforge-discovery")) {
      scanConfigs.push(generateScanForgeConfig(target, roe));
      for (const port of target.knownPorts) {
        provenance.push({
          passiveObservationId: `port-${target.hostname}-${port.port}`,
          passiveSignal: `Port ${port.port}/${port.service} detected via passive recon`,
          activeTool: "scanforge-discovery",
          target: target.hostname,
          rationale: `Verify service version and check for vulnerabilities on port ${port.port}`
        });
      }
    }
    if (roe.allowedScanTypes.includes("nuclei")) {
      nucleiConfigs.push(generateNucleiConfig(target, roe));
      for (const tech of target.technologies.slice(0, 3)) {
        provenance.push({
          passiveObservationId: `tech-${target.hostname}-${tech}`,
          passiveSignal: `Technology "${tech}" detected via passive recon`,
          activeTool: "nuclei",
          target: target.hostname,
          rationale: `Run ${tech}-specific vulnerability templates`
        });
      }
    }
    if (roe.allowedScanTypes.includes("zap")) {
      const zapConfig = generateZapConfig(target, roe);
      if (zapConfig) {
        zapConfigs.push(zapConfig);
        provenance.push({
          passiveObservationId: `webapp-${target.hostname}`,
          passiveSignal: `Web application detected at ${target.hostname}`,
          activeTool: "zap",
          target: target.hostname,
          rationale: `Deep web application scan with ${zapConfig.useAjaxSpider ? "AJAX spider (SPA)" : "traditional spider"}`
        });
      }
    }
  }
  const discoveryMinutes = scanConfigs.length * 5;
  const nucleiMinutes = nucleiConfigs.length * 3;
  const zapMinutes = zapConfigs.length * 15;
  const totalMinutes = discoveryMinutes + nucleiMinutes + zapMinutes;
  const estimatedDuration = totalMinutes < 60 ? `${totalMinutes} minutes` : `${Math.round(totalMinutes / 60 * 10) / 10} hours`;
  const highRiskSignals = passiveResults.riskSignals.filter(
    (s) => s.severity === "critical" || s.severity === "high"
  );
  const coveredHighRisk = highRiskSignals.filter((s) => {
    const assetId = s.assetId || "";
    return targets.some((t) => assetId.includes(t.hostname) || t.hostname.includes(assetId));
  });
  const riskCoverage = highRiskSignals.length > 0 ? Math.round(coveredHighRisk.length / highRiskSignals.length * 100) : 100;
  return {
    generatedAt: /* @__PURE__ */ new Date(),
    totalTargets: targets.length,
    targets,
    scanConfigs,
    nucleiConfigs,
    zapConfigs,
    excludedByRoE,
    stats: {
      totalPassiveObservations: passiveResults.observations.length,
      targetsInScope: targets.length,
      targetsExcluded: excludedByRoE.length,
      estimatedScanDuration: estimatedDuration,
      riskCoverage
    },
    provenance
  };
}
function buildDefaultRoE(targetDomains, engagementType, options) {
  return {
    scopedAssets: targetDomains,
    excludedAssets: options?.excludedAssets || [],
    allowedScanTypes: options?.allowedTools || ["scanforge-discovery", "nuclei", "zap", "dast"],
    maxIntensity: options?.maxIntensity || (engagementType === "red_team" ? 4 : 3),
    socialEngineeringAllowed: engagementType === "red_team",
    dosTestingAllowed: false,
    maxConcurrentScans: 3
  };
}
function formatScanPlanSummary(plan) {
  const lines = [];
  lines.push(`Active Scan Plan \u2014 ${plan.totalTargets} targets`);
  lines.push(`Generated: ${plan.generatedAt.toISOString()}`);
  lines.push(`Estimated duration: ${plan.stats.estimatedScanDuration}`);
  lines.push(`Risk coverage: ${plan.stats.riskCoverage}%`);
  lines.push("");
  lines.push("Targets (by priority):");
  for (const t of plan.targets.slice(0, 10)) {
    lines.push(`  [${t.priority}] ${t.hostname} \u2014 ${t.technologies.slice(0, 3).join(", ") || "unknown tech"} \u2014 ${t.knownPorts.length} ports \u2014 ${t.triggeringSignals.length} signals`);
  }
  if (plan.targets.length > 10) {
    lines.push(`  ... and ${plan.targets.length - 10} more`);
  }
  if (plan.excludedByRoE.length > 0) {
    lines.push("");
    lines.push(`Excluded by RoE: ${plan.excludedByRoE.length} targets`);
    for (const e of plan.excludedByRoE.slice(0, 5)) {
      lines.push(`  - ${e.hostname}: ${e.reason}`);
    }
  }
  lines.push("");
  lines.push(`Scan configs: ${plan.scanConfigs.length} ScanForge discovery, ${plan.nucleiConfigs.length} nuclei, ${plan.zapConfigs.length} ZAP`);
  lines.push(`Provenance records: ${plan.provenance.length}`);
  return lines.join("\n");
}
export {
  buildDefaultRoE,
  formatScanPlanSummary,
  generateActiveScanPlan
};
