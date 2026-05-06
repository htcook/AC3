import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/dynamic-attack-mapper.ts
function recommendTechniques(params) {
  const {
    vulnClass,
    accessLevel,
    techStack,
    hasWaf,
    isCloudEnvironment,
    safeModeEnabled,
    demonstratedTechniques
  } = params;
  const baseTechniques = VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];
  const allTechniques = [...baseTechniques];
  if (isCloudEnvironment && vulnClass === "ssrf") {
  }
  const accessOrder = ["none", "web_user", "authenticated", "shell", "root"];
  const currentAccessIdx = accessOrder.indexOf(accessLevel);
  const recommendations = allTechniques.filter((t) => {
    const requiredIdx = accessOrder.indexOf(t.requiredAccess);
    return requiredIdx <= currentAccessIdx || requiredIdx <= 0;
  }).filter((t) => {
    if (safeModeEnabled) {
      const riskyTactics = ["persistence", "impact", "lateral-movement", "exfiltration"];
      return !riskyTactics.includes(t.tactic);
    }
    return true;
  }).map((technique, idx) => ({
    technique,
    rationale: buildRationale(technique, vulnClass, techStack, hasWaf),
    confidence: calculateConfidence(technique, vulnClass, techStack),
    priority: idx + 1,
    demonstrated: demonstratedTechniques.includes(technique.techniqueId)
  })).sort((a, b) => {
    if (a.demonstrated !== b.demonstrated) return a.demonstrated ? 1 : -1;
    const tacticA = TACTIC_ORDER.indexOf(a.technique.tactic);
    const tacticB = TACTIC_ORDER.indexOf(b.technique.tactic);
    if (tacticA !== tacticB) return tacticA - tacticB;
    return b.confidence - a.confidence;
  });
  return recommendations.map((r, idx) => ({ ...r, priority: idx + 1 }));
}
function buildRationale(technique, vulnClass, techStack, hasWaf) {
  const parts = [];
  parts.push(`${technique.techniqueName} (${technique.techniqueId}) is relevant because ${vulnClass} vulnerabilities commonly enable ${technique.tactic} activities.`);
  if (hasWaf && technique.detectionDifficulty >= 3) {
    parts.push("This technique has moderate-to-high detection difficulty, making it suitable against WAF-protected targets.");
  }
  if (technique.relatedWSTG.length > 0) {
    parts.push(`Aligns with OWASP WSTG tests: ${technique.relatedWSTG.join(", ")}.`);
  }
  return parts.join(" ");
}
function calculateConfidence(technique, vulnClass, techStack) {
  let confidence = 0.5;
  if (VULN_TO_TECHNIQUE_MAP[vulnClass]?.some((t) => t.techniqueId === technique.techniqueId)) {
    confidence += 0.3;
  }
  const techStackLower = techStack.map((t) => t.toLowerCase()).join(" ");
  if (technique.tools.some((tool) => techStackLower.includes(tool.toLowerCase()))) {
    confidence += 0.1;
  }
  return Math.min(confidence, 0.95);
}
function analyzeKillChainCoverage(params) {
  const { vulnClass, demonstratedTechniques, accessLevel, safeModeEnabled } = params;
  const coveredTactics = /* @__PURE__ */ new Set();
  for (const dt of demonstratedTechniques) {
    coveredTactics.add(dt.tactic);
  }
  const relevantTechniques = VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];
  const relevantTactics = new Set(relevantTechniques.map((t) => t.tactic));
  relevantTactics.add("initial-access");
  const uncoveredTactics = [...relevantTactics].filter((t) => !coveredTactics.has(t));
  const coveragePercent = relevantTactics.size > 0 ? Math.round(coveredTactics.size / relevantTactics.size * 100) : 0;
  const demonstratedIds = demonstratedTechniques.map((dt) => dt.techniqueId);
  const gapFillers = recommendTechniques({
    vulnClass,
    accessLevel,
    techStack: [],
    hasWaf: false,
    isCloudEnvironment: false,
    safeModeEnabled,
    demonstratedTechniques: demonstratedIds
  }).filter((r) => !r.demonstrated && uncoveredTactics.includes(r.technique.tactic));
  return {
    coveredTactics: [...coveredTactics],
    uncoveredTactics,
    coveragePercent,
    gapFillers
  };
}
function generateNavigatorLayer(params) {
  const { engagementName, demonstratedTechniques, recommendedTechniques } = params;
  const techniques = [];
  for (const dt of demonstratedTechniques) {
    const qualityScore = {
      definitive: 100,
      strong: 75,
      moderate: 50,
      weak: 25
    };
    techniques.push({
      techniqueID: dt.techniqueId,
      tactic: dt.tactic,
      color: "#e60000",
      // Red for demonstrated
      comment: `Demonstrated: ${dt.evidence} (${dt.quality} quality)`,
      score: qualityScore[dt.quality] || 50,
      enabled: true
    });
  }
  if (recommendedTechniques) {
    for (const rt of recommendedTechniques) {
      if (!rt.demonstrated) {
        techniques.push({
          techniqueID: rt.technique.techniqueId,
          tactic: rt.technique.tactic,
          color: "#ffcc00",
          // Yellow for recommended but not demonstrated
          comment: `Recommended: ${rt.rationale}`,
          score: Math.round(rt.confidence * 100),
          enabled: true
        });
      }
    }
  }
  return {
    name: `${engagementName} \u2014 Exploitation Coverage`,
    versions: {
      attack: "14",
      navigator: "4.9.1",
      layer: "4.5"
    },
    domain: "enterprise-attack",
    description: `ATT&CK technique coverage for engagement: ${engagementName}. Red = demonstrated, Yellow = recommended.`,
    techniques,
    gradient: {
      colors: ["#ffffff", "#ffcc00", "#e60000"],
      minValue: 0,
      maxValue: 100
    },
    legendItems: [
      { label: "Demonstrated", color: "#e60000" },
      { label: "Recommended", color: "#ffcc00" },
      { label: "Not Applicable", color: "#ffffff" }
    ]
  };
}
function createEngagementTracker(engagementId, vulnClass, accessLevel, techStack) {
  const recommendations = recommendTechniques({
    vulnClass,
    accessLevel,
    techStack,
    hasWaf: false,
    isCloudEnvironment: false,
    safeModeEnabled: false,
    demonstratedTechniques: []
  });
  return {
    engagementId,
    recommendedTechniques: recommendations,
    demonstratedTechniques: /* @__PURE__ */ new Map(),
    coverage: analyzeKillChainCoverage({
      vulnClass,
      demonstratedTechniques: [],
      accessLevel,
      safeModeEnabled: false
    })
  };
}
function recordDemonstration(tracker, technique, vulnClass) {
  const newDemonstrated = new Map(tracker.demonstratedTechniques);
  newDemonstrated.set(technique.techniqueId, technique);
  const demonstratedList = [...newDemonstrated.values()];
  const demonstratedIds = demonstratedList.map((d) => d.techniqueId);
  const updatedRecommendations = tracker.recommendedTechniques.map((r) => ({
    ...r,
    demonstrated: demonstratedIds.includes(r.technique.techniqueId)
  }));
  const updatedCoverage = analyzeKillChainCoverage({
    vulnClass,
    demonstratedTechniques: demonstratedList,
    accessLevel: "none",
    // Will be overridden by actual state
    safeModeEnabled: false
  });
  return {
    ...tracker,
    recommendedTechniques: updatedRecommendations,
    demonstratedTechniques: newDemonstrated,
    coverage: updatedCoverage
  };
}
function getNextRecommendation(tracker) {
  return tracker.recommendedTechniques.find((r) => !r.demonstrated) || null;
}
function generateAttackContextForPrompt(params) {
  const recommendations = recommendTechniques({
    ...params,
    techStack: [],
    hasWaf: false,
    isCloudEnvironment: false
  });
  const nextTechniques = recommendations.filter((r) => !r.demonstrated).slice(0, 3);
  if (nextTechniques.length === 0) {
    return "All relevant ATT&CK techniques have been demonstrated for this vulnerability class.";
  }
  const lines = [
    "## ATT&CK Technique Guidance",
    "",
    "The following MITRE ATT&CK techniques should be demonstrated during exploitation:",
    ""
  ];
  for (const rec of nextTechniques) {
    lines.push(`### ${rec.technique.techniqueId}: ${rec.technique.techniqueName} (${rec.technique.tactic})`);
    lines.push(`**Guidance:** ${rec.technique.exploitGuidance}`);
    lines.push(`**Tools:** ${rec.technique.tools.join(", ")}`);
    lines.push(`**WSTG:** ${rec.technique.relatedWSTG.join(", ")}`);
    lines.push("");
  }
  if (params.demonstratedTechniques.length > 0) {
    lines.push(`**Already demonstrated:** ${params.demonstratedTechniques.join(", ")}`);
    lines.push("Focus on the techniques listed above that have NOT been demonstrated yet.");
  }
  return lines.join("\n");
}
function getSupportedVulnClasses() {
  return Object.keys(VULN_TO_TECHNIQUE_MAP);
}
function getTechniquesForVulnClass(vulnClass) {
  return VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];
}
var VULN_TO_TECHNIQUE_MAP, TACTIC_ORDER;
var init_dynamic_attack_mapper = __esm({
  "server/lib/dynamic-attack-mapper.ts"() {
    VULN_TO_TECHNIQUE_MAP = {
      sqli: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Use SQL injection to gain initial access. For UNION-based: enumerate columns, extract data. For blind: use boolean/time-based inference. For stacked queries: attempt command execution via xp_cmdshell (MSSQL) or LOAD_FILE/INTO OUTFILE (MySQL).",
          tools: ["sqlmap", "manual UNION crafting", "time-based blind scripts"],
          detectionDifficulty: 2,
          prerequisites: ["injectable parameter identified", "database type known"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Network Traffic"],
          relatedCWEs: ["CWE-89", "CWE-564"],
          relatedWSTG: ["WSTG-INPV-05"]
        },
        {
          techniqueId: "T1005",
          techniqueName: "Data from Local System",
          tactic: "collection",
          exploitGuidance: "After confirming SQLi, extract database contents to demonstrate data access. Use UNION SELECT to read from information_schema, then target tables with sensitive data (users, credentials, PII). Document table names and column names as proof without extracting actual PII.",
          tools: ["UNION SELECT queries", "database-specific metadata tables"],
          detectionDifficulty: 2,
          prerequisites: ["confirmed SQL injection"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Database Log"],
          relatedCWEs: ["CWE-89"],
          relatedWSTG: ["WSTG-INPV-05"]
        },
        {
          techniqueId: "T1078",
          techniqueName: "Valid Accounts",
          tactic: "persistence",
          exploitGuidance: "If SQLi extracts credential hashes, attempt offline cracking or use pass-the-hash to authenticate as a legitimate user. This demonstrates persistence via valid account compromise.",
          tools: ["hashcat", "john", "credential extraction queries"],
          detectionDifficulty: 4,
          prerequisites: ["credential hashes extracted via SQLi"],
          requiredAccess: "none",
          dataSources: ["Authentication Log", "Account Audit"],
          relatedCWEs: ["CWE-89", "CWE-522"],
          relatedWSTG: ["WSTG-INPV-05", "WSTG-ATHN-02"]
        },
        {
          techniqueId: "T1059",
          techniqueName: "Command and Scripting Interpreter",
          tactic: "execution",
          exploitGuidance: "For MSSQL: use xp_cmdshell for OS command execution. For MySQL: use INTO OUTFILE to write webshell, or LOAD_FILE to read system files. For PostgreSQL: use COPY TO/FROM or pg_read_file(). This escalates SQLi from data access to RCE.",
          tools: ["xp_cmdshell", "INTO OUTFILE", "COPY TO", "pg_read_file"],
          detectionDifficulty: 2,
          prerequisites: ["confirmed SQLi with sufficient privileges"],
          requiredAccess: "none",
          dataSources: ["Process Monitoring", "File Monitoring"],
          relatedCWEs: ["CWE-89", "CWE-78"],
          relatedWSTG: ["WSTG-INPV-05"]
        }
      ],
      xss: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Inject JavaScript via XSS to execute in victim browser context. For reflected: craft URL with payload. For stored: inject into persistent storage. For DOM-based: manipulate client-side JavaScript.",
          tools: ["browser developer tools", "XSS payload generators", "Burp Suite"],
          detectionDifficulty: 3,
          prerequisites: ["injectable parameter identified", "output context known"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Network Traffic"],
          relatedCWEs: ["CWE-79"],
          relatedWSTG: ["WSTG-INPV-01", "WSTG-INPV-02"]
        },
        {
          techniqueId: "T1539",
          techniqueName: "Steal Web Session Cookie",
          tactic: "credential-access",
          exploitGuidance: "Use XSS to exfiltrate session cookies via document.cookie. If HttpOnly flag is set, demonstrate the XSS with document.domain instead and note that cookie theft is mitigated by HttpOnly. Check for other sensitive tokens in localStorage/sessionStorage.",
          tools: ["JavaScript payload", "OOB exfiltration server"],
          detectionDifficulty: 3,
          prerequisites: ["confirmed XSS execution"],
          requiredAccess: "none",
          dataSources: ["Application Log"],
          relatedCWEs: ["CWE-79", "CWE-614"],
          relatedWSTG: ["WSTG-INPV-01", "WSTG-SESS-02"]
        },
        {
          techniqueId: "T1185",
          techniqueName: "Browser Session Hijacking",
          tactic: "collection",
          exploitGuidance: "Use XSS to perform actions as the victim user \u2014 modify profile, change email, initiate transactions. This demonstrates the full impact beyond just cookie theft.",
          tools: ["XMLHttpRequest/fetch payloads", "BeEF framework"],
          detectionDifficulty: 4,
          prerequisites: ["confirmed XSS in authenticated context"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Network Traffic"],
          relatedCWEs: ["CWE-79"],
          relatedWSTG: ["WSTG-INPV-01"]
        }
      ],
      command_injection: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Inject OS commands via vulnerable parameter. Test all injection operators: ;, |, &&, ||, `, $(). For blind injection, use DNS OOB or time-based detection.",
          tools: ["manual payload crafting", "Burp Suite", "commix"],
          detectionDifficulty: 2,
          prerequisites: ["injectable parameter identified", "OS type known"],
          requiredAccess: "none",
          dataSources: ["Process Monitoring", "Application Log"],
          relatedCWEs: ["CWE-78", "CWE-77"],
          relatedWSTG: ["WSTG-INPV-12"]
        },
        {
          techniqueId: "T1059.004",
          techniqueName: "Unix Shell",
          tactic: "execution",
          parentId: "T1059",
          exploitGuidance: "After confirming command injection on Linux, execute system enumeration commands: whoami, id, hostname, uname -a. Use DNS OOB for blind exfiltration. Avoid reverse shells unless specifically authorized.",
          tools: ["bash commands", "DNS OOB exfiltration"],
          detectionDifficulty: 2,
          prerequisites: ["confirmed command injection on Linux"],
          requiredAccess: "none",
          dataSources: ["Process Monitoring", "Command Execution"],
          relatedCWEs: ["CWE-78"],
          relatedWSTG: ["WSTG-INPV-12"]
        },
        {
          techniqueId: "T1068",
          techniqueName: "Exploitation for Privilege Escalation",
          tactic: "privilege-escalation",
          exploitGuidance: "If command injection runs as non-root, check for privilege escalation vectors: SUID binaries, sudo misconfigurations, kernel exploits, writable cron jobs. Use `sudo -l`, `find / -perm -4000`, and kernel version checks.",
          tools: ["LinPEAS", "sudo -l", "find SUID", "kernel exploit databases"],
          detectionDifficulty: 2,
          prerequisites: ["shell access via command injection"],
          requiredAccess: "shell",
          dataSources: ["Process Monitoring", "File Monitoring"],
          relatedCWEs: ["CWE-269"],
          relatedWSTG: ["WSTG-INPV-12"]
        }
      ],
      ssrf: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Exploit SSRF to access internal services. Test all IP bypass techniques: decimal IP, hex IP, IPv6, DNS rebinding, URL parser differentials. Primary targets: cloud metadata (169.254.169.254), internal APIs, admin panels.",
          tools: ["Burp Suite", "IP format converters", "DNS rebinding tools"],
          detectionDifficulty: 3,
          prerequisites: ["URL/host parameter identified", "cloud environment detected"],
          requiredAccess: "none",
          dataSources: ["Network Traffic", "Application Log"],
          relatedCWEs: ["CWE-918"],
          relatedWSTG: ["WSTG-INPV-19"]
        },
        {
          techniqueId: "T1552.005",
          techniqueName: "Cloud Instance Metadata API",
          tactic: "credential-access",
          parentId: "T1552",
          exploitGuidance: "Use SSRF to reach cloud metadata services: AWS (169.254.169.254/latest/meta-data/iam/security-credentials/), GCP (metadata.google.internal/computeMetadata/v1/), Azure (169.254.169.254/metadata/identity/oauth2/token). Extract IAM credentials without using them.",
          tools: ["SSRF payload", "cloud metadata endpoints"],
          detectionDifficulty: 3,
          prerequisites: ["confirmed SSRF", "cloud environment"],
          requiredAccess: "none",
          dataSources: ["Cloud API Logs", "Network Traffic"],
          relatedCWEs: ["CWE-918"],
          relatedWSTG: ["WSTG-INPV-19"]
        },
        {
          techniqueId: "T1046",
          techniqueName: "Network Service Discovery",
          tactic: "discovery",
          exploitGuidance: "Use SSRF as an internal port scanner. Iterate through common ports on internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) to map internal services. Response timing and error messages reveal open/closed ports.",
          tools: ["SSRF-based port scanning scripts", "response timing analysis"],
          detectionDifficulty: 3,
          prerequisites: ["confirmed SSRF"],
          requiredAccess: "none",
          dataSources: ["Network Traffic"],
          relatedCWEs: ["CWE-918"],
          relatedWSTG: ["WSTG-INPV-19"]
        }
      ],
      idor: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Access resources belonging to other users by manipulating object references (IDs, UUIDs, filenames). Test all CRUD operations: GET (read), PUT/PATCH (modify), DELETE (destroy). Always use two accounts you control.",
          tools: ["Burp Suite", "API testing tools", "Autorize extension"],
          detectionDifficulty: 4,
          prerequisites: ["two test accounts", "API endpoint with object references"],
          requiredAccess: "authenticated",
          dataSources: ["Application Log", "API Audit"],
          relatedCWEs: ["CWE-639", "CWE-284"],
          relatedWSTG: ["WSTG-ATHZ-04"]
        },
        {
          techniqueId: "T1530",
          techniqueName: "Data from Cloud Storage",
          tactic: "collection",
          exploitGuidance: "If IDOR exposes file storage references (S3 keys, blob paths), enumerate and access files belonging to other users. Document the scope of accessible data without downloading actual files.",
          tools: ["API requests with modified references", "S3 enumeration"],
          detectionDifficulty: 4,
          prerequisites: ["confirmed IDOR on file/storage endpoints"],
          requiredAccess: "authenticated",
          dataSources: ["Cloud Storage Logs", "API Audit"],
          relatedCWEs: ["CWE-639"],
          relatedWSTG: ["WSTG-ATHZ-04"]
        }
      ],
      auth_bypass: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Bypass authentication mechanisms: JWT manipulation (alg:none, key confusion), session fixation, default credentials, forced browsing to authenticated endpoints. Test each bypass independently.",
          tools: ["JWT tools", "Burp Suite", "forced browsing wordlists"],
          detectionDifficulty: 3,
          prerequisites: ["authentication mechanism identified"],
          requiredAccess: "none",
          dataSources: ["Authentication Log", "Application Log"],
          relatedCWEs: ["CWE-287", "CWE-306"],
          relatedWSTG: ["WSTG-ATHN-04", "WSTG-ATHN-06"]
        },
        {
          techniqueId: "T1078",
          techniqueName: "Valid Accounts",
          tactic: "persistence",
          exploitGuidance: "If authentication bypass grants access to account creation or credential reset, create a persistent backdoor account. Document the capability without actually creating production accounts.",
          tools: ["API requests", "admin panel access"],
          detectionDifficulty: 5,
          prerequisites: ["confirmed auth bypass with admin access"],
          requiredAccess: "none",
          dataSources: ["Authentication Log", "Account Audit"],
          relatedCWEs: ["CWE-287"],
          relatedWSTG: ["WSTG-ATHN-04"]
        }
      ],
      file_upload: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Upload malicious files to achieve code execution. Test bypass techniques: double extensions (.php.jpg), null bytes (.php%00.jpg), content-type manipulation, polyglot files. Verify the uploaded file is accessible and executable.",
          tools: ["Burp Suite", "polyglot file generators", "webshell templates"],
          detectionDifficulty: 2,
          prerequisites: ["file upload endpoint identified", "server-side language known"],
          requiredAccess: "none",
          dataSources: ["Application Log", "File Monitoring"],
          relatedCWEs: ["CWE-434"],
          relatedWSTG: ["WSTG-BUSL-08"]
        },
        {
          techniqueId: "T1505.003",
          techniqueName: "Web Shell",
          tactic: "persistence",
          parentId: "T1505",
          exploitGuidance: "After successful file upload, deploy a minimal webshell to demonstrate persistent access. Use a one-liner that executes a single command (whoami) rather than a full-featured shell. Document the upload path and execution proof.",
          tools: ["minimal webshell", "curl for execution verification"],
          detectionDifficulty: 3,
          prerequisites: ["successful malicious file upload", "file is web-accessible"],
          requiredAccess: "none",
          dataSources: ["File Monitoring", "Process Monitoring"],
          relatedCWEs: ["CWE-434"],
          relatedWSTG: ["WSTG-BUSL-08"]
        }
      ],
      misconfig: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Exploit misconfigurations: exposed admin panels, default credentials, directory listing, debug mode enabled, unnecessary HTTP methods, missing security headers.",
          tools: ["Nikto", "directory brute-forcing", "HTTP method testing"],
          detectionDifficulty: 4,
          prerequisites: ["misconfiguration identified"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Network Traffic"],
          relatedCWEs: ["CWE-16", "CWE-1188"],
          relatedWSTG: ["WSTG-CONF-02", "WSTG-CONF-04", "WSTG-CONF-06"]
        }
      ],
      info_disclosure: [
        {
          techniqueId: "T1592",
          techniqueName: "Gather Victim Host Information",
          tactic: "reconnaissance",
          exploitGuidance: "Collect exposed information: stack traces, version numbers, internal IPs, API keys in source code, .git exposure, backup files. Each piece of information feeds into further exploitation planning.",
          tools: ["browser source view", "directory brute-forcing", "git-dumper"],
          detectionDifficulty: 5,
          prerequisites: ["target URL identified"],
          requiredAccess: "none",
          dataSources: ["Application Log"],
          relatedCWEs: ["CWE-200", "CWE-209"],
          relatedWSTG: ["WSTG-INFO-01", "WSTG-INFO-02", "WSTG-INFO-05"]
        }
      ],
      business_logic: [
        {
          techniqueId: "T1190",
          techniqueName: "Exploit Public-Facing Application",
          tactic: "initial-access",
          exploitGuidance: "Exploit business logic flaws: race conditions (concurrent requests), price manipulation, workflow bypass, parameter tampering, forced browsing. These require understanding the application business flow.",
          tools: ["Turbo Intruder", "Burp Suite", "async HTTP clients"],
          detectionDifficulty: 5,
          prerequisites: ["business flow understood", "application-specific knowledge"],
          requiredAccess: "none",
          dataSources: ["Application Log", "Business Logic Monitoring"],
          relatedCWEs: ["CWE-840", "CWE-362"],
          relatedWSTG: ["WSTG-BUSL-01", "WSTG-BUSL-07"]
        }
      ]
    };
    TACTIC_ORDER = [
      "reconnaissance",
      "resource-development",
      "initial-access",
      "execution",
      "persistence",
      "privilege-escalation",
      "defense-evasion",
      "credential-access",
      "discovery",
      "lateral-movement",
      "collection",
      "command-and-control",
      "exfiltration",
      "impact"
    ];
  }
});
init_dynamic_attack_mapper();
export {
  analyzeKillChainCoverage,
  createEngagementTracker,
  generateAttackContextForPrompt,
  generateNavigatorLayer,
  getNextRecommendation,
  getSupportedVulnClasses,
  getTechniquesForVulnClass,
  recommendTechniques,
  recordDemonstration
};
