/**
 * Detection Rules Engine
 * Post-processes LLM-generated detection rules and injects real IOCs from engagement data.
 * Also provides production-ready rule templates for common vulnerability types.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

interface DetectionRules {
  sigma: string | null;
  yara: string | null;
  suricata: string | null;
}

interface FindingContext {
  title: string;
  severity: string;
  cve?: string;
  cweId?: string;
  affectedAssets: string[];
  evidence?: Array<{ type: string; description: string; data: string }>;
  owaspCategory?: string;
}

interface EngagementIOCs {
  targetIPs: string[];
  targetHostnames: string[];
  detectedSoftware: Array<{ name: string; version?: string }>;
  attackPayloads: string[];
  vulnerableParams: string[];
  vulnerableURLs: string[];
  exploitModules: string[];
  detectedPorts: number[];
}

// ─── Rule Template Library ───────────────────────────────────────────────────

const SIGMA_TEMPLATES: Record<string, (ctx: FindingContext, iocs: EngagementIOCs) => string> = {
  // SQL Injection detection
  sqli: (ctx, iocs) => {
    const hosts = iocs.targetHostnames.length > 0 ? iocs.targetHostnames : iocs.targetIPs;
    const urls = iocs.vulnerableURLs.length > 0 ? iocs.vulnerableURLs.slice(0, 5) : [];
    const params = iocs.vulnerableParams.length > 0 ? iocs.vulnerableParams.slice(0, 10) : [];
    return `title: SQL Injection Attempt - ${ctx.title}
id: ${generateRuleId()}
status: production
level: high
description: Detects SQL injection attempts against ${hosts.join(', ')}${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
references:
  - ${ctx.cve ? `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${ctx.cve}` : 'https://owasp.org/Top10/A03_2021-Injection/'}
tags:
  - attack.initial_access
  - attack.t1190
  - cve.${ctx.cve || 'generic'}
logsource:
  category: webserver
  product: any
detection:
  selection_uri:
    cs-uri-query|contains:
      - "' OR "
      - "1=1"
      - "UNION SELECT"
      - "UNION ALL SELECT"
      - "' AND '"
      - "ORDER BY 1--"
      - "WAITFOR DELAY"
      - "BENCHMARK("
      - "SLEEP("
      - "pg_sleep("
      - "extractvalue("
      - "updatexml("
${params.length > 0 ? `  selection_param:\n    cs-uri-query|contains:\n${params.map(p => `      - "${p}="`).join('\n')}\n` : ''}${urls.length > 0 ? `  selection_target:\n    cs-uri-stem:\n${urls.map(u => { try { return `      - "${new URL(u, 'http://placeholder').pathname}"`; } catch { return `      - "${u}"`; } }).join('\n')}\n` : ''}  condition: selection_uri${params.length > 0 ? ' and selection_param' : ''}${urls.length > 0 ? ' and selection_target' : ''}
falsepositives:
  - Legitimate database query parameters in application URLs
  - Security scanning tools during authorized testing`;
  },

  // XSS detection
  xss: (ctx, iocs) => {
    const hosts = iocs.targetHostnames.length > 0 ? iocs.targetHostnames : iocs.targetIPs;
    return `title: Cross-Site Scripting Attempt - ${ctx.title}
id: ${generateRuleId()}
status: production
level: medium
description: Detects XSS attempts against ${hosts.join(', ')}${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
references:
  - https://owasp.org/Top10/A03_2021-Injection/
tags:
  - attack.initial_access
  - attack.t1189
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-query|contains:
      - "<script"
      - "javascript:"
      - "onerror="
      - "onload="
      - "onmouseover="
      - "onfocus="
      - "onclick="
      - "eval("
      - "document.cookie"
      - "document.location"
      - "window.location"
      - "String.fromCharCode"
      - "atob("
${iocs.attackPayloads.length > 0 ? `  selection_payload:\n    cs-uri-query|contains:\n${iocs.attackPayloads.slice(0, 5).map(p => `      - "${escapeYaml(p.substring(0, 100))}"`).join('\n')}\n` : ''}  condition: selection${iocs.attackPayloads.length > 0 ? ' or selection_payload' : ''}
falsepositives:
  - Legitimate JavaScript in URL parameters
  - Web development tools`;
  },

  // Command Injection detection
  cmdi: (ctx, iocs) => {
    return `title: Command Injection Attempt - ${ctx.title}
id: ${generateRuleId()}
status: production
level: critical
description: Detects OS command injection attempts${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.execution
  - attack.t1059
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-query|contains:
      - "; cat "
      - "| cat "
      - "\`cat "
      - "$(cat "
      - "; ls "
      - "| ls "
      - "; id"
      - "| id"
      - "; whoami"
      - "| whoami"
      - "; ping "
      - "| ping "
      - "; wget "
      - "; curl "
      - "/etc/passwd"
      - "/etc/shadow"
      - "cmd.exe"
      - "powershell"
  condition: selection
falsepositives:
  - Legitimate system administration tools in URLs`;
  },

  // Path Traversal detection
  lfi: (ctx, iocs) => {
    return `title: Path Traversal / LFI Attempt - ${ctx.title}
id: ${generateRuleId()}
status: production
level: high
description: Detects path traversal and local file inclusion attempts${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.discovery
  - attack.t1083
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-query|contains:
      - "../"
      - "..%2f"
      - "..%5c"
      - "%2e%2e/"
      - "%2e%2e%2f"
      - "..../"
      - "/etc/passwd"
      - "/etc/shadow"
      - "/proc/self"
      - "C:\\\\Windows"
      - "C:/Windows"
      - "boot.ini"
      - "win.ini"
  condition: selection
falsepositives:
  - Legitimate relative path references in web applications`;
  },

  // Brute Force detection
  bruteforce: (ctx, iocs) => {
    const hosts = iocs.targetHostnames.length > 0 ? iocs.targetHostnames : iocs.targetIPs;
    return `title: Brute Force Authentication Attempt - ${ctx.title}
id: ${generateRuleId()}
status: production
level: high
description: Detects brute force authentication attempts against ${hosts.join(', ')}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  category: authentication
  product: any
detection:
  selection:
    EventType: AuthenticationFailure
${iocs.targetIPs.length > 0 ? `    TargetHost|contains:\n${iocs.targetIPs.map(ip => `      - "${ip}"`).join('\n')}\n` : ''}  timeframe: 5m
  condition: selection | count() > 10
falsepositives:
  - Legitimate users with forgotten passwords
  - Automated health checks with stale credentials`;
  },

  // Sensitive Data Exposure
  exposure: (ctx, iocs) => {
    return `title: Sensitive Data Exposure - ${ctx.title}
id: ${generateRuleId()}
status: production
level: medium
description: Detects access to sensitive endpoints or data exposure${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.collection
  - attack.t1005
logsource:
  category: webserver
  product: any
detection:
  selection_sensitive_paths:
    cs-uri-stem|contains:
      - "/.env"
      - "/.git/"
      - "/wp-config.php"
      - "/config.php"
      - "/phpinfo.php"
      - "/server-status"
      - "/server-info"
      - "/.htaccess"
      - "/web.config"
      - "/crossdomain.xml"
      - "/robots.txt"
      - "/sitemap.xml"
      - "/.well-known/"
      - "/api/debug"
      - "/actuator/"
      - "/swagger"
      - "/graphql"
  selection_success:
    sc-status:
      - 200
      - 301
      - 302
  condition: selection_sensitive_paths and selection_success
falsepositives:
  - Legitimate access to public configuration files
  - Search engine crawlers`;
  },

  // SSL/TLS Misconfiguration
  tls: (ctx, iocs) => {
    return `title: Weak TLS Configuration Detected - ${ctx.title}
id: ${generateRuleId()}
status: production
level: medium
description: Detects connections using deprecated or weak TLS protocols${ctx.cve ? ` (${ctx.cve})` : ''}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
tags:
  - attack.credential_access
  - attack.t1557
logsource:
  category: proxy
  product: any
detection:
  selection:
    cs-version|contains:
      - "SSLv2"
      - "SSLv3"
      - "TLSv1.0"
      - "TLSv1.1"
${iocs.targetIPs.length > 0 ? `    dst_ip:\n${iocs.targetIPs.map(ip => `      - "${ip}"`).join('\n')}\n` : ''}  condition: selection
falsepositives:
  - Legacy systems requiring backward compatibility`;
  },

  // Default/Generic rule
  generic: (ctx, iocs) => {
    const hosts = iocs.targetHostnames.length > 0 ? iocs.targetHostnames : iocs.targetIPs;
    return `title: Security Finding - ${ctx.title}
id: ${generateRuleId()}
status: experimental
level: ${ctx.severity === 'Critical' ? 'critical' : ctx.severity === 'High' ? 'high' : 'medium'}
description: ${ctx.title}${ctx.cve ? ` (${ctx.cve})` : ''} detected on ${hosts.join(', ')}
author: Ace C3 Automated Detection Engine
date: ${new Date().toISOString().split('T')[0]}
${ctx.cve ? `references:\n  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=${ctx.cve}\n` : ''}tags:
  - attack.initial_access
logsource:
  category: webserver
  product: any
detection:
  selection:
    cs-uri-stem|contains: "*"
${iocs.targetIPs.length > 0 ? `    dst_ip:\n${iocs.targetIPs.map(ip => `      - "${ip}"`).join('\n')}\n` : ''}  condition: selection
falsepositives:
  - Legitimate application traffic`;
  },
};

const SURICATA_TEMPLATES: Record<string, (ctx: FindingContext, iocs: EngagementIOCs) => string> = {
  sqli: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    const ports = iocs.detectedPorts.filter(p => [80, 443, 8080, 8443].includes(p));
    const portStr = ports.length > 0 ? ports.join(',') : '80,443,8080';
    return `alert http $EXTERNAL_NET any -> [${targets}] [${portStr}] (msg:"AC3 SQL Injection Attempt - ${escapeQuotes(ctx.title)}"; flow:established,to_server; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; within:20; classtype:web-application-attack; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)

alert http $EXTERNAL_NET any -> [${targets}] [${portStr}] (msg:"AC3 SQL Injection - Boolean Blind"; flow:established,to_server; content:"' OR '"; nocase; classtype:web-application-attack; sid:${sid + 1}; rev:1;)

alert http $EXTERNAL_NET any -> [${targets}] [${portStr}] (msg:"AC3 SQL Injection - Time Blind"; flow:established,to_server; content:"WAITFOR"; nocase; content:"DELAY"; nocase; distance:0; within:15; classtype:web-application-attack; sid:${sid + 2}; rev:1;)`;
  },

  xss: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    return `alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 XSS Attempt - ${escapeQuotes(ctx.title)}"; flow:established,to_server; content:"<script"; nocase; classtype:web-application-attack; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)

alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 XSS - Event Handler Injection"; flow:established,to_server; pcre:"/on(error|load|mouseover|focus|click)\\s*=/i"; classtype:web-application-attack; sid:${sid + 1}; rev:1;)`;
  },

  cmdi: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    return `alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 Command Injection - ${escapeQuotes(ctx.title)}"; flow:established,to_server; content:"/etc/passwd"; nocase; classtype:web-application-attack; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)

alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 Command Injection - Pipe/Semicolon"; flow:established,to_server; pcre:"/[;|]\s*(cat|ls|id|whoami|wget|curl|ping|nc|bash|sh)\b/i"; classtype:web-application-attack; sid:${sid + 1}; rev:1;)`;
  },

  lfi: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    return `alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 Path Traversal - ${escapeQuotes(ctx.title)}"; flow:established,to_server; content:"../"; classtype:web-application-attack; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)

alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 LFI - Encoded Traversal"; flow:established,to_server; content:"%2e%2e%2f"; nocase; classtype:web-application-attack; sid:${sid + 1}; rev:1;)`;
  },

  bruteforce: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    const sshPorts = iocs.detectedPorts.filter(p => [22, 2222].includes(p));
    const sshPortStr = sshPorts.length > 0 ? sshPorts.join(',') : '22';
    return `alert tcp $EXTERNAL_NET any -> [${targets}] [${sshPortStr}] (msg:"AC3 SSH Brute Force - ${escapeQuotes(ctx.title)}"; flow:to_server; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)

alert http $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 HTTP Login Brute Force"; flow:established,to_server; content:"POST"; http_method; content:"login"; nocase; http_uri; threshold:type both, track by_src, count 10, seconds 120; classtype:attempted-admin; sid:${sid + 1}; rev:1;)`;
  },

  generic: (ctx, iocs) => {
    const sid = generateSID();
    const targets = iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any';
    return `alert ip $EXTERNAL_NET any -> [${targets}] any (msg:"AC3 Security Finding - ${escapeQuotes(ctx.title)}"; classtype:misc-attack; sid:${sid}; rev:1; metadata:created ${new Date().toISOString().split('T')[0]};)`;
  },
};

const YARA_TEMPLATES: Record<string, (ctx: FindingContext, iocs: EngagementIOCs) => string> = {
  webshell: (ctx, iocs) => {
    return `rule AC3_WebShell_${sanitizeRuleName(ctx.title)} {
    meta:
        description = "Detects potential web shell related to ${ctx.title}"
        author = "Ace C3 Detection Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${ctx.severity}"
${ctx.cve ? `        cve = "${ctx.cve}"\n` : ''}        reference = "https://owasp.org/www-community/attacks/Web_Shell"
    strings:
        $php_eval = "eval(" ascii nocase
        $php_system = "system(" ascii nocase
        $php_exec = "exec(" ascii nocase
        $php_passthru = "passthru(" ascii nocase
        $php_shell = "shell_exec(" ascii nocase
        $php_popen = "popen(" ascii nocase
        $php_proc = "proc_open(" ascii nocase
        $php_base64 = "base64_decode(" ascii nocase
        $php_assert = "assert(" ascii nocase
        $cmd_whoami = "whoami" ascii nocase
        $cmd_uname = "uname -a" ascii nocase
        $cmd_id = /\\bid\\b/ ascii
    condition:
        filesize < 500KB and
        (2 of ($php_*) or (1 of ($php_*) and 1 of ($cmd_*)))
}`;
  },

  malware: (ctx, iocs) => {
    const payloads = iocs.attackPayloads.filter(p => p.length > 10).slice(0, 5);
    const hexStrings = payloads.map((p, i) => {
      const hex = Buffer.from(p.substring(0, 50)).toString('hex').match(/.{2}/g)?.join(' ') || '';
      return `        $payload_${i} = { ${hex} }`;
    });
    return `rule AC3_ExploitPayload_${sanitizeRuleName(ctx.title)} {
    meta:
        description = "Detects exploit payload for ${ctx.title}"
        author = "Ace C3 Detection Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${ctx.severity}"
${ctx.cve ? `        cve = "${ctx.cve}"\n` : ''}    strings:
${hexStrings.length > 0 ? hexStrings.join('\n') : `        $generic = "exploit" ascii nocase`}
    condition:
        any of them
}`;
  },

  generic: (ctx, iocs) => {
    return `rule AC3_Finding_${sanitizeRuleName(ctx.title)} {
    meta:
        description = "${ctx.title}"
        author = "Ace C3 Detection Engine"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "${ctx.severity}"
${ctx.cve ? `        cve = "${ctx.cve}"\n` : ''}    strings:
        $indicator = "${ctx.title.replace(/"/g, '\\"').substring(0, 100)}" ascii nocase
    condition:
        $indicator
}`;
  },
};

// ─── Rule Category Classification ────────────────────────────────────────────

function classifyFindingCategory(finding: FindingContext): string {
  const title = finding.title.toLowerCase();
  const cwe = finding.cweId?.toLowerCase() || '';
  const owasp = finding.owaspCategory?.toLowerCase() || '';

  if (title.includes('sql injection') || title.includes('sqli') || cwe.includes('cwe-89') || cwe.includes('cwe-564')) return 'sqli';
  if (title.includes('xss') || title.includes('cross-site scripting') || cwe.includes('cwe-79')) return 'xss';
  if (title.includes('command injection') || title.includes('os command') || title.includes('rce') || title.includes('remote code') || cwe.includes('cwe-78') || cwe.includes('cwe-77')) return 'cmdi';
  if (title.includes('path traversal') || title.includes('lfi') || title.includes('local file') || title.includes('directory traversal') || cwe.includes('cwe-22') || cwe.includes('cwe-98')) return 'lfi';
  if (title.includes('brute') || title.includes('credential') || title.includes('weak password') || title.includes('default password') || cwe.includes('cwe-307') || cwe.includes('cwe-521')) return 'bruteforce';
  if (title.includes('web shell') || title.includes('backdoor') || title.includes('reverse shell')) return 'webshell';
  if (title.includes('ssl') || title.includes('tls') || title.includes('certificate') || title.includes('cipher') || cwe.includes('cwe-295') || cwe.includes('cwe-326')) return 'tls';
  if (title.includes('exposure') || title.includes('disclosure') || title.includes('information leak') || title.includes('directory listing') || cwe.includes('cwe-200') || cwe.includes('cwe-548')) return 'exposure';

  return 'generic';
}

// ─── Main Post-Processor ─────────────────────────────────────────────────────

export function postProcessDetectionRules(
  findings: Array<{
    title: string;
    severity: string;
    cve?: string;
    cweId?: string;
    affectedAssets: string[];
    evidence?: Array<{ type: string; description: string; data: string }>;
    owaspCategory?: string;
    detectionRules: DetectionRules;
  }>,
  engagementIOCs: EngagementIOCs
): void {
  for (const finding of findings) {
    const category = classifyFindingCategory(finding);
    const ctx: FindingContext = {
      title: finding.title,
      severity: finding.severity,
      cve: finding.cve,
      cweId: finding.cweId,
      affectedAssets: finding.affectedAssets,
      evidence: finding.evidence,
      owaspCategory: finding.owaspCategory,
    };

    // Check if LLM-generated rules are placeholders or empty
    const sigmaIsPlaceholder = !finding.detectionRules.sigma || isPlaceholderRule(finding.detectionRules.sigma);
    const suricataIsPlaceholder = !finding.detectionRules.suricata || isPlaceholderRule(finding.detectionRules.suricata);
    const yaraIsPlaceholder = !finding.detectionRules.yara || isPlaceholderRule(finding.detectionRules.yara);

    // Replace placeholders with production-ready rules
    if (sigmaIsPlaceholder) {
      const template = SIGMA_TEMPLATES[category] || SIGMA_TEMPLATES.generic;
      finding.detectionRules.sigma = template(ctx, engagementIOCs);
    } else {
      // Inject real IOCs into existing LLM-generated rules
      finding.detectionRules.sigma = injectIOCsIntoSigma(finding.detectionRules.sigma!, engagementIOCs);
    }

    if (suricataIsPlaceholder) {
      const template = SURICATA_TEMPLATES[category] || SURICATA_TEMPLATES.generic;
      finding.detectionRules.suricata = template(ctx, engagementIOCs);
    } else {
      finding.detectionRules.suricata = injectIOCsIntoSuricata(finding.detectionRules.suricata!, engagementIOCs);
    }

    // YARA rules are only useful for file-based findings (webshells, malware, exploit payloads)
    if (category === 'webshell' || category === 'cmdi' || (finding.evidence?.some(e => e.type === 'attack_payload'))) {
      if (yaraIsPlaceholder) {
        const yaraCategory = category === 'webshell' ? 'webshell' : 'malware';
        const template = YARA_TEMPLATES[yaraCategory] || YARA_TEMPLATES.generic;
        finding.detectionRules.yara = template(ctx, engagementIOCs);
      }
    } else {
      // Don't generate YARA for network-only findings — it's not applicable
      if (yaraIsPlaceholder) {
        finding.detectionRules.yara = null;
      }
    }
  }
}

// ─── IOC Extraction from Engagement Data ─────────────────────────────────────

export function extractIOCsFromEngagement(
  assets: Array<{
    hostname: string;
    ip?: string;
    knownPorts?: Array<{ port: number; service?: string; version?: string } | number>;
    technologies?: string[];
    vulns?: Array<{ attack?: string; param?: string; url?: string; evidence?: string }>;
    toolResults?: Array<{ rawOutput?: string; findings?: Array<{ attack?: string; param?: string; url?: string }> }>;
    exploitAttempts?: Array<{ payload?: string; output?: string }>;
  }>
): EngagementIOCs {
  const iocs: EngagementIOCs = {
    targetIPs: [],
    targetHostnames: [],
    detectedSoftware: [],
    attackPayloads: [],
    vulnerableParams: [],
    vulnerableURLs: [],
    exploitModules: [],
    detectedPorts: [],
  };

  for (const asset of assets) {
    if (asset.hostname) iocs.targetHostnames.push(asset.hostname);
    if (asset.ip) iocs.targetIPs.push(asset.ip);

    // Extract ports
    for (const p of asset.knownPorts || []) {
      if (typeof p === 'number') {
        iocs.detectedPorts.push(p);
      } else {
        iocs.detectedPorts.push(p.port);
        if (p.service && p.version) {
          iocs.detectedSoftware.push({ name: p.service, version: p.version });
        }
      }
    }

    // Extract technologies
    for (const tech of asset.technologies || []) {
      const versionMatch = tech.match(/^(.+?)\s+([\d.]+)/);
      if (versionMatch) {
        iocs.detectedSoftware.push({ name: versionMatch[1], version: versionMatch[2] });
      } else {
        iocs.detectedSoftware.push({ name: tech });
      }
    }

    // Extract attack payloads and vulnerable params from vulns
    for (const v of asset.vulns || []) {
      if (v.attack) iocs.attackPayloads.push(v.attack);
      if (v.param) iocs.vulnerableParams.push(v.param);
      if (v.url) iocs.vulnerableURLs.push(v.url);
    }

    // Extract from tool results
    for (const tr of asset.toolResults || []) {
      for (const f of tr.findings || []) {
        if ((f as any).attack) iocs.attackPayloads.push((f as any).attack);
        if ((f as any).param) iocs.vulnerableParams.push((f as any).param);
        if ((f as any).url) iocs.vulnerableURLs.push((f as any).url);
      }
    }

    // Extract from exploit attempts
    for (const ea of asset.exploitAttempts || []) {
      if (ea.payload) iocs.attackPayloads.push(ea.payload);
    }
  }

  // Deduplicate
  iocs.targetIPs = [...new Set(iocs.targetIPs)];
  iocs.targetHostnames = [...new Set(iocs.targetHostnames)];
  iocs.attackPayloads = [...new Set(iocs.attackPayloads)].slice(0, 20);
  iocs.vulnerableParams = [...new Set(iocs.vulnerableParams)].slice(0, 20);
  iocs.vulnerableURLs = [...new Set(iocs.vulnerableURLs)].slice(0, 20);
  iocs.detectedPorts = [...new Set(iocs.detectedPorts)].sort((a, b) => a - b);

  return iocs;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function isPlaceholderRule(rule: string): boolean {
  const lower = rule.toLowerCase();
  const placeholderIndicators = [
    'todo',
    'placeholder',
    'example',
    'replace with',
    'insert ',
    'your_',
    '<target',
    '<ip',
    '<host',
    'xxx.xxx',
    '0.0.0.0',
    'example.com',
    'target_ip',
    'target_host',
    'change_me',
    'customize',
    'modify as needed',
    'adjust according',
    'update with actual',
    'generic detection',
  ];
  return placeholderIndicators.some(p => lower.includes(p)) ||
    rule.trim().length < 50 ||
    (rule.includes('$') && !rule.includes('alert') && !rule.includes('rule') && rule.length < 100);
}

function injectIOCsIntoSigma(rule: string, iocs: EngagementIOCs): string {
  let result = rule;
  // Replace placeholder IPs
  result = result.replace(/\b(10\.0\.0\.1|192\.168\.1\.1|0\.0\.0\.0|xxx\.xxx\.xxx\.xxx|target_ip)\b/gi,
    iocs.targetIPs[0] || '$EXTERNAL_NET');
  // Replace placeholder hostnames
  result = result.replace(/\b(example\.com|target\.com|target_host)\b/gi,
    iocs.targetHostnames[0] || 'target');
  return result;
}

function injectIOCsIntoSuricata(rule: string, iocs: EngagementIOCs): string {
  let result = rule;
  // Replace placeholder IPs in Suricata rules
  result = result.replace(/\b(10\.0\.0\.1|192\.168\.1\.1|0\.0\.0\.0|xxx\.xxx\.xxx\.xxx|TARGET_IP)\b/gi,
    iocs.targetIPs.length > 0 ? iocs.targetIPs.join(',') : 'any');
  return result;
}

function generateRuleId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;
}

let sidCounter = 9000000;
function generateSID(): number {
  return sidCounter++;
}

function sanitizeRuleName(title: string): string {
  return title.replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 50);
}

function escapeYaml(str: string): string {
  return str.replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function escapeQuotes(str: string): string {
  return str.replace(/"/g, '\\"').substring(0, 100);
}
