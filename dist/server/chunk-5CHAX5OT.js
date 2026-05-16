import {
  init_knowledge_loader,
  loadKnowledgeData
} from "./chunk-3ZWO3NC7.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/offensive-techniques-knowledge.ts
async function initOffensiveTechniques() {
  if (_loaded) return;
  const data = await loadKnowledgeData("offensive_techniques.json", FALLBACK);
  LOTL_RESOURCES = data.lotlResources || [];
  FILE_UPLOAD_BYPASS_TECHNIQUES = data.fileUploadBypassTechniques || [];
  FIREWALL_TESTING_TOOLS = data.firewallTestingTools || [];
  SOCIAL_ENGINEERING_TAXONOMY = data.socialEngineeringTaxonomy || [];
  SHODAN_QUERIES = data.shodanQueries || [];
  SHODAN_FILTERS = data.shodanFilters || {};
  SUBDOMAIN_TOOLS = data.subdomainTools || [];
  _loaded = true;
  console.log(`[OffensiveTech] Loaded ${LOTL_RESOURCES.length} LOTL, ${FILE_UPLOAD_BYPASS_TECHNIQUES.length} upload bypass, ${FIREWALL_TESTING_TOOLS.length} FW tools`);
}
function getLOTLContext(platform) {
  const relevant = platform ? LOTL_RESOURCES.filter((r) => r.platform === platform || r.platform === "cross-platform") : LOTL_RESOURCES;
  const formatted = relevant.map(
    (r) => `- **${r.name}** (${r.platform}): ${r.description}${r.mitreTechniques.length ? ` [MITRE: ${r.mitreTechniques.join(", ")}]` : ""}`
  ).join("\n");
  return `## Living Off the Land (LOTL) Resources
When planning post-exploitation or lateral movement, leverage legitimate system binaries and drivers to avoid detection:

${formatted}

**Key Principle:** Prefer LOTL techniques over dropping custom tools. They blend with normal system activity and are harder to detect.${platform === "windows" ? " Check LOLBAS for Windows binaries, LOLDrivers for driver abuse, and WADComs for AD attacks." : platform === "linux" ? " Check GTFOBins for Unix binary abuse and privilege escalation." : platform === "macos" ? " Check LOOBins for macOS native binary abuse." : " Check GTFOBins (Linux), LOLBAS (Windows), or LOOBins (macOS) before writing custom payloads."}`;
}
function getFileUploadBypassContext() {
  const formatted = FILE_UPLOAD_BYPASS_TECHNIQUES.map(
    (t) => `### ${t.name}
**Character:** ${t.character} | **Hex:** ${t.hexValue}
**Description:** ${t.description}
**Payloads:** ${t.payloads.slice(0, 4).join(", ")}`
  ).join("\n\n");
  return `## File Upload Extension Filter Bypass Techniques
When testing file upload functionality, use extension splitting to bypass server-side filters:

${formatted}

**Strategy:** Start with null byte (%00), then newline/CR, then Unicode overlong. Test each encoding variant. Goal: server sees ".php" while filter sees ".png".

**Additional Techniques:**
- Double extensions: shell.php.png, shell.png.php
- Case variation: shell.pHp, shell.PHP
- Alternate extensions: shell.phtml, shell.php5, shell.phar
- Content-Type mismatch: Upload .php with Content-Type: image/png
- Magic bytes: Prepend PNG header to PHP file`;
}
function getFirewallEvasionContext(hasFirewall, hasWAF) {
  let tools = FIREWALL_TESTING_TOOLS;
  if (hasWAF) {
    tools = [
      ...tools.filter((t) => t.category === "waf"),
      ...tools.filter((t) => t.category === "evasion"),
      ...tools.filter((t) => t.category === "tunneling"),
      ...tools.filter((t) => t.category !== "waf" && t.category !== "evasion" && t.category !== "tunneling")
    ];
  } else if (hasFirewall) {
    tools = [
      ...tools.filter((t) => t.category === "evasion"),
      ...tools.filter((t) => t.category === "tunneling"),
      ...tools.filter((t) => t.category !== "evasion" && t.category !== "tunneling")
    ];
  }
  const formatted = tools.map(
    (t) => `${t.id}. **${t.technique}** -> ${t.tool} [${t.category}] [MITRE: ${t.mitreTechniques.join(", ")}]`
  ).join("\n");
  return `## Firewall & WAF Testing/Evasion Checklist
${hasWAF ? "WAF DETECTED - prioritize WAF bypass techniques before active scanning." : ""}
${hasFirewall ? "Firewall detected - consider evasion and tunneling techniques." : ""}

${formatted}

**Evasion Strategy:**
1. Detect first: Use Wafw00f to identify WAF vendor, then tailor bypass payloads
2. Fragment packets: Use Fragroute/Masscan/Naabu -f to split payloads across fragments
3. Tunnel traffic: If ports are filtered, try DNS tunneling (Dns2tcp/Iodine) or HTTP tunneling
4. Encode payloads: Use Veil-Evasion for encrypted payloads that bypass signature detection
5. Timing: Use slow scan rates (rate-limited scanning) to avoid rate-based detection
6. Source spoofing: Use decoy IPs (ScanForge Discovery -D) and source port spoofing (--source-port 53/80)`;
}
function getSocialEngineeringContext(category) {
  const relevant = category ? SOCIAL_ENGINEERING_TAXONOMY.filter((c) => c.name.toLowerCase() === category.toLowerCase()) : SOCIAL_ENGINEERING_TAXONOMY;
  const formatted = relevant.map((cat) => {
    const subs = cat.subTechniques.map(
      (st) => `  - **${st.name}:** ${st.description}`
    ).join("\n");
    return `### ${cat.name} [MITRE: ${cat.mitreTechnique}]
${cat.description}
${subs}`;
  }).join("\n\n");
  return `## Social Engineering Attack Taxonomy
Use this taxonomy when planning phishing campaigns, assessing social engineering risk, or generating awareness training content:

${formatted}

**Campaign Planning Tips:**
- Match the attack vector to the target's role (executives -> BEC, IT staff -> tech support scam, general staff -> phishing)
- Layer multiple techniques: spear phishing email -> fake login page -> credential harvest -> BEC follow-up
- Use pretexting to establish trust before the primary attack vector`;
}
function getShodanReconContext(targetType) {
  let queries = SHODAN_QUERIES;
  if (targetType) {
    queries = SHODAN_QUERIES.filter((q) => q.category === targetType);
    if (queries.length === 0) queries = SHODAN_QUERIES;
  }
  const formatted = queries.map((q) => `- **${q.target}:** \`${q.query}\``).join("\n");
  const filterSummary = Object.entries(SHODAN_FILTERS).map(
    ([cat, filters]) => `- **${cat}:** ${filters.slice(0, 8).join(", ")}${filters.length > 8 ? ` (+${filters.length - 8} more)` : ""}`
  ).join("\n");
  return `## Shodan Reconnaissance Queries
Use these pre-built Shodan queries to discover exposed services and attack surface:

${formatted}

### Available Shodan Filters
${filterSummary}

**Recon Strategy:**
1. Start with broad service discovery: hostname:target.com or org:"Target Corp"
2. Narrow by exposed databases, remote access, and IoT/ICS systems
3. Check for authentication-disabled services (VNC, Samba, FTP anonymous)
4. Use has_vuln:true filter to find hosts with known CVEs
5. Cross-reference Shodan findings with ScanForge discovery results for validation`;
}
function getSubdomainEnumContext() {
  const byTier = (tier) => SUBDOMAIN_TOOLS.filter((t) => t.tier === tier).map((t) => `  - **${t.name}** (${t.method}): ${t.description}`).join("\n");
  return `## Subdomain Enumeration Strategy
Use a layered approach combining passive and active enumeration:

### Tier 1: Primary Tools (always use)
${byTier("primary")}

### Tier 2: Secondary Tools (additional coverage)
${byTier("secondary")}

### Tier 3: Specialized Tools (specific scenarios)
${byTier("specialized")}

**Recommended Workflow:**
1. Passive first: Run Subfinder + Amass passive + Assetfinder in parallel
2. Certificate transparency: Query crt.sh and Censys for CT log entries
3. DNS brute-force: Use Massdns + dnsx with quality wordlist (SecLists dns)
4. Permutation: Run altdns on discovered subdomains to find variations
5. Validation: Resolve all discovered subdomains with dnsx, filter live hosts
6. Visual recon: Run Aquatone/httpx on live subdomains for screenshots and tech detection
7. Reverse DNS: Use hakrevdns on IP ranges to find additional hostnames`;
}
function buildOffensiveTechniquesContext(params) {
  const sections = [];
  if (params.phase === "recon" || params.phase === "enumeration") {
    sections.push(getSubdomainEnumContext());
    if (params.includeShodan !== false) {
      sections.push(getShodanReconContext());
    }
  }
  if (params.phase === "enumeration" || params.phase === "vuln_detection") {
    if (params.hasFirewall || params.hasWAF) {
      sections.push(getFirewallEvasionContext(params.hasFirewall, params.hasWAF));
    }
    if (params.hasFileUpload) {
      sections.push(getFileUploadBypassContext());
    }
  }
  if (params.phase === "exploitation" || params.phase === "post_exploitation") {
    sections.push(getLOTLContext(params.platform));
    if (params.hasFileUpload) {
      sections.push(getFileUploadBypassContext());
    }
  }
  if (params.phase === "post_exploitation") {
    if (params.hasFirewall || params.hasWAF) {
      sections.push(getFirewallEvasionContext(params.hasFirewall, params.hasWAF));
    }
  }
  if (params.includePhishing) {
    sections.push(getSocialEngineeringContext());
  }
  if (sections.length === 0) return "";
  return `# Offensive Techniques Knowledge Base

${sections.join("\n\n---\n\n")}`;
}
var FALLBACK, LOTL_RESOURCES, FILE_UPLOAD_BYPASS_TECHNIQUES, FIREWALL_TESTING_TOOLS, SOCIAL_ENGINEERING_TAXONOMY, SHODAN_QUERIES, SHODAN_FILTERS, SUBDOMAIN_TOOLS, _loaded;
var init_offensive_techniques_knowledge = __esm({
  "server/lib/knowledge/offensive-techniques-knowledge.ts"() {
    "use strict";
    init_knowledge_loader();
    FALLBACK = {
      lotlResources: [],
      fileUploadBypassTechniques: [],
      firewallTestingTools: [],
      socialEngineeringTaxonomy: [],
      shodanQueries: [],
      shodanFilters: {},
      subdomainTools: []
    };
    LOTL_RESOURCES = [];
    FILE_UPLOAD_BYPASS_TECHNIQUES = [];
    FIREWALL_TESTING_TOOLS = [];
    SOCIAL_ENGINEERING_TAXONOMY = [];
    SHODAN_QUERIES = [];
    SHODAN_FILTERS = {};
    SUBDOMAIN_TOOLS = [];
    _loaded = false;
    initOffensiveTechniques().catch((e) => console.warn("[OffensiveTech] Auto-init failed:", e.message));
  }
});

export {
  getLOTLContext,
  getFileUploadBypassContext,
  getFirewallEvasionContext,
  getSocialEngineeringContext,
  getShodanReconContext,
  getSubdomainEnumContext,
  buildOffensiveTechniquesContext,
  init_offensive_techniques_knowledge
};
