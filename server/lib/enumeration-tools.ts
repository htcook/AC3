/**
 * Enumeration Tools Module
 * 
 * Provides command generation and output parsing for all enumeration tools
 * that run on the scan server. These are integrated into the engagement
 * orchestrator's Phase B (targeted tool deployment).
 * 
 * Tools:
 * - Katana: JS-aware web crawling (R1 — Critical)
 * - Feroxbuster: Recursive content discovery (R4 — High)
 * - ffuf: Web fuzzing + virtual host enumeration (R4, R12 — High/Medium)
 * - testssl.sh: TLS vulnerability testing (R8 — Medium)
 * - Arjun: Hidden parameter discovery (R7 — High)
 * - ParamSpider: Web archive parameter mining (R7 — High)
 * - wafw00f: WAF fingerprinting (R15 — Low)
 * - API Spec Discovery: Swagger/GraphQL/WSDL probing (R5 — High)
 */

// ─── Katana: JS-Aware Web Crawling ──────────────────────────────────

export interface KatanaConfig {
  target: string;
  depth?: number;           // Crawl depth (default: 3)
  jsRendering?: boolean;    // Enable headless JS rendering (default: true)
  timeout?: number;         // Per-request timeout in seconds (default: 15)
  maxDuration?: number;     // Max total crawl duration in seconds (default: 300)
  rateLimit?: number;       // Requests per second (default: 10)
  scope?: string[];         // Restrict crawling to these domains
  excludePatterns?: string[]; // URL patterns to exclude
  formFill?: boolean;       // Auto-fill and submit forms (default: false)
  evasionLevel?: number;    // 0-3, higher = more evasion
}

export function buildKatanaCommand(config: KatanaConfig): string {
  const args = [
    "katana",
    `-u ${config.target}`,
    `-d ${config.depth ?? 3}`,
    "-jc",                  // JavaScript crawling
    "-kf",                  // Known files (robots.txt, sitemap.xml, etc.)
    "-json",                // JSON output
    "-silent",
    `-timeout ${config.timeout ?? 15}`,
    `-rate-limit ${config.rateLimit ?? 10}`,
  ];

  if (config.jsRendering !== false) {
    args.push("-headless"); // Enable headless browser for JS rendering
  }

  if (config.maxDuration) {
    args.push(`-crawl-duration ${config.maxDuration}s`);
  }

  if (config.scope?.length) {
    for (const s of config.scope) {
      args.push(`-cs ${s}`);
    }
  }

  if (config.excludePatterns?.length) {
    for (const p of config.excludePatterns) {
      args.push(`-ef ${p}`);
    }
  }

  if (config.formFill) {
    args.push("-form-fill");
    args.push("-form-extraction");
  }

  if (config.evasionLevel && config.evasionLevel > 0) {
    args.push(`-delay ${config.evasionLevel * 2}s`); // Add delay for evasion
    args.push("-random-agent");
  }

  return args.join(" ");
}

export interface KatanaResult {
  endpoints: string[];
  forms: { action: string; method: string; inputs: string[] }[];
  jsFiles: string[];
  apiEndpoints: string[];
  emails: string[];
  totalUrls: number;
}

export function parseKatanaOutput(stdout: string): KatanaResult {
  const endpoints: string[] = [];
  const forms: { action: string; method: string; inputs: string[] }[] = [];
  const jsFiles: string[] = [];
  const apiEndpoints: string[] = [];
  const emails: string[] = [];

  for (const line of stdout.split("\n").filter(Boolean)) {
    try {
      const entry = JSON.parse(line);
      const url = entry.request?.endpoint || entry.endpoint || entry.url || "";
      if (url) {
        endpoints.push(url);
        if (url.match(/\.js(\?|$)/i)) jsFiles.push(url);
        if (url.match(/\/(api|v[0-9]+|graphql|rest)\//i)) apiEndpoints.push(url);
      }
      if (entry.form) {
        forms.push({
          action: entry.form.action || "",
          method: entry.form.method || "GET",
          inputs: (entry.form.inputs || []).map((i: any) => i.name || i),
        });
      }
      // Extract emails from response body
      const body = entry.response?.body || "";
      const emailMatches = body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
      if (emailMatches) emails.push(...emailMatches);
    } catch {
      // Non-JSON line — might be a plain URL
      if (line.startsWith("http")) endpoints.push(line.trim());
    }
  }

  return {
    endpoints: [...new Set(endpoints)],
    forms,
    jsFiles: [...new Set(jsFiles)],
    apiEndpoints: [...new Set(apiEndpoints)],
    emails: [...new Set(emails)],
    totalUrls: endpoints.length,
  };
}

// ─── Feroxbuster: Recursive Content Discovery ───────────────────────

export interface FeroxbusterConfig {
  target: string;
  wordlist?: string;        // Default: raft-medium-directories.txt
  threads?: number;         // Default: 50
  depth?: number;           // Recursion depth (default: 3)
  timeout?: number;         // Per-request timeout in seconds (default: 10)
  statusCodes?: number[];   // Status codes to include (default: 200,204,301,302,307,308,401,403,405)
  extensions?: string[];    // File extensions to append (default: php,asp,aspx,jsp,html,js)
  filterSize?: number[];    // Filter responses by size
  evasionLevel?: number;    // 0-3
  autoCalibration?: boolean; // Auto-filter false positives (default: true)
}

export function buildFeroxbusterCommand(config: FeroxbusterConfig): string {
  const wordlist = config.wordlist ?? "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt";
  const statusCodes = config.statusCodes ?? [200, 204, 301, 302, 307, 308, 401, 403, 405];
  const extensions = config.extensions ?? ["php", "asp", "aspx", "jsp", "html", "js"];

  const args = [
    "feroxbuster",
    `-u ${config.target}`,
    `-w ${wordlist}`,
    `-t ${config.threads ?? 50}`,
    `--depth ${config.depth ?? 3}`,
    `--timeout ${config.timeout ?? 10}`,
    `--status-codes ${statusCodes.join(",")}`,
    `-x ${extensions.join(",")}`,
    "--json",
    "--quiet",
    "--no-state",           // Don't save state file
    "--dont-scan /logout",  // Avoid logout endpoints
  ];

  if (config.autoCalibration !== false) {
    args.push("--auto-calibration");
  }

  if (config.filterSize?.length) {
    for (const s of config.filterSize) {
      args.push(`-S ${s}`);
    }
  }

  if (config.evasionLevel && config.evasionLevel > 0) {
    args.push("--random-agent");
    if (config.evasionLevel >= 2) {
      args.push(`--rate-limit ${Math.max(5, 30 - config.evasionLevel * 10)}`);
    }
  }

  return args.join(" ");
}

export interface FeroxbusterResult {
  urls: { url: string; status: number; size: number; lines: number; words: number }[];
  directories: string[];
  files: string[];
  totalFound: number;
}

export function parseFeroxbusterOutput(stdout: string): FeroxbusterResult {
  const urls: { url: string; status: number; size: number; lines: number; words: number }[] = [];
  const directories: string[] = [];
  const files: string[] = [];

  for (const line of stdout.split("\n").filter(Boolean)) {
    try {
      const entry = JSON.parse(line);
      if (entry.type === "response" && entry.url) {
        urls.push({
          url: entry.url,
          status: entry.status || 0,
          size: entry.content_length || entry.line_count || 0,
          lines: entry.line_count || 0,
          words: entry.word_count || 0,
        });
        if (entry.is_directory || entry.url.endsWith("/")) {
          directories.push(entry.url);
        } else {
          files.push(entry.url);
        }
      }
    } catch {
      // Skip non-JSON lines
    }
  }

  return {
    urls,
    directories: [...new Set(directories)],
    files: [...new Set(files)],
    totalFound: urls.length,
  };
}

// ─── ffuf: Web Fuzzer + Virtual Host Enumeration ────────────────────

export interface FfufConfig {
  target: string;
  wordlist?: string;
  mode: "content" | "vhost" | "parameter";
  threads?: number;
  timeout?: number;
  matchCodes?: number[];
  filterSize?: number[];
  filterWords?: number[];
  filterLines?: number[];
  extensions?: string[];
  method?: string;
  headers?: Record<string, string>;
  data?: string;            // POST body with FUZZ keyword
  evasionLevel?: number;
}

export function buildFfufCommand(config: FfufConfig): string {
  const wordlist = config.wordlist ?? "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt";
  const matchCodes = config.matchCodes ?? [200, 204, 301, 302, 307, 308, 401, 403, 405];

  const args = [
    "ffuf",
    `-w ${wordlist}`,
    `-t ${config.threads ?? 40}`,
    `-timeout ${config.timeout ?? 10}`,
    `-mc ${matchCodes.join(",")}`,
    "-json",
    "-s",                   // Silent mode
  ];

  if (config.mode === "vhost") {
    // Virtual host enumeration
    args.push(`-u ${config.target}`);
    args.push(`-H "Host: FUZZ.${new URL(config.target).hostname}"`);
  } else if (config.mode === "parameter") {
    // Parameter fuzzing
    if (config.method === "POST") {
      args.push(`-u ${config.target}`);
      args.push(`-X POST`);
      args.push(`-d "${config.data || 'FUZZ=test'}"`);
    } else {
      args.push(`-u ${config.target}?FUZZ=test`);
    }
  } else {
    // Content discovery
    args.push(`-u ${config.target}/FUZZ`);
    if (config.extensions?.length) {
      args.push(`-e ${config.extensions.map(e => `.${e}`).join(",")}`);
    }
  }

  if (config.filterSize?.length) {
    args.push(`-fs ${config.filterSize.join(",")}`);
  }
  if (config.filterWords?.length) {
    args.push(`-fw ${config.filterWords.join(",")}`);
  }
  if (config.filterLines?.length) {
    args.push(`-fl ${config.filterLines.join(",")}`);
  }

  if (config.headers) {
    for (const [k, v] of Object.entries(config.headers)) {
      args.push(`-H "${k}: ${v}"`);
    }
  }

  if (config.evasionLevel && config.evasionLevel > 0) {
    args.push(`-rate ${Math.max(5, 50 - config.evasionLevel * 15)}`);
  }

  return args.join(" ");
}

export interface FfufResult {
  results: { input: string; url: string; status: number; size: number; words: number; lines: number; host?: string }[];
  totalFound: number;
}

export function parseFfufOutput(stdout: string): FfufResult {
  const results: FfufResult["results"] = [];

  try {
    const data = JSON.parse(stdout);
    if (data.results && Array.isArray(data.results)) {
      for (const r of data.results) {
        results.push({
          input: r.input?.FUZZ || "",
          url: r.url || "",
          status: r.status || 0,
          size: r.length || 0,
          words: r.words || 0,
          lines: r.lines || 0,
          host: r.host || undefined,
        });
      }
    }
  } catch {
    // Try line-by-line JSON
    for (const line of stdout.split("\n").filter(Boolean)) {
      try {
        const entry = JSON.parse(line);
        if (entry.url) {
          results.push({
            input: entry.input?.FUZZ || "",
            url: entry.url,
            status: entry.status || 0,
            size: entry.length || 0,
            words: entry.words || 0,
            lines: entry.lines || 0,
            host: entry.host || undefined,
          });
        }
      } catch {
        continue;
      }
    }
  }

  return { results, totalFound: results.length };
}

// ─── testssl.sh: TLS Vulnerability Testing ──────────────────────────

export interface TestsslConfig {
  target: string;           // host:port
  checks?: ("protocols" | "ciphers" | "vulnerabilities" | "headers" | "certificate")[];
  timeout?: number;
  fast?: boolean;           // Skip less critical checks
}

export function buildTestsslCommand(config: TestsslConfig): string {
  const args = [
    "testssl.sh",
    "--jsonfile -",         // JSON output to stdout
    "--quiet",
    "--color 0",            // No ANSI colors
    "--sneaky",             // Use common user-agent
  ];

  if (config.fast) {
    args.push("--fast");
  }

  if (config.checks?.length) {
    if (config.checks.includes("protocols")) args.push("-p");
    if (config.checks.includes("ciphers")) args.push("-E");
    if (config.checks.includes("vulnerabilities")) args.push("-U");
    if (config.checks.includes("headers")) args.push("-h");
    if (config.checks.includes("certificate")) args.push("-S");
  }

  if (config.timeout) {
    args.push(`--connect-timeout ${config.timeout}`);
    args.push(`--openssl-timeout ${config.timeout}`);
  }

  args.push(config.target);

  return args.join(" ");
}

export interface TestsslResult {
  vulnerabilities: { id: string; severity: string; finding: string; cve?: string }[];
  protocols: { name: string; enabled: boolean; severity: string }[];
  ciphers: { name: string; severity: string; bits: number }[];
  certificate: { subject: string; issuer: string; validFrom: string; validTo: string; sigAlg: string; keySize: number }[];
  totalFindings: number;
}

export function parseTestsslOutput(stdout: string): TestsslResult {
  const vulnerabilities: TestsslResult["vulnerabilities"] = [];
  const protocols: TestsslResult["protocols"] = [];
  const ciphers: TestsslResult["ciphers"] = [];
  const certificate: TestsslResult["certificate"] = [];

  try {
    const entries = JSON.parse(stdout);
    if (!Array.isArray(entries)) return { vulnerabilities, protocols, ciphers, certificate, totalFindings: 0 };

    for (const entry of entries) {
      const severity = entry.severity || "INFO";
      const id = entry.id || "";
      const finding = entry.finding || "";

      // Vulnerability checks
      if (id.match(/^(heartbleed|CCS|ticketbleed|ROBOT|secure_renego|secure_client_renego|CRIME|BREACH|POODLE|TLS_FALLBACK|SWEET32|FREAK|DROWN|LOGJAM|BEAST|LUCKY13|RC4)/i)) {
        if (severity !== "OK" && severity !== "INFO") {
          vulnerabilities.push({
            id,
            severity: severity.toLowerCase(),
            finding,
            cve: entry.cve || undefined,
          });
        }
      }
      // Protocol checks
      else if (id.match(/^(SSLv2|SSLv3|TLS1$|TLS1_1|TLS1_2|TLS1_3)/)) {
        protocols.push({
          name: id,
          enabled: !finding.includes("not offered"),
          severity: severity.toLowerCase(),
        });
      }
      // Certificate info
      else if (id.match(/^(cert_|chain_)/)) {
        if (id === "cert_commonName" || id === "cert_subjectAltName") {
          certificate.push({
            subject: finding,
            issuer: "",
            validFrom: "",
            validTo: "",
            sigAlg: "",
            keySize: 0,
          });
        }
      }
    }
  } catch {
    // Non-JSON output
  }

  return {
    vulnerabilities,
    protocols,
    ciphers,
    certificate,
    totalFindings: vulnerabilities.length + protocols.filter(p => p.severity !== "ok" && p.severity !== "info").length,
  };
}

// ─── Arjun: Hidden Parameter Discovery ──────────────────────────────

export interface ArjunConfig {
  target: string;
  method?: "GET" | "POST" | "JSON";
  threads?: number;
  timeout?: number;
  wordlist?: string;
  headers?: Record<string, string>;
  stable?: boolean;         // Use stable mode for rate-limited targets
}

export function buildArjunCommand(config: ArjunConfig): string {
  const args = [
    "arjun",
    `-u ${config.target}`,
    `-m ${config.method || "GET"}`,
    `-t ${config.threads ?? 10}`,
    `--timeout ${config.timeout ?? 15}`,
    "-oJ /dev/stdout",      // JSON output to stdout
    "--passive",            // Also check Wayback for known params
  ];

  if (config.wordlist) {
    args.push(`-w ${config.wordlist}`);
  }

  if (config.headers) {
    for (const [k, v] of Object.entries(config.headers)) {
      args.push(`--headers "${k}: ${v}"`);
    }
  }

  if (config.stable) {
    args.push("--stable");
  }

  return args.join(" ");
}

export interface ArjunResult {
  parameters: { name: string; method: string; url: string }[];
  totalFound: number;
}

export function parseArjunOutput(stdout: string): ArjunResult {
  const parameters: ArjunResult["parameters"] = [];

  try {
    const data = JSON.parse(stdout);
    // Arjun outputs: { "url": { "method": ["param1", "param2"] } }
    for (const [url, methods] of Object.entries(data)) {
      for (const [method, params] of Object.entries(methods as Record<string, string[]>)) {
        if (Array.isArray(params)) {
          for (const param of params) {
            parameters.push({ name: param, method, url });
          }
        }
      }
    }
  } catch {
    // Try to extract params from non-JSON output
    const paramRegex = /\[(\w+)\]\s+(\S+)/g;
    let match: RegExpExecArray | null;
    while ((match = paramRegex.exec(stdout)) !== null) {
      parameters.push({ name: match[2], method: match[1], url: "" });
    }
  }

  return { parameters, totalFound: parameters.length };
}

// ─── ParamSpider: Web Archive Parameter Mining ──────────────────────

export interface ParamSpiderConfig {
  domain: string;
  exclude?: string[];       // Extensions to exclude (default: css,js,png,jpg,gif,svg,woff,ttf)
  level?: string;           // URL level to crawl (default: high)
}

export function buildParamSpiderCommand(config: ParamSpiderConfig): string {
  const exclude = config.exclude ?? ["css", "js", "png", "jpg", "gif", "svg", "woff", "ttf", "ico", "pdf"];

  const args = [
    "paramspider",
    `-d ${config.domain}`,
    `--exclude ${exclude.join(",")}`,
    `--level ${config.level || "high"}`,
    "-o /dev/stdout",
  ];

  return args.join(" ");
}

export interface ParamSpiderResult {
  urls: string[];
  parameters: { name: string; url: string }[];
  totalUrls: number;
}

export function parseParamSpiderOutput(stdout: string): ParamSpiderResult {
  const urls: string[] = [];
  const paramMap = new Map<string, string>();

  for (const line of stdout.split("\n").filter(Boolean)) {
    if (line.startsWith("http")) {
      urls.push(line.trim());
      // Extract parameter names from URL
      try {
        const url = new URL(line.trim());
        for (const [key] of url.searchParams) {
          if (!paramMap.has(key)) {
            paramMap.set(key, line.trim());
          }
        }
      } catch {
        continue;
      }
    }
  }

  const parameters = Array.from(paramMap.entries()).map(([name, url]) => ({ name, url }));

  return {
    urls: [...new Set(urls)],
    parameters,
    totalUrls: urls.length,
  };
}

// ─── wafw00f: WAF Fingerprinting ────────────────────────────────────

export interface Wafw00fConfig {
  target: string;
  findAll?: boolean;        // Check all WAFs (not just first match)
  verbose?: boolean;
}

export function buildWafw00fCommand(config: Wafw00fConfig): string {
  const args = [
    "wafw00f",
    config.target,
    "-o -",                 // JSON output to stdout
  ];

  if (config.findAll) {
    args.push("-a");        // Check all WAFs
  }

  return args.join(" ");
}

export interface Wafw00fResult {
  waf: string | null;
  manufacturer: string | null;
  detected: boolean;
  allDetected: { name: string; manufacturer: string }[];
}

export function parseWafw00fOutput(stdout: string): Wafw00fResult {
  try {
    const data = JSON.parse(stdout);
    if (Array.isArray(data) && data.length > 0) {
      const first = data[0];
      return {
        waf: first.firewall || null,
        manufacturer: first.manufacturer || null,
        detected: !!first.firewall && first.firewall !== "None",
        allDetected: data
          .filter((d: any) => d.firewall && d.firewall !== "None")
          .map((d: any) => ({ name: d.firewall, manufacturer: d.manufacturer || "" })),
      };
    }
  } catch {
    // Try text parsing
    const wafMatch = stdout.match(/is behind (.+?)(?:\s*\((.+?)\))?$/m);
    if (wafMatch) {
      return {
        waf: wafMatch[1].trim(),
        manufacturer: wafMatch[2]?.trim() || null,
        detected: true,
        allDetected: [{ name: wafMatch[1].trim(), manufacturer: wafMatch[2]?.trim() || "" }],
      };
    }
  }

  return { waf: null, manufacturer: null, detected: false, allDetected: [] };
}

// ─── API Specification Discovery ────────────────────────────────────

export interface ApiSpecProbeConfig {
  target: string;           // Base URL (e.g., https://example.com)
  timeout?: number;
}

/**
 * Build a list of API specification probe URLs to check.
 * These are common locations for API documentation endpoints.
 */
export function getApiSpecProbeUrls(baseUrl: string): string[] {
  const base = baseUrl.replace(/\/+$/, "");
  return [
    // OpenAPI / Swagger
    `${base}/swagger.json`,
    `${base}/swagger.yaml`,
    `${base}/openapi.json`,
    `${base}/openapi.yaml`,
    `${base}/api-docs`,
    `${base}/api-docs.json`,
    `${base}/v1/api-docs`,
    `${base}/v2/api-docs`,
    `${base}/v3/api-docs`,
    `${base}/api/swagger.json`,
    `${base}/api/openapi.json`,
    `${base}/docs`,
    `${base}/docs/api`,
    `${base}/api/docs`,
    `${base}/swagger-ui.html`,
    `${base}/swagger-ui/`,
    `${base}/redoc`,
    // GraphQL
    `${base}/graphql`,
    `${base}/graphiql`,
    `${base}/playground`,
    `${base}/altair`,
    `${base}/api/graphql`,
    `${base}/v1/graphql`,
    // WSDL / SOAP
    `${base}?wsdl`,
    `${base}/service?wsdl`,
    `${base}/ws?wsdl`,
    `${base}/api?wsdl`,
    // gRPC
    `${base}/grpc.reflection.v1alpha.ServerReflection`,
    // Other API docs
    `${base}/.well-known/openapi`,
    `${base}/api/v1`,
    `${base}/api/v2`,
    `${base}/api/health`,
    `${base}/api/status`,
    `${base}/api/version`,
    `${base}/actuator`,
    `${base}/actuator/info`,
    `${base}/actuator/health`,
    `${base}/actuator/env`,
  ];
}

/**
 * Build a GraphQL introspection query for detecting GraphQL endpoints.
 */
export function getGraphQLIntrospectionQuery(): string {
  return JSON.stringify({
    query: `{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description type{name kind ofType{name kind}}}}}}`,
  });
}

// ─── Recursive Subdomain Enumeration ────────────────────────────────

/**
 * Generate sub-subdomain targets for recursive enumeration.
 * Given discovered subdomains, create targets for depth-2 enumeration.
 */
export function generateRecursiveTargets(
  discoveredSubdomains: string[],
  rootDomain: string,
  maxDepth = 2,
): string[] {
  const targets: string[] = [];
  
  for (const sub of discoveredSubdomains) {
    // Only recurse on subdomains that are exactly one level deep
    const parts = sub.replace(`.${rootDomain}`, "").split(".");
    if (parts.length < maxDepth) {
      targets.push(sub);
    }
  }

  return targets;
}

// ─── Technology-Specific Wordlist Selection ─────────────────────────

export interface TechWordlistConfig {
  technologies: string[];   // Detected technologies from httpx
  baseWordlist?: string;
}

/**
 * Select appropriate wordlists based on detected technologies.
 * Returns paths to SecLists wordlists that match the tech stack.
 */
export function selectTechWordlists(technologies: string[]): string[] {
  const wordlists: string[] = [];
  const techLower = technologies.map(t => t.toLowerCase());

  // Always include the upgraded base wordlist
  wordlists.push("/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt");

  // Technology-specific wordlists
  if (techLower.some(t => t.includes("wordpress") || t.includes("wp"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt");
  }
  if (techLower.some(t => t.includes("drupal"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/CMS/drupal.txt");
  }
  if (techLower.some(t => t.includes("joomla"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/CMS/joomla-plugins.txt");
  }
  if (techLower.some(t => t.includes("django") || t.includes("python"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/django.txt");
  }
  if (techLower.some(t => t.includes("spring") || t.includes("java") || t.includes("tomcat"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/spring-boot.txt");
    wordlists.push("/opt/SecLists/Discovery/Web-Content/tomcat.txt");
  }
  if (techLower.some(t => t.includes("asp") || t.includes(".net") || t.includes("iis"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/IIS.fuzz.txt");
  }
  if (techLower.some(t => t.includes("php") || t.includes("laravel") || t.includes("symfony"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/PHP.fuzz.txt");
  }
  if (techLower.some(t => t.includes("nginx"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/nginx.txt");
  }
  if (techLower.some(t => t.includes("apache"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/apache.txt");
  }
  if (techLower.some(t => t.includes("node") || t.includes("express") || t.includes("next"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/nodejs.txt");
  }
  if (techLower.some(t => t.includes("ruby") || t.includes("rails"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/ror.txt");
  }
  if (techLower.some(t => t.includes("graphql"))) {
    wordlists.push("/opt/SecLists/Discovery/Web-Content/graphql.txt");
  }

  return [...new Set(wordlists)];
}

// ─── Tool Availability Check ────────────────────────────────────────

/**
 * Commands to check if each tool is installed on the scan server.
 * Returns a map of tool name → check command.
 */
export function getToolCheckCommands(): Record<string, string> {
  return {
    katana: "katana -version 2>&1 | head -1",
    feroxbuster: "feroxbuster --version 2>&1 | head -1",
    ffuf: "ffuf -V 2>&1 | head -1",
    testssl: "testssl.sh --version 2>&1 | head -1",
    arjun: "arjun --help 2>&1 | head -1",
    paramspider: "paramspider --help 2>&1 | head -1",
    wafw00f: "wafw00f --version 2>&1 | head -1",
  };
}

/**
 * Installation commands for each tool on the scan server.
 */
export function getToolInstallCommands(): Record<string, string> {
  return {
    katana: "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    feroxbuster: "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s -- -b /usr/local/bin",
    ffuf: "go install github.com/ffuf/ffuf/v2@latest",
    testssl: "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh",
    arjun: "pip3 install arjun",
    paramspider: "pip3 install paramspider",
    wafw00f: "pip3 install wafw00f",
  };
}
