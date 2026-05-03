/**
 * Vulnerability Class Specialist Module
 *
 * Provides specialized knowledge for each vulnerability class that goes beyond
 * generic scanning. Each specialist understands the specific tools, techniques,
 * detection patterns, and exploitation chains for its vulnerability class.
 *
 * Based on expert bug bounty tooling review and real-world researcher workflows.
 */

export interface VulnClassTool {
  name: string;
  role: "primary" | "secondary" | "verification";
  command: string;
  description: string;
}

export interface DetectionPattern {
  name: string;
  description: string;
  indicators: string[];
  falsePositiveRate: "low" | "medium" | "high";
  verificationSteps: string[];
}

export interface ExploitChain {
  name: string;
  steps: string[];
  impact: string;
  severity: "critical" | "high" | "medium" | "low";
  requiredConditions: string[];
}

export interface VulnClassSpecialist {
  vulnClass: string;
  cweIds: string[];
  description: string;
  tools: VulnClassTool[];
  detectionPatterns: DetectionPattern[];
  exploitChains: ExploitChain[];
  bugBountyTips: string[];
  commonBypasses: string[];
  /** Priority order for testing (lower = test first) */
  testingPriority: number;
}

export const VULN_CLASS_SPECIALISTS: Record<string, VulnClassSpecialist> = {
  xss: {
    vulnClass: "Cross-Site Scripting (XSS)",
    cweIds: ["CWE-79", "CWE-80"],
    description: "Injection of client-side scripts into web pages. Specialized tools (dalfox, kxss) significantly outperform generic scanners because XSS detection requires understanding of context (HTML, JS, attribute, URL) and encoding.",
    tools: [
      {
        name: "dalfox",
        role: "primary",
        command: "dalfox url '{URL}' --silence --format json --delay 100",
        description: "Specialized XSS scanner with WAF bypass, blind XSS, and DOM analysis",
      },
      {
        name: "kxss",
        role: "secondary",
        command: "echo '{URL}' | kxss",
        description: "Finds reflective parameters that may be XSS-vulnerable — pairs with dalfox for confirmation",
      },
      {
        name: "nuclei",
        role: "verification",
        command: "nuclei -u {URL} -tags xss -severity medium,high,critical -jsonl",
        description: "Template-based XSS checks for known patterns",
      },
    ],
    detectionPatterns: [
      {
        name: "Reflected Parameter Echo",
        description: "Input parameter value appears unmodified in response body",
        indicators: ["Parameter value reflected in HTML body", "No encoding on reflected value", "Reflection inside script tags or event handlers"],
        falsePositiveRate: "medium",
        verificationSteps: ["Inject canary string and check reflection", "Test encoding bypass with <script>alert(1)</script>", "Check if CSP blocks execution"],
      },
      {
        name: "DOM-Based Sink",
        description: "JavaScript reads from user-controllable source and writes to dangerous sink",
        indicators: ["document.location used in innerHTML", "URL hash/search params in eval()", "postMessage data in DOM manipulation"],
        falsePositiveRate: "high",
        verificationSteps: ["Trace data flow from source to sink", "Verify no sanitization in path", "Test with actual payload execution"],
      },
      {
        name: "Stored XSS via Input Fields",
        description: "User input stored and rendered to other users without sanitization",
        indicators: ["Form fields that display to other users", "Comment/review systems", "Profile fields rendered in public views"],
        falsePositiveRate: "low",
        verificationSteps: ["Submit payload and check rendering for other users", "Verify payload persists across sessions", "Check if output encoding is applied"],
      },
    ],
    exploitChains: [
      {
        name: "XSS → Session Hijacking",
        steps: ["Find reflected/stored XSS", "Inject cookie-stealing payload", "Exfiltrate session token to attacker server", "Replay session token for account takeover"],
        impact: "Full account takeover",
        severity: "high",
        requiredConditions: ["No HttpOnly flag on session cookie", "No CSP or bypassable CSP"],
      },
      {
        name: "XSS → Admin Panel Access",
        steps: ["Find stored XSS in user-facing input", "Payload executes when admin views content", "Extract admin session or perform admin actions via XSS"],
        impact: "Administrative access, potential full application compromise",
        severity: "critical",
        requiredConditions: ["Admin views user-submitted content", "No strict CSP"],
      },
      {
        name: "Blind XSS → Delayed Exploitation",
        steps: ["Inject blind XSS payload with callback URL", "Payload stored and rendered in admin/internal panel", "Callback fires when internal user views the payload", "Extract internal application data"],
        impact: "Internal system access, data exfiltration",
        severity: "high",
        requiredConditions: ["Input processed by internal/admin systems", "Callback server accessible from target network"],
      },
    ],
    bugBountyTips: [
      "Always test blind XSS — payloads that fire in admin panels are consistently high-severity findings",
      "DOM XSS is underreported because most automated tools miss it — manual JS review pays off",
      "CSP bypass is often possible — check for unsafe-inline, unsafe-eval, or allowlisted CDNs",
      "XSS in password reset flows or OAuth callbacks escalates to account takeover",
      "Test all input contexts: HTML body, attributes, JavaScript strings, URL parameters, CSS",
    ],
    commonBypasses: [
      "HTML entity encoding bypass: &#x3c;script&#x3e;",
      "Event handler bypass: <img src=x onerror=alert(1)>",
      "SVG-based: <svg onload=alert(1)>",
      "Template literal injection: ${alert(1)}",
      "Unicode normalization bypass",
      "Double encoding: %253Cscript%253E",
      "Mutation XSS via DOM clobbering",
    ],
    testingPriority: 2,
  },

  ssrf: {
    vulnClass: "Server-Side Request Forgery (SSRF)",
    cweIds: ["CWE-918"],
    description: "Server makes requests to attacker-controlled destinations or internal resources. Critical in cloud environments where SSRF can access metadata endpoints for credential theft. Requires OOB infrastructure for blind detection.",
    tools: [
      {
        name: "ssrfmap",
        role: "primary",
        command: "python3 ssrfmap.py -r request.txt -p url -m readfiles,portscan,aws,gce,digitalocean",
        description: "Automated SSRF exploitation with cloud metadata, port scanning, and protocol handlers",
      },
      {
        name: "interactsh",
        role: "primary",
        command: "interactsh-client -v",
        description: "OOB callback infrastructure for blind SSRF confirmation",
      },
      {
        name: "nuclei",
        role: "verification",
        command: "nuclei -u {URL} -tags ssrf -jsonl",
        description: "Template-based SSRF pattern detection",
      },
    ],
    detectionPatterns: [
      {
        name: "URL Parameter Fetch",
        description: "Application fetches content from user-supplied URL",
        indicators: ["Parameters named url, uri, path, redirect, callback, webhook", "Image/file URL inputs", "PDF generation from URL", "Import/export functionality with URLs"],
        falsePositiveRate: "low",
        verificationSteps: ["Supply interactsh URL and check for callback", "Test internal IP ranges (127.0.0.1, 10.x, 172.16-31.x, 192.168.x)", "Test cloud metadata endpoints"],
      },
      {
        name: "Blind SSRF via DNS",
        description: "Application resolves attacker-controlled hostname without visible response",
        indicators: ["DNS callback received but no HTTP response data", "Timing differences between internal and external URLs", "Error messages revealing internal resolution"],
        falsePositiveRate: "medium",
        verificationSteps: ["Use interactsh DNS callback", "Compare response times for internal vs external", "Check for partial error disclosure"],
      },
    ],
    exploitChains: [
      {
        name: "SSRF → Cloud Metadata → Credential Theft",
        steps: ["Find SSRF in URL parameter", "Access cloud metadata endpoint (169.254.169.254)", "Extract IAM role credentials", "Use credentials for cloud account access"],
        impact: "Cloud account compromise, data exfiltration, lateral movement",
        severity: "critical",
        requiredConditions: ["Cloud-hosted target", "IMDSv1 or bypassable IMDSv2", "No SSRF URL validation"],
      },
      {
        name: "SSRF → Internal Service Access",
        steps: ["Find SSRF vulnerability", "Scan internal network via SSRF", "Access internal admin panels, databases, or APIs", "Extract sensitive data or escalate privileges"],
        impact: "Internal network access, data breach",
        severity: "critical",
        requiredConditions: ["SSRF allows internal IP access", "Internal services lack authentication"],
      },
      {
        name: "SSRF → File Read via Protocol Handlers",
        steps: ["Find SSRF with protocol handler support", "Use file:// to read local files", "Extract configuration files, source code, or credentials"],
        impact: "Source code disclosure, credential theft",
        severity: "high",
        requiredConditions: ["Application supports file:// protocol", "No protocol restriction"],
      },
    ],
    bugBountyTips: [
      "Cloud metadata SSRF is consistently critical — always test 169.254.169.254 and cloud-specific endpoints",
      "Blind SSRF is common and often missed — always use OOB infrastructure",
      "PDF generators, image processors, and webhook handlers are prime SSRF targets",
      "Test alternative IP representations: decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1)",
      "DNS rebinding can bypass IP allowlists — use tools like rebinder or custom DNS servers",
    ],
    commonBypasses: [
      "IP representation alternatives: decimal, hex, octal, IPv6",
      "URL parser confusion: http://127.0.0.1@evil.com, http://evil.com#@127.0.0.1",
      "Redirect chains: attacker server 302 → internal target",
      "DNS rebinding: domain resolves to internal IP after initial check",
      "URL encoding: %31%32%37%2e%30%2e%30%2e%31",
      "IPv6 representations: ::1, ::ffff:127.0.0.1",
      "CRLF injection in URL to smuggle headers",
    ],
    testingPriority: 1,
  },

  subdomain_takeover: {
    vulnClass: "Subdomain Takeover",
    cweIds: ["CWE-284"],
    description: "Dangling DNS records (usually CNAMEs) pointing to deregistered cloud services that an attacker can claim. Consistently high-severity bug bounty findings because they enable phishing, cookie theft, and CSP bypass from a trusted subdomain.",
    tools: [
      {
        name: "subjack",
        role: "primary",
        command: "subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v",
        description: "CNAME-based takeover detection with 30+ cloud service fingerprints",
      },
      {
        name: "nuclei",
        role: "secondary",
        command: "nuclei -l subdomains.txt -tags takeover -jsonl",
        description: "Template-based takeover detection covering additional services",
      },
      {
        name: "subzy",
        role: "verification",
        command: "subzy run --targets subdomains.txt --concurrency 50 --hide_fails",
        description: "Alternative takeover checker — run multiple tools for coverage",
      },
    ],
    detectionPatterns: [
      {
        name: "Dangling CNAME to Cloud Service",
        description: "CNAME record points to a cloud service that no longer exists",
        indicators: ["NXDOMAIN on CNAME target", "Cloud service error page (GitHub 404, Heroku no-app)", "S3 NoSuchBucket response", "Azure/Cloudfront default error"],
        falsePositiveRate: "medium",
        verificationSteps: ["Resolve CNAME and check if target exists", "Visit subdomain and check for service-specific error", "Attempt to register the dangling resource"],
      },
    ],
    exploitChains: [
      {
        name: "Takeover → Cookie Theft",
        steps: ["Identify dangling CNAME", "Register the cloud resource", "Serve content from the taken-over subdomain", "Steal cookies scoped to parent domain"],
        impact: "Session hijacking for all applications on the parent domain",
        severity: "high",
        requiredConditions: ["Cookies scoped to parent domain (*.target.com)", "Attacker can register the dangling resource"],
      },
      {
        name: "Takeover → Phishing",
        steps: ["Take over subdomain", "Host convincing phishing page", "Leverage trusted subdomain for social engineering"],
        impact: "Credential theft via trusted domain",
        severity: "high",
        requiredConditions: ["Subdomain is recognizable/trustworthy", "No CAA records preventing cert issuance"],
      },
    ],
    bugBountyTips: [
      "Run multiple takeover tools — each has different fingerprint databases",
      "Always verify manually before reporting — false positives are common",
      "Some takeovers require actually registering the resource to prove exploitability",
      "Check for edge cases: NS delegation takeovers, MX record takeovers, A record to deprovisioned IPs",
      "Subdomain takeover + cookie scope = critical finding in most programs",
    ],
    commonBypasses: [],
    testingPriority: 3,
  },

  cors: {
    vulnClass: "Cross-Origin Resource Sharing (CORS) Misconfiguration",
    cweIds: ["CWE-942", "CWE-346"],
    description: "Misconfigured CORS policies that allow unauthorized cross-origin access to sensitive data. Often found when applications reflect the Origin header or use overly permissive wildcard patterns.",
    tools: [
      {
        name: "corsy",
        role: "primary",
        command: "python3 corsy.py -u {URL} -t 20",
        description: "Specialized CORS misconfiguration scanner with multiple bypass techniques",
      },
      {
        name: "nuclei",
        role: "secondary",
        command: "nuclei -u {URL} -tags cors -jsonl",
        description: "Template-based CORS checks",
      },
    ],
    detectionPatterns: [
      {
        name: "Origin Reflection",
        description: "Server reflects the Origin header in Access-Control-Allow-Origin",
        indicators: ["ACAO header matches arbitrary Origin", "ACAO includes attacker-controlled domain", "Access-Control-Allow-Credentials: true with reflected origin"],
        falsePositiveRate: "low",
        verificationSteps: ["Send request with Origin: https://evil.com", "Check if ACAO reflects the evil origin", "Verify ACAC: true is present", "Confirm sensitive data in response"],
      },
      {
        name: "Null Origin Allowed",
        description: "Server allows null origin, exploitable via sandboxed iframes",
        indicators: ["ACAO: null in response", "ACAC: true with null origin"],
        falsePositiveRate: "low",
        verificationSteps: ["Send request with Origin: null", "Verify ACAO: null response", "Create sandboxed iframe PoC"],
      },
      {
        name: "Subdomain Wildcard",
        description: "CORS allows any subdomain, exploitable if any subdomain has XSS",
        indicators: ["ACAO allows *.target.com pattern", "Regex-based origin check with bypass"],
        falsePositiveRate: "medium",
        verificationSteps: ["Test with Origin: https://evil.target.com", "Check if subdomain XSS can chain with CORS", "Verify sensitive data exposure"],
      },
    ],
    exploitChains: [
      {
        name: "CORS + Origin Reflection → Data Theft",
        steps: ["Find CORS misconfiguration with credential support", "Host malicious page that makes cross-origin request", "Victim visits attacker page while authenticated", "Attacker reads sensitive response data"],
        impact: "Sensitive data exfiltration (PII, tokens, account data)",
        severity: "high",
        requiredConditions: ["ACAC: true with reflected/permissive origin", "Sensitive data in API responses", "Victim must visit attacker page"],
      },
    ],
    bugBountyTips: [
      "CORS + ACAC: true is the critical combination — without credentials, impact is usually low",
      "Test prefix/suffix bypasses: evil-target.com, targetevil.com, target.com.evil.com",
      "Null origin bypass via sandboxed iframe is often overlooked",
      "Chain CORS with subdomain XSS for maximum impact",
    ],
    commonBypasses: [
      "Prefix match bypass: evil-target.com",
      "Suffix match bypass: target.com.evil.com",
      "Null origin via sandboxed iframe",
      "Special characters in origin: target.com%60evil.com",
      "Protocol downgrade: http:// when https:// is checked",
    ],
    testingPriority: 4,
  },

  open_redirect: {
    vulnClass: "Open Redirect",
    cweIds: ["CWE-601"],
    description: "Application redirects users to attacker-controlled URLs. Often chained with OAuth flows or SSRF for higher impact. Specialized tools find patterns that generic scanners miss.",
    tools: [
      {
        name: "openredirex",
        role: "primary",
        command: "python3 openredirex.py -l urls.txt -p payloads.txt --keyword FUZZ",
        description: "Specialized open redirect scanner with payload fuzzing",
      },
      {
        name: "nuclei",
        role: "secondary",
        command: "nuclei -u {URL} -tags redirect -jsonl",
        description: "Template-based redirect detection",
      },
    ],
    detectionPatterns: [
      {
        name: "URL Parameter Redirect",
        description: "Redirect destination controlled by URL parameter",
        indicators: ["Parameters named redirect, url, next, return, returnTo, goto, destination", "302/301 response with Location header from parameter", "Meta refresh with user-controlled URL"],
        falsePositiveRate: "low",
        verificationSteps: ["Replace redirect parameter with external URL", "Verify 3xx redirect to attacker domain", "Check for validation bypass opportunities"],
      },
    ],
    exploitChains: [
      {
        name: "Open Redirect → OAuth Token Theft",
        steps: ["Find open redirect in OAuth redirect_uri parameter", "Craft OAuth authorization URL with malicious redirect", "Victim authenticates and token is sent to attacker", "Attacker uses token for account access"],
        impact: "Account takeover via OAuth token theft",
        severity: "critical",
        requiredConditions: ["OAuth flow with redirect_uri parameter", "Insufficient redirect_uri validation"],
      },
      {
        name: "Open Redirect → Phishing",
        steps: ["Find open redirect on trusted domain", "Craft link: trusted.com/redirect?url=evil.com", "Victim trusts the trusted.com domain", "Redirected to phishing page"],
        impact: "Credential theft via trusted domain phishing",
        severity: "medium",
        requiredConditions: ["Open redirect on recognizable domain"],
      },
    ],
    bugBountyTips: [
      "Open redirect alone is often low severity — chain with OAuth or SSRF for higher impact",
      "OAuth redirect_uri open redirects are consistently critical findings",
      "Test login/logout redirect parameters — these are frequently vulnerable",
      "Some programs don't accept open redirect without demonstrated chain — always chain if possible",
    ],
    commonBypasses: [
      "Double URL encoding: %252f%252f",
      "Backslash: \\\\evil.com",
      "Protocol-relative: //evil.com",
      "URL with @ symbol: https://trusted.com@evil.com",
      "Tab/newline injection in URL",
      "Whitelisted domain as subdomain: evil.com/trusted.com",
    ],
    testingPriority: 6,
  },

  race_condition: {
    vulnClass: "Race Condition / TOCTOU",
    cweIds: ["CWE-362", "CWE-367"],
    description: "Time-of-check to time-of-use vulnerabilities where concurrent requests exploit timing windows. Increasingly important in modern web apps with financial transactions, coupon redemption, and vote/like systems.",
    tools: [
      {
        name: "turbo_intruder",
        role: "primary",
        command: "# Burp Suite extension — use race-single-packet-attack.py template",
        description: "High-speed request sending for race condition exploitation via Burp",
      },
      {
        name: "race_the_web",
        role: "secondary",
        command: "race-the-web config.toml",
        description: "Standalone race condition testing tool",
      },
    ],
    detectionPatterns: [
      {
        name: "Financial Transaction Race",
        description: "Concurrent requests to transfer/withdraw/redeem can exceed balance",
        indicators: ["Balance check before deduction", "Non-atomic read-modify-write", "Coupon/voucher redemption endpoints", "Transfer/payment endpoints"],
        falsePositiveRate: "low",
        verificationSteps: ["Send concurrent identical requests", "Check if balance went negative or coupon used multiple times", "Verify with different concurrency levels"],
      },
      {
        name: "Limit Bypass Race",
        description: "Rate limits or usage limits bypassed via concurrent requests",
        indicators: ["Vote/like/follow limits", "API rate limits checked in application layer", "Invitation/referral limits"],
        falsePositiveRate: "medium",
        verificationSteps: ["Send burst of concurrent requests", "Check if limit was exceeded", "Verify the excess actions persisted"],
      },
    ],
    exploitChains: [
      {
        name: "Race → Financial Loss",
        steps: ["Identify non-atomic financial operation", "Send concurrent withdrawal/transfer requests", "Exploit timing window to exceed balance", "Extract excess funds"],
        impact: "Direct financial loss to the application",
        severity: "critical",
        requiredConditions: ["Non-atomic balance check + deduction", "Concurrent request processing"],
      },
    ],
    bugBountyTips: [
      "Single-packet attack technique (Turbo Intruder) is the most reliable method",
      "Test all financial operations: transfers, purchases, coupon redemptions, withdrawals",
      "Vote/like manipulation via race conditions is a valid finding in most programs",
      "Document the exact timing window and success rate in your report",
    ],
    commonBypasses: [],
    testingPriority: 5,
  },

  cache_poisoning: {
    vulnClass: "Web Cache Poisoning",
    cweIds: ["CWE-444"],
    description: "Manipulating cache behavior to serve malicious content to other users. Requires understanding of cache keys, unkeyed inputs, and cache behavior. Specialized tools like param-miner find unkeyed headers/parameters that generic scanners miss.",
    tools: [
      {
        name: "param_miner",
        role: "primary",
        command: "# Burp Suite extension — right-click → Extensions → Param Miner → Guess headers/params",
        description: "Discovers unkeyed parameters and headers that influence cached responses",
      },
      {
        name: "web_cache_vuln_scanner",
        role: "secondary",
        command: "wcvs -u {URL} -hw header-wordlist.txt",
        description: "Standalone web cache vulnerability scanner",
      },
    ],
    detectionPatterns: [
      {
        name: "Unkeyed Header Reflection",
        description: "Header value reflected in cached response but not part of cache key",
        indicators: ["X-Forwarded-Host reflected in response", "X-Original-URL influences routing", "Custom headers reflected in page content", "Cache-Control headers present"],
        falsePositiveRate: "medium",
        verificationSteps: ["Identify cache behavior (Age, X-Cache headers)", "Find unkeyed input that influences response", "Poison cache and verify other users receive poisoned response"],
      },
    ],
    exploitChains: [
      {
        name: "Cache Poisoning → Stored XSS at Scale",
        steps: ["Find unkeyed header that reflects in response", "Inject XSS payload via unkeyed header", "Response cached with XSS payload", "All users requesting the cached URL receive XSS"],
        impact: "Mass XSS affecting all users of the cached page",
        severity: "critical",
        requiredConditions: ["CDN/cache in front of application", "Unkeyed input reflected in response", "Response is cacheable"],
      },
    ],
    bugBountyTips: [
      "Cache poisoning findings are consistently high-severity because they affect all users",
      "param-miner is essential — manual testing for unkeyed inputs is impractical",
      "Always check for CDN-specific behaviors (Cloudflare, Akamai, Fastly have different cache key rules)",
      "Document the cache TTL and blast radius in your report",
    ],
    commonBypasses: [
      "Fat GET requests: GET with body parameters",
      "HTTP method override: X-HTTP-Method-Override",
      "Cache key normalization differences between CDN and origin",
      "Port-based cache poisoning",
    ],
    testingPriority: 7,
  },

  graphql: {
    vulnClass: "GraphQL Vulnerabilities",
    cweIds: ["CWE-200", "CWE-284", "CWE-400"],
    description: "GraphQL-specific vulnerabilities including introspection disclosure, authorization bypass, query complexity attacks, and injection. Modern bug bounty targets increasingly use GraphQL, and specialized tools find issues generic scanners miss.",
    tools: [
      {
        name: "graphw00f",
        role: "primary",
        command: "python3 main.py -t {URL}/graphql",
        description: "Fingerprints GraphQL implementations to identify technology-specific vulnerabilities",
      },
      {
        name: "graphqlmap",
        role: "primary",
        command: "python3 graphqlmap.py -u {URL}/graphql --method POST",
        description: "GraphQL exploitation tool with introspection, injection, and field enumeration",
      },
      {
        name: "graphql_cop",
        role: "secondary",
        command: "python3 graphql-cop.py -t {URL}/graphql",
        description: "GraphQL security audit tool checking for common misconfigurations",
      },
    ],
    detectionPatterns: [
      {
        name: "Introspection Enabled",
        description: "GraphQL introspection query returns full schema",
        indicators: ["__schema query returns types and fields", "Full API schema exposed", "Internal types and mutations visible"],
        falsePositiveRate: "low",
        verificationSteps: ["Send introspection query", "Map all types, queries, and mutations", "Identify sensitive operations"],
      },
      {
        name: "Authorization Bypass via Field Access",
        description: "Accessing fields or mutations without proper authorization",
        indicators: ["User can query admin-only fields", "Mutations accessible without authentication", "Nested object access bypasses field-level auth"],
        falsePositiveRate: "low",
        verificationSteps: ["Enumerate all fields via introspection", "Test each sensitive field/mutation with low-privilege user", "Check nested object authorization"],
      },
      {
        name: "Query Complexity DoS",
        description: "Deeply nested or aliased queries consuming excessive server resources",
        indicators: ["No query depth limit", "No query complexity limit", "Alias-based multiplication possible"],
        falsePositiveRate: "medium",
        verificationSteps: ["Send deeply nested query", "Send query with many aliases", "Monitor response time and server behavior"],
      },
    ],
    exploitChains: [
      {
        name: "Introspection → Auth Bypass → Data Exfiltration",
        steps: ["Discover GraphQL endpoint", "Run introspection to map schema", "Identify admin mutations/queries", "Access sensitive data without proper authorization"],
        impact: "Unauthorized data access, privilege escalation",
        severity: "high",
        requiredConditions: ["Introspection enabled", "Missing field-level authorization"],
      },
    ],
    bugBountyTips: [
      "Always check for introspection first — it's the roadmap to everything else",
      "If introspection is disabled, try field suggestion/autocomplete brute forcing",
      "Batch queries can bypass rate limits — test for batch query support",
      "GraphQL injection in string arguments is often overlooked",
      "Check for IDOR via GraphQL node IDs — sequential or predictable IDs are common",
    ],
    commonBypasses: [
      "Introspection bypass: __schema via GET, different content types, aliased query names",
      "Authorization bypass via nested queries: query { user { adminField { secret } } }",
      "Batch query rate limit bypass",
      "Field suggestion brute forcing when introspection is disabled",
    ],
    testingPriority: 4,
  },
};

/**
 * Get the specialist for a specific vulnerability class
 */
export function getVulnSpecialist(vulnClass: string): VulnClassSpecialist | undefined {
  return VULN_CLASS_SPECIALISTS[vulnClass.toLowerCase().replace(/[^a-z_]/g, "_")];
}

/**
 * Get all specialists sorted by testing priority
 */
export function getSpecialistsByPriority(): VulnClassSpecialist[] {
  return Object.values(VULN_CLASS_SPECIALISTS).sort((a, b) => a.testingPriority - b.testingPriority);
}

/**
 * Get recommended tools for a vulnerability class
 */
export function getToolsForVulnClass(vulnClass: string): VulnClassTool[] {
  const specialist = getVulnSpecialist(vulnClass);
  return specialist?.tools ?? [];
}

/**
 * Get exploit chains for a vulnerability class filtered by severity
 */
export function getExploitChains(vulnClass: string, minSeverity?: "critical" | "high" | "medium" | "low"): ExploitChain[] {
  const specialist = getVulnSpecialist(vulnClass);
  if (!specialist) return [];

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const minLevel = minSeverity ? severityOrder[minSeverity] : 3;

  return specialist.exploitChains.filter(
    (chain) => severityOrder[chain.severity] <= minLevel
  );
}

/**
 * Build LLM context for vulnerability class testing
 */
export function buildVulnClassContext(vulnClasses: string[]): string {
  const sections: string[] = [];

  for (const vc of vulnClasses) {
    const specialist = getVulnSpecialist(vc);
    if (!specialist) continue;

    const toolList = specialist.tools
      .map((t) => `  - ${t.name} (${t.role}): ${t.description}`)
      .join("\n");

    const tips = specialist.bugBountyTips.map((t) => `  - ${t}`).join("\n");

    const bypasses = specialist.commonBypasses.length > 0
      ? specialist.commonBypasses.map((b) => `  - ${b}`).join("\n")
      : "  (none documented)";

    sections.push(
      `### ${specialist.vulnClass}\n` +
      `${specialist.description}\n\n` +
      `**Tools:**\n${toolList}\n\n` +
      `**Bug Bounty Tips:**\n${tips}\n\n` +
      `**Common Bypasses:**\n${bypasses}`
    );
  }

  return sections.join("\n\n---\n\n");
}

/**
 * Match detected technologies/findings to relevant vulnerability classes
 */
export function matchTechToVulnClasses(context: {
  technologies?: string[];
  hasGraphQL?: boolean;
  hasCloudHosting?: boolean;
  hasOAuthFlow?: boolean;
  hasCDN?: boolean;
  hasFileUpload?: boolean;
  hasUserInput?: boolean;
}): string[] {
  const classes: string[] = [];

  // Always test XSS if there's user input
  if (context.hasUserInput !== false) classes.push("xss");

  // SSRF is critical for cloud-hosted targets
  if (context.hasCloudHosting || context.hasFileUpload) classes.push("ssrf");

  // GraphQL-specific testing
  if (context.hasGraphQL) classes.push("graphql");

  // Cache poisoning if CDN detected
  if (context.hasCDN) classes.push("cache_poisoning");

  // Open redirect especially important with OAuth
  if (context.hasOAuthFlow) classes.push("open_redirect");

  // CORS is always worth checking
  classes.push("cors");

  // Subdomain takeover if we have subdomain data
  classes.push("subdomain_takeover");

  // Race conditions for financial/transactional apps
  classes.push("race_condition");

  return [...new Set(classes)];
}
