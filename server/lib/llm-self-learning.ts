/**
 * LLM Self-Learning Engine
 *
 * Enables the platform's LLM to improve its vulnerability analysis accuracy
 * over time through four mechanisms:
 *
 * 1. **Feedback Knowledge Base** — Aggregates operator corrections into a
 *    persistent "lessons learned" store. When an operator marks a finding as
 *    incorrect or adds a missed finding, the correction is stored and injected
 *    into all future LLM prompts for that target type.
 *
 * 2. **Ground Truth Library** — Maps each training target to its known
 *    vulnerabilities. After every scan, the LLM's findings are automatically
 *    scored against ground truth, producing precision/recall/F1 metrics.
 *
 * 3. **Progressive Prompt Refinement** — Builds a "correction history" that
 *    gets prepended to every LLM analysis call, teaching the model what it
 *    previously missed, over-rated, or misclassified.
 *
 * 4. **Accuracy Trending** — Tracks the LLM's accuracy score over time per
 *    target type, enabling operators to see whether the system is improving.
 */

// ─── Ground Truth Library ──────────────────────────────────────────────────

export interface GroundTruthVuln {
  title: string;
  category: string;
  owaspCategory?: string;
  severity: string;
  cve?: string;
  description: string;
  detectionHint?: string;
}

/**
 * Built-in ground truth for known vulnerable training targets.
 * These are the vulnerabilities that the LLM *should* find.
 */
export const GROUND_TRUTH_LIBRARY: Record<string, GroundTruthVuln[]> = {
  "juice-shop": [
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Login form is vulnerable to SQL injection via the email field. Payload: ' OR 1=1-- allows admin bypass.", detectionHint: "Test login form with SQLi payloads" },
    { title: "Reflected XSS in Search", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Search functionality reflects user input without sanitization, allowing script injection.", detectionHint: "Test search with <script>alert(1)</script>" },
    { title: "Broken Authentication - Admin Account", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Admin account (admin@juice-sh.op) accessible via SQL injection or weak password.", detectionHint: "Attempt admin login with common credentials" },
    { title: "Sensitive Data Exposure - FTP Directory", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "FTP directory (/ftp) is publicly accessible and contains sensitive files including backups.", detectionHint: "Directory enumeration reveals /ftp" },
    { title: "Broken Access Control - Admin Panel", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "critical", description: "Admin panel at /#/administration accessible by manipulating JWT token or direct URL access.", detectionHint: "Check for admin routes in client-side JavaScript" },
    { title: "JWT Vulnerability - None Algorithm", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "critical", description: "JWT tokens can be forged using the 'none' algorithm to bypass authentication.", detectionHint: "Decode JWT and test with alg:none" },
    { title: "SSRF via Profile Image URL", category: "Server-Side Request Forgery", owaspCategory: "A10:2025", severity: "high", description: "Profile image upload accepts URLs, allowing SSRF to internal services.", detectionHint: "Test profile image with internal URLs" },
    { title: "NoSQL Injection in Product Reviews", category: "Injection", owaspCategory: "A03:2025", severity: "medium", description: "Product review endpoint vulnerable to NoSQL injection via MongoDB query operators.", detectionHint: "Test review API with $gt/$ne operators" },
    { title: "Insecure Deserialization", category: "Insecure Deserialization", owaspCategory: "A08:2025", severity: "high", description: "Application deserializes user-controlled data without validation.", detectionHint: "Check for serialized objects in cookies/requests" },
    { title: "Directory Traversal - File Access", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File serving endpoint allows directory traversal to access arbitrary files.", detectionHint: "Test file endpoints with ../../../etc/passwd" },
    { title: "Information Disclosure - Error Messages", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Verbose error messages expose stack traces and internal paths.", detectionHint: "Trigger errors and check response bodies" },
    { title: "CSRF - No Token Validation", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "medium", description: "State-changing operations lack CSRF token validation.", detectionHint: "Check forms for CSRF tokens" },
    { title: "Outdated Dependencies", category: "Vulnerable Components", owaspCategory: "A06:2025", severity: "medium", description: "Application uses outdated npm packages with known CVEs.", detectionHint: "Check package.json and npm audit" },
    { title: "Missing Security Headers", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "Missing Content-Security-Policy, X-Frame-Options, and other security headers.", detectionHint: "Check HTTP response headers" },
    { title: "Weak Password Policy", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "medium", description: "No password complexity requirements, allows single-character passwords.", detectionHint: "Test registration with weak passwords" },
  ],

  "vulnweb-php": [
    { title: "SQL Injection in Artist Search", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Search functionality vulnerable to SQL injection via the searchFor parameter.", detectionHint: "Test search with ' UNION SELECT" },
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Login form vulnerable to authentication bypass via SQL injection.", detectionHint: "Test with admin'--" },
    { title: "Reflected XSS in Search", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Search results page reflects input without encoding.", detectionHint: "Test with <script> tags in search" },
    { title: "File Inclusion Vulnerability", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "PHP file inclusion via URL parameters allows reading arbitrary files.", detectionHint: "Test with ?page=../../../../etc/passwd" },
    { title: "Directory Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "Path traversal in file download functionality.", detectionHint: "Test file parameters with ../" },
    { title: "CSRF on Profile Update", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "medium", description: "Profile update form lacks CSRF protection.", detectionHint: "Check for CSRF tokens in forms" },
    { title: "Information Disclosure - phpinfo", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "phpinfo() page accessible revealing server configuration.", detectionHint: "Check for /phpinfo.php" },
    { title: "Weak Session Management", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "medium", description: "Session IDs are predictable and not regenerated after login.", detectionHint: "Analyze session cookie patterns" },
    { title: "Missing Security Headers", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "Missing CSP, X-Frame-Options, and HSTS headers.", detectionHint: "Check HTTP response headers" },
  ],

  "vulnweb-asp": [
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "ASP.NET login form vulnerable to SQL injection.", detectionHint: "Test with ' OR 1=1--" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Multiple pages reflect user input without encoding.", detectionHint: "Test input fields with XSS payloads" },
    { title: "Path Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File serving allows path traversal on IIS.", detectionHint: "Test with ..\\..\\web.config" },
    { title: "Information Disclosure - IIS", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "IIS default error pages expose server version and paths.", detectionHint: "Trigger 404/500 errors" },
    { title: "Viewstate Tampering", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "medium", description: "ASP.NET ViewState not encrypted or MAC-protected.", detectionHint: "Decode ViewState from forms" },
  ],

  "vulnweb-rest": [
    { title: "Broken Object Level Authorization", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "critical", description: "API endpoints allow accessing other users' data by changing IDs.", detectionHint: "Test API with different user IDs" },
    { title: "Broken Authentication", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "API authentication can be bypassed or tokens are weak.", detectionHint: "Test token validation and expiry" },
    { title: "Excessive Data Exposure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "API returns more data than the client needs, including sensitive fields.", detectionHint: "Check API responses for extra fields" },
    { title: "Injection via API Parameters", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "API parameters vulnerable to injection attacks.", detectionHint: "Test API params with injection payloads" },
    { title: "Missing Rate Limiting", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "No rate limiting on authentication or data endpoints.", detectionHint: "Send rapid requests to check rate limits" },
  ],

  "hackazon": [
    { title: "SQL Injection in Product Search", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "E-commerce search vulnerable to SQL injection.", detectionHint: "Test search with SQL payloads" },
    { title: "XSS in Product Reviews", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Product review submission allows stored XSS.", detectionHint: "Submit review with script tags" },
    { title: "CSRF on Checkout", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "high", description: "Checkout process lacks CSRF protection.", detectionHint: "Check checkout forms for tokens" },
    { title: "Business Logic - Price Manipulation", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "critical", description: "Cart prices can be manipulated via client-side parameters.", detectionHint: "Intercept and modify price in requests" },
    { title: "Authentication Bypass", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Authentication can be bypassed via REST API.", detectionHint: "Test API auth endpoints" },
    { title: "Information Disclosure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Debug information and stack traces exposed.", detectionHint: "Trigger errors and check responses" },
  ],

  "altoro-mutual": [
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Banking login vulnerable to SQL injection authentication bypass.", detectionHint: "Test with ' OR 1=1--" },
    { title: "XSS in Search", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Search functionality reflects input without sanitization.", detectionHint: "Test search with XSS payloads" },
    { title: "IDOR - Account Access", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "critical", description: "Account numbers in URLs allow accessing other users' accounts.", detectionHint: "Change account ID in URL" },
    { title: "Session Fixation", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "high", description: "Session ID not regenerated after login.", detectionHint: "Check session cookie before/after login" },
    { title: "Path Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File serving allows path traversal.", detectionHint: "Test with ../ in file parameters" },
    { title: "Missing HTTPS Enforcement", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "medium", description: "Application accessible over HTTP without redirect.", detectionHint: "Check for HSTS header" },
  ],

  "zero-bank": [
    { title: "Broken Authentication", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Weak authentication mechanism allows bypass.", detectionHint: "Test login with common credentials" },
    { title: "IDOR in Account Operations", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "critical", description: "Account operations accessible by changing account IDs.", detectionHint: "Modify account ID in requests" },
    { title: "XSS in Feedback Form", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Feedback form stores and reflects XSS payloads.", detectionHint: "Submit feedback with script tags" },
    { title: "CSRF on Fund Transfer", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "high", description: "Fund transfer lacks CSRF protection.", detectionHint: "Check transfer form for tokens" },
  ],

  "webscantest": [
    { title: "XSS - Multiple Vectors", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Multiple XSS vectors across the application.", detectionHint: "Test all input fields" },
    { title: "SQL Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "SQL injection in search and login forms.", detectionHint: "Test with SQL payloads" },
    { title: "Open Redirect", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "URL redirect parameter can be manipulated.", detectionHint: "Test redirect parameters" },
    { title: "Information Disclosure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "Server version and configuration exposed.", detectionHint: "Check response headers and error pages" },
  ],

  // ─── New Training Targets (March 2026) ─────────────────────────────────────

  "broken-crystals": [
    { title: "JWT None Algorithm Bypass", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "critical", description: "JWT tokens accept 'none' algorithm, allowing forged tokens to bypass authentication entirely.", detectionHint: "Decode JWT, change alg to none, remove signature" },
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Login endpoint vulnerable to SQL injection via username/password fields.", detectionHint: "Test login with ' OR 1=1--" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Multiple endpoints reflect user input without sanitization.", detectionHint: "Test input fields with <script>alert(1)</script>" },
    { title: "Server-Side Request Forgery (SSRF)", category: "Server-Side Request Forgery", owaspCategory: "A10:2025", severity: "high", description: "URL fetch functionality allows SSRF to internal services.", detectionHint: "Test URL parameters with http://localhost or internal IPs" },
    { title: "Server-Side Template Injection (SSTI)", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Template engine processes user input, allowing code execution via template syntax.", detectionHint: "Test with {{7*7}} or ${7*7} in input fields" },
    { title: "XML External Entity (XXE)", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "XML parser processes external entities, allowing file read and SSRF.", detectionHint: "Submit XML with <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" },
    { title: "LDAP Injection", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "LDAP query constructed from user input without sanitization.", detectionHint: "Test with *)(&) in LDAP-related fields" },
    { title: "OS Command Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "System command execution via user-controlled input.", detectionHint: "Test with ; id or | whoami in input fields" },
    { title: "Prototype Pollution", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "JavaScript prototype chain can be polluted via __proto__ or constructor.prototype.", detectionHint: "Send JSON with __proto__ key" },
    { title: "IDOR - Insecure Direct Object Reference", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "API endpoints allow accessing other users' data by changing IDs.", detectionHint: "Modify user/object IDs in API requests" },
    { title: "CSRF - Missing Token Validation", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "medium", description: "State-changing operations lack CSRF token validation.", detectionHint: "Check forms for CSRF tokens" },
    { title: "Default Login Credentials", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "Application ships with default admin:admin credentials.", detectionHint: "Try admin:admin at login" },
    { title: "GraphQL Introspection Enabled", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "GraphQL introspection query exposes entire API schema.", detectionHint: "Send __schema introspection query to /graphql" },
    { title: "Mass Assignment", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "API accepts and processes extra fields allowing privilege escalation.", detectionHint: "Add role:admin to registration/update requests" },
    { title: "Unvalidated Redirect", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Redirect parameter accepts arbitrary URLs for phishing.", detectionHint: "Test redirect params with external URLs" },
    { title: "File Upload Vulnerability", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "File upload allows malicious file types without validation.", detectionHint: "Upload .php/.jsp files with modified content-type" },
    { title: "Version Control Exposure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: ".git directory accessible, exposing source code.", detectionHint: "Check for /.git/HEAD" },
    { title: "Missing Security Headers", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "Missing CSP, X-Frame-Options, HSTS headers.", detectionHint: "Check HTTP response headers" },
  ],

  "gin-juice-shop": [
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Multiple reflected XSS vectors across the application.", detectionHint: "Test search and input fields with XSS payloads" },
    { title: "DOM-based XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Client-side JavaScript processes URL fragments unsafely.", detectionHint: "Test URL hash/fragment with XSS payloads" },
    { title: "SQL Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Database queries constructed from user input without parameterization.", detectionHint: "Test with ' UNION SELECT in input fields" },
    { title: "Server-Side Request Forgery (SSRF)", category: "Server-Side Request Forgery", owaspCategory: "A10:2025", severity: "high", description: "URL fetch functionality allows SSRF to internal AWS metadata.", detectionHint: "Test with http://169.254.169.254/" },
    { title: "Server-Side Template Injection (SSTI)", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Template engine processes user input allowing code execution.", detectionHint: "Test with {{7*7}} in input fields" },
    { title: "XML External Entity (XXE)", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "XML parser processes external entities.", detectionHint: "Submit crafted XML with external entity declarations" },
    { title: "CORS Misconfiguration", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "Overly permissive CORS policy reflects arbitrary origins.", detectionHint: "Send request with Origin: evil.com header" },
    { title: "Clickjacking", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Missing X-Frame-Options allows framing for clickjacking.", detectionHint: "Check for X-Frame-Options header" },
    { title: "HTTP Request Smuggling", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Discrepancies in Content-Length/Transfer-Encoding handling allow request smuggling.", detectionHint: "Send ambiguous CL/TE headers" },
    { title: "Insecure Deserialization", category: "Insecure Deserialization", owaspCategory: "A08:2025", severity: "critical", description: "Application deserializes untrusted data allowing RCE.", detectionHint: "Check for serialized objects in cookies/requests" },
    { title: "Path Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File serving allows path traversal to read arbitrary files.", detectionHint: "Test with ../../etc/passwd in file parameters" },
    { title: "Authentication Bypass", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Authentication mechanism can be bypassed.", detectionHint: "Test token manipulation and auth header bypass" },
    { title: "Broken Access Control", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "Horizontal and vertical privilege escalation possible.", detectionHint: "Access admin endpoints with regular user tokens" },
    { title: "Information Disclosure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Verbose error messages and debug information exposed.", detectionHint: "Trigger errors and check responses" },
  ],

  "google-gruyere": [
    { title: "Stored XSS in Snippets", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "User-created snippets allow stored XSS that executes for all visitors.", detectionHint: "Create snippet with <script> tags" },
    { title: "Reflected XSS in Error Pages", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Error pages reflect user input without encoding.", detectionHint: "Trigger errors with XSS payloads in URL" },
    { title: "CSRF on State-Changing Operations", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "high", description: "No CSRF protection on snippet creation and account operations.", detectionHint: "Check for CSRF tokens in forms" },
    { title: "Remote Code Execution via Template", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Template system allows code execution through crafted input.", detectionHint: "Test template syntax in user-controlled fields" },
    { title: "Information Disclosure - Source Code", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Application source code accessible through specific URLs.", detectionHint: "Check for source code disclosure paths" },
    { title: "Path Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File serving allows reading files outside intended directory.", detectionHint: "Test with ../ in file paths" },
    { title: "Denial of Service", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Resource exhaustion possible through crafted requests.", detectionHint: "Test with large payloads or recursive structures" },
  ],

  "firing-range": [
    { title: "DOM XSS - Multiple Vectors", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "50+ DOM-based XSS variants through various sinks (innerHTML, document.write, eval, etc.).", detectionHint: "Test each DOM sink with appropriate XSS payloads" },
    { title: "Reflected XSS - Multiple Vectors", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Multiple reflected XSS through URL parameters, headers, and POST data.", detectionHint: "Test URL parameters with XSS payloads" },
    { title: "CORS Misconfiguration", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "Overly permissive CORS policy allows cross-origin data theft.", detectionHint: "Test with arbitrary Origin headers" },
    { title: "Reverse Clickjacking", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Application can be tricked into framing attacker-controlled content.", detectionHint: "Check for frame-busting bypass" },
    { title: "Mixed Content", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "medium", description: "HTTPS pages load resources over HTTP, allowing MitM.", detectionHint: "Check for HTTP resources on HTTPS pages" },
    { title: "Remote Inclusion", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "Application includes remote resources based on user input.", detectionHint: "Test include parameters with external URLs" },
  ],

  "vulnweb-aspnet": [
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "ASP.NET login form vulnerable to SQL injection via username field.", detectionHint: "Test with ' OR 1=1--" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Blog post and comment fields reflect input without encoding.", detectionHint: "Test input fields with XSS payloads" },
    { title: "ASP.NET Misconfiguration - Trace Enabled", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "ASP.NET trace.axd accessible, exposing request details and session data.", detectionHint: "Check for /trace.axd" },
    { title: "Information Disclosure - IIS Version", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "IIS server version exposed in HTTP headers.", detectionHint: "Check Server header in responses" },
    { title: "ViewState Tampering", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "medium", description: "ASP.NET ViewState not MAC-protected, allowing tampering.", detectionHint: "Decode and modify ViewState" },
  ],

  "vulnweb-html5": [
    { title: "NoSQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "CouchDB login vulnerable to NoSQL injection via JSON operators.", detectionHint: "Test with {\"$gt\": \"\"} in password field" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Tweet and search fields reflect input without sanitization.", detectionHint: "Test with <script> in tweet/search" },
    { title: "HTML5 Web Storage Exposure", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Sensitive data stored in HTML5 localStorage accessible via XSS.", detectionHint: "Check localStorage via browser console" },
    { title: "CORS Misconfiguration", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "Overly permissive CORS allows cross-origin data access.", detectionHint: "Test with arbitrary Origin header" },
    { title: "Missing Security Headers", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "Missing CSP, X-Frame-Options, and HSTS headers.", detectionHint: "Check HTTP response headers" },
  ],

  "hack-yourself-first": [
    { title: "SQL Injection in Search", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Vehicle search vulnerable to SQL injection via make/model parameters.", detectionHint: "Test search with ' UNION SELECT" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Search results reflect input without encoding.", detectionHint: "Test search with XSS payloads" },
    { title: "CSRF on Account Operations", category: "Cross-Site Request Forgery", owaspCategory: "A01:2025", severity: "high", description: "Account update operations lack CSRF protection.", detectionHint: "Check forms for anti-CSRF tokens" },
    { title: "IDOR - User Data Access", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "User profile data accessible by changing user IDs.", detectionHint: "Modify user ID in API requests" },
    { title: "Information Disclosure - Stack Traces", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Verbose ASP.NET error pages expose stack traces and paths.", detectionHint: "Trigger errors and check response" },
    { title: "Insecure Transport - Mixed Content", category: "Cryptographic Failures", owaspCategory: "A02:2025", severity: "medium", description: "Application serves content over HTTP without HSTS.", detectionHint: "Check for HSTS header and HTTP access" },
  ],

  "testsparker-aspnet": [
    { title: "SQL Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Multiple SQL injection points in login and search forms.", detectionHint: "Test with ' OR 1=1-- in login fields" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Input reflected without encoding across multiple pages.", detectionHint: "Test with <script>alert(1)</script>" },
    { title: "Path Traversal", category: "Broken Access Control", owaspCategory: "A01:2025", severity: "high", description: "File download allows path traversal on IIS.", detectionHint: "Test with ..\\..\\web.config" },
    { title: "Authentication Bypass", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Authentication mechanism can be bypassed via SQL injection.", detectionHint: "Use SQLi in login to bypass auth" },
    { title: "Information Disclosure - Server Version", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "low", description: "IIS and ASP.NET version exposed in headers.", detectionHint: "Check Server and X-Powered-By headers" },
  ],

  "testsparker-php": [
    { title: "SQL Injection in Login", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Login form vulnerable to SQL injection authentication bypass.", detectionHint: "Test with admin'-- in username" },
    { title: "Reflected XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Search and input fields reflect user input without sanitization.", detectionHint: "Test with XSS payloads in search" },
    { title: "Local File Inclusion (LFI)", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "PHP include via URL parameter allows reading arbitrary files.", detectionHint: "Test with ?page=../../../../etc/passwd" },
    { title: "Command Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "System command execution via user-controlled input.", detectionHint: "Test with ; id or | whoami" },
    { title: "Information Disclosure - PHP Info", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "phpinfo() page accessible revealing server configuration.", detectionHint: "Check for /phpinfo.php" },
  ],

  "testsparker-angular": [
    { title: "DOM-based XSS", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Angular template injection and DOM manipulation vulnerabilities.", detectionHint: "Test with {{constructor.constructor('alert(1)')()}}" },
    { title: "Angular Template Injection", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "User input processed as Angular template expressions.", detectionHint: "Test with {{7*7}} in input fields" },
    { title: "CORS Misconfiguration", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "high", description: "API CORS policy overly permissive for SPA.", detectionHint: "Test with arbitrary Origin header" },
    { title: "API Security - Broken Auth", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "high", description: "SPA API endpoints have weak authentication.", detectionHint: "Test API calls without/with modified tokens" },
    { title: "Information Disclosure - Source Maps", category: "Security Misconfiguration", owaspCategory: "A05:2025", severity: "medium", description: "Angular source maps accessible, exposing application logic.", detectionHint: "Check for .js.map files" },
  ],

  "pentest-ground": [
    { title: "SQL Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "Multiple SQL injection points across vulnerable applications.", detectionHint: "Test login and search forms with SQL payloads" },
    { title: "XSS - Multiple Types", category: "Cross-Site Scripting", owaspCategory: "A03:2025", severity: "high", description: "Reflected and stored XSS across multiple apps.", detectionHint: "Test input fields with XSS payloads" },
    { title: "Command Injection", category: "Injection", owaspCategory: "A03:2025", severity: "critical", description: "OS command injection via user input fields.", detectionHint: "Test with ; id or | whoami" },
    { title: "File Upload Vulnerability", category: "Injection", owaspCategory: "A03:2025", severity: "high", description: "Unrestricted file upload allows malicious file execution.", detectionHint: "Upload PHP/JSP webshell" },
    { title: "Authentication Bypass", category: "Broken Authentication", owaspCategory: "A02:2025", severity: "critical", description: "Authentication mechanisms can be bypassed.", detectionHint: "Test with SQLi and default credentials" },
  ],
};

// ─── Feedback Knowledge Base ───────────────────────────────────────────────

export interface LearningEntry {
  targetPreset: string;
  findingTitle: string;
  llmSeverity?: string;
  correctSeverity?: string;
  llmCategory?: string;
  correctCategory?: string;
  feedbackType: string;
  operatorNotes?: string;
  correctionContext?: string;
}

/**
 * Store a learning entry from operator feedback.
 * This creates a persistent correction that will be injected into future LLM prompts.
 */
export async function storeLearningEntry(entry: LearningEntry & { sessionId: string; targetUrl: string; operatorId?: number }): Promise<void> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    await conn.execute(
      `INSERT INTO llm_learning_entries (target_preset, target_url, session_id, finding_title, llm_severity, correct_severity, llm_category, correct_category, feedback_type, operator_notes, correction_context, operator_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [entry.targetPreset, entry.targetUrl, entry.sessionId, entry.findingTitle, entry.llmSeverity || null, entry.correctSeverity || null, entry.llmCategory || null, entry.correctCategory || null, entry.feedbackType, entry.operatorNotes || null, entry.correctionContext || null, entry.operatorId || null]
    );
  } finally {
    await conn.end();
  }
}

/**
 * Retrieve all learning entries for a target preset.
 * Used to build the correction history for progressive prompt refinement.
 */
export async function getLearningEntries(targetPreset: string): Promise<LearningEntry[]> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const [rows] = await conn.execute(
      `SELECT * FROM llm_learning_entries WHERE target_preset = ? ORDER BY created_at DESC LIMIT 100`,
      [targetPreset]
    );
    return (rows as any[]).map(r => ({
      targetPreset: r.target_preset,
      findingTitle: r.finding_title,
      llmSeverity: r.llm_severity,
      correctSeverity: r.correct_severity,
      llmCategory: r.llm_category,
      correctCategory: r.correct_category,
      feedbackType: r.feedback_type,
      operatorNotes: r.operator_notes,
      correctionContext: r.correction_context,
    }));
  } finally {
    await conn.end();
  }
}

/**
 * Get all learning entries across all targets for global pattern learning.
 */
export async function getAllLearningEntries(limit = 200): Promise<LearningEntry[]> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const [rows] = await conn.execute(
      `SELECT * FROM llm_learning_entries ORDER BY created_at DESC LIMIT ?`,
      [String(limit)]
    );
    return (rows as any[]).map(r => ({
      targetPreset: r.target_preset,
      findingTitle: r.finding_title,
      llmSeverity: r.llm_severity,
      correctSeverity: r.correct_severity,
      llmCategory: r.llm_category,
      correctCategory: r.correct_category,
      feedbackType: r.feedback_type,
      operatorNotes: r.operator_notes,
      correctionContext: r.correction_context,
    }));
  } finally {
    await conn.end();
  }
}

// ─── Progressive Prompt Refinement ─────────────────────────────────────────

/**
 * Build the correction history prompt section.
 * This is injected into every LLM analysis call to teach the model
 * from previous mistakes.
 */
export function buildCorrectionHistoryPrompt(
  targetPreset: string,
  targetLearnings: LearningEntry[],
  globalLearnings: LearningEntry[]
): string {
  if (targetLearnings.length === 0 && globalLearnings.length === 0) return "";

  const sections: string[] = [];

  // Target-specific corrections (highest priority)
  if (targetLearnings.length > 0) {
    const incorrectFindings = targetLearnings.filter(l => l.feedbackType === "incorrect" || l.feedbackType === "false_positive");
    const missedFindings = targetLearnings.filter(l => l.feedbackType === "missed_finding");
    const severityCorrections = targetLearnings.filter(l => l.feedbackType === "partial" && l.correctSeverity);
    const correctFindings = targetLearnings.filter(l => l.feedbackType === "correct");

    sections.push(`\n═══ LEARNING FROM PREVIOUS SCANS OF THIS TARGET ═══`);

    if (incorrectFindings.length > 0) {
      sections.push(`\nFALSE POSITIVES TO AVOID (you previously reported these incorrectly):`);
      for (const f of incorrectFindings.slice(0, 15)) {
        sections.push(`  ✗ "${f.findingTitle}" was ${f.feedbackType}${f.operatorNotes ? ` — Operator note: ${f.operatorNotes}` : ""}`);
      }
    }

    if (missedFindings.length > 0) {
      sections.push(`\nMISSED VULNERABILITIES (you failed to detect these — look harder):`);
      for (const f of missedFindings.slice(0, 15)) {
        sections.push(`  ⚠ "${f.findingTitle}" [${f.correctSeverity || "unknown"}] ${f.correctCategory ? `(${f.correctCategory})` : ""}${f.operatorNotes ? ` — Hint: ${f.operatorNotes}` : ""}`);
      }
    }

    if (severityCorrections.length > 0) {
      sections.push(`\nSEVERITY CORRECTIONS (you mis-rated these):`);
      for (const f of severityCorrections.slice(0, 10)) {
        sections.push(`  ↕ "${f.findingTitle}": you said ${f.llmSeverity} → correct is ${f.correctSeverity}`);
      }
    }

    if (correctFindings.length > 0) {
      sections.push(`\nCONFIRMED CORRECT (keep reporting these):`);
      sections.push(`  ✓ ${correctFindings.length} findings were confirmed correct by operators`);
    }
  }

  // Global pattern corrections (lower priority, cross-target learning)
  const globalIncorrect = globalLearnings.filter(l =>
    l.feedbackType === "incorrect" || l.feedbackType === "false_positive"
  ).filter(l => l.targetPreset !== targetPreset); // Exclude already-shown target-specific ones

  const globalMissed = globalLearnings.filter(l =>
    l.feedbackType === "missed_finding"
  ).filter(l => l.targetPreset !== targetPreset);

  if (globalIncorrect.length > 0 || globalMissed.length > 0) {
    sections.push(`\n═══ CROSS-TARGET LEARNING PATTERNS ═══`);

    if (globalIncorrect.length > 0) {
      // Group by finding title to find recurring false positives
      const fpCounts = new Map<string, number>();
      for (const f of globalIncorrect) {
        const key = f.findingTitle.toLowerCase();
        fpCounts.set(key, (fpCounts.get(key) || 0) + 1);
      }
      const recurring = [...fpCounts.entries()].filter(([, c]) => c >= 2).sort((a, b) => b[1] - a[1]);
      if (recurring.length > 0) {
        sections.push(`\nRECURRING FALSE POSITIVE PATTERNS:`);
        for (const [title, count] of recurring.slice(0, 5)) {
          sections.push(`  ✗ "${title}" — marked incorrect ${count} times across different targets`);
        }
      }
    }

    if (globalMissed.length > 0) {
      const missedCounts = new Map<string, number>();
      for (const f of globalMissed) {
        const cat = f.correctCategory || f.llmCategory || "Unknown";
        missedCounts.set(cat, (missedCounts.get(cat) || 0) + 1);
      }
      const weakAreas = [...missedCounts.entries()].sort((a, b) => b[1] - a[1]);
      if (weakAreas.length > 0) {
        sections.push(`\nWEAK DETECTION AREAS (categories you frequently miss):`);
        for (const [cat, count] of weakAreas.slice(0, 5)) {
          sections.push(`  ⚠ ${cat} — missed ${count} times. Pay extra attention to this category.`);
        }
      }
    }
  }

  if (sections.length === 0) return "";

  return sections.join("\n") + "\n\nUse this feedback to improve your analysis accuracy. Avoid repeating previous mistakes.\n";
}

// ─── Ground Truth Comparison & Scoring ─────────────────────────────────────

export interface AccuracyScore {
  totalGroundTruth: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  severityAccuracy: number;
  overallScore: number;
  matchDetails: Array<{
    groundTruth: GroundTruthVuln;
    matched: boolean;
    llmFinding?: any;
    severityMatch: boolean;
  }>;
  unmatchedLlmFindings: any[];
}

/**
 * Compare LLM findings against ground truth for a target.
 * Returns precision, recall, F1, and detailed match information.
 */
export function scoreAgainstGroundTruth(
  targetPreset: string,
  llmFindings: Array<{ title: string; severity: string; category?: string; cve?: string }>
): AccuracyScore | null {
  const groundTruth = GROUND_TRUTH_LIBRARY[targetPreset];
  if (!groundTruth || groundTruth.length === 0) return null;

  const matchDetails: AccuracyScore["matchDetails"] = [];
  const matchedLlmIndices = new Set<number>();

  // For each ground truth vuln, find the best matching LLM finding
  for (const gt of groundTruth) {
    let bestMatch: { index: number; score: number; finding: any } | null = null;

    for (let i = 0; i < llmFindings.length; i++) {
      if (matchedLlmIndices.has(i)) continue;

      const f = llmFindings[i];
      let matchScore = 0;

      // Title similarity (fuzzy match)
      const gtTitle = gt.title.toLowerCase();
      const fTitle = (f.title || "").toLowerCase();
      if (fTitle.includes(gtTitle) || gtTitle.includes(fTitle)) matchScore += 3;
      else {
        // Check for keyword overlap
        const gtWords = new Set(gtTitle.split(/\s+/).filter(w => w.length > 3));
        const fWords = new Set(fTitle.split(/\s+/).filter(w => w.length > 3));
        let overlap = 0;
        for (const w of gtWords) { if (fWords.has(w)) overlap++; }
        matchScore += (overlap / Math.max(gtWords.size, 1)) * 2;
      }

      // Category match
      const gtCat = gt.category.toLowerCase();
      const fCat = (f.category || "").toLowerCase();
      if (fCat.includes(gtCat) || gtCat.includes(fCat)) matchScore += 1;

      // CVE match (strong signal)
      if (gt.cve && f.cve && gt.cve === f.cve) matchScore += 3;

      // Severity keyword match
      const gtSev = gt.severity.toLowerCase();
      const fSev = (f.severity || "").toLowerCase();
      if (gtSev === fSev) matchScore += 0.5;

      if (matchScore > 1.0 && (!bestMatch || matchScore > bestMatch.score)) {
        bestMatch = { index: i, score: matchScore, finding: f };
      }
    }

    if (bestMatch) {
      matchedLlmIndices.add(bestMatch.index);
      const severityMatch = gt.severity.toLowerCase() === (bestMatch.finding.severity || "").toLowerCase();
      matchDetails.push({ groundTruth: gt, matched: true, llmFinding: bestMatch.finding, severityMatch });
    } else {
      matchDetails.push({ groundTruth: gt, matched: false, severityMatch: false });
    }
  }

  // Unmatched LLM findings = potential false positives
  const unmatchedLlmFindings = llmFindings.filter((_, i) => !matchedLlmIndices.has(i));

  const truePositives = matchDetails.filter(m => m.matched).length;
  const falseNegatives = matchDetails.filter(m => !m.matched).length;
  const falsePositives = unmatchedLlmFindings.length;

  const precision = truePositives + falsePositives > 0
    ? truePositives / (truePositives + falsePositives) : 0;
  const recall = truePositives + falseNegatives > 0
    ? truePositives / (truePositives + falseNegatives) : 0;
  const f1Score = precision + recall > 0
    ? 2 * (precision * recall) / (precision + recall) : 0;

  const severityCorrect = matchDetails.filter(m => m.matched && m.severityMatch).length;
  const severityAccuracy = truePositives > 0 ? severityCorrect / truePositives : 0;

  // Overall score: weighted combination of F1 (60%) + severity accuracy (20%) + low FP rate (20%)
  const fpRate = llmFindings.length > 0 ? falsePositives / llmFindings.length : 0;
  const overallScore = (f1Score * 0.6) + (severityAccuracy * 0.2) + ((1 - fpRate) * 0.2);

  return {
    totalGroundTruth: groundTruth.length,
    truePositives,
    falsePositives,
    falseNegatives,
    precision: Math.round(precision * 10000) / 10000,
    recall: Math.round(recall * 10000) / 10000,
    f1Score: Math.round(f1Score * 10000) / 10000,
    severityAccuracy: Math.round(severityAccuracy * 10000) / 10000,
    overallScore: Math.round(overallScore * 10000) / 10000,
    matchDetails,
    unmatchedLlmFindings,
  };
}

/**
 * Persist an accuracy score to the database for trending.
 */
export async function saveAccuracyScore(sessionId: string, targetPreset: string, score: AccuracyScore): Promise<void> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    await conn.execute(
      `INSERT INTO llm_accuracy_scores (session_id, target_preset, total_ground_truth, true_positives, false_positives, false_negatives, precision_score, recall_score, f1_score, severity_accuracy, overall_score, scored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [sessionId, targetPreset, score.totalGroundTruth, score.truePositives, score.falsePositives, score.falseNegatives, score.precision, score.recall, score.f1Score, score.severityAccuracy, score.overallScore, Date.now()]
    );
  } finally {
    await conn.end();
  }
}

/**
 * Get accuracy trend data for a target preset.
 */
export async function getAccuracyTrend(targetPreset?: string, limit = 50): Promise<Array<{
  sessionId: string;
  targetPreset: string;
  f1Score: number;
  precision: number;
  recall: number;
  overallScore: number;
  scoredAt: number;
}>> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const query = targetPreset
      ? `SELECT * FROM llm_accuracy_scores WHERE target_preset = ? ORDER BY scored_at DESC LIMIT ?`
      : `SELECT * FROM llm_accuracy_scores ORDER BY scored_at DESC LIMIT ?`;
    const params = targetPreset ? [targetPreset, String(limit)] : [String(limit)];
    const [rows] = await conn.execute(query, params);
    return (rows as any[]).map(r => ({
      sessionId: r.session_id,
      targetPreset: r.target_preset,
      f1Score: Number(r.f1_score),
      precision: Number(r.precision_score),
      recall: Number(r.recall_score),
      overallScore: Number(r.overall_score),
      scoredAt: Number(r.scored_at),
    }));
  } finally {
    await conn.end();
  }
}

/**
 * Get aggregate accuracy stats per target.
 */
export async function getAccuracyStats(): Promise<Array<{
  targetPreset: string;
  sessionCount: number;
  avgF1: number;
  avgPrecision: number;
  avgRecall: number;
  avgOverall: number;
  latestF1: number;
  trend: "improving" | "declining" | "stable" | "insufficient_data";
}>> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const [rows] = await conn.execute(`
      SELECT target_preset,
        COUNT(*) as session_count,
        AVG(f1_score) as avg_f1,
        AVG(precision_score) as avg_precision,
        AVG(recall_score) as avg_recall,
        AVG(overall_score) as avg_overall
      FROM llm_accuracy_scores
      GROUP BY target_preset
      ORDER BY session_count DESC
    `);

    const results: any[] = [];
    for (const r of rows as any[]) {
      // Get latest and second-latest to determine trend
      const [trendRows] = await conn.execute(
        `SELECT f1_score FROM llm_accuracy_scores WHERE target_preset = ? ORDER BY scored_at DESC LIMIT 3`,
        [r.target_preset]
      );
      const scores = (trendRows as any[]).map(t => Number(t.f1_score));
      let trend: string = "insufficient_data";
      if (scores.length >= 3) {
        const recent = (scores[0] + scores[1]) / 2;
        const older = scores[2];
        if (recent > older + 0.05) trend = "improving";
        else if (recent < older - 0.05) trend = "declining";
        else trend = "stable";
      } else if (scores.length === 2) {
        if (scores[0] > scores[1] + 0.05) trend = "improving";
        else if (scores[0] < scores[1] - 0.05) trend = "declining";
        else trend = "stable";
      }

      results.push({
        targetPreset: r.target_preset,
        sessionCount: Number(r.session_count),
        avgF1: Math.round(Number(r.avg_f1) * 10000) / 10000,
        avgPrecision: Math.round(Number(r.avg_precision) * 10000) / 10000,
        avgRecall: Math.round(Number(r.avg_recall) * 10000) / 10000,
        avgOverall: Math.round(Number(r.avg_overall) * 10000) / 10000,
        latestF1: scores[0] || 0,
        trend,
      });
    }
    return results;
  } finally {
    await conn.end();
  }
}

/**
 * Build the complete learning context for an LLM analysis prompt.
 * This is the main entry point — call this before every LLM analysis.
 */
export async function buildLearningContext(targetPreset: string): Promise<string> {
  try {
    const [targetLearnings, globalLearnings] = await Promise.all([
      getLearningEntries(targetPreset),
      getAllLearningEntries(200),
    ]);

    const correctionPrompt = buildCorrectionHistoryPrompt(targetPreset, targetLearnings, globalLearnings);

    // Add ground truth hints if available
    const groundTruth = GROUND_TRUTH_LIBRARY[targetPreset];
    let groundTruthHint = "";
    if (groundTruth && groundTruth.length > 0) {
      groundTruthHint = `\n═══ KNOWN VULNERABILITY AREAS FOR THIS TARGET ═══\nThis is a known vulnerable training application with ${groundTruth.length} documented vulnerabilities.\nCategories to investigate: ${[...new Set(groundTruth.map(g => g.category))].join(", ")}\nExpected severity range: ${[...new Set(groundTruth.map(g => g.severity))].join(", ")}\nBe thorough — your accuracy is being measured against known ground truth.\n`;
    }

    return correctionPrompt + groundTruthHint;
  } catch (e: any) {
    console.error("[LLM-SelfLearning] Failed to build learning context:", e.message);
    return "";
  }
}

/**
 * Get learning stats summary for the dashboard.
 */
export async function getLearningStats(): Promise<{
  totalFeedbackEntries: number;
  correctCount: number;
  incorrectCount: number;
  missedCount: number;
  partialCount: number;
  uniqueTargets: number;
  accuracyStats: Awaited<ReturnType<typeof getAccuracyStats>>;
}> {
  const mysql = await import("mysql2/promise");
  const conn = await mysql.createConnection(process.env.DATABASE_URL);
  try {
    const [countRows] = await conn.execute(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_count,
        SUM(CASE WHEN feedback_type = 'incorrect' OR feedback_type = 'false_positive' THEN 1 ELSE 0 END) as incorrect_count,
        SUM(CASE WHEN feedback_type = 'missed_finding' THEN 1 ELSE 0 END) as missed_count,
        SUM(CASE WHEN feedback_type = 'partial' THEN 1 ELSE 0 END) as partial_count,
        COUNT(DISTINCT target_preset) as unique_targets
      FROM llm_learning_entries
    `);
    const r = (countRows as any[])[0] || {};
    const accuracyStats = await getAccuracyStats();
    await conn.end();

    return {
      totalFeedbackEntries: Number(r.total) || 0,
      correctCount: Number(r.correct_count) || 0,
      incorrectCount: Number(r.incorrect_count) || 0,
      missedCount: Number(r.missed_count) || 0,
      partialCount: Number(r.partial_count) || 0,
      uniqueTargets: Number(r.unique_targets) || 0,
      accuracyStats,
    };
  } catch (e: any) {
    console.error("[LLM-SelfLearning] Failed to get learning stats:", e.message);
    return {
      totalFeedbackEntries: 0,
      correctCount: 0,
      incorrectCount: 0,
      missedCount: 0,
      partialCount: 0,
      uniqueTargets: 0,
      accuracyStats: [],
    };
  }
}
