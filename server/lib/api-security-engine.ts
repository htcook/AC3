/**
 * API Security Testing Engine
 * Tests APIs against OWASP API Security Top 10 (2023 edition).
 */

export interface APISecurityTestDef {
  id: string;
  testName: string;
  owaspCategory: string;
  owaspId: string;
  owaspName: string;
  description: string;
  testType: "automated" | "semi_automated" | "manual";
  severity: "critical" | "high" | "medium" | "low" | "info";
  testPayload: { method: string; path: string; headers?: Record<string, string>; body?: any; description: string };
  expectedResult: string;
}

// ── OWASP API Security Top 10 (2023) ────────────────────────────────────
export const OWASP_API_TOP_10 = {
  API1_BOLA: {
    id: "API1",
    name: "Broken Object Level Authorization",
    description: "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Every function that receives an ID from the client should check whether the client is authorized to access the resource.",
    severity: "critical" as const,
  },
  API2_BROKEN_AUTH: {
    id: "API2",
    name: "Broken Authentication",
    description: "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.",
    severity: "critical" as const,
  },
  API3_OBJECT_PROPERTY: {
    id: "API3",
    name: "Broken Object Property Level Authorization",
    description: "APIs tend to expose endpoints that return all object properties. This is particularly valid for REST APIs. Lack of or improper authorization validation at the object property level can lead to information exposure or manipulation.",
    severity: "high" as const,
  },
  API4_UNRESTRICTED_CONSUMPTION: {
    id: "API4",
    name: "Unrestricted Resource Consumption",
    description: "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. APIs that do not limit resource consumption are vulnerable to DoS attacks.",
    severity: "medium" as const,
  },
  API5_BROKEN_FUNCTION_AUTH: {
    id: "API5",
    name: "Broken Function Level Authorization",
    description: "Complex access control policies with different hierarchies, groups, and roles create a tendency for authorization flaws. Attackers can access other users' resources or admin functions.",
    severity: "critical" as const,
  },
  API6_SERVER_SIDE_REQUEST_FORGERY: {
    id: "API6",
    name: "Server Side Request Forgery",
    description: "APIs that fetch remote resources without validating the user-supplied URI can be exploited to make requests to internal services, bypassing firewalls and access controls.",
    severity: "high" as const,
  },
  API7_SECURITY_MISCONFIGURATION: {
    id: "API7",
    name: "Security Misconfiguration",
    description: "APIs and the systems supporting them typically contain complex configurations. Misconfigurations at any level can expose the API to various attacks.",
    severity: "medium" as const,
  },
  API8_LACK_OF_PROTECTION: {
    id: "API8",
    name: "Lack of Protection from Automated Threats",
    description: "APIs are accessible to automated tools and bots. APIs that do not implement protections against automated threats are vulnerable to business logic abuse.",
    severity: "medium" as const,
  },
  API9_IMPROPER_INVENTORY: {
    id: "API9",
    name: "Improper Inventory Management",
    description: "APIs tend to expose more endpoints than traditional web applications. Proper and updated documentation is important. Hosts and deployed API versions inventory also play an important role.",
    severity: "medium" as const,
  },
  API10_UNSAFE_API_CONSUMPTION: {
    id: "API10",
    name: "Unsafe Consumption of APIs",
    description: "Developers tend to trust data received from third-party APIs more than user input. Attackers target integrated third-party services to compromise APIs that consume their data.",
    severity: "high" as const,
  },
};

// ── Built-in API Security Tests ─────────────────────────────────────────
export const API_SECURITY_TESTS: APISecurityTestDef[] = [
  // API1: BOLA
  {
    id: "api-bola-01", testName: "IDOR via Sequential ID Enumeration", owaspCategory: "API1_BOLA", owaspId: "API1", owaspName: "Broken Object Level Authorization",
    description: "Tests whether API endpoints allow access to other users' resources by changing object IDs",
    testType: "automated", severity: "critical",
    testPayload: { method: "GET", path: "/api/users/{other_user_id}/profile", description: "Replace {other_user_id} with another user's ID" },
    expectedResult: "API should return 403 Forbidden when accessing another user's resource",
  },
  {
    id: "api-bola-02", testName: "IDOR via UUID Prediction", owaspCategory: "API1_BOLA", owaspId: "API1", owaspName: "Broken Object Level Authorization",
    description: "Tests whether UUIDs are predictable or enumerable",
    testType: "automated", severity: "critical",
    testPayload: { method: "GET", path: "/api/resources/{uuid}", description: "Test with sequential or predictable UUIDs" },
    expectedResult: "UUIDs should be random and access should be authorized per-user",
  },
  // API2: Broken Auth
  {
    id: "api-auth-01", testName: "JWT None Algorithm Attack", owaspCategory: "API2_BROKEN_AUTH", owaspId: "API2", owaspName: "Broken Authentication",
    description: "Tests whether the API accepts JWTs with 'none' algorithm",
    testType: "automated", severity: "critical",
    testPayload: { method: "GET", path: "/api/protected", headers: { "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0..." }, description: "Send JWT with alg:none" },
    expectedResult: "API should reject tokens with 'none' algorithm",
  },
  {
    id: "api-auth-02", testName: "Brute Force Login", owaspCategory: "API2_BROKEN_AUTH", owaspId: "API2", owaspName: "Broken Authentication",
    description: "Tests rate limiting on authentication endpoints",
    testType: "automated", severity: "high",
    testPayload: { method: "POST", path: "/api/auth/login", body: { username: "admin", password: "test" }, description: "Send 100+ login attempts rapidly" },
    expectedResult: "API should implement rate limiting and account lockout",
  },
  {
    id: "api-auth-03", testName: "Token Expiration Validation", owaspCategory: "API2_BROKEN_AUTH", owaspId: "API2", owaspName: "Broken Authentication",
    description: "Tests whether expired tokens are properly rejected",
    testType: "automated", severity: "high",
    testPayload: { method: "GET", path: "/api/protected", headers: { "Authorization": "Bearer {expired_token}" }, description: "Send expired JWT" },
    expectedResult: "API should reject expired tokens with 401",
  },
  // API3: Object Property
  {
    id: "api-prop-01", testName: "Mass Assignment via Extra Properties", owaspCategory: "API3_OBJECT_PROPERTY", owaspId: "API3", owaspName: "Broken Object Property Level Authorization",
    description: "Tests whether the API accepts and processes unexpected properties in request body",
    testType: "automated", severity: "high",
    testPayload: { method: "PUT", path: "/api/users/me", body: { name: "Test", role: "admin", isVerified: true }, description: "Include unauthorized properties" },
    expectedResult: "API should ignore or reject unauthorized properties like role, isVerified",
  },
  {
    id: "api-prop-02", testName: "Excessive Data Exposure", owaspCategory: "API3_OBJECT_PROPERTY", owaspId: "API3", owaspName: "Broken Object Property Level Authorization",
    description: "Tests whether API responses contain sensitive fields that should be filtered",
    testType: "semi_automated", severity: "medium",
    testPayload: { method: "GET", path: "/api/users", description: "Check response for sensitive fields (password hashes, SSNs, etc.)" },
    expectedResult: "API should not expose sensitive fields in responses",
  },
  // API4: Unrestricted Consumption
  {
    id: "api-rate-01", testName: "Rate Limit Bypass", owaspCategory: "API4_UNRESTRICTED_CONSUMPTION", owaspId: "API4", owaspName: "Unrestricted Resource Consumption",
    description: "Tests whether rate limits can be bypassed via header manipulation",
    testType: "automated", severity: "medium",
    testPayload: { method: "GET", path: "/api/search", headers: { "X-Forwarded-For": "127.0.0.1" }, description: "Attempt to bypass rate limiting" },
    expectedResult: "Rate limits should not be bypassable via header manipulation",
  },
  {
    id: "api-rate-02", testName: "Large Payload DoS", owaspCategory: "API4_UNRESTRICTED_CONSUMPTION", owaspId: "API4", owaspName: "Unrestricted Resource Consumption",
    description: "Tests whether the API limits request body size",
    testType: "automated", severity: "medium",
    testPayload: { method: "POST", path: "/api/upload", body: "10MB_payload", description: "Send oversized request body" },
    expectedResult: "API should reject oversized payloads with 413",
  },
  // API5: Broken Function Auth
  {
    id: "api-func-01", testName: "Admin Endpoint Access as Regular User", owaspCategory: "API5_BROKEN_FUNCTION_AUTH", owaspId: "API5", owaspName: "Broken Function Level Authorization",
    description: "Tests whether admin-only endpoints are accessible to regular users",
    testType: "automated", severity: "critical",
    testPayload: { method: "GET", path: "/api/admin/users", description: "Access admin endpoint with regular user token" },
    expectedResult: "API should return 403 for non-admin users",
  },
  {
    id: "api-func-02", testName: "HTTP Method Tampering", owaspCategory: "API5_BROKEN_FUNCTION_AUTH", owaspId: "API5", owaspName: "Broken Function Level Authorization",
    description: "Tests whether changing HTTP method bypasses authorization (GET vs DELETE)",
    testType: "automated", severity: "high",
    testPayload: { method: "DELETE", path: "/api/resources/{id}", description: "Use DELETE on read-only endpoint" },
    expectedResult: "API should enforce authorization regardless of HTTP method",
  },
  // API6: SSRF
  {
    id: "api-ssrf-01", testName: "Internal Service Access via URL Parameter", owaspCategory: "API6_SERVER_SIDE_REQUEST_FORGERY", owaspId: "API6", owaspName: "Server Side Request Forgery",
    description: "Tests whether the API can be tricked into accessing internal services",
    testType: "automated", severity: "high",
    testPayload: { method: "POST", path: "/api/fetch-url", body: { url: "http://169.254.169.254/latest/meta-data/" }, description: "Attempt to access cloud metadata" },
    expectedResult: "API should block requests to internal/metadata endpoints",
  },
  // API7: Security Misconfiguration
  {
    id: "api-misconfig-01", testName: "CORS Misconfiguration", owaspCategory: "API7_SECURITY_MISCONFIGURATION", owaspId: "API7", owaspName: "Security Misconfiguration",
    description: "Tests whether CORS headers allow overly permissive origins",
    testType: "automated", severity: "medium",
    testPayload: { method: "OPTIONS", path: "/api/data", headers: { "Origin": "https://evil.com" }, description: "Send request with malicious origin" },
    expectedResult: "API should not reflect arbitrary origins in Access-Control-Allow-Origin",
  },
  {
    id: "api-misconfig-02", testName: "Verbose Error Messages", owaspCategory: "API7_SECURITY_MISCONFIGURATION", owaspId: "API7", owaspName: "Security Misconfiguration",
    description: "Tests whether error responses leak implementation details",
    testType: "automated", severity: "low",
    testPayload: { method: "GET", path: "/api/nonexistent' OR 1=1--", description: "Send malformed request to trigger error" },
    expectedResult: "Error responses should not reveal stack traces, SQL queries, or internal paths",
  },
  // API8: Automated Threats
  {
    id: "api-bot-01", testName: "Credential Stuffing Protection", owaspCategory: "API8_LACK_OF_PROTECTION", owaspId: "API8", owaspName: "Lack of Protection from Automated Threats",
    description: "Tests whether the API detects and blocks credential stuffing attacks",
    testType: "semi_automated", severity: "medium",
    testPayload: { method: "POST", path: "/api/auth/login", description: "Send 1000 unique credential pairs rapidly" },
    expectedResult: "API should detect and block automated credential testing",
  },
  // API9: Improper Inventory
  {
    id: "api-inv-01", testName: "Deprecated API Version Access", owaspCategory: "API9_IMPROPER_INVENTORY", owaspId: "API9", owaspName: "Improper Inventory Management",
    description: "Tests whether deprecated API versions are still accessible",
    testType: "semi_automated", severity: "medium",
    testPayload: { method: "GET", path: "/api/v1/users", description: "Access deprecated v1 API" },
    expectedResult: "Deprecated API versions should be decommissioned or return deprecation notices",
  },
  // API10: Unsafe Consumption
  {
    id: "api-unsafe-01", testName: "Injection via Third-Party Data", owaspCategory: "API10_UNSAFE_API_CONSUMPTION", owaspId: "API10", owaspName: "Unsafe Consumption of APIs",
    description: "Tests whether data from third-party APIs is properly validated before use",
    testType: "manual", severity: "high",
    testPayload: { method: "POST", path: "/api/webhook", body: { data: "<script>alert(1)</script>" }, description: "Send XSS payload via webhook" },
    expectedResult: "API should sanitize all external data before processing or storing",
  },
];

// ── Fuzzing Strategies ──────────────────────────────────────────────────
export const FUZZING_STRATEGIES = {
  parameter_mutation: {
    name: "Parameter Mutation",
    description: "Mutates parameter values with boundary values, type confusion, and special characters",
    mutations: ["null", "undefined", "0", "-1", "999999999", "true", "false", "[]", "{}", "''", "' OR 1=1--", "<script>", "../../../etc/passwd"],
  },
  injection: {
    name: "Injection Testing",
    description: "Tests for SQL injection, NoSQL injection, command injection, and XSS",
    payloads: {
      sql: ["' OR '1'='1", "'; DROP TABLE users;--", "1 UNION SELECT * FROM users--", "admin'--"],
      nosql: ['{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}'],
      command: ["; ls -la", "| cat /etc/passwd", "$(whoami)", "`id`"],
      xss: ["<script>alert(1)</script>", "<img onerror=alert(1) src=x>", "javascript:alert(1)"],
    },
  },
  auth_bypass: {
    name: "Authentication Bypass",
    description: "Tests various authentication bypass techniques",
    techniques: ["Remove auth header", "Empty bearer token", "JWT alg:none", "Expired token", "Token from different user", "SQL injection in credentials"],
  },
  rate_limit: {
    name: "Rate Limit Testing",
    description: "Tests rate limiting effectiveness and bypass techniques",
    techniques: ["Rapid sequential requests", "Distributed requests via different IPs", "Header manipulation (X-Forwarded-For)", "Slow-rate attacks"],
  },
  schema_violation: {
    name: "Schema Violation",
    description: "Sends requests that violate the expected schema",
    violations: ["Wrong data types", "Missing required fields", "Extra unexpected fields", "Oversized values", "Negative numbers for positive-only fields", "Future dates for past-only fields"],
  },
};

/**
 * Calculate API security score
 */
export function calculateAPISecurityScore(results: Array<{ result: string; severity: string }>) {
  const total = results.length;
  if (total === 0) return { score: 100, vulnerabilities: 0, secure: 0 };
  
  const vulnerable = results.filter(r => r.result === "vulnerable");
  const secure = results.filter(r => r.result === "secure").length;
  
  // Weight by severity
  const severityWeights: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
  const maxScore = results.reduce((sum, r) => sum + (severityWeights[r.severity] || 1), 0);
  const lostScore = vulnerable.reduce((sum, r) => sum + (severityWeights[r.severity] || 1), 0);
  
  const score = maxScore > 0 ? Math.round(((maxScore - lostScore) / maxScore) * 100) : 100;
  
  return {
    score,
    total,
    secure,
    vulnerabilities: vulnerable.length,
    bySeverity: {
      critical: vulnerable.filter(r => r.severity === "critical").length,
      high: vulnerable.filter(r => r.severity === "high").length,
      medium: vulnerable.filter(r => r.severity === "medium").length,
      low: vulnerable.filter(r => r.severity === "low").length,
    },
  };
}
