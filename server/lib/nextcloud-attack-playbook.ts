/**
 * Nextcloud Attack Playbook
 * 
 * Defines structured attack phases targeting Nextcloud's highest-value
 * attack surfaces, mapped to MITRE ATT&CK techniques and CWEs.
 * Each phase includes specific test cases, tools, and expected outcomes.
 */

import type { TestLabConfig } from "./nextcloud-test-lab";
import { DEFAULT_LAB_CONFIG } from "./nextcloud-test-lab";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AttackPhase {
  id: string;
  name: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  estimatedHours: number;
  /** MITRE ATT&CK technique IDs */
  attackTechniques: AttackTechnique[];
  /** CWE IDs this phase targets */
  targetCwes: CweReference[];
  /** Specific test cases to execute */
  testCases: TestCase[];
  /** Tools recommended for this phase */
  tools: string[];
  /** Nextcloud apps/components in scope */
  targetComponents: string[];
  /** Prerequisites that must be met before this phase */
  prerequisites: string[];
  /** Expected bounty range if vulnerabilities found */
  bountyRange: { min: number; max: number };
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface CweReference {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface TestCase {
  id: string;
  name: string;
  description: string;
  steps: string[];
  expectedResult: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  automated: boolean;
  /** Burp scan profile that covers this test case (if any) */
  burpProfile?: string;
}

export interface AttackPlaybook {
  name: string;
  target: string;
  version: string;
  createdAt: number;
  totalPhases: number;
  totalTestCases: number;
  estimatedTotalHours: number;
  maxBounty: number;
  phases: AttackPhase[];
}

// ─── Phase Definitions ───────────────────────────────────────────────────────

const PHASE_1_AUTH: AttackPhase = {
  id: "phase-1-auth",
  name: "Authentication & Session Management",
  description: "Target Nextcloud's authentication stack including login, 2FA, app passwords, session management, CSRF protections, and brute force controls. Includes LDAP and SAML/SSO bypass if configured.",
  priority: "critical",
  estimatedHours: 12,
  attackTechniques: [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
    { id: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
    { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access" },
    { id: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" },
    { id: "T1556", name: "Modify Authentication Process", tactic: "Credential Access" },
    { id: "T1556.002", name: "Password Filter DLL (LDAP analogy)", tactic: "Credential Access" },
  ],
  targetCwes: [
    { id: "CWE-287", name: "Improper Authentication", severity: "critical" },
    { id: "CWE-352", name: "Cross-Site Request Forgery", severity: "high" },
    { id: "CWE-384", name: "Session Fixation", severity: "high" },
    { id: "CWE-307", name: "Improper Restriction of Excessive Auth Attempts", severity: "medium" },
    { id: "CWE-613", name: "Insufficient Session Expiration", severity: "medium" },
    { id: "CWE-90", name: "LDAP Injection", severity: "critical" },
  ],
  testCases: [
    {
      id: "auth-01",
      name: "Login CSRF bypass",
      description: "Attempt to forge login requests without valid CSRF token",
      steps: [
        "Capture a valid login request with Burp",
        "Remove or modify the requesttoken parameter",
        "Replay the request and observe the response",
        "Test with different Content-Type headers to bypass CSRF checks",
      ],
      expectedResult: "Login should fail without valid CSRF token",
      severity: "high",
      automated: true,
      burpProfile: "auth-endpoints",
    },
    {
      id: "auth-02",
      name: "Session fixation via app password",
      description: "Test if app passwords can be used to fixate sessions",
      steps: [
        "Generate an app password via /settings/personal/security",
        "Use the app password to authenticate via WebDAV",
        "Check if the session token is predictable or reusable across contexts",
        "Attempt to use the app password token in the web UI",
      ],
      expectedResult: "App password sessions should be isolated from web sessions",
      severity: "high",
      automated: false,
    },
    {
      id: "auth-03",
      name: "Brute force rate limiting bypass",
      description: "Test rate limiting on login endpoint with various evasion techniques",
      steps: [
        "Send 30+ failed login attempts from a single IP",
        "Verify rate limiting kicks in (HTTP 429 or delay)",
        "Try bypassing with X-Forwarded-For header manipulation",
        "Try bypassing with different User-Agent strings",
        "Test if rate limiting applies per-user or per-IP",
      ],
      expectedResult: "Rate limiting should not be bypassable via header manipulation",
      severity: "medium",
      automated: true,
      burpProfile: "auth-endpoints",
    },
    {
      id: "auth-04",
      name: "LDAP injection in login",
      description: "Test for LDAP injection in the login form when LDAP backend is configured",
      steps: [
        "Configure LDAP authentication in admin settings",
        "Attempt login with LDAP injection payloads: *)(&, *)(uid=*, )(cn=*",
        "Test LDAP injection in the username field",
        "Test LDAP injection in group membership queries",
      ],
      expectedResult: "LDAP special characters should be properly escaped",
      severity: "critical",
      automated: true,
      burpProfile: "ldap-integration",
    },
    {
      id: "auth-05",
      name: "2FA bypass via login flow v2",
      description: "Test if the login flow v2 (used by mobile/desktop clients) properly enforces 2FA",
      steps: [
        "Enable TOTP 2FA for a test user",
        "Initiate login flow v2 via /login/v2",
        "Complete the flow and check if 2FA is enforced",
        "Try polling /login/v2/poll before 2FA completion",
        "Test race condition between 2FA prompt and poll endpoint",
      ],
      expectedResult: "2FA should be enforced before granting access token",
      severity: "critical",
      automated: false,
    },
    {
      id: "auth-06",
      name: "SAML assertion manipulation",
      description: "Test SAML SSO for assertion replay, signature bypass, and redirect manipulation",
      steps: [
        "Capture SAML assertion from Keycloak login flow",
        "Modify assertion attributes (email, groups, admin flag)",
        "Test XML signature wrapping attacks",
        "Test assertion replay after logout",
        "Manipulate RelayState parameter for open redirect",
      ],
      expectedResult: "Modified assertions should be rejected; signatures must be verified",
      severity: "critical",
      automated: false,
    },
  ],
  tools: ["Burp Suite", "Hydra", "Custom Python scripts", "SAML Raider (Burp extension)"],
  targetComponents: ["core/login", "user_ldap", "user_saml", "twofactor_totp", "twofactor_webauthn"],
  prerequisites: ["Test lab deployed", "LDAP configured (if testing LDAP)", "Keycloak configured (if testing SAML)"],
  bountyRange: { min: 250, max: 5000 },
};

const PHASE_2_SHARING: AttackPhase = {
  id: "phase-2-sharing",
  name: "File Sharing & ACL Bypass",
  description: "Target Nextcloud's file sharing system including internal shares, public links, federated sharing, group shares, and permission enforcement. Focus on IDOR, permission escalation, and data leakage.",
  priority: "critical",
  estimatedHours: 10,
  attackTechniques: [
    { id: "T1080", name: "Taint Shared Content", tactic: "Lateral Movement" },
    { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
    { id: "T1537", name: "Transfer Data to Cloud Account", tactic: "Exfiltration" },
  ],
  targetCwes: [
    { id: "CWE-639", name: "Authorization Bypass Through User-Controlled Key", severity: "critical" },
    { id: "CWE-284", name: "Improper Access Control", severity: "high" },
    { id: "CWE-862", name: "Missing Authorization", severity: "high" },
    { id: "CWE-863", name: "Incorrect Authorization", severity: "high" },
    { id: "CWE-200", name: "Exposure of Sensitive Information", severity: "medium" },
  ],
  testCases: [
    {
      id: "share-01",
      name: "IDOR in share API",
      description: "Test for insecure direct object references in the sharing API",
      steps: [
        "Create a share as testuser1 and note the share ID",
        "As testuser2, attempt to access/modify the share by ID",
        "Enumerate share IDs sequentially to find other users' shares",
        "Test PUT/DELETE on shares owned by other users",
      ],
      expectedResult: "Users should only access their own shares",
      severity: "critical",
      automated: true,
      burpProfile: "sharing-api",
    },
    {
      id: "share-02",
      name: "Public link password bypass",
      description: "Test if password-protected public links can be accessed without the password",
      steps: [
        "Create a password-protected public share link",
        "Attempt to access the shared file via WebDAV using the share token",
        "Test if the password check can be bypassed via API endpoints",
        "Test timing attacks on password verification",
      ],
      expectedResult: "Password should be required for all access methods",
      severity: "high",
      automated: true,
      burpProfile: "sharing-api",
    },
    {
      id: "share-03",
      name: "Permission escalation on shared folders",
      description: "Test if read-only share permissions can be escalated to write",
      steps: [
        "Share a folder with testuser2 as read-only",
        "As testuser2, attempt to upload files via WebDAV MKCOL/PUT",
        "Attempt to delete files via WebDAV DELETE",
        "Test if MOVE/COPY operations bypass read-only restrictions",
      ],
      expectedResult: "Read-only shares should prevent all write operations",
      severity: "high",
      automated: false,
    },
    {
      id: "share-04",
      name: "Federated share trust boundary",
      description: "Test if federated shares from external servers can bypass local policies",
      steps: [
        "Configure a second Nextcloud instance as federated partner",
        "Send a federated share with manipulated metadata",
        "Test if the receiving server validates the share permissions",
        "Check if federated share notifications can be spoofed",
      ],
      expectedResult: "Federated shares should enforce local security policies",
      severity: "high",
      automated: false,
    },
    {
      id: "share-05",
      name: "Share expiry bypass",
      description: "Test if expired shares can still be accessed",
      steps: [
        "Create a share with a short expiry (1 minute)",
        "Access the share before expiry and cache the response",
        "After expiry, attempt to access via direct WebDAV path",
        "Test if the share token remains valid after expiry",
      ],
      expectedResult: "Expired shares should be completely inaccessible",
      severity: "medium",
      automated: true,
      burpProfile: "sharing-api",
    },
  ],
  tools: ["Burp Suite", "Custom WebDAV client", "curl"],
  targetComponents: ["files_sharing", "federatedfilesharing", "sharebymail", "files"],
  prerequisites: ["Test lab deployed", "Multiple test users created"],
  bountyRange: { min: 250, max: 5000 },
};

const PHASE_3_E2E: AttackPhase = {
  id: "phase-3-e2e",
  name: "End-to-End Encryption",
  description: "Target Nextcloud's E2E encryption implementation including key management, metadata protection, encryption/decryption flows, and potential downgrade attacks.",
  priority: "high",
  estimatedHours: 8,
  attackTechniques: [
    { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
    { id: "T1600", name: "Weaken Encryption", tactic: "Defense Evasion" },
    { id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access" },
  ],
  targetCwes: [
    { id: "CWE-310", name: "Cryptographic Issues", severity: "critical" },
    { id: "CWE-326", name: "Inadequate Encryption Strength", severity: "high" },
    { id: "CWE-327", name: "Use of Broken Crypto Algorithm", severity: "high" },
    { id: "CWE-200", name: "Information Exposure", severity: "medium" },
    { id: "CWE-311", name: "Missing Encryption of Sensitive Data", severity: "high" },
  ],
  testCases: [
    {
      id: "e2e-01",
      name: "Private key extraction from server",
      description: "Test if the server stores or can access the user's E2E private key",
      steps: [
        "Enable E2E encryption for testuser1",
        "Generate key pair via the E2E API",
        "Check if the private key is stored server-side in cleartext",
        "As admin, attempt to access the private key via OCC or database",
        "Check if the encrypted private key passphrase can be brute-forced",
      ],
      expectedResult: "Private key should never be accessible to the server in cleartext",
      severity: "critical",
      automated: false,
    },
    {
      id: "e2e-02",
      name: "Metadata leakage in E2E folders",
      description: "Test if file metadata (names, sizes, timestamps) leaks for E2E encrypted folders",
      steps: [
        "Create an E2E encrypted folder and upload files",
        "As a different user or admin, query the folder via WebDAV PROPFIND",
        "Check if file names, sizes, or modification times are visible",
        "Check the database directly for metadata exposure",
      ],
      expectedResult: "No file metadata should be visible to unauthorized users",
      severity: "high",
      automated: false,
    },
    {
      id: "e2e-03",
      name: "E2E lock bypass for concurrent access",
      description: "Test if the E2E lock mechanism can be bypassed to corrupt encrypted data",
      steps: [
        "Lock an E2E folder via the lock API",
        "From another session, attempt to modify files in the locked folder",
        "Test race conditions between lock acquisition and file operations",
        "Test if lock tokens can be guessed or enumerated",
      ],
      expectedResult: "Locked folders should reject all modifications from other sessions",
      severity: "high",
      automated: true,
      burpProfile: "e2e-encryption",
    },
    {
      id: "e2e-04",
      name: "Encryption downgrade attack",
      description: "Test if the client can be tricked into disabling E2E encryption",
      steps: [
        "Intercept the capabilities response from the server",
        "Remove or modify the E2E encryption capability flags",
        "Check if the client falls back to unencrypted upload",
        "Test if the server accepts unencrypted files in an E2E folder",
      ],
      expectedResult: "E2E folders should reject unencrypted uploads regardless of capability flags",
      severity: "critical",
      automated: false,
    },
  ],
  tools: ["Burp Suite", "mitmproxy", "Custom crypto analysis scripts", "OpenSSL"],
  targetComponents: ["end_to_end_encryption", "encryption"],
  prerequisites: ["Test lab deployed", "E2E encryption app installed"],
  bountyRange: { min: 500, max: 10000 },
};

const PHASE_4_TALK: AttackPhase = {
  id: "phase-4-talk",
  name: "Talk / WebRTC Attacks",
  description: "Target Nextcloud Talk's real-time communication stack including WebRTC signaling, TURN server abuse, chat message injection, call manipulation, and participant enumeration.",
  priority: "high",
  estimatedHours: 8,
  attackTechniques: [
    { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access" },
    { id: "T1040", name: "Network Sniffing", tactic: "Credential Access" },
    { id: "T1059.007", name: "JavaScript", tactic: "Execution" },
  ],
  targetCwes: [
    { id: "CWE-79", name: "Cross-Site Scripting", severity: "high" },
    { id: "CWE-918", name: "Server-Side Request Forgery", severity: "high" },
    { id: "CWE-200", name: "Information Exposure", severity: "medium" },
    { id: "CWE-346", name: "Origin Validation Error", severity: "high" },
    { id: "CWE-862", name: "Missing Authorization", severity: "high" },
  ],
  testCases: [
    {
      id: "talk-01",
      name: "Chat message XSS",
      description: "Test for stored XSS in Talk chat messages",
      steps: [
        "Send messages with HTML/JS payloads in Talk conversations",
        "Test markdown rendering for XSS (images, links, code blocks)",
        "Test file sharing messages for path traversal in previews",
        "Test mention/notification rendering for injection",
      ],
      expectedResult: "All user input should be properly sanitized",
      severity: "high",
      automated: true,
      burpProfile: "talk-webrtc",
    },
    {
      id: "talk-02",
      name: "TURN server credential abuse",
      description: "Test if TURN server credentials can be extracted and abused",
      steps: [
        "Join a Talk call and capture the TURN server credentials",
        "Test if credentials are time-limited and properly rotated",
        "Attempt to use TURN credentials for relaying arbitrary traffic",
        "Test if TURN can be used as a SOCKS proxy for SSRF",
      ],
      expectedResult: "TURN credentials should be short-lived and scope-limited",
      severity: "high",
      automated: false,
    },
    {
      id: "talk-03",
      name: "Call participant enumeration",
      description: "Test if call participants can be enumerated without being in the call",
      steps: [
        "Create a private conversation between testuser1 and testuser2",
        "As testuser3, attempt to enumerate participants via the API",
        "Test if the signaling endpoint leaks participant information",
        "Check if WebRTC ICE candidates leak internal IP addresses",
      ],
      expectedResult: "Participant info should only be visible to conversation members",
      severity: "medium",
      automated: true,
      burpProfile: "talk-webrtc",
    },
    {
      id: "talk-04",
      name: "Conversation join bypass",
      description: "Test if private/password-protected conversations can be joined without authorization",
      steps: [
        "Create a private conversation with a password",
        "As an unauthorized user, attempt to join via the API",
        "Test if the conversation token is predictable",
        "Test race conditions in the join/leave flow",
      ],
      expectedResult: "Private conversations should enforce access controls",
      severity: "high",
      automated: false,
    },
  ],
  tools: ["Burp Suite", "Wireshark", "Custom WebRTC client", "turnutils_uclient"],
  targetComponents: ["spreed", "coturn"],
  prerequisites: ["Test lab deployed", "Talk app installed", "Coturn configured"],
  bountyRange: { min: 250, max: 5000 },
};

const PHASE_5_SERVER: AttackPhase = {
  id: "phase-5-server",
  name: "Server-Side Attacks",
  description: "Target Nextcloud server core for SSRF, XXE, SQL injection, command injection, and path traversal vulnerabilities in WebDAV, OCS API, and app store integration.",
  priority: "critical",
  estimatedHours: 14,
  attackTechniques: [
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1059.007", name: "JavaScript/PHP", tactic: "Execution" },
    { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
    { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  ],
  targetCwes: [
    { id: "CWE-918", name: "Server-Side Request Forgery", severity: "critical" },
    { id: "CWE-611", name: "XXE", severity: "critical" },
    { id: "CWE-89", name: "SQL Injection", severity: "critical" },
    { id: "CWE-22", name: "Path Traversal", severity: "high" },
    { id: "CWE-94", name: "Code Injection", severity: "critical" },
    { id: "CWE-434", name: "Unrestricted File Upload", severity: "high" },
  ],
  testCases: [
    {
      id: "srv-01",
      name: "SSRF via app store / external storage",
      description: "Test for SSRF through features that make outbound HTTP requests",
      steps: [
        "Configure external storage with a malicious URL pointing to internal services",
        "Test app store URL handling for SSRF (custom app repository)",
        "Test preview generation for SSRF via crafted file URLs",
        "Test webhook/notification URLs for SSRF",
        "Use Collabora WOPI discovery URL for SSRF",
      ],
      expectedResult: "All outbound requests should validate against SSRF blocklists",
      severity: "critical",
      automated: true,
      burpProfile: "admin-settings",
    },
    {
      id: "srv-02",
      name: "XXE in WebDAV PROPFIND/PROPPATCH",
      description: "Test for XML External Entity injection in WebDAV operations",
      steps: [
        "Send PROPFIND request with XXE payload in the XML body",
        "Test PROPPATCH with external entity references",
        "Test REPORT method with XXE payloads",
        "Test CalDAV/CardDAV XML parsing for XXE",
      ],
      expectedResult: "XML parsing should disable external entity resolution",
      severity: "critical",
      automated: true,
      burpProfile: "core-webdav",
    },
    {
      id: "srv-03",
      name: "SQL injection in search/filter endpoints",
      description: "Test for SQL injection in search, filter, and sort parameters",
      steps: [
        "Test the unified search endpoint with SQL injection payloads",
        "Test file list sorting parameters for injection",
        "Test OCS API filter parameters",
        "Test tag/comment search for injection",
      ],
      expectedResult: "All database queries should use parameterized statements",
      severity: "critical",
      automated: true,
      burpProfile: "core-webdav",
    },
    {
      id: "srv-04",
      name: "Path traversal in file operations",
      description: "Test for path traversal in file upload, download, and management",
      steps: [
        "Upload files with ../ in the filename via WebDAV PUT",
        "Test MOVE/COPY operations with traversal in destination",
        "Test chunked upload with traversal in chunk paths",
        "Test trash/versions restore with traversal payloads",
      ],
      expectedResult: "Path traversal should be blocked in all file operations",
      severity: "high",
      automated: true,
      burpProfile: "core-webdav",
    },
    {
      id: "srv-05",
      name: "PHP deserialization in session/cache",
      description: "Test for PHP object injection via session or cache manipulation",
      steps: [
        "Analyze session storage mechanism (file, Redis, database)",
        "Test if session data can be manipulated to inject PHP objects",
        "Check if any API endpoints accept serialized PHP data",
        "Test memcache/Redis for deserialization vulnerabilities",
      ],
      expectedResult: "No user-controllable data should be unserialized",
      severity: "critical",
      automated: false,
    },
  ],
  tools: ["Burp Suite", "SQLMap", "XXEinjector", "Custom WebDAV scripts"],
  targetComponents: ["core/webdav", "core/search", "files_external", "core/preview"],
  prerequisites: ["Test lab deployed", "Admin access configured"],
  bountyRange: { min: 500, max: 10000 },
};

const PHASE_6_APPS: AttackPhase = {
  id: "phase-6-apps",
  name: "App-Specific Attacks",
  description: "Target individual Nextcloud apps for XSS, IDOR, data leakage, and logic flaws. Covers Calendar, Contacts, Mail, Deck, Forms, Notes, Text, and Photos.",
  priority: "high",
  estimatedHours: 12,
  attackTechniques: [
    { id: "T1059.007", name: "JavaScript", tactic: "Execution" },
    { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { id: "T1566", name: "Phishing", tactic: "Initial Access" },
  ],
  targetCwes: [
    { id: "CWE-79", name: "Cross-Site Scripting", severity: "high" },
    { id: "CWE-639", name: "IDOR", severity: "high" },
    { id: "CWE-200", name: "Information Exposure", severity: "medium" },
    { id: "CWE-862", name: "Missing Authorization", severity: "high" },
    { id: "CWE-434", name: "Unrestricted File Upload", severity: "high" },
  ],
  testCases: [
    {
      id: "app-01",
      name: "Calendar event injection (CalDAV)",
      description: "Test for injection in calendar event creation via CalDAV",
      steps: [
        "Create calendar events with XSS payloads in title, description, location",
        "Test iCalendar VTIMEZONE injection",
        "Test shared calendar event rendering for stored XSS",
        "Test calendar import (.ics) for XXE/injection",
      ],
      expectedResult: "All event fields should be properly sanitized",
      severity: "high",
      automated: true,
      burpProfile: "collaboration-apps",
    },
    {
      id: "app-02",
      name: "Mail SSRF via account setup",
      description: "Test for SSRF when configuring mail accounts (IMAP/SMTP server addresses)",
      steps: [
        "Add a mail account with internal IP as IMAP server",
        "Test with various SSRF bypass techniques (DNS rebinding, IPv6)",
        "Check if mail attachment fetching can be used for SSRF",
        "Test HTML email rendering for external resource loading",
      ],
      expectedResult: "Mail server connections should validate against internal networks",
      severity: "high",
      automated: true,
      burpProfile: "mail-app",
    },
    {
      id: "app-03",
      name: "Deck board IDOR",
      description: "Test for insecure direct object references in Deck boards and cards",
      steps: [
        "Create a private board as testuser1",
        "As testuser2, attempt to access the board by ID",
        "Test card attachment access across board boundaries",
        "Test if board activity feed leaks data to non-members",
      ],
      expectedResult: "Board access should be strictly enforced per-user",
      severity: "high",
      automated: true,
      burpProfile: "collaboration-apps",
    },
    {
      id: "app-04",
      name: "Forms response data leakage",
      description: "Test if form responses are accessible to unauthorized users",
      steps: [
        "Create a form with sensitive questions",
        "Submit responses as different users",
        "As a non-owner, attempt to access responses via API",
        "Test if form tokens are predictable for enumeration",
      ],
      expectedResult: "Only form owners should access response data",
      severity: "high",
      automated: true,
      burpProfile: "collaboration-apps",
    },
    {
      id: "app-05",
      name: "Text/Markdown stored XSS",
      description: "Test for stored XSS in the collaborative text editor",
      steps: [
        "Create documents with XSS payloads in markdown",
        "Test image embedding with javascript: URLs",
        "Test link rendering for XSS",
        "Test collaborative editing for injection during sync",
      ],
      expectedResult: "Markdown rendering should sanitize all dangerous content",
      severity: "high",
      automated: true,
      burpProfile: "collaboration-apps",
    },
    {
      id: "app-06",
      name: "Photos EXIF data leakage",
      description: "Test if photo EXIF metadata (GPS, camera info) leaks through sharing",
      steps: [
        "Upload photos with GPS EXIF data",
        "Share the photos via public link",
        "Check if EXIF data is stripped from shared previews",
        "Test if the original file (with EXIF) is downloadable via the share",
      ],
      expectedResult: "Sensitive EXIF data should be stripped from shared content",
      severity: "medium",
      automated: false,
    },
  ],
  tools: ["Burp Suite", "Custom CalDAV/CardDAV clients", "ExifTool"],
  targetComponents: ["calendar", "contacts", "mail", "deck", "forms", "notes", "text", "photos"],
  prerequisites: ["Test lab deployed", "All target apps installed"],
  bountyRange: { min: 100, max: 5000 },
};

// ─── Playbook Assembly ───────────────────────────────────────────────────────

const ALL_PHASES: AttackPhase[] = [
  PHASE_1_AUTH,
  PHASE_2_SHARING,
  PHASE_3_E2E,
  PHASE_4_TALK,
  PHASE_5_SERVER,
  PHASE_6_APPS,
];

/**
 * Generate the full Nextcloud attack playbook.
 */
export function generateAttackPlaybook(
  targetHost: string = "localhost:8443"
): AttackPlaybook {
  const totalTestCases = ALL_PHASES.reduce((sum, p) => sum + p.testCases.length, 0);
  const estimatedTotalHours = ALL_PHASES.reduce((sum, p) => sum + p.estimatedHours, 0);
  const maxBounty = Math.max(...ALL_PHASES.map((p) => p.bountyRange.max));

  return {
    name: "Nextcloud Bug Bounty Attack Playbook",
    target: targetHost,
    version: "1.0.0",
    createdAt: Date.now(),
    totalPhases: ALL_PHASES.length,
    totalTestCases,
    estimatedTotalHours,
    maxBounty,
    phases: ALL_PHASES,
  };
}

/**
 * Generate a playbook for a specific engagement, using the engagement's
 * target domain and enabled features.
 */
export function generatePlaybookForEngagement(
  engagement: {
    targetDomain?: string;
    scope?: string;
    notes?: string;
  },
  labConfig: TestLabConfig = DEFAULT_LAB_CONFIG
): AttackPlaybook {
  const host = engagement.targetDomain || labConfig.scanServerHost || "localhost";
  const target = `${host}:${labConfig.hostPort}`;

  const playbook = generateAttackPlaybook(target);

  // Filter phases based on lab config
  playbook.phases = playbook.phases.filter((phase) => {
    // Always include auth, sharing, server, and apps
    if (["phase-1-auth", "phase-2-sharing", "phase-5-server", "phase-6-apps"].includes(phase.id)) {
      return true;
    }
    // Include E2E only if encryption is likely enabled
    if (phase.id === "phase-3-e2e") return true; // Always relevant for Nextcloud
    // Include Talk only if coturn is enabled
    if (phase.id === "phase-4-talk") return labConfig.enableCoturn;
    return true;
  });

  // Update target URLs in all phases
  const oldBase = `https://localhost:${labConfig.hostPort}`;
  const newBase = `https://${target}`;
  if (oldBase !== newBase) {
    for (const phase of playbook.phases) {
      // Update test case descriptions if they reference localhost
      for (const tc of phase.testCases) {
        tc.description = tc.description.replace(/localhost/g, host);
      }
    }
  }

  playbook.totalPhases = playbook.phases.length;
  playbook.totalTestCases = playbook.phases.reduce((sum, p) => sum + p.testCases.length, 0);
  playbook.estimatedTotalHours = playbook.phases.reduce((sum, p) => sum + p.estimatedHours, 0);

  return playbook;
}

/**
 * Get a specific phase by ID.
 */
export function getPhase(phaseId: string): AttackPhase | undefined {
  return ALL_PHASES.find((p) => p.id === phaseId);
}

/**
 * Get test cases that can be automated with Burp Suite.
 */
export function getAutomatedTestCases(): TestCase[] {
  return ALL_PHASES.flatMap((p) => p.testCases.filter((tc) => tc.automated));
}

/**
 * Get test cases mapped to a specific Burp scan profile.
 */
export function getTestCasesForBurpProfile(profileName: string): TestCase[] {
  return ALL_PHASES.flatMap((p) =>
    p.testCases.filter((tc) => tc.burpProfile === profileName)
  );
}

/**
 * Get all unique MITRE ATT&CK techniques across the playbook.
 */
export function getAllAttackTechniques(): AttackTechnique[] {
  const seen = new Set<string>();
  const techniques: AttackTechnique[] = [];
  for (const phase of ALL_PHASES) {
    for (const t of phase.attackTechniques) {
      if (!seen.has(t.id)) {
        seen.add(t.id);
        techniques.push(t);
      }
    }
  }
  return techniques;
}

/**
 * Get all unique CWEs across the playbook.
 */
export function getAllTargetCwes(): CweReference[] {
  const seen = new Set<string>();
  const cwes: CweReference[] = [];
  for (const phase of ALL_PHASES) {
    for (const c of phase.targetCwes) {
      if (!seen.has(c.id)) {
        seen.add(c.id);
        cwes.push(c);
      }
    }
  }
  return cwes;
}

/**
 * Get playbook summary statistics.
 */
export function getPlaybookStats(): {
  totalPhases: number;
  totalTestCases: number;
  automatedTestCases: number;
  manualTestCases: number;
  totalEstimatedHours: number;
  uniqueAttackTechniques: number;
  uniqueCwes: number;
  maxBounty: number;
  totalBountyRange: { min: number; max: number };
} {
  const totalTestCases = ALL_PHASES.reduce((s, p) => s + p.testCases.length, 0);
  const automatedTestCases = getAutomatedTestCases().length;

  return {
    totalPhases: ALL_PHASES.length,
    totalTestCases,
    automatedTestCases,
    manualTestCases: totalTestCases - automatedTestCases,
    totalEstimatedHours: ALL_PHASES.reduce((s, p) => s + p.estimatedHours, 0),
    uniqueAttackTechniques: getAllAttackTechniques().length,
    uniqueCwes: getAllTargetCwes().length,
    maxBounty: Math.max(...ALL_PHASES.map((p) => p.bountyRange.max)),
    totalBountyRange: {
      min: ALL_PHASES.reduce((s, p) => s + p.bountyRange.min, 0),
      max: ALL_PHASES.reduce((s, p) => s + p.bountyRange.max, 0),
    },
  };
}
