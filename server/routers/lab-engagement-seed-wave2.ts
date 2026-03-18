/**
 * Lab Engagement Seed — Wave 2: Expanded LLM Training Data
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Generates significantly more training data across diverse attack scenarios:
 *   - OWASP Top 10 deep dives (SQLi, XSS, SSRF, IDOR, deserialization, etc.)
 *   - API security attacks (broken auth, mass assignment, BOLA, rate limiting)
 *   - Cloud misconfiguration exploitation (S3 buckets, IAM, metadata service)
 *   - Active Directory attack chains (Kerberoasting, AS-REP, DCSync, Golden Ticket)
 *   - Phishing campaign simulations (spear phishing, credential harvesting, pretexting)
 *   - Threat actor emulation (APT29, APT41, FIN7, Lazarus Group techniques)
 *   - Post-exploitation & C2 operations (beaconing, data staging, exfiltration)
 *
 * Target output: 500+ training examples, 1500+ decision logs, 3000+ telemetry records
 */

import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { getDb } from "../db";
import { randomUUID } from "crypto";
import {
  engagements,
  engagementTimelineEvents,
  llmTelemetry,
  llmDecisionLog,
  llmTrainingExamples,
  nexusPipelineExecutions,
  nexusQualityGates,
  nexusShadowConfigs,
  nexusShadowTests,
} from "../../drizzle/schema";
import { sql } from "drizzle-orm";

// ─── Constants ──────────────────────────────────────────────────────────────

const LAB_TARGETS = [
  { name: "DVWA", domain: "scan.aceofcloud.io/lab/dvwa", ip: "159.65.185.0" },
  { name: "bWAPP", domain: "scan.aceofcloud.io/lab/bwapp", ip: "159.65.185.0" },
  { name: "Mutillidae", domain: "scan.aceofcloud.io/lab/mutillidae", ip: "159.65.185.0" },
  { name: "Juice Shop", domain: "scan.aceofcloud.io/lab/juiceshop", ip: "159.65.185.0" },
  { name: "WebGoat", domain: "scan.aceofcloud.io/lab/webgoat", ip: "159.65.185.0" },
];

const AGENT_CALLERS = [
  { prefix: "specialist:osint-analyst", name: "OSINT Analyst", category: "intelligence" },
  { prefix: "specialist:pentester", name: "Pentester", category: "exploitation" },
  { prefix: "specialist:social-engineer", name: "Social Engineer", category: "social_engineering" },
  { prefix: "specialist:red-team-operator", name: "Red Team Operator", category: "red_team" },
  { prefix: "specialist:report-writer", name: "Report Writer", category: "reporting" },
  { prefix: "specialist:scan-analyst", name: "Scan Analyst", category: "reconnaissance" },
  { prefix: "specialist:exploit-selector", name: "Exploit Selector", category: "exploitation" },
  { prefix: "specialist:evasion-optimizer", name: "Evasion Optimizer", category: "evasion" },
  { prefix: "specialist:lateral-planner", name: "Lateral Planner", category: "post_exploitation" },
  { prefix: "specialist:persistence-engineer", name: "Persistence Engineer", category: "persistence" },
];

const ORCHESTRATOR_CALLERS = [
  "engagement-orchestrator.opsDecision",
  "engagement-orchestrator.phaseTransition",
  "operator-cockpit.chat",
  "operator-cockpit.advisorRecommendation",
  "ai-attack-planner",
  "functional-exploit-generator",
  "continuous-training.iteration",
  "training-lab.llmAnalysis",
  "c2-actor-feedback-loop",
  "domain-intel.riskAssessment",
  "domain-intel.assetClassification",
  "campaign-advisor.recommendation",
  "zap-config-generator",
  "vuln-verification.analysis",
  "threat-mapper.correlation",
  "scan-analyst.portAnalysis",
];

const MODELS = ["gemini-2.5-flash", "gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514"];
const PHASES = ["recon", "scanning", "enumeration", "exploitation", "post_exploitation", "reporting", "lateral_movement", "persistence", "exfiltration"];

// ─── Expanded Attack Scenario Libraries ─────────────────────────────────────

const OWASP_SCENARIOS = [
  // A01: Broken Access Control
  { decision: "Test IDOR vulnerability by manipulating user ID parameter in /api/users/{id}", phase: "exploitation", technique: "T1078", category: "owasp_a01" },
  { decision: "Attempt forced browsing to admin panel at /admin/dashboard", phase: "enumeration", technique: "T1190", category: "owasp_a01" },
  { decision: "Bypass CORS restrictions to access cross-origin API endpoints", phase: "exploitation", technique: "T1190", category: "owasp_a01" },
  { decision: "Escalate privileges by modifying JWT role claim from 'user' to 'admin'", phase: "exploitation", technique: "T1078.004", category: "owasp_a01" },
  { decision: "Test path traversal in file download endpoint /api/files?path=../../etc/passwd", phase: "exploitation", technique: "T1083", category: "owasp_a01" },
  // A02: Cryptographic Failures
  { decision: "Analyze TLS configuration for weak cipher suites and protocol versions", phase: "scanning", technique: "T1557", category: "owasp_a02" },
  { decision: "Check for sensitive data exposure in HTTP responses (API keys, tokens)", phase: "enumeration", technique: "T1552.001", category: "owasp_a02" },
  { decision: "Test for insecure direct object references in encrypted cookie values", phase: "exploitation", technique: "T1539", category: "owasp_a02" },
  // A03: Injection
  { decision: "Execute blind SQL injection using time-based technique on search parameter", phase: "exploitation", technique: "T1190", category: "owasp_a03" },
  { decision: "Test for NoSQL injection in MongoDB query via JSON parameter manipulation", phase: "exploitation", technique: "T1190", category: "owasp_a03" },
  { decision: "Attempt OS command injection via ping utility parameter in network tools", phase: "exploitation", technique: "T1059.004", category: "owasp_a03" },
  { decision: "Test LDAP injection in authentication form username field", phase: "exploitation", technique: "T1190", category: "owasp_a03" },
  { decision: "Execute second-order SQL injection via stored profile data", phase: "exploitation", technique: "T1190", category: "owasp_a03" },
  { decision: "Test XPath injection in XML-based search functionality", phase: "exploitation", technique: "T1190", category: "owasp_a03" },
  // A04: Insecure Design
  { decision: "Analyze business logic for rate limiting bypass in password reset flow", phase: "enumeration", technique: "T1110.001", category: "owasp_a04" },
  { decision: "Test for race condition in account balance transfer endpoint", phase: "exploitation", technique: "T1190", category: "owasp_a04" },
  // A05: Security Misconfiguration
  { decision: "Enumerate exposed debug endpoints and stack traces in error responses", phase: "enumeration", technique: "T1592.004", category: "owasp_a05" },
  { decision: "Check for default credentials on discovered admin interfaces", phase: "exploitation", technique: "T1078.001", category: "owasp_a05" },
  { decision: "Test for XML External Entity (XXE) processing in file upload", phase: "exploitation", technique: "T1190", category: "owasp_a05" },
  // A06: Vulnerable Components
  { decision: "Identify outdated jQuery version with known XSS vulnerability CVE-2020-11023", phase: "scanning", technique: "T1190", category: "owasp_a06" },
  { decision: "Exploit known deserialization vulnerability in Apache Commons Collections", phase: "exploitation", technique: "T1190", category: "owasp_a06" },
  // A07: Auth Failures
  { decision: "Brute force login endpoint with credential stuffing attack using leaked database", phase: "exploitation", technique: "T1110.004", category: "owasp_a07" },
  { decision: "Test session fixation by injecting JSESSIONID before authentication", phase: "exploitation", technique: "T1539", category: "owasp_a07" },
  { decision: "Bypass MFA by exploiting backup code generation weakness", phase: "exploitation", technique: "T1111", category: "owasp_a07" },
  // A08: Software Integrity
  { decision: "Test for CI/CD pipeline injection via malicious pull request webhook", phase: "exploitation", technique: "T1195.002", category: "owasp_a08" },
  // A09: Logging Failures
  { decision: "Test for log injection by inserting CRLF sequences in user-agent header", phase: "exploitation", technique: "T1070.001", category: "owasp_a09" },
  // A10: SSRF
  { decision: "Exploit SSRF in URL preview feature to access internal metadata service at 169.254.169.254", phase: "exploitation", technique: "T1090", category: "owasp_a10" },
  { decision: "Chain SSRF with cloud metadata to extract IAM temporary credentials", phase: "exploitation", technique: "T1552.005", category: "owasp_a10" },
  { decision: "Test blind SSRF via DNS rebinding attack against internal services", phase: "exploitation", technique: "T1090", category: "owasp_a10" },
];

const API_ATTACK_SCENARIOS = [
  { decision: "Test Broken Object Level Authorization (BOLA) by accessing other users' resources via API", phase: "exploitation", technique: "T1078", category: "api_security" },
  { decision: "Exploit mass assignment vulnerability by adding 'isAdmin' field to user update request", phase: "exploitation", technique: "T1078.004", category: "api_security" },
  { decision: "Bypass API rate limiting using distributed requests from multiple source IPs", phase: "exploitation", technique: "T1499.002", category: "api_security" },
  { decision: "Enumerate API endpoints via OpenAPI/Swagger specification discovery", phase: "enumeration", technique: "T1592.002", category: "api_security" },
  { decision: "Test GraphQL introspection to discover hidden queries and mutations", phase: "enumeration", technique: "T1592.002", category: "api_security" },
  { decision: "Exploit GraphQL batching to bypass rate limits on authentication endpoint", phase: "exploitation", technique: "T1110.001", category: "api_security" },
  { decision: "Test JWT algorithm confusion attack (RS256 to HS256) for token forgery", phase: "exploitation", technique: "T1550.001", category: "api_security" },
  { decision: "Exploit insecure API key rotation allowing use of revoked keys", phase: "exploitation", technique: "T1552.001", category: "api_security" },
  { decision: "Test for excessive data exposure in API response containing PII fields", phase: "enumeration", technique: "T1530", category: "api_security" },
  { decision: "Exploit broken function level authorization to access admin-only API endpoints", phase: "exploitation", technique: "T1078.004", category: "api_security" },
];

const AD_ATTACK_SCENARIOS = [
  { decision: "Perform Kerberoasting attack to extract service account TGS tickets", phase: "exploitation", technique: "T1558.003", category: "ad_attack" },
  { decision: "Execute AS-REP Roasting against accounts with pre-auth disabled", phase: "exploitation", technique: "T1558.004", category: "ad_attack" },
  { decision: "Perform DCSync attack to replicate domain controller password hashes", phase: "post_exploitation", technique: "T1003.006", category: "ad_attack" },
  { decision: "Create Golden Ticket using extracted KRBTGT hash for persistent domain access", phase: "persistence", technique: "T1558.001", category: "ad_attack" },
  { decision: "Execute Pass-the-Hash attack using extracted NTLM hashes", phase: "lateral_movement", technique: "T1550.002", category: "ad_attack" },
  { decision: "Enumerate AD trust relationships for cross-domain attack path", phase: "enumeration", technique: "T1482", category: "ad_attack" },
  { decision: "Exploit unconstrained delegation to impersonate privileged accounts", phase: "exploitation", technique: "T1558", category: "ad_attack" },
  { decision: "Perform LLMNR/NBT-NS poisoning to capture NTLMv2 hashes on network", phase: "exploitation", technique: "T1557.001", category: "ad_attack" },
  { decision: "Exploit Group Policy Preferences (GPP) for cached credential extraction", phase: "post_exploitation", technique: "T1552.006", category: "ad_attack" },
  { decision: "Create Silver Ticket for targeted service impersonation", phase: "persistence", technique: "T1558.002", category: "ad_attack" },
  { decision: "Enumerate BloodHound attack paths from compromised user to Domain Admin", phase: "enumeration", technique: "T1087.002", category: "ad_attack" },
  { decision: "Exploit PrintNightmare (CVE-2021-34527) for remote code execution on DC", phase: "exploitation", technique: "T1210", category: "ad_attack" },
];

const CLOUD_ATTACK_SCENARIOS = [
  { decision: "Enumerate publicly accessible S3 buckets for sensitive data exposure", phase: "recon", technique: "T1530", category: "cloud_attack" },
  { decision: "Exploit overly permissive IAM role to escalate from EC2 to admin access", phase: "exploitation", technique: "T1078.004", category: "cloud_attack" },
  { decision: "Access EC2 instance metadata service to extract temporary IAM credentials", phase: "exploitation", technique: "T1552.005", category: "cloud_attack" },
  { decision: "Exploit Lambda function environment variables for hardcoded secrets", phase: "post_exploitation", technique: "T1552.001", category: "cloud_attack" },
  { decision: "Enumerate Azure AD for misconfigured application registrations", phase: "enumeration", technique: "T1087.004", category: "cloud_attack" },
  { decision: "Exploit GCP service account key file for lateral movement between projects", phase: "lateral_movement", technique: "T1078.004", category: "cloud_attack" },
  { decision: "Test for container escape via privileged Docker socket mount", phase: "exploitation", technique: "T1611", category: "cloud_attack" },
  { decision: "Exploit Kubernetes RBAC misconfiguration for cluster-admin escalation", phase: "exploitation", technique: "T1078.004", category: "cloud_attack" },
  { decision: "Enumerate exposed cloud storage blobs via Azure Blob Storage anonymous access", phase: "recon", technique: "T1530", category: "cloud_attack" },
  { decision: "Exploit AWS STS AssumeRole for cross-account access via trust policy", phase: "lateral_movement", technique: "T1078.004", category: "cloud_attack" },
];

const PHISHING_SCENARIOS = [
  { decision: "Craft spear phishing email targeting CFO with invoice-themed lure", phase: "recon", technique: "T1566.001", category: "phishing" },
  { decision: "Deploy credential harvesting page mimicking corporate SSO portal", phase: "exploitation", technique: "T1056.003", category: "phishing" },
  { decision: "Create pretexting scenario as IT helpdesk for password reset social engineering", phase: "exploitation", technique: "T1598.003", category: "phishing" },
  { decision: "Generate macro-enabled document payload with sandbox evasion techniques", phase: "exploitation", technique: "T1204.002", category: "phishing" },
  { decision: "Set up typosquatting domain for watering hole attack campaign", phase: "recon", technique: "T1583.001", category: "phishing" },
  { decision: "Deploy browser-in-the-browser (BitB) attack for OAuth token theft", phase: "exploitation", technique: "T1557", category: "phishing" },
  { decision: "Create QR code phishing campaign targeting mobile device users", phase: "exploitation", technique: "T1566.001", category: "phishing" },
  { decision: "Analyze email gateway SPF/DKIM/DMARC for spoofing viability", phase: "recon", technique: "T1589.002", category: "phishing" },
];

const THREAT_ACTOR_SCENARIOS = [
  { decision: "Emulate APT29 (Cozy Bear) supply chain attack via SolarWinds-style compromise", phase: "exploitation", technique: "T1195.002", category: "threat_actor", actor: "APT29" },
  { decision: "Simulate APT29 WellMess malware C2 communication patterns", phase: "persistence", technique: "T1071.001", category: "threat_actor", actor: "APT29" },
  { decision: "Emulate APT41 dual espionage/financial crime operations targeting healthcare", phase: "exploitation", technique: "T1190", category: "threat_actor", actor: "APT41" },
  { decision: "Simulate FIN7 Carbanak-style POS malware deployment chain", phase: "exploitation", technique: "T1059.001", category: "threat_actor", actor: "FIN7" },
  { decision: "Emulate Lazarus Group cryptocurrency exchange targeting via watering hole", phase: "exploitation", technique: "T1189", category: "threat_actor", actor: "Lazarus" },
  { decision: "Simulate Sandworm destructive wiper malware deployment (NotPetya-style)", phase: "exploitation", technique: "T1485", category: "threat_actor", actor: "Sandworm" },
  { decision: "Emulate APT28 (Fancy Bear) credential harvesting via OAuth phishing", phase: "exploitation", technique: "T1528", category: "threat_actor", actor: "APT28" },
  { decision: "Simulate Turla Group satellite-based C2 infrastructure setup", phase: "persistence", technique: "T1102", category: "threat_actor", actor: "Turla" },
  { decision: "Emulate HAFNIUM Exchange Server exploitation chain (ProxyLogon)", phase: "exploitation", technique: "T1190", category: "threat_actor", actor: "HAFNIUM" },
  { decision: "Simulate Volt Typhoon living-off-the-land techniques targeting critical infrastructure", phase: "post_exploitation", technique: "T1218", category: "threat_actor", actor: "Volt Typhoon" },
];

const C2_POST_EXPLOIT_SCENARIOS = [
  { decision: "Configure Cobalt Strike beacon with jitter and sleep for low-and-slow C2", phase: "persistence", technique: "T1071.001", category: "c2_ops" },
  { decision: "Stage exfiltration data in temporary directory with AES-256 encryption", phase: "exfiltration", technique: "T1074.001", category: "c2_ops" },
  { decision: "Establish DNS-over-HTTPS covert channel for data exfiltration", phase: "exfiltration", technique: "T1048.003", category: "c2_ops" },
  { decision: "Deploy process hollowing technique to inject payload into svchost.exe", phase: "exploitation", technique: "T1055.012", category: "c2_ops" },
  { decision: "Create scheduled task persistence with obfuscated PowerShell payload", phase: "persistence", technique: "T1053.005", category: "c2_ops" },
  { decision: "Establish reverse SSH tunnel through compromised DMZ host for pivoting", phase: "lateral_movement", technique: "T1572", category: "c2_ops" },
  { decision: "Deploy keylogger via DLL side-loading on target workstation", phase: "post_exploitation", technique: "T1574.002", category: "c2_ops" },
  { decision: "Configure domain fronting for C2 traffic to evade network monitoring", phase: "persistence", technique: "T1090.004", category: "c2_ops" },
  { decision: "Extract browser saved passwords and session cookies from compromised host", phase: "post_exploitation", technique: "T1555.003", category: "c2_ops" },
  { decision: "Perform token impersonation to elevate from local admin to SYSTEM", phase: "post_exploitation", technique: "T1134.001", category: "c2_ops" },
];

// Combine all scenarios
const ALL_EXPANDED_DECISIONS = [
  ...OWASP_SCENARIOS,
  ...API_ATTACK_SCENARIOS,
  ...AD_ATTACK_SCENARIOS,
  ...CLOUD_ATTACK_SCENARIOS,
  ...PHISHING_SCENARIOS,
  ...THREAT_ACTOR_SCENARIOS,
  ...C2_POST_EXPLOIT_SCENARIOS,
];

// Expanded timeline events
const EXPANDED_TIMELINE_EVENTS = [
  { eventType: "phase_started" as const, severity: "info" as const, title: "OWASP Top 10 assessment phase initiated" },
  { eventType: "scan_completed" as const, severity: "info" as const, title: "API endpoint enumeration completed — 47 endpoints discovered" },
  { eventType: "finding_discovered" as const, severity: "critical" as const, title: "Blind SQL injection confirmed in search parameter" },
  { eventType: "finding_discovered" as const, severity: "critical" as const, title: "Remote Code Execution via Java deserialization" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "SSRF vulnerability allows internal network scanning" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "Broken Object Level Authorization in REST API" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "JWT algorithm confusion allows token forgery" },
  { eventType: "finding_discovered" as const, severity: "medium" as const, title: "Stored XSS in user profile bio field" },
  { eventType: "finding_discovered" as const, severity: "medium" as const, title: "CORS misconfiguration allows credential theft" },
  { eventType: "finding_discovered" as const, severity: "low" as const, title: "Information disclosure via verbose error messages" },
  { eventType: "exploit_attempted" as const, severity: "high" as const, title: "Attempting Kerberoasting against service accounts" },
  { eventType: "exploit_succeeded" as const, severity: "critical" as const, title: "DCSync attack successful — extracted KRBTGT hash" },
  { eventType: "exploit_succeeded" as const, severity: "critical" as const, title: "Golden Ticket created for persistent domain access" },
  { eventType: "credential_found" as const, severity: "critical" as const, title: "AWS IAM temporary credentials extracted from metadata service" },
  { eventType: "credential_found" as const, severity: "high" as const, title: "Service account password cracked: svc_backup:P@ssw0rd123" },
  { eventType: "shell_obtained" as const, severity: "critical" as const, title: "Reverse shell via deserialization exploit on port 9001" },
  { eventType: "pivot_established" as const, severity: "high" as const, title: "Lateral movement to Domain Controller via Pass-the-Hash" },
  { eventType: "data_exfiltrated" as const, severity: "critical" as const, title: "Exfiltrated 15MB of AD credentials via DNS-over-HTTPS tunnel" },
  { eventType: "opsec_alert" as const, severity: "high" as const, title: "EDR alert triggered — switching to fileless techniques" },
  { eventType: "opsec_alert" as const, severity: "medium" as const, title: "Anomalous login detected — adjusting attack timing" },
  { eventType: "tool_executed" as const, severity: "info" as const, title: "BloodHound collection completed — 15,432 objects mapped" },
  { eventType: "tool_executed" as const, severity: "info" as const, title: "Responder LLMNR/NBT-NS poisoning active on subnet" },
  { eventType: "phase_completed" as const, severity: "info" as const, title: "Active Directory attack chain completed — Domain Admin achieved" },
  { eventType: "objective_completed" as const, severity: "info" as const, title: "All OWASP Top 10 categories tested with 23 findings" },
  { eventType: "finding_discovered" as const, severity: "critical" as const, title: "Container escape via privileged Docker socket" },
  { eventType: "finding_discovered" as const, severity: "high" as const, title: "GraphQL introspection enabled — full schema exposed" },
  { eventType: "exploit_attempted" as const, severity: "medium" as const, title: "Testing race condition in payment processing endpoint" },
  { eventType: "exploit_succeeded" as const, severity: "high" as const, title: "Mass assignment exploit grants admin role via API" },
];

// Expanded training example templates per specialist
const TRAINING_TEMPLATES: Record<string, Array<{ system: string; userTemplate: string; assistantTemplate: string }>> = {
  "osint-analyst-v2": [
    {
      system: "You are an OSINT analyst specialist. Analyze targets using open-source intelligence techniques to map attack surfaces, identify personnel, and discover exposed assets.",
      userTemplate: "Perform OSINT reconnaissance on {target}. Identify exposed services, employee information, and potential attack vectors.",
      assistantTemplate: "OSINT analysis of {target} reveals: {finding}. Recommended approach: {approach}. Risk level: {risk}. MITRE ATT&CK: {technique}.",
    },
    {
      system: "You are an OSINT analyst specialist focused on threat actor attribution and tracking.",
      userTemplate: "Analyze indicators of compromise from {target} and attribute to known threat actors.",
      assistantTemplate: "IOC analysis suggests {actor} involvement based on: {evidence}. Confidence: {confidence}%. TTPs match {technique} pattern. Recommended countermeasures: {countermeasures}.",
    },
  ],
  "pentester-v2": [
    {
      system: "You are a penetration testing specialist. Identify and exploit vulnerabilities in web applications following OWASP methodology.",
      userTemplate: "Test {target} for {category} vulnerabilities. Provide exploitation steps and proof of concept.",
      assistantTemplate: "Vulnerability confirmed: {finding} on {target}. Exploitation: {exploit_steps}. Impact: {impact}. CVSS: {cvss}. Remediation: {remediation}.",
    },
    {
      system: "You are a penetration testing specialist focused on API security assessment.",
      userTemplate: "Assess the API security of {target}. Test for BOLA, mass assignment, and authentication bypass.",
      assistantTemplate: "API assessment of {target}: {finding}. Attack vector: {vector}. Data exposure risk: {risk}. Proof of concept: {poc}. Fix: {fix}.",
    },
  ],
  "red-team-operator-v2": [
    {
      system: "You are a red team operator specialist. Plan and execute adversary emulation campaigns using real-world threat actor TTPs.",
      userTemplate: "Emulate {actor} TTPs against {target}. Plan the attack chain from initial access to objective completion.",
      assistantTemplate: "Attack plan for {actor} emulation: Phase 1: {phase1}. Phase 2: {phase2}. Phase 3: {phase3}. C2 infrastructure: {c2}. Evasion: {evasion}. Expected detection: {detection}.",
    },
    {
      system: "You are a red team operator specialist focused on Active Directory attack chains.",
      userTemplate: "Plan AD attack chain from initial foothold on {target} to Domain Admin. Include Kerberos attacks and lateral movement.",
      assistantTemplate: "AD attack chain: 1) {step1} 2) {step2} 3) {step3}. Kerberos attack: {kerberos}. Lateral movement via: {lateral}. Persistence: {persistence}. OPSEC considerations: {opsec}.",
    },
  ],
  "exploit-selector-v2": [
    {
      system: "You are an exploit selection specialist. Choose optimal exploits based on target environment, stealth requirements, and success probability.",
      userTemplate: "Select best exploit for {vuln} on {target}. Consider stealth score requirement of {stealth_req} and available tools.",
      assistantTemplate: "Recommended exploit: {exploit}. Success probability: {prob}%. Stealth score: {stealth}. Alternative: {alt_exploit}. Payload: {payload}. Post-exploitation: {post_exploit}.",
    },
  ],
  "evasion-optimizer-v2": [
    {
      system: "You are an evasion optimization specialist. Configure attack tools and payloads to bypass security controls including EDR, WAF, and IDS/IPS.",
      userTemplate: "Optimize evasion for {attack} against {target} with {security_control} in place. Minimize detection probability.",
      assistantTemplate: "Evasion strategy: {strategy}. Technique: {technique}. Payload modification: {modification}. Expected detection rate: {detection_rate}%. Fallback: {fallback}.",
    },
  ],
  "lateral-planner-v2": [
    {
      system: "You are a lateral movement planning specialist. Map network topology and plan optimal paths between compromised hosts.",
      userTemplate: "Plan lateral movement from {source} to {destination} in {network}. Available credentials: {creds}. Avoid {constraints}.",
      assistantTemplate: "Lateral movement plan: Path: {path}. Method: {method}. Credential usage: {cred_usage}. OPSEC: {opsec}. Time estimate: {time}. Risk: {risk}.",
    },
  ],
  "persistence-engineer-v2": [
    {
      system: "You are a persistence engineering specialist. Design and deploy persistent access mechanisms that survive reboots and security sweeps.",
      userTemplate: "Establish persistence on {target} ({os}). Requirements: survive reboot, evade {av}, maintain {access_level} access.",
      assistantTemplate: "Persistence mechanism: {mechanism}. Installation: {install}. Trigger: {trigger}. Evasion: {evasion}. Cleanup: {cleanup}. Backup persistence: {backup}.",
    },
  ],
  "social-engineer-v2": [
    {
      system: "You are a social engineering specialist. Design and execute social engineering campaigns including phishing, pretexting, and vishing.",
      userTemplate: "Design phishing campaign targeting {target_org}. Goal: {goal}. Constraints: {constraints}.",
      assistantTemplate: "Campaign design: Pretext: {pretext}. Lure: {lure}. Landing page: {landing}. Payload: {payload}. Success metrics: {metrics}. OPSEC: {opsec}.",
    },
  ],
  "scan-analyst-v2": [
    {
      system: "You are a scan analysis specialist. Analyze vulnerability scan results, prioritize findings, and filter false positives.",
      userTemplate: "Analyze scan results for {target}. {scan_count} findings detected. Prioritize by exploitability and business impact.",
      assistantTemplate: "Analysis: {critical} critical, {high} high, {medium} medium, {low} low findings. False positives: {fp}. Priority targets: {priorities}. Recommended attack sequence: {sequence}.",
    },
  ],
  "report-writer-v2": [
    {
      system: "You are a report writing specialist. Generate professional penetration test and red team reports with executive summaries, technical details, and remediation guidance.",
      userTemplate: "Generate report section for {finding_type} findings on {target}. Include CVSS scoring, evidence, and remediation timeline.",
      assistantTemplate: "## {finding_title}\n**CVSS:** {cvss} | **Severity:** {severity}\n\n**Description:** {description}\n\n**Evidence:** {evidence}\n\n**Impact:** {impact}\n\n**Remediation:** {remediation}\n**Timeline:** {timeline}",
    },
  ],
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function rand(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randFloat(min: number, max: number, decimals = 2): number {
  return Number((Math.random() * (max - min) + min).toFixed(decimals));
}
function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
function pickN<T>(arr: T[], n: number): T[] {
  const shuffled = [...arr].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}
function daysAgo(days: number): string {
  const d = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 19).replace("T", " ");
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const labEngagementSeedWave2Router = router({
  /**
   * Wave 2: Expanded LLM training data with diverse attack scenarios.
   * Adds ~10 new engagements, 500+ training examples, 1500+ decisions, 3000+ telemetry.
   */
  seedWave2: protectedProcedure.mutation(async () => {
    const db = await getDb();
    const results: Record<string, number> = {};

    // ─── 1. Create 10 New Scenario-Based Engagements ─────────────────────
    const ENGAGEMENT_SCENARIOS = [
      { name: "OWASP Top 10 Assessment: DVWA", target: LAB_TARGETS[0], type: "pentest" as const, focus: "owasp" },
      { name: "API Security Audit: Juice Shop", target: LAB_TARGETS[3], type: "pentest" as const, focus: "api_security" },
      { name: "AD Attack Chain: WebGoat Network", target: LAB_TARGETS[4], type: "red_team" as const, focus: "ad_attack" },
      { name: "Cloud Misconfiguration Hunt: bWAPP", target: LAB_TARGETS[1], type: "pentest" as const, focus: "cloud_attack" },
      { name: "Phishing Campaign Simulation: Mutillidae", target: LAB_TARGETS[2], type: "red_team" as const, focus: "phishing" },
      { name: "APT29 Emulation: Full Kill Chain", target: LAB_TARGETS[0], type: "red_team" as const, focus: "threat_actor" },
      { name: "C2 Infrastructure Validation: Juice Shop", target: LAB_TARGETS[3], type: "red_team" as const, focus: "c2_ops" },
      { name: "Purple Team Exercise: DVWA + bWAPP", target: LAB_TARGETS[0], type: "red_team" as const, focus: "owasp" },
      { name: "Assumed Breach: Internal Pivot from WebGoat", target: LAB_TARGETS[4], type: "red_team" as const, focus: "ad_attack" },
      { name: "Full Scope Red Team: All Lab Targets", target: LAB_TARGETS[0], type: "red_team" as const, focus: "threat_actor" },
    ];

    const engagementIds: number[] = [];
    for (let i = 0; i < ENGAGEMENT_SCENARIOS.length; i++) {
      const scenario = ENGAGEMENT_SCENARIOS[i];
      const startDaysAgo = rand(1, 30);
      const statuses = ["active", "active", "active", "completed", "completed", "completed", "completed", "planning", "paused", "active"] as const;

      const result = await db.insert(engagements).values({
        name: scenario.name,
        customerName: "AC3 Internal Lab",
        description: `Wave 2 expanded scenario: ${scenario.name}. Focus area: ${scenario.focus}. Testing advanced LLM-driven attack planning and execution across ${scenario.focus.replace(/_/g, ' ')} scenarios.`,
        engagementType: scenario.type,
        status: statuses[i],
        startDate: daysAgo(startDaysAgo),
        targetDomain: scenario.target.domain,
        targetIpRange: scenario.target.ip,
        notes: `Wave 2 seed — ${scenario.focus} focus. Auto-generated for expanded LLM training.`,
        createdBy: 1,
        roeStatus: "signed" as const,
        roeSignedDate: daysAgo(startDaysAgo + 1),
        roeExpiryDate: daysAgo(-60),
        scanMode: "active" as const,
      });
      const engId = Number((result as any)[0]?.insertId || (result as any).insertId);
      engagementIds.push(engId);
    }
    results.engagements = engagementIds.length;

    // ─── 2. Create Rich Timeline Events ──────────────────────────────────
    let timelineCount = 0;
    for (const engId of engagementIds) {
      const events = pickN(EXPANDED_TIMELINE_EVENTS, rand(12, 28));
      for (let j = 0; j < events.length; j++) {
        const evt = events[j];
        const phase = PHASES[Math.min(j % PHASES.length, PHASES.length - 1)];
        await db.insert(engagementTimelineEvents).values({
          engagementId: engId,
          phase,
          eventType: evt.eventType,
          severity: evt.severity,
          title: evt.title,
          description: `Wave 2 event for engagement #${engId}: ${evt.title}`,
          metadata: { seeded: true, wave: 2, labTarget: LAB_TARGETS[engagementIds.indexOf(engId) % LAB_TARGETS.length]?.name },
          sourceModule: pick(AGENT_CALLERS).prefix,
          targetHost: pick(LAB_TARGETS).ip,
          targetPort: pick([80, 443, 3306, 8080, 22, 8443, 8888, 9001, 5432, 27017, 6379, 88, 389, 636, 445]),
          attackTechnique: pick(ALL_EXPANDED_DECISIONS).technique,
          operatorId: 1,
          timestamp: Date.now() - rand(0, 30 * 24 * 60 * 60 * 1000),
        });
        timelineCount++;
      }
    }
    results.timelineEvents = timelineCount;

    // ─── 3. Expanded LLM Telemetry (60 days, higher volume) ──────────────
    let telemetryCount = 0;
    const allCallers = [...AGENT_CALLERS.map(a => a.prefix), ...ORCHESTRATOR_CALLERS];

    for (let day = 0; day < 60; day++) {
      const callsPerDay = rand(40, 80); // Higher volume than wave 1
      for (let c = 0; c < callsPerDay; c++) {
        const caller = pick(allCallers);
        const model = pick(MODELS);
        const isError = Math.random() < 0.05;
        const isTimeout = !isError && Math.random() < 0.015;
        const isRetry = !isError && !isTimeout && Math.random() < 0.07;
        const status = isError ? "error" as const
          : isTimeout ? "timeout" as const
          : isRetry ? "retried_success" as const
          : "success" as const;

        const latency = isTimeout ? rand(25000, 30000)
          : isError ? rand(100, 2000)
          : rand(150, 12000);

        const engId = pick(engagementIds);
        const calledAtTs = new Date(Date.now() - day * 24 * 60 * 60 * 1000 - rand(0, 86400000))
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(llmTelemetry).values({
          calledAt: calledAtTs,
          caller,
          model,
          llmStatus: status,
          httpStatus: isError ? pick([429, 500, 502, 503]) : 200,
          latencyMs: latency,
          retryCount: isRetry ? rand(1, 3) : 0,
          tokensIn: rand(300, 6000),
          tokensOut: rand(150, 3000),
          hasResponseFormat: Math.random() > 0.4 ? 1 : 0,
          errorMessage: isError ? pick([
            "Rate limit exceeded",
            "Internal server error",
            "Model overloaded",
            "Context length exceeded",
            "Invalid response format",
            "Connection timeout to upstream",
            "Token budget exceeded for caller",
          ]) : null,
          engagementId: engId,
          createdAt: calledAtTs,
        });
        telemetryCount++;
      }
    }
    results.llmTelemetry = telemetryCount;

    // ─── 4. Expanded Decision Log (all scenario categories) ──────────────
    let decisionCount = 0;
    for (let day = 0; day < 60; day++) {
      const decisionsPerDay = rand(15, 35); // Much higher volume
      for (let d = 0; d < decisionsPerDay; d++) {
        const dec = pick(ALL_EXPANDED_DECISIONS);
        const agent = pick(AGENT_CALLERS);
        const engId = pick(engagementIds);
        const outcomes = ["success", "success", "success", "success", "partial", "partial", "failure", "pending"] as const;
        const outcome = pick(outcomes);
        const stealthScore = randFloat(0.2, 0.99);
        const latency = rand(300, 15000);
        const tokens = rand(400, 8000);

        const createdAtTs = new Date(Date.now() - day * 24 * 60 * 60 * 1000 - rand(0, 86400000))
          .toISOString().slice(0, 19).replace("T", " ");

        // Richer reasoning based on category
        const categoryReasons: Record<string, string> = {
          owasp_a01: `Access control testing: ${agent.name} identified broken authorization. Stealth: ${Math.round(stealthScore * 100)}%. OWASP A01 coverage.`,
          owasp_a02: `Cryptographic analysis: ${agent.name} detected weak encryption. Risk: ${outcome === 'success' ? 'confirmed' : 'needs verification'}.`,
          owasp_a03: `Injection testing: ${agent.name} crafted payload for ${dec.decision.includes('SQL') ? 'SQL' : dec.decision.includes('NoSQL') ? 'NoSQL' : 'command'} injection. Stealth: ${Math.round(stealthScore * 100)}%.`,
          owasp_a04: `Design flaw analysis: ${agent.name} identified insecure design pattern. Business logic vulnerability confirmed.`,
          owasp_a05: `Misconfiguration check: ${agent.name} found security misconfiguration. Default credentials or debug endpoints exposed.`,
          owasp_a06: `Component analysis: ${agent.name} identified vulnerable dependency. CVE match confirmed with known exploit.`,
          owasp_a07: `Authentication testing: ${agent.name} tested auth mechanisms. ${outcome === 'success' ? 'Bypass achieved' : 'Controls held'}.`,
          owasp_a08: `Integrity check: ${agent.name} tested software supply chain integrity. CI/CD pipeline security assessed.`,
          owasp_a09: `Logging analysis: ${agent.name} tested logging and monitoring. ${outcome === 'success' ? 'Log injection successful' : 'Logs properly sanitized'}.`,
          owasp_a10: `SSRF testing: ${agent.name} tested server-side request forgery. ${outcome === 'success' ? 'Internal service accessed' : 'SSRF blocked by WAF'}.`,
          api_security: `API security assessment: ${agent.name} tested API endpoint. ${outcome === 'success' ? 'Authorization bypass confirmed' : 'API controls effective'}. Stealth: ${Math.round(stealthScore * 100)}%.`,
          ad_attack: `AD attack chain: ${agent.name} executed Active Directory attack. ${outcome === 'success' ? 'Privilege escalation achieved' : 'Attack detected by EDR'}. Kerberos ticket manipulation: ${stealthScore > 0.7 ? 'undetected' : 'flagged'}.`,
          cloud_attack: `Cloud exploitation: ${agent.name} targeted cloud infrastructure. ${outcome === 'success' ? 'Cloud credentials obtained' : 'IAM policy blocked access'}. Metadata service: ${stealthScore > 0.6 ? 'accessible' : 'restricted'}.`,
          phishing: `Social engineering: ${agent.name} executed phishing campaign. ${outcome === 'success' ? 'Credentials harvested' : 'Target suspicious'}. Click rate: ${rand(5, 45)}%. Stealth: ${Math.round(stealthScore * 100)}%.`,
          threat_actor: `Threat actor emulation: ${agent.name} simulated ${(dec as any).actor || 'APT'} TTPs. ${outcome === 'success' ? 'Kill chain completed' : 'Detected at stage ' + rand(1, 5)}. Fidelity: ${Math.round(stealthScore * 100)}%.`,
          c2_ops: `C2 operations: ${agent.name} managed command and control. ${outcome === 'success' ? 'Beacon established' : 'C2 channel blocked'}. Jitter: ${rand(10, 60)}%. Sleep: ${rand(30, 300)}s.`,
        };

        const reasoning = categoryReasons[(dec as any).category] ||
          `${agent.name} analyzed target and determined action has ${Math.round(stealthScore * 100)}% stealth rating. Outcome: ${outcome}.`;

        await db.insert(llmDecisionLog).values({
          engagementId: engId,
          phase: dec.phase,
          caller: agent.prefix,
          decision: dec.decision,
          reasoning,
          actions: JSON.stringify([
            { tool: pick(["nmap", "gobuster", "sqlmap", "nikto", "zap", "metasploit", "hydra", "burpsuite", "bloodhound", "mimikatz", "responder", "impacket", "crackmapexec", "rubeus", "certify", "sharphound"]), args: dec.decision },
            { tool: "opsec-check", args: `stealth_score=${stealthScore}` },
          ]),
          outcome,
          outcomeDetail: outcome === "success"
            ? `Action completed successfully. ${(dec as any).category === 'ad_attack' ? 'AD credentials captured.' : (dec as any).category === 'cloud_attack' ? 'Cloud access obtained.' : 'No detection triggered.'}`
            : outcome === "failure"
            ? `Action blocked. ${pick(['WAF rule triggered', 'EDR quarantined payload', 'IDS alert generated', 'Rate limit hit', 'Authentication required', 'Network segmentation blocked'])}.`
            : outcome === "partial"
            ? `Partial success — ${pick(['some data retrieved but connection dropped', 'initial access gained but lateral movement blocked', 'credentials obtained but expired', 'exploit worked but payload failed'])}.`
            : "Awaiting execution in queue",
          stealthScore,
          latencyMs: latency,
          tokensUsed: tokens,
          contextSummary: `Wave 2 | Eng #${engId} | ${dec.phase} | ${(dec as any).category} | ${agent.name} | ${pick(LAB_TARGETS).name}`,
          createdAt: createdAtTs,
        });
        decisionCount++;
      }
    }
    results.llmDecisionLog = decisionCount;

    // ─── 5. Expanded Training Examples (all specialist models) ───────────
    let trainingCount = 0;
    const modelNames = Object.keys(TRAINING_TEMPLATES);

    for (const modelName of modelNames) {
      const templates = TRAINING_TEMPLATES[modelName];
      const examplesPerModel = rand(40, 70); // Much more per model

      for (let e = 0; e < examplesPerModel; e++) {
        const template = pick(templates);
        const source = pick(["lab_scenario", "lab_scenario", "live_engagement", "live_engagement", "synthetic", "manual"] as const);
        const quality = pick(["high", "high", "high", "medium", "medium", "low", "rejected"] as const);
        const qualityScore = quality === "high" ? randFloat(0.82, 0.99)
          : quality === "medium" ? randFloat(0.55, 0.81)
          : quality === "low" ? randFloat(0.25, 0.54)
          : randFloat(0.0, 0.24);

        const dec = pick(ALL_EXPANDED_DECISIONS);
        const target = pick(LAB_TARGETS);
        const actor = pick(["APT29", "APT41", "FIN7", "Lazarus", "Sandworm", "APT28", "Turla", "HAFNIUM", "Volt Typhoon"]);

        // Fill in template variables
        const filledUser = template.userTemplate
          .replace("{target}", target.name)
          .replace("{category}", (dec as any).category || "general")
          .replace("{target_org}", "AC3 Lab Corp")
          .replace("{goal}", "credential harvesting")
          .replace("{constraints}", "avoid email gateway detection")
          .replace("{vuln}", dec.decision.slice(0, 50))
          .replace("{stealth_req}", String(randFloat(0.6, 0.95)))
          .replace("{attack}", dec.decision.slice(0, 40))
          .replace("{security_control}", pick(["CrowdStrike EDR", "Palo Alto NGFW", "Cloudflare WAF", "Microsoft Defender"]))
          .replace("{source}", "compromised-workstation")
          .replace("{destination}", "domain-controller")
          .replace("{network}", "10.0.0.0/16")
          .replace("{creds}", "NTLM hash: aad3b435...")
          .replace("{os}", pick(["Windows Server 2022", "Ubuntu 22.04", "Windows 11"]))
          .replace("{av}", pick(["Windows Defender", "CrowdStrike", "SentinelOne"]))
          .replace("{access_level}", pick(["SYSTEM", "root", "domain admin"]))
          .replace("{actor}", actor)
          .replace("{scan_count}", String(rand(50, 500)))
          .replace("{finding_type}", pick(["critical", "high", "OWASP", "infrastructure"]));

        const filledAssistant = template.assistantTemplate
          .replace("{target}", target.name)
          .replace("{finding}", dec.decision)
          .replace("{approach}", `Execute ${dec.decision} with stealth score ${randFloat(0.5, 0.95)}`)
          .replace("{risk}", pick(["Critical", "High", "Medium"]))
          .replace("{technique}", dec.technique)
          .replace("{actor}", actor)
          .replace("{evidence}", `TTP overlap: ${dec.technique}, infrastructure pattern match, timing correlation`)
          .replace("{confidence}", String(rand(60, 95)))
          .replace("{countermeasures}", "Block IOCs, patch vulnerable systems, enhance monitoring")
          .replace("{exploit_steps}", `1. Identify entry point 2. Craft payload 3. Execute 4. Verify access`)
          .replace("{impact}", pick(["Full system compromise", "Data breach", "Lateral movement enabled", "Credential theft"]))
          .replace("{cvss}", `${randFloat(5.0, 10.0)}`)
          .replace("{remediation}", "Apply security patches, implement input validation, enforce least privilege")
          .replace("{vector}", dec.decision.slice(0, 60))
          .replace("{poc}", `curl -X POST ${target.domain}/api/vuln -d '{"payload":"test"}'`)
          .replace("{fix}", "Implement proper authorization checks and input validation")
          .replace("{phase1}", "Initial access via phishing")
          .replace("{phase2}", "Privilege escalation and lateral movement")
          .replace("{phase3}", "Data exfiltration and persistence")
          .replace("{c2}", pick(["Cobalt Strike", "Sliver", "Mythic", "Havoc"]))
          .replace("{evasion}", "Domain fronting + process hollowing")
          .replace("{detection}", `${rand(10, 70)}% probability`)
          .replace("{exploit}", dec.decision.slice(0, 50))
          .replace("{prob}", String(rand(60, 95)))
          .replace("{stealth}", String(randFloat(0.5, 0.95)))
          .replace("{alt_exploit}", "Manual exploitation via Burp Suite")
          .replace("{payload}", pick(["reverse_shell", "meterpreter", "beacon", "web_shell"]))
          .replace("{post_exploit}", "Credential dump + persistence")
          .replace("{strategy}", "Multi-layer evasion with encoding + timing")
          .replace("{modification}", "Custom XOR encoding + sleep timer")
          .replace("{detection_rate}", String(rand(2, 25)))
          .replace("{fallback}", "Switch to fileless technique")
          .replace("{path}", "WS01 → DC01 via SMB")
          .replace("{method}", pick(["Pass-the-Hash", "WMI", "PSRemoting", "RDP"]))
          .replace("{cred_usage}", "NTLM hash relay")
          .replace("{opsec}", "Avoid golden ticket — use silver ticket for targeted access")
          .replace("{time}", `${rand(5, 120)} minutes`)
          .replace("{mechanism}", pick(["Scheduled task", "Registry run key", "WMI subscription", "DLL hijack"]))
          .replace("{install}", "Automated via PowerShell one-liner")
          .replace("{trigger}", pick(["System boot", "User logon", "Timer (30min)", "Network event"]))
          .replace("{cleanup}", "Self-deleting script after execution")
          .replace("{backup}", "Secondary persistence via registry")
          .replace("{pretext}", "IT department security audit notification")
          .replace("{lure}", "Urgent password reset required")
          .replace("{landing}", "Cloned SSO portal with credential capture")
          .replace("{metrics}", `Expected ${rand(10, 40)}% click rate`)
          .replace("{critical}", String(rand(2, 8)))
          .replace("{high}", String(rand(5, 15)))
          .replace("{medium}", String(rand(10, 30)))
          .replace("{low}", String(rand(15, 50)))
          .replace("{fp}", `${rand(5, 20)}%`)
          .replace("{priorities}", "Focus on RCE and auth bypass first")
          .replace("{sequence}", "SQLi → RCE → Privesc → Lateral")
          .replace("{step1}", "Kerberoasting service accounts")
          .replace("{step2}", "Pass-the-Hash to file server")
          .replace("{step3}", "DCSync for KRBTGT hash")
          .replace("{kerberos}", "AS-REP roasting + Kerberoasting")
          .replace("{lateral}", "SMB + WMI + PSRemoting")
          .replace("{persistence}", "Golden Ticket + scheduled task")
          .replace("{finding_title}", dec.decision.slice(0, 60))
          .replace("{severity}", pick(["Critical", "High", "Medium"]))
          .replace("{description}", dec.decision)
          .replace("{timeline}", pick(["Immediate", "30 days", "90 days", "Next patch cycle"]));

        const createdAtTs = new Date(Date.now() - rand(0, 60) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(llmTrainingExamples).values({
          exampleId: `te2-${randomUUID().slice(0, 8)}`,
          model: modelName,
          source: source as any,
          sourceId: source === "lab_scenario" ? `lab-${target.name.toLowerCase().replace(/\s+/g, '-')}-w2-${rand(1, 500)}`
            : source === "live_engagement" ? `eng-${pick(engagementIds)}`
            : `${source}-w2-${rand(1, 1000)}`,
          quality,
          qualityScore,
          messages: JSON.stringify([
            { role: "system", content: template.system },
            { role: "user", content: filledUser },
            { role: "assistant", content: filledAssistant },
          ]),
          metadata: JSON.stringify({
            labTarget: target.name,
            phase: dec.phase,
            category: (dec as any).category,
            mitreTechnique: dec.technique,
            wave: 2,
            seeded: true,
          }),
          createdAt: createdAtTs,
        });
        trainingCount++;
      }
    }
    results.llmTrainingExamples = trainingCount;

    // ─── 6. More NEXUS Pipeline Executions ───────────────────────────────
    let nexusCount = 0;
    const nexusCallers = [
      "specialist:scan-analyst", "specialist:exploit-selector",
      "specialist:evasion-optimizer", "specialist:lateral-planner",
      "specialist:persistence-engineer", "specialist:osint-analyst",
      "specialist:pentester", "specialist:red-team-operator",
      "specialist:social-engineer", "specialist:report-writer",
      "engagement-orchestrator", "ai-attack-planner",
    ];

    for (const caller of nexusCallers) {
      const runsPerCaller = rand(3, 7);
      for (let r = 0; r < runsPerCaller; r++) {
        const executionId = `npe2-${randomUUID().slice(0, 8)}`;
        const tier = pick([1, 2, 3, 4]);
        const statuses = ["completed", "completed", "completed", "completed", "failed", "running"] as const;
        const status = pick(statuses);
        const stages = ["requirement_analysis", "architecture", "code_generation", "qa_validation", "security_review", "integration_test"];
        const completedStages = status === "completed" ? stages.length : status === "failed" ? rand(1, 4) : rand(1, 3);

        const stageHistory = stages.slice(0, completedStages).map((stage, idx) => ({
          stage,
          startedAt: Date.now() - rand(1, 60) * 24 * 60 * 60 * 1000,
          completedAt: idx < completedStages - 1 || status === "completed" ? Date.now() - rand(0, 59) * 24 * 60 * 60 * 1000 : undefined,
          status: (idx < completedStages - 1 || status === "completed" ? "passed" : status === "failed" ? "failed" : "passed") as "passed" | "failed" | "skipped",
          retries: rand(0, 3),
          evidence: `Wave 2: ${stage} ${idx < completedStages - 1 || status === "completed" ? "passed" : "in progress"} for ${caller}`,
          score: rand(55, 100),
          agentUsed: caller,
        }));

        const qaScore = rand(45, 100);
        const secScore = rand(35, 100);
        const intScore = rand(50, 100);
        const overallScore = Math.round((qaScore + secScore + intScore) / 3);

        const startedAtTs = new Date(Date.now() - rand(1, 60) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(nexusPipelineExecutions).values({
          executionId,
          callerName: caller,
          graduationTier: tier,
          triggerType: pick(["auto", "manual", "scheduled"] as const),
          currentStage: status === "completed" ? "completed" as const : status === "failed" ? "failed" as const : pick(stages.slice(0, completedStages)) as any,
          stageHistory,
          requirementSpec: {
            inputSchema: { type: "object", properties: { target: { type: "string" }, scenario: { type: "string" } } },
            outputSchema: { type: "object", properties: { result: { type: "string" }, score: { type: "number" }, findings: { type: "array" } } },
            sampleInputs: [{ target: pick(LAB_TARGETS).domain, scenario: pick(["owasp", "api", "ad", "cloud", "phishing"]) }],
            sampleOutputs: [{ result: "vulnerability_confirmed", score: 85, findings: ["SQLi", "XSS", "IDOR"] }],
            constraints: ["Must complete within 60s", "Stealth score > 0.6", "Cover all OWASP categories"],
            performanceTargets: { maxLatencyMs: 8000, minAccuracy: 0.80 },
          },
          generatedCode: `// Wave 2 auto-generated code for ${caller}\n// Scenario: ${pick(["owasp", "api", "ad", "cloud", "phishing"])}\nexport async function execute(input) {\n  const result = await analyzeTarget(input.target);\n  return { result: result.status, score: ${overallScore}, findings: result.findings };\n}`,
          generatedTests: `// Wave 2 tests for ${caller}\ndescribe("${caller}", () => {\n  test("should execute scenario successfully", async () => {\n    const result = await execute({ target: "test.lab", scenario: "owasp" });\n    expect(result.score).toBeGreaterThan(50);\n  });\n});`,
          qaScore,
          securityScore: secScore,
          integrationScore: intScore,
          overallScore,
          costSaved: String(randFloat(0.5, 25.0)),
          tokensConsumed: rand(8000, 80000),
          llmCallsCount: rand(5, 30),
          status,
          errorMessage: status === "failed" ? pick([
            "Quality gate failed: security score below threshold",
            "Integration test timeout after 60s",
            "Code generation produced invalid syntax",
            "LLM rate limit exceeded during pipeline",
          ]) : null,
          startedAt: startedAtTs,
          completedAt: status === "completed" || status === "failed"
            ? new Date(Date.now() - rand(0, 59) * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace("T", " ")
            : null,
        });

        // Quality gates
        const gateTypes = ["llm_judge", "unit_test", "type_check", "security_scan", "performance_bench", "integration_test"] as const;
        for (const gateType of gateTypes) {
          const passed = Math.random() > 0.2;
          const score = passed ? rand(65, 100) : rand(15, 60);
          await db.insert(nexusQualityGates).values({
            executionId,
            gateName: `Wave 2: ${gateType.replace(/_/g, ' ')} for ${caller}`,
            gateType,
            passed,
            score,
            maxScore: 100,
            evidence: {
              judgeReasoning: gateType === "llm_judge" ? `Wave 2 assessment: ${passed ? 'Meets expanded standards' : 'Below threshold'}. Score: ${score}/100.` : undefined,
              testResults: gateType === "unit_test" ? { passed: rand(10, 25), failed: passed ? 0 : rand(1, 5), skipped: rand(0, 3) } : undefined,
              securityFindings: gateType === "security_scan" ? (passed ? [] : [{ severity: pick(["high", "medium", "critical"]), description: pick(["Injection vulnerability", "Auth bypass", "SSRF", "Deserialization flaw"]) }]) : undefined,
              performanceMetrics: gateType === "performance_bench" ? { latencyMs: rand(50, 8000), memoryMb: rand(30, 800), throughputRps: rand(5, 200) } : undefined,
            },
            retryAttempt: passed ? 0 : rand(0, 3),
          });
        }
        nexusCount++;
      }
    }
    results.nexusPipelineExecutions = nexusCount;

    // ─── 7. More Shadow Test Results ─────────────────────────────────────
    let shadowCount = 0;
    const existingConfigs = await db.select().from(nexusShadowConfigs);
    const configIds = existingConfigs.map(c => c.id);

    for (const configId of configIds) {
      const config = existingConfigs.find(c => c.id === configId)!;
      const testsPerConfig = rand(20, 40); // More tests per config
      for (let t = 0; t < testsPerConfig; t++) {
        const caller = pick(allCallers);
        const primaryLatency = rand(150, 6000);
        const expLatency = rand(150, 10000);
        const primaryScore = rand(40, 100);
        const expScore = rand(40, 100);
        const verdict = primaryScore > expScore + 10 ? "primary_better" as const
          : expScore > primaryScore + 10 ? "experimental_better" as const
          : "tie" as const;

        const dec = pick(ALL_EXPANDED_DECISIONS);
        const createdAtTs = new Date(Date.now() - rand(0, 60) * 24 * 60 * 60 * 1000)
          .toISOString().slice(0, 19).replace("T", " ");

        await db.insert(nexusShadowTests).values({
          configId,
          caller,
          promptSnippet: dec.decision.slice(0, 200),
          primaryModel: config.primaryModel || "gemini-2.5-flash",
          primaryLatencyMs: primaryLatency,
          primaryTokensIn: rand(300, 4000),
          primaryTokensOut: rand(150, 2000),
          primaryScore,
          experimentalModel: config.experimentalModel || "gpt-4o",
          experimentalLatencyMs: expLatency,
          experimentalTokensIn: rand(300, 4000),
          experimentalTokensOut: rand(150, 2000),
          experimentalScore: expScore,
          judgeVerdict: verdict,
          judgeReasoning: `Wave 2 A/B test: ${verdict === "primary_better" ? "Primary model" : verdict === "experimental_better" ? "Experimental model" : "Both models"} ${verdict === "tie" ? "performed comparably" : "showed superior"} on ${(dec as any).category} scenario. Primary: ${primaryScore}/100 (${primaryLatency}ms). Experimental: ${expScore}/100 (${expLatency}ms). Category: ${(dec as any).category}.`,
          judgeScore: Math.round((primaryScore + expScore) / 2),
          status: "completed" as const,
          createdAt: createdAtTs,
          completedAt: createdAtTs,
        });
        shadowCount++;
      }

      await db.update(nexusShadowConfigs)
        .set({ totalRuns: sql`nsc_total_runs + ${shadowCount}` })
        .where(sql`id = ${configId}`);
    }
    results.nexusShadowTests = shadowCount;

    return {
      success: true,
      message: "Wave 2 expanded LLM training data seeded successfully",
      wave: 2,
      counts: results,
      engagementIds,
      categories: ["owasp_top10", "api_security", "ad_attacks", "cloud_attacks", "phishing", "threat_actor_emulation", "c2_operations"],
      tables: [
        "engagements", "engagement_timeline_events", "llm_telemetry",
        "llm_decision_log", "llm_training_examples",
        "nexus_pipeline_executions", "nexus_quality_gates", "nexus_shadow_tests",
      ],
    };
  }),
});
