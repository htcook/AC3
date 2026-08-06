/**
 * Burp Suite ↔ Test Lab Bridge
 * 
 * Wires Burp auto-scan to target the Nextcloud test lab.
 * Handles:
 * - Auto-configuring scan targets from test lab config
 * - Pre-populating Burp with Nextcloud auth credentials
 * - Per-app scan configurations with specific URL paths
 * - Pre-flight checks (ensure lab is running before scan)
 * - Quick-action scan launcher
 */

import { type TestLabConfig, DEFAULT_LAB_CONFIG, BOUNTY_ELIGIBLE_APPS } from "./nextcloud-test-lab";
import { getLabScanTargets, getLatestDeployment, type LabDeploymentState } from "./test-lab-deployer";
import { launchBurpAutoScan, type BurpAutoScanConfig } from "./burp-auto-scan";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface NextcloudScanProfile {
  name: string;
  description: string;
  targetUrls: string[];
  authConfig: NextcloudAuthConfig;
  scanMode: "strict_passive" | "standard" | "active";
  /** MITRE ATT&CK techniques this profile tests */
  attackTechniques: string[];
  /** CWEs this profile targets */
  targetCwes: string[];
  /** Priority: 1 = highest */
  priority: number;
}

export interface NextcloudAuthConfig {
  username: string;
  password: string;
  loginUrl: string;
  /** Additional auth headers for API endpoints */
  apiAuthHeader?: string;
}

export interface LabScanPreflightResult {
  ready: boolean;
  labStatus: "running" | "stopped" | "not_deployed" | "unknown";
  labUrl: string | null;
  issues: string[];
  scanTargetCount: number;
  estimatedDuration: string;
}

export interface LabScanLaunchResult {
  success: boolean;
  scanId: string | null;
  profile: string;
  targetCount: number;
  error: string | null;
}

// ─── Scan Profile Generation ─────────────────────────────────────────────────

/**
 * Generate Nextcloud-specific scan profiles targeting different attack surfaces.
 * Each profile focuses on a specific area with appropriate auth and scan depth.
 */
export function generateScanProfiles(config: TestLabConfig = DEFAULT_LAB_CONFIG): NextcloudScanProfile[] {
  const host = config.scanServerHost || "localhost";
  const base = `https://${host}:${config.hostPort}`;

  const profiles: NextcloudScanProfile[] = [
    {
      name: "core-webdav",
      description: "WebDAV file operations — PROPFIND, MOVE, COPY, LOCK, MKCOL injection vectors",
      targetUrls: [
        `${base}/remote.php/dav`,
        `${base}/remote.php/webdav`,
        `${base}/remote.php/dav/files/testuser1`,
        `${base}/remote.php/dav/calendars/testuser1`,
        `${base}/remote.php/dav/addressbooks/testuser1`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1190", "T1059.007", "T1071.001"],
      targetCwes: ["CWE-22", "CWE-89", "CWE-611", "CWE-918"],
      priority: 1,
    },
    {
      name: "sharing-api",
      description: "File sharing ACL bypass — permission escalation, public link abuse, federated shares",
      targetUrls: [
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/shares`,
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/remote_shares`,
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/sharees`,
        `${base}/index.php/s/`, // Public share links
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1080", "T1567", "T1537"],
      targetCwes: ["CWE-639", "CWE-284", "CWE-862", "CWE-863"],
      priority: 1,
    },
    {
      name: "auth-endpoints",
      description: "Authentication attacks — login, 2FA, session management, CSRF, brute force",
      targetUrls: [
        `${base}/index.php/login`,
        `${base}/index.php/login/v2`,
        `${base}/index.php/login/v2/poll`,
        `${base}/ocs/v2.php/cloud/users`,
        `${base}/ocs/v2.php/cloud/groups`,
        `${base}/index.php/settings/personal/security`,
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1110", "T1078", "T1539", "T1556"],
      targetCwes: ["CWE-287", "CWE-352", "CWE-384", "CWE-307", "CWE-613"],
      priority: 1,
    },
    {
      name: "talk-webrtc",
      description: "Nextcloud Talk — WebRTC signaling, TURN abuse, chat injection, call manipulation",
      targetUrls: [
        `${base}/index.php/apps/spreed`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/room`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/signaling`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/call`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1557", "T1040", "T1059.007"],
      targetCwes: ["CWE-79", "CWE-918", "CWE-200", "CWE-346"],
      priority: 2,
    },
    {
      name: "e2e-encryption",
      description: "End-to-end encryption — key management, metadata leakage, downgrade attacks",
      targetUrls: [
        `${base}/index.php/apps/end_to_end_encryption`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/private-key`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/lock`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1557", "T1600", "T1552"],
      targetCwes: ["CWE-310", "CWE-326", "CWE-327", "CWE-200"],
      priority: 2,
    },
    {
      name: "admin-settings",
      description: "Admin panel — SSRF via app store, config injection, privilege escalation",
      targetUrls: [
        `${base}/index.php/settings/admin`,
        `${base}/index.php/settings/admin/overview`,
        `${base}/index.php/settings/admin/security`,
        `${base}/index.php/settings/apps`,
        `${base}/ocs/v2.php/cloud/apps`,
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1190", "T1068", "T1548"],
      targetCwes: ["CWE-918", "CWE-94", "CWE-269", "CWE-434"],
      priority: 2,
    },
    {
      name: "mail-app",
      description: "Mail app — SSRF, HTML injection, attachment handling, IMAP injection",
      targetUrls: [
        `${base}/index.php/apps/mail`,
        `${base}/index.php/apps/mail/api/accounts`,
        `${base}/index.php/apps/mail/api/messages`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "standard",
      attackTechniques: ["T1566", "T1071.003", "T1059.007"],
      targetCwes: ["CWE-918", "CWE-79", "CWE-434", "CWE-89"],
      priority: 3,
    },
    {
      name: "collaboration-apps",
      description: "Deck, Forms, Calendar, Contacts — XSS, IDOR, data leakage",
      targetUrls: [
        `${base}/index.php/apps/deck`,
        `${base}/index.php/apps/forms`,
        `${base}/index.php/apps/calendar`,
        `${base}/index.php/apps/contacts`,
        `${base}/index.php/apps/notes`,
        `${base}/index.php/apps/text`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "standard",
      attackTechniques: ["T1059.007", "T1190"],
      targetCwes: ["CWE-79", "CWE-639", "CWE-200", "CWE-862"],
      priority: 3,
    },
    {
      name: "ocsapi-provisioning",
      description: "OCS Provisioning API — user/group management, capability enumeration",
      targetUrls: [
        `${base}/ocs/v2.php/cloud/users`,
        `${base}/ocs/v2.php/cloud/groups`,
        `${base}/ocs/v2.php/cloud/capabilities`,
        `${base}/ocs/v2.php/apps/provisioning_api/api/v1/config/apps`,
        `${base}/status.php`,
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
        apiAuthHeader: `Basic ${Buffer.from(`${config.adminUser}:${config.adminPassword}`).toString("base64")}`,
      },
      scanMode: "standard",
      attackTechniques: ["T1087", "T1069", "T1082"],
      targetCwes: ["CWE-200", "CWE-284", "CWE-269"],
      priority: 3,
    },
  ];

  // Add LDAP profile if enabled
  if (config.enableLDAP) {
    profiles.push({
      name: "ldap-integration",
      description: "LDAP authentication — injection, bind bypass, attribute enumeration",
      targetUrls: [
        `${base}/index.php/settings/admin/ldap`,
        `${base}/index.php/login`, // LDAP login path
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1556.002", "T1087.002"],
      targetCwes: ["CWE-90", "CWE-287", "CWE-200"],
      priority: 2,
    });
  }

  // Add Keycloak/SAML profile if enabled
  if (config.enableKeycloak) {
    profiles.push({
      name: "saml-sso",
      description: "SAML/SSO via Keycloak — assertion manipulation, redirect bypass, session confusion",
      targetUrls: [
        `${base}/index.php/apps/user_saml/saml/login`,
        `${base}/index.php/apps/user_saml/saml/metadata`,
        `https://${host}:8444/realms/nextcloud`,
        `https://${host}:8444/realms/nextcloud/protocol/saml`,
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "active",
      attackTechniques: ["T1556", "T1550.001"],
      targetCwes: ["CWE-287", "CWE-346", "CWE-611"],
      priority: 2,
    });
  }

  // Add Collabora profile if enabled
  if (config.enableCollabora) {
    profiles.push({
      name: "collabora-office",
      description: "Collabora Online — document conversion exploits, WOPI token abuse",
      targetUrls: [
        `${base}/index.php/apps/richdocuments`,
        `${base}/index.php/apps/richdocuments/wopi/files`,
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
      },
      scanMode: "standard",
      attackTechniques: ["T1203", "T1059"],
      targetCwes: ["CWE-434", "CWE-918", "CWE-94"],
      priority: 3,
    });
  }

  return profiles.sort((a, b) => a.priority - b.priority);
}

// ─── Pre-flight Check ────────────────────────────────────────────────────────

/**
 * Check if the test lab is ready for scanning.
 * Verifies deployment status and estimates scan duration.
 */
export function preflightCheck(
  engagementId: number,
  config: TestLabConfig = DEFAULT_LAB_CONFIG
): LabScanPreflightResult {
  const issues: string[] = [];

  // Check deployment status
  const deployment = getLatestDeployment(engagementId);
  let labStatus: LabScanPreflightResult["labStatus"] = "not_deployed";
  let labUrl: string | null = null;

  if (deployment) {
    if (deployment.status === "running") {
      labStatus = "running";
      labUrl = deployment.labUrl;
    } else if (deployment.status === "stopped" || deployment.status === "destroying") {
      labStatus = "stopped";
      issues.push("Test lab is stopped. Deploy it first.");
    } else if (deployment.status === "failed") {
      labStatus = "stopped";
      issues.push(`Last deployment failed: ${deployment.error}`);
    } else {
      labStatus = "unknown";
      issues.push(`Lab is in '${deployment.status}' state. Wait for deployment to complete.`);
    }
  } else {
    issues.push("No test lab deployment found. Deploy the test lab first.");
  }

  // Check scan server config
  const sshHost = config.scanServerHost || process.env.SCAN_SERVER_HOST;
  if (!sshHost && !labUrl) {
    issues.push("No scan server host configured and no lab URL available.");
  }

  const profiles = generateScanProfiles(config);
  const totalTargets = profiles.reduce((sum, p) => sum + p.targetUrls.length, 0);

  // Estimate duration: ~2 min per target for standard, ~5 min for active
  const activeTargets = profiles.filter((p) => p.scanMode === "active").reduce((s, p) => s + p.targetUrls.length, 0);
  const standardTargets = totalTargets - activeTargets;
  const estimatedMinutes = activeTargets * 5 + standardTargets * 2;
  const hours = Math.floor(estimatedMinutes / 60);
  const mins = estimatedMinutes % 60;
  const estimatedDuration = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;

  return {
    ready: issues.length === 0,
    labStatus,
    labUrl,
    issues,
    scanTargetCount: totalTargets,
    estimatedDuration,
  };
}

// ─── Quick-Action Scan Launcher ──────────────────────────────────────────────

/**
 * Launch a Burp scan against the test lab using a specific profile.
 * This is the "Scan Test Lab" quick-action.
 */
export async function launchProfileScan(
  engagementId: number,
  engagementHandle: string,
  userId: string,
  credentialId: number,
  burpConfig: { baseUrl: string; apiKey: string; type: "pro" | "enterprise" },
  profileName: string,
  config: TestLabConfig = DEFAULT_LAB_CONFIG
): Promise<LabScanLaunchResult> {
  const profiles = generateScanProfiles(config);
  const profile = profiles.find((p) => p.name === profileName);

  if (!profile) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: 0,
      error: `Profile '${profileName}' not found. Available: ${profiles.map((p) => p.name).join(", ")}`,
    };
  }

  // Pre-flight check
  const preflight = preflightCheck(engagementId, config);
  if (!preflight.ready) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: `Pre-flight failed: ${preflight.issues.join("; ")}`,
    };
  }

  try {
    const scanConfig: BurpAutoScanConfig = {
      engagementId,
      engagementHandle,
      userId,
      targetUrls: profile.targetUrls,
      credentialId,
      burpConfig,
      scanConfigName: `AC3-${profile.name}`,
      appLogin: {
        username: profile.authConfig.username,
        password: profile.authConfig.password,
        loginUrl: profile.authConfig.loginUrl,
      },
      scanMode: profile.scanMode,
    };

    const scanState = await launchBurpAutoScan(scanConfig);

    return {
      success: true,
      scanId: scanState.scanId,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: null,
    };
  } catch (err: any) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: err.message || "Failed to launch scan",
    };
  }
}

/**
 * Launch all scan profiles sequentially (full test lab scan).
 * Returns results for each profile.
 */
export async function launchFullLabScan(
  engagementId: number,
  engagementHandle: string,
  userId: string,
  credentialId: number,
  burpConfig: { baseUrl: string; apiKey: string; type: "pro" | "enterprise" },
  config: TestLabConfig = DEFAULT_LAB_CONFIG
): Promise<LabScanLaunchResult[]> {
  const profiles = generateScanProfiles(config);
  const results: LabScanLaunchResult[] = [];

  for (const profile of profiles) {
    const result = await launchProfileScan(
      engagementId,
      engagementHandle,
      userId,
      credentialId,
      burpConfig,
      profile.name,
      config
    );
    results.push(result);
  }

  return results;
}

/**
 * Get all available scan profiles with their details.
 */
export function listScanProfiles(config: TestLabConfig = DEFAULT_LAB_CONFIG): NextcloudScanProfile[] {
  return generateScanProfiles(config);
}

/**
 * Get the total number of unique scan targets across all profiles.
 */
export function getTotalScanTargets(config: TestLabConfig = DEFAULT_LAB_CONFIG): number {
  const profiles = generateScanProfiles(config);
  const allUrls = new Set<string>();
  for (const p of profiles) {
    for (const u of p.targetUrls) {
      allUrls.add(u);
    }
  }
  return allUrls.size;
}
