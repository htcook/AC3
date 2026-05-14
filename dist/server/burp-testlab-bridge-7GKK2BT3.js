import {
  getLatestDeployment
} from "./chunk-Z4GDQK7R.js";
import {
  init_burp_auto_scan,
  launchBurpAutoScan
} from "./chunk-HKC2BDBZ.js";
import "./chunk-CQ47Y25T.js";
import "./chunk-DACF3QRL.js";
import "./chunk-HPRQMQNG.js";
import "./chunk-ZMTZQD5V.js";
import "./chunk-YKJATTT4.js";
import "./chunk-ACNS3YHQ.js";
import "./chunk-6LI7JMZW.js";
import "./chunk-KNYH6XKO.js";
import "./chunk-5DEWV7VV.js";
import "./chunk-CNZKARK3.js";
import "./chunk-MJGBFYEG.js";
import "./chunk-IL4FZKPB.js";
import {
  DEFAULT_LAB_CONFIG,
  init_nextcloud_test_lab
} from "./chunk-E5TT6UGW.js";
import "./chunk-H26DZ3R6.js";
import "./chunk-5JM52P7I.js";
import "./chunk-R4LF5PWF.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import "./chunk-7DIV2VRB.js";
import "./chunk-RPDKBLF3.js";
import "./chunk-3QHJY6IR.js";
import "./chunk-N4SKBCBX.js";
import "./chunk-YY5JEKDP.js";
import "./chunk-Z63B6QCQ.js";
import "./chunk-NQKLH74H.js";
import "./chunk-E7WGGYZE.js";
import "./chunk-SSYKZXNO.js";
import "./chunk-WP62CKNZ.js";
import "./chunk-G45ZFGC3.js";
import "./chunk-LPSC3SDV.js";
import "./chunk-J6EMIQSU.js";
import "./chunk-RXZBKY45.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-YW5WVS53.js";
import "./chunk-PFTNS476.js";
import "./chunk-TP4TYLYW.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KUPDIQVG.js";
import "./chunk-JP5I5SRV.js";
import "./chunk-GN2OC6SU.js";
import "./chunk-FLBHZBVD.js";
import "./chunk-KFQGP6VL.js";

// server/lib/burp-testlab-bridge.ts
init_nextcloud_test_lab();
init_burp_auto_scan();
function generateScanProfiles(config = DEFAULT_LAB_CONFIG) {
  const host = config.scanServerHost || "localhost";
  const base = `https://${host}:${config.hostPort}`;
  const profiles = [
    {
      name: "core-webdav",
      description: "WebDAV file operations \u2014 PROPFIND, MOVE, COPY, LOCK, MKCOL injection vectors",
      targetUrls: [
        `${base}/remote.php/dav`,
        `${base}/remote.php/webdav`,
        `${base}/remote.php/dav/files/testuser1`,
        `${base}/remote.php/dav/calendars/testuser1`,
        `${base}/remote.php/dav/addressbooks/testuser1`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1190", "T1059.007", "T1071.001"],
      targetCwes: ["CWE-22", "CWE-89", "CWE-611", "CWE-918"],
      priority: 1
    },
    {
      name: "sharing-api",
      description: "File sharing ACL bypass \u2014 permission escalation, public link abuse, federated shares",
      targetUrls: [
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/shares`,
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/remote_shares`,
        `${base}/ocs/v2.php/apps/files_sharing/api/v1/sharees`,
        `${base}/index.php/s/`
        // Public share links
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1080", "T1567", "T1537"],
      targetCwes: ["CWE-639", "CWE-284", "CWE-862", "CWE-863"],
      priority: 1
    },
    {
      name: "auth-endpoints",
      description: "Authentication attacks \u2014 login, 2FA, session management, CSRF, brute force",
      targetUrls: [
        `${base}/index.php/login`,
        `${base}/index.php/login/v2`,
        `${base}/index.php/login/v2/poll`,
        `${base}/ocs/v2.php/cloud/users`,
        `${base}/ocs/v2.php/cloud/groups`,
        `${base}/index.php/settings/personal/security`
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1110", "T1078", "T1539", "T1556"],
      targetCwes: ["CWE-287", "CWE-352", "CWE-384", "CWE-307", "CWE-613"],
      priority: 1
    },
    {
      name: "talk-webrtc",
      description: "Nextcloud Talk \u2014 WebRTC signaling, TURN abuse, chat injection, call manipulation",
      targetUrls: [
        `${base}/index.php/apps/spreed`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/room`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/signaling`,
        `${base}/ocs/v2.php/apps/spreed/api/v4/call`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1557", "T1040", "T1059.007"],
      targetCwes: ["CWE-79", "CWE-918", "CWE-200", "CWE-346"],
      priority: 2
    },
    {
      name: "e2e-encryption",
      description: "End-to-end encryption \u2014 key management, metadata leakage, downgrade attacks",
      targetUrls: [
        `${base}/index.php/apps/end_to_end_encryption`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/public-key`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/private-key`,
        `${base}/ocs/v2.php/apps/end_to_end_encryption/api/v1/lock`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1557", "T1600", "T1552"],
      targetCwes: ["CWE-310", "CWE-326", "CWE-327", "CWE-200"],
      priority: 2
    },
    {
      name: "admin-settings",
      description: "Admin panel \u2014 SSRF via app store, config injection, privilege escalation",
      targetUrls: [
        `${base}/index.php/settings/admin`,
        `${base}/index.php/settings/admin/overview`,
        `${base}/index.php/settings/admin/security`,
        `${base}/index.php/settings/apps`,
        `${base}/ocs/v2.php/cloud/apps`
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1190", "T1068", "T1548"],
      targetCwes: ["CWE-918", "CWE-94", "CWE-269", "CWE-434"],
      priority: 2
    },
    {
      name: "mail-app",
      description: "Mail app \u2014 SSRF, HTML injection, attachment handling, IMAP injection",
      targetUrls: [
        `${base}/index.php/apps/mail`,
        `${base}/index.php/apps/mail/api/accounts`,
        `${base}/index.php/apps/mail/api/messages`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "standard",
      attackTechniques: ["T1566", "T1071.003", "T1059.007"],
      targetCwes: ["CWE-918", "CWE-79", "CWE-434", "CWE-89"],
      priority: 3
    },
    {
      name: "collaboration-apps",
      description: "Deck, Forms, Calendar, Contacts \u2014 XSS, IDOR, data leakage",
      targetUrls: [
        `${base}/index.php/apps/deck`,
        `${base}/index.php/apps/forms`,
        `${base}/index.php/apps/calendar`,
        `${base}/index.php/apps/contacts`,
        `${base}/index.php/apps/notes`,
        `${base}/index.php/apps/text`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "standard",
      attackTechniques: ["T1059.007", "T1190"],
      targetCwes: ["CWE-79", "CWE-639", "CWE-200", "CWE-862"],
      priority: 3
    },
    {
      name: "ocsapi-provisioning",
      description: "OCS Provisioning API \u2014 user/group management, capability enumeration",
      targetUrls: [
        `${base}/ocs/v2.php/cloud/users`,
        `${base}/ocs/v2.php/cloud/groups`,
        `${base}/ocs/v2.php/cloud/capabilities`,
        `${base}/ocs/v2.php/apps/provisioning_api/api/v1/config/apps`,
        `${base}/status.php`
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`,
        apiAuthHeader: `Basic ${Buffer.from(`${config.adminUser}:${config.adminPassword}`).toString("base64")}`
      },
      scanMode: "standard",
      attackTechniques: ["T1087", "T1069", "T1082"],
      targetCwes: ["CWE-200", "CWE-284", "CWE-269"],
      priority: 3
    }
  ];
  if (config.enableLDAP) {
    profiles.push({
      name: "ldap-integration",
      description: "LDAP authentication \u2014 injection, bind bypass, attribute enumeration",
      targetUrls: [
        `${base}/index.php/settings/admin/ldap`,
        `${base}/index.php/login`
        // LDAP login path
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1556.002", "T1087.002"],
      targetCwes: ["CWE-90", "CWE-287", "CWE-200"],
      priority: 2
    });
  }
  if (config.enableKeycloak) {
    profiles.push({
      name: "saml-sso",
      description: "SAML/SSO via Keycloak \u2014 assertion manipulation, redirect bypass, session confusion",
      targetUrls: [
        `${base}/index.php/apps/user_saml/saml/login`,
        `${base}/index.php/apps/user_saml/saml/metadata`,
        `https://${host}:8444/realms/nextcloud`,
        `https://${host}:8444/realms/nextcloud/protocol/saml`
      ],
      authConfig: {
        username: config.adminUser,
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "active",
      attackTechniques: ["T1556", "T1550.001"],
      targetCwes: ["CWE-287", "CWE-346", "CWE-611"],
      priority: 2
    });
  }
  if (config.enableCollabora) {
    profiles.push({
      name: "collabora-office",
      description: "Collabora Online \u2014 document conversion exploits, WOPI token abuse",
      targetUrls: [
        `${base}/index.php/apps/richdocuments`,
        `${base}/index.php/apps/richdocuments/wopi/files`
      ],
      authConfig: {
        username: "testuser1",
        password: config.adminPassword,
        loginUrl: `${base}/index.php/login`
      },
      scanMode: "standard",
      attackTechniques: ["T1203", "T1059"],
      targetCwes: ["CWE-434", "CWE-918", "CWE-94"],
      priority: 3
    });
  }
  return profiles.sort((a, b) => a.priority - b.priority);
}
function preflightCheck(engagementId, config = DEFAULT_LAB_CONFIG) {
  const issues = [];
  const deployment = getLatestDeployment(engagementId);
  let labStatus = "not_deployed";
  let labUrl = null;
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
  const sshHost = config.scanServerHost || process.env.SCAN_SERVER_HOST;
  if (!sshHost && !labUrl) {
    issues.push("No scan server host configured and no lab URL available.");
  }
  const profiles = generateScanProfiles(config);
  const totalTargets = profiles.reduce((sum, p) => sum + p.targetUrls.length, 0);
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
    estimatedDuration
  };
}
async function launchProfileScan(engagementId, engagementHandle, userId, credentialId, burpConfig, profileName, config = DEFAULT_LAB_CONFIG) {
  const profiles = generateScanProfiles(config);
  const profile = profiles.find((p) => p.name === profileName);
  if (!profile) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: 0,
      error: `Profile '${profileName}' not found. Available: ${profiles.map((p) => p.name).join(", ")}`
    };
  }
  const preflight = preflightCheck(engagementId, config);
  if (!preflight.ready) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: `Pre-flight failed: ${preflight.issues.join("; ")}`
    };
  }
  try {
    const scanConfig = {
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
        loginUrl: profile.authConfig.loginUrl
      },
      scanMode: profile.scanMode
    };
    const scanState = await launchBurpAutoScan(scanConfig);
    return {
      success: true,
      scanId: scanState.scanId,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: null
    };
  } catch (err) {
    return {
      success: false,
      scanId: null,
      profile: profileName,
      targetCount: profile.targetUrls.length,
      error: err.message || "Failed to launch scan"
    };
  }
}
async function launchFullLabScan(engagementId, engagementHandle, userId, credentialId, burpConfig, config = DEFAULT_LAB_CONFIG) {
  const profiles = generateScanProfiles(config);
  const results = [];
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
function listScanProfiles(config = DEFAULT_LAB_CONFIG) {
  return generateScanProfiles(config);
}
function getTotalScanTargets(config = DEFAULT_LAB_CONFIG) {
  const profiles = generateScanProfiles(config);
  const allUrls = /* @__PURE__ */ new Set();
  for (const p of profiles) {
    for (const u of p.targetUrls) {
      allUrls.add(u);
    }
  }
  return allUrls.size;
}
export {
  generateScanProfiles,
  getTotalScanTargets,
  launchFullLabScan,
  launchProfileScan,
  listScanProfiles,
  preflightCheck
};
