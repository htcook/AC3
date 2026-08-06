/**
 * Firebase Security Scanner
 * ─────────────────────────
 * Security testing for Firebase / Google Cloud deployments:
 * - Firestore security rules misconfiguration (open read/write)
 * - Firebase Auth bypass (anonymous auth, email enumeration)
 * - Exposed Firebase config keys in client-side JavaScript
 * - Cloud Functions unauthenticated invocation
 * - Realtime Database open access
 * - Firebase Storage bucket misconfiguration
 * - Firebase Admin SDK credential exposure
 * - GCP IAM privilege escalation via Firebase service accounts
 *
 * @module firebase-scanner
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type FirebaseVulnCategory =
  | "firestore_rules_misconfiguration"
  | "auth_bypass"
  | "config_exposure"
  | "cloud_functions_abuse"
  | "realtime_db_open_access"
  | "storage_misconfiguration"
  | "admin_sdk_exposure"
  | "iam_privilege_escalation"
  | "api_key_abuse"
  | "email_enumeration"
  | "information_disclosure";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface FirebaseFinding {
  id: string;
  category: FirebaseVulnCategory;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  mitreTechnique?: string;
}

export interface FirebaseTarget {
  projectId: string;
  apiKey?: string;
  authDomain?: string;
  databaseURL?: string;
  storageBucket?: string;
  appUrl?: string;
  cloudFunctionsRegion?: string;
}

export interface FirebaseScanResult {
  target: FirebaseTarget;
  findings: FirebaseFinding[];
  profile: FirebaseProfile;
  scanDuration: number;
  timestamp: string;
}

export interface FirebaseProfile {
  projectId: string;
  hasFirestore: boolean;
  hasRealtimeDB: boolean;
  hasStorage: boolean;
  hasAuth: boolean;
  hasCloudFunctions: boolean;
  authProviders: string[];
  anonymousAuthEnabled: boolean;
  firestoreRulesOpen: boolean;
  realtimeDBRulesOpen: boolean;
  storageBucketPublic: boolean;
  exposedConfigKeys: string[];
  cloudFunctionsEndpoints: string[];
}

// ─── Firebase Config Extraction ──────────────────────────────────────────────

/**
 * Extract Firebase configuration from client-side JavaScript source.
 */
export function extractFirebaseConfig(htmlOrJs: string): Partial<FirebaseTarget> | null {
  const config: Partial<FirebaseTarget> = {};

  // Pattern 1: firebaseConfig object literal
  const configMatch = htmlOrJs.match(
    /(?:firebase|fire)Config\s*=\s*\{([^}]+)\}/i
  );
  if (configMatch) {
    const block = configMatch[1];
    const apiKeyMatch = block.match(/apiKey\s*:\s*["']([^"']+)["']/);
    const authDomainMatch = block.match(/authDomain\s*:\s*["']([^"']+)["']/);
    const projectIdMatch = block.match(/projectId\s*:\s*["']([^"']+)["']/);
    const dbUrlMatch = block.match(/databaseURL\s*:\s*["']([^"']+)["']/);
    const storageBucketMatch = block.match(/storageBucket\s*:\s*["']([^"']+)["']/);

    if (apiKeyMatch) config.apiKey = apiKeyMatch[1];
    if (authDomainMatch) config.authDomain = authDomainMatch[1];
    if (projectIdMatch) config.projectId = projectIdMatch[1];
    if (dbUrlMatch) config.databaseURL = dbUrlMatch[1];
    if (storageBucketMatch) config.storageBucket = storageBucketMatch[1];
  }

  // Pattern 2: Individual variable assignments
  if (!config.apiKey) {
    const apiKeyMatch = htmlOrJs.match(/(?:FIREBASE_API_KEY|REACT_APP_FIREBASE_API_KEY|VITE_FIREBASE_API_KEY|apiKey)\s*[=:]\s*["']([A-Za-z0-9_-]{30,})["']/);
    if (apiKeyMatch) config.apiKey = apiKeyMatch[1];
  }

  if (!config.projectId) {
    const projectMatch = htmlOrJs.match(/(?:projectId|FIREBASE_PROJECT_ID)\s*[=:]\s*["']([a-z0-9-]+)["']/);
    if (projectMatch) config.projectId = projectMatch[1];
  }

  return Object.keys(config).length > 0 ? config : null;
}

// ─── Firestore Rules Testing ─────────────────────────────────────────────────

export const FIRESTORE_TEST_COLLECTIONS = [
  "users",
  "accounts",
  "profiles",
  "admin",
  "config",
  "settings",
  "orders",
  "payments",
  "messages",
  "documents",
  "files",
  "secrets",
  "tokens",
  "api_keys",
  "logs",
  "analytics",
  "metadata",
  "internal",
  "private",
  "system",
];

// ─── Cloud Functions Endpoints ───────────────────────────────────────────────

export const COMMON_CLOUD_FUNCTION_PATHS = [
  "/api",
  "/webhook",
  "/callback",
  "/auth",
  "/login",
  "/signup",
  "/admin",
  "/process",
  "/export",
  "/import",
  "/sync",
  "/notify",
  "/email",
  "/payment",
  "/stripe-webhook",
  "/cron",
  "/scheduled",
  "/migrate",
  "/seed",
  "/debug",
  "/test",
  "/health",
  "/status",
];

// ─── Scan Execution ──────────────────────────────────────────────────────────

/**
 * Execute a comprehensive Firebase security scan.
 */
export async function scanFirebaseTarget(
  target: FirebaseTarget,
  options: {
    fetchFn: (url: string, init?: RequestInit) => Promise<{ status: number; headers: Record<string, string>; body: string }>;
    aggressive?: boolean;
  }
): Promise<FirebaseScanResult> {
  const startTime = Date.now();
  const findings: FirebaseFinding[] = [];
  const { fetchFn, aggressive = false } = options;

  const profile: FirebaseProfile = {
    projectId: target.projectId,
    hasFirestore: false,
    hasRealtimeDB: false,
    hasStorage: false,
    hasAuth: false,
    hasCloudFunctions: false,
    authProviders: [],
    anonymousAuthEnabled: false,
    firestoreRulesOpen: false,
    realtimeDBRulesOpen: false,
    storageBucketPublic: false,
    exposedConfigKeys: [],
    cloudFunctionsEndpoints: [],
  };

  // Step 1: Extract config from app URL
  if (target.appUrl) {
    try {
      const resp = await fetchFn(target.appUrl);
      const extractedConfig = extractFirebaseConfig(resp.body);
      if (extractedConfig) {
        if (!target.apiKey && extractedConfig.apiKey) target.apiKey = extractedConfig.apiKey;
        if (!target.projectId && extractedConfig.projectId) target.projectId = extractedConfig.projectId;
        if (!target.databaseURL && extractedConfig.databaseURL) target.databaseURL = extractedConfig.databaseURL;
        if (!target.storageBucket && extractedConfig.storageBucket) target.storageBucket = extractedConfig.storageBucket;

        const exposedKeys = Object.entries(extractedConfig)
          .filter(([, v]) => v)
          .map(([k]) => k);
        profile.exposedConfigKeys = exposedKeys;

        findings.push({
          id: "FB-001",
          category: "config_exposure",
          severity: "medium",
          title: "Firebase Configuration Exposed in Client-Side Code",
          description: `Firebase configuration including ${exposedKeys.join(", ")} is embedded in client-side JavaScript. While API keys alone aren't secret, they can be used to enumerate services and test for misconfigurations.`,
          evidence: `Extracted config keys: ${exposedKeys.join(", ")}. Project ID: ${target.projectId}`,
          remediation: "Firebase API keys are designed to be public, but restrict them via API key restrictions in Google Cloud Console. Set HTTP referrer restrictions. Enable App Check for additional verification.",
          cwe: "CWE-200",
          mitreTechnique: "T1592",
        });
      }
    } catch { /* app not accessible */ }
  }

  // Step 2: Test Firestore open access
  if (target.apiKey && target.projectId) {
    const firestoreBase = `https://firestore.googleapis.com/v1/projects/${target.projectId}/databases/(default)/documents`;

    for (const collection of FIRESTORE_TEST_COLLECTIONS.slice(0, aggressive ? 20 : 5)) {
      try {
        const resp = await fetchFn(`${firestoreBase}/${collection}?key=${target.apiKey}`);
        if (resp.status === 200) {
          profile.hasFirestore = true;
          profile.firestoreRulesOpen = true;

          const data = JSON.parse(resp.body);
          const docCount = data.documents?.length || 0;

          findings.push({
            id: `FB-FS-${collection}`,
            category: "firestore_rules_misconfiguration",
            severity: "critical",
            title: `Firestore Collection "${collection}" Publicly Readable`,
            description: `The Firestore collection "${collection}" allows unauthenticated read access. ${docCount} document(s) returned. This exposes potentially sensitive data to any user with the API key.`,
            evidence: `GET ${firestoreBase}/${collection} returned 200 with ${docCount} documents. First doc fields: ${data.documents?.[0] ? Object.keys(data.documents[0].fields || {}).join(", ") : "none"}`,
            remediation: `Update Firestore security rules to deny unauthenticated access:\nrules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /${collection}/{doc} {\n      allow read: if request.auth != null;\n      allow write: if false;\n    }\n  }\n}`,
            cwe: "CWE-284",
            mitreTechnique: "T1530",
          });
          break; // One finding is enough to flag the issue
        }
      } catch { /* not accessible */ }
    }

    // Test Firestore write access
    if (aggressive && profile.firestoreRulesOpen) {
      try {
        const testDoc = `${firestoreBase}/_security_test_${Date.now()}?key=${target.apiKey}`;
        const resp = await fetchFn(testDoc, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" } as any,
          body: JSON.stringify({
            fields: {
              _test: { stringValue: "security_scan_test" },
              _timestamp: { integerValue: String(Date.now()) },
            },
          }),
        });
        if (resp.status === 200) {
          findings.push({
            id: "FB-FS-WRITE",
            category: "firestore_rules_misconfiguration",
            severity: "critical",
            title: "Firestore Allows Unauthenticated Write Access",
            description: "Firestore security rules allow unauthenticated users to create/modify documents. An attacker can inject, modify, or delete data without authentication.",
            evidence: `PATCH to test document returned 200. Write access confirmed.`,
            remediation: "Immediately update Firestore rules to require authentication for all write operations. Audit existing data for unauthorized modifications.",
            cwe: "CWE-284",
            mitreTechnique: "T1565",
          });
        }
      } catch { /* write denied — good */ }
    }
  }

  // Step 3: Test Realtime Database open access
  const dbUrl = target.databaseURL || `https://${target.projectId}-default-rtdb.firebaseio.com`;
  try {
    const resp = await fetchFn(`${dbUrl}/.json`);
    if (resp.status === 200 && resp.body !== "null") {
      profile.hasRealtimeDB = true;
      profile.realtimeDBRulesOpen = true;

      findings.push({
        id: "FB-RTDB-001",
        category: "realtime_db_open_access",
        severity: "critical",
        title: "Firebase Realtime Database Publicly Readable",
        description: "The Firebase Realtime Database is accessible without authentication. The entire database contents can be downloaded by appending /.json to the database URL.",
        evidence: `GET ${dbUrl}/.json returned 200. Response size: ${resp.body.length} bytes`,
        remediation: 'Update Realtime Database rules to require authentication:\n{\n  "rules": {\n    ".read": "auth != null",\n    ".write": "auth != null"\n  }\n}',
        cwe: "CWE-284",
        mitreTechnique: "T1530",
      });
    }
  } catch { /* not accessible */ }

  // Step 4: Test Firebase Storage bucket
  const storageBucket = target.storageBucket || `${target.projectId}.appspot.com`;
  try {
    // Test via Google Cloud Storage API
    const resp = await fetchFn(`https://storage.googleapis.com/${storageBucket}`);
    if (resp.status === 200 && resp.body.includes("<Contents>")) {
      profile.hasStorage = true;
      profile.storageBucketPublic = true;

      findings.push({
        id: "FB-STOR-001",
        category: "storage_misconfiguration",
        severity: "high",
        title: "Firebase Storage Bucket Publicly Listable",
        description: `The Firebase Storage bucket (${storageBucket}) allows public listing of objects. An attacker can enumerate and download all stored files.`,
        evidence: `GET https://storage.googleapis.com/${storageBucket} returned 200 with file listing`,
        remediation: "Update Firebase Storage security rules to require authentication. Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
        cwe: "CWE-552",
        mitreTechnique: "T1530",
      });
    }
  } catch { /* not accessible */ }

  // Step 5: Test Firebase Auth — anonymous auth and email enumeration
  if (target.apiKey) {
    // Test anonymous auth
    try {
      const resp = await fetchFn(
        `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${target.apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" } as any,
          body: JSON.stringify({ returnSecureToken: true }),
        }
      );
      if (resp.status === 200) {
        profile.hasAuth = true;
        profile.anonymousAuthEnabled = true;

        findings.push({
          id: "FB-AUTH-001",
          category: "auth_bypass",
          severity: "medium",
          title: "Anonymous Authentication Enabled",
          description: "Firebase Anonymous Authentication is enabled, allowing anyone to create anonymous user accounts. If Firestore/RTDB rules only check `request.auth != null`, anonymous users bypass access controls.",
          evidence: `POST accounts:signUp returned 200 with anonymous user token`,
          remediation: "Disable anonymous auth if not needed. If required, ensure security rules check for specific auth claims (e.g., email_verified, custom claims) rather than just auth != null.",
          cwe: "CWE-287",
          mitreTechnique: "T1078",
        });
      }
    } catch { /* anonymous auth disabled — good */ }

    // Test email enumeration
    try {
      const resp = await fetchFn(
        `https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=${target.apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" } as any,
          body: JSON.stringify({
            identifier: "test@example.com",
            continueUri: "https://example.com",
          }),
        }
      );
      if (resp.status === 200) {
        const data = JSON.parse(resp.body);
        if (data.registered !== undefined) {
          findings.push({
            id: "FB-AUTH-002",
            category: "email_enumeration",
            severity: "medium",
            title: "Email Enumeration via Firebase Auth API",
            description: "The Firebase Auth API reveals whether an email address is registered, enabling user enumeration attacks.",
            evidence: `POST accounts:createAuthUri returns "registered" field indicating account existence`,
            remediation: "Enable Email Enumeration Protection in Firebase Console → Authentication → Settings. This prevents the API from revealing whether an email is registered.",
            cwe: "CWE-204",
            mitreTechnique: "T1589.002",
          });
        }
      }
    } catch { /* not accessible */ }
  }

  // Step 6: Test Cloud Functions for unauthenticated access
  if (target.projectId) {
    const regions = [target.cloudFunctionsRegion || "us-central1"];
    const functionsBase = `https://${regions[0]}-${target.projectId}.cloudfunctions.net`;

    for (const path of COMMON_CLOUD_FUNCTION_PATHS.slice(0, aggressive ? 22 : 8)) {
      try {
        const resp = await fetchFn(`${functionsBase}${path}`);
        if (resp.status === 200 || resp.status === 204) {
          profile.hasCloudFunctions = true;
          profile.cloudFunctionsEndpoints.push(path);

          findings.push({
            id: `FB-CF-${path.replace(/\//g, "")}`,
            category: "cloud_functions_abuse",
            severity: "high",
            title: `Cloud Function "${path}" Accessible Without Authentication`,
            description: `The Cloud Function at ${functionsBase}${path} responds to unauthenticated requests. If this function performs privileged operations, it can be abused by any attacker.`,
            evidence: `GET ${functionsBase}${path} returned ${resp.status}. Response: ${resp.body.substring(0, 200)}`,
            remediation: "Add authentication checks to the Cloud Function. Use Firebase Auth ID tokens or implement API key validation. Set invoker permissions to require authentication in GCP Console.",
            cwe: "CWE-306",
            mitreTechnique: "T1190",
          });
        }
      } catch { /* not accessible */ }
    }
  }

  // Step 7: Check for Admin SDK credential exposure
  if (target.appUrl) {
    const credentialPaths = [
      "/firebase-adminsdk.json",
      "/serviceAccountKey.json",
      "/service-account.json",
      "/firebase-credentials.json",
      "/google-credentials.json",
      "/.env",
      "/config/firebase.json",
      "/secrets/firebase.json",
    ];

    for (const path of credentialPaths) {
      try {
        const resp = await fetchFn(`${target.appUrl}${path}`);
        if (resp.status === 200 && (
          resp.body.includes("private_key") ||
          resp.body.includes("FIREBASE_") ||
          resp.body.includes("service_account")
        )) {
          findings.push({
            id: `FB-CRED-${path.replace(/[\/\.]/g, "")}`,
            category: "admin_sdk_exposure",
            severity: "critical",
            title: `Firebase Admin SDK Credentials Exposed: ${path}`,
            description: `Firebase Admin SDK service account credentials are publicly accessible at ${path}. This grants full administrative access to the Firebase project including all data, user accounts, and cloud resources.`,
            evidence: `GET ${target.appUrl}${path} returned 200 with credential content`,
            remediation: "Remove the file immediately. Rotate the service account key in Google Cloud Console. Audit all Firebase project activity for unauthorized access. Never commit service account keys to source control.",
            cwe: "CWE-798",
            mitreTechnique: "T1552.001",
          });
        }
      } catch { /* not accessible */ }
    }
  }

  return {
    target,
    findings,
    profile,
    scanDuration: Date.now() - startTime,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Generate a Firebase-specific test plan for an engagement.
 */
export function generateFirebaseTestPlan(profile: FirebaseProfile): string[] {
  const tests: string[] = [
    "Extract Firebase configuration from client-side JavaScript",
    "Test API key restrictions (HTTP referrer, API restrictions)",
    "Check for Firebase App Check enforcement",
  ];

  if (profile.hasFirestore || !profile.hasFirestore) {
    tests.push(
      "Test Firestore security rules for unauthenticated read access on common collections",
      "Test Firestore security rules for unauthenticated write access",
      "Test Firestore rules for cross-user data access (horizontal privilege escalation)",
      "Test Firestore rules for admin collection access"
    );
  }

  if (profile.hasRealtimeDB || !profile.hasRealtimeDB) {
    tests.push(
      "Test Realtime Database for open read access (/.json)",
      "Test Realtime Database for open write access",
      "Check for sensitive data in Realtime Database paths"
    );
  }

  if (profile.hasAuth || !profile.hasAuth) {
    tests.push(
      "Test for anonymous authentication",
      "Test email enumeration via Auth API",
      "Test for weak password policy",
      "Test custom claims for privilege escalation"
    );
  }

  if (profile.hasStorage || !profile.hasStorage) {
    tests.push(
      "Test Storage bucket for public listing",
      "Test Storage security rules for unauthenticated upload",
      "Check for sensitive files in Storage bucket"
    );
  }

  tests.push(
    "Enumerate Cloud Functions endpoints",
    "Test Cloud Functions for unauthenticated invocation",
    "Check for exposed Admin SDK credentials on web server",
    "Test for GCP IAM privilege escalation via Firebase service account"
  );

  return tests;
}
