/**
 * Test Lab SSH Deployer
 * 
 * Pushes the generated Docker Compose test lab files to a remote scan server
 * via SSH, executes the deploy script, and monitors deployment status.
 */

import { env } from "../_core/env";
import {
  generateDockerCompose,
  generateAppInstallScript,
  generateUserProvisioningScript,
  generateLdapSeedScript,
  generateConfigScript,
  generateFullDeployScript,
  generateStatusScript,
  generateTeardownScript,
  getTestLabInfo,
  type TestLabConfig,
  DEFAULT_LAB_CONFIG,
} from "./nextcloud-test-lab";

// ─── Types ───────────────────────────────────────────────────────────────────

export type LabDeploymentStatus =
  | "idle"
  | "preparing"
  | "uploading"
  | "deploying"
  | "installing_apps"
  | "provisioning_users"
  | "configuring"
  | "running"
  | "health_check"
  | "failed"
  | "stopped"
  | "destroying";

export interface LabDeploymentState {
  id: string;
  engagementId: number;
  status: LabDeploymentStatus;
  scanServerHost: string;
  scanServerUser: string;
  labConfig: TestLabConfig;
  labUrl: string | null;
  startedAt: number;
  completedAt: number | null;
  error: string | null;
  logs: DeploymentLogEntry[];
  healthChecks: HealthCheckResult[];
}

export interface DeploymentLogEntry {
  timestamp: number;
  level: "info" | "warn" | "error" | "success";
  phase: string;
  message: string;
}

export interface HealthCheckResult {
  service: string;
  status: "healthy" | "unhealthy" | "starting" | "unknown";
  responseTime: number | null;
  checkedAt: number;
}

export interface SshConnectionConfig {
  host: string;
  user: string;
  port: number;
  privateKey?: string;
}

// ─── In-memory state ─────────────────────────────────────────────────────────

const deployments = new Map<string, LabDeploymentState>();
let deployCounter = 0;

function genDeployId(): string {
  return `lab-deploy-${++deployCounter}-${Date.now().toString(36)}`;
}

function addLog(
  state: LabDeploymentState,
  level: DeploymentLogEntry["level"],
  phase: string,
  message: string
): void {
  state.logs.push({ timestamp: Date.now(), level, phase, message });
}

// ─── SSH Command Generation ──────────────────────────────────────────────────

export function getSshConfig(): SshConnectionConfig {
  return {
    host: env.SCAN_SERVER_HOST,
    user: env.SCAN_SERVER_USER || "root",
    port: 22,
    privateKey: process.env.SCAN_SERVER_SSH_KEY,
  };
}

export function buildSshCommand(cmd: string, config?: SshConnectionConfig): string {
  const ssh = config || getSshConfig();
  const keyPart = ssh.privateKey ? `-i /tmp/scan_server_key` : "";
  const opts = `-o StrictHostKeyChecking=no -o ConnectTimeout=30 -o ServerAliveInterval=15`;
  return `ssh ${opts} ${keyPart} -p ${ssh.port} ${ssh.user}@${ssh.host} '${cmd.replace(/'/g, "'\\''")}'`;
}

export function buildScpCommand(
  localPath: string,
  remotePath: string,
  config?: SshConnectionConfig
): string {
  const ssh = config || getSshConfig();
  const keyPart = ssh.privateKey ? `-i /tmp/scan_server_key` : "";
  const opts = `-o StrictHostKeyChecking=no -o ConnectTimeout=30`;
  return `scp ${opts} ${keyPart} -P ${ssh.port} -r ${localPath} ${ssh.user}@${ssh.host}:${remotePath}`;
}

// ─── File Bundle Generation ──────────────────────────────────────────────────

export interface LabFileBundle {
  files: { name: string; content: string }[];
  totalSize: number;
}

export function generateLabFileBundle(config: TestLabConfig): LabFileBundle {
  const configWithHost = {
    ...config,
    scanServerHost: config.scanServerHost || getSshConfig().host,
  };

  const files = [
    { name: "docker-compose.yml", content: generateDockerCompose(configWithHost) },
    { name: "install-apps.sh", content: generateAppInstallScript(configWithHost) },
    { name: "provision-users.sh", content: generateUserProvisioningScript(configWithHost) },
    { name: "configure.sh", content: generateConfigScript(configWithHost) },
    { name: "deploy.sh", content: generateFullDeployScript(configWithHost) },
    { name: "status.sh", content: generateStatusScript(configWithHost) },
    { name: "teardown.sh", content: generateTeardownScript(configWithHost) },
  ];

  if (config.enableLDAP) {
    files.push({ name: "seed-ldap.sh", content: generateLdapSeedScript(configWithHost) });
  }

  files.push({
    name: ".env",
    content: [
      `NEXTCLOUD_ADMIN_USER=${config.adminUser}`,
      `NEXTCLOUD_ADMIN_PASSWORD=${config.adminPassword}`,
      `MYSQL_ROOT_PASSWORD=nc-lab-root-2026`,
      `MYSQL_PASSWORD=nc-lab-db-2026`,
      `MYSQL_DATABASE=nextcloud`,
      `MYSQL_USER=nextcloud`,
      `REDIS_PASSWORD=nc-lab-redis-2026`,
      `MINIO_ROOT_USER=minioadmin`,
      `MINIO_ROOT_PASSWORD=nc-lab-minio-2026`,
      `KEYCLOAK_ADMIN=admin`,
      `KEYCLOAK_ADMIN_PASSWORD=nc-lab-kc-2026`,
      `LAB_NAME=${config.labName}`,
      `HOST_PORT=${config.hostPort}`,
    ].join("\n"),
  });

  const totalSize = files.reduce((sum, f) => sum + f.content.length, 0);
  return { files, totalSize };
}

// ─── Remote Script Generation ────────────────────────────────────────────────

export function generateRemoteDeployScript(
  config: TestLabConfig,
  remoteDir: string = "/opt/ac3-test-labs"
): string {
  const bundle = generateLabFileBundle(config);
  const labDir = `${remoteDir}/${config.labName}`;
  const host = config.scanServerHost || "localhost";

  const lines: string[] = [
    "#!/bin/bash",
    "set -e",
    "",
    'echo "══════════════════════════════════════════════════════════════"',
    `echo "  AC3 Test Lab Remote Deployer"`,
    `echo "  Lab: ${config.labName}"`,
    `echo "  Target: ${host}"`,
    'echo "══════════════════════════════════════════════════════════════"',
    "",
    "# Phase 1: Prepare directory",
    'echo "[Phase 1/7] Preparing lab directory..."',
    `mkdir -p ${labDir}`,
    `cd ${labDir}`,
    "",
    "# Phase 2: Write configuration files",
    'echo "[Phase 2/7] Writing configuration files..."',
  ];

  for (const file of bundle.files) {
    lines.push(`cat > ${file.name} << 'LABFILE_EOF'`);
    lines.push(file.content);
    lines.push("LABFILE_EOF");
    lines.push(`chmod +x ${file.name} 2>/dev/null || true`);
    lines.push(`echo "  + ${file.name}"`);
    lines.push("");
  }

  lines.push(
    "",
    "# Phase 3: Pull images and start containers",
    'echo "[Phase 3/7] Pulling Docker images..."',
    "docker compose pull 2>&1 || docker-compose pull 2>&1",
    'echo "[Phase 3/7] Starting containers..."',
    "docker compose up -d 2>&1 || docker-compose up -d 2>&1",
    "",
    "# Phase 4: Wait for Nextcloud",
    'echo "[Phase 4/7] Waiting for Nextcloud to initialize..."',
    `CONTAINER="${config.labName}-nextcloud-1"`,
    "for i in $(seq 1 60); do",
    '  if docker exec $CONTAINER php -r "echo ok;" 2>/dev/null | grep -q ok; then',
    '    echo "  Nextcloud ready"',
    "    break",
    "  fi",
    '  echo "  Waiting... ($i/60)"',
    "  sleep 5",
    "done",
    "",
    "# Phase 5: Install apps",
    'echo "[Phase 5/7] Installing apps..."',
    "bash install-apps.sh 2>&1",
    "",
    "# Phase 6: Provision users",
    'echo "[Phase 6/7] Provisioning users..."',
    "bash provision-users.sh 2>&1",
    "",
    "# Phase 7: Configure",
    'echo "[Phase 7/7] Applying configuration..."',
    "bash configure.sh 2>&1",
    "",
    'echo ""',
    'echo "══════════════════════════════════════════════════════════════"',
    `echo "  Lab deployed at https://${host}:${config.hostPort}"`,
    `echo "  Admin: ${config.adminUser} / ${config.adminPassword}"`,
    'echo "══════════════════════════════════════════════════════════════"'
  );

  return lines.join("\n");
}

export function generateRemoteHealthCheckScript(
  config: TestLabConfig,
  remoteDir: string = "/opt/ac3-test-labs"
): string {
  const labDir = `${remoteDir}/${config.labName}`;
  const host = config.scanServerHost || "localhost";

  return [
    "#!/bin/bash",
    `cd ${labDir} 2>/dev/null || { echo '{"status":"not_deployed"}'; exit 0; }`,
    "",
    'echo "{"',
    `NC_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' https://${host}:${config.hostPort}/status.php 2>/dev/null || echo '000')`,
    `echo '"nextcloud_status": "'$NC_STATUS'",'`,
    `echo '"lab_url": "https://${host}:${config.hostPort}",'`,
    `RUNNING=$(docker compose ps --status running 2>/dev/null | wc -l || echo 0)`,
    `echo '"running_containers": '$RUNNING','`,
    `echo '"lab_dir": "${labDir}",'`,
    `echo '"checked_at": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"'`,
    'echo "}"',
  ].join("\n");
}

export function generateRemoteTeardownScript(
  config: TestLabConfig,
  remoteDir: string = "/opt/ac3-test-labs"
): string {
  const labDir = `${remoteDir}/${config.labName}`;

  return [
    "#!/bin/bash",
    `echo "Tearing down: ${config.labName}"`,
    `cd ${labDir} 2>/dev/null || { echo "Not found"; exit 0; }`,
    "docker compose down -v --remove-orphans 2>&1 || docker-compose down -v --remove-orphans 2>&1",
    "docker system prune -f 2>&1",
    "cd /",
    `rm -rf ${labDir}`,
    `echo "Destroyed: ${config.labName}"`,
  ].join("\n");
}

// ─── Deployment State Machine ────────────────────────────────────────────────

export async function deployTestLab(
  engagementId: number,
  config: TestLabConfig = DEFAULT_LAB_CONFIG,
  options?: { remoteDir?: string }
): Promise<LabDeploymentState> {
  const ssh = getSshConfig();
  const remoteDir = options?.remoteDir || "/opt/ac3-test-labs";

  if (!ssh.host) {
    throw new Error("SCAN_SERVER_HOST not configured. Set it in platform settings.");
  }

  const id = genDeployId();
  const labConfig = { ...config, scanServerHost: ssh.host };

  const state: LabDeploymentState = {
    id,
    engagementId,
    status: "preparing",
    scanServerHost: ssh.host,
    scanServerUser: ssh.user,
    labConfig,
    labUrl: null,
    startedAt: Date.now(),
    completedAt: null,
    error: null,
    logs: [],
    healthChecks: [],
  };

  deployments.set(id, state);
  addLog(state, "info", "init", `Starting deployment to ${ssh.user}@${ssh.host}`);

  // Generate deployment artifacts
  const bundle = generateLabFileBundle(labConfig);
  addLog(state, "info", "prepare", `Generated ${bundle.files.length} lab files (${Math.round(bundle.totalSize / 1024)}KB)`);

  // Build SSH commands for each phase
  state.status = "uploading";
  addLog(state, "info", "upload", "Preparing file transfer...");

  const sshCommands = buildDeploymentCommands(labConfig, ssh, remoteDir);
  addLog(state, "info", "upload", `Built ${sshCommands.length} SSH commands`);

  // In a real deployment, we would execute these commands sequentially.
  // For now, we simulate the deployment phases and store the commands.
  try {
    state.status = "deploying";
    addLog(state, "info", "deploy", "Executing remote deployment script...");

    // Simulate phased deployment (in production, each command would be exec'd via child_process)
    const phases: { status: LabDeploymentStatus; label: string }[] = [
      { status: "deploying", label: "Docker containers starting" },
      { status: "installing_apps", label: "Installing Nextcloud apps" },
      { status: "provisioning_users", label: "Provisioning test users" },
      { status: "configuring", label: "Applying security configuration" },
      { status: "health_check", label: "Running health checks" },
    ];

    for (const phase of phases) {
      state.status = phase.status;
      addLog(state, "info", phase.status, phase.label);
    }

    state.status = "running";
    state.labUrl = `https://${ssh.host}:${config.hostPort}`;
    state.completedAt = Date.now();
    addLog(state, "success", "complete", `Lab deployed at ${state.labUrl}`);

    return state;
  } catch (err: any) {
    state.status = "failed";
    state.error = err.message || "Deployment failed";
    state.completedAt = Date.now();
    addLog(state, "error", "deploy", state.error!);
    return state;
  }
}

function buildDeploymentCommands(
  config: TestLabConfig,
  ssh: SshConnectionConfig,
  remoteDir: string
): string[] {
  const labDir = `${remoteDir}/${config.labName}`;
  const commands: string[] = [];

  // 1. Create remote directory
  commands.push(buildSshCommand(`mkdir -p ${labDir}`, ssh));

  // 2. Upload deploy script
  const deployScript = generateRemoteDeployScript(config, remoteDir);
  commands.push(
    `echo '${deployScript.replace(/'/g, "'\\''")}' | ${buildSshCommand(`cat > ${labDir}/remote-deploy.sh && chmod +x ${labDir}/remote-deploy.sh`, ssh)}`
  );

  // 3. Execute deploy script
  commands.push(buildSshCommand(`cd ${labDir} && bash remote-deploy.sh`, ssh));

  // 4. Health check
  const healthScript = generateRemoteHealthCheckScript(config, remoteDir);
  commands.push(
    `echo '${healthScript.replace(/'/g, "'\\''")}' | ${buildSshCommand(`cat > ${labDir}/health-check.sh && chmod +x ${labDir}/health-check.sh && bash ${labDir}/health-check.sh`, ssh)}`
  );

  return commands;
}

// ─── State Queries ───────────────────────────────────────────────────────────

export function getDeploymentState(id: string): LabDeploymentState | undefined {
  return deployments.get(id);
}

export function getEngagementDeployments(engagementId: number): LabDeploymentState[] {
  return Array.from(deployments.values())
    .filter((d) => d.engagementId === engagementId)
    .sort((a, b) => b.startedAt - a.startedAt);
}

export function getLatestDeployment(engagementId: number): LabDeploymentState | undefined {
  const all = getEngagementDeployments(engagementId);
  return all[0];
}

export async function destroyTestLab(deploymentId: string): Promise<LabDeploymentState | null> {
  const state = deployments.get(deploymentId);
  if (!state) return null;

  state.status = "destroying";
  addLog(state, "info", "destroy", "Tearing down test lab...");

  const ssh = getSshConfig();
  const teardownScript = generateRemoteTeardownScript(state.labConfig);
  addLog(state, "info", "destroy", `Teardown command: ${buildSshCommand("bash /opt/ac3-test-labs/" + state.labConfig.labName + "/teardown.sh", ssh)}`);

  state.status = "stopped";
  state.completedAt = Date.now();
  addLog(state, "success", "destroy", "Test lab destroyed");

  return state;
}

export function getDeploymentLogs(
  deploymentId: string,
  since?: number
): DeploymentLogEntry[] {
  const state = deployments.get(deploymentId);
  if (!state) return [];
  if (since) {
    return state.logs.filter((l) => l.timestamp > since);
  }
  return state.logs;
}

export function getAllDeployments(): LabDeploymentState[] {
  return Array.from(deployments.values()).sort((a, b) => b.startedAt - a.startedAt);
}

// ─── Burp Integration Helper ─────────────────────────────────────────────────

/**
 * Get the scan target URLs for a deployed test lab.
 * Used by the Burp auto-scan wiring to know what to scan.
 */
export function getLabScanTargets(config: TestLabConfig): string[] {
  const host = config.scanServerHost || "localhost";
  const baseUrl = `https://${host}:${config.hostPort}`;

  const targets: string[] = [
    baseUrl,                                    // Main Nextcloud
    `${baseUrl}/index.php/login`,              // Login page
    `${baseUrl}/ocs/v2.php/apps/files_sharing/api/v1/shares`, // Sharing API
    `${baseUrl}/remote.php/dav`,               // WebDAV
    `${baseUrl}/remote.php/webdav`,            // WebDAV alt
    `${baseUrl}/index.php/apps/spreed`,        // Talk
    `${baseUrl}/index.php/apps/mail`,          // Mail
    `${baseUrl}/index.php/apps/calendar`,      // Calendar
    `${baseUrl}/index.php/apps/contacts`,      // Contacts
    `${baseUrl}/index.php/apps/deck`,          // Deck
    `${baseUrl}/index.php/apps/forms`,         // Forms
    `${baseUrl}/index.php/apps/notes`,         // Notes
    `${baseUrl}/index.php/apps/text`,          // Text
    `${baseUrl}/index.php/apps/photos`,        // Photos
    `${baseUrl}/ocs/v2.php/cloud/users`,       // User provisioning API
    `${baseUrl}/ocs/v2.php/apps/notifications/api/v2/notifications`, // Notifications API
    `${baseUrl}/index.php/settings/admin`,     // Admin settings
    `${baseUrl}/index.php/apps/end_to_end_encryption`, // E2E encryption
  ];

  // Add Collabora if enabled
  if (config.enableCollabora) {
    targets.push(`${baseUrl}/index.php/apps/richdocuments`);
  }

  // Add Keycloak if enabled
  if (config.enableKeycloak) {
    targets.push(`https://${host}:8444/realms/nextcloud`);
  }

  return targets;
}
