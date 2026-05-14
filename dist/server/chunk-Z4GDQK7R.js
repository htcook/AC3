import {
  DEFAULT_LAB_CONFIG,
  generateAppInstallScript,
  generateConfigScript,
  generateDockerCompose,
  generateFullDeployScript,
  generateLdapSeedScript,
  generateStatusScript,
  generateTeardownScript,
  generateUserProvisioningScript,
  init_nextcloud_test_lab
} from "./chunk-E5TT6UGW.js";
import {
  ENV,
  init_env
} from "./chunk-GN2OC6SU.js";

// server/lib/test-lab-deployer.ts
init_env();
init_nextcloud_test_lab();
var deployments = /* @__PURE__ */ new Map();
var deployCounter = 0;
function genDeployId() {
  return `lab-deploy-${++deployCounter}-${Date.now().toString(36)}`;
}
function addLog(state, level, phase, message) {
  state.logs.push({ timestamp: Date.now(), level, phase, message });
}
function getSshConfig() {
  return {
    host: ENV.SCAN_SERVER_HOST,
    user: ENV.SCAN_SERVER_USER || "root",
    port: 22,
    privateKey: process.env.SCAN_SERVER_SSH_KEY
  };
}
function buildSshCommand(cmd, config) {
  const ssh = config || getSshConfig();
  const keyPart = ssh.privateKey ? `-i /tmp/scan_server_key` : "";
  const opts = `-o StrictHostKeyChecking=no -o ConnectTimeout=30 -o ServerAliveInterval=15`;
  return `ssh ${opts} ${keyPart} -p ${ssh.port} ${ssh.user}@${ssh.host} '${cmd.replace(/'/g, "'\\''")}'`;
}
function buildScpCommand(localPath, remotePath, config) {
  const ssh = config || getSshConfig();
  const keyPart = ssh.privateKey ? `-i /tmp/scan_server_key` : "";
  const opts = `-o StrictHostKeyChecking=no -o ConnectTimeout=30`;
  return `scp ${opts} ${keyPart} -P ${ssh.port} -r ${localPath} ${ssh.user}@${ssh.host}:${remotePath}`;
}
function generateLabFileBundle(config) {
  const configWithHost = {
    ...config,
    scanServerHost: config.scanServerHost || getSshConfig().host
  };
  const files = [
    { name: "docker-compose.yml", content: generateDockerCompose(configWithHost) },
    { name: "install-apps.sh", content: generateAppInstallScript(configWithHost) },
    { name: "provision-users.sh", content: generateUserProvisioningScript(configWithHost) },
    { name: "configure.sh", content: generateConfigScript(configWithHost) },
    { name: "deploy.sh", content: generateFullDeployScript(configWithHost) },
    { name: "status.sh", content: generateStatusScript(configWithHost) },
    { name: "teardown.sh", content: generateTeardownScript(configWithHost) }
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
      `HOST_PORT=${config.hostPort}`
    ].join("\n")
  });
  const totalSize = files.reduce((sum, f) => sum + f.content.length, 0);
  return { files, totalSize };
}
function generateRemoteDeployScript(config, remoteDir = "/opt/ac3-test-labs") {
  const bundle = generateLabFileBundle(config);
  const labDir = `${remoteDir}/${config.labName}`;
  const host = config.scanServerHost || "localhost";
  const lines = [
    "#!/bin/bash",
    "set -e",
    "",
    'echo "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"',
    `echo "  AC3 Test Lab Remote Deployer"`,
    `echo "  Lab: ${config.labName}"`,
    `echo "  Target: ${host}"`,
    'echo "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"',
    "",
    "# Phase 1: Prepare directory",
    'echo "[Phase 1/7] Preparing lab directory..."',
    `mkdir -p ${labDir}`,
    `cd ${labDir}`,
    "",
    "# Phase 2: Write configuration files",
    'echo "[Phase 2/7] Writing configuration files..."'
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
    'echo "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"',
    `echo "  Lab deployed at https://${host}:${config.hostPort}"`,
    `echo "  Admin: ${config.adminUser} / ${config.adminPassword}"`,
    'echo "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"'
  );
  return lines.join("\n");
}
function generateRemoteHealthCheckScript(config, remoteDir = "/opt/ac3-test-labs") {
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
    'echo "}"'
  ].join("\n");
}
function generateRemoteTeardownScript(config, remoteDir = "/opt/ac3-test-labs") {
  const labDir = `${remoteDir}/${config.labName}`;
  return [
    "#!/bin/bash",
    `echo "Tearing down: ${config.labName}"`,
    `cd ${labDir} 2>/dev/null || { echo "Not found"; exit 0; }`,
    "docker compose down -v --remove-orphans 2>&1 || docker-compose down -v --remove-orphans 2>&1",
    "docker system prune -f 2>&1",
    "cd /",
    `rm -rf ${labDir}`,
    `echo "Destroyed: ${config.labName}"`
  ].join("\n");
}
async function deployTestLab(engagementId, config = DEFAULT_LAB_CONFIG, options) {
  const ssh = getSshConfig();
  const remoteDir = options?.remoteDir || "/opt/ac3-test-labs";
  if (!ssh.host) {
    throw new Error("SCAN_SERVER_HOST not configured. Set it in platform settings.");
  }
  const id = genDeployId();
  const labConfig = { ...config, scanServerHost: ssh.host };
  const state = {
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
    healthChecks: []
  };
  deployments.set(id, state);
  addLog(state, "info", "init", `Starting deployment to ${ssh.user}@${ssh.host}`);
  const bundle = generateLabFileBundle(labConfig);
  addLog(state, "info", "prepare", `Generated ${bundle.files.length} lab files (${Math.round(bundle.totalSize / 1024)}KB)`);
  state.status = "uploading";
  addLog(state, "info", "upload", "Preparing file transfer...");
  const sshCommands = buildDeploymentCommands(labConfig, ssh, remoteDir);
  addLog(state, "info", "upload", `Built ${sshCommands.length} SSH commands`);
  try {
    state.status = "deploying";
    addLog(state, "info", "deploy", "Executing remote deployment script...");
    const phases = [
      { status: "deploying", label: "Docker containers starting" },
      { status: "installing_apps", label: "Installing Nextcloud apps" },
      { status: "provisioning_users", label: "Provisioning test users" },
      { status: "configuring", label: "Applying security configuration" },
      { status: "health_check", label: "Running health checks" }
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
  } catch (err) {
    state.status = "failed";
    state.error = err.message || "Deployment failed";
    state.completedAt = Date.now();
    addLog(state, "error", "deploy", state.error);
    return state;
  }
}
function buildDeploymentCommands(config, ssh, remoteDir) {
  const labDir = `${remoteDir}/${config.labName}`;
  const commands = [];
  commands.push(buildSshCommand(`mkdir -p ${labDir}`, ssh));
  const deployScript = generateRemoteDeployScript(config, remoteDir);
  commands.push(
    `echo '${deployScript.replace(/'/g, "'\\''")}' | ${buildSshCommand(`cat > ${labDir}/remote-deploy.sh && chmod +x ${labDir}/remote-deploy.sh`, ssh)}`
  );
  commands.push(buildSshCommand(`cd ${labDir} && bash remote-deploy.sh`, ssh));
  const healthScript = generateRemoteHealthCheckScript(config, remoteDir);
  commands.push(
    `echo '${healthScript.replace(/'/g, "'\\''")}' | ${buildSshCommand(`cat > ${labDir}/health-check.sh && chmod +x ${labDir}/health-check.sh && bash ${labDir}/health-check.sh`, ssh)}`
  );
  return commands;
}
function getDeploymentState(id) {
  return deployments.get(id);
}
function getEngagementDeployments(engagementId) {
  return Array.from(deployments.values()).filter((d) => d.engagementId === engagementId).sort((a, b) => b.startedAt - a.startedAt);
}
function getLatestDeployment(engagementId) {
  const all = getEngagementDeployments(engagementId);
  return all[0];
}
async function destroyTestLab(deploymentId) {
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
function getDeploymentLogs(deploymentId, since) {
  const state = deployments.get(deploymentId);
  if (!state) return [];
  if (since) {
    return state.logs.filter((l) => l.timestamp > since);
  }
  return state.logs;
}
function getAllDeployments() {
  return Array.from(deployments.values()).sort((a, b) => b.startedAt - a.startedAt);
}
function getLabScanTargets(config) {
  const host = config.scanServerHost || "localhost";
  const baseUrl = `https://${host}:${config.hostPort}`;
  const targets = [
    baseUrl,
    // Main Nextcloud
    `${baseUrl}/index.php/login`,
    // Login page
    `${baseUrl}/ocs/v2.php/apps/files_sharing/api/v1/shares`,
    // Sharing API
    `${baseUrl}/remote.php/dav`,
    // WebDAV
    `${baseUrl}/remote.php/webdav`,
    // WebDAV alt
    `${baseUrl}/index.php/apps/spreed`,
    // Talk
    `${baseUrl}/index.php/apps/mail`,
    // Mail
    `${baseUrl}/index.php/apps/calendar`,
    // Calendar
    `${baseUrl}/index.php/apps/contacts`,
    // Contacts
    `${baseUrl}/index.php/apps/deck`,
    // Deck
    `${baseUrl}/index.php/apps/forms`,
    // Forms
    `${baseUrl}/index.php/apps/notes`,
    // Notes
    `${baseUrl}/index.php/apps/text`,
    // Text
    `${baseUrl}/index.php/apps/photos`,
    // Photos
    `${baseUrl}/ocs/v2.php/cloud/users`,
    // User provisioning API
    `${baseUrl}/ocs/v2.php/apps/notifications/api/v2/notifications`,
    // Notifications API
    `${baseUrl}/index.php/settings/admin`,
    // Admin settings
    `${baseUrl}/index.php/apps/end_to_end_encryption`
    // E2E encryption
  ];
  if (config.enableCollabora) {
    targets.push(`${baseUrl}/index.php/apps/richdocuments`);
  }
  if (config.enableKeycloak) {
    targets.push(`https://${host}:8444/realms/nextcloud`);
  }
  return targets;
}

export {
  getSshConfig,
  buildSshCommand,
  buildScpCommand,
  generateLabFileBundle,
  generateRemoteDeployScript,
  generateRemoteHealthCheckScript,
  generateRemoteTeardownScript,
  deployTestLab,
  getDeploymentState,
  getEngagementDeployments,
  getLatestDeployment,
  destroyTestLab,
  getDeploymentLogs,
  getAllDeployments,
  getLabScanTargets
};
