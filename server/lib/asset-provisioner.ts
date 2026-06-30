/**
 * Asset Provisioner — Build & Deploy Pipeline for Downloadable Assets
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * When a bug bounty program's in-scope assets are SOURCE_CODE, DOWNLOADABLE_EXECUTABLES,
 * or SMART_CONTRACT, they cannot be scanned as live URLs. This module:
 *
 *   1. Clones/downloads the asset to the scan server
 *   2. Builds it using the LLM-generated build instructions
 *   3. Deploys it in a Docker container for local scanning
 *   4. Returns the local target URL for the scan pipeline to use
 *
 * Architecture:
 *   Engagement Builder → buildRequirements → this provisioner → SSH to scan server
 *     → git clone / wget → build → docker run → return localhost:PORT
 *
 * Integration:
 *   - scan-server-executor.ts → SSH command execution
 *   - engagement-builder.ts → provides buildRequirements from LLM
 *   - digitalocean-infra.ts → optional: provision dedicated droplet for large builds
 */

import { executeRawCommand, executeTool, checkScanServerStatus } from "./scan-server-executor";
import { broadcastOpsUpdate } from "./engagement-orchestrator";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BuildRequirement {
  assetName: string;
  assetType: string;
  acquisitionMethod: string;
  buildInstructions: string[];
  deployInstructions: string[];
  dependencies: string[];
  sponsorInstructions?: string | null;
  hasHostedInstance?: boolean;
  hostedInstanceUrl?: string | null;
}

export interface ProvisioningResult {
  assetName: string;
  status: "success" | "partial" | "failed" | "skipped";
  /** The local URL where the asset is accessible for scanning (e.g., http://localhost:9100) */
  localTargetUrl?: string;
  /** The Docker container ID if deployed via Docker */
  containerId?: string;
  /** The directory where the source was cloned/downloaded */
  sourceDir?: string;
  /** Build output log */
  buildLog: string;
  /** Deploy output log */
  deployLog: string;
  /** Error message if failed */
  error?: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Tools that were installed during provisioning */
  installedTools: string[];
}

export interface ToolInstallResult {
  tool: string;
  status: "installed" | "already_installed" | "failed";
  installCommand: string;
  output: string;
  error?: string;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const PROVISION_BASE_DIR = "/opt/ac3-provisions";
const DOCKER_NETWORK = "ac3-provision-net";
const BASE_PORT = 9100; // Provisioned assets start at port 9100
let nextPort = BASE_PORT;

// Maximum time for each step
const CLONE_TIMEOUT = 300;   // 5 min
const BUILD_TIMEOUT = 600;   // 10 min
const DEPLOY_TIMEOUT = 120;  // 2 min
const TOOL_INSTALL_TIMEOUT = 180; // 3 min

// ─── Asset Provisioning ─────────────────────────────────────────────────────

/**
 * Provision a single buildable asset on the scan server.
 * Executes: acquire → install dependencies → build → deploy → verify
 */
export async function provisionAsset(
  br: BuildRequirement,
  engagementId: number,
  options?: { port?: number; skipBuild?: boolean; skipDeploy?: boolean }
): Promise<ProvisioningResult> {
  const startTime = Date.now();
  const port = options?.port || nextPort++;
  const safeAssetName = br.assetName.replace(/[^a-zA-Z0-9_-]/g, "_").substring(0, 50);
  const assetDir = `${PROVISION_BASE_DIR}/${engagementId}/${safeAssetName}`;
  const containerName = `ac3-${engagementId}-${safeAssetName}`.substring(0, 63);

  let buildLog = "";
  let deployLog = "";
  const installedTools: string[] = [];

  // Helper to broadcast provisioning progress
  const broadcast = (stage: string, status: string, detail: string, progress?: number) => {
    try {
      broadcastOpsUpdate(engagementId, {
        type: "provision_progress",
        assetName: br.assetName,
        stage,
        status,
        detail,
        progress: progress ?? undefined,
        elapsedMs: Date.now() - startTime,
      });
    } catch (_) { /* non-critical */ }
  };

  try {
    // 0. Ensure base directory and Docker network exist
    broadcast("init", "running", `Preparing workspace for ${br.assetName}...`, 0);
    await executeRawCommand(
      `mkdir -p ${assetDir} && docker network create ${DOCKER_NETWORK} 2>/dev/null || true`,
      30000
    );

    // 1. Acquire the asset (git clone, wget, etc.)
    broadcast("acquire", "running", `Cloning/downloading ${br.assetName}...`, 10);
    buildLog += `\n=== ACQUISITION ===\n`;
    const acquisitionCmd = deriveAcquisitionCommand(br, assetDir);
    const acqResult = await executeRawCommand(acquisitionCmd, CLONE_TIMEOUT * 1000);
    buildLog += `$ ${acquisitionCmd}\n${acqResult.stdout}\n`;
    if (acqResult.exitCode !== 0) {
      buildLog += `STDERR: ${acqResult.stderr}\n`;
      // Try alternative acquisition if git clone fails
      if (br.acquisitionMethod.includes("git clone") && acqResult.exitCode !== 0) {
        const altCmd = `cd ${assetDir} && wget -q "${br.assetName}/archive/refs/heads/main.zip" -O source.zip && unzip -q source.zip 2>/dev/null || true`;
        const altResult = await executeRawCommand(altCmd, CLONE_TIMEOUT * 1000);
        buildLog += `\n=== FALLBACK ACQUISITION ===\n$ ${altCmd}\n${altResult.stdout}\n`;
      }
    }

    // 2. Install dependencies
    broadcast("acquire", "complete", `Source acquired successfully`, 25);
    if (br.dependencies && br.dependencies.length > 0) {
      broadcast("dependencies", "running", `Installing ${br.dependencies.length} dependencies...`, 30);
      buildLog += `\n=== DEPENDENCIES ===\n`;
      for (const dep of br.dependencies) {
        const depCmd = deriveInstallCommand(dep);
        if (depCmd) {
          const depResult = await executeRawCommand(depCmd, TOOL_INSTALL_TIMEOUT * 1000);
          buildLog += `$ ${depCmd}\n${depResult.stdout.substring(0, 500)}\n`;
          if (depResult.exitCode === 0) installedTools.push(dep);
        }
      }
    }

    // 3. Build (unless skipped or has hosted instance)
    if (!options?.skipBuild && !br.hasHostedInstance) {
      broadcast("build", "running", `Building ${br.assetName}...`, 50);
      buildLog += `\n=== BUILD ===\n`;
      if (br.buildInstructions && br.buildInstructions.length > 0) {
        for (const step of br.buildInstructions) {
          // Prefix each build step with cd to the asset directory
          const buildCmd = step.startsWith("cd ") ? step : `cd ${assetDir} && ${step}`;
          const buildResult = await executeRawCommand(buildCmd, BUILD_TIMEOUT * 1000);
          buildLog += `$ ${step}\n${buildResult.stdout.substring(0, 1000)}\n`;
          if (buildResult.exitCode !== 0) {
            buildLog += `STDERR: ${buildResult.stderr.substring(0, 500)}\n`;
            buildLog += `WARNING: Build step failed (exit ${buildResult.exitCode}), continuing...\n`;
          }
        }
      } else {
        // Auto-detect build system
        buildLog += `No explicit build instructions. Auto-detecting...\n`;
        const autoResult = await autoDetectAndBuild(assetDir);
        buildLog += autoResult.log;
      }
    }

    // 4. Deploy (Docker preferred)
    if (!options?.skipDeploy) {
      broadcast("deploy", "running", `Deploying to Docker container on port ${port}...`, 75);
      deployLog += `\n=== DEPLOY ===\n`;
      if (br.hasHostedInstance && br.hostedInstanceUrl) {
        deployLog += `Using hosted instance: ${br.hostedInstanceUrl}\n`;
        return {
          assetName: br.assetName,
          status: "success",
          localTargetUrl: br.hostedInstanceUrl,
          sourceDir: assetDir,
          buildLog,
          deployLog,
          durationMs: Date.now() - startTime,
          installedTools,
        };
      }

      if (br.deployInstructions && br.deployInstructions.length > 0) {
        for (const step of br.deployInstructions) {
          // Replace placeholder port references with the actual assigned port
          const deployCmd = step
            .replace(/\$\{PORT\}/g, String(port))
            .replace(/PORT=\d+/g, `PORT=${port}`)
            .replace(/-p\s+\d+:/g, `-p ${port}:`);
          const fullCmd = deployCmd.startsWith("cd ") ? deployCmd : `cd ${assetDir} && ${deployCmd}`;
          const deployResult = await executeRawCommand(fullCmd, DEPLOY_TIMEOUT * 1000);
          deployLog += `$ ${deployCmd}\n${deployResult.stdout.substring(0, 500)}\n`;
          if (deployResult.exitCode !== 0) {
            deployLog += `STDERR: ${deployResult.stderr.substring(0, 500)}\n`;
          }
        }
      } else {
        // Auto-deploy with Docker
        deployLog += `No explicit deploy instructions. Auto-deploying with Docker...\n`;
        const autoDeployResult = await autoDockerDeploy(assetDir, containerName, port);
        deployLog += autoDeployResult.log;
      }

      // 5. Verify the deployment is accessible
      broadcast("verify", "running", `Verifying deployment on port ${port}...`, 90);
      const verifyResult = await executeRawCommand(
        `sleep 5 && curl -s -o /dev/null -w '%{http_code}' http://localhost:${port}/ 2>/dev/null || echo 'unreachable'`,
        30000
      );
      const httpCode = verifyResult.stdout.trim();
      deployLog += `\n=== VERIFY ===\nHTTP status: ${httpCode}\n`;

      if (httpCode === "unreachable" || httpCode === "000") {
        broadcast("verify", "warning", `Asset deployed but not responding on port ${port}. May need manual configuration.`, 95);
        return {
          assetName: br.assetName,
          status: "partial",
          localTargetUrl: `http://localhost:${port}`,
          containerId: containerName,
          sourceDir: assetDir,
          buildLog,
          deployLog: deployLog + "\nWARNING: Asset deployed but not responding on expected port. May need manual configuration.",
          durationMs: Date.now() - startTime,
          installedTools,
        };
      }
    }

    broadcast("complete", "success", `Asset provisioned successfully at http://localhost:${port}`, 100);
    return {
      assetName: br.assetName,
      status: "success",
      localTargetUrl: `http://localhost:${port}`,
      containerId: containerName,
      sourceDir: assetDir,
      buildLog,
      deployLog,
      durationMs: Date.now() - startTime,
      installedTools,
    };
  } catch (error: any) {
    broadcast("error", "failed", `Provisioning failed: ${error.message}`, 100);
    return {
      assetName: br.assetName,
      status: "failed",
      sourceDir: assetDir,
      buildLog,
      deployLog,
      error: error.message || String(error),
      durationMs: Date.now() - startTime,
      installedTools,
    };
  }
}

/**
 * Provision all buildable assets for an engagement.
 */
export async function provisionAllAssets(
  buildRequirements: BuildRequirement[],
  engagementId: number
): Promise<ProvisioningResult[]> {
  const results: ProvisioningResult[] = [];
  let port = BASE_PORT;

  for (const br of buildRequirements) {
    const result = await provisionAsset(br, engagementId, { port });
    results.push(result);
    port++;
  }

  return results;
}

// ─── Tool Installation ──────────────────────────────────────────────────────

/**
 * Install specialized security tools on the scan server based on LLM-generated requirements.
 */
export async function installTools(
  toolRequirements: Array<{
    tool: string;
    installCommand: string;
    purpose: string;
    category: string;
    required: boolean;
    alternatives: string[];
  }>
): Promise<ToolInstallResult[]> {
  const results: ToolInstallResult[] = [];

  for (const tr of toolRequirements) {
    // First check if the tool is already installed
    const checkResult = await executeRawCommand(
      `which ${tr.tool} 2>/dev/null || command -v ${tr.tool} 2>/dev/null`,
      10000
    );

    if (checkResult.exitCode === 0 && checkResult.stdout.trim()) {
      results.push({
        tool: tr.tool,
        status: "already_installed",
        installCommand: tr.installCommand,
        output: `Already installed at: ${checkResult.stdout.trim()}`,
      });
      continue;
    }

    // Install the tool
    try {
      const installResult = await executeRawCommand(
        tr.installCommand,
        TOOL_INSTALL_TIMEOUT * 1000
      );

      if (installResult.exitCode === 0) {
        results.push({
          tool: tr.tool,
          status: "installed",
          installCommand: tr.installCommand,
          output: installResult.stdout.substring(0, 500),
        });
      } else {
        // Try alternatives
        let installed = false;
        for (const alt of tr.alternatives) {
          const altCheckResult = await executeRawCommand(
            `which ${alt} 2>/dev/null`,
            10000
          );
          if (altCheckResult.exitCode === 0) {
            results.push({
              tool: tr.tool,
              status: "already_installed",
              installCommand: tr.installCommand,
              output: `Alternative '${alt}' already available at: ${altCheckResult.stdout.trim()}`,
            });
            installed = true;
            break;
          }
        }
        if (!installed) {
          results.push({
            tool: tr.tool,
            status: "failed",
            installCommand: tr.installCommand,
            output: installResult.stdout.substring(0, 500),
            error: installResult.stderr.substring(0, 500),
          });
        }
      }
    } catch (error: any) {
      results.push({
        tool: tr.tool,
        status: "failed",
        installCommand: tr.installCommand,
        output: "",
        error: error.message || String(error),
      });
    }
  }

  return results;
}

/**
 * Clean up provisioned assets for an engagement (remove containers and source).
 */
export async function cleanupProvisionedAssets(engagementId: number): Promise<string> {
  let log = "";

  // Stop and remove all containers for this engagement
  const listResult = await executeRawCommand(
    `docker ps -a --filter "name=ac3-${engagementId}-" --format "{{.Names}}"`,
    30000
  );
  const containers = listResult.stdout.trim().split("\n").filter(Boolean);
  for (const c of containers) {
    await executeRawCommand(`docker rm -f ${c}`, 30000);
    log += `Removed container: ${c}\n`;
  }

  // Remove source directory
  const rmResult = await executeRawCommand(
    `rm -rf ${PROVISION_BASE_DIR}/${engagementId}`,
    30000
  );
  log += `Removed source directory: ${PROVISION_BASE_DIR}/${engagementId}\n`;

  return log;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function deriveAcquisitionCommand(br: BuildRequirement, assetDir: string): string {
  const method = br.acquisitionMethod.toLowerCase();

  if (method.includes("git clone")) {
    // Extract the URL from the acquisition method or use the asset name
    const urlMatch = method.match(/git clone\s+(https?:\/\/\S+)/i);
    const repoUrl = urlMatch ? urlMatch[1] : br.assetName;
    return `git clone --depth 1 ${repoUrl} ${assetDir}/source 2>&1`;
  }

  if (method.includes("wget") || method.includes("download")) {
    const urlMatch = method.match(/(https?:\/\/\S+)/);
    const downloadUrl = urlMatch ? urlMatch[1] : br.assetName;
    return `wget -q "${downloadUrl}" -P ${assetDir}/ 2>&1`;
  }

  if (method.includes("npm") || method.includes("npx")) {
    return `cd ${assetDir} && ${br.acquisitionMethod} 2>&1`;
  }

  // Default: try git clone if the asset name looks like a URL
  if (br.assetName.startsWith("http")) {
    return `git clone --depth 1 ${br.assetName} ${assetDir}/source 2>&1`;
  }

  return `echo "Unknown acquisition method: ${br.acquisitionMethod}"`;
}

function deriveInstallCommand(dependency: string): string | null {
  const dep = dependency.toLowerCase();

  // Common runtime/language dependencies
  const aptPackages: Record<string, string> = {
    "node": "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs",
    "nodejs": "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs",
    "python": "apt-get install -y python3 python3-pip python3-venv",
    "python3": "apt-get install -y python3 python3-pip python3-venv",
    "go": "apt-get install -y golang-go",
    "golang": "apt-get install -y golang-go",
    "rust": "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
    "java": "apt-get install -y default-jdk",
    "jdk": "apt-get install -y default-jdk",
    "docker": "apt-get install -y docker.io && systemctl start docker",
    "docker-compose": "apt-get install -y docker-compose",
    "make": "apt-get install -y build-essential",
    "gcc": "apt-get install -y build-essential",
    "cmake": "apt-get install -y cmake",
    "mysql": "apt-get install -y mysql-client",
    "postgresql": "apt-get install -y postgresql-client",
    "redis": "apt-get install -y redis-tools",
    "mongodb": "apt-get install -y mongodb-clients",
  };

  for (const [key, cmd] of Object.entries(aptPackages)) {
    if (dep.includes(key)) return cmd;
  }

  // If it looks like a pip package
  if (dep.includes("pip") || dep.includes("python")) {
    return `pip3 install ${dependency}`;
  }

  // If it looks like an npm package
  if (dep.includes("npm") || dep.includes("node")) {
    return `npm install -g ${dependency}`;
  }

  // Generic apt-get attempt
  return `apt-get install -y ${dependency} 2>/dev/null || echo "Could not install: ${dependency}"`;
}

async function autoDetectAndBuild(assetDir: string): Promise<{ log: string }> {
  let log = "";
  const sourceDir = `${assetDir}/source`;

  // Check for common build files
  const checkResult = await executeRawCommand(
    `ls ${sourceDir}/package.json ${sourceDir}/Makefile ${sourceDir}/Cargo.toml ${sourceDir}/go.mod ${sourceDir}/setup.py ${sourceDir}/Dockerfile ${sourceDir}/docker-compose.yml 2>/dev/null || echo "none"`,
    10000
  );
  const files = checkResult.stdout.trim();
  log += `Detected build files: ${files}\n`;

  if (files.includes("docker-compose.yml")) {
    const result = await executeRawCommand(`cd ${sourceDir} && docker-compose build 2>&1`, BUILD_TIMEOUT * 1000);
    log += `docker-compose build: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("Dockerfile")) {
    const result = await executeRawCommand(`cd ${sourceDir} && docker build -t ac3-provision . 2>&1`, BUILD_TIMEOUT * 1000);
    log += `docker build: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("package.json")) {
    const result = await executeRawCommand(`cd ${sourceDir} && npm install 2>&1 && npm run build 2>&1 || true`, BUILD_TIMEOUT * 1000);
    log += `npm install + build: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("Makefile")) {
    const result = await executeRawCommand(`cd ${sourceDir} && make 2>&1`, BUILD_TIMEOUT * 1000);
    log += `make: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("Cargo.toml")) {
    const result = await executeRawCommand(`cd ${sourceDir} && cargo build --release 2>&1`, BUILD_TIMEOUT * 1000);
    log += `cargo build: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("go.mod")) {
    const result = await executeRawCommand(`cd ${sourceDir} && go build ./... 2>&1`, BUILD_TIMEOUT * 1000);
    log += `go build: ${result.stdout.substring(0, 1000)}\n`;
  } else if (files.includes("setup.py")) {
    const result = await executeRawCommand(`cd ${sourceDir} && pip3 install -e . 2>&1`, BUILD_TIMEOUT * 1000);
    log += `pip install: ${result.stdout.substring(0, 1000)}\n`;
  } else {
    log += `No recognized build system found. Source code available for SAST scanning at ${sourceDir}\n`;
  }

  return { log };
}

async function autoDockerDeploy(
  assetDir: string,
  containerName: string,
  port: number
): Promise<{ log: string }> {
  let log = "";
  const sourceDir = `${assetDir}/source`;

  // Check for docker-compose first
  const checkResult = await executeRawCommand(
    `ls ${sourceDir}/docker-compose.yml ${sourceDir}/Dockerfile 2>/dev/null || echo "none"`,
    10000
  );

  if (checkResult.stdout.includes("docker-compose.yml")) {
    const result = await executeRawCommand(
      `cd ${sourceDir} && PORT=${port} docker-compose up -d 2>&1`,
      DEPLOY_TIMEOUT * 1000
    );
    log += `docker-compose up: ${result.stdout.substring(0, 500)}\n`;
  } else if (checkResult.stdout.includes("Dockerfile")) {
    const buildResult = await executeRawCommand(
      `cd ${sourceDir} && docker build -t ${containerName} . 2>&1`,
      BUILD_TIMEOUT * 1000
    );
    log += `docker build: ${buildResult.stdout.substring(0, 500)}\n`;

    const runResult = await executeRawCommand(
      `docker run -d --name ${containerName} --network ${DOCKER_NETWORK} -p ${port}:${port} -e PORT=${port} ${containerName} 2>&1`,
      DEPLOY_TIMEOUT * 1000
    );
    log += `docker run: ${runResult.stdout.substring(0, 500)}\n`;
  } else {
    // Try to create a generic Dockerfile for Node.js/Python projects
    const pkgCheck = await executeRawCommand(`cat ${sourceDir}/package.json 2>/dev/null | head -1`, 10000);
    if (pkgCheck.exitCode === 0) {
      const dockerfile = `FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN npm install --production\nEXPOSE ${port}\nENV PORT=${port}\nCMD ["npm", "start"]`;
      await executeRawCommand(`echo '${dockerfile}' > ${sourceDir}/Dockerfile.ac3`, 10000);
      const buildResult = await executeRawCommand(
        `cd ${sourceDir} && docker build -f Dockerfile.ac3 -t ${containerName} . 2>&1`,
        BUILD_TIMEOUT * 1000
      );
      log += `Auto-generated Dockerfile (Node.js): ${buildResult.stdout.substring(0, 500)}\n`;
      const runResult = await executeRawCommand(
        `docker run -d --name ${containerName} --network ${DOCKER_NETWORK} -p ${port}:${port} ${containerName} 2>&1`,
        DEPLOY_TIMEOUT * 1000
      );
      log += `docker run: ${runResult.stdout.substring(0, 500)}\n`;
    } else {
      log += `No Dockerfile or docker-compose.yml found. Source available for SAST at ${sourceDir}. Manual deployment required.\n`;
    }
  }

  return { log };
}
