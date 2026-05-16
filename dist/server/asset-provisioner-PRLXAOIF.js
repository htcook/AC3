import {
  broadcastOpsUpdate,
  init_engagement_orchestrator
} from "./chunk-6WYUJOSH.js";
import "./chunk-5NGBKC7L.js";
import "./chunk-HPRQMQNG.js";
import "./chunk-GTXFXXF6.js";
import "./chunk-K2IN3TSM.js";
import "./chunk-Z5TMGFAM.js";
import "./chunk-5DEWV7VV.js";
import "./chunk-V664VQNA.js";
import "./chunk-IL4FZKPB.js";
import "./chunk-V5HPWQV7.js";
import "./chunk-MJGBFYEG.js";
import "./chunk-4SO4BXOB.js";
import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-KW2CWOOD.js";
import "./chunk-Y2UB65JM.js";
import "./chunk-ZPRVWVSC.js";
import "./chunk-R4LF5PWF.js";
import "./chunk-4SXJ2GAM.js";
import "./chunk-5BWO4Y3K.js";
import "./chunk-7DIV2VRB.js";
import "./chunk-5JA6RSFC.js";
import "./chunk-2GCVRYR2.js";
import "./chunk-4YZBXG5G.js";
import "./chunk-YY5JEKDP.js";
import "./chunk-Z63B6QCQ.js";
import "./chunk-NQKLH74H.js";
import "./chunk-SSYKZXNO.js";
import "./chunk-WP62CKNZ.js";
import "./chunk-G45ZFGC3.js";
import "./chunk-LPSC3SDV.js";
import "./chunk-J6EMIQSU.js";
import "./chunk-RXZBKY45.js";
import "./chunk-E7WGGYZE.js";
import "./chunk-PIYDKQBM.js";
import "./chunk-JPJQZXKW.js";
import "./chunk-YW5WVS53.js";
import "./chunk-PFTNS476.js";
import "./chunk-SD56WPOS.js";
import "./chunk-TCEHBLTC.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-KUPDIQVG.js";
import "./chunk-L5ZLWR7T.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-L4JENJ4Z.js";
import "./chunk-KFQGP6VL.js";

// server/lib/asset-provisioner.ts
init_scan_server_executor();
init_engagement_orchestrator();
var PROVISION_BASE_DIR = "/opt/ac3-provisions";
var DOCKER_NETWORK = "ac3-provision-net";
var BASE_PORT = 9100;
var nextPort = BASE_PORT;
var CLONE_TIMEOUT = 300;
var BUILD_TIMEOUT = 600;
var DEPLOY_TIMEOUT = 120;
var TOOL_INSTALL_TIMEOUT = 180;
async function provisionAsset(br, engagementId, options) {
  const startTime = Date.now();
  const port = options?.port || nextPort++;
  const safeAssetName = br.assetName.replace(/[^a-zA-Z0-9_-]/g, "_").substring(0, 50);
  const assetDir = `${PROVISION_BASE_DIR}/${engagementId}/${safeAssetName}`;
  const containerName = `ac3-${engagementId}-${safeAssetName}`.substring(0, 63);
  let buildLog = "";
  let deployLog = "";
  const installedTools = [];
  const broadcast = (stage, status, detail, progress) => {
    try {
      broadcastOpsUpdate(engagementId, {
        type: "provision_progress",
        assetName: br.assetName,
        stage,
        status,
        detail,
        progress: progress ?? void 0,
        elapsedMs: Date.now() - startTime
      });
    } catch (_) {
    }
  };
  try {
    broadcast("init", "running", `Preparing workspace for ${br.assetName}...`, 0);
    await executeRawCommand(
      `mkdir -p ${assetDir} && docker network create ${DOCKER_NETWORK} 2>/dev/null || true`,
      3e4
    );
    broadcast("acquire", "running", `Cloning/downloading ${br.assetName}...`, 10);
    buildLog += `
=== ACQUISITION ===
`;
    const acquisitionCmd = deriveAcquisitionCommand(br, assetDir);
    const acqResult = await executeRawCommand(acquisitionCmd, CLONE_TIMEOUT * 1e3);
    buildLog += `$ ${acquisitionCmd}
${acqResult.stdout}
`;
    if (acqResult.exitCode !== 0) {
      buildLog += `STDERR: ${acqResult.stderr}
`;
      if (br.acquisitionMethod.includes("git clone") && acqResult.exitCode !== 0) {
        const altCmd = `cd ${assetDir} && wget -q "${br.assetName}/archive/refs/heads/main.zip" -O source.zip && unzip -q source.zip 2>/dev/null || true`;
        const altResult = await executeRawCommand(altCmd, CLONE_TIMEOUT * 1e3);
        buildLog += `
=== FALLBACK ACQUISITION ===
$ ${altCmd}
${altResult.stdout}
`;
      }
    }
    broadcast("acquire", "complete", `Source acquired successfully`, 25);
    if (br.dependencies && br.dependencies.length > 0) {
      broadcast("dependencies", "running", `Installing ${br.dependencies.length} dependencies...`, 30);
      buildLog += `
=== DEPENDENCIES ===
`;
      for (const dep of br.dependencies) {
        const depCmd = deriveInstallCommand(dep);
        if (depCmd) {
          const depResult = await executeRawCommand(depCmd, TOOL_INSTALL_TIMEOUT * 1e3);
          buildLog += `$ ${depCmd}
${depResult.stdout.substring(0, 500)}
`;
          if (depResult.exitCode === 0) installedTools.push(dep);
        }
      }
    }
    if (!options?.skipBuild && !br.hasHostedInstance) {
      broadcast("build", "running", `Building ${br.assetName}...`, 50);
      buildLog += `
=== BUILD ===
`;
      if (br.buildInstructions && br.buildInstructions.length > 0) {
        for (const step of br.buildInstructions) {
          const buildCmd = step.startsWith("cd ") ? step : `cd ${assetDir} && ${step}`;
          const buildResult = await executeRawCommand(buildCmd, BUILD_TIMEOUT * 1e3);
          buildLog += `$ ${step}
${buildResult.stdout.substring(0, 1e3)}
`;
          if (buildResult.exitCode !== 0) {
            buildLog += `STDERR: ${buildResult.stderr.substring(0, 500)}
`;
            buildLog += `WARNING: Build step failed (exit ${buildResult.exitCode}), continuing...
`;
          }
        }
      } else {
        buildLog += `No explicit build instructions. Auto-detecting...
`;
        const autoResult = await autoDetectAndBuild(assetDir);
        buildLog += autoResult.log;
      }
    }
    if (!options?.skipDeploy) {
      broadcast("deploy", "running", `Deploying to Docker container on port ${port}...`, 75);
      deployLog += `
=== DEPLOY ===
`;
      if (br.hasHostedInstance && br.hostedInstanceUrl) {
        deployLog += `Using hosted instance: ${br.hostedInstanceUrl}
`;
        return {
          assetName: br.assetName,
          status: "success",
          localTargetUrl: br.hostedInstanceUrl,
          sourceDir: assetDir,
          buildLog,
          deployLog,
          durationMs: Date.now() - startTime,
          installedTools
        };
      }
      if (br.deployInstructions && br.deployInstructions.length > 0) {
        for (const step of br.deployInstructions) {
          const deployCmd = step.replace(/\$\{PORT\}/g, String(port)).replace(/PORT=\d+/g, `PORT=${port}`).replace(/-p\s+\d+:/g, `-p ${port}:`);
          const fullCmd = deployCmd.startsWith("cd ") ? deployCmd : `cd ${assetDir} && ${deployCmd}`;
          const deployResult = await executeRawCommand(fullCmd, DEPLOY_TIMEOUT * 1e3);
          deployLog += `$ ${deployCmd}
${deployResult.stdout.substring(0, 500)}
`;
          if (deployResult.exitCode !== 0) {
            deployLog += `STDERR: ${deployResult.stderr.substring(0, 500)}
`;
          }
        }
      } else {
        deployLog += `No explicit deploy instructions. Auto-deploying with Docker...
`;
        const autoDeployResult = await autoDockerDeploy(assetDir, containerName, port);
        deployLog += autoDeployResult.log;
      }
      broadcast("verify", "running", `Verifying deployment on port ${port}...`, 90);
      const verifyResult = await executeRawCommand(
        `sleep 5 && curl -s -o /dev/null -w '%{http_code}' http://localhost:${port}/ 2>/dev/null || echo 'unreachable'`,
        3e4
      );
      const httpCode = verifyResult.stdout.trim();
      deployLog += `
=== VERIFY ===
HTTP status: ${httpCode}
`;
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
          installedTools
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
      installedTools
    };
  } catch (error) {
    broadcast("error", "failed", `Provisioning failed: ${error.message}`, 100);
    return {
      assetName: br.assetName,
      status: "failed",
      sourceDir: assetDir,
      buildLog,
      deployLog,
      error: error.message || String(error),
      durationMs: Date.now() - startTime,
      installedTools
    };
  }
}
async function provisionAllAssets(buildRequirements, engagementId) {
  const results = [];
  let port = BASE_PORT;
  for (const br of buildRequirements) {
    const result = await provisionAsset(br, engagementId, { port });
    results.push(result);
    port++;
  }
  return results;
}
async function installTools(toolRequirements) {
  const results = [];
  for (const tr of toolRequirements) {
    const checkResult = await executeRawCommand(
      `which ${tr.tool} 2>/dev/null || command -v ${tr.tool} 2>/dev/null`,
      1e4
    );
    if (checkResult.exitCode === 0 && checkResult.stdout.trim()) {
      results.push({
        tool: tr.tool,
        status: "already_installed",
        installCommand: tr.installCommand,
        output: `Already installed at: ${checkResult.stdout.trim()}`
      });
      continue;
    }
    try {
      const installResult = await executeRawCommand(
        tr.installCommand,
        TOOL_INSTALL_TIMEOUT * 1e3
      );
      if (installResult.exitCode === 0) {
        results.push({
          tool: tr.tool,
          status: "installed",
          installCommand: tr.installCommand,
          output: installResult.stdout.substring(0, 500)
        });
      } else {
        let installed = false;
        for (const alt of tr.alternatives) {
          const altCheckResult = await executeRawCommand(
            `which ${alt} 2>/dev/null`,
            1e4
          );
          if (altCheckResult.exitCode === 0) {
            results.push({
              tool: tr.tool,
              status: "already_installed",
              installCommand: tr.installCommand,
              output: `Alternative '${alt}' already available at: ${altCheckResult.stdout.trim()}`
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
            error: installResult.stderr.substring(0, 500)
          });
        }
      }
    } catch (error) {
      results.push({
        tool: tr.tool,
        status: "failed",
        installCommand: tr.installCommand,
        output: "",
        error: error.message || String(error)
      });
    }
  }
  return results;
}
async function cleanupProvisionedAssets(engagementId) {
  let log = "";
  const listResult = await executeRawCommand(
    `docker ps -a --filter "name=ac3-${engagementId}-" --format "{{.Names}}"`,
    3e4
  );
  const containers = listResult.stdout.trim().split("\n").filter(Boolean);
  for (const c of containers) {
    await executeRawCommand(`docker rm -f ${c}`, 3e4);
    log += `Removed container: ${c}
`;
  }
  const rmResult = await executeRawCommand(
    `rm -rf ${PROVISION_BASE_DIR}/${engagementId}`,
    3e4
  );
  log += `Removed source directory: ${PROVISION_BASE_DIR}/${engagementId}
`;
  return log;
}
function deriveAcquisitionCommand(br, assetDir) {
  const method = br.acquisitionMethod.toLowerCase();
  if (method.includes("git clone")) {
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
  if (br.assetName.startsWith("http")) {
    return `git clone --depth 1 ${br.assetName} ${assetDir}/source 2>&1`;
  }
  return `echo "Unknown acquisition method: ${br.acquisitionMethod}"`;
}
function deriveInstallCommand(dependency) {
  const dep = dependency.toLowerCase();
  const aptPackages = {
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
    "mongodb": "apt-get install -y mongodb-clients"
  };
  for (const [key, cmd] of Object.entries(aptPackages)) {
    if (dep.includes(key)) return cmd;
  }
  if (dep.includes("pip") || dep.includes("python")) {
    return `pip3 install ${dependency}`;
  }
  if (dep.includes("npm") || dep.includes("node")) {
    return `npm install -g ${dependency}`;
  }
  return `apt-get install -y ${dependency} 2>/dev/null || echo "Could not install: ${dependency}"`;
}
async function autoDetectAndBuild(assetDir) {
  let log = "";
  const sourceDir = `${assetDir}/source`;
  const checkResult = await executeRawCommand(
    `ls ${sourceDir}/package.json ${sourceDir}/Makefile ${sourceDir}/Cargo.toml ${sourceDir}/go.mod ${sourceDir}/setup.py ${sourceDir}/Dockerfile ${sourceDir}/docker-compose.yml 2>/dev/null || echo "none"`,
    1e4
  );
  const files = checkResult.stdout.trim();
  log += `Detected build files: ${files}
`;
  if (files.includes("docker-compose.yml")) {
    const result = await executeRawCommand(`cd ${sourceDir} && docker-compose build 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `docker-compose build: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("Dockerfile")) {
    const result = await executeRawCommand(`cd ${sourceDir} && docker build -t ac3-provision . 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `docker build: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("package.json")) {
    const result = await executeRawCommand(`cd ${sourceDir} && npm install 2>&1 && npm run build 2>&1 || true`, BUILD_TIMEOUT * 1e3);
    log += `npm install + build: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("Makefile")) {
    const result = await executeRawCommand(`cd ${sourceDir} && make 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `make: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("Cargo.toml")) {
    const result = await executeRawCommand(`cd ${sourceDir} && cargo build --release 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `cargo build: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("go.mod")) {
    const result = await executeRawCommand(`cd ${sourceDir} && go build ./... 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `go build: ${result.stdout.substring(0, 1e3)}
`;
  } else if (files.includes("setup.py")) {
    const result = await executeRawCommand(`cd ${sourceDir} && pip3 install -e . 2>&1`, BUILD_TIMEOUT * 1e3);
    log += `pip install: ${result.stdout.substring(0, 1e3)}
`;
  } else {
    log += `No recognized build system found. Source code available for SAST scanning at ${sourceDir}
`;
  }
  return { log };
}
async function autoDockerDeploy(assetDir, containerName, port) {
  let log = "";
  const sourceDir = `${assetDir}/source`;
  const checkResult = await executeRawCommand(
    `ls ${sourceDir}/docker-compose.yml ${sourceDir}/Dockerfile 2>/dev/null || echo "none"`,
    1e4
  );
  if (checkResult.stdout.includes("docker-compose.yml")) {
    const result = await executeRawCommand(
      `cd ${sourceDir} && PORT=${port} docker-compose up -d 2>&1`,
      DEPLOY_TIMEOUT * 1e3
    );
    log += `docker-compose up: ${result.stdout.substring(0, 500)}
`;
  } else if (checkResult.stdout.includes("Dockerfile")) {
    const buildResult = await executeRawCommand(
      `cd ${sourceDir} && docker build -t ${containerName} . 2>&1`,
      BUILD_TIMEOUT * 1e3
    );
    log += `docker build: ${buildResult.stdout.substring(0, 500)}
`;
    const runResult = await executeRawCommand(
      `docker run -d --name ${containerName} --network ${DOCKER_NETWORK} -p ${port}:${port} -e PORT=${port} ${containerName} 2>&1`,
      DEPLOY_TIMEOUT * 1e3
    );
    log += `docker run: ${runResult.stdout.substring(0, 500)}
`;
  } else {
    const pkgCheck = await executeRawCommand(`cat ${sourceDir}/package.json 2>/dev/null | head -1`, 1e4);
    if (pkgCheck.exitCode === 0) {
      const dockerfile = `FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install --production
EXPOSE ${port}
ENV PORT=${port}
CMD ["npm", "start"]`;
      await executeRawCommand(`echo '${dockerfile}' > ${sourceDir}/Dockerfile.ac3`, 1e4);
      const buildResult = await executeRawCommand(
        `cd ${sourceDir} && docker build -f Dockerfile.ac3 -t ${containerName} . 2>&1`,
        BUILD_TIMEOUT * 1e3
      );
      log += `Auto-generated Dockerfile (Node.js): ${buildResult.stdout.substring(0, 500)}
`;
      const runResult = await executeRawCommand(
        `docker run -d --name ${containerName} --network ${DOCKER_NETWORK} -p ${port}:${port} ${containerName} 2>&1`,
        DEPLOY_TIMEOUT * 1e3
      );
      log += `docker run: ${runResult.stdout.substring(0, 500)}
`;
    } else {
      log += `No Dockerfile or docker-compose.yml found. Source available for SAST at ${sourceDir}. Manual deployment required.
`;
    }
  }
  return { log };
}
export {
  cleanupProvisionedAssets,
  installTools,
  provisionAllAssets,
  provisionAsset
};
