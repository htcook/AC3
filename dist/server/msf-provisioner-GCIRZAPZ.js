import {
  ENV,
  init_env
} from "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/msf-provisioner.ts
init_env();
import crypto from "crypto";
function generateCloudInit(rpcPort, rpcUser, rpcPass) {
  return `#!/bin/bash
set -euo pipefail

# Log everything
exec > /var/log/msf-setup.log 2>&1

echo "[*] Starting Metasploit Framework setup..."

# Update and install Docker
apt-get update -y
apt-get install -y docker.io docker-compose curl jq ufw

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow ${rpcPort}/tcp
ufw --force enable

# Enable Docker
systemctl enable docker
systemctl start docker

# Pull Metasploit Docker image
echo "[*] Pulling Metasploit Framework Docker image..."
docker pull metasploitframework/metasploit-framework:latest

# Create persistent data directory
mkdir -p /opt/msf/data /opt/msf/logs

# Create docker-compose for MSF
cat > /opt/msf/docker-compose.yml << 'COMPOSE'
version: '3.8'
services:
  msf:
    image: metasploitframework/metasploit-framework:latest
    container_name: msf-framework
    restart: unless-stopped
    ports:
      - "${rpcPort}:${rpcPort}"
    volumes:
      - /opt/msf/data:/root/.msf4
      - /opt/msf/logs:/var/log/msf
    environment:
      - MSF_RPC_PORT=${rpcPort}
      - MSF_RPC_USER=${rpcUser}
      - MSF_RPC_PASS=${rpcPass}
    entrypoint: ["./msfrpcd", "-P", "${rpcPass}", "-U", "${rpcUser}", "-p", "${rpcPort}", "-a", "0.0.0.0", "-S"]
    healthcheck:
      test: ["CMD", "curl", "-sf", "https://localhost:${rpcPort}/api/v1/json-rpc", "--insecure", "-X", "POST", "-H", "Content-Type: application/json", "-d", '{"jsonrpc":"2.0","method":"db.status","id":1,"params":[]}']
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 120s
COMPOSE

# Start MSF container
echo "[*] Starting Metasploit Framework container..."
cd /opt/msf && docker-compose up -d

# Wait for MSF to initialize (can take 60-120 seconds)
echo "[*] Waiting for MSGRPC to initialize..."
for i in $(seq 1 60); do
  if curl -sf --insecure "https://localhost:${rpcPort}/api/v1/json-rpc"     -X POST -H "Content-Type: application/json"     -d '{"jsonrpc":"2.0","method":"db.status","id":1,"params":[]}' > /dev/null 2>&1; then
    echo "[+] MSGRPC is ready!"
    break
  fi
  echo "  Waiting... ($i/60)"
  sleep 5
done

# Write status file
cat > /opt/msf/status.json << EOF
{
  "status": "ready",
  "rpcPort": ${rpcPort},
  "rpcUser": "${rpcUser}",
  "setupCompleted": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "[+] Metasploit Framework setup complete!"
`;
}
var DO_API = "https://api.digitalocean.com/v2";
async function doFetch(path, options = {}) {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DigitalOcean access token not configured");
  const resp = await fetch(`${DO_API}${path}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...options.headers
    },
    signal: AbortSignal.timeout(3e4)
  });
  if (!resp.ok) {
    const errText = await resp.text().catch(() => "unknown");
    throw new Error(`DigitalOcean API error ${resp.status}: ${errText}`);
  }
  if (resp.status === 204) return null;
  return resp.json();
}
async function provisionMsfDroplet(req) {
  const region = req.region || "nyc1";
  const size = req.size || "s-2vcpu-4gb";
  const rpcPort = req.rpcPort || 55553;
  const rpcUser = req.rpcUser || "msf";
  const rpcPass = crypto.randomBytes(24).toString("base64url");
  try {
    console.log(`[MSF-Provisioner] Creating droplet "${req.name}" in ${region} (${size})...`);
    const cloudInit = generateCloudInit(rpcPort, rpcUser, rpcPass);
    const data = await doFetch("/droplets", {
      method: "POST",
      body: JSON.stringify({
        name: `msf-${req.name.replace(/[^a-z0-9-]/gi, "-").toLowerCase()}`,
        region,
        size,
        image: "ubuntu-22-04-x64",
        ssh_keys: await getAccountSshKeys(),
        user_data: cloudInit,
        tags: ["metasploit", "caldera-dashboard", "auto-provisioned"],
        monitoring: true
      })
    });
    const droplet = data.droplet;
    console.log(`[MSF-Provisioner] Droplet created: ID=${droplet.id}`);
    return {
      success: true,
      dropletId: String(droplet.id),
      rpcPort,
      rpcUser,
      rpcPass,
      rpcSsl: true,
      statusMessage: `Droplet ${droplet.id} created. MSF installing via cloud-init (2-5 min).`
    };
  } catch (err) {
    console.error(`[MSF-Provisioner] Provision failed:`, err.message);
    return { success: false, error: err.message };
  }
}
async function getDropletIp(dropletId) {
  try {
    const data = await doFetch(`/droplets/${dropletId}`);
    const networks = data.droplet?.networks?.v4 || [];
    const publicNet = networks.find((n) => n.type === "public");
    return publicNet?.ip_address || null;
  } catch {
    return null;
  }
}
async function getDropletStatus(dropletId) {
  try {
    const data = await doFetch(`/droplets/${dropletId}`);
    const d = data.droplet;
    const networks = d.networks?.v4 || [];
    const publicNet = networks.find((n) => n.type === "public");
    return {
      dropletId: String(d.id),
      status: d.status,
      ipAddress: publicNet?.ip_address,
      region: d.region?.slug || "",
      memory: d.memory,
      vcpus: d.vcpus,
      disk: d.disk
    };
  } catch {
    return null;
  }
}
async function destroyMsfDroplet(dropletId) {
  try {
    console.log(`[MSF-Provisioner] Destroying droplet ${dropletId}...`);
    await doFetch(`/droplets/${dropletId}`, { method: "DELETE" });
    console.log(`[MSF-Provisioner] Droplet ${dropletId} destroyed`);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function rebootDroplet(dropletId) {
  try {
    await doFetch(`/droplets/${dropletId}/actions`, {
      method: "POST",
      body: JSON.stringify({ type: "reboot" })
    });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function getAccountSshKeys() {
  try {
    const data = await doFetch("/account/keys?per_page=50");
    return (data.ssh_keys || []).map((k) => k.id);
  } catch {
    return [];
  }
}
async function listMsfDroplets() {
  try {
    const data = await doFetch("/droplets?tag_name=metasploit&per_page=50");
    return (data.droplets || []).map((d) => {
      const networks = d.networks?.v4 || [];
      const publicNet = networks.find((n) => n.type === "public");
      return {
        dropletId: String(d.id),
        status: d.status,
        ipAddress: publicNet?.ip_address,
        region: d.region?.slug || "",
        memory: d.memory,
        vcpus: d.vcpus,
        disk: d.disk
      };
    });
  } catch {
    return [];
  }
}
async function getAvailableRegions() {
  try {
    const data = await doFetch("/regions?per_page=50");
    return (data.regions || []).filter((r) => r.available).map((r) => ({
      slug: r.slug,
      name: r.name,
      available: r.available
    }));
  } catch {
    return [];
  }
}
export {
  destroyMsfDroplet,
  getAvailableRegions,
  getDropletIp,
  getDropletStatus,
  listMsfDroplets,
  provisionMsfDroplet,
  rebootDroplet
};
