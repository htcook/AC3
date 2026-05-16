import {
  ENV,
  init_env
} from "./chunk-KDOLKO2A.js";
import "./chunk-KFQGP6VL.js";

// server/lib/msf-provisioner.ts
init_env();
import crypto from "crypto";
function generateUserData(rpcPort, rpcUser, rpcPass) {
  const script = `#!/bin/bash
set -euo pipefail

# Log everything
exec > /var/log/msf-setup.log 2>&1

echo "[*] Starting Metasploit Framework setup on AWS EC2..."

# Update and install Docker
apt-get update -y
apt-get install -y docker.io docker-compose curl jq

# Configure iptables (AWS SG handles external firewall)
# Only restrict internal traffic if needed

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
  if curl -sf --insecure "https://localhost:${rpcPort}/api/v1/json-rpc" \\
    -X POST -H "Content-Type: application/json" \\
    -d '{"jsonrpc":"2.0","method":"db.status","id":1,"params":[]}' > /dev/null 2>&1; then
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
  return Buffer.from(script).toString("base64");
}
function getAwsCredentials() {
  const accessKeyId = ENV.AWS_ACCESS_KEY_ID;
  const secretAccessKey = ENV.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("AWS credentials not configured (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)");
  }
  return { accessKeyId, secretAccessKey };
}
async function getEc2Client(region) {
  const { EC2Client } = await import("@aws-sdk/client-ec2");
  const credentials = getAwsCredentials();
  return new EC2Client({
    region: region || ENV.AWS_REGION || "us-east-1",
    credentials
  });
}
async function provisionMsfInstance(req) {
  const region = req.region || ENV.AWS_REGION || "us-east-1";
  const instanceType = req.instanceType || "t3.medium";
  const rpcPort = req.rpcPort || 55553;
  const rpcUser = req.rpcUser || "msf";
  const rpcPass = crypto.randomBytes(24).toString("base64url");
  try {
    console.log(`[MSF-Provisioner] Launching EC2 instance "${req.name}" in ${region} (${instanceType})...`);
    const { RunInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const userData = generateUserData(rpcPort, rpcUser, rpcPass);
    const amiId = req.amiId || ENV.AWS_MSF_AMI_ID || await getUbuntuAmi(region);
    const params = {
      ImageId: amiId,
      InstanceType: instanceType,
      MinCount: 1,
      MaxCount: 1,
      UserData: userData,
      TagSpecifications: [
        {
          ResourceType: "instance",
          Tags: [
            { Key: "Name", Value: `msf-${req.name.replace(/[^a-z0-9-]/gi, "-").toLowerCase()}` },
            { Key: "Purpose", Value: "metasploit" },
            { Key: "ManagedBy", Value: "ac3-caldera-dashboard" },
            { Key: "AutoDestroy", Value: req.autoDestroy ? "true" : "false" },
            ...req.engagementId ? [{ Key: "EngagementId", Value: String(req.engagementId) }] : []
          ]
        }
      ]
    };
    if (req.securityGroupId || ENV.AWS_SECURITY_GROUP_ID) {
      params.SecurityGroupIds = [req.securityGroupId || ENV.AWS_SECURITY_GROUP_ID];
    }
    if (req.subnetId || ENV.AWS_SUBNET_ID) {
      params.SubnetId = req.subnetId || ENV.AWS_SUBNET_ID;
    }
    if (ENV.AWS_KEY_PAIR_NAME) {
      params.KeyName = ENV.AWS_KEY_PAIR_NAME;
    }
    const result = await ec2.send(new RunInstancesCommand(params));
    const instance = result.Instances?.[0];
    if (!instance?.InstanceId) {
      throw new Error("EC2 RunInstances returned no instance");
    }
    console.log(`[MSF-Provisioner] EC2 instance launched: ${instance.InstanceId}`);
    return {
      success: true,
      instanceId: instance.InstanceId,
      privateIp: instance.PrivateIpAddress || void 0,
      rpcPort,
      rpcUser,
      rpcPass,
      rpcSsl: true,
      statusMessage: `EC2 instance ${instance.InstanceId} launched. MSF installing via UserData (2-5 min).`
    };
  } catch (err) {
    console.error(`[MSF-Provisioner] Provision failed:`, err.message);
    return { success: false, error: err.message };
  }
}
async function getInstanceIp(instanceId, region) {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId]
    }));
    const instance = result.Reservations?.[0]?.Instances?.[0];
    return instance?.PublicIpAddress || null;
  } catch {
    return null;
  }
}
async function getInstanceStatus(instanceId, region) {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId]
    }));
    const inst = result.Reservations?.[0]?.Instances?.[0];
    if (!inst) return null;
    return {
      instanceId: inst.InstanceId || instanceId,
      status: inst.State?.Name || "unknown",
      ipAddress: inst.PublicIpAddress || void 0,
      privateIp: inst.PrivateIpAddress || void 0,
      region: region || ENV.AWS_REGION || "us-east-1",
      instanceType: inst.InstanceType || "",
      launchTime: inst.LaunchTime?.toISOString()
    };
  } catch {
    return null;
  }
}
async function terminateMsfInstance(instanceId, region) {
  try {
    console.log(`[MSF-Provisioner] Terminating EC2 instance ${instanceId}...`);
    const { TerminateInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new TerminateInstancesCommand({ InstanceIds: [instanceId] }));
    console.log(`[MSF-Provisioner] EC2 instance ${instanceId} terminated`);
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function rebootInstance(instanceId, region) {
  try {
    const { RebootInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new RebootInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function stopInstance(instanceId, region) {
  try {
    const { StopInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function startInstance(instanceId, region) {
  try {
    const { StartInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
async function listMsfInstances(region) {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      Filters: [
        { Name: "tag:Purpose", Values: ["metasploit"] },
        { Name: "tag:ManagedBy", Values: ["ac3-caldera-dashboard"] },
        { Name: "instance-state-name", Values: ["pending", "running", "stopping", "stopped"] }
      ]
    }));
    const instances = [];
    for (const reservation of result.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        instances.push({
          instanceId: inst.InstanceId || "",
          status: inst.State?.Name || "unknown",
          ipAddress: inst.PublicIpAddress || void 0,
          privateIp: inst.PrivateIpAddress || void 0,
          region: region || ENV.AWS_REGION || "us-east-1",
          instanceType: inst.InstanceType || "",
          launchTime: inst.LaunchTime?.toISOString()
        });
      }
    }
    return instances;
  } catch {
    return [];
  }
}
async function getAvailableRegions() {
  try {
    const { DescribeRegionsCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client();
    const result = await ec2.send(new DescribeRegionsCommand({}));
    return (result.Regions || []).map((r) => ({
      slug: r.RegionName || "",
      name: r.RegionName || "",
      available: true
    }));
  } catch {
    return [];
  }
}
async function getUbuntuAmi(region) {
  const fallbackAmis = {
    "us-east-1": "ami-0c7217cdde317cfec",
    "us-east-2": "ami-05fb0b8c1424f266b",
    "us-west-1": "ami-0ce2cb35386fc22e9",
    "us-west-2": "ami-008fe2fc65df48dac",
    "eu-west-1": "ami-0905a3c97561e0b69",
    "eu-central-1": "ami-0faab6bdbac9486fb",
    "ap-southeast-1": "ami-078c1149d8ad719a7",
    "ap-northeast-1": "ami-07c589821f2b353aa"
  };
  try {
    const resp = await fetch(
      `https://ssm.${region}.amazonaws.com/?Action=GetParameter&Name=/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id&Version=1`,
      { signal: AbortSignal.timeout(5e3) }
    );
    if (resp.ok) {
      const text = await resp.text();
      const match = text.match(/ami-[a-z0-9]+/);
      if (match) return match[0];
    }
  } catch {
  }
  return fallbackAmis[region] || fallbackAmis["us-east-1"];
}
var provisionMsfDroplet = provisionMsfInstance;
var getDropletIp = getInstanceIp;
async function getDropletStatus(instanceId) {
  const status = await getInstanceStatus(instanceId);
  if (!status) return null;
  return {
    dropletId: status.instanceId,
    status: status.status,
    ipAddress: status.ipAddress,
    region: status.region,
    memory: 4096,
    // t3.medium default
    vcpus: 2,
    disk: 20
  };
}
async function provisionMsfServer(opts) {
  return provisionMsfInstance({
    name: opts.name,
    instanceType: opts.instanceType,
    region: opts.region
  });
}
async function destroyMsfServer(instanceId) {
  return terminateMsfInstance(instanceId);
}
var destroyMsfDroplet = terminateMsfInstance;
var rebootDroplet = rebootInstance;
async function listMsfDroplets() {
  const instances = await listMsfInstances();
  return instances.map((i) => ({
    dropletId: i.instanceId,
    status: i.status,
    ipAddress: i.ipAddress,
    region: i.region,
    memory: 4096,
    vcpus: 2,
    disk: 20
  }));
}
export {
  destroyMsfDroplet,
  destroyMsfServer,
  getAvailableRegions,
  getDropletIp,
  getDropletStatus,
  getInstanceIp,
  getInstanceStatus,
  listMsfDroplets,
  listMsfInstances,
  provisionMsfDroplet,
  provisionMsfInstance,
  provisionMsfServer,
  rebootDroplet,
  rebootInstance,
  startInstance,
  stopInstance,
  terminateMsfInstance
};
