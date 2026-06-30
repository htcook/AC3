/**
 * Metasploit EC2 Provisioner
 *
 * Automates the lifecycle of Metasploit Framework instances on AWS EC2:
 * 1. Launch an EC2 instance with Docker + MSF container via UserData
 * 2. Auto-configure MSGRPC daemon
 * 3. Health-check and monitor
 * 4. Terminate when no longer needed
 *
 * The MSF instance runs as a Docker container with msfrpcd exposed on the
 * configured port. A random password is generated for each instance.
 *
 * LICENSING NOTE (BSD-3-Clause):
 * Metasploit Framework is open source under the BSD 3-Clause license.
 * Commercial use is explicitly permitted. We use the official Docker image
 * (metasploitframework/metasploit-framework) which is free and unencumbered.
 * No Rapid7 Pro/Enterprise license is required for this usage pattern.
 */

import { ENV } from "../_core/env";
import crypto from "crypto";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface ProvisionRequest {
  name: string;
  region?: string;        // default: from AWS_REGION env
  instanceType?: string;  // default: t3.medium (2 vCPU, 4GB — minimum for MSF)
  rpcPort?: number;       // default: 55553
  rpcUser?: string;       // default: msf
  autoDestroy?: boolean;  // terminate after engagement ends
  engagementId?: number;
  subnetId?: string;      // override default subnet
  securityGroupId?: string; // override default SG
  amiId?: string;         // override default AMI (for pre-baked MSF images)
}

export interface ProvisionResult {
  success: boolean;
  instanceId?: string;
  ipAddress?: string;
  privateIp?: string;
  rpcPort?: number;
  rpcUser?: string;
  rpcPass?: string;
  rpcSsl?: boolean;
  error?: string;
  statusMessage?: string;
}

export interface InstanceStatus {
  instanceId: string;
  status: string;       // "pending", "running", "stopping", "stopped", "terminated"
  ipAddress?: string;
  privateIp?: string;
  region: string;
  instanceType: string;
  launchTime?: string;
}

// ─── UserData Script (Cloud-Init) ─────────────────────────────────────────

function generateUserData(rpcPort: number, rpcUser: string, rpcPass: string): string {
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
  // EC2 UserData must be base64-encoded
  return Buffer.from(script).toString("base64");
}

// ─── AWS EC2 Helpers ──────────────────────────────────────────────────────

function getAwsCredentials() {
  const accessKeyId = ENV.AWS_ACCESS_KEY_ID;
  const secretAccessKey = ENV.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("AWS credentials not configured (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)");
  }
  return { accessKeyId, secretAccessKey };
}

async function getEc2Client(region?: string) {
  const { EC2Client } = await import("@aws-sdk/client-ec2");
  const credentials = getAwsCredentials();
  return new EC2Client({
    region: region || ENV.AWS_REGION || "us-east-1",
    credentials,
  });
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Provision a new Metasploit Framework EC2 instance on AWS.
 * Returns connection details once the instance is launched.
 */
export async function provisionMsfInstance(req: ProvisionRequest): Promise<ProvisionResult> {
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

    // Use custom AMI if provided, otherwise use Ubuntu 22.04 (will be resolved)
    const amiId = req.amiId || ENV.AWS_MSF_AMI_ID || await getUbuntuAmi(region);

    const params: any = {
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
            ...(req.engagementId ? [{ Key: "EngagementId", Value: String(req.engagementId) }] : []),
          ],
        },
      ],
    };

    // Add networking config
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
      privateIp: instance.PrivateIpAddress || undefined,
      rpcPort,
      rpcUser,
      rpcPass,
      rpcSsl: true,
      statusMessage: `EC2 instance ${instance.InstanceId} launched. MSF installing via UserData (2-5 min).`,
    };
  } catch (err: any) {
    console.error(`[MSF-Provisioner] Provision failed:`, err.message);
    return { success: false, error: err.message };
  }
}

/**
 * Get the public IP address of an EC2 instance.
 */
export async function getInstanceIp(instanceId: string, region?: string): Promise<string | null> {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId],
    }));
    const instance = result.Reservations?.[0]?.Instances?.[0];
    return instance?.PublicIpAddress || null;
  } catch {
    return null;
  }
}

/**
 * Get full EC2 instance status.
 */
export async function getInstanceStatus(instanceId: string, region?: string): Promise<InstanceStatus | null> {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      InstanceIds: [instanceId],
    }));
    const inst = result.Reservations?.[0]?.Instances?.[0];
    if (!inst) return null;

    return {
      instanceId: inst.InstanceId || instanceId,
      status: inst.State?.Name || "unknown",
      ipAddress: inst.PublicIpAddress || undefined,
      privateIp: inst.PrivateIpAddress || undefined,
      region: region || ENV.AWS_REGION || "us-east-1",
      instanceType: inst.InstanceType || "",
      launchTime: inst.LaunchTime?.toISOString(),
    };
  } catch {
    return null;
  }
}

/**
 * Terminate a Metasploit EC2 instance.
 */
export async function terminateMsfInstance(instanceId: string, region?: string): Promise<{ success: boolean; error?: string }> {
  try {
    console.log(`[MSF-Provisioner] Terminating EC2 instance ${instanceId}...`);
    const { TerminateInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new TerminateInstancesCommand({ InstanceIds: [instanceId] }));
    console.log(`[MSF-Provisioner] EC2 instance ${instanceId} terminated`);
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * Reboot an EC2 instance.
 */
export async function rebootInstance(instanceId: string, region?: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { RebootInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new RebootInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * Stop an EC2 instance (preserves data, stops billing for compute).
 */
export async function stopInstance(instanceId: string, region?: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { StopInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * Start a stopped EC2 instance.
 */
export async function startInstance(instanceId: string, region?: string): Promise<{ success: boolean; error?: string }> {
  try {
    const { StartInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    await ec2.send(new StartInstancesCommand({ InstanceIds: [instanceId] }));
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

/**
 * List all MSF-tagged EC2 instances.
 */
export async function listMsfInstances(region?: string): Promise<InstanceStatus[]> {
  try {
    const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client(region);
    const result = await ec2.send(new DescribeInstancesCommand({
      Filters: [
        { Name: "tag:Purpose", Values: ["metasploit"] },
        { Name: "tag:ManagedBy", Values: ["ac3-caldera-dashboard"] },
        { Name: "instance-state-name", Values: ["pending", "running", "stopping", "stopped"] },
      ],
    }));

    const instances: InstanceStatus[] = [];
    for (const reservation of result.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        instances.push({
          instanceId: inst.InstanceId || "",
          status: inst.State?.Name || "unknown",
          ipAddress: inst.PublicIpAddress || undefined,
          privateIp: inst.PrivateIpAddress || undefined,
          region: region || ENV.AWS_REGION || "us-east-1",
          instanceType: inst.InstanceType || "",
          launchTime: inst.LaunchTime?.toISOString(),
        });
      }
    }
    return instances;
  } catch {
    return [];
  }
}

/**
 * Get available AWS regions.
 */
export async function getAvailableRegions(): Promise<Array<{ slug: string; name: string; available: boolean }>> {
  try {
    const { DescribeRegionsCommand } = await import("@aws-sdk/client-ec2");
    const ec2 = await getEc2Client();
    const result = await ec2.send(new DescribeRegionsCommand({}));
    return (result.Regions || []).map((r) => ({
      slug: r.RegionName || "",
      name: r.RegionName || "",
      available: true,
    }));
  } catch {
    return [];
  }
}

/**
 * Resolve the latest Ubuntu 22.04 AMI for the given region.
 * Uses SSM Parameter Store public parameter.
 */
async function getUbuntuAmi(region: string): Promise<string> {
  // Fallback AMI IDs for common regions (Ubuntu 22.04 LTS)
  const fallbackAmis: Record<string, string> = {
    "us-east-1": "ami-0c7217cdde317cfec",
    "us-east-2": "ami-05fb0b8c1424f266b",
    "us-west-1": "ami-0ce2cb35386fc22e9",
    "us-west-2": "ami-008fe2fc65df48dac",
    "eu-west-1": "ami-0905a3c97561e0b69",
    "eu-central-1": "ami-0faab6bdbac9486fb",
    "ap-southeast-1": "ami-078c1149d8ad719a7",
    "ap-northeast-1": "ami-07c589821f2b353aa",
  };

  // Try to resolve via SSM (canonical's public AMI parameter)
  try {
    const resp = await fetch(
      `https://ssm.${region}.amazonaws.com/?Action=GetParameter&Name=/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id&Version=1`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (resp.ok) {
      const text = await resp.text();
      const match = text.match(/ami-[a-z0-9]+/);
      if (match) return match[0];
    }
  } catch {
    // Fall through to hardcoded fallback
  }

  return fallbackAmis[region] || fallbackAmis["us-east-1"];
}

// ─── Legacy Compatibility (deprecated DO functions → map to AWS) ──────────

/** @deprecated Use provisionMsfInstance instead */
export const provisionMsfDroplet = provisionMsfInstance;

/** @deprecated Use getInstanceIp instead */
export const getDropletIp = getInstanceIp;

/** @deprecated Use getInstanceStatus instead */
export async function getDropletStatus(instanceId: string): Promise<any> {
  const status = await getInstanceStatus(instanceId);
  if (!status) return null;
  return {
    dropletId: status.instanceId,
    status: status.status,
    ipAddress: status.ipAddress,
    region: status.region,
    memory: 4096, // t3.medium default
    vcpus: 2,
    disk: 20,
  };
}

/** Alias used by commercial-scanners router */
export async function provisionMsfServer(opts: { name: string; instanceType?: string; region?: string; userId?: string }) {
  return provisionMsfInstance({
    name: opts.name,
    instanceType: opts.instanceType,
    region: opts.region,
  });
}

/** Alias used by commercial-scanners router */
export async function destroyMsfServer(instanceId: string) {
  return terminateMsfInstance(instanceId);
}

/** @deprecated Use terminateMsfInstance instead */
export const destroyMsfDroplet = terminateMsfInstance;

/** @deprecated Use rebootInstance instead */
export const rebootDroplet = rebootInstance;

/** @deprecated Use listMsfInstances instead */
export async function listMsfDroplets(): Promise<any[]> {
  const instances = await listMsfInstances();
  return instances.map((i) => ({
    dropletId: i.instanceId,
    status: i.status,
    ipAddress: i.ipAddress,
    region: i.region,
    memory: 4096,
    vcpus: 2,
    disk: 20,
  }));
}
