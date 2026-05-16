/**
 * AWS EC2 Infrastructure Service
 * Instance provisioning, security group management, SSH key listing, and health checks
 * via the AWS SDK v3.
 *
 * Replaces the legacy DigitalOcean infrastructure module.
 * All scan infrastructure now runs on AWS EC2.
 */

import { ENV } from "../_core/env";

function getCredentials() {
  const accessKeyId = ENV.AWS_ACCESS_KEY_ID;
  const secretAccessKey = ENV.AWS_SECRET_ACCESS_KEY;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error("AWS credentials not configured (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)");
  }
  return { accessKeyId, secretAccessKey };
}

async function getEc2Client(region?: string) {
  const { EC2Client } = await import("@aws-sdk/client-ec2");
  return new EC2Client({
    region: region || ENV.AWS_REGION || "us-east-1",
    credentials: getCredentials(),
  });
}

// ─── Instance Types ──────────────────────────────────────────────────────────

export interface EC2Instance {
  id: string;
  name: string;
  status: string;
  region: string;
  instanceType: string;
  ipv4Public: string | null;
  ipv4Private: string | null;
  tags: Record<string, string>;
  createdAt: string;
  memory: number;  // approximate MB based on instance type
  vcpus: number;
  disk: number;    // root volume GB
}

function mapInstance(inst: any): EC2Instance {
  const tags: Record<string, string> = {};
  for (const t of inst.Tags || []) {
    tags[t.Key] = t.Value;
  }
  const typeInfo = INSTANCE_TYPE_SPECS[inst.InstanceType] || { memory: 0, vcpus: 0, disk: 0 };
  return {
    id: inst.InstanceId,
    name: tags["Name"] || inst.InstanceId,
    status: inst.State?.Name || "unknown",
    region: inst.Placement?.AvailabilityZone?.replace(/[a-z]$/, "") || "",
    instanceType: inst.InstanceType || "",
    ipv4Public: inst.PublicIpAddress || null,
    ipv4Private: inst.PrivateIpAddress || null,
    tags,
    createdAt: inst.LaunchTime?.toISOString() || "",
    memory: typeInfo.memory,
    vcpus: typeInfo.vcpus,
    disk: typeInfo.disk,
  };
}

// Approximate specs for common instance types
const INSTANCE_TYPE_SPECS: Record<string, { memory: number; vcpus: number; disk: number }> = {
  "t3.micro": { memory: 1024, vcpus: 2, disk: 8 },
  "t3.small": { memory: 2048, vcpus: 2, disk: 20 },
  "t3.medium": { memory: 4096, vcpus: 2, disk: 20 },
  "t3.large": { memory: 8192, vcpus: 2, disk: 30 },
  "t3.xlarge": { memory: 16384, vcpus: 4, disk: 30 },
  "c5.large": { memory: 4096, vcpus: 2, disk: 20 },
  "c5.xlarge": { memory: 8192, vcpus: 4, disk: 20 },
  "c5.2xlarge": { memory: 16384, vcpus: 8, disk: 20 },
  "m5.large": { memory: 8192, vcpus: 2, disk: 20 },
  "m5.xlarge": { memory: 16384, vcpus: 4, disk: 30 },
};

// ─── Instance CRUD ───────────────────────────────────────────────────────────

export async function listInstances(tag?: string): Promise<EC2Instance[]> {
  const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  const filters: any[] = [
    { Name: "instance-state-name", Values: ["pending", "running", "stopping", "stopped"] },
    { Name: "tag:ManagedBy", Values: ["ac3-caldera-dashboard"] },
  ];
  if (tag) {
    filters.push({ Name: `tag:Purpose`, Values: [tag] });
  }
  const result = await ec2.send(new DescribeInstancesCommand({ Filters: filters }));
  const instances: EC2Instance[] = [];
  for (const res of result.Reservations || []) {
    for (const inst of res.Instances || []) {
      instances.push(mapInstance(inst));
    }
  }
  return instances;
}

export async function createInstance(opts: {
  name: string;
  region?: string;
  instanceType: string;
  amiId: string;
  keyName?: string;
  securityGroupIds?: string[];
  subnetId?: string;
  tags?: Record<string, string>;
  userData?: string;
}): Promise<EC2Instance> {
  const { RunInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client(opts.region);

  const tagSpecs = [
    {
      ResourceType: "instance" as const,
      Tags: [
        { Key: "Name", Value: opts.name },
        { Key: "ManagedBy", Value: "ac3-caldera-dashboard" },
        ...(Object.entries(opts.tags || {}).map(([Key, Value]) => ({ Key, Value }))),
      ],
    },
  ];

  const params: any = {
    ImageId: opts.amiId,
    InstanceType: opts.instanceType,
    MinCount: 1,
    MaxCount: 1,
    TagSpecifications: tagSpecs,
  };

  if (opts.userData) params.UserData = Buffer.from(opts.userData).toString("base64");
  if (opts.keyName || ENV.AWS_KEY_PAIR_NAME) params.KeyName = opts.keyName || ENV.AWS_KEY_PAIR_NAME;
  if (opts.securityGroupIds?.length || ENV.AWS_SECURITY_GROUP_ID) {
    params.SecurityGroupIds = opts.securityGroupIds?.length ? opts.securityGroupIds : [ENV.AWS_SECURITY_GROUP_ID];
  }
  if (opts.subnetId || ENV.AWS_SUBNET_ID) params.SubnetId = opts.subnetId || ENV.AWS_SUBNET_ID;

  const result = await ec2.send(new RunInstancesCommand(params));
  const inst = result.Instances?.[0];
  if (!inst) throw new Error("EC2 RunInstances returned no instance");
  return mapInstance(inst);
}

export async function deleteInstance(id: string): Promise<void> {
  const { TerminateInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [id] }));
}

export async function getInstance(id: string): Promise<EC2Instance | null> {
  const { DescribeInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  const result = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }));
  const inst = result.Reservations?.[0]?.Instances?.[0];
  return inst ? mapInstance(inst) : null;
}

export async function stopInstance(id: string): Promise<void> {
  const { StopInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  await ec2.send(new StopInstancesCommand({ InstanceIds: [id] }));
}

export async function startInstance(id: string): Promise<void> {
  const { StartInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  await ec2.send(new StartInstancesCommand({ InstanceIds: [id] }));
}

export async function rebootInstance(id: string): Promise<void> {
  const { RebootInstancesCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  await ec2.send(new RebootInstancesCommand({ InstanceIds: [id] }));
}

// ─── Health Check ────────────────────────────────────────────────────────────

export interface HealthResult {
  instanceId: string;
  name: string;
  ip: string | null;
  status: string;
  httpReachable: boolean;
  checkedAt: number;
}

export async function healthCheckAll(tag?: string): Promise<HealthResult[]> {
  const instances = await listInstances(tag);
  const results: HealthResult[] = [];
  for (const inst of instances) {
    let httpReachable = false;
    if (inst.ipv4Public && inst.status === "running") {
      try {
        const r = await fetch(`http://${inst.ipv4Public}/`, { signal: AbortSignal.timeout(5000) });
        httpReachable = r.ok || r.status < 500;
      } catch {}
    }
    results.push({
      instanceId: inst.id,
      name: inst.name,
      ip: inst.ipv4Public,
      status: inst.status,
      httpReachable,
      checkedAt: Date.now(),
    });
  }
  return results;
}

// ─── Security Groups (replaces DO Firewalls) ─────────────────────────────────

export interface SecurityGroup {
  id: string;
  name: string;
  description: string;
  vpcId: string;
  inboundRules: Array<{ protocol: string; ports: string; sources: string }>;
  outboundRules: Array<{ protocol: string; ports: string; destinations: string }>;
}

export async function listSecurityGroups(): Promise<SecurityGroup[]> {
  const { DescribeSecurityGroupsCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  const result = await ec2.send(new DescribeSecurityGroupsCommand({
    Filters: [{ Name: "tag:ManagedBy", Values: ["ac3-caldera-dashboard"] }],
  }));
  return (result.SecurityGroups || []).map((sg) => ({
    id: sg.GroupId || "",
    name: sg.GroupName || "",
    description: sg.Description || "",
    vpcId: sg.VpcId || "",
    inboundRules: (sg.IpPermissions || []).map((p) => ({
      protocol: p.IpProtocol || "all",
      ports: p.FromPort === p.ToPort ? String(p.FromPort || "all") : `${p.FromPort}-${p.ToPort}`,
      sources: (p.IpRanges || []).map((r) => r.CidrIp).join(", ") || "any",
    })),
    outboundRules: (sg.IpPermissionsEgress || []).map((p) => ({
      protocol: p.IpProtocol || "all",
      ports: p.FromPort === p.ToPort ? String(p.FromPort || "all") : `${p.FromPort}-${p.ToPort}`,
      destinations: (p.IpRanges || []).map((r) => r.CidrIp).join(", ") || "any",
    })),
  }));
}

export async function deleteSecurityGroup(id: string): Promise<void> {
  const { DeleteSecurityGroupCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  await ec2.send(new DeleteSecurityGroupCommand({ GroupId: id }));
}

// ─── SSH Key Pairs ───────────────────────────────────────────────────────────

export interface EC2KeyPair {
  id: string;
  name: string;
  fingerprint: string;
}

export async function listKeyPairs(): Promise<EC2KeyPair[]> {
  const { DescribeKeyPairsCommand } = await import("@aws-sdk/client-ec2");
  const ec2 = await getEc2Client();
  const result = await ec2.send(new DescribeKeyPairsCommand({}));
  return (result.KeyPairs || []).map((k) => ({
    id: k.KeyPairId || "",
    name: k.KeyName || "",
    fingerprint: k.KeyFingerprint || "",
  }));
}

// ─── User-Data Generators ────────────────────────────────────────────────────

export function generateRedirectorUserData(opts: {
  type: "http" | "smtp" | "dns" | "c2";
  backendHost: string;
  backendPort: number;
  adminCidr?: string;
}): string {
  const adminCidr = opts.adminCidr ?? "0.0.0.0/0";
  const base = `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban socat
sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${adminCidr} to any port 22
`;
  if (opts.type === "http") {
    return `${base}
apt-get install -y -qq nginx certbot python3-certbot-nginx
cat > /etc/nginx/sites-available/redirector <<'NGINX'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://${opts.backendHost}:${opts.backendPort};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
`;
  }
  if (opts.type === "smtp") {
    return `${base}
debconf-set-selections <<< "postfix postfix/main_mailer_type select Internet Site"
debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"
apt-get install -y -qq postfix
postconf -e "relayhost = [${opts.backendHost}]:${opts.backendPort}"
postconf -e "smtp_tls_security_level = may"
systemctl restart postfix
ufw allow 25/tcp
ufw allow 587/tcp
ufw --force enable
`;
  }
  if (opts.type === "dns") {
    return `${base}
cat > /etc/systemd/system/dns-redir.service <<EOF
[Unit]
Description=DNS Redirector
After=network.target
[Service]
ExecStart=/usr/bin/socat UDP4-LISTEN:53,reuseaddr,fork UDP4:${opts.backendHost}:${opts.backendPort}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now dns-redir
ufw allow 53/tcp
ufw allow 53/udp
ufw --force enable
`;
  }
  return `${base}
cat > /etc/systemd/system/c2-redir.service <<EOF
[Unit]
Description=C2 Redirector
After=network.target
[Service]
ExecStart=/usr/bin/socat TCP4-LISTEN:443,reuseaddr,fork TCP4:${opts.backendHost}:${opts.backendPort}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now c2-redir
ufw allow 443/tcp
ufw --force enable
`;
}

export function generateTeamServerUserData(opts: { calderaPort?: number; adminCidr?: string } = {}): string {
  const port = opts.calderaPort ?? 8888;
  const adminCidr = opts.adminCidr ?? "0.0.0.0/0";
  return `#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get upgrade -y -qq
apt-get install -y -qq ufw fail2ban docker.io docker-compose-plugin
sed -i 's/#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
ufw default deny incoming
ufw default allow outgoing
ufw allow from ${adminCidr} to any port 22
ufw allow from ${adminCidr} to any port ${port}
ufw --force enable
systemctl enable --now docker
echo "Team server ready — port ${port}"
`;
}

// ─── Legacy Compatibility (maps old DO function names to AWS equivalents) ────

/** @deprecated Use createInstance instead */
export const createDroplet = async (opts: {
  name: string;
  region: string;
  size: string;
  image: string;
  sshKeys?: number[];
  tags?: string[];
  userData?: string;
  monitoring?: boolean;
}): Promise<any> => {
  const inst = await createInstance({
    name: opts.name,
    instanceType: mapSizeToInstanceType(opts.size),
    amiId: opts.image.startsWith("ami-") ? opts.image : await getDefaultAmi(),
    userData: opts.userData,
    tags: { Purpose: (opts.tags || [])[0] || "general" },
  });
  // Return in DO-compatible shape
  return {
    id: inst.id,
    name: inst.name,
    status: inst.status === "running" ? "active" : inst.status,
    region: inst.region,
    sizeSlug: inst.instanceType,
    ipv4Public: inst.ipv4Public,
    ipv4Private: inst.ipv4Private,
    tags: Object.values(inst.tags),
    createdAt: inst.createdAt,
    memory: inst.memory,
    vcpus: inst.vcpus,
    disk: inst.disk,
  };
};

/** @deprecated Use deleteInstance instead */
export const deleteDroplet = async (id: number | string): Promise<void> => {
  await deleteInstance(String(id));
};

/** @deprecated Use getInstance instead */
export const getDroplet = async (id: number | string): Promise<any> => {
  const inst = await getInstance(String(id));
  if (!inst) throw new Error(`Instance ${id} not found`);
  return {
    id: inst.id,
    name: inst.name,
    status: inst.status === "running" ? "active" : inst.status,
    region: inst.region,
    sizeSlug: inst.instanceType,
    ipv4Public: inst.ipv4Public,
    ipv4Private: inst.ipv4Private,
    tags: Object.values(inst.tags),
    createdAt: inst.createdAt,
    memory: inst.memory,
    vcpus: inst.vcpus,
    disk: inst.disk,
  };
};

/** @deprecated Use listInstances instead */
export const listDroplets = async (tag?: string): Promise<any[]> => {
  const instances = await listInstances(tag);
  return instances.map((inst) => ({
    id: inst.id,
    name: inst.name,
    status: inst.status === "running" ? "active" : inst.status,
    region: inst.region,
    sizeSlug: inst.instanceType,
    ipv4Public: inst.ipv4Public,
    ipv4Private: inst.ipv4Private,
    tags: Object.values(inst.tags),
    createdAt: inst.createdAt,
    memory: inst.memory,
    vcpus: inst.vcpus,
    disk: inst.disk,
  }));
};

/** @deprecated Use listSecurityGroups instead */
export const listFirewalls = listSecurityGroups;

/** @deprecated Use deleteSecurityGroup instead */
export const deleteFirewall = deleteSecurityGroup;

/** @deprecated Use listKeyPairs instead */
export const listSshKeys = async (): Promise<any[]> => {
  const keys = await listKeyPairs();
  return keys.map((k) => ({ id: k.id, name: k.name, fingerprint: k.fingerprint, publicKey: "" }));
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function mapSizeToInstanceType(doSize: string): string {
  const mapping: Record<string, string> = {
    "s-1vcpu-1gb": "t3.micro",
    "s-1vcpu-2gb": "t3.small",
    "s-2vcpu-2gb": "t3.small",
    "s-2vcpu-4gb": "t3.medium",
    "s-4vcpu-8gb": "c5.xlarge",
    "c-4-8gib": "c5.xlarge",
    "c-8-16gib": "c5.2xlarge",
    "s-8vcpu-16gb": "m5.xlarge",
  };
  return mapping[doSize] || "t3.medium";
}

async function getDefaultAmi(): Promise<string> {
  // Ubuntu 22.04 LTS fallback AMIs
  const region = ENV.AWS_REGION || "us-east-1";
  const fallbacks: Record<string, string> = {
    "us-east-1": "ami-0c7217cdde317cfec",
    "us-east-2": "ami-05fb0b8c1424f266b",
    "us-west-1": "ami-0ce2cb35386fc22e9",
    "us-west-2": "ami-008fe2fc65df48dac",
    "eu-west-1": "ami-0905a3c97561e0b69",
    "eu-central-1": "ami-0faab6bdbac9486fb",
  };
  return fallbacks[region] || fallbacks["us-east-1"];
}
