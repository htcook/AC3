/**
 * Infrastructure Deployment Automation Engine
 * 
 * Based on Red Team Infrastructure Wiki principles:
 *   - Terraform for infrastructure provisioning
 *   - Ansible for configuration management
 *   - Docker for containerization
 *   - Automated setup of redirectors, team servers, phishing infra
 * 
 * Provides:
 *   - Deployment blueprint library (pre-built infra patterns)
 *   - Terraform plan generation for cloud providers
 *   - Ansible playbook generation for configuration
 *   - Deployment status tracking and rollback
 */

export type CloudProvider = "digitalocean" | "aws" | "azure" | "gcp" | "linode" | "vultr";
export type DeploymentStatus = "draft" | "planning" | "deploying" | "active" | "destroying" | "destroyed" | "failed";
export type ComponentType = "team_server" | "redirector" | "phishing_server" | "payload_host" | "log_sink" | "vpn_gateway" | "dns_server";

export interface InfraBlueprint {
  id: string;
  name: string;
  description: string;
  /** Components in this blueprint */
  components: BlueprintComponent[];
  /** Network topology */
  network: NetworkConfig;
  /** Estimated monthly cost */
  estimatedCostUsd: number;
  /** Deployment time estimate */
  estimatedDeployMinutes: number;
  /** MITRE ATT&CK techniques supported */
  mitreTechniques: string[];
  tags: string[];
}

export interface BlueprintComponent {
  id: string;
  name: string;
  type: ComponentType;
  provider: CloudProvider;
  region: string;
  /** VM size / instance type */
  size: string;
  /** OS image */
  image: string;
  /** Ports to expose */
  exposedPorts: number[];
  /** Software to install */
  software: string[];
  /** Configuration templates */
  configTemplates: string[];
  /** Dependencies (other component IDs) */
  dependsOn: string[];
}

export interface NetworkConfig {
  /** VPC/VNet CIDR */
  cidr: string;
  /** Subnet allocations */
  subnets: Array<{ name: string; cidr: string; components: string[] }>;
  /** Firewall rules */
  firewallRules: FirewallRule[];
  /** VPN configuration */
  vpn?: { type: "wireguard" | "openvpn"; serverComponent: string };
}

export interface FirewallRule {
  name: string;
  direction: "inbound" | "outbound";
  protocol: "tcp" | "udp" | "icmp" | "all";
  port?: string; // "80", "443", "1-65535"
  source: string; // CIDR or "any"
  destination: string;
  action: "allow" | "deny";
}

export interface Deployment {
  id: string;
  name: string;
  blueprintId: string;
  engagementId?: string;
  status: DeploymentStatus;
  provider: CloudProvider;
  region: string;
  /** Provisioned resources */
  resources: ProvisionedResource[];
  /** Terraform state reference */
  terraformState?: string;
  /** Deployment log */
  log: DeploymentLogEntry[];
  createdAt: number;
  updatedAt: number;
  destroyedAt?: number;
}

export interface ProvisionedResource {
  id: string;
  componentId: string;
  type: ComponentType;
  publicIp?: string;
  privateIp?: string;
  hostname?: string;
  status: "pending" | "running" | "stopped" | "terminated";
  provider: CloudProvider;
  region: string;
  size: string;
  monthlyCostUsd: number;
}

export interface DeploymentLogEntry {
  timestamp: number;
  level: "info" | "warn" | "error" | "success";
  message: string;
  component?: string;
}

// ── In-memory store ────────────────────────────────────────────────────

const blueprints = new Map<string, InfraBlueprint>();
const deployments = new Map<string, Deployment>();
let nextId = 1;

function genId(prefix: string): string {
  return `${prefix}-${Date.now()}-${nextId++}`;
}

// ── Built-in Blueprints ────────────────────────────────────────────────

const BUILT_IN_BLUEPRINTS: Omit<InfraBlueprint, "id">[] = [
  {
    name: "Basic Red Team Setup",
    description: "Minimal red team infrastructure: 1 team server, 1 HTTP redirector, 1 SMTP redirector. Suitable for small engagements.",
    components: [
      {
        id: "ts-1",
        name: "Team Server",
        type: "team_server",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-2vcpu-4gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [22],
        software: ["cobalt-strike", "sliver", "metasploit"],
        configTemplates: ["team-server-hardening.yml"],
        dependsOn: [],
      },
      {
        id: "rdr-http-1",
        name: "HTTP Redirector",
        type: "redirector",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [80, 443],
        software: ["apache2", "certbot"],
        configTemplates: ["apache-mod-rewrite.conf"],
        dependsOn: ["ts-1"],
      },
      {
        id: "rdr-smtp-1",
        name: "SMTP Redirector",
        type: "redirector",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [25, 587],
        software: ["postfix", "opendkim"],
        configTemplates: ["postfix-relay.conf"],
        dependsOn: [],
      },
    ],
    network: {
      cidr: "10.0.0.0/16",
      subnets: [
        { name: "team-servers", cidr: "10.0.1.0/24", components: ["ts-1"] },
        { name: "redirectors", cidr: "10.0.2.0/24", components: ["rdr-http-1", "rdr-smtp-1"] },
      ],
      firewallRules: [
        { name: "allow-ssh-admin", direction: "inbound", protocol: "tcp", port: "22", source: "ADMIN_CIDR", destination: "10.0.0.0/16", action: "allow" },
        { name: "allow-http", direction: "inbound", protocol: "tcp", port: "80", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-https", direction: "inbound", protocol: "tcp", port: "443", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-smtp", direction: "inbound", protocol: "tcp", port: "25", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "deny-all-inbound", direction: "inbound", protocol: "all", source: "any", destination: "10.0.0.0/16", action: "deny" },
      ],
    },
    estimatedCostUsd: 30,
    estimatedDeployMinutes: 15,
    mitreTechniques: ["T1583.001", "T1583.003", "T1584.001"],
    tags: ["basic", "small-engagement"],
  },
  {
    name: "Full Engagement Infrastructure",
    description: "Complete red team infrastructure: team server, multiple redirectors (HTTP, HTTPS, DNS, SMTP), payload host, log sink, and VPN gateway.",
    components: [
      {
        id: "ts-1",
        name: "Primary Team Server",
        type: "team_server",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-4vcpu-8gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [22],
        software: ["cobalt-strike", "sliver", "metasploit", "caldera"],
        configTemplates: ["team-server-hardening.yml", "caldera-setup.yml"],
        dependsOn: [],
      },
      {
        id: "rdr-http-1",
        name: "HTTP/S Redirector (Primary)",
        type: "redirector",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [80, 443],
        software: ["apache2", "certbot", "mod_rewrite"],
        configTemplates: ["apache-c2-redirector.conf"],
        dependsOn: ["ts-1"],
      },
      {
        id: "rdr-http-2",
        name: "HTTP/S Redirector (Backup)",
        type: "redirector",
        provider: "aws",
        region: "us-east-1",
        size: "t3.micro",
        image: "ami-ubuntu-22.04",
        exposedPorts: [80, 443],
        software: ["nginx", "certbot"],
        configTemplates: ["nginx-c2-redirector.conf"],
        dependsOn: ["ts-1"],
      },
      {
        id: "rdr-dns-1",
        name: "DNS Redirector",
        type: "dns_server",
        provider: "digitalocean",
        region: "sfo3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [53],
        software: ["socat", "dnsmasq"],
        configTemplates: ["dns-redirector.sh"],
        dependsOn: ["ts-1"],
      },
      {
        id: "rdr-smtp-1",
        name: "SMTP Redirector",
        type: "redirector",
        provider: "digitalocean",
        region: "ams3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [25, 587],
        software: ["postfix", "opendkim", "opendmarc"],
        configTemplates: ["postfix-phishing.conf", "dkim-setup.sh"],
        dependsOn: [],
      },
      {
        id: "phish-1",
        name: "Phishing Server",
        type: "phishing_server",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-2vcpu-2gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [80, 443, 3333],
        software: ["gophish", "evilginx2", "certbot"],
        configTemplates: ["gophish-setup.yml", "evilginx-config.yml"],
        dependsOn: ["rdr-smtp-1"],
      },
      {
        id: "payload-1",
        name: "Payload Host",
        type: "payload_host",
        provider: "aws",
        region: "us-east-1",
        size: "t3.micro",
        image: "ami-ubuntu-22.04",
        exposedPorts: [80, 443],
        software: ["nginx", "certbot"],
        configTemplates: ["payload-host.conf"],
        dependsOn: [],
      },
      {
        id: "log-1",
        name: "Log Aggregator",
        type: "log_sink",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-2vcpu-4gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [514, 9200],
        software: ["rsyslog", "elasticsearch", "kibana"],
        configTemplates: ["elk-setup.yml", "rsyslog-central.conf"],
        dependsOn: [],
      },
      {
        id: "vpn-1",
        name: "VPN Gateway",
        type: "vpn_gateway",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [51820],
        software: ["wireguard"],
        configTemplates: ["wireguard-setup.sh"],
        dependsOn: [],
      },
    ],
    network: {
      cidr: "10.0.0.0/16",
      subnets: [
        { name: "team-servers", cidr: "10.0.1.0/24", components: ["ts-1"] },
        { name: "redirectors", cidr: "10.0.2.0/24", components: ["rdr-http-1", "rdr-http-2", "rdr-dns-1", "rdr-smtp-1"] },
        { name: "phishing", cidr: "10.0.3.0/24", components: ["phish-1"] },
        { name: "payload", cidr: "10.0.4.0/24", components: ["payload-1"] },
        { name: "logging", cidr: "10.0.5.0/24", components: ["log-1"] },
        { name: "vpn", cidr: "10.0.6.0/24", components: ["vpn-1"] },
      ],
      firewallRules: [
        { name: "allow-vpn", direction: "inbound", protocol: "udp", port: "51820", source: "ADMIN_CIDR", destination: "10.0.6.0/24", action: "allow" },
        { name: "allow-ssh-vpn", direction: "inbound", protocol: "tcp", port: "22", source: "10.0.6.0/24", destination: "10.0.0.0/16", action: "allow" },
        { name: "allow-http-redirectors", direction: "inbound", protocol: "tcp", port: "80", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-https-redirectors", direction: "inbound", protocol: "tcp", port: "443", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-dns", direction: "inbound", protocol: "udp", port: "53", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-smtp", direction: "inbound", protocol: "tcp", port: "25", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-internal", direction: "inbound", protocol: "all", source: "10.0.0.0/16", destination: "10.0.0.0/16", action: "allow" },
        { name: "deny-all", direction: "inbound", protocol: "all", source: "any", destination: "10.0.0.0/16", action: "deny" },
      ],
      vpn: { type: "wireguard", serverComponent: "vpn-1" },
    },
    estimatedCostUsd: 120,
    estimatedDeployMinutes: 45,
    mitreTechniques: ["T1583.001", "T1583.003", "T1583.006", "T1584.001", "T1584.004", "T1585.002"],
    tags: ["full", "enterprise", "multi-provider"],
  },
  {
    name: "Phishing Campaign Infrastructure",
    description: "Focused phishing infrastructure: GoPhish server, SMTP relay with DKIM/DMARC, Evilginx2 for credential harvesting, and payload hosting.",
    components: [
      {
        id: "phish-1",
        name: "GoPhish + Evilginx Server",
        type: "phishing_server",
        provider: "digitalocean",
        region: "nyc3",
        size: "s-2vcpu-4gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [80, 443, 3333],
        software: ["gophish", "evilginx2", "certbot", "caddy"],
        configTemplates: ["gophish-setup.yml", "evilginx-phishlets.yml"],
        dependsOn: [],
      },
      {
        id: "smtp-1",
        name: "SMTP Relay",
        type: "redirector",
        provider: "digitalocean",
        region: "ams3",
        size: "s-1vcpu-1gb",
        image: "ubuntu-22-04-x64",
        exposedPorts: [25, 587],
        software: ["postfix", "opendkim", "opendmarc", "spamassassin"],
        configTemplates: ["postfix-phishing.conf", "dkim-keygen.sh", "dmarc-setup.sh"],
        dependsOn: [],
      },
      {
        id: "payload-1",
        name: "Payload Staging",
        type: "payload_host",
        provider: "aws",
        region: "us-east-1",
        size: "t3.micro",
        image: "ami-ubuntu-22.04",
        exposedPorts: [80, 443],
        software: ["nginx", "certbot"],
        configTemplates: ["payload-host-timed.conf"],
        dependsOn: [],
      },
    ],
    network: {
      cidr: "10.0.0.0/16",
      subnets: [
        { name: "phishing", cidr: "10.0.1.0/24", components: ["phish-1"] },
        { name: "smtp", cidr: "10.0.2.0/24", components: ["smtp-1"] },
        { name: "payload", cidr: "10.0.3.0/24", components: ["payload-1"] },
      ],
      firewallRules: [
        { name: "allow-http", direction: "inbound", protocol: "tcp", port: "80", source: "any", destination: "10.0.0.0/16", action: "allow" },
        { name: "allow-https", direction: "inbound", protocol: "tcp", port: "443", source: "any", destination: "10.0.0.0/16", action: "allow" },
        { name: "allow-smtp", direction: "inbound", protocol: "tcp", port: "25", source: "any", destination: "10.0.2.0/24", action: "allow" },
        { name: "allow-ssh-admin", direction: "inbound", protocol: "tcp", port: "22", source: "ADMIN_CIDR", destination: "10.0.0.0/16", action: "allow" },
      ],
    },
    estimatedCostUsd: 45,
    estimatedDeployMinutes: 25,
    mitreTechniques: ["T1566.001", "T1566.002", "T1583.001", "T1585.002", "T1608.001"],
    tags: ["phishing", "email", "credential-harvesting"],
  },
];

// ── Initialize ─────────────────────────────────────────────────────────

export function initBlueprints(): void {
  for (const bp of BUILT_IN_BLUEPRINTS) {
    const id = genId("bp");
    blueprints.set(id, { ...bp, id });
  }
}

// ── Blueprint CRUD ─────────────────────────────────────────────────────

export function listBlueprints(): InfraBlueprint[] {
  return Array.from(blueprints.values());
}

export function getBlueprint(id: string): InfraBlueprint | undefined {
  return blueprints.get(id);
}

export function createBlueprint(input: Omit<InfraBlueprint, "id">): InfraBlueprint {
  const id = genId("bp");
  const bp: InfraBlueprint = { ...input, id };
  blueprints.set(id, bp);
  return bp;
}

// ── Deployment Management ──────────────────────────────────────────────

export function createDeployment(input: {
  name: string;
  blueprintId: string;
  engagementId?: string;
  provider: CloudProvider;
  region: string;
}): Deployment | null {
  const blueprint = blueprints.get(input.blueprintId);
  if (!blueprint) return null;

  const id = genId("deploy");
  const deployment: Deployment = {
    id,
    name: input.name,
    blueprintId: input.blueprintId,
    engagementId: input.engagementId,
    status: "draft",
    provider: input.provider,
    region: input.region,
    resources: [],
    log: [{ timestamp: Date.now(), level: "info", message: `Deployment "${input.name}" created from blueprint "${blueprint.name}"` }],
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };

  deployments.set(id, deployment);
  return deployment;
}

export function startDeployment(id: string): Deployment | null {
  const deployment = deployments.get(id);
  if (!deployment || deployment.status !== "draft") return null;

  const blueprint = blueprints.get(deployment.blueprintId);
  if (!blueprint) return null;

  deployment.status = "deploying";
  deployment.log.push({ timestamp: Date.now(), level: "info", message: "Starting infrastructure deployment..." });

  // Simulate provisioning resources
  for (const component of blueprint.components) {
    const resource: ProvisionedResource = {
      id: genId("res"),
      componentId: component.id,
      type: component.type,
      publicIp: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      privateIp: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      hostname: `${component.name.toLowerCase().replace(/[^a-z0-9]/g, "-")}-${id.slice(-4)}`,
      status: "running",
      provider: component.provider,
      region: component.region,
      size: component.size,
      monthlyCostUsd: component.size.includes("4gb") ? 24 : component.size.includes("8gb") ? 48 : 6,
    };
    deployment.resources.push(resource);
    deployment.log.push({
      timestamp: Date.now(),
      level: "success",
      message: `Provisioned ${component.name} (${resource.publicIp})`,
      component: component.id,
    });
  }

  deployment.status = "active";
  deployment.updatedAt = Date.now();
  deployment.log.push({ timestamp: Date.now(), level: "success", message: "All resources provisioned successfully" });

  return deployment;
}

export function destroyDeployment(id: string): Deployment | null {
  const deployment = deployments.get(id);
  if (!deployment || deployment.status === "destroyed") return null;

  deployment.status = "destroying";
  deployment.log.push({ timestamp: Date.now(), level: "info", message: "Destroying infrastructure..." });

  for (const resource of deployment.resources) {
    resource.status = "terminated";
    deployment.log.push({
      timestamp: Date.now(),
      level: "info",
      message: `Terminated ${resource.hostname} (${resource.publicIp})`,
    });
  }

  deployment.status = "destroyed";
  deployment.destroyedAt = Date.now();
  deployment.updatedAt = Date.now();
  deployment.log.push({ timestamp: Date.now(), level: "success", message: "All resources destroyed" });

  return deployment;
}

export function getDeployment(id: string): Deployment | undefined {
  return deployments.get(id);
}

export function listDeployments(filters?: { status?: DeploymentStatus; engagementId?: string }): Deployment[] {
  let results = Array.from(deployments.values());
  if (filters?.status) results = results.filter(d => d.status === filters.status);
  if (filters?.engagementId) results = results.filter(d => d.engagementId === filters.engagementId);
  return results.sort((a, b) => b.createdAt - a.createdAt);
}

// ── Terraform Generation ───────────────────────────────────────────────

export function generateTerraform(blueprintId: string, vars: {
  provider: CloudProvider;
  region: string;
  sshKeyFingerprint: string;
  adminCidr: string;
}): string | null {
  const bp = blueprints.get(blueprintId);
  if (!bp) return null;

  if (vars.provider === "digitalocean") {
    return generateDoTerraform(bp, vars);
  }
  if (vars.provider === "aws") {
    return generateAwsTerraform(bp, vars);
  }
  return `# Terraform generation for ${vars.provider} not yet implemented\n# Blueprint: ${bp.name}`;
}

function generateDoTerraform(bp: InfraBlueprint, vars: { region: string; sshKeyFingerprint: string; adminCidr: string }): string {
  let tf = `# Terraform Configuration — ${bp.name}
# Generated by Ace C3 Infrastructure Automation
# Provider: DigitalOcean | Region: ${vars.region}

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "ssh_key_fingerprint" {
  default = "${vars.sshKeyFingerprint}"
}

variable "admin_cidr" {
  default = "${vars.adminCidr}"
}

provider "digitalocean" {
  token = var.do_token
}

# VPC
resource "digitalocean_vpc" "redteam" {
  name     = "redteam-vpc"
  region   = "${vars.region}"
  ip_range = "${bp.network.cidr}"
}

`;

  for (const component of bp.components) {
    if (component.provider !== "digitalocean") continue;
    const safeName = component.name.toLowerCase().replace(/[^a-z0-9]/g, "_");
    tf += `# ${component.name} (${component.type})
resource "digitalocean_droplet" "${safeName}" {
  image    = "${component.image}"
  name     = "${safeName}"
  region   = "${vars.region}"
  size     = "${component.size}"
  vpc_uuid = digitalocean_vpc.redteam.id
  ssh_keys = [var.ssh_key_fingerprint]

  tags = [${component.software.map(s => `"${s}"`).join(", ")}]
}

`;
  }

  // Firewall
  tf += `# Firewall Rules
resource "digitalocean_firewall" "redteam" {
  name = "redteam-firewall"

  droplet_ids = [${bp.components.filter(c => c.provider === "digitalocean").map(c => `digitalocean_droplet.${c.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}.id`).join(", ")}]

`;

  for (const rule of bp.network.firewallRules) {
    if (rule.action === "allow" && rule.direction === "inbound") {
      const src = rule.source === "ADMIN_CIDR" ? "${var.admin_cidr}" : rule.source === "any" ? "0.0.0.0/0" : rule.source;
      tf += `  inbound_rule {
    protocol         = "${rule.protocol}"
    port_range       = "${rule.port || "1-65535"}"
    source_addresses = ["${src}"]
  }

`;
    }
  }

  tf += `  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }
}

# Outputs
${bp.components.filter(c => c.provider === "digitalocean").map(c => {
  const safeName = c.name.toLowerCase().replace(/[^a-z0-9]/g, "_");
  return `output "${safeName}_ip" {
  value = digitalocean_droplet.${safeName}.ipv4_address
}`;
}).join("\n\n")}
`;

  return tf;
}

function generateAwsTerraform(bp: InfraBlueprint, vars: { region: string; sshKeyFingerprint: string; adminCidr: string }): string {
  return `# Terraform Configuration — ${bp.name}
# Generated by Ace C3 Infrastructure Automation
# Provider: AWS | Region: ${vars.region}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "aws_region" {
  default = "${vars.region}"
}

variable "admin_cidr" {
  default = "${vars.adminCidr}"
}

provider "aws" {
  region = var.aws_region
}

# VPC
resource "aws_vpc" "redteam" {
  cidr_block = "${bp.network.cidr}"
  tags = { Name = "redteam-vpc" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.redteam.id
}

# Security Group
resource "aws_security_group" "redteam" {
  name   = "redteam-sg"
  vpc_id = aws_vpc.redteam.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 Instances
${bp.components.filter(c => c.provider === "aws").map(c => {
  const safeName = c.name.toLowerCase().replace(/[^a-z0-9]/g, "_");
  return `resource "aws_instance" "${safeName}" {
  ami           = "${c.image}"
  instance_type = "${c.size}"
  vpc_security_group_ids = [aws_security_group.redteam.id]
  tags = { Name = "${c.name}" }
}`;
}).join("\n\n")}
`;
}

// ── Ansible Generation ─────────────────────────────────────────────────

export function generateAnsiblePlaybook(blueprintId: string): string | null {
  const bp = blueprints.get(blueprintId);
  if (!bp) return null;

  let playbook = `---
# Ansible Playbook — ${bp.name}
# Generated by Ace C3 Infrastructure Automation

`;

  for (const component of bp.components) {
    const safeName = component.name.toLowerCase().replace(/[^a-z0-9]/g, "_");
    playbook += `- name: Configure ${component.name}
  hosts: ${safeName}
  become: yes
  tasks:
    - name: Update system packages
      apt:
        update_cache: yes
        upgrade: dist

    - name: Install required packages
      apt:
        name:
${component.software.map(s => `          - ${s}`).join("\n")}
        state: present

    - name: Configure firewall (ufw)
      ufw:
        rule: allow
        port: "{{ item }}"
        proto: tcp
      loop:
${component.exposedPorts.map(p => `        - "${p}"`).join("\n")}

    - name: Enable UFW
      ufw:
        state: enabled
        policy: deny

    - name: Harden SSH
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin prohibit-password' }
        - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^X11Forwarding', line: 'X11Forwarding no' }
      notify: restart sshd

  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted

`;
  }

  return playbook;
}

// ── Reset (for testing) ────────────────────────────────────────────────

export function _resetForTesting(): void {
  blueprints.clear();
  deployments.clear();
  nextId = 1;
}
