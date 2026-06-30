/**
 * Connector Factory
 * Instantiates the correct commercial scanner connector based on platform ID.
 */
import type { CommercialScannerConfig, ICommercialScanner } from "./types";
import { TenableConnector } from "./tenable";
import { QualysConnector } from "./qualys";
import { Rapid7Connector } from "./rapid7";
import { VeracodeConnector } from "./veracode";
import { CheckmarxConnector } from "./checkmarx";
import { FortifyConnector } from "./fortify";
import { PrismaCloudConnector } from "./prisma-cloud";
import { WizConnector } from "./wiz";
import { CrowdStrikeConnector } from "./crowdstrike";
import { MsDefenderConnector } from "./ms-defender";
import { AnchoreConnector } from "./anchore";
import { SnykConnector } from "./snyk";
import { BurpEnterpriseConnector } from "./burp-enterprise";
import { HclAppScanConnector } from "./hcl-appscan";
import { AcunetixConnector } from "./acunetix";
import { SonarQubeConnector } from "./sonarqube";

const CONNECTOR_MAP: Record<string, new (config: CommercialScannerConfig) => ICommercialScanner> = {
  tenable_io: TenableConnector,
  qualys_vmdr: QualysConnector,
  rapid7_insightvm: Rapid7Connector,
  veracode: VeracodeConnector,
  checkmarx_one: CheckmarxConnector,
  fortify_on_demand: FortifyConnector,
  prisma_cloud: PrismaCloudConnector,
  wiz: WizConnector,
  crowdstrike_falcon: CrowdStrikeConnector,
  ms_defender_vuln: MsDefenderConnector,
  anchore_enterprise: AnchoreConnector,
  snyk: SnykConnector,
  burp_suite_enterprise: BurpEnterpriseConnector,
  hcl_appscan: HclAppScanConnector,
  acunetix: AcunetixConnector,
  sonarqube: SonarQubeConnector,
};

/**
 * Create a connector instance for the given platform.
 */
export function createConnector(config: CommercialScannerConfig): ICommercialScanner {
  const ConnectorClass = CONNECTOR_MAP[config.platform];
  if (!ConnectorClass) {
    throw new Error(`Unsupported scanner platform: ${config.platform}. Supported: ${Object.keys(CONNECTOR_MAP).join(", ")}`);
  }
  return new ConnectorClass(config);
}

/**
 * Get list of all supported platforms.
 */
export function getSupportedPlatforms(): string[] {
  return Object.keys(CONNECTOR_MAP);
}

/**
 * Platform metadata for UI display.
 */
export const PLATFORM_METADATA: Record<string, {
  name: string;
  vendor: string;
  fedRampLevel: string;
  scanTypes: string[];
  authFields: Array<{ key: string; label: string; type: "text" | "password"; required: boolean }>;
  defaultBaseUrl: string;
}> = {
  tenable_io: {
    name: "Tenable.io", vendor: "Tenable", fedRampLevel: "FedRAMP High",
    scanTypes: ["Network Vulnerability", "Web Application", "Compliance Audit"],
    authFields: [
      { key: "accessKey", label: "Access Key", type: "password", required: true },
      { key: "secretKey", label: "Secret Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://cloud.tenable.com",
  },
  qualys_vmdr: {
    name: "Qualys VMDR", vendor: "Qualys", fedRampLevel: "FedRAMP High",
    scanTypes: ["Network Vulnerability", "Web Application", "Compliance", "Patch Management"],
    authFields: [
      { key: "username", label: "Username", type: "text", required: true },
      { key: "password", label: "Password", type: "password", required: true },
    ],
    defaultBaseUrl: "https://qualysapi.qualys.com",
  },
  rapid7_insightvm: {
    name: "Rapid7 InsightVM", vendor: "Rapid7", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["Network Vulnerability", "Agent-Based", "Container"],
    authFields: [
      { key: "apiKey", label: "API Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://us.api.insight.rapid7.com",
  },
  veracode: {
    name: "Veracode", vendor: "Veracode", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["SAST", "DAST", "SCA", "Manual Penetration Testing"],
    authFields: [
      { key: "apiId", label: "API ID", type: "text", required: true },
      { key: "apiKey", label: "API Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://analysiscenter.veracode.com",
  },
  checkmarx_one: {
    name: "Checkmarx One", vendor: "Checkmarx", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["SAST", "SCA", "IaC (KICS)", "API Security"],
    authFields: [
      { key: "clientId", label: "Client ID", type: "text", required: true },
      { key: "clientSecret", label: "Client Secret", type: "password", required: true },
      { key: "tenant", label: "Tenant ID", type: "text", required: true },
    ],
    defaultBaseUrl: "https://ast.checkmarx.net",
  },
  fortify_on_demand: {
    name: "Fortify on Demand", vendor: "OpenText (Micro Focus)", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["SAST", "DAST", "Mobile"],
    authFields: [
      { key: "clientId", label: "API Key", type: "text", required: true },
      { key: "clientSecret", label: "API Secret", type: "password", required: true },
      { key: "tenant", label: "Tenant Code", type: "text", required: true },
    ],
    defaultBaseUrl: "https://api.ams.fortify.com",
  },
  prisma_cloud: {
    name: "Prisma Cloud", vendor: "Palo Alto Networks", fedRampLevel: "FedRAMP High",
    scanTypes: ["CSPM", "CWPP", "CIEM", "IaC", "Container"],
    authFields: [
      { key: "accessKey", label: "Access Key", type: "text", required: true },
      { key: "secretKey", label: "Secret Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://api.prismacloud.io",
  },
  wiz: {
    name: "Wiz", vendor: "Wiz", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["CSPM", "Vulnerability", "Attack Path", "IaC", "Container"],
    authFields: [
      { key: "clientId", label: "Client ID", type: "text", required: true },
      { key: "clientSecret", label: "Client Secret", type: "password", required: true },
    ],
    defaultBaseUrl: "https://api.us1.app.wiz.io",
  },
  crowdstrike_falcon: {
    name: "CrowdStrike Falcon", vendor: "CrowdStrike", fedRampLevel: "FedRAMP High / DoD IL5",
    scanTypes: ["EDR", "Vulnerability Assessment (Spotlight)", "IoT"],
    authFields: [
      { key: "clientId", label: "Client ID", type: "text", required: true },
      { key: "clientSecret", label: "Client Secret", type: "password", required: true },
    ],
    defaultBaseUrl: "https://api.crowdstrike.com",
  },
  ms_defender_vuln: {
    name: "Microsoft Defender Vulnerability Management", vendor: "Microsoft", fedRampLevel: "FedRAMP High / DoD IL5",
    scanTypes: ["Endpoint Vulnerability", "Threat & Vulnerability Management"],
    authFields: [
      { key: "tenantId", label: "Tenant ID", type: "text", required: true },
      { key: "clientId", label: "Application (Client) ID", type: "text", required: true },
      { key: "clientSecret", label: "Client Secret", type: "password", required: true },
    ],
    defaultBaseUrl: "https://api.securitycenter.microsoft.com",
  },
  anchore_enterprise: {
    name: "Anchore Enterprise", vendor: "Anchore", fedRampLevel: "FedRAMP Moderate / DoD Iron Bank",
    scanTypes: ["Container Vulnerability", "SBOM", "Compliance"],
    authFields: [
      { key: "username", label: "Username", type: "text", required: true },
      { key: "password", label: "Password", type: "password", required: true },
    ],
    defaultBaseUrl: "https://anchore.example.com/v1",
  },
  snyk: {
    name: "Snyk", vendor: "Snyk", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["SCA", "SAST", "Container", "IaC"],
    authFields: [
      { key: "token", label: "API Token", type: "password", required: true },
      { key: "orgId", label: "Organization ID", type: "text", required: true },
    ],
    defaultBaseUrl: "https://api.snyk.io",
  },
  burp_suite_enterprise: {
    name: "Burp Suite Enterprise", vendor: "PortSwigger", fedRampLevel: "NIST Approved",
    scanTypes: ["DAST", "Web Application"],
    authFields: [
      { key: "apiKey", label: "API Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://burp.example.com",
  },
  hcl_appscan: {
    name: "HCL AppScan", vendor: "HCL Technologies", fedRampLevel: "FedRAMP Moderate",
    scanTypes: ["DAST", "SAST", "IAST", "SCA"],
    authFields: [
      { key: "apiKey", label: "Key ID", type: "text", required: true },
      { key: "apiSecret", label: "Key Secret", type: "password", required: true },
    ],
    defaultBaseUrl: "https://cloud.appscan.com",
  },
  acunetix: {
    name: "Acunetix", vendor: "Invicti (Acunetix)", fedRampLevel: "NIST/DoD Approved",
    scanTypes: ["DAST", "Web Application", "API"],
    authFields: [
      { key: "apiKey", label: "API Key", type: "password", required: true },
    ],
    defaultBaseUrl: "https://acunetix.example.com",
  },
  sonarqube: {
    name: "SonarQube", vendor: "SonarSource", fedRampLevel: "NIST Approved",
    scanTypes: ["SAST", "Code Quality", "Security Hotspots"],
    authFields: [
      { key: "token", label: "User Token", type: "password", required: true },
    ],
    defaultBaseUrl: "https://sonarqube.example.com",
  },
};
