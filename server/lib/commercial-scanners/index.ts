/**
 * Commercial Scanner Connectors
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * API client implementations for FedRAMP/NIST/DoD-approved commercial
 * scanning platforms. Each connector provides:
 *   - Credential validation (testConnection)
 *   - Scan launching
 *   - Result fetching and normalization to AC3 unified format
 *   - Asset/target management
 * 
 * Licensing: All connectors are BYOL (Bring Your Own License).
 * The customer provides their own API credentials.
 */

export { TenableConnector } from "./tenable";
export { QualysConnector } from "./qualys";
export { Rapid7Connector } from "./rapid7";
export { VeracodeConnector } from "./veracode";
export { CheckmarxConnector } from "./checkmarx";
export { FortifyConnector } from "./fortify";
export { PrismaCloudConnector } from "./prisma-cloud";
export { WizConnector } from "./wiz";
export { CrowdStrikeConnector } from "./crowdstrike";
export { MsDefenderConnector } from "./ms-defender";
export { AnchoreConnector } from "./anchore";
export { SnykConnector } from "./snyk";
export { BurpEnterpriseConnector } from "./burp-enterprise";
export { HclAppScanConnector } from "./hcl-appscan";
export { AcunetixConnector } from "./acunetix";
export { SonarQubeConnector } from "./sonarqube";

export type { CommercialScannerConfig, ScanResult, NormalizedFinding, ConnectorHealth } from "./types";
