/**
 * Microsoft Fabric Scanner API Integration
 *
 * Provides credentialed scanning of a client's Microsoft Fabric environment
 * using the Fabric Admin REST APIs and Scanner APIs. Requires an Entra ID
 * Service Principal with Fabric.Read.All or Tenant.Read.All permissions,
 * and the Fabric admin must enable "Service principals can access admin APIs"
 * in the Fabric Admin Portal.
 *
 * Scanner API workflow:
 *   1. GetModifiedWorkspaces — discover workspaces changed since last scan
 *   2. PostWorkspaceInfo     — initiate metadata scan for selected workspaces
 *   3. GetScanStatus         — poll until scan completes
 *   4. GetScanResult         — retrieve full metadata for scanned workspaces
 *
 * @module fabric-scanner
 */

// ── Types ───────────────────────────────────────────────────────────────────

export interface FabricCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface FabricWorkspace {
  id: string;
  name: string;
  type?: string;
  state?: string;
  capacityId?: string;
  isOnDedicatedCapacity?: boolean;
}

export interface FabricItem {
  id: string;
  name: string;
  type: string; // Report, Dashboard, Dataset, Dataflow, Lakehouse, Notebook, etc.
  createdBy?: string;
  modifiedBy?: string;
  createdDateTime?: string;
  modifiedDateTime?: string;
  sensitivityLabel?: {
    labelId: string;
    labelName?: string;
  } | null;
  endorsementDetails?: {
    endorsement: string; // Promoted, Certified, None
    certifiedBy?: string;
  } | null;
  description?: string;
}

export interface FabricUser {
  displayName: string;
  emailAddress?: string;
  principalType: string; // User, Group, App
  identifier: string;
  graphId?: string;
  userType?: string;
  fabricItemAccessRights?: string;
}

export interface FabricDataSource {
  datasourceType?: string;
  connectionDetails?: {
    server?: string;
    database?: string;
    url?: string;
    path?: string;
  };
  datasourceId?: string;
  gatewayId?: string;
}

export interface FabricMisconfiguration {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  affectedResources: string[];
  recommendation: string;
  cisBenchmark?: string;
}

export interface FabricScanResult {
  tenantId: string;
  scanTimestamp: Date;
  workspaces: FabricWorkspaceDetail[];
  summary: FabricScanSummary;
  misconfigurations: FabricMisconfiguration[];
  errors: string[];
}

export interface FabricWorkspaceDetail {
  workspace: FabricWorkspace;
  items: FabricItem[];
  users: FabricUser[];
  dataSources: FabricDataSource[];
}

export interface FabricScanSummary {
  totalWorkspaces: number;
  totalItems: number;
  totalUsers: number;
  totalDataSources: number;
  totalMisconfigurations: number;
  itemsByType: Record<string, number>;
  workspacesWithoutLabels: number;
  workspacesWithExternalSharing: number;
  privilegedUsers: number;
  endorsedItems: number;
  certifiedItems: number;
}

// ── Authentication ──────────────────────────────────────────────────────────

/**
 * Authenticate with Entra ID and obtain an access token for the Fabric/Power BI Admin API.
 */
async function getAccessToken(creds: FabricCredentials): Promise<string> {
  const { ClientSecretCredential } = await import("@azure/identity");
  const credential = new ClientSecretCredential(creds.tenantId, creds.clientId, creds.clientSecret);
  // Power BI / Fabric Admin API scope
  const tokenResponse = await credential.getToken("https://analysis.windows.net/powerbi/api/.default");
  return tokenResponse.token;
}

/**
 * Validate that the service principal can authenticate and has Fabric API access.
 */
export async function validateFabricCredentials(
  creds: FabricCredentials
): Promise<{ valid: boolean; identity?: string; error?: string }> {
  try {
    const token = await getAccessToken(creds);
    // Test with a simple admin API call
    const resp = await fetch("https://api.powerbi.com/v1.0/myorg/admin/groups?$top=1", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (resp.ok) {
      return { valid: true, identity: `Fabric SP: ${creds.clientId} @ ${creds.tenantId}` };
    }
    const errorBody = await resp.text();
    return { valid: false, error: `Fabric API returned ${resp.status}: ${errorBody.slice(0, 200)}` };
  } catch (e: any) {
    return { valid: false, error: `Authentication failed: ${e.message}` };
  }
}

// ── Scanner API Workflow ────────────────────────────────────────────────────

/**
 * Step 1: Get workspaces modified since a given date (or all workspaces).
 */
async function getModifiedWorkspaces(
  token: string,
  modifiedSince?: Date
): Promise<string[]> {
  let url = "https://api.powerbi.com/v1.0/myorg/admin/workspaces/modified";
  if (modifiedSince) {
    url += `?modifiedSince=${modifiedSince.toISOString()}`;
  }
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) {
    throw new Error(`GetModifiedWorkspaces failed: ${resp.status} ${await resp.text()}`);
  }
  const data = await resp.json() as any[];
  return data.map((w: any) => w.id);
}

/**
 * Step 2: Initiate a metadata scan for a batch of workspace IDs (max 100 per call).
 */
async function postWorkspaceInfo(
  token: string,
  workspaceIds: string[],
  options?: {
    lineageEnabled?: boolean;
    datasourceDetailsEnabled?: boolean;
    datasetSchemaEnabled?: boolean;
    datasetExpressionEnabled?: boolean;
    getArtifactUsersEnabled?: boolean;
  }
): Promise<string> {
  const queryParams: string[] = [];
  if (options?.lineageEnabled) queryParams.push("lineage=True");
  if (options?.datasourceDetailsEnabled) queryParams.push("datasourceDetails=True");
  if (options?.datasetSchemaEnabled) queryParams.push("datasetSchema=True");
  if (options?.datasetExpressionEnabled) queryParams.push("datasetExpressions=True");
  if (options?.getArtifactUsersEnabled) queryParams.push("getArtifactUsers=True");

  const url = `https://api.powerbi.com/v1.0/myorg/admin/workspaces/getInfo${queryParams.length ? "?" + queryParams.join("&") : ""}`;

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ workspaces: workspaceIds }),
  });
  if (!resp.ok) {
    throw new Error(`PostWorkspaceInfo failed: ${resp.status} ${await resp.text()}`);
  }
  const data = await resp.json() as any;
  return data.id; // scan ID
}

/**
 * Step 3: Poll scan status until completed.
 */
async function waitForScanCompletion(
  token: string,
  scanId: string,
  maxWaitMs: number = 300_000 // 5 minutes
): Promise<void> {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    const resp = await fetch(
      `https://api.powerbi.com/v1.0/myorg/admin/workspaces/scanStatus/${scanId}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    if (!resp.ok) {
      throw new Error(`GetScanStatus failed: ${resp.status} ${await resp.text()}`);
    }
    const data = await resp.json() as any;
    if (data.status === "Succeeded") return;
    if (data.status === "Failed") {
      throw new Error(`Scan failed: ${JSON.stringify(data.error || data)}`);
    }
    // Poll every 3 seconds
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  throw new Error(`Scan timed out after ${maxWaitMs / 1000}s`);
}

/**
 * Step 4: Retrieve full scan results.
 */
async function getScanResult(
  token: string,
  scanId: string
): Promise<any> {
  const resp = await fetch(
    `https://api.powerbi.com/v1.0/myorg/admin/workspaces/scanResult/${scanId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!resp.ok) {
    throw new Error(`GetScanResult failed: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

// ── Workspace Enumeration (Admin API) ───────────────────────────────────────

/**
 * List all workspaces via the Admin API (paginated).
 */
async function listAllWorkspaces(token: string): Promise<FabricWorkspace[]> {
  const workspaces: FabricWorkspace[] = [];
  let url: string | null = "https://api.powerbi.com/v1.0/myorg/admin/groups?$top=5000";

  while (url) {
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) {
      throw new Error(`List workspaces failed: ${resp.status} ${await resp.text()}`);
    }
    const data = await resp.json() as any;
    for (const ws of data.value || []) {
      workspaces.push({
        id: ws.id,
        name: ws.name,
        type: ws.type,
        state: ws.state,
        capacityId: ws.capacityId,
        isOnDedicatedCapacity: ws.isOnDedicatedCapacity,
      });
    }
    url = data["@odata.nextLink"] || null;
  }
  return workspaces;
}

// ── Misconfiguration Detection ──────────────────────────────────────────────

function detectMisconfigurations(
  workspaceDetails: FabricWorkspaceDetail[]
): FabricMisconfiguration[] {
  const misconfigs: FabricMisconfiguration[] = [];

  for (const wd of workspaceDetails) {
    const wsName = wd.workspace.name;

    // 1. Items without sensitivity labels
    const unlabeledItems = wd.items.filter(i => !i.sensitivityLabel);
    if (unlabeledItems.length > 0) {
      misconfigs.push({
        type: "missing_sensitivity_labels",
        severity: "medium",
        description: `${unlabeledItems.length} items in workspace "${wsName}" lack sensitivity labels`,
        affectedResources: unlabeledItems.map(i => `${i.type}: ${i.name}`),
        recommendation: "Apply sensitivity labels to all Fabric items to ensure proper data classification and DLP policy enforcement.",
        cisBenchmark: "CIS M365 5.1.2",
      });
    }

    // 2. Unendorsed datasets/reports
    const unendorsedDatasets = wd.items.filter(
      i => (i.type === "Dataset" || i.type === "SemanticModel") && (!i.endorsementDetails || i.endorsementDetails.endorsement === "None")
    );
    if (unendorsedDatasets.length > 3) {
      misconfigs.push({
        type: "unendorsed_datasets",
        severity: "low",
        description: `${unendorsedDatasets.length} datasets in workspace "${wsName}" are not endorsed or certified`,
        affectedResources: unendorsedDatasets.map(i => i.name),
        recommendation: "Endorse or certify trusted datasets to help users identify authoritative data sources.",
      });
    }

    // 3. External/guest users with access
    const externalUsers = wd.users.filter(
      u => u.userType === "Guest" || u.principalType === "App"
    );
    if (externalUsers.length > 0) {
      misconfigs.push({
        type: "external_user_access",
        severity: "high",
        description: `${externalUsers.length} external/guest users or apps have access to workspace "${wsName}"`,
        affectedResources: externalUsers.map(u => `${u.principalType}: ${u.displayName} (${u.emailAddress || u.identifier})`),
        recommendation: "Review external user access and remove unnecessary guest accounts. Ensure B2B sharing policies are properly configured.",
        cisBenchmark: "CIS M365 5.2.1",
      });
    }

    // 4. Overly broad workspace access (Admin role to many users)
    const adminUsers = wd.users.filter(
      u => u.fabricItemAccessRights?.includes("Admin") || u.fabricItemAccessRights?.includes("ReadWriteReshare")
    );
    if (adminUsers.length > 5) {
      misconfigs.push({
        type: "excessive_workspace_admins",
        severity: "medium",
        description: `${adminUsers.length} users have Admin/ReadWriteReshare access to workspace "${wsName}"`,
        affectedResources: adminUsers.map(u => `${u.displayName} (${u.principalType})`),
        recommendation: "Limit workspace admin access to a small number of trusted users. Use Viewer or Contributor roles for broader access.",
      });
    }

    // 5. Data sources with gateway bindings (on-prem exposure)
    const gatewayBound = wd.dataSources.filter(ds => ds.gatewayId);
    if (gatewayBound.length > 0) {
      misconfigs.push({
        type: "gateway_bound_datasources",
        severity: "info",
        description: `${gatewayBound.length} data sources in workspace "${wsName}" use on-premises data gateways`,
        affectedResources: gatewayBound.map(ds => `${ds.datasourceType}: ${ds.connectionDetails?.server || ds.connectionDetails?.url || "unknown"}`),
        recommendation: "Ensure on-premises data gateways are patched, use encrypted connections, and have restricted admin access.",
      });
    }

    // 6. Data sources with plain-text connection strings
    const plainTextConnections = wd.dataSources.filter(
      ds => ds.connectionDetails?.server && !ds.connectionDetails.server.includes("encrypted")
    );
    if (plainTextConnections.length > 0) {
      misconfigs.push({
        type: "unencrypted_datasource_connections",
        severity: "medium",
        description: `${plainTextConnections.length} data sources in workspace "${wsName}" may use unencrypted connections`,
        affectedResources: plainTextConnections.map(ds => `${ds.datasourceType}: ${ds.connectionDetails?.server || "unknown"}`),
        recommendation: "Ensure all data source connections use TLS/SSL encryption. Review connection strings for embedded credentials.",
      });
    }

    // 7. Workspace not on dedicated capacity (shared capacity = noisy neighbor risk)
    if (!wd.workspace.isOnDedicatedCapacity) {
      misconfigs.push({
        type: "shared_capacity",
        severity: "low",
        description: `Workspace "${wsName}" is on shared capacity (not dedicated/premium)`,
        affectedResources: [wsName],
        recommendation: "Consider moving sensitive workspaces to dedicated capacity for better isolation, performance, and governance controls.",
      });
    }
  }

  // 8. Global check: workspaces with no items (stale/orphaned)
  const emptyWorkspaces = workspaceDetails.filter(wd => wd.items.length === 0);
  if (emptyWorkspaces.length > 0) {
    misconfigs.push({
      type: "empty_workspaces",
      severity: "low",
      description: `${emptyWorkspaces.length} workspaces have no items (potentially orphaned)`,
      affectedResources: emptyWorkspaces.map(wd => wd.workspace.name),
      recommendation: "Review and remove empty workspaces to reduce attack surface and simplify governance.",
    });
  }

  return misconfigs;
}

// ── Main Scan Function ──────────────────────────────────────────────────────

/**
 * Run a full Microsoft Fabric security scan.
 *
 * @param creds - Entra ID service principal credentials
 * @param options - Scan options
 * @returns Complete scan results with misconfigurations
 */
export async function scanFabricEnvironment(
  creds: FabricCredentials,
  options?: {
    modifiedSince?: Date;
    includeLineage?: boolean;
    includeDatasourceDetails?: boolean;
    includeDatasetSchema?: boolean;
    includeDatasetExpressions?: boolean;
    includeArtifactUsers?: boolean;
    maxWorkspacesPerBatch?: number;
  }
): Promise<FabricScanResult> {
  const errors: string[] = [];
  const allWorkspaceDetails: FabricWorkspaceDetail[] = [];
  const scanTimestamp = new Date();

  const token = await getAccessToken(creds);

  // Step 1: Discover workspaces
  let workspaceIds: string[];
  try {
    if (options?.modifiedSince) {
      workspaceIds = await getModifiedWorkspaces(token, options.modifiedSince);
    } else {
      const allWorkspaces = await listAllWorkspaces(token);
      workspaceIds = allWorkspaces.map(w => w.id);
    }
  } catch (e: any) {
    errors.push(`Workspace discovery failed: ${e.message}`);
    return {
      tenantId: creds.tenantId,
      scanTimestamp,
      workspaces: [],
      summary: emptySummary(),
      misconfigurations: [],
      errors,
    };
  }

  // Step 2-4: Scan workspaces in batches of 100 (API limit)
  const batchSize = options?.maxWorkspacesPerBatch || 100;
  for (let i = 0; i < workspaceIds.length; i += batchSize) {
    const batch = workspaceIds.slice(i, i + batchSize);
    try {
      const scanId = await postWorkspaceInfo(token, batch, {
        lineageEnabled: options?.includeLineage ?? false,
        datasourceDetailsEnabled: options?.includeDatasourceDetails ?? true,
        datasetSchemaEnabled: options?.includeDatasetSchema ?? false,
        datasetExpressionEnabled: options?.includeDatasetExpressions ?? false,
        getArtifactUsersEnabled: options?.includeArtifactUsers ?? true,
      });

      await waitForScanCompletion(token, scanId);
      const result = await getScanResult(token, scanId);

      // Parse scan results into structured format
      for (const ws of result.workspaces || []) {
        const workspace: FabricWorkspace = {
          id: ws.id,
          name: ws.name,
          type: ws.type,
          state: ws.state,
          capacityId: ws.capacityId,
          isOnDedicatedCapacity: ws.isOnDedicatedCapacity,
        };

        const items: FabricItem[] = [];
        for (const itemType of ["reports", "dashboards", "datasets", "dataflows", "lakehouses", "notebooks", "datamarts", "semanticModels"]) {
          for (const item of ws[itemType] || []) {
            items.push({
              id: item.id,
              name: item.name,
              type: itemType === "semanticModels" ? "SemanticModel" : itemType.charAt(0).toUpperCase() + itemType.slice(1, -1),
              createdBy: item.createdBy,
              modifiedBy: item.modifiedBy,
              createdDateTime: item.createdDateTime,
              modifiedDateTime: item.modifiedDateTime,
              sensitivityLabel: item.sensitivityLabel ? {
                labelId: item.sensitivityLabel.labelId,
                labelName: item.sensitivityLabel.labelName,
              } : null,
              endorsementDetails: item.endorsementDetails ? {
                endorsement: item.endorsementDetails.endorsement,
                certifiedBy: item.endorsementDetails.certifiedBy,
              } : null,
              description: item.description,
            });
          }
        }

        const users: FabricUser[] = (ws.users || []).map((u: any) => ({
          displayName: u.displayName,
          emailAddress: u.emailAddress,
          principalType: u.principalType,
          identifier: u.identifier,
          graphId: u.graphId,
          userType: u.userType,
          fabricItemAccessRights: u.groupUserAccessRight || u.datasetUserAccessRight,
        }));

        const dataSources: FabricDataSource[] = [];
        for (const ds of ws.datasets || ws.semanticModels || []) {
          for (const src of ds.datasourceUsages || ds.datasources || []) {
            dataSources.push({
              datasourceType: src.datasourceType,
              connectionDetails: src.connectionDetails,
              datasourceId: src.datasourceId,
              gatewayId: src.gatewayId,
            });
          }
        }

        allWorkspaceDetails.push({ workspace, items, users, dataSources });
      }
    } catch (e: any) {
      errors.push(`Batch scan failed (workspaces ${i}-${i + batch.length}): ${e.message}`);
    }
  }

  // Detect misconfigurations
  const misconfigurations = detectMisconfigurations(allWorkspaceDetails);

  // Build summary
  const summary = buildSummary(allWorkspaceDetails, misconfigurations);

  return {
    tenantId: creds.tenantId,
    scanTimestamp,
    workspaces: allWorkspaceDetails,
    summary,
    misconfigurations,
    errors,
  };
}

// ── Tenant-Level Security Checks ────────────────────────────────────────────

/**
 * Check tenant-level Fabric security settings via the Admin API.
 * These are global settings that affect all workspaces.
 */
export async function checkTenantSecuritySettings(
  creds: FabricCredentials
): Promise<FabricMisconfiguration[]> {
  const misconfigs: FabricMisconfiguration[] = [];
  const token = await getAccessToken(creds);

  // Check tenant settings
  try {
    const resp = await fetch("https://api.powerbi.com/v1.0/myorg/admin/tenantsettings", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (resp.ok) {
      const data = await resp.json() as any;
      const settings = data.tenantSettings || [];

      // Check critical tenant settings
      const settingsMap = new Map(settings.map((s: any) => [s.settingName, s]));

      // External sharing enabled
      const externalSharing = settingsMap.get("AllowExternalDataSharing");
      if (externalSharing?.enabled) {
        misconfigs.push({
          type: "external_data_sharing_enabled",
          severity: "high",
          description: "External data sharing is enabled at the tenant level",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Restrict external data sharing to specific security groups or disable if not required.",
          cisBenchmark: "CIS M365 5.2.2",
        });
      }

      // Publish to web enabled
      const publishToWeb = settingsMap.get("PublishToWeb");
      if (publishToWeb?.enabled) {
        misconfigs.push({
          type: "publish_to_web_enabled",
          severity: "critical",
          description: "Publish to Web is enabled — reports can be embedded publicly without authentication",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Disable Publish to Web or restrict to specific security groups. Published reports are accessible to anyone on the internet.",
          cisBenchmark: "CIS M365 5.1.1",
        });
      }

      // Export data enabled
      const exportData = settingsMap.get("ExportReport");
      if (exportData?.enabled) {
        misconfigs.push({
          type: "data_export_enabled",
          severity: "medium",
          description: "Users can export data from reports and dashboards",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Restrict data export to specific security groups to prevent unauthorized data exfiltration.",
        });
      }

      // Service principals can use APIs
      const spApiAccess = settingsMap.get("ServicePrincipalAccess");
      if (spApiAccess?.enabled && !spApiAccess.properties?.find((p: any) => p.name === "SecurityGroupsIds")?.value) {
        misconfigs.push({
          type: "unrestricted_service_principal_api_access",
          severity: "high",
          description: "Service principal API access is enabled for the entire organization (not restricted to security groups)",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Restrict service principal API access to specific security groups.",
        });
      }

      // Guest user access
      const guestAccess = settingsMap.get("AllowGuestUsersToAccessPowerBI");
      if (guestAccess?.enabled) {
        misconfigs.push({
          type: "guest_user_access_enabled",
          severity: "medium",
          description: "Guest users can access Power BI / Fabric content",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Review guest access policies and ensure they align with data classification requirements.",
          cisBenchmark: "CIS M365 5.2.3",
        });
      }

      // Custom visuals enabled (potential code execution)
      const customVisuals = settingsMap.get("CustomVisualsEnabled");
      if (customVisuals?.enabled) {
        misconfigs.push({
          type: "custom_visuals_enabled",
          severity: "medium",
          description: "Custom visuals from AppSource or file upload are enabled — potential code execution vector",
          affectedResources: ["Tenant-wide setting"],
          recommendation: "Restrict custom visuals to certified-only or disable if not required. Custom visuals can execute JavaScript in the browser context.",
        });
      }
    }
  } catch (e: any) {
    misconfigs.push({
      type: "tenant_settings_access_denied",
      severity: "info",
      description: `Could not read tenant settings: ${e.message}`,
      affectedResources: ["Tenant settings API"],
      recommendation: "Ensure the service principal has Fabric admin API permissions.",
    });
  }

  return misconfigs;
}

// ── Capacity & Gateway Enumeration ──────────────────────────────────────────

/**
 * Enumerate Fabric capacities and gateways for infrastructure-level audit.
 */
export async function enumerateInfrastructure(
  creds: FabricCredentials
): Promise<{
  capacities: any[];
  gateways: any[];
  misconfigurations: FabricMisconfiguration[];
}> {
  const token = await getAccessToken(creds);
  const misconfigs: FabricMisconfiguration[] = [];
  let capacities: any[] = [];
  let gateways: any[] = [];

  // Enumerate capacities
  try {
    const resp = await fetch("https://api.powerbi.com/v1.0/myorg/admin/capacities", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (resp.ok) {
      const data = await resp.json() as any;
      capacities = data.value || [];
    }
  } catch { /* ignore */ }

  // Enumerate gateways
  try {
    const resp = await fetch("https://api.powerbi.com/v1.0/myorg/admin/gateways", {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (resp.ok) {
      const data = await resp.json() as any;
      gateways = data.value || [];

      // Check for gateways with outdated versions or public access
      for (const gw of gateways) {
        if (gw.publicKey?.exponent && gw.gatewayStatus !== "Live") {
          misconfigs.push({
            type: "gateway_offline",
            severity: "medium",
            description: `Data gateway "${gw.name}" is not in Live status (status: ${gw.gatewayStatus})`,
            affectedResources: [gw.name],
            recommendation: "Investigate offline gateways — they may indicate infrastructure issues or abandoned resources.",
          });
        }
      }
    }
  } catch { /* ignore */ }

  return { capacities, gateways, misconfigurations: misconfigs };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function emptySummary(): FabricScanSummary {
  return {
    totalWorkspaces: 0,
    totalItems: 0,
    totalUsers: 0,
    totalDataSources: 0,
    totalMisconfigurations: 0,
    itemsByType: {},
    workspacesWithoutLabels: 0,
    workspacesWithExternalSharing: 0,
    privilegedUsers: 0,
    endorsedItems: 0,
    certifiedItems: 0,
  };
}

function buildSummary(
  workspaces: FabricWorkspaceDetail[],
  misconfigs: FabricMisconfiguration[]
): FabricScanSummary {
  const itemsByType: Record<string, number> = {};
  let totalItems = 0;
  let totalUsers = 0;
  let totalDataSources = 0;
  let workspacesWithoutLabels = 0;
  let workspacesWithExternalSharing = 0;
  let privilegedUsers = 0;
  let endorsedItems = 0;
  let certifiedItems = 0;

  for (const wd of workspaces) {
    totalItems += wd.items.length;
    totalUsers += wd.users.length;
    totalDataSources += wd.dataSources.length;

    for (const item of wd.items) {
      itemsByType[item.type] = (itemsByType[item.type] || 0) + 1;
      if (item.endorsementDetails?.endorsement === "Promoted") endorsedItems++;
      if (item.endorsementDetails?.endorsement === "Certified") certifiedItems++;
    }

    const hasUnlabeled = wd.items.some(i => !i.sensitivityLabel);
    if (hasUnlabeled) workspacesWithoutLabels++;

    const hasExternal = wd.users.some(u => u.userType === "Guest");
    if (hasExternal) workspacesWithExternalSharing++;

    const admins = wd.users.filter(u =>
      u.fabricItemAccessRights?.includes("Admin") || u.fabricItemAccessRights?.includes("ReadWriteReshare")
    );
    privilegedUsers += admins.length;
  }

  return {
    totalWorkspaces: workspaces.length,
    totalItems,
    totalUsers,
    totalDataSources,
    totalMisconfigurations: misconfigs.length,
    itemsByType,
    workspacesWithoutLabels,
    workspacesWithExternalSharing,
    privilegedUsers,
    endorsedItems,
    certifiedItems,
  };
}
