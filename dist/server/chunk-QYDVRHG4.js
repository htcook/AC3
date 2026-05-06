import {
  getFIPSHttpsAgent,
  init_fips_tls
} from "./chunk-HRFBKKXV.js";
import {
  getDb,
  init_db
} from "./chunk-SI4LILOM.js";
import {
  init_schema,
  vendorCachedData,
  vendorIntegrations,
  vendorSyncEvents
} from "./chunk-YQRYZ5JK.js";

// server/lib/vendors/index.ts
init_db();
init_schema();
import { eq } from "drizzle-orm";

// server/lib/vendors/base-client.ts
init_fips_tls();
import axios, { AxiosError } from "axios";
var CIRCUIT_THRESHOLD = 5;
var CIRCUIT_RESET_MS = 6e4;
var BaseVendorClient = class {
  constructor(vendor, authConfig, connectionConfig) {
    // OAuth2 token cache
    this.accessToken = null;
    this.tokenExpiresAt = 0;
    this.vendor = vendor;
    this.authConfig = authConfig;
    this.connectionConfig = connectionConfig;
    this.circuit = { failures: 0, lastFailure: 0, isOpen: false, halfOpenAttempts: 0 };
    this.httpClient = axios.create({
      baseURL: connectionConfig.baseUrl,
      timeout: connectionConfig.timeout ?? 3e4,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        ...connectionConfig.customHeaders
      },
      httpsAgent: getFIPSHttpsAgent()
    });
  }
  // ─── Shared HTTP Methods ───────────────────────────────────────────────────
  async request(config) {
    if (this.circuit.isOpen) {
      const elapsed = Date.now() - this.circuit.lastFailure;
      if (elapsed < CIRCUIT_RESET_MS) {
        throw new VendorError(
          this.vendor,
          `Circuit breaker open \u2014 ${this.vendor} API unavailable. Retry in ${Math.ceil((CIRCUIT_RESET_MS - elapsed) / 1e3)}s`,
          "CIRCUIT_OPEN"
        );
      }
      this.circuit.isOpen = false;
      this.circuit.halfOpenAttempts++;
    }
    await this.ensureAuthenticated();
    try {
      const response = await this.httpClient.request(config);
      this.circuit.failures = 0;
      this.circuit.halfOpenAttempts = 0;
      return response.data;
    } catch (error) {
      this.circuit.failures++;
      this.circuit.lastFailure = Date.now();
      if (this.circuit.failures >= CIRCUIT_THRESHOLD) {
        this.circuit.isOpen = true;
      }
      if (error instanceof AxiosError) {
        const status = error.response?.status;
        const message = error.response?.data?.message || error.response?.data?.errors?.[0]?.message || error.message;
        if (status === 401 || status === 403) {
          this.accessToken = null;
          this.tokenExpiresAt = 0;
          throw new VendorError(this.vendor, `Authentication failed: ${message}`, "AUTH_FAILED", status);
        }
        if (status === 429) {
          throw new VendorError(this.vendor, `Rate limited: ${message}`, "RATE_LIMITED", status);
        }
        throw new VendorError(this.vendor, `API error (${status}): ${message}`, "API_ERROR", status);
      }
      throw new VendorError(this.vendor, `Request failed: ${error.message}`, "NETWORK_ERROR");
    }
  }
  async ensureAuthenticated() {
    if (this.authConfig.apiToken) return;
    if (this.accessToken && Date.now() < this.tokenExpiresAt - 6e4) return;
    await this.authenticate();
  }
  setAuthHeader(token, scheme = "Bearer") {
    this.httpClient.defaults.headers.common["Authorization"] = `${scheme} ${token}`;
  }
  // ─── Utility ───────────────────────────────────────────────────────────────
  getCircuitState() {
    return { ...this.circuit };
  }
  resetCircuit() {
    this.circuit = { failures: 0, lastFailure: 0, isOpen: false, halfOpenAttempts: 0 };
  }
};
var VendorError = class extends Error {
  constructor(vendor, message, code, httpStatus) {
    super(`[${vendor}] ${message}`);
    this.name = "VendorError";
    this.vendor = vendor;
    this.code = code;
    this.httpStatus = httpStatus;
  }
};

// server/lib/vendors/crowdstrike.ts
import axios2 from "axios";
init_fips_tls();
var CS_REGIONS = {
  "us-1": "https://api.crowdstrike.com",
  "us-2": "https://api.us-2.crowdstrike.com",
  "eu-1": "https://api.eu-1.crowdstrike.com",
  "us-gov-1": "https://api.laggar.gcw.crowdstrike.com"
};
var CrowdStrikeClient = class extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    const baseUrl = connectionConfig.baseUrl || CS_REGIONS[authConfig.region || "us-1"] || CS_REGIONS["us-1"];
    super("crowdstrike", authConfig, { ...connectionConfig, baseUrl });
  }
  getDisplayName() {
    return "CrowdStrike Falcon";
  }
  // ─── OAuth2 Authentication ─────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("crowdstrike", "Missing clientId or clientSecret", "AUTH_CONFIG_MISSING");
    }
    try {
      const response = await axios2.post(
        `${this.connectionConfig.baseUrl}/oauth2/token`,
        new URLSearchParams({
          client_id: this.authConfig.clientId,
          client_secret: this.authConfig.clientSecret
        }).toString(),
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          timeout: 15e3,
          httpsAgent: getFIPSHttpsAgent()
        }
      );
      this.accessToken = response.data.access_token;
      this.tokenExpiresAt = Date.now() + (response.data.expires_in || 1800) * 1e3;
      this.setAuthHeader(this.accessToken);
    } catch (error) {
      if (error instanceof VendorError) throw error;
      const msg = error?.response?.data?.errors?.[0]?.message || error.message;
      throw new VendorError("crowdstrike", `OAuth2 token exchange failed: ${msg}`, "AUTH_FAILED");
    }
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/sensors/queries/installers/ccid/v1" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "CrowdStrike Falcon API is reachable and authenticated"
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: error.message
      };
    }
  }
  // ─── Hosts ─────────────────────────────────────────────────────────────────
  async queryHosts(options) {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";
    const idsResponse = await this.request({
      method: "GET",
      url: "/devices/queries/devices/v1",
      params: { limit, offset, filter: filter || void 0 }
    });
    if (!idsResponse.resources?.length) return [];
    const detailsResponse = await this.request({
      method: "POST",
      url: "/devices/entities/devices/v2",
      data: { ids: idsResponse.resources }
    });
    return (detailsResponse.resources || []).map((h) => this.normalizeHost(h));
  }
  async getHost(deviceId) {
    const response = await this.request({
      method: "POST",
      url: "/devices/entities/devices/v2",
      data: { ids: [deviceId] }
    });
    const host = response.resources?.[0];
    return host ? this.normalizeHost(host) : null;
  }
  normalizeHost(h) {
    return {
      id: h.device_id,
      type: "host",
      title: h.hostname || h.device_id,
      status: h.status,
      hostname: h.hostname,
      ipAddress: h.local_ip || h.external_ip,
      raw: h
    };
  }
  // ─── Detections ────────────────────────────────────────────────────────────
  async queryDetections(options) {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";
    const idsResponse = await this.request({
      method: "GET",
      url: "/detects/queries/detects/v1",
      params: { limit, offset, filter: filter || void 0 }
    });
    if (!idsResponse.resources?.length) return [];
    const detailsResponse = await this.request({
      method: "POST",
      url: "/detects/entities/summaries/GET/v1",
      data: { ids: idsResponse.resources }
    });
    return (detailsResponse.resources || []).map((d) => this.normalizeDetection(d));
  }
  normalizeDetection(d) {
    const severity = d.max_severity >= 80 ? "critical" : d.max_severity >= 60 ? "high" : d.max_severity >= 40 ? "medium" : d.max_severity >= 20 ? "low" : "informational";
    const mitreId = d.behaviors?.[0]?.technique_id;
    return {
      id: d.detection_id,
      type: "detection",
      title: d.display_name || d.behaviors?.[0]?.display_name || `Detection on ${d.hostname}`,
      severity,
      status: d.status,
      hostname: d.hostname,
      mitreAttackId: mitreId,
      detectedAt: new Date(d.created_timestamp).getTime(),
      raw: d
    };
  }
  // ─── Incidents ─────────────────────────────────────────────────────────────
  async queryIncidents(options) {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const filter = options?.filter || "";
    const idsResponse = await this.request({
      method: "GET",
      url: "/incidents/queries/incidents/v1",
      params: { limit, offset, filter: filter || void 0 }
    });
    if (!idsResponse.resources?.length) return [];
    const detailsResponse = await this.request({
      method: "POST",
      url: "/incidents/entities/incidents/GET/v1",
      data: { ids: idsResponse.resources }
    });
    return (detailsResponse.resources || []).map((i) => this.normalizeIncident(i));
  }
  normalizeIncident(i) {
    const severity = i.fine_score >= 80 ? "critical" : i.fine_score >= 60 ? "high" : i.fine_score >= 40 ? "medium" : i.fine_score >= 20 ? "low" : "informational";
    return {
      id: i.incident_id,
      type: "incident",
      title: i.name || `Incident ${i.incident_id.slice(0, 8)}`,
      severity,
      status: i.state,
      hostname: i.hosts?.[0]?.hostname,
      ipAddress: i.hosts?.[0]?.local_ip,
      mitreAttackId: i.techniques?.[0],
      detectedAt: new Date(i.created).getTime(),
      raw: i
    };
  }
  // ─── IOCs ──────────────────────────────────────────────────────────────────
  async queryIOCs(options) {
    const limit = options?.limit ?? 100;
    const offset = options?.offset ?? 0;
    const response = await this.request({
      method: "GET",
      url: "/iocs/combined/indicator/v1",
      params: { limit, offset }
    });
    return (response.resources || []).map((ioc) => ({
      id: ioc.id,
      type: "indicator",
      title: `${ioc.type}: ${ioc.value}`,
      severity: ioc.severity === "critical" ? "critical" : ioc.severity === "high" ? "high" : ioc.severity === "medium" ? "medium" : "low",
      status: ioc.action,
      raw: ioc
    }));
  }
  // ─── Containment ───────────────────────────────────────────────────────────
  async containHost(deviceId) {
    await this.request({
      method: "POST",
      url: "/devices/entities/devices-actions/v2",
      params: { action_name: "contain" },
      data: { ids: [deviceId] }
    });
  }
  async liftContainment(deviceId) {
    await this.request({
      method: "POST",
      url: "/devices/entities/devices-actions/v2",
      params: { action_name: "lift_containment" },
      data: { ids: [deviceId] }
    });
  }
};
function createCrowdStrikeClient(authConfig, connectionConfig) {
  return new CrowdStrikeClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || CS_REGIONS[authConfig.region || "us-1"],
    timeout: connectionConfig?.timeout ?? 3e4,
    ...connectionConfig
  });
}

// server/lib/vendors/sentinelone.ts
var SentinelOneClient = class extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    super("sentinelone", authConfig, connectionConfig);
  }
  getDisplayName() {
    return "SentinelOne";
  }
  // ─── Token Authentication ──────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.apiToken) {
      throw new VendorError("sentinelone", "Missing API token", "AUTH_CONFIG_MISSING");
    }
    this.setAuthHeader(this.authConfig.apiToken, "ApiToken");
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/web/api/v2.1/system/info" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "SentinelOne management console is reachable and authenticated"
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: error.message
      };
    }
  }
  // ─── Agents ────────────────────────────────────────────────────────────────
  async queryAgents(options) {
    const limit = options?.limit ?? 100;
    const params = { limit };
    if (options?.filter) params.computerName__contains = options.filter;
    if (options?.sort) params.sortBy = options.sort;
    const response = await this.request({
      method: "GET",
      url: "/web/api/v2.1/agents",
      params
    });
    return (response.data || []).map((a) => this.normalizeAgent(a));
  }
  async getAgent(agentId) {
    const response = await this.request({
      method: "GET",
      url: "/web/api/v2.1/agents",
      params: { ids: agentId }
    });
    const agent = response.data?.[0];
    return agent ? this.normalizeAgent(agent) : null;
  }
  normalizeAgent(a) {
    return {
      id: a.id,
      type: "host",
      title: a.computerName || a.id,
      status: a.isActive ? a.infected ? "infected" : "healthy" : "offline",
      hostname: a.computerName,
      ipAddress: a.lastIpToMgmt || a.externalIp,
      domain: a.domain,
      raw: a
    };
  }
  // ─── Threats ───────────────────────────────────────────────────────────────
  async queryThreats(options) {
    const limit = options?.limit ?? 100;
    const params = { limit };
    if (options?.timeRange) {
      params.createdAt__gte = new Date(options.timeRange.start).toISOString();
      params.createdAt__lte = new Date(options.timeRange.end).toISOString();
    }
    const response = await this.request({
      method: "GET",
      url: "/web/api/v2.1/threats",
      params
    });
    return (response.data || []).map((t) => this.normalizeThreat(t));
  }
  normalizeThreat(t) {
    const severity = t.confidenceLevel === "malicious" ? "critical" : t.confidenceLevel === "suspicious" ? "high" : "medium";
    return {
      id: t.id,
      type: "threat",
      title: t.threatName || `Threat on ${t.agentComputerName}`,
      severity,
      status: t.mitigationStatus,
      hostname: t.agentComputerName,
      detectedAt: new Date(t.createdDate).getTime(),
      raw: t
    };
  }
  // ─── Activities ────────────────────────────────────────────────────────────
  async queryActivities(options) {
    const limit = options?.limit ?? 100;
    const params = { limit };
    const response = await this.request({
      method: "GET",
      url: "/web/api/v2.1/activities",
      params
    });
    return (response.data || []).map((a) => ({
      id: a.id,
      type: "alert",
      title: a.primaryDescription || `Activity ${a.activityType}`,
      status: "active",
      detectedAt: new Date(a.createdAt).getTime(),
      raw: a
    }));
  }
  // ─── Threat Actions ────────────────────────────────────────────────────────
  async mitigateThreat(threatId, action) {
    await this.request({
      method: "POST",
      url: `/web/api/v2.1/threats/mitigate/${action}`,
      data: { filter: { ids: [threatId] } }
    });
  }
  async disconnectAgent(agentId) {
    await this.request({
      method: "POST",
      url: "/web/api/v2.1/agents/actions/disconnect",
      data: { filter: { ids: [agentId] } }
    });
  }
  async reconnectAgent(agentId) {
    await this.request({
      method: "POST",
      url: "/web/api/v2.1/agents/actions/connect",
      data: { filter: { ids: [agentId] } }
    });
  }
};
function createSentinelOneClient(authConfig, connectionConfig) {
  return new SentinelOneClient(authConfig, connectionConfig);
}

// server/lib/vendors/defender.ts
import axios3 from "axios";
init_fips_tls();
var DefenderClient = class _DefenderClient extends BaseVendorClient {
  static {
    this.BASE_URL = "https://api.securitycenter.microsoft.com/api";
  }
  static {
    this.TOKEN_URL = "https://login.microsoftonline.com";
  }
  static {
    this.SCOPE = "https://api.securitycenter.microsoft.com/.default";
  }
  constructor(authConfig, connectionConfig) {
    super("defender", authConfig, {
      ...connectionConfig,
      baseUrl: connectionConfig.baseUrl || _DefenderClient.BASE_URL
    });
  }
  getDisplayName() {
    return "Microsoft Defender for Endpoint";
  }
  // ─── Azure AD OAuth2 Authentication ────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.tenantId || !this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("defender", "Missing tenantId, clientId, or clientSecret", "AUTH_CONFIG_MISSING");
    }
    try {
      const tokenUrl = `${_DefenderClient.TOKEN_URL}/${this.authConfig.tenantId}/oauth2/v2.0/token`;
      const response = await axios3.post(
        tokenUrl,
        new URLSearchParams({
          client_id: this.authConfig.clientId,
          client_secret: this.authConfig.clientSecret,
          scope: _DefenderClient.SCOPE,
          grant_type: "client_credentials"
        }).toString(),
        {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          timeout: 15e3,
          httpsAgent: getFIPSHttpsAgent()
        }
      );
      this.accessToken = response.data.access_token;
      this.tokenExpiresAt = Date.now() + (response.data.expires_in || 3600) * 1e3;
      this.setAuthHeader(this.accessToken);
    } catch (error) {
      if (error instanceof VendorError) throw error;
      const msg = error?.response?.data?.error_description || error.message;
      throw new VendorError("defender", `Azure AD token exchange failed: ${msg}`, "AUTH_FAILED");
    }
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/machines", params: { "$top": 1 } });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Microsoft Defender for Endpoint API is reachable and authenticated"
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: error.message
      };
    }
  }
  // ─── Machines ──────────────────────────────────────────────────────────────
  async queryMachines(options) {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;
    const params = { "$top": top, "$skip": skip };
    if (options?.filter) params["$filter"] = options.filter;
    const response = await this.request({
      method: "GET",
      url: "/machines",
      params
    });
    return (response.value || []).map((m) => this.normalizeMachine(m));
  }
  normalizeMachine(m) {
    const severity = m.riskScore === "High" ? "high" : m.riskScore === "Medium" ? "medium" : m.riskScore === "Low" ? "low" : "informational";
    return {
      id: m.id,
      type: "host",
      title: m.computerDnsName || m.id,
      severity,
      status: m.healthStatus,
      hostname: m.computerDnsName,
      ipAddress: m.lastIpAddress || m.lastExternalIpAddress,
      raw: m
    };
  }
  // ─── Alerts ────────────────────────────────────────────────────────────────
  async queryAlerts(options) {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;
    const params = { "$top": top, "$skip": skip };
    if (options?.filter) params["$filter"] = options.filter;
    if (options?.timeRange) {
      params["$filter"] = `alertCreationTime ge ${new Date(options.timeRange.start).toISOString()} and alertCreationTime le ${new Date(options.timeRange.end).toISOString()}`;
    }
    const response = await this.request({
      method: "GET",
      url: "/alerts",
      params
    });
    return (response.value || []).map((a) => this.normalizeAlert(a));
  }
  normalizeAlert(a) {
    const severity = a.severity?.toLowerCase() || "medium";
    return {
      id: a.id,
      type: "alert",
      title: a.title || `Alert ${a.id}`,
      severity,
      status: a.status,
      hostname: a.computerDnsName,
      mitreAttackId: a.mitreTechniques?.[0],
      detectedAt: new Date(a.alertCreationTime).getTime(),
      raw: a
    };
  }
  // ─── Vulnerabilities ───────────────────────────────────────────────────────
  async queryVulnerabilities(options) {
    const top = options?.limit ?? 100;
    const skip = options?.offset ?? 0;
    const response = await this.request({
      method: "GET",
      url: "/vulnerabilities",
      params: { "$top": top, "$skip": skip }
    });
    return (response.value || []).map((v) => this.normalizeVulnerability(v));
  }
  normalizeVulnerability(v) {
    const severity = v.cvssV3 >= 9 ? "critical" : v.cvssV3 >= 7 ? "high" : v.cvssV3 >= 4 ? "medium" : "low";
    return {
      id: v.id,
      type: "vulnerability",
      title: `${v.name}: ${v.description?.slice(0, 100)}`,
      severity,
      status: v.publicExploit ? "exploit_available" : "no_exploit",
      detectedAt: new Date(v.publishedOn).getTime(),
      raw: v
    };
  }
  // ─── Advanced Hunting (KQL) ────────────────────────────────────────────────
  async advancedHunting(query) {
    const response = await this.request({
      method: "POST",
      url: "/advancedqueries/run",
      data: { Query: query }
    });
    return (response.Results || []).map((r, i) => ({
      id: `kql-${i}`,
      type: "search_result",
      title: r.DeviceName || r.FileName || `Result ${i + 1}`,
      hostname: r.DeviceName,
      ipAddress: r.LocalIP || r.RemoteIP,
      raw: r
    }));
  }
  // ─── Machine Actions ───────────────────────────────────────────────────────
  async isolateMachine(machineId, comment = "Isolated via AC3") {
    await this.request({
      method: "POST",
      url: `/machines/${machineId}/isolate`,
      data: { Comment: comment, IsolationType: "Full" }
    });
  }
  async unisolateMachine(machineId, comment = "Released via AC3") {
    await this.request({
      method: "POST",
      url: `/machines/${machineId}/unisolate`,
      data: { Comment: comment }
    });
  }
};
function createDefenderClient(authConfig, connectionConfig) {
  return new DefenderClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || DefenderClient["BASE_URL"],
    timeout: connectionConfig?.timeout ?? 3e4,
    ...connectionConfig
  });
}

// server/lib/vendors/splunk.ts
var SplunkClient = class extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    super("splunk", authConfig, connectionConfig);
  }
  getDisplayName() {
    return "Splunk Enterprise Security";
  }
  // ─── Token Authentication ──────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.apiToken) {
      throw new VendorError("splunk", "Missing Splunk auth token", "AUTH_CONFIG_MISSING");
    }
    this.setAuthHeader(this.authConfig.apiToken, "Bearer");
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.request({
        method: "GET",
        url: "/services/server/info",
        params: { output_mode: "json" }
      });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Splunk REST API is reachable and authenticated"
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: error.message
      };
    }
  }
  // ─── Search Jobs ───────────────────────────────────────────────────────────
  async createSearchJob(spl, options) {
    const data = {
      search: spl.startsWith("search ") || spl.startsWith("|") ? spl : `search ${spl}`,
      output_mode: "json",
      exec_mode: "normal"
    };
    if (options?.earliest) data.earliest_time = options.earliest;
    if (options?.latest) data.latest_time = options.latest;
    const response = await this.request({
      method: "POST",
      url: "/services/search/jobs",
      data: new URLSearchParams(data).toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });
    return response.sid;
  }
  async getSearchJobStatus(sid) {
    const response = await this.request({
      method: "GET",
      url: `/services/search/jobs/${sid}`,
      params: { output_mode: "json" }
    });
    return response.entry?.[0]?.content;
  }
  async getSearchResults(sid, options) {
    const count = options?.count ?? 100;
    const offset = options?.offset ?? 0;
    const response = await this.request({
      method: "GET",
      url: `/services/search/jobs/${sid}/results`,
      params: { output_mode: "json", count, offset }
    });
    return (response.results || []).map((r, i) => this.normalizeSearchResult(r, i));
  }
  normalizeSearchResult(r, index) {
    return {
      id: `splunk-${index}-${Date.now()}`,
      type: "search_result",
      title: r.source || r.sourcetype || `Result ${index + 1}`,
      hostname: r.host,
      detectedAt: r._time ? new Date(r._time).getTime() : void 0,
      raw: r
    };
  }
  // ─── One-shot Search (create + poll + return) ──────────────────────────────
  async search(spl, options) {
    const sid = await this.createSearchJob(spl, options);
    const maxWait = options?.maxWaitMs ?? 6e4;
    const pollInterval = 2e3;
    let elapsed = 0;
    while (elapsed < maxWait) {
      const status = await this.getSearchJobStatus(sid);
      if (status.dispatchState === "DONE" || status.dispatchState === "FINALIZED") {
        return this.getSearchResults(sid, { count: options?.limit ?? 100 });
      }
      if (status.dispatchState === "FAILED") {
        throw new VendorError("splunk", `Search job ${sid} failed`, "SEARCH_FAILED");
      }
      await new Promise((r) => setTimeout(r, pollInterval));
      elapsed += pollInterval;
    }
    throw new VendorError("splunk", `Search job ${sid} timed out after ${maxWait}ms`, "SEARCH_TIMEOUT");
  }
  // ─── Notable Events (Enterprise Security) ─────────────────────────────────
  async queryNotableEvents(options) {
    const earliest = options?.timeRange ? new Date(options.timeRange.start).toISOString() : "-24h";
    const latest = options?.timeRange ? new Date(options.timeRange.end).toISOString() : "now";
    const spl = `\`notable\` | head ${options?.limit ?? 100}`;
    const results = await this.search(spl, { earliest, latest, limit: options?.limit });
    return results.map((r) => {
      const raw = r.raw;
      const severity = raw.urgency === "critical" ? "critical" : raw.urgency === "high" ? "high" : raw.urgency === "medium" ? "medium" : raw.urgency === "low" ? "low" : "informational";
      return {
        ...r,
        type: "alert",
        title: raw.rule_title || raw.rule_name || r.title,
        severity,
        status: raw.status,
        hostname: raw.dest,
        ipAddress: raw.dest_ip || raw.src_ip
      };
    });
  }
  // ─── Saved Searches ────────────────────────────────────────────────────────
  async listSavedSearches() {
    const response = await this.request({
      method: "GET",
      url: "/services/saved/searches",
      params: { output_mode: "json", count: 100 }
    });
    return (response.entry || []).map((e) => ({
      name: e.name,
      search: e.content.search,
      description: e.content.description
    }));
  }
  async runSavedSearch(name) {
    const response = await this.request({
      method: "POST",
      url: `/services/saved/searches/${encodeURIComponent(name)}/dispatch`,
      params: { output_mode: "json" }
    });
    return response.sid;
  }
};
function createSplunkClient(authConfig, connectionConfig) {
  return new SplunkClient(authConfig, connectionConfig);
}

// server/lib/vendors/xsoar.ts
var XSOARClient = class extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    super("xsoar", authConfig, connectionConfig);
  }
  getDisplayName() {
    return "Palo Alto Cortex XSOAR";
  }
  // ─── API Key Authentication ────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.apiToken) {
      throw new VendorError("xsoar", "Missing XSOAR API key", "AUTH_CONFIG_MISSING");
    }
    if (this.authConfig.apiKeyId) {
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
      this.httpClient.defaults.headers.common["x-xdr-auth-id"] = this.authConfig.apiKeyId;
    } else {
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
    }
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.request({ method: "GET", url: "/user" });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: "Cortex XSOAR API is reachable and authenticated"
      };
    } catch (error) {
      return {
        status: error instanceof VendorError && error.code === "AUTH_FAILED" ? "disconnected" : "error",
        latencyMs: Date.now() - start,
        message: error.message
      };
    }
  }
  // ─── Incidents ─────────────────────────────────────────────────────────────
  async queryIncidents(options) {
    const size = options?.limit ?? 100;
    const page = options?.offset ? Math.floor(options.offset / size) : 0;
    const body = { size, page };
    if (options?.filter) {
      body.filter = { query: options.filter };
    }
    if (options?.sort) {
      body.sort = [{ field: options.sort, asc: false }];
    }
    const response = await this.request({
      method: "POST",
      url: "/incidents/search",
      data: body
    });
    return (response.data || []).map((i) => this.normalizeIncident(i));
  }
  async getIncident(incidentId) {
    try {
      const response = await this.request({
        method: "GET",
        url: `/incident/${incidentId}`
      });
      return this.normalizeIncident(response);
    } catch {
      return null;
    }
  }
  normalizeIncident(i) {
    const severity = i.severity === 4 ? "critical" : i.severity === 3 ? "high" : i.severity === 2 ? "medium" : i.severity === 1 ? "low" : "informational";
    const status = i.status === 0 ? "active" : i.status === 1 ? "closed" : "archived";
    return {
      id: i.id,
      type: "incident",
      title: i.name || `Incident ${i.id}`,
      severity,
      status,
      detectedAt: new Date(i.occurred || i.created).getTime(),
      raw: i
    };
  }
  // ─── Indicators ────────────────────────────────────────────────────────────
  async queryIndicators(options) {
    const size = options?.limit ?? 100;
    const page = options?.offset ? Math.floor(options.offset / size) : 0;
    const body = { size, page };
    if (options?.filter) {
      body.filter = { query: options.filter };
    }
    const response = await this.request({
      method: "POST",
      url: "/indicators/search",
      data: body
    });
    return (response.iocObjects || []).map((ind) => this.normalizeIndicator(ind));
  }
  normalizeIndicator(ind) {
    const severity = ind.score === 3 ? "critical" : ind.score === 2 ? "high" : ind.score === 1 ? "low" : "informational";
    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ind.value);
    const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(ind.value);
    return {
      id: ind.id,
      type: "indicator",
      title: `${ind.indicator_type}: ${ind.value}`,
      severity,
      status: ind.score === 3 ? "malicious" : ind.score === 2 ? "suspicious" : "unknown",
      ipAddress: isIp ? ind.value : void 0,
      domain: isDomain ? ind.value : void 0,
      detectedAt: new Date(ind.firstSeen).getTime(),
      raw: ind
    };
  }
  // ─── Playbooks ─────────────────────────────────────────────────────────────
  async listPlaybooks() {
    const response = await this.request({
      method: "POST",
      url: "/playbook/search",
      data: { size: 100 }
    });
    return (response.playbooks || []).filter((p) => !p.deprecated).map((p) => ({
      id: p.id,
      name: p.name,
      description: p.description
    }));
  }
  async runPlaybook(playbookId, incidentId) {
    await this.request({
      method: "POST",
      url: `/incident/${incidentId}/playbook/${playbookId}/run`
    });
  }
  // ─── Create Incident ───────────────────────────────────────────────────────
  async createIncident(data) {
    const response = await this.request({
      method: "POST",
      url: "/incident",
      data: {
        name: data.name,
        type: data.type || "Unclassified",
        severity: data.severity ?? 2,
        labels: data.labels || [],
        CustomFields: data.customFields || {},
        createInvestigation: true
      }
    });
    return response.id;
  }
  // ─── War Room Notes ────────────────────────────────────────────────────────
  async addWarRoomNote(incidentId, note) {
    await this.request({
      method: "POST",
      url: `/entry/note`,
      data: {
        investigationId: incidentId,
        data: note
      }
    });
  }
};
function createXSOARClient(authConfig, connectionConfig) {
  return new XSOARClient(authConfig, connectionConfig);
}

// server/lib/vendors/sentinel.ts
import axios4 from "axios";
init_fips_tls();
var SentinelClient = class _SentinelClient extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    super("sentinel", authConfig, {
      ...connectionConfig,
      baseUrl: connectionConfig.baseUrl || _SentinelClient.ARM_BASE
    });
    // Log Analytics workspace ID for KQL queries
    // Separate token for Log Analytics API
    this.logAnalyticsToken = null;
    this.logAnalyticsTokenExpiry = 0;
    const parts = (connectionConfig.baseUrl || "").split("/").filter(Boolean);
    this.subscriptionId = parts[0] || "";
    this.resourceGroup = parts[1] || "";
    this.workspaceName = parts[2] || "";
    this.workspaceId = parts[3] || "";
    this.httpClient.defaults.baseURL = _SentinelClient.ARM_BASE;
  }
  static {
    this.ARM_BASE = "https://management.azure.com";
  }
  static {
    this.TOKEN_URL = "https://login.microsoftonline.com";
  }
  static {
    this.ARM_SCOPE = "https://management.azure.com/.default";
  }
  static {
    this.LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default";
  }
  // ─── Auth ──────────────────────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.tenantId || !this.authConfig.clientId || !this.authConfig.clientSecret) {
      throw new VendorError("sentinel", "Missing Azure AD credentials (tenantId, clientId, clientSecret)", "AUTH_CONFIG");
    }
    try {
      const tokenUrl = `${_SentinelClient.TOKEN_URL}/${this.authConfig.tenantId}/oauth2/v2.0/token`;
      const httpsAgent = getFIPSHttpsAgent();
      const armResponse = await axios4.post(tokenUrl, new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.authConfig.clientId,
        client_secret: this.authConfig.clientSecret,
        scope: _SentinelClient.ARM_SCOPE
      }).toString(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        httpsAgent
      });
      this.accessToken = armResponse.data.access_token;
      this.tokenExpiresAt = Date.now() + armResponse.data.expires_in * 1e3;
      this.setAuthHeader(this.accessToken);
      const laResponse = await axios4.post(tokenUrl, new URLSearchParams({
        grant_type: "client_credentials",
        client_id: this.authConfig.clientId,
        client_secret: this.authConfig.clientSecret,
        scope: _SentinelClient.LOG_ANALYTICS_SCOPE
      }).toString(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        httpsAgent
      });
      this.logAnalyticsToken = laResponse.data.access_token;
      this.logAnalyticsTokenExpiry = Date.now() + laResponse.data.expires_in * 1e3;
    } catch (error) {
      throw new VendorError("sentinel", `Azure AD auth failed: ${error.message}`, "AUTH_FAILED");
    }
  }
  getDisplayName() {
    return "Microsoft Sentinel";
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.ensureAuthenticated();
      const incidents = await this.listIncidents({ limit: 1 });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: `Sentinel workspace "${this.workspaceName}" connected`,
        details: {
          workspace: this.workspaceName,
          subscriptionId: this.subscriptionId,
          incidentCount: incidents.length
        }
      };
    } catch (error) {
      return {
        status: "error",
        latencyMs: Date.now() - start,
        message: error.message || "Health check failed"
      };
    }
  }
  // ─── Sentinel API Path Builder ─────────────────────────────────────────────
  get sentinelBasePath() {
    return `/subscriptions/${this.subscriptionId}/resourceGroups/${this.resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/${this.workspaceName}/providers/Microsoft.SecurityInsights`;
  }
  // ─── Incidents ─────────────────────────────────────────────────────────────
  async listIncidents(options) {
    const limit = options?.limit ?? 50;
    const filter = options?.filter ? `&$filter=${encodeURIComponent(options.filter)}` : "";
    const orderBy = "&$orderby=properties/createdTimeUtc desc";
    const data = await this.request({
      method: "GET",
      url: `${this.sentinelBasePath}/incidents?api-version=2023-11-01&$top=${limit}${filter}${orderBy}`
    });
    return (data.value || []).map((inc) => ({
      id: inc.name,
      type: "incident",
      title: inc.properties.title,
      severity: this.normalizeSeverity(inc.properties.severity),
      status: inc.properties.status.toLowerCase(),
      detectedAt: new Date(inc.properties.createdTimeUtc).getTime(),
      mitreAttackId: inc.properties.additionalData?.tactics?.join(", "),
      raw: inc
    }));
  }
  async getIncident(incidentId) {
    return this.request({
      method: "GET",
      url: `${this.sentinelBasePath}/incidents/${incidentId}?api-version=2023-11-01`
    });
  }
  async updateIncidentStatus(incidentId, status, classification) {
    const incident = await this.getIncident(incidentId);
    await this.request({
      method: "PUT",
      url: `${this.sentinelBasePath}/incidents/${incidentId}?api-version=2023-11-01`,
      data: {
        ...incident,
        properties: {
          ...incident.properties,
          status,
          ...classification && { classification }
        }
      }
    });
  }
  // ─── Analytics Rules ───────────────────────────────────────────────────────
  async listAnalyticsRules(options) {
    const data = await this.request({
      method: "GET",
      url: `${this.sentinelBasePath}/alertRules?api-version=2023-11-01`
    });
    return data.value || [];
  }
  async toggleAnalyticsRule(ruleId, enabled) {
    const rules = await this.listAnalyticsRules();
    const rule = rules.find((r) => r.name === ruleId);
    if (!rule) throw new VendorError("sentinel", `Rule ${ruleId} not found`, "NOT_FOUND");
    await this.request({
      method: "PUT",
      url: `${this.sentinelBasePath}/alertRules/${ruleId}?api-version=2023-11-01`,
      data: {
        ...rule,
        properties: { ...rule.properties, enabled }
      }
    });
  }
  // ─── Hunting Queries (KQL via Log Analytics) ───────────────────────────────
  async runHuntingQuery(kqlQuery, timespan) {
    if (!this.logAnalyticsToken || Date.now() >= this.logAnalyticsTokenExpiry - 6e4) {
      await this.authenticate();
    }
    const httpsAgent = getFIPSHttpsAgent();
    const response = await axios4.post(
      `https://api.loganalytics.io/v1/workspaces/${this.workspaceId}/query`,
      {
        query: kqlQuery,
        timespan: timespan || "P7D"
        // default 7 days
      },
      {
        headers: {
          Authorization: `Bearer ${this.logAnalyticsToken}`,
          "Content-Type": "application/json"
        },
        httpsAgent,
        timeout: 6e4
      }
    );
    return response.data;
  }
  // ─── Watchlists ────────────────────────────────────────────────────────────
  async listWatchlists() {
    const data = await this.request({
      method: "GET",
      url: `${this.sentinelBasePath}/watchlists?api-version=2023-11-01`
    });
    return data.value || [];
  }
  async addWatchlistItems(watchlistAlias, items) {
    for (const item of items) {
      const itemId = `ac3-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      await this.request({
        method: "PUT",
        url: `${this.sentinelBasePath}/watchlists/${watchlistAlias}/watchlistItems/${itemId}?api-version=2023-11-01`,
        data: {
          properties: {
            itemsKeyValue: item
          }
        }
      });
    }
  }
  // ─── IOC Push (via TI Indicators) ──────────────────────────────────────────
  async pushIndicators(indicators) {
    let created = 0;
    let failed = 0;
    for (const ioc of indicators) {
      try {
        const indicatorId = `ac3-ioc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const patternMap = {
          ipv4: `[ipv4-addr:value = '${ioc.value}']`,
          ipv6: `[ipv6-addr:value = '${ioc.value}']`,
          domain: `[domain-name:value = '${ioc.value}']`,
          url: `[url:value = '${ioc.value}']`,
          file_hash_sha256: `[file:hashes.'SHA-256' = '${ioc.value}']`
        };
        await this.request({
          method: "PUT",
          url: `${this.sentinelBasePath}/threatIntelligence/main/indicators/${indicatorId}?api-version=2023-11-01`,
          data: {
            kind: "indicator",
            properties: {
              source: "AC3 Platform",
              displayName: `[AC3] ${ioc.type}: ${ioc.value}`,
              description: ioc.description,
              confidence: ioc.confidence,
              pattern: patternMap[ioc.type] || `[artifact:payload_bin = '${ioc.value}']`,
              patternType: "stix",
              threatTypes: [ioc.threatType],
              validFrom: (/* @__PURE__ */ new Date()).toISOString(),
              validUntil: ioc.validUntil
            }
          }
        });
        created++;
      } catch {
        failed++;
      }
    }
    return { created, failed };
  }
  // ─── Helpers ───────────────────────────────────────────────────────────────
  normalizeSeverity(severity) {
    switch (severity.toLowerCase()) {
      case "high":
        return "high";
      case "medium":
        return "medium";
      case "low":
        return "low";
      case "informational":
        return "informational";
      default:
        return "medium";
    }
  }
};
function createSentinelClient(authConfig, connectionConfig) {
  return new SentinelClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || "",
    timeout: connectionConfig?.timeout ?? 3e4,
    ...connectionConfig
  });
}

// server/lib/vendors/cortex-xdr.ts
import crypto from "crypto";
var CortexXDRClient = class extends BaseVendorClient {
  constructor(authConfig, connectionConfig) {
    super("cortex_xdr", authConfig, connectionConfig);
    this.apiKeyId = authConfig.apiKeyId || "";
    this.securityLevel = authConfig.region === "standard" ? "standard" : "advanced";
  }
  // ─── Auth ──────────────────────────────────────────────────────────────────
  async authenticate() {
    if (!this.authConfig.apiToken || !this.apiKeyId) {
      throw new VendorError("cortex_xdr", "Missing API Key or API Key ID", "AUTH_CONFIG");
    }
    if (this.securityLevel === "standard") {
      this.httpClient.defaults.headers.common["x-xdr-auth-id"] = this.apiKeyId;
      this.httpClient.defaults.headers.common["Authorization"] = this.authConfig.apiToken;
    }
  }
  getDisplayName() {
    return "Palo Alto Cortex XDR";
  }
  // ─── Advanced Auth Headers (per-request nonce) ─────────────────────────────
  getAdvancedHeaders() {
    if (this.securityLevel !== "advanced") return {};
    const nonce = crypto.randomBytes(32).toString("hex");
    const timestamp = Date.now().toString();
    const authString = `${this.authConfig.apiToken}${nonce}${timestamp}`;
    const hash = crypto.createHash("sha256").update(authString).digest("hex");
    return {
      "x-xdr-auth-id": this.apiKeyId,
      "x-xdr-nonce": nonce,
      "x-xdr-timestamp": timestamp,
      "Authorization": hash
    };
  }
  // ─── Override request to inject advanced auth headers ──────────────────────
  async request(config) {
    if (this.securityLevel === "advanced") {
      config.headers = { ...config.headers, ...this.getAdvancedHeaders() };
    }
    return super.request(config);
  }
  // ─── Health Check ──────────────────────────────────────────────────────────
  async healthCheck() {
    const start = Date.now();
    try {
      await this.ensureAuthenticated();
      const endpoints = await this.listEndpoints({ limit: 1 });
      return {
        status: "connected",
        latencyMs: Date.now() - start,
        message: `Cortex XDR connected \u2014 ${endpoints.length} endpoint(s) visible`,
        details: {
          securityLevel: this.securityLevel,
          endpointCount: endpoints.length
        }
      };
    } catch (error) {
      return {
        status: "error",
        latencyMs: Date.now() - start,
        message: error.message || "Health check failed"
      };
    }
  }
  // ─── Incidents ─────────────────────────────────────────────────────────────
  async listIncidents(options) {
    const limit = options?.limit ?? 50;
    const filters = [];
    if (options?.timeRange) {
      filters.push({
        field: "creation_time",
        operator: "gte",
        value: options.timeRange.start
      });
      filters.push({
        field: "creation_time",
        operator: "lte",
        value: options.timeRange.end
      });
    }
    const data = await this.request({
      method: "POST",
      url: "/public_api/v1/incidents/get_incidents",
      data: {
        request_data: {
          filters,
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit,
          sort: { field: "creation_time", keyword: "desc" }
        }
      }
    });
    return (data.reply?.incidents || []).map((inc) => ({
      id: inc.incident_id,
      type: "incident",
      title: inc.incident_name,
      severity: inc.severity,
      status: inc.status,
      detectedAt: inc.creation_time,
      mitreAttackId: inc.mitre_techniques_ids_and_names?.join(", "),
      raw: inc
    }));
  }
  async getIncidentDetails(incidentId) {
    const data = await this.request({
      method: "POST",
      url: "/public_api/v1/incidents/get_incident_extra_data",
      data: {
        request_data: { incident_id: incidentId }
      }
    });
    return { ...data.reply.incident, alerts: data.reply.alerts?.data || [] };
  }
  // ─── Alerts ────────────────────────────────────────────────────────────────
  async listAlerts(options) {
    const limit = options?.limit ?? 50;
    const filters = [];
    if (options?.timeRange) {
      filters.push({
        field: "detection_timestamp",
        operator: "gte",
        value: options.timeRange.start
      });
    }
    const data = await this.request({
      method: "POST",
      url: "/public_api/v1/alerts/get_alerts_multi_events",
      data: {
        request_data: {
          filters,
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit,
          sort: { field: "detection_timestamp", keyword: "desc" }
        }
      }
    });
    return (data.reply?.alerts || []).map((alert) => ({
      id: alert.alert_id,
      type: "alert",
      title: alert.name,
      severity: this.normalizeSeverity(alert.severity),
      status: alert.action_status,
      hostname: alert.host_name,
      ipAddress: alert.host_ip?.[0],
      detectedAt: alert.detection_timestamp,
      mitreAttackId: alert.mitre_technique_id_and_name,
      raw: alert
    }));
  }
  // ─── Endpoints ─────────────────────────────────────────────────────────────
  async listEndpoints(options) {
    const limit = options?.limit ?? 100;
    const data = await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/get_endpoint",
      data: {
        request_data: {
          filters: [],
          search_from: options?.offset ?? 0,
          search_to: (options?.offset ?? 0) + limit
        }
      }
    });
    return data.reply || [];
  }
  async getEndpoint(endpointId) {
    const data = await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/get_endpoint",
      data: {
        request_data: {
          filters: [{ field: "endpoint_id", operator: "in", value: [endpointId] }]
        }
      }
    });
    return data.reply?.[0] || null;
  }
  // ─── XQL Queries ───────────────────────────────────────────────────────────
  async runXQLQuery(query, timeframe) {
    const startData = await this.request({
      method: "POST",
      url: "/public_api/v1/xql/start_xql_query",
      data: {
        request_data: {
          query,
          tenants: [],
          timeframe: timeframe || {
            from: Date.now() - 7 * 24 * 60 * 60 * 1e3,
            to: Date.now()
          }
        }
      }
    });
    const queryId = startData.reply;
    for (let i = 0; i < 15; i++) {
      await new Promise((resolve) => setTimeout(resolve, 2e3));
      const result = await this.request({
        method: "POST",
        url: "/public_api/v1/xql/get_query_results",
        data: {
          request_data: { query_id: queryId, pending_result: true }
        }
      });
      if (result.reply.status === "SUCCESS" || result.reply.status === "PARTIAL_SUCCESS") {
        return result.reply;
      }
      if (result.reply.status === "FAIL") {
        throw new VendorError("cortex_xdr", "XQL query failed", "QUERY_FAILED");
      }
    }
    throw new VendorError("cortex_xdr", "XQL query timed out", "TIMEOUT");
  }
  // ─── Response Actions ──────────────────────────────────────────────────────
  async isolateEndpoint(endpointId) {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/isolate",
      data: {
        request_data: { endpoint_id: endpointId }
      }
    });
  }
  async unisolateEndpoint(endpointId) {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/unisolate",
      data: {
        request_data: { endpoint_id: endpointId }
      }
    });
  }
  async scanEndpoint(endpointId) {
    await this.request({
      method: "POST",
      url: "/public_api/v1/endpoints/scan",
      data: {
        request_data: {
          filters: [{ field: "endpoint_id", operator: "in", value: [endpointId] }]
        }
      }
    });
  }
  // ─── IOC Management ────────────────────────────────────────────────────────
  async pushIOCs(indicators) {
    try {
      await this.request({
        method: "POST",
        url: "/public_api/v1/indicators/insert_jsons",
        data: {
          request_data: indicators.map((ioc) => ({
            indicator: ioc.value,
            type: ioc.type,
            reputation: ioc.reputation,
            comment: `[AC3] ${ioc.comment}`,
            expiration_date: ioc.expiration || Date.now() + 30 * 24 * 60 * 60 * 1e3,
            severity: ioc.reputation === "BAD" ? "HIGH" : "MEDIUM",
            vendors: [{ vendor_name: "AC3", reliability: "A", reputation: ioc.reputation }],
            class: "Malware"
          }))
        }
      });
      return { created: indicators.length, failed: 0 };
    } catch {
      return { created: 0, failed: indicators.length };
    }
  }
  // ─── Helpers ───────────────────────────────────────────────────────────────
  normalizeSeverity(severity) {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "critical";
      case "high":
        return "high";
      case "medium":
        return "medium";
      case "low":
        return "low";
      case "informational":
        return "informational";
      default:
        return "medium";
    }
  }
};
function createCortexXDRClient(authConfig, connectionConfig) {
  return new CortexXDRClient(authConfig, {
    baseUrl: connectionConfig?.baseUrl || "",
    timeout: connectionConfig?.timeout ?? 3e4,
    ...connectionConfig
  });
}

// server/lib/vendors/index.ts
var VENDOR_METADATA = {
  crowdstrike: {
    displayName: "CrowdStrike Falcon",
    category: "EDR",
    authType: "oauth2",
    requiredFields: ["clientId", "clientSecret"],
    optionalFields: ["region"],
    defaultBaseUrl: "https://api.crowdstrike.com",
    description: "Endpoint detection and response with cloud-native architecture",
    capabilities: ["hosts", "detections", "incidents", "iocs", "containment"]
  },
  sentinelone: {
    displayName: "SentinelOne",
    category: "EDR",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: [],
    defaultBaseUrl: "",
    description: "AI-powered endpoint protection with autonomous response",
    capabilities: ["agents", "threats", "activities", "mitigation", "network_isolation"]
  },
  defender: {
    displayName: "Microsoft Defender for Endpoint",
    category: "EDR",
    authType: "oauth2",
    requiredFields: ["tenantId", "clientId", "clientSecret"],
    optionalFields: [],
    defaultBaseUrl: "https://api.securitycenter.microsoft.com/api",
    description: "Enterprise endpoint security with advanced hunting (KQL)",
    capabilities: ["machines", "alerts", "vulnerabilities", "advanced_hunting", "isolation"]
  },
  splunk: {
    displayName: "Splunk Enterprise Security",
    category: "SIEM",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: [],
    defaultBaseUrl: "",
    description: "Security information and event management with SPL search",
    capabilities: ["search", "notable_events", "saved_searches", "correlation"]
  },
  xsoar: {
    displayName: "Palo Alto Cortex XSOAR",
    category: "SOAR",
    authType: "token",
    requiredFields: ["apiToken"],
    optionalFields: ["apiKeyId"],
    defaultBaseUrl: "",
    description: "Security orchestration, automation, and response platform",
    capabilities: ["incidents", "indicators", "playbooks", "war_room", "automation"]
  },
  sentinel: {
    displayName: "Microsoft Sentinel",
    category: "SIEM",
    authType: "oauth2",
    requiredFields: ["tenantId", "clientId", "clientSecret"],
    optionalFields: [],
    defaultBaseUrl: "",
    description: "Cloud-native SIEM with KQL hunting, analytics rules, watchlists, and threat intelligence",
    capabilities: ["incidents", "hunting_queries", "analytics_rules", "watchlists", "threat_intelligence", "ioc_push"]
  },
  cortex_xdr: {
    displayName: "Palo Alto Cortex XDR",
    category: "XDR",
    authType: "token",
    requiredFields: ["apiToken", "apiKeyId"],
    optionalFields: ["region"],
    defaultBaseUrl: "",
    description: "Extended detection and response with XQL queries, endpoint actions, and IOC management",
    capabilities: ["incidents", "alerts", "endpoints", "xql_queries", "isolation", "ioc_management"]
  }
};
var clientCache = /* @__PURE__ */ new Map();
var CACHE_TTL = 5 * 60 * 1e3;
function createVendorClient(vendor, authConfig, connectionConfig) {
  switch (vendor) {
    case "crowdstrike":
      return createCrowdStrikeClient(authConfig, connectionConfig);
    case "sentinelone":
      return createSentinelOneClient(authConfig, connectionConfig);
    case "defender":
      return createDefenderClient(authConfig, connectionConfig);
    case "splunk":
      return createSplunkClient(authConfig, connectionConfig);
    case "xsoar":
      return createXSOARClient(authConfig, connectionConfig);
    case "sentinel":
      return createSentinelClient(authConfig, connectionConfig);
    case "cortex_xdr":
      return createCortexXDRClient(authConfig, connectionConfig);
    default:
      throw new VendorError(vendor, `Unknown vendor: ${vendor}`, "UNKNOWN_VENDOR");
  }
}
async function listIntegrations() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(vendorIntegrations).orderBy(vendorIntegrations.vendor);
}
async function getIntegration(id) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.id, id));
  return rows[0] || null;
}
async function getIntegrationByVendor(vendor) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db.select().from(vendorIntegrations).where(eq(vendorIntegrations.vendor, vendor));
  return rows[0] || null;
}
async function upsertIntegration(data) {
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const existing = await getIntegrationByVendor(data.vendor);
  if (existing) {
    await db.update(vendorIntegrations).set({
      displayName: data.displayName,
      authConfig: data.authConfig,
      connectionConfig: data.connectionConfig,
      enabled: data.enabled ?? existing.enabled,
      syncEnabled: data.syncEnabled ?? existing.syncEnabled,
      syncIntervalMinutes: data.syncIntervalMinutes ?? existing.syncIntervalMinutes
    }).where(eq(vendorIntegrations.id, existing.id));
    clientCache.delete(existing.id);
    return existing.id;
  }
  const result = await db.insert(vendorIntegrations).values({
    vendor: data.vendor,
    displayName: data.displayName,
    authConfig: data.authConfig,
    connectionConfig: data.connectionConfig,
    enabled: data.enabled ?? false,
    syncEnabled: data.syncEnabled ?? false,
    syncIntervalMinutes: data.syncIntervalMinutes ?? 60,
    createdBy: data.createdBy
  });
  return Number(result[0].insertId);
}
async function deleteIntegration(id) {
  const db = await getDb();
  if (!db) return;
  await db.delete(vendorIntegrations).where(eq(vendorIntegrations.id, id));
  clientCache.delete(id);
}
async function updateIntegrationStatus(id, status, error) {
  const db = await getDb();
  if (!db) return;
  await db.update(vendorIntegrations).set({
    status,
    lastHealthCheck: Date.now(),
    lastError: error || null
  }).where(eq(vendorIntegrations.id, id));
}
async function getClientForIntegration(id) {
  const cached = clientCache.get(id);
  if (cached && Date.now() - cached.createdAt < CACHE_TTL) {
    return cached.client;
  }
  const integration = await getIntegration(id);
  if (!integration) throw new VendorError("crowdstrike", `Integration ${id} not found`, "NOT_FOUND");
  if (!integration.enabled) throw new VendorError(integration.vendor, `Integration ${integration.vendor} is disabled`, "DISABLED");
  const authConfig = integration.authConfig || {};
  const connConfig = integration.connectionConfig || {};
  const client = createVendorClient(integration.vendor, authConfig, connConfig);
  clientCache.set(id, { client, createdAt: Date.now() });
  return client;
}
async function healthCheckAll() {
  const integrations = await listIntegrations();
  const results = [];
  for (const integration of integrations) {
    if (!integration.enabled) {
      results.push({
        vendor: integration.vendor,
        id: integration.id,
        result: { status: "disconnected", latencyMs: 0, message: "Integration is disabled" }
      });
      continue;
    }
    try {
      const client = await getClientForIntegration(integration.id);
      const result = await client.healthCheck();
      await updateIntegrationStatus(integration.id, result.status, result.status === "error" ? result.message : void 0);
      results.push({ vendor: integration.vendor, id: integration.id, result });
    } catch (error) {
      const result = {
        status: "error",
        latencyMs: 0,
        message: error.message
      };
      await updateIntegrationStatus(integration.id, "error", result.message);
      results.push({ vendor: integration.vendor, id: integration.id, result });
    }
  }
  return results;
}
async function logSyncEvent(data) {
  const db = await getDb();
  if (!db) return;
  await db.insert(vendorSyncEvents).values({
    integrationId: data.integrationId,
    eventType: data.eventType,
    status: data.status,
    recordsProcessed: data.recordsProcessed ?? 0,
    recordsFailed: data.recordsFailed ?? 0,
    summary: data.summary,
    errorMessage: data.errorMessage,
    durationMs: data.durationMs,
    triggeredBy: data.triggeredBy
  });
}
async function cacheVendorData(integrationId, items) {
  const db = await getDb();
  if (!db) return 0;
  if (!items.length) return 0;
  const values = items.map((item) => ({
    integrationId,
    dataType: item.type,
    externalId: item.id,
    title: item.title?.slice(0, 512),
    severity: item.severity,
    status: item.status?.slice(0, 64),
    rawData: item.raw,
    normalizedData: item,
    hostname: item.hostname?.slice(0, 255),
    ipAddress: item.ipAddress?.slice(0, 45),
    domain: item.domain?.slice(0, 255),
    mitreAttackId: item.mitreAttackId?.slice(0, 32),
    detectedAt: item.detectedAt,
    lastUpdatedAt: Date.now()
  }));
  let inserted = 0;
  for (let i = 0; i < values.length; i += 50) {
    const batch = values.slice(i, i + 50);
    await db.insert(vendorCachedData).values(batch);
    inserted += batch.length;
  }
  return inserted;
}
async function queryCachedData(filters) {
  const db = await getDb();
  if (!db) return [];
  let query = db.select().from(vendorCachedData);
  const conditions = [];
  if (filters.integrationId) conditions.push(eq(vendorCachedData.integrationId, filters.integrationId));
  if (filters.dataType) conditions.push(eq(vendorCachedData.dataType, filters.dataType));
  if (filters.hostname) conditions.push(eq(vendorCachedData.hostname, filters.hostname));
  if (filters.ipAddress) conditions.push(eq(vendorCachedData.ipAddress, filters.ipAddress));
  if (filters.severity) conditions.push(eq(vendorCachedData.severity, filters.severity));
  if (conditions.length === 1) {
    query = query.where(conditions[0]);
  }
  return query.limit(filters.limit ?? 100);
}

export {
  BaseVendorClient,
  VendorError,
  CrowdStrikeClient,
  SentinelOneClient,
  DefenderClient,
  SplunkClient,
  XSOARClient,
  SentinelClient,
  CortexXDRClient,
  VENDOR_METADATA,
  createVendorClient,
  listIntegrations,
  getIntegration,
  getIntegrationByVendor,
  upsertIntegration,
  deleteIntegration,
  updateIntegrationStatus,
  getClientForIntegration,
  healthCheckAll,
  logSyncEvent,
  cacheVendorData,
  queryCachedData
};
