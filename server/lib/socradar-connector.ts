/**
 * SOCRadar Connector — Dark Web Monitoring, Brand Protection & Threat Feeds
 *
 * Integrates with SOCRadar's Extended Threat Intelligence platform:
 *   - Incidents API: dark web mentions, brand impersonation, data leaks
 *   - ThreatFusion API: IOC enrichment (IP, domain, hash reputation)
 *   - Threat Feeds: curated IOC feeds (C2, botnet, malware hashes, APT)
 *
 * API Base: https://platform.socradar.com/api/
 * Auth: API Key + Company ID
 */

// ─── Types ───────────────────────────────────────────────────────────────

export interface SOCRadarConfig {
  apiKey: string;
  companyId: string;
  baseUrl?: string; // defaults to https://platform.socradar.com/api
}

export interface SOCRadarIncident {
  id: number;
  mainType: string;
  subType: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  content?: string;
  createdAt: string;
  resolvedAt?: string;
  isFalsePositive: boolean;
  isResolved: boolean;
  assets?: string[];
  source?: string;
}

export interface SOCRadarIOCReputation {
  indicator: string;
  type: "ip" | "domain" | "hash";
  riskScore: number; // 0-100
  totalEncounters: number;
  scoreDetails: Record<string, number>;
  geoLocation?: {
    country: string;
    city?: string;
    asn?: string;
    asnName?: string;
    latitude?: number;
    longitude?: number;
  };
  whoisDetails?: Record<string, any>;
  dnsDetails?: Record<string, any>;
  lastSeen?: string;
  tags?: string[];
}

export interface SOCRadarThreatFeed {
  id: string;
  name: string;
  type: "c2" | "botnet" | "malware" | "apt" | "ransomware" | "phishing" | "scanner";
  indicators: SOCRadarFeedIndicator[];
  lastUpdated: string;
  totalCount: number;
}

export interface SOCRadarFeedIndicator {
  value: string;
  type: "ip" | "domain" | "url" | "hash";
  confidence: number; // 0-100
  firstSeen: string;
  lastSeen: string;
  tags?: string[];
  threatActor?: string;
}

export interface SOCRadarBrandAlert {
  id: number;
  type: "impersonation" | "phishing_domain" | "social_media" | "mobile_app" | "typosquat";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  detectedAt: string;
  domain?: string;
  url?: string;
  status: "active" | "taken_down" | "monitoring";
  takedownRequested: boolean;
}

export interface SOCRadarDarkWebMention {
  id: number;
  source: "forum" | "marketplace" | "paste" | "telegram" | "discord" | "irc";
  title: string;
  content: string;
  detectedAt: string;
  severity: "critical" | "high" | "medium" | "low";
  category: "credential_leak" | "data_sale" | "exploit_discussion" | "brand_mention" | "access_sale";
  threatActor?: string;
  url?: string;
  affectedAssets?: string[];
}

export interface SOCRadarStats {
  totalIncidents: number;
  openIncidents: number;
  resolvedIncidents: number;
  falsePositives: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
  darkWebMentions: number;
  brandAlerts: number;
  dataLeaks: number;
}

// ─── Connector Class ─────────────────────────────────────────────────────

export class SOCRadarConnector {
  private config: SOCRadarConfig;
  private baseUrl: string;

  constructor(config: SOCRadarConfig) {
    this.config = config;
    this.baseUrl = (config.baseUrl || "https://platform.socradar.com/api").replace(/\/+$/, "");
  }

  // ─── Connection Verification ───────────────────────────────────────────

  async verify(): Promise<{ valid: boolean; message: string; companyName?: string }> {
    try {
      const res = await this.request("/company/info");
      if (res.ok) {
        const data = await res.json();
        return {
          valid: true,
          message: "Successfully connected to SOCRadar platform",
          companyName: data.company_name || data.name || "Unknown",
        };
      }
      if (res.status === 401 || res.status === 403) {
        return { valid: false, message: "Invalid API key or insufficient permissions" };
      }
      return { valid: false, message: `SOCRadar returned status ${res.status}` };
    } catch (err: any) {
      return { valid: false, message: `Connection failed: ${err.message}` };
    }
  }

  // ─── Incidents ─────────────────────────────────────────────────────────

  async getIncidents(params?: {
    severity?: string[];
    mainType?: string;
    subType?: string;
    resolved?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ incidents: SOCRadarIncident[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.severity?.length) query.set("severity", params.severity.join(","));
    if (params?.mainType) query.set("main_type", params.mainType);
    if (params?.subType) query.set("sub_type", params.subType);
    if (params?.resolved !== undefined) query.set("is_resolved", String(params.resolved));
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));

    try {
      const res = await this.request(`/incidents?${query.toString()}`);
      if (!res.ok) return { incidents: [], total: 0 };
      const data = await res.json();
      const incidents: SOCRadarIncident[] = (data.incidents || data.data || []).map(this.normalizeIncident);
      return { incidents, total: data.total || incidents.length };
    } catch {
      return { incidents: [], total: 0 };
    }
  }

  async markIncidentFP(incidentId: number, comments?: string): Promise<boolean> {
    try {
      const res = await this.request(`/incidents/${incidentId}/false-positive`, {
        method: "POST",
        body: JSON.stringify({ comments: comments || "Marked as FP from AC3 platform" }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  async markIncidentResolved(incidentId: number, comments?: string): Promise<boolean> {
    try {
      const res = await this.request(`/incidents/${incidentId}/resolve`, {
        method: "POST",
        body: JSON.stringify({ comments: comments || "Resolved from AC3 platform" }),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  // ─── Dark Web Monitoring ───────────────────────────────────────────────

  async getDarkWebMentions(params?: {
    category?: string;
    severity?: string;
    limit?: number;
  }): Promise<SOCRadarDarkWebMention[]> {
    const query = new URLSearchParams();
    if (params?.category) query.set("category", params.category);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.limit) query.set("limit", String(params.limit));

    try {
      const res = await this.request(`/darkweb/mentions?${query.toString()}`);
      if (!res.ok) return [];
      const data = await res.json();
      return (data.mentions || data.data || []).map(this.normalizeDarkWebMention);
    } catch {
      return [];
    }
  }

  // ─── Brand Protection ──────────────────────────────────────────────────

  async getBrandAlerts(params?: {
    type?: string;
    status?: string;
    limit?: number;
  }): Promise<SOCRadarBrandAlert[]> {
    const query = new URLSearchParams();
    if (params?.type) query.set("type", params.type);
    if (params?.status) query.set("status", params.status);
    if (params?.limit) query.set("limit", String(params.limit));

    try {
      const res = await this.request(`/brand/alerts?${query.toString()}`);
      if (!res.ok) return [];
      const data = await res.json();
      return (data.alerts || data.data || []).map(this.normalizeBrandAlert);
    } catch {
      return [];
    }
  }

  async requestTakedown(alertId: number): Promise<boolean> {
    try {
      const res = await this.request(`/brand/alerts/${alertId}/takedown`, {
        method: "POST",
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  // ─── IOC Enrichment (ThreatFusion) ─────────────────────────────────────

  async enrichIP(ip: string): Promise<SOCRadarIOCReputation | null> {
    return this.enrichIndicator(ip, "ip");
  }

  async enrichDomain(domain: string): Promise<SOCRadarIOCReputation | null> {
    return this.enrichIndicator(domain, "domain");
  }

  async enrichHash(hash: string): Promise<SOCRadarIOCReputation | null> {
    return this.enrichIndicator(hash, "hash");
  }

  private async enrichIndicator(
    indicator: string,
    type: "ip" | "domain" | "hash",
  ): Promise<SOCRadarIOCReputation | null> {
    try {
      const res = await this.request(`/threatfusion/${type}/${encodeURIComponent(indicator)}`);
      if (!res.ok) return null;
      const data = await res.json();
      return {
        indicator,
        type,
        riskScore: data.risk_score ?? data["Risk Score"] ?? 0,
        totalEncounters: data.total_encounters ?? data["Total Encounters"] ?? 0,
        scoreDetails: data.score_details ?? data["Score Details"] ?? {},
        geoLocation: data.geo_location
          ? {
              country: data.geo_location.CountryName || data.geo_location.country || "",
              city: data.geo_location.CityName || data.geo_location.city,
              asn: data.geo_location.ASN || data.geo_location.asn,
              asnName: data.geo_location.AsnName || data.geo_location.asn_name,
              latitude: data.geo_location.Latitude || data.geo_location.latitude,
              longitude: data.geo_location.Longitude || data.geo_location.longitude,
            }
          : undefined,
        whoisDetails: data.whois_details ?? data["Whois Details"],
        dnsDetails: data.dns_details ?? data["DNS Details"],
        lastSeen: data.last_seen,
        tags: data.tags || [],
      };
    } catch {
      return null;
    }
  }

  // ─── Threat Feeds ──────────────────────────────────────────────────────

  async getThreatFeeds(params?: {
    type?: string;
    limit?: number;
  }): Promise<SOCRadarThreatFeed[]> {
    const query = new URLSearchParams();
    if (params?.type) query.set("type", params.type);
    if (params?.limit) query.set("limit", String(params.limit));

    try {
      const res = await this.request(`/threat-feeds?${query.toString()}`);
      if (!res.ok) return [];
      const data = await res.json();
      return (data.feeds || data.data || []).map(this.normalizeThreatFeed);
    } catch {
      return [];
    }
  }

  async getFeedIndicators(feedId: string, limit = 100): Promise<SOCRadarFeedIndicator[]> {
    try {
      const res = await this.request(`/threat-feeds/${feedId}/indicators?limit=${limit}`);
      if (!res.ok) return [];
      const data = await res.json();
      return (data.indicators || data.data || []).map(this.normalizeFeedIndicator);
    } catch {
      return [];
    }
  }

  // ─── Statistics ────────────────────────────────────────────────────────

  async getStats(): Promise<SOCRadarStats> {
    try {
      const res = await this.request("/stats/summary");
      if (!res.ok) {
        return this.emptyStats();
      }
      const data = await res.json();
      return {
        totalIncidents: data.total_incidents ?? 0,
        openIncidents: data.open_incidents ?? 0,
        resolvedIncidents: data.resolved_incidents ?? 0,
        falsePositives: data.false_positives ?? 0,
        bySeverity: data.by_severity ?? {},
        byType: data.by_type ?? {},
        darkWebMentions: data.dark_web_mentions ?? 0,
        brandAlerts: data.brand_alerts ?? 0,
        dataLeaks: data.data_leaks ?? 0,
      };
    } catch {
      return this.emptyStats();
    }
  }

  // ─── Private Helpers ───────────────────────────────────────────────────

  private async request(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${this.config.apiKey}`,
      "X-Company-ID": this.config.companyId,
    };

    return fetch(url, {
      ...init,
      headers: { ...headers, ...(init?.headers as Record<string, string> || {}) },
      signal: AbortSignal.timeout(15000),
    });
  }

  private normalizeIncident(raw: any): SOCRadarIncident {
    return {
      id: raw.id || raw.incident_id || 0,
      mainType: raw.main_type || raw.mainType || "unknown",
      subType: raw.sub_type || raw.subType || "",
      severity: (raw.severity || "medium").toLowerCase() as any,
      title: raw.title || raw.name || "Untitled Incident",
      content: raw.content || raw.description || "",
      createdAt: raw.created_at || raw.createdAt || new Date().toISOString(),
      resolvedAt: raw.resolved_at || raw.resolvedAt,
      isFalsePositive: raw.is_false_positive ?? raw.isFalsePositive ?? false,
      isResolved: raw.is_resolved ?? raw.isResolved ?? false,
      assets: raw.assets || raw.affected_assets || [],
      source: raw.source || "",
    };
  }

  private normalizeDarkWebMention(raw: any): SOCRadarDarkWebMention {
    return {
      id: raw.id || 0,
      source: (raw.source || "forum").toLowerCase() as any,
      title: raw.title || "Dark Web Mention",
      content: raw.content || raw.description || "",
      detectedAt: raw.detected_at || raw.createdAt || new Date().toISOString(),
      severity: (raw.severity || "medium").toLowerCase() as any,
      category: (raw.category || "brand_mention").toLowerCase().replace(/\s+/g, "_") as any,
      threatActor: raw.threat_actor || raw.threatActor,
      url: raw.url,
      affectedAssets: raw.affected_assets || raw.assets || [],
    };
  }

  private normalizeBrandAlert(raw: any): SOCRadarBrandAlert {
    return {
      id: raw.id || 0,
      type: (raw.type || "impersonation").toLowerCase().replace(/\s+/g, "_") as any,
      severity: (raw.severity || "medium").toLowerCase() as any,
      title: raw.title || "Brand Alert",
      description: raw.description || raw.content || "",
      detectedAt: raw.detected_at || raw.createdAt || new Date().toISOString(),
      domain: raw.domain,
      url: raw.url,
      status: (raw.status || "active").toLowerCase().replace(/\s+/g, "_") as any,
      takedownRequested: raw.takedown_requested ?? false,
    };
  }

  private normalizeThreatFeed(raw: any): SOCRadarThreatFeed {
    return {
      id: raw.id || String(Math.random()),
      name: raw.name || "Unknown Feed",
      type: (raw.type || "malware").toLowerCase() as any,
      indicators: [],
      lastUpdated: raw.last_updated || raw.updatedAt || new Date().toISOString(),
      totalCount: raw.total_count || raw.indicator_count || 0,
    };
  }

  private normalizeFeedIndicator(raw: any): SOCRadarFeedIndicator {
    return {
      value: raw.value || raw.indicator || "",
      type: (raw.type || "ip").toLowerCase() as any,
      confidence: raw.confidence ?? 80,
      firstSeen: raw.first_seen || raw.firstSeen || new Date().toISOString(),
      lastSeen: raw.last_seen || raw.lastSeen || new Date().toISOString(),
      tags: raw.tags || [],
      threatActor: raw.threat_actor || raw.threatActor,
    };
  }

  private emptyStats(): SOCRadarStats {
    return {
      totalIncidents: 0,
      openIncidents: 0,
      resolvedIncidents: 0,
      falsePositives: 0,
      bySeverity: {},
      byType: {},
      darkWebMentions: 0,
      brandAlerts: 0,
      dataLeaks: 0,
    };
  }
}
