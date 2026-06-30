/**
 * Bug Bounty Platform Live Feed Connectors
 * 
 * Provides real-time integration with HackerOne and Bugcrowd APIs:
 * - Program listing with scope, rewards, and response times
 * - Disclosed report feeds for trend analysis
 * - New scope change detection for opportunity alerts
 * - Payout tracking for ROI estimation
 * 
 * API References:
 * - HackerOne: https://api.hackerone.com/ (JSON:API spec)
 * - Bugcrowd: https://docs.bugcrowd.com/api/ (JSON:API spec)
 */

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface BountyProgram {
  id: string;
  platform: "hackerone" | "bugcrowd" | "intigriti";
  handle: string;
  name: string;
  url: string;
  managed: boolean;
  state: "open" | "paused" | "closed";
  offersBounties: boolean;
  rewardRange: { min: number; max: number; currency: string } | null;
  averagePayout: number | null;
  responseEfficiency: {
    firstResponseDays: number | null;
    triageDays: number | null;
    bountyDays: number | null;
    resolutionDays: number | null;
  };
  scope: ProgramScope[];
  vulnTypes: string[];
  lastUpdated: string;
  launchDate: string | null;
  reportsResolved: number;
  hackerCount: number;
}

export interface ProgramScope {
  type: "url" | "domain" | "wildcard" | "ios" | "android" | "api" | "hardware" | "other";
  target: string;
  eligible: boolean;
  maxSeverity: string | null;
  instruction: string | null;
}

export interface DisclosedReport {
  id: string;
  platform: "hackerone" | "bugcrowd";
  programHandle: string;
  title: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  cweId: string | null;
  cvssScore: number | null;
  bountyAmount: number | null;
  currency: string;
  state: string;
  disclosedAt: string;
  url: string;
  vulnType: string | null;
}

export interface ScopeChange {
  id: string;
  platform: "hackerone" | "bugcrowd";
  programHandle: string;
  programName: string;
  changeType: "added" | "removed" | "modified";
  target: string;
  targetType: string;
  detectedAt: string;
  previousValue?: string;
}

export interface FeedEvent {
  id: string;
  type: "new_program" | "scope_change" | "payout" | "disclosure" | "program_update";
  platform: "hackerone" | "bugcrowd" | "intigriti";
  programHandle: string;
  programName: string;
  title: string;
  description: string;
  severity?: string;
  amount?: number;
  currency?: string;
  timestamp: string;
  url: string;
}

export interface FeedState {
  lastFetchedAt: string | null;
  totalPrograms: number;
  activePrograms: number;
  totalDisclosures: number;
  recentScopeChanges: number;
  feedHealth: "healthy" | "degraded" | "error";
  errorMessage: string | null;
}

// ─── HackerOne API Client ──────────────────────────────────────────────────────

export class HackerOneClient {
  private baseUrl = "https://api.hackerone.com/v1";
  private apiToken: string;
  private apiIdentifier: string;

  constructor(apiIdentifier: string, apiToken: string) {
    this.apiIdentifier = apiIdentifier;
    this.apiToken = apiToken;
  }

  private getAuthHeader(): string {
    return "Basic " + Buffer.from(`${this.apiIdentifier}:${this.apiToken}`).toString("base64");
  }

  private async request<T>(endpoint: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    if (params) {
      Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    }

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: this.getAuthHeader(),
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`HackerOne API error: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  async getPrograms(page = 1, pageSize = 25): Promise<{ programs: BountyProgram[]; total: number }> {
    const data = await this.request<any>("/hackers/programs", {
      "page[number]": String(page),
      "page[size]": String(pageSize),
    });

    const programs: BountyProgram[] = (data.data || []).map((p: any) => this.mapProgram(p));
    const total = data.meta?.total_count || programs.length;

    return { programs, total };
  }

  async getProgramByHandle(handle: string): Promise<BountyProgram | null> {
    try {
      const data = await this.request<any>(`/hackers/programs/${handle}`);
      return this.mapProgram(data.data);
    } catch {
      return null;
    }
  }

  async getProgramScope(handle: string): Promise<ProgramScope[]> {
    try {
      const data = await this.request<any>(
        `/hackers/programs/${handle}/structured_scopes`,
        { "page[size]": "100" }
      );
      return (data.data || []).map((s: any) => ({
        type: s.attributes?.asset_type || "other",
        target: s.attributes?.asset_identifier || "",
        eligible: s.attributes?.eligible_for_bounty ?? true,
        maxSeverity: s.attributes?.max_severity || null,
        instruction: s.attributes?.instruction || null,
      }));
    } catch {
      return [];
    }
  }

  async getDisclosedReports(programHandle?: string, page = 1): Promise<DisclosedReport[]> {
    const params: Record<string, string> = {
      "page[number]": String(page),
      "page[size]": "25",
      "filter[disclosed]": "true",
    };
    if (programHandle) {
      params["filter[program][]"] = programHandle;
    }

    try {
      const data = await this.request<any>("/hackers/reports", params);
      return (data.data || []).map((r: any) => ({
        id: r.id,
        platform: "hackerone" as const,
        programHandle: r.relationships?.program?.data?.attributes?.handle || "",
        title: r.attributes?.title || "Untitled",
        severity: this.mapSeverity(r.attributes?.severity_rating),
        cweId: r.attributes?.cwe_id || null,
        cvssScore: r.attributes?.cvss_score || null,
        bountyAmount: r.relationships?.bounties?.data?.[0]?.attributes?.amount || null,
        currency: "USD",
        state: r.attributes?.state || "unknown",
        disclosedAt: r.attributes?.disclosed_at || new Date().toISOString(),
        url: `https://hackerone.com/reports/${r.id}`,
        vulnType: r.attributes?.weakness?.name || null,
      }));
    } catch {
      return [];
    }
  }

  private mapProgram(p: any): BountyProgram {
    const attrs = p.attributes || {};
    return {
      id: p.id,
      platform: "hackerone",
      handle: attrs.handle || p.id,
      name: attrs.name || attrs.handle || "Unknown",
      url: `https://hackerone.com/${attrs.handle || p.id}`,
      managed: attrs.triage_active || false,
      state: attrs.state === "public_mode" ? "open" : attrs.state === "paused" ? "paused" : "open",
      offersBounties: attrs.offers_bounties ?? true,
      rewardRange: attrs.meta?.bounty_table ? {
        min: attrs.meta.bounty_table.low || 0,
        max: attrs.meta.bounty_table.high || 0,
        currency: "USD",
      } : null,
      averagePayout: attrs.average_bounty_lower_amount || null,
      responseEfficiency: {
        firstResponseDays: attrs.first_response_sla_days || null,
        triageDays: attrs.triage_sla_days || null,
        bountyDays: attrs.bounty_sla_days || null,
        resolutionDays: attrs.resolution_sla_days || null,
      },
      scope: [],
      vulnTypes: [],
      lastUpdated: attrs.updated_at || new Date().toISOString(),
      launchDate: attrs.started_accepting_at || null,
      reportsResolved: attrs.resolved_report_count || 0,
      hackerCount: attrs.hacker_count || 0,
    };
  }

  private mapSeverity(rating: string | null): DisclosedReport["severity"] {
    switch (rating) {
      case "critical": return "critical";
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      default: return "none";
    }
  }
}

// ─── Bugcrowd API Client ───────────────────────────────────────────────────────

export class BugcrowdClient {
  private baseUrl = "https://api.bugcrowd.com";
  private apiToken: string;

  constructor(apiToken: string) {
    this.apiToken = apiToken;
  }

  private async request<T>(endpoint: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    if (params) {
      Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
    }

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Token ${this.apiToken}`,
        Accept: "application/vnd.bugcrowd+json",
      },
    });

    if (!response.ok) {
      throw new Error(`Bugcrowd API error: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<T>;
  }

  async getPrograms(page = 1, pageSize = 25): Promise<{ programs: BountyProgram[]; total: number }> {
    const offset = (page - 1) * pageSize;
    const data = await this.request<any>("/programs", {
      "page[offset]": String(offset),
      "page[limit]": String(pageSize),
      "filter[participation]": "registered",
    });

    const programs: BountyProgram[] = (data.data || []).map((p: any) => this.mapProgram(p));
    const total = data.meta?.total_hits || programs.length;

    return { programs, total };
  }

  async getProgramByCode(code: string): Promise<BountyProgram | null> {
    try {
      const data = await this.request<any>(`/programs/${code}`);
      return this.mapProgram(data.data);
    } catch {
      return null;
    }
  }

  async getTargets(programCode: string): Promise<ProgramScope[]> {
    try {
      const data = await this.request<any>(`/programs/${programCode}/targets`, {
        "page[limit]": "100",
      });
      return (data.data || []).map((t: any) => ({
        type: this.mapTargetType(t.attributes?.category),
        target: t.attributes?.name || t.attributes?.uri || "",
        eligible: t.attributes?.in_scope ?? true,
        maxSeverity: null,
        instruction: t.attributes?.description || null,
      }));
    } catch {
      return [];
    }
  }

  async getSubmissions(programCode?: string, page = 1): Promise<DisclosedReport[]> {
    const params: Record<string, string> = {
      "page[offset]": String((page - 1) * 25),
      "page[limit]": "25",
      "filter[state]": "disclosed",
    };
    if (programCode) {
      params["filter[program]"] = programCode;
    }

    try {
      const data = await this.request<any>("/submissions", params);
      return (data.data || []).map((s: any) => ({
        id: s.id,
        platform: "bugcrowd" as const,
        programHandle: s.relationships?.program?.data?.id || "",
        title: s.attributes?.title || "Untitled",
        severity: this.mapPriority(s.attributes?.priority),
        cweId: s.attributes?.cwe || null,
        cvssScore: s.attributes?.cvss_score || null,
        bountyAmount: s.attributes?.amount_cents ? s.attributes.amount_cents / 100 : null,
        currency: "USD",
        state: s.attributes?.state || "unknown",
        disclosedAt: s.attributes?.disclosed_at || new Date().toISOString(),
        url: `https://bugcrowd.com${s.attributes?.url || ""}`,
        vulnType: s.attributes?.vulnerability_type || null,
      }));
    } catch {
      return [];
    }
  }

  private mapProgram(p: any): BountyProgram {
    const attrs = p.attributes || {};
    return {
      id: p.id,
      platform: "bugcrowd",
      handle: attrs.code || p.id,
      name: attrs.name || "Unknown",
      url: `https://bugcrowd.com${attrs.program_url || `/${attrs.code}`}`,
      managed: attrs.managed || false,
      state: attrs.status === "open" ? "open" : attrs.status === "paused" ? "paused" : "closed",
      offersBounties: attrs.offers_rewards ?? true,
      rewardRange: attrs.reward_range ? {
        min: attrs.reward_range.min || 0,
        max: attrs.reward_range.max || 0,
        currency: "USD",
      } : null,
      averagePayout: attrs.average_payout || null,
      responseEfficiency: {
        firstResponseDays: null,
        triageDays: null,
        bountyDays: null,
        resolutionDays: null,
      },
      scope: [],
      vulnTypes: attrs.target_groups || [],
      lastUpdated: attrs.updated_at || new Date().toISOString(),
      launchDate: attrs.starts_at || null,
      reportsResolved: attrs.total_submissions_resolved || 0,
      hackerCount: attrs.researcher_count || 0,
    };
  }

  private mapTargetType(category: string | null): ProgramScope["type"] {
    switch (category) {
      case "website": return "url";
      case "api": return "api";
      case "android": return "android";
      case "ios": return "ios";
      case "hardware": return "hardware";
      default: return "other";
    }
  }

  private mapPriority(priority: number | null): DisclosedReport["severity"] {
    switch (priority) {
      case 1: return "critical";
      case 2: return "high";
      case 3: return "medium";
      case 4: return "low";
      default: return "none";
    }
  }
}

// ─── Feed Aggregator ───────────────────────────────────────────────────────────

export class BugBountyFeedAggregator {
  private h1Client: HackerOneClient | null = null;
  private bcClient: BugcrowdClient | null = null;
  private feedCache: FeedEvent[] = [];
  private programCache: Map<string, BountyProgram> = new Map();
  private scopeSnapshot: Map<string, ProgramScope[]> = new Map();
  private lastFetchTimestamp: string | null = null;
  private feedHealth: FeedState["feedHealth"] = "healthy";
  private errorMessage: string | null = null;

  constructor(config: {
    hackeroneApiIdentifier?: string;
    hackeroneApiToken?: string;
    bugcrowdApiToken?: string;
  }) {
    if (config.hackeroneApiIdentifier && config.hackeroneApiToken) {
      this.h1Client = new HackerOneClient(config.hackeroneApiIdentifier, config.hackeroneApiToken);
    }
    if (config.bugcrowdApiToken) {
      this.bcClient = new BugcrowdClient(config.bugcrowdApiToken);
    }
  }

  get isConfigured(): boolean {
    return this.h1Client !== null || this.bcClient !== null;
  }

  get configuredPlatforms(): string[] {
    const platforms: string[] = [];
    if (this.h1Client) platforms.push("hackerone");
    if (this.bcClient) platforms.push("bugcrowd");
    return platforms;
  }

  async fetchPrograms(platform?: "hackerone" | "bugcrowd", page = 1): Promise<{ programs: BountyProgram[]; total: number }> {
    const allPrograms: BountyProgram[] = [];
    let total = 0;

    try {
      if ((!platform || platform === "hackerone") && this.h1Client) {
        const h1Result = await this.h1Client.getPrograms(page);
        allPrograms.push(...h1Result.programs);
        total += h1Result.total;
      }

      if ((!platform || platform === "bugcrowd") && this.bcClient) {
        const bcResult = await this.bcClient.getPrograms(page);
        allPrograms.push(...bcResult.programs);
        total += bcResult.total;
      }

      // Update cache
      allPrograms.forEach(p => this.programCache.set(`${p.platform}:${p.handle}`, p));
      this.feedHealth = "healthy";
      this.errorMessage = null;
    } catch (err: any) {
      this.feedHealth = "degraded";
      this.errorMessage = err.message;
    }

    return { programs: allPrograms, total };
  }

  async fetchDisclosedReports(platform?: "hackerone" | "bugcrowd", page = 1): Promise<DisclosedReport[]> {
    const reports: DisclosedReport[] = [];

    try {
      if ((!platform || platform === "hackerone") && this.h1Client) {
        const h1Reports = await this.h1Client.getDisclosedReports(undefined, page);
        reports.push(...h1Reports);
      }

      if ((!platform || platform === "bugcrowd") && this.bcClient) {
        const bcReports = await this.bcClient.getSubmissions(undefined, page);
        reports.push(...bcReports);
      }

      this.feedHealth = "healthy";
      this.errorMessage = null;
    } catch (err: any) {
      this.feedHealth = "degraded";
      this.errorMessage = err.message;
    }

    return reports.sort((a, b) => new Date(b.disclosedAt).getTime() - new Date(a.disclosedAt).getTime());
  }

  async detectScopeChanges(programHandle: string, platform: "hackerone" | "bugcrowd"): Promise<ScopeChange[]> {
    const changes: ScopeChange[] = [];
    const cacheKey = `${platform}:${programHandle}`;

    let currentScope: ProgramScope[] = [];
    if (platform === "hackerone" && this.h1Client) {
      currentScope = await this.h1Client.getProgramScope(programHandle);
    } else if (platform === "bugcrowd" && this.bcClient) {
      currentScope = await this.bcClient.getTargets(programHandle);
    }

    const previousScope = this.scopeSnapshot.get(cacheKey) || [];

    // Detect additions
    for (const current of currentScope) {
      const existed = previousScope.find(p => p.target === current.target && p.type === current.type);
      if (!existed) {
        changes.push({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          platform,
          programHandle,
          programName: this.programCache.get(cacheKey)?.name || programHandle,
          changeType: "added",
          target: current.target,
          targetType: current.type,
          detectedAt: new Date().toISOString(),
        });
      }
    }

    // Detect removals
    for (const prev of previousScope) {
      const stillExists = currentScope.find(c => c.target === prev.target && c.type === prev.type);
      if (!stillExists) {
        changes.push({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          platform,
          programHandle,
          programName: this.programCache.get(cacheKey)?.name || programHandle,
          changeType: "removed",
          target: prev.target,
          targetType: prev.type,
          detectedAt: new Date().toISOString(),
          previousValue: prev.target,
        });
      }
    }

    // Update snapshot
    this.scopeSnapshot.set(cacheKey, currentScope);

    return changes;
  }

  async generateFeedEvents(limit = 50): Promise<FeedEvent[]> {
    const events: FeedEvent[] = [];

    try {
      // Fetch recent disclosures as feed events
      const reports = await this.fetchDisclosedReports();
      for (const report of reports.slice(0, 20)) {
        events.push({
          id: `disclosure-${report.id}`,
          type: "disclosure",
          platform: report.platform,
          programHandle: report.programHandle,
          programName: report.programHandle,
          title: `Disclosed: ${report.title}`,
          description: `${report.severity.toUpperCase()} severity ${report.vulnType || "vulnerability"} disclosed`,
          severity: report.severity,
          amount: report.bountyAmount || undefined,
          currency: report.currency,
          timestamp: report.disclosedAt,
          url: report.url,
        });
      }

      // Sort by timestamp descending
      events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      this.feedCache = events.slice(0, limit);
      this.lastFetchTimestamp = new Date().toISOString();
      this.feedHealth = "healthy";
      this.errorMessage = null;
    } catch (err: any) {
      this.feedHealth = "error";
      this.errorMessage = err.message;
    }

    return this.feedCache;
  }

  getFeedState(): FeedState {
    return {
      lastFetchedAt: this.lastFetchTimestamp,
      totalPrograms: this.programCache.size,
      activePrograms: Array.from(this.programCache.values()).filter(p => p.state === "open").length,
      totalDisclosures: this.feedCache.filter(e => e.type === "disclosure").length,
      recentScopeChanges: this.feedCache.filter(e => e.type === "scope_change").length,
      feedHealth: this.feedHealth,
      errorMessage: this.errorMessage,
    };
  }

  getCachedPrograms(): BountyProgram[] {
    return Array.from(this.programCache.values());
  }

  getCachedFeed(): FeedEvent[] {
    return this.feedCache;
  }
}

// ─── Singleton Factory ─────────────────────────────────────────────────────────

let aggregatorInstance: BugBountyFeedAggregator | null = null;

export function getBugBountyFeedAggregator(): BugBountyFeedAggregator {
  if (!aggregatorInstance) {
    aggregatorInstance = new BugBountyFeedAggregator({
      hackeroneApiIdentifier: process.env.HACKERONE_API_USERNAME || undefined,
      hackeroneApiToken: process.env.HACKERONE_API_KEY || undefined,
      bugcrowdApiToken: process.env.BUGCROWD_API_TOKEN || undefined,
    });
  }
  return aggregatorInstance;
}

export function resetFeedAggregator(): void {
  aggregatorInstance = null;
}
