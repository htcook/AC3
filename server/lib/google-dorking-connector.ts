/**
 * Google Dorking Connector
 * 
 * Uses Google Custom Search JSON API to perform Google dorking queries
 * for OSINT and reconnaissance purposes. Supports predefined dork templates
 * for common pentest scenarios (exposed panels, config files, directory listings, etc.)
 */

// Uses process.env directly for GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID

// ─── Dork Categories & Templates ─────────────────────────────────────────────

export interface DorkTemplate {
  id: string;
  name: string;
  category: DorkCategory;
  description: string;
  query: string; // Template with {{domain}} placeholder
  severity: "critical" | "high" | "medium" | "low" | "info";
  mitreTechnique?: string;
}

export type DorkCategory =
  | "exposed_panels"
  | "sensitive_files"
  | "directory_listings"
  | "config_files"
  | "database_exposure"
  | "login_pages"
  | "error_messages"
  | "vulnerable_servers"
  | "cloud_exposure"
  | "api_exposure";

export const DORK_TEMPLATES: DorkTemplate[] = [
  // Exposed Panels
  { id: "admin-panel-1", name: "Admin Panel (intitle)", category: "exposed_panels", description: "Finds admin panels via page title", query: 'site:{{domain}} intitle:"admin" OR intitle:"dashboard" OR intitle:"control panel"', severity: "high", mitreTechnique: "T1190" },
  { id: "admin-panel-2", name: "Admin Login Pages", category: "exposed_panels", description: "Finds admin login URLs", query: 'site:{{domain}} inurl:admin OR inurl:login OR inurl:wp-admin OR inurl:administrator', severity: "high", mitreTechnique: "T1190" },
  { id: "phpmyadmin", name: "phpMyAdmin Exposed", category: "exposed_panels", description: "Finds exposed phpMyAdmin instances", query: 'site:{{domain}} inurl:phpmyadmin OR intitle:"phpMyAdmin"', severity: "critical", mitreTechnique: "T1190" },
  { id: "grafana", name: "Grafana Dashboard", category: "exposed_panels", description: "Finds exposed Grafana dashboards", query: 'site:{{domain}} intitle:"Grafana" OR inurl:grafana', severity: "medium", mitreTechnique: "T1190" },
  { id: "jenkins", name: "Jenkins CI", category: "exposed_panels", description: "Finds exposed Jenkins instances", query: 'site:{{domain}} intitle:"Dashboard [Jenkins]" OR inurl:jenkins', severity: "critical", mitreTechnique: "T1190" },

  // Sensitive Files
  { id: "env-files", name: "Environment Files", category: "sensitive_files", description: "Finds exposed .env files with credentials", query: 'site:{{domain}} filetype:env OR inurl:.env "DB_PASSWORD" OR "API_KEY"', severity: "critical", mitreTechnique: "T1552.001" },
  { id: "sql-dumps", name: "SQL Database Dumps", category: "sensitive_files", description: "Finds exposed SQL dump files", query: 'site:{{domain}} filetype:sql "INSERT INTO" OR "CREATE TABLE"', severity: "critical", mitreTechnique: "T1530" },
  { id: "backup-files", name: "Backup Files", category: "sensitive_files", description: "Finds exposed backup archives", query: 'site:{{domain}} filetype:bak OR filetype:old OR filetype:backup', severity: "high", mitreTechnique: "T1530" },
  { id: "private-keys", name: "Private Keys", category: "sensitive_files", description: "Finds exposed private key files", query: 'site:{{domain}} filetype:pem OR filetype:key "PRIVATE KEY"', severity: "critical", mitreTechnique: "T1552.004" },
  { id: "password-files", name: "Password Files", category: "sensitive_files", description: "Finds files containing passwords", query: 'site:{{domain}} filetype:txt OR filetype:log "password" OR "passwd" OR "credentials"', severity: "high", mitreTechnique: "T1552.001" },

  // Directory Listings
  { id: "dir-listing-1", name: "Apache Directory Listing", category: "directory_listings", description: "Finds open Apache directory listings", query: 'site:{{domain}} intitle:"Index of /" OR intitle:"Directory listing for"', severity: "medium", mitreTechnique: "T1083" },
  { id: "dir-listing-2", name: "Parent Directory Links", category: "directory_listings", description: "Finds directory listings with parent links", query: 'site:{{domain}} "parent directory" OR "last modified" "name" "size"', severity: "medium", mitreTechnique: "T1083" },

  // Config Files
  { id: "wp-config", name: "WordPress Config", category: "config_files", description: "Finds exposed WordPress configuration", query: 'site:{{domain}} inurl:wp-config.php OR filetype:php "DB_NAME" "DB_PASSWORD"', severity: "critical", mitreTechnique: "T1552.001" },
  { id: "web-config", name: "Web.config / .htaccess", category: "config_files", description: "Finds exposed web server configs", query: 'site:{{domain}} filetype:xml "web.config" OR filetype:htaccess', severity: "high", mitreTechnique: "T1552.001" },
  { id: "git-exposed", name: "Git Repository Exposed", category: "config_files", description: "Finds exposed .git directories", query: 'site:{{domain}} inurl:.git OR intitle:"Index of /.git"', severity: "critical", mitreTechnique: "T1213.003" },
  { id: "docker-compose", name: "Docker Compose Files", category: "config_files", description: "Finds exposed docker-compose files", query: 'site:{{domain}} filetype:yml "docker-compose" OR inurl:docker-compose.yml', severity: "high", mitreTechnique: "T1552.001" },

  // Database Exposure
  { id: "db-error-mysql", name: "MySQL Errors", category: "database_exposure", description: "Finds MySQL error messages revealing DB info", query: 'site:{{domain}} "mysql_connect" OR "mysql_query" OR "SQL syntax" OR "mysql_fetch"', severity: "medium", mitreTechnique: "T1190" },
  { id: "db-error-pg", name: "PostgreSQL Errors", category: "database_exposure", description: "Finds PostgreSQL error messages", query: 'site:{{domain}} "PostgreSQL" "ERROR" "syntax error" OR "pg_connect"', severity: "medium", mitreTechnique: "T1190" },

  // Login Pages
  { id: "login-forms", name: "Login Forms", category: "login_pages", description: "Finds login pages for credential attacks", query: 'site:{{domain}} inurl:login OR inurl:signin OR intitle:"Sign In" OR intitle:"Log In"', severity: "low", mitreTechnique: "T1078" },
  { id: "forgot-password", name: "Password Reset Pages", category: "login_pages", description: "Finds password reset functionality", query: 'site:{{domain}} inurl:"forgot" OR inurl:"reset" "password"', severity: "info", mitreTechnique: "T1078" },

  // Error Messages
  { id: "stack-traces", name: "Stack Traces", category: "error_messages", description: "Finds exposed stack traces and debug info", query: 'site:{{domain}} "stack trace" OR "traceback" OR "exception" filetype:html OR filetype:php', severity: "medium", mitreTechnique: "T1190" },
  { id: "debug-mode", name: "Debug Mode Enabled", category: "error_messages", description: "Finds apps running in debug mode", query: 'site:{{domain}} "DEBUG = True" OR "debug mode" OR intitle:"Django Debug"', severity: "high", mitreTechnique: "T1190" },

  // Vulnerable Servers
  { id: "iis-default", name: "IIS Default Page", category: "vulnerable_servers", description: "Finds default IIS installation pages", query: 'site:{{domain}} intitle:"IIS Windows Server" OR intitle:"Welcome to IIS"', severity: "low", mitreTechnique: "T1190" },
  { id: "apache-default", name: "Apache Default Page", category: "vulnerable_servers", description: "Finds default Apache installation pages", query: 'site:{{domain}} intitle:"Apache2 Ubuntu Default Page" OR intitle:"Test Page for Apache"', severity: "low", mitreTechnique: "T1190" },
  { id: "tomcat-default", name: "Tomcat Manager", category: "vulnerable_servers", description: "Finds exposed Tomcat manager", query: 'site:{{domain}} intitle:"Apache Tomcat" inurl:manager OR inurl:status', severity: "high", mitreTechnique: "T1190" },

  // Cloud Exposure
  { id: "s3-buckets", name: "S3 Bucket References", category: "cloud_exposure", description: "Finds references to S3 buckets", query: 'site:{{domain}} "s3.amazonaws.com" OR "s3-" ".amazonaws.com"', severity: "medium", mitreTechnique: "T1530" },
  { id: "azure-storage", name: "Azure Storage References", category: "cloud_exposure", description: "Finds references to Azure storage", query: 'site:{{domain}} "blob.core.windows.net" OR "azurewebsites.net"', severity: "medium", mitreTechnique: "T1530" },
  { id: "firebase", name: "Firebase Database", category: "cloud_exposure", description: "Finds references to Firebase databases", query: 'site:{{domain}} "firebaseio.com" OR "firebase.google.com"', severity: "medium", mitreTechnique: "T1530" },

  // API Exposure
  { id: "swagger-ui", name: "Swagger/OpenAPI Docs", category: "api_exposure", description: "Finds exposed API documentation", query: 'site:{{domain}} inurl:swagger OR inurl:api-docs OR intitle:"Swagger UI"', severity: "medium", mitreTechnique: "T1190" },
  { id: "graphql", name: "GraphQL Endpoints", category: "api_exposure", description: "Finds exposed GraphQL endpoints", query: 'site:{{domain}} inurl:graphql OR inurl:graphiql OR intitle:"GraphiQL"', severity: "medium", mitreTechnique: "T1190" },
  { id: "api-keys-exposed", name: "API Keys in URLs", category: "api_exposure", description: "Finds API keys exposed in URLs or pages", query: 'site:{{domain}} "api_key=" OR "apikey=" OR "api-key=" OR "access_token="', severity: "high", mitreTechnique: "T1552.001" },
];

// ─── API Types ───────────────────────────────────────────────────────────────

export interface GoogleSearchResult {
  title: string;
  link: string;
  snippet: string;
  displayLink: string;
  formattedUrl: string;
  pagemap?: {
    metatags?: Array<Record<string, string>>;
  };
}

export interface DorkScanResult {
  dorkTemplate: DorkTemplate;
  query: string;
  results: GoogleSearchResult[];
  totalResults: number;
  searchTime: number;
  timestamp: number;
}

export interface DorkScanSummary {
  domain: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  scannedAt: number;
  categories: Record<DorkCategory, number>;
  results: DorkScanResult[];
}

// ─── Connector Class ─────────────────────────────────────────────────────────

export class GoogleDorkingConnector {
  private apiKey: string;
  private searchEngineId: string;
  private baseUrl = "https://www.googleapis.com/customsearch/v1";

  constructor(apiKey?: string, searchEngineId?: string) {
    this.apiKey = apiKey || process.env.GOOGLE_CSE_API_KEY || "";
    this.searchEngineId = searchEngineId || process.env.GOOGLE_CSE_ID || "";
  }

  isConfigured(): boolean {
    return !!(this.apiKey && this.searchEngineId);
  }

  /**
   * Execute a single Google Custom Search query
   */
  async search(query: string, start = 1, num = 10): Promise<{ results: GoogleSearchResult[]; totalResults: number; searchTime: number }> {
    if (!this.isConfigured()) {
      throw new Error("Google Custom Search API is not configured. Set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID.");
    }

    const params = new URLSearchParams({
      key: this.apiKey,
      cx: this.searchEngineId,
      q: query,
      start: String(start),
      num: String(Math.min(num, 10)), // API max is 10 per request
    });

    const response = await fetch(`${this.baseUrl}?${params.toString()}`);

    if (!response.ok) {
      const errorBody = await response.text();
      if (response.status === 429) {
        throw new Error("Google API rate limit exceeded. Free tier allows 100 queries/day.");
      }
      throw new Error(`Google CSE API error (${response.status}): ${errorBody}`);
    }

    const data = await response.json();

    return {
      results: (data.items || []).map((item: any) => ({
        title: item.title || "",
        link: item.link || "",
        snippet: item.snippet || "",
        displayLink: item.displayLink || "",
        formattedUrl: item.formattedUrl || "",
        pagemap: item.pagemap,
      })),
      totalResults: parseInt(data.searchInformation?.totalResults || "0", 10),
      searchTime: parseFloat(data.searchInformation?.searchTime || "0"),
    };
  }

  /**
   * Execute a single dork template against a domain
   */
  async executeDork(template: DorkTemplate, domain: string): Promise<DorkScanResult> {
    const query = template.query.replace(/\{\{domain\}\}/g, domain);

    try {
      const { results, totalResults, searchTime } = await this.search(query);
      return {
        dorkTemplate: template,
        query,
        results,
        totalResults,
        searchTime,
        timestamp: Date.now(),
      };
    } catch (err: any) {
      // Return empty result on error (rate limit, etc.)
      return {
        dorkTemplate: template,
        query,
        results: [],
        totalResults: 0,
        searchTime: 0,
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Execute a custom dork query (user-defined)
   */
  async executeCustomDork(query: string): Promise<{ results: GoogleSearchResult[]; totalResults: number; searchTime: number }> {
    return this.search(query);
  }

  /**
   * Run a full scan with selected dork categories against a domain
   * Rate-limited to avoid hitting the 100 queries/day free tier limit
   */
  async runScan(domain: string, categories?: DorkCategory[], delayMs = 1000): Promise<DorkScanSummary> {
    const templates = categories
      ? DORK_TEMPLATES.filter((t) => categories.includes(t.category))
      : DORK_TEMPLATES;

    const results: DorkScanResult[] = [];
    const categoryCount: Record<string, number> = {};

    for (const template of templates) {
      const result = await this.executeDork(template, domain);
      if (result.totalResults > 0) {
        results.push(result);
        categoryCount[template.category] = (categoryCount[template.category] || 0) + result.totalResults;
      }

      // Rate limiting between queries
      if (delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }

    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const r of results) {
      severityCounts[r.dorkTemplate.severity] += r.totalResults;
    }

    return {
      domain,
      totalFindings: results.reduce((sum, r) => sum + r.totalResults, 0),
      criticalCount: severityCounts.critical,
      highCount: severityCounts.high,
      mediumCount: severityCounts.medium,
      lowCount: severityCounts.low,
      infoCount: severityCounts.info,
      scannedAt: Date.now(),
      categories: categoryCount as Record<DorkCategory, number>,
      results,
    };
  }

  /**
   * Get available dork templates grouped by category
   */
  getTemplates(category?: DorkCategory): DorkTemplate[] {
    if (category) {
      return DORK_TEMPLATES.filter((t) => t.category === category);
    }
    return DORK_TEMPLATES;
  }

  /**
   * Get category metadata
   */
  getCategories(): Array<{ id: DorkCategory; name: string; count: number; description: string }> {
    const categoryMeta: Record<DorkCategory, { name: string; description: string }> = {
      exposed_panels: { name: "Exposed Admin Panels", description: "Admin dashboards, control panels, and management interfaces" },
      sensitive_files: { name: "Sensitive Files", description: "Environment files, SQL dumps, backups, private keys" },
      directory_listings: { name: "Directory Listings", description: "Open directory indexes exposing file structures" },
      config_files: { name: "Configuration Files", description: "Web configs, .git repos, docker-compose files" },
      database_exposure: { name: "Database Exposure", description: "Database errors and connection strings" },
      login_pages: { name: "Login Pages", description: "Authentication endpoints for credential attacks" },
      error_messages: { name: "Error Messages", description: "Stack traces, debug info, verbose errors" },
      vulnerable_servers: { name: "Vulnerable Servers", description: "Default installations and known vulnerable services" },
      cloud_exposure: { name: "Cloud Exposure", description: "S3 buckets, Azure storage, Firebase databases" },
      api_exposure: { name: "API Exposure", description: "Swagger docs, GraphQL endpoints, exposed API keys" },
    };

    return Object.entries(categoryMeta).map(([id, meta]) => ({
      id: id as DorkCategory,
      name: meta.name,
      count: DORK_TEMPLATES.filter((t) => t.category === id).length,
      description: meta.description,
    }));
  }
}
