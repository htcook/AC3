/**
 * ScanForge Knowledge Base (KB) System
 * 
 * Inspired by OpenVAS Redis-backed KB — provides cross-template state sharing
 * so one template's discoveries feed into another template's checks.
 * 
 * Architecture:
 * - In-memory Map per scan session (no Redis dependency, runs in-process)
 * - Hierarchical key structure: host/port/service/finding
 * - Template dependency resolution: templates declare what KB keys they need
 * - Auto-population from ScanForge discovery/service detection results
 * - Persistence to DB for post-engagement analysis
 */

export interface KBEntry {
  key: string;
  value: string | number | boolean | string[];
  source: string;          // template ID or "scanforge-discovery" or "service-detect"
  timestamp: number;
  confidence: number;      // 0-1
  ttl?: number;            // seconds before expiry (0 = permanent)
}

export interface KBHostContext {
  ip: string;
  hostname?: string;
  os?: string;
  entries: Map<string, KBEntry>;
}

export interface KBQuery {
  key: string;             // exact key or glob pattern (e.g., "ports/*/service")
  host?: string;           // filter by host IP
  source?: string;         // filter by source template
  minConfidence?: number;  // minimum confidence threshold
}

export interface KBDependency {
  requires: string[];      // KB keys this template needs (e.g., ["ports/*/service=http"])
  provides: string[];      // KB keys this template produces
  priority: number;        // execution order (lower = earlier)
}

// Standard KB key prefixes (matching OpenVAS conventions)
export const KB_KEYS = {
  // Host-level
  HOST_ALIVE: "host/alive",
  HOST_OS: "host/os",
  HOST_FQDN: "host/fqdn",
  HOST_MAC: "host/mac",
  
  // Port-level
  PORT_STATE: (port: number, proto: string) => `ports/${proto}/${port}/state`,
  PORT_SERVICE: (port: number, proto: string) => `ports/${proto}/${port}/service`,
  PORT_VERSION: (port: number, proto: string) => `ports/${proto}/${port}/version`,
  PORT_BANNER: (port: number, proto: string) => `ports/${proto}/${port}/banner`,
  PORT_SSL: (port: number, proto: string) => `ports/${proto}/${port}/ssl`,
  
  // Service-level
  SERVICE_HTTP_METHODS: (port: number) => `services/http/${port}/methods`,
  SERVICE_HTTP_SERVER: (port: number) => `services/http/${port}/server`,
  SERVICE_HTTP_TECH: (port: number) => `services/http/${port}/technologies`,
  SERVICE_SSH_VERSION: (port: number) => `services/ssh/${port}/version`,
  SERVICE_SSH_ALGOS: (port: number) => `services/ssh/${port}/algorithms`,
  SERVICE_SMB_SHARES: (port: number) => `services/smb/${port}/shares`,
  SERVICE_SMB_OS: (port: number) => `services/smb/${port}/os`,
  SERVICE_SNMP_COMMUNITY: (port: number) => `services/snmp/${port}/community`,
  SERVICE_SNMP_SYSINFO: (port: number) => `services/snmp/${port}/sysinfo`,
  SERVICE_FTP_BANNER: (port: number) => `services/ftp/${port}/banner`,
  SERVICE_FTP_ANON: (port: number) => `services/ftp/${port}/anonymous`,
  SERVICE_SMTP_BANNER: (port: number) => `services/smtp/${port}/banner`,
  SERVICE_DNS_VERSION: (port: number) => `services/dns/${port}/version`,
  SERVICE_MYSQL_VERSION: (port: number) => `services/mysql/${port}/version`,
  SERVICE_POSTGRES_VERSION: (port: number) => `services/postgres/${port}/version`,
  SERVICE_REDIS_VERSION: (port: number) => `services/redis/${port}/version`,
  SERVICE_MONGO_VERSION: (port: number) => `services/mongo/${port}/version`,
  
  // SSL/TLS
  TLS_CERT_SUBJECT: (port: number) => `tls/${port}/cert/subject`,
  TLS_CERT_ISSUER: (port: number) => `tls/${port}/cert/issuer`,
  TLS_CERT_EXPIRY: (port: number) => `tls/${port}/cert/expiry`,
  TLS_PROTOCOLS: (port: number) => `tls/${port}/protocols`,
  TLS_CIPHERS: (port: number) => `tls/${port}/ciphers`,
  TLS_SELF_SIGNED: (port: number) => `tls/${port}/self_signed`,
  
  // Vulnerability findings (cross-template reference)
  VULN_FOUND: (vulnId: string) => `vulns/${vulnId}/found`,
  VULN_CONFIRMED: (vulnId: string) => `vulns/${vulnId}/confirmed`,
  VULN_CVE: (cve: string) => `vulns/cve/${cve}`,
  
  // Credentials (discovered during scan)
  CRED_FOUND: (service: string, port: number) => `creds/${service}/${port}`,
  CRED_DEFAULT: (service: string, port: number) => `creds/${service}/${port}/default`,
  
  // Web application
  WEB_DIRS: (port: number) => `web/${port}/directories`,
  WEB_FORMS: (port: number) => `web/${port}/forms`,
  WEB_PARAMS: (port: number) => `web/${port}/parameters`,
  WEB_COOKIES: (port: number) => `web/${port}/cookies`,
  WEB_TECH_STACK: (port: number) => `web/${port}/tech_stack`,
  WEB_CMS: (port: number) => `web/${port}/cms`,
  WEB_WAF: (port: number) => `web/${port}/waf`,
} as const;

/**
 * ScanForge Knowledge Base — in-process, per-scan session
 */
export class ScanForgeKB {
  private hosts: Map<string, KBHostContext> = new Map();
  private globalEntries: Map<string, KBEntry> = new Map();
  private templateDeps: Map<string, KBDependency> = new Map();
  private changeListeners: Array<(key: string, entry: KBEntry, host?: string) => void> = [];
  
  constructor(private scanId: string) {}
  
  // ─── Host Management ───────────────────────────────────────────
  
  getOrCreateHost(ip: string): KBHostContext {
    let host = this.hosts.get(ip);
    if (!host) {
      host = { ip, entries: new Map() };
      this.hosts.set(ip, host);
    }
    return host;
  }
  
  getAllHosts(): KBHostContext[] {
    return Array.from(this.hosts.values());
  }
  
  // ─── Set/Get Operations ────────────────────────────────────────
  
  set(key: string, value: KBEntry["value"], source: string, opts?: {
    host?: string;
    confidence?: number;
    ttl?: number;
  }): void {
    const entry: KBEntry = {
      key,
      value,
      source,
      timestamp: Date.now(),
      confidence: opts?.confidence ?? 0.8,
      ttl: opts?.ttl,
    };
    
    if (opts?.host) {
      const hostCtx = this.getOrCreateHost(opts.host);
      hostCtx.entries.set(key, entry);
    } else {
      this.globalEntries.set(key, entry);
    }
    
    // Notify listeners
    for (const listener of this.changeListeners) {
      try { listener(key, entry, opts?.host); } catch {}
    }
  }
  
  get(key: string, host?: string): KBEntry | undefined {
    if (host) {
      const hostCtx = this.hosts.get(host);
      if (hostCtx) {
        const entry = hostCtx.entries.get(key);
        if (entry && !this.isExpired(entry)) return entry;
      }
    }
    const global = this.globalEntries.get(key);
    if (global && !this.isExpired(global)) return global;
    return undefined;
  }
  
  getValue(key: string, host?: string): KBEntry["value"] | undefined {
    return this.get(key, host)?.value;
  }
  
  /**
   * Query KB with glob pattern matching
   * Supports * wildcard in key patterns
   */
  query(q: KBQuery): KBEntry[] {
    const results: KBEntry[] = [];
    const regex = this.globToRegex(q.key);
    
    const checkEntry = (entry: KBEntry) => {
      if (this.isExpired(entry)) return;
      if (!regex.test(entry.key)) return;
      if (q.source && entry.source !== q.source) return;
      if (q.minConfidence && entry.confidence < q.minConfidence) return;
      results.push(entry);
    };
    
    if (q.host) {
      const hostCtx = this.hosts.get(q.host);
      if (hostCtx) {
        for (const entry of hostCtx.entries.values()) checkEntry(entry);
      }
    } else {
      // Search all hosts + global
      for (const hostCtx of this.hosts.values()) {
        for (const entry of hostCtx.entries.values()) checkEntry(entry);
      }
      for (const entry of this.globalEntries.values()) checkEntry(entry);
    }
    
    return results;
  }
  
  /**
   * Check if a KB key exists (for dependency resolution)
   */
  has(key: string, host?: string): boolean {
    return this.get(key, host) !== undefined;
  }
  
  /**
   * Get all entries matching a service type on a specific host
   */
  getServicePorts(host: string, service: string): number[] {
    const ports: number[] = [];
    const hostCtx = this.hosts.get(host);
    if (!hostCtx) return ports;
    
    const pattern = new RegExp(`^ports/(tcp|udp)/(\\d+)/service$`);
    for (const [key, entry] of hostCtx.entries) {
      const match = key.match(pattern);
      if (match && entry.value === service) {
        ports.push(parseInt(match[2], 10));
      }
    }
    return ports;
  }
  
  /**
   * Get all open ports for a host
   */
  getOpenPorts(host: string, proto: string = "tcp"): number[] {
    const ports: number[] = [];
    const hostCtx = this.hosts.get(host);
    if (!hostCtx) return ports;
    
    const pattern = new RegExp(`^ports/${proto}/(\\d+)/state$`);
    for (const [key, entry] of hostCtx.entries) {
      const match = key.match(pattern);
      if (match && entry.value === "open") {
        ports.push(parseInt(match[1], 10));
      }
    }
    return ports.sort((a, b) => a - b);
  }
  
  // ─── Nmap Result Ingestion ─────────────────────────────────────
  
  /**
   * Populate KB from ScanForge discovery scan results
   * This is the primary way to seed the KB before template execution
   */
  ingestDiscoveryResults(host: string, discoveryData: {
    ports: Array<{
      port: number;
      proto: string;
      state: string;
      service?: string;
      version?: string;
      banner?: string;
    }>;
    os?: string;
    hostname?: string;
    mac?: string;
  }): void {
    const source = "scanforge-discovery";
    
    this.set(KB_KEYS.HOST_ALIVE, true, source, { host, confidence: 1.0 });
    if (discoveryData.os) this.set(KB_KEYS.HOST_OS, discoveryData.os, source, { host, confidence: 0.7 });
    if (discoveryData.hostname) this.set(KB_KEYS.HOST_FQDN, discoveryData.hostname, source, { host, confidence: 0.9 });
    if (discoveryData.mac) this.set(KB_KEYS.HOST_MAC, discoveryData.mac, source, { host, confidence: 1.0 });
    
    for (const p of discoveryData.ports) {
      this.set(KB_KEYS.PORT_STATE(p.port, p.proto), p.state, source, { host, confidence: 1.0 });
      if (p.service) {
        this.set(KB_KEYS.PORT_SERVICE(p.port, p.proto), p.service, source, { host, confidence: 0.85 });
      }
      if (p.version) {
        this.set(KB_KEYS.PORT_VERSION(p.port, p.proto), p.version, source, { host, confidence: 0.8 });
      }
      if (p.banner) {
        this.set(KB_KEYS.PORT_BANNER(p.port, p.proto), p.banner, source, { host, confidence: 1.0 });
      }
    }
  }
  
  // ─── Template Dependency Resolution ────────────────────────────
  
  registerTemplateDeps(templateId: string, deps: KBDependency): void {
    this.templateDeps.set(templateId, deps);
  }
  
  /**
   * Resolve template execution order based on KB dependencies
   * Returns templates sorted by dependency order
   */
  resolveExecutionOrder(templateIds: string[]): string[] {
    const resolved: string[] = [];
    const unresolved = new Set(templateIds);
    const providedKeys = new Set<string>();
    
    // First pass: templates with no requirements
    for (const id of templateIds) {
      const deps = this.templateDeps.get(id);
      if (!deps || deps.requires.length === 0) {
        resolved.push(id);
        unresolved.delete(id);
        if (deps) {
          for (const key of deps.provides) providedKeys.add(key);
        }
      }
    }
    
    // Iterative resolution
    let maxIterations = templateIds.length;
    while (unresolved.size > 0 && maxIterations-- > 0) {
      for (const id of [...unresolved]) {
        const deps = this.templateDeps.get(id);
        if (!deps) {
          resolved.push(id);
          unresolved.delete(id);
          continue;
        }
        
        // Check if all requirements are satisfied
        const satisfied = deps.requires.every(req => {
          // Check if any provided key matches the requirement pattern
          const regex = this.globToRegex(req);
          for (const provided of providedKeys) {
            if (regex.test(provided)) return true;
          }
          // Also check existing KB entries
          return this.query({ key: req }).length > 0;
        });
        
        if (satisfied) {
          resolved.push(id);
          unresolved.delete(id);
          for (const key of deps.provides) providedKeys.add(key);
        }
      }
    }
    
    // Add any remaining unresolved templates at the end
    for (const id of unresolved) {
      resolved.push(id);
    }
    
    // Sort by priority within dependency groups
    return resolved.sort((a, b) => {
      const aDeps = this.templateDeps.get(a);
      const bDeps = this.templateDeps.get(b);
      const aPriority = aDeps?.priority ?? 50;
      const bPriority = bDeps?.priority ?? 50;
      return aPriority - bPriority;
    });
  }
  
  /**
   * Check if a template's dependencies are satisfied
   */
  canExecuteTemplate(templateId: string, host: string): boolean {
    const deps = this.templateDeps.get(templateId);
    if (!deps || deps.requires.length === 0) return true;
    
    return deps.requires.every(req => {
      return this.query({ key: req, host }).length > 0;
    });
  }
  
  // ─── Change Listeners ─────────────────────────────────────────
  
  onChange(listener: (key: string, entry: KBEntry, host?: string) => void): () => void {
    this.changeListeners.push(listener);
    return () => {
      const idx = this.changeListeners.indexOf(listener);
      if (idx >= 0) this.changeListeners.splice(idx, 1);
    };
  }
  
  // ─── Serialization ────────────────────────────────────────────
  
  /**
   * Export KB to JSON for persistence/analysis
   */
  toJSON(): Record<string, unknown> {
    const hostData: Record<string, Record<string, unknown>> = {};
    for (const [ip, ctx] of this.hosts) {
      const entries: Record<string, unknown> = {};
      for (const [key, entry] of ctx.entries) {
        if (!this.isExpired(entry)) {
          entries[key] = { value: entry.value, source: entry.source, confidence: entry.confidence };
        }
      }
      hostData[ip] = { hostname: ctx.hostname, os: ctx.os, entries };
    }
    
    const globalData: Record<string, unknown> = {};
    for (const [key, entry] of this.globalEntries) {
      if (!this.isExpired(entry)) {
        globalData[key] = { value: entry.value, source: entry.source, confidence: entry.confidence };
      }
    }
    
    return { scanId: this.scanId, hosts: hostData, global: globalData };
  }
  
  /**
   * Get KB statistics
   */
  getStats(): {
    hostCount: number;
    totalEntries: number;
    entriesBySource: Record<string, number>;
    openPortCount: number;
    serviceCount: number;
  } {
    let totalEntries = this.globalEntries.size;
    let openPortCount = 0;
    let serviceCount = 0;
    const entriesBySource: Record<string, number> = {};
    
    for (const ctx of this.hosts.values()) {
      totalEntries += ctx.entries.size;
      for (const entry of ctx.entries.values()) {
        entriesBySource[entry.source] = (entriesBySource[entry.source] || 0) + 1;
        if (entry.key.endsWith("/state") && entry.value === "open") openPortCount++;
        if (entry.key.endsWith("/service")) serviceCount++;
      }
    }
    
    for (const entry of this.globalEntries.values()) {
      entriesBySource[entry.source] = (entriesBySource[entry.source] || 0) + 1;
    }
    
    return {
      hostCount: this.hosts.size,
      totalEntries,
      entriesBySource,
      openPortCount,
      serviceCount,
    };
  }
  
  // ─── Internal Helpers ─────────────────────────────────────────
  
  private isExpired(entry: KBEntry): boolean {
    if (!entry.ttl || entry.ttl <= 0) return false;
    return Date.now() - entry.timestamp > entry.ttl * 1000;
  }
  
  private globToRegex(pattern: string): RegExp {
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    const withWildcards = escaped.replace(/\*/g, ".*");
    return new RegExp(`^${withWildcards}$`);
  }
}

/**
 * KB-aware template wrapper
 * Enhances template execution with KB reads/writes
 */
export interface KBAwareTemplate {
  id: string;
  dependencies: KBDependency;
  
  /** Called before execution to check if template should run */
  shouldRun(kb: ScanForgeKB, host: string): boolean;
  
  /** Called after execution to store results in KB */
  onComplete(kb: ScanForgeKB, host: string, findings: unknown[]): void;
}

/**
 * Factory: create a KB instance pre-populated from engagement ScanForge data
 */
export function createKBFromEngagement(
  scanId: string,
  assets: Array<{
    ip: string;
    hostname?: string;
    openPorts?: Array<{ port: number; service?: string; version?: string; banner?: string }>;
    os?: string;
  }>
): ScanForgeKB {
  const kb = new ScanForgeKB(scanId);
  
  for (const asset of assets) {
    kb.ingestDiscoveryResults(asset.ip, {
      ports: (asset.openPorts || []).map(p => ({
        port: p.port,
        proto: "tcp",
        state: "open",
        service: p.service,
        version: p.version,
        banner: p.banner,
      })),
      os: asset.os,
      hostname: asset.hostname,
    });
  }
  
  return kb;
}
