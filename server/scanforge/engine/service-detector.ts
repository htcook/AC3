/**
 * ScanForge Service Detection Engine
 * 
 * Inspired by OpenVAS nasl_builtin_find_service.c — provides native
 * service fingerprinting using banner grabbing and protocol probes.
 * 
 * Features:
 * - Banner grabbing on all open ports
 * - Protocol-specific probes (HTTP, FTP, SMTP, POP3, IMAP, SSH, etc.)
 * - SSL/TLS service detection and certificate extraction
 * - Version extraction from banners using regex patterns
 * - Technology stack fingerprinting for web services
 * - Populates KB with service information for downstream templates
 */

import { ScanForgeKB, KB_KEYS } from "./knowledge-base";

export interface ServiceProbe {
  name: string;
  protocol: "tcp" | "udp";
  defaultPorts: number[];
  /** Bytes to send to trigger a response (null = just connect and read) */
  probeBanner: string | null;
  /** Regex patterns to match response and extract service + version */
  matchers: Array<{
    pattern: RegExp;
    service: string;
    versionGroup?: number;
    infoGroup?: number;
  }>;
  /** Timeout in ms for this probe */
  timeout: number;
  /** Whether to attempt SSL/TLS wrapping */
  trySSL: boolean;
}

export interface ServiceResult {
  host: string;
  port: number;
  proto: string;
  service: string;
  version?: string;
  banner?: string;
  ssl: boolean;
  confidence: number;
  extraInfo?: Record<string, string>;
}

export interface TLSInfo {
  host: string;
  port: number;
  protocols: string[];
  ciphers: string[];
  certSubject?: string;
  certIssuer?: string;
  certExpiry?: string;
  selfSigned: boolean;
}

// ─── Protocol Probes ─────────────────────────────────────────────

const SERVICE_PROBES: ServiceProbe[] = [
  // NULL probe — just connect and read banner
  {
    name: "null-banner",
    protocol: "tcp",
    defaultPorts: [],
    probeBanner: null,
    matchers: [
      { pattern: /^SSH-(\d+\.\d+)-(.+)/i, service: "ssh", versionGroup: 2 },
      { pattern: /^220[- ].*FTP/i, service: "ftp" },
      { pattern: /^220[- ].*SMTP/i, service: "smtp" },
      { pattern: /^220[- ].*Microsoft ESMTP/i, service: "smtp" },
      { pattern: /^\+OK.*POP3/i, service: "pop3" },
      { pattern: /^\* OK.*IMAP/i, service: "imap" },
      { pattern: /^MySQL/i, service: "mysql" },
      { pattern: /^\{".*":/i, service: "http-api" },
      { pattern: /^RFB (\d+\.\d+)/i, service: "vnc", versionGroup: 1 },
      { pattern: /^-ERR.*Redis/i, service: "redis" },
      { pattern: /^AMQP/i, service: "amqp" },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // HTTP probe
  {
    name: "http-get",
    protocol: "tcp",
    defaultPorts: [80, 8080, 8000, 8443, 8888, 3000, 5000, 9090],
    probeBanner: "GET / HTTP/1.1\r\nHost: {{HOST}}\r\nUser-Agent: ScanForge/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    matchers: [
      { pattern: /^HTTP\/(\d+\.\d+)\s+(\d+).*\r\nServer:\s*(.+)/im, service: "http", versionGroup: 3 },
      { pattern: /^HTTP\/(\d+\.\d+)\s+(\d+)/im, service: "http" },
      { pattern: /X-Powered-By:\s*(.+)/im, service: "http", infoGroup: 1 },
    ],
    timeout: 10000,
    trySSL: false,
  },
  
  // HTTPS probe (SSL-wrapped HTTP)
  {
    name: "https-get",
    protocol: "tcp",
    defaultPorts: [443, 8443, 4443, 9443],
    probeBanner: "GET / HTTP/1.1\r\nHost: {{HOST}}\r\nUser-Agent: ScanForge/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
    matchers: [
      { pattern: /^HTTP\/(\d+\.\d+)\s+(\d+).*\r\nServer:\s*(.+)/im, service: "https", versionGroup: 3 },
      { pattern: /^HTTP\/(\d+\.\d+)\s+(\d+)/im, service: "https" },
    ],
    timeout: 10000,
    trySSL: true,
  },
  
  // FTP probe
  {
    name: "ftp-banner",
    protocol: "tcp",
    defaultPorts: [21, 2121],
    probeBanner: null,
    matchers: [
      { pattern: /^220[- ].*\((.+)\)/i, service: "ftp", versionGroup: 1 },
      { pattern: /^220[- ](.+)/i, service: "ftp", versionGroup: 1 },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // SMTP probe
  {
    name: "smtp-ehlo",
    protocol: "tcp",
    defaultPorts: [25, 587, 465, 2525],
    probeBanner: "EHLO scanforge.local\r\n",
    matchers: [
      { pattern: /^220[- ].*\s(.+)\s/i, service: "smtp", versionGroup: 1 },
      { pattern: /^250[- ](.+)/im, service: "smtp" },
    ],
    timeout: 10000,
    trySSL: false,
  },
  
  // MySQL probe
  {
    name: "mysql-handshake",
    protocol: "tcp",
    defaultPorts: [3306, 3307],
    probeBanner: null,
    matchers: [
      { pattern: /(\d+\.\d+\.\d+[-\w]*)/i, service: "mysql", versionGroup: 1 },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // PostgreSQL probe
  {
    name: "postgres-startup",
    protocol: "tcp",
    defaultPorts: [5432, 5433],
    probeBanner: null,
    matchers: [
      { pattern: /PostgreSQL/i, service: "postgresql" },
      { pattern: /FATAL/i, service: "postgresql" },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // Redis probe
  {
    name: "redis-ping",
    protocol: "tcp",
    defaultPorts: [6379, 6380],
    probeBanner: "PING\r\n",
    matchers: [
      { pattern: /^\+PONG/i, service: "redis" },
      { pattern: /^-NOAUTH/i, service: "redis" },
      { pattern: /^-ERR.*redis/i, service: "redis" },
    ],
    timeout: 3000,
    trySSL: false,
  },
  
  // MongoDB probe
  {
    name: "mongodb-ismaster",
    protocol: "tcp",
    defaultPorts: [27017, 27018],
    probeBanner: null,
    matchers: [
      { pattern: /ismaster|mongodb/i, service: "mongodb" },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // SNMP probe (UDP)
  {
    name: "snmp-getrequest",
    protocol: "udp",
    defaultPorts: [161, 162],
    probeBanner: null, // SNMP uses binary protocol, handled separately
    matchers: [
      { pattern: /.*/, service: "snmp" },
    ],
    timeout: 3000,
    trySSL: false,
  },
  
  // DNS probe (UDP)
  {
    name: "dns-version",
    protocol: "udp",
    defaultPorts: [53],
    probeBanner: null, // DNS uses binary protocol, handled separately
    matchers: [
      { pattern: /.*/, service: "dns" },
    ],
    timeout: 3000,
    trySSL: false,
  },
  
  // RDP probe
  {
    name: "rdp-cookie",
    protocol: "tcp",
    defaultPorts: [3389],
    probeBanner: null,
    matchers: [
      { pattern: /^\x03\x00/i, service: "rdp" },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // LDAP probe
  {
    name: "ldap-search",
    protocol: "tcp",
    defaultPorts: [389, 636],
    probeBanner: null,
    matchers: [
      { pattern: /objectClass|namingContexts/i, service: "ldap" },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // Elasticsearch probe
  {
    name: "elasticsearch-root",
    protocol: "tcp",
    defaultPorts: [9200, 9300],
    probeBanner: "GET / HTTP/1.0\r\n\r\n",
    matchers: [
      { pattern: /"cluster_name"|"tagline"\s*:\s*"You Know, for Search"/i, service: "elasticsearch" },
      { pattern: /"version".*"number"\s*:\s*"(\d+\.\d+\.\d+)"/i, service: "elasticsearch", versionGroup: 1 },
    ],
    timeout: 5000,
    trySSL: false,
  },
  
  // RabbitMQ AMQP probe
  {
    name: "amqp-header",
    protocol: "tcp",
    defaultPorts: [5672, 5671],
    probeBanner: "AMQP\x00\x00\x09\x01",
    matchers: [
      { pattern: /AMQP/i, service: "amqp" },
      { pattern: /RabbitMQ/i, service: "rabbitmq" },
    ],
    timeout: 5000,
    trySSL: false,
  },
];

// ─── HTTP Technology Fingerprints ────────────────────────────────

interface TechFingerprint {
  name: string;
  category: "server" | "framework" | "cms" | "waf" | "language" | "cdn" | "cache";
  headerPatterns?: Array<{ header: string; pattern: RegExp }>;
  bodyPatterns?: RegExp[];
  cookiePatterns?: RegExp[];
}

const TECH_FINGERPRINTS: TechFingerprint[] = [
  // Servers
  { name: "nginx", category: "server", headerPatterns: [{ header: "server", pattern: /nginx/i }] },
  { name: "Apache", category: "server", headerPatterns: [{ header: "server", pattern: /apache/i }] },
  { name: "IIS", category: "server", headerPatterns: [{ header: "server", pattern: /microsoft-iis/i }] },
  { name: "LiteSpeed", category: "server", headerPatterns: [{ header: "server", pattern: /litespeed/i }] },
  { name: "Caddy", category: "server", headerPatterns: [{ header: "server", pattern: /caddy/i }] },
  
  // Frameworks
  { name: "Express", category: "framework", headerPatterns: [{ header: "x-powered-by", pattern: /express/i }] },
  { name: "Django", category: "framework", headerPatterns: [{ header: "x-frame-options", pattern: /DENY/i }], cookiePatterns: [/csrftoken/i] },
  { name: "Rails", category: "framework", headerPatterns: [{ header: "x-powered-by", pattern: /phusion/i }], cookiePatterns: [/_session/i] },
  { name: "ASP.NET", category: "framework", headerPatterns: [{ header: "x-powered-by", pattern: /asp\.net/i }, { header: "x-aspnet-version", pattern: /.+/ }] },
  { name: "Spring", category: "framework", cookiePatterns: [/JSESSIONID/i] },
  { name: "Laravel", category: "framework", cookiePatterns: [/laravel_session/i] },
  { name: "Flask", category: "framework", headerPatterns: [{ header: "server", pattern: /werkzeug/i }] },
  
  // CMS
  { name: "WordPress", category: "cms", bodyPatterns: [/wp-content/i, /wp-includes/i, /wp-json/i] },
  { name: "Drupal", category: "cms", headerPatterns: [{ header: "x-generator", pattern: /drupal/i }], bodyPatterns: [/sites\/default\/files/i] },
  { name: "Joomla", category: "cms", bodyPatterns: [/\/media\/jui\//i, /Joomla!/i] },
  
  // WAF
  { name: "Cloudflare", category: "waf", headerPatterns: [{ header: "server", pattern: /cloudflare/i }, { header: "cf-ray", pattern: /.+/ }] },
  { name: "AWS WAF", category: "waf", headerPatterns: [{ header: "x-amzn-requestid", pattern: /.+/ }] },
  { name: "Akamai", category: "waf", headerPatterns: [{ header: "x-akamai-transformed", pattern: /.+/ }] },
  { name: "ModSecurity", category: "waf", headerPatterns: [{ header: "server", pattern: /mod_security/i }] },
  
  // Languages
  { name: "PHP", category: "language", headerPatterns: [{ header: "x-powered-by", pattern: /php/i }], cookiePatterns: [/PHPSESSID/i] },
  { name: "Java", category: "language", cookiePatterns: [/JSESSIONID/i] },
  { name: "Python", category: "language", headerPatterns: [{ header: "server", pattern: /python|werkzeug|gunicorn|uvicorn/i }] },
  
  // CDN/Cache
  { name: "Varnish", category: "cache", headerPatterns: [{ header: "via", pattern: /varnish/i }, { header: "x-varnish", pattern: /.+/ }] },
  { name: "Fastly", category: "cdn", headerPatterns: [{ header: "x-served-by", pattern: /cache-/i }] },
];

// ─── Service Detection Engine ────────────────────────────────────

export class ServiceDetector {
  private probes: ServiceProbe[] = SERVICE_PROBES;
  private techFingerprints: TechFingerprint[] = TECH_FINGERPRINTS;
  
  /**
   * Detect services on all open ports for a host
   * Populates the KB with service information
   */
  async detectServices(
    host: string,
    openPorts: Array<{ port: number; proto: string }>,
    kb: ScanForgeKB,
    opts?: {
      timeout?: number;
      maxConcurrent?: number;
      executorFn?: (host: string, port: number, probe: string, ssl: boolean, timeout: number) => Promise<string | null>;
    }
  ): Promise<ServiceResult[]> {
    const results: ServiceResult[] = [];
    const executor = opts?.executorFn || this.defaultExecutor.bind(this);
    const maxConcurrent = opts?.maxConcurrent ?? 10;
    
    // Group ports into batches for concurrent execution
    const batches: Array<{ port: number; proto: string }>[] = [];
    for (let i = 0; i < openPorts.length; i += maxConcurrent) {
      batches.push(openPorts.slice(i, i + maxConcurrent));
    }
    
    for (const batch of batches) {
      const batchPromises = batch.map(async ({ port, proto }) => {
        const result = await this.detectServiceOnPort(host, port, proto, kb, executor, opts?.timeout);
        if (result) {
          results.push(result);
          this.populateKB(kb, result);
        }
      });
      
      await Promise.all(batchPromises);
    }
    
    return results;
  }
  
  /**
   * Detect service on a single port by trying probes in order
   */
  private async detectServiceOnPort(
    host: string,
    port: number,
    proto: string,
    kb: ScanForgeKB,
    executor: (host: string, port: number, probe: string, ssl: boolean, timeout: number) => Promise<string | null>,
    timeout?: number
  ): Promise<ServiceResult | null> {
    // Find applicable probes for this port
    const applicableProbes = this.probes.filter(p => {
      if (p.protocol !== proto) return false;
      // Always try null banner probe + probes that list this port
      return p.probeBanner === null || p.defaultPorts.includes(port) || p.defaultPorts.length === 0;
    });
    
    for (const probe of applicableProbes) {
      try {
        const probeStr = probe.probeBanner?.replace("{{HOST}}", host) || "";
        const banner = await executor(host, port, probeStr, probe.trySSL, timeout || probe.timeout);
        
        if (!banner) continue;
        
        for (const matcher of probe.matchers) {
          const match = banner.match(matcher.pattern);
          if (match) {
            return {
              host,
              port,
              proto,
              service: matcher.service,
              version: matcher.versionGroup ? match[matcher.versionGroup] : undefined,
              banner: banner.substring(0, 512),
              ssl: probe.trySSL,
              confidence: 0.9,
              extraInfo: matcher.infoGroup ? { info: match[matcher.infoGroup] } : undefined,
            };
          }
        }
      } catch {
        // Probe failed, try next
        continue;
      }
    }
    
    // Fallback: port-based guess
    return this.guessServiceByPort(host, port, proto);
  }
  
  /**
   * Fingerprint HTTP technologies from response headers and body
   */
  fingerprintHTTP(
    headers: Record<string, string>,
    body: string,
    cookies: string[]
  ): Array<{ name: string; category: string; confidence: number }> {
    const detected: Array<{ name: string; category: string; confidence: number }> = [];
    
    for (const fp of this.techFingerprints) {
      let matched = false;
      let confidence = 0.7;
      
      // Check headers
      if (fp.headerPatterns) {
        for (const hp of fp.headerPatterns) {
          const headerValue = headers[hp.header.toLowerCase()];
          if (headerValue && hp.pattern.test(headerValue)) {
            matched = true;
            confidence = 0.95;
            break;
          }
        }
      }
      
      // Check body patterns
      if (!matched && fp.bodyPatterns) {
        for (const bp of fp.bodyPatterns) {
          if (bp.test(body)) {
            matched = true;
            confidence = 0.8;
            break;
          }
        }
      }
      
      // Check cookie patterns
      if (!matched && fp.cookiePatterns) {
        for (const cp of fp.cookiePatterns) {
          if (cookies.some(c => cp.test(c))) {
            matched = true;
            confidence = 0.85;
            break;
          }
        }
      }
      
      if (matched) {
        detected.push({ name: fp.name, category: fp.category, confidence });
      }
    }
    
    return detected;
  }
  
  /**
   * Populate KB with detected service information
   */
  private populateKB(kb: ScanForgeKB, result: ServiceResult): void {
    const source = "service-detect";
    
    kb.set(
      KB_KEYS.PORT_SERVICE(result.port, result.proto),
      result.service,
      source,
      { host: result.host, confidence: result.confidence }
    );
    
    if (result.version) {
      kb.set(
        KB_KEYS.PORT_VERSION(result.port, result.proto),
        result.version,
        source,
        { host: result.host, confidence: result.confidence }
      );
    }
    
    if (result.banner) {
      kb.set(
        KB_KEYS.PORT_BANNER(result.port, result.proto),
        result.banner,
        source,
        { host: result.host, confidence: 1.0 }
      );
    }
    
    if (result.ssl) {
      kb.set(
        KB_KEYS.PORT_SSL(result.port, result.proto),
        true,
        source,
        { host: result.host, confidence: 1.0 }
      );
    }
  }
  
  /**
   * Fallback: guess service by well-known port number
   */
  private guessServiceByPort(host: string, port: number, proto: string): ServiceResult | null {
    const portMap: Record<number, string> = {
      21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
      80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
      139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
      443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
      587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s",
      1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
      3389: "rdp", 5432: "postgresql", 5672: "amqp", 5900: "vnc",
      6379: "redis", 8080: "http-proxy", 8443: "https-alt",
      9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
      27017: "mongodb",
    };
    
    const service = portMap[port];
    if (service) {
      return {
        host, port, proto, service,
        banner: undefined,
        ssl: [443, 465, 636, 993, 995, 8443, 9443].includes(port),
        confidence: 0.5, // Low confidence — just a guess
      };
    }
    
    return null;
  }
  
  /**
   * Default executor — placeholder for actual network I/O
   * In production, this would use the scan-server-executor SSH bridge
   */
  private async defaultExecutor(
    _host: string,
    _port: number,
    _probe: string,
    _ssl: boolean,
    _timeout: number
  ): Promise<string | null> {
    // This is a placeholder — actual implementation uses scan-server-executor
    // to run banner grabbing commands via SSH on the scan server
    return null;
  }
}

/**
 * Build scan-server commands for service detection
 * These are executed via the existing scan-server-executor SSH bridge
 */
export function buildServiceDetectionCommands(host: string, ports: number[]): string[] {
  const commands: string[] = [];
  
  for (const port of ports) {
    // Banner grab with timeout
    commands.push(
      `timeout 5 bash -c 'echo "" | nc -w 3 ${host} ${port} 2>/dev/null' | head -c 512 | base64 -w0 || echo "NOBANNER"`
    );
  }
  
  // SSL certificate extraction for common HTTPS ports
  const sslPorts = ports.filter(p => [443, 8443, 4443, 9443, 465, 636, 993, 995].includes(p));
  for (const port of sslPorts) {
    commands.push(
      `echo | timeout 5 openssl s_client -connect ${host}:${port} -servername ${host} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "NOSSL"`
    );
  }
  
  // HTTP technology fingerprinting
  const httpPorts = ports.filter(p => [80, 8080, 8000, 8888, 3000, 5000, 9090].includes(p));
  for (const port of httpPorts) {
    commands.push(
      `curl -sI -m 5 http://${host}:${port}/ 2>/dev/null | head -30 || echo "NOHTTP"`
    );
  }
  
  const httpsPorts = ports.filter(p => [443, 8443, 4443, 9443].includes(p));
  for (const port of httpsPorts) {
    commands.push(
      `curl -skI -m 5 https://${host}:${port}/ 2>/dev/null | head -30 || echo "NOHTTPS"`
    );
  }
  
  return commands;
}
