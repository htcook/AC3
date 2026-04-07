/**
 * service-resolver.ts — Resolves "unknown" service labels on open ports
 *
 * Three-tier resolution:
 *   1. Active fingerprint (nmap/httpx banner grab) — highest confidence
 *   2. Passive recon merge (Shodan/Censys service data) — medium confidence
 *   3. Well-known port→service mapping (IANA + common) — fallback
 *
 * Each resolved service includes a `source` field so the UI can show
 * how the service was identified (fingerprinted / passive / inferred).
 */

// ─── Well-Known Port → Service Map ──────────────────────────────────────────
// Covers IANA assigned ports + common non-standard ports seen in pentests

export const WELL_KNOWN_PORTS: Record<number, { service: string; product?: string; protocol?: string }> = {
  // SSH / Remote Access
  21: { service: 'ftp', product: 'FTP' },
  22: { service: 'ssh', product: 'SSH' },
  23: { service: 'telnet', product: 'Telnet' },
  2222: { service: 'ssh', product: 'SSH (alt)' },
  3389: { service: 'rdp', product: 'RDP' },
  5900: { service: 'vnc', product: 'VNC' },
  5901: { service: 'vnc', product: 'VNC' },

  // Web
  80: { service: 'http', product: 'HTTP' },
  443: { service: 'https', product: 'HTTPS' },
  8080: { service: 'http-proxy', product: 'HTTP Proxy' },
  8443: { service: 'https-alt', product: 'HTTPS (alt)' },
  8000: { service: 'http-alt', product: 'HTTP (alt)' },
  8888: { service: 'http-alt', product: 'HTTP (alt)' },
  8090: { service: 'http-alt', product: 'HTTP (alt)' },
  3000: { service: 'http-alt', product: 'HTTP (Node/dev)' },
  3001: { service: 'http-alt', product: 'HTTP (dev)' },
  4000: { service: 'http-alt', product: 'HTTP (app)' },
  4443: { service: 'https-alt', product: 'HTTPS (alt)' },
  5000: { service: 'http-alt', product: 'HTTP (Flask/dev)' },
  9000: { service: 'http-alt', product: 'HTTP (PHP-FPM/SonarQube)' },
  9090: { service: 'http-alt', product: 'HTTP (Prometheus/Cockpit)' },
  9443: { service: 'https-alt', product: 'HTTPS (alt)' },

  // Mail
  25: { service: 'smtp', product: 'SMTP' },
  110: { service: 'pop3', product: 'POP3' },
  143: { service: 'imap', product: 'IMAP' },
  465: { service: 'smtps', product: 'SMTPS' },
  587: { service: 'submission', product: 'SMTP Submission' },
  993: { service: 'imaps', product: 'IMAPS' },
  995: { service: 'pop3s', product: 'POP3S' },

  // DNS
  53: { service: 'dns', product: 'DNS', protocol: 'tcp/udp' },

  // Database
  1433: { service: 'mssql', product: 'Microsoft SQL Server' },
  1521: { service: 'oracle', product: 'Oracle DB' },
  3306: { service: 'mysql', product: 'MySQL/MariaDB' },
  5432: { service: 'postgresql', product: 'PostgreSQL' },
  6379: { service: 'redis', product: 'Redis' },
  27017: { service: 'mongodb', product: 'MongoDB' },
  9200: { service: 'elasticsearch', product: 'Elasticsearch' },
  9300: { service: 'elasticsearch', product: 'Elasticsearch (transport)' },
  5984: { service: 'couchdb', product: 'CouchDB' },
  8529: { service: 'arangodb', product: 'ArangoDB' },
  7474: { service: 'neo4j', product: 'Neo4j' },

  // Message Queues / Caches
  5672: { service: 'amqp', product: 'RabbitMQ' },
  15672: { service: 'http-alt', product: 'RabbitMQ Management' },
  6380: { service: 'redis', product: 'Redis (alt)' },
  11211: { service: 'memcached', product: 'Memcached' },
  9092: { service: 'kafka', product: 'Apache Kafka' },
  2181: { service: 'zookeeper', product: 'ZooKeeper' },

  // LDAP / Directory
  389: { service: 'ldap', product: 'LDAP' },
  636: { service: 'ldaps', product: 'LDAPS' },
  88: { service: 'kerberos', product: 'Kerberos' },
  464: { service: 'kpasswd', product: 'Kerberos Password' },

  // SMB / File Sharing
  135: { service: 'msrpc', product: 'MS-RPC' },
  137: { service: 'netbios-ns', product: 'NetBIOS Name Service', protocol: 'udp' },
  138: { service: 'netbios-dgm', product: 'NetBIOS Datagram', protocol: 'udp' },
  139: { service: 'netbios-ssn', product: 'NetBIOS Session' },
  445: { service: 'smb', product: 'SMB/CIFS' },
  2049: { service: 'nfs', product: 'NFS' },

  // Monitoring / Management
  161: { service: 'snmp', product: 'SNMP', protocol: 'udp' },
  162: { service: 'snmp-trap', product: 'SNMP Trap', protocol: 'udp' },
  514: { service: 'syslog', product: 'Syslog' },
  10050: { service: 'zabbix-agent', product: 'Zabbix Agent' },
  10051: { service: 'zabbix-server', product: 'Zabbix Server' },

  // Docker / Container
  2375: { service: 'docker', product: 'Docker API (unencrypted)' },
  2376: { service: 'docker-tls', product: 'Docker API (TLS)' },
  6443: { service: 'kubernetes', product: 'Kubernetes API' },
  10250: { service: 'kubelet', product: 'Kubelet API' },

  // CI/CD / DevOps
  8081: { service: 'http-alt', product: 'HTTP (Nexus/Jenkins)' },
  50000: { service: 'jenkins-agent', product: 'Jenkins Agent' },

  // VPN / Proxy
  1194: { service: 'openvpn', product: 'OpenVPN' },
  1080: { service: 'socks', product: 'SOCKS Proxy' },
  3128: { service: 'squid', product: 'Squid Proxy' },
  8118: { service: 'privoxy', product: 'Privoxy' },

  // Other common
  111: { service: 'rpcbind', product: 'RPCBind' },
  179: { service: 'bgp', product: 'BGP' },
  500: { service: 'isakmp', product: 'IKE/IPSec', protocol: 'udp' },
  548: { service: 'afp', product: 'Apple Filing Protocol' },
  554: { service: 'rtsp', product: 'RTSP' },
  873: { service: 'rsync', product: 'Rsync' },
  1723: { service: 'pptp', product: 'PPTP VPN' },
  1883: { service: 'mqtt', product: 'MQTT' },
  5060: { service: 'sip', product: 'SIP' },
  5061: { service: 'sip-tls', product: 'SIP (TLS)' },
  6660: { service: 'irc', product: 'IRC' },
  6667: { service: 'irc', product: 'IRC' },
  6697: { service: 'ircs', product: 'IRC (TLS)' },
};

// ─── Types ──────────────────────────────────────────────────────────────────

export type ServiceSource = 'fingerprinted' | 'passive' | 'inferred';

export interface ResolvedPort {
  port: number;
  service: string;
  version?: string;
  product?: string;
  source: ServiceSource;
  confidence: number; // 0.0–1.0
}

export interface PassiveServiceData {
  port: number;
  service?: string;
  product?: string;
  version?: string;
  source?: string;
}

export interface ActivePortData {
  port: number;
  service: string;
  version?: string;
}

// ─── Resolution Logic ───────────────────────────────────────────────────────

/**
 * Resolve a single port's service name using the three-tier strategy.
 */
export function resolvePortService(
  port: number,
  activeService: string | undefined,
  activeVersion: string | undefined,
  passiveServices: PassiveServiceData[] = [],
): ResolvedPort {
  // Tier 1: Active fingerprint — if service is set and not "unknown"
  if (activeService && activeService !== 'unknown' && activeService !== '') {
    return {
      port,
      service: activeService,
      version: activeVersion,
      source: 'fingerprinted',
      confidence: 0.95,
    };
  }

  // Tier 2: Passive recon — check if Shodan/Censys/etc. identified the service
  const passiveMatch = passiveServices.find(s => s.port === port && s.service && s.service !== 'unknown');
  if (passiveMatch) {
    return {
      port,
      service: passiveMatch.service!,
      version: passiveMatch.version || activeVersion,
      product: passiveMatch.product,
      source: 'passive',
      confidence: 0.75,
    };
  }

  // Tier 3: Well-known port mapping
  const wellKnown = WELL_KNOWN_PORTS[port];
  if (wellKnown) {
    return {
      port,
      service: wellKnown.service,
      product: wellKnown.product,
      version: activeVersion,
      source: 'inferred',
      confidence: 0.5,
    };
  }

  // Fallback: still unknown
  return {
    port,
    service: 'unknown',
    version: activeVersion,
    source: 'inferred',
    confidence: 0.1,
  };
}

/**
 * Resolve all ports for an asset, merging active scan + passive recon + well-known mappings.
 * Returns ports with resolved service names and source indicators.
 */
export function resolveAssetServices(
  activePorts: ActivePortData[],
  passiveServices: PassiveServiceData[] = [],
): ResolvedPort[] {
  const resolved: ResolvedPort[] = [];
  const seenPorts = new Set<number>();

  // Process active scan ports first (they have priority)
  for (const p of activePorts) {
    seenPorts.add(p.port);
    resolved.push(resolvePortService(p.port, p.service, p.version, passiveServices));
  }

  // Add any passive-only ports not seen in active scan
  for (const ps of passiveServices) {
    if (!seenPorts.has(ps.port)) {
      seenPorts.add(ps.port);
      resolved.push({
        port: ps.port,
        service: ps.service || WELL_KNOWN_PORTS[ps.port]?.service || 'unknown',
        version: ps.version,
        product: ps.product,
        source: 'passive',
        confidence: ps.service && ps.service !== 'unknown' ? 0.7 : 0.3,
      });
    }
  }

  return resolved.sort((a, b) => a.port - b.port);
}

/**
 * Quick helper: resolve a single port number to its most likely service name.
 * Used for inline display where full resolution context isn't needed.
 */
export function inferServiceName(port: number): string {
  return WELL_KNOWN_PORTS[port]?.service || 'unknown';
}

/**
 * Enrich an existing ports array by replacing "unknown" services with resolved names.
 * Mutates the array in-place for easy integration into existing orchestrator code.
 */
export function enrichPortServices(
  ports: Array<{ port: number; service: string; version?: string }>,
  passiveServices: PassiveServiceData[] = [],
): void {
  for (const p of ports) {
    if (p.service === 'unknown' || p.service === '') {
      // Try passive recon first
      const passiveMatch = passiveServices.find(s => s.port === p.port && s.service && s.service !== 'unknown');
      if (passiveMatch) {
        p.service = passiveMatch.service!;
        if (!p.version && passiveMatch.version) {
          p.version = passiveMatch.version;
        }
      } else {
        // Fall back to well-known port mapping
        const wellKnown = WELL_KNOWN_PORTS[p.port];
        if (wellKnown) {
          p.service = wellKnown.service;
        }
      }
    }
  }
}

/**
 * Get a human-friendly label for the service source.
 */
export function getSourceLabel(source: ServiceSource): string {
  switch (source) {
    case 'fingerprinted': return 'Banner Grab';
    case 'passive': return 'Passive Recon';
    case 'inferred': return 'Port Mapping';
  }
}

/**
 * Get a confidence color class for the UI.
 */
export function getConfidenceColor(confidence: number): string {
  if (confidence >= 0.8) return 'text-emerald-400';
  if (confidence >= 0.5) return 'text-cyan-400';
  if (confidence >= 0.3) return 'text-yellow-400';
  return 'text-muted-foreground';
}
