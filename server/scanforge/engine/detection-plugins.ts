/**
 * ScanForge Detection Plugin System
 *
 * YAML-based safe detection plugins that define:
 *   - Targeting criteria (service, ports, products)
 *   - Preconditions for execution
 *   - Detection logic (HTTP probes, header checks, TLS handshakes, etc.)
 *   - Verification steps (bounded rechecks)
 *   - Output defaults (state, severity, tags)
 *
 * All plugins are safe_by_default — no destructive actions.
 * The plugin engine evaluates which plugins apply to a given asset/service
 * and orchestrates detection + verification in bounded execution windows.
 */

// ─── Plugin Types ───────────────────────────────────────────────────────────

export interface DetectionPlugin {
  id: string;
  metadata: {
    title: string;
    category: PluginCategory;
    safe_by_default: boolean;
    references: string[];
  };
  targeting: {
    service: string[];
    ports: number[];
    products: string[];
  };
  preconditions: string[];
  detection: DetectionConfig;
  verification?: VerificationConfig;
  output: {
    default_state: "verified" | "probable" | "suspected" | "informational";
    severity: "critical" | "high" | "medium" | "low" | "informational";
    tags: string[];
  };
}

export type PluginCategory =
  | "web_server"
  | "cloud_storage"
  | "tls"
  | "dns"
  | "authentication"
  | "network"
  | "database"
  | "api"
  | "container"
  | "iot"
  | "ics"
  | "configuration"
  | "disclosure";

export type DetectionConfig =
  | HttpRequestDetection
  | ResponseHeaderDetection
  | TlsHandshakeDetection
  | AnonymousHttpProbeDetection
  | BannerGrabDetection
  | DnsQueryDetection;

export interface HttpRequestDetection {
  type: "http_request";
  method: "GET" | "POST" | "HEAD" | "OPTIONS";
  path_candidates: string[];
  success_indicators: string[];
  headers?: Record<string, string>;
  timeout_ms?: number;
}

export interface ResponseHeaderDetection {
  type: "response_header";
  header: string;
  regex: string;
}

export interface TlsHandshakeDetection {
  type: "tls_handshake_matrix";
  reject_if_supported: {
    protocols: string[];
    cipher_patterns: string[];
  };
}

export interface AnonymousHttpProbeDetection {
  type: "anonymous_http_probe";
  method: "GET" | "HEAD";
  path_candidates: string[];
  success_indicators: string[];
}

export interface BannerGrabDetection {
  type: "banner_grab";
  port: number;
  protocol: "tcp" | "udp";
  regex: string;
}

export interface DnsQueryDetection {
  type: "dns_query";
  record_type: "A" | "AAAA" | "MX" | "TXT" | "NS" | "SOA" | "CNAME" | "AXFR";
  success_indicators: string[];
}

export type VerificationConfig =
  | { type: "bounded_content_check"; confirm_only: boolean; max_bytes: number }
  | { type: "banner_confirmation" }
  | { type: "repeat_handshake" }
  | { type: "anonymous_listing_guarded"; confirm_only: boolean }
  | { type: "dns_recheck"; delay_ms: number };

// ─── Built-in Plugin Definitions ────────────────────────────────────────────

export const BUILTIN_PLUGINS: DetectionPlugin[] = [
  // Apache Path Traversal (CVE-2021-41773)
  {
    id: "apache_path_traversal_cve_2021_41773",
    metadata: {
      title: "Apache HTTP Server Path Traversal Check",
      category: "web_server",
      safe_by_default: true,
      references: ["CVE-2021-41773"],
    },
    targeting: {
      service: ["http", "https"],
      ports: [80, 443, 8080, 8443],
      products: ["Apache httpd"],
    },
    preconditions: ["target responds to HTTP"],
    detection: {
      type: "http_request",
      method: "GET",
      path_candidates: ["/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
      success_indicators: ["root:x:"],
    },
    verification: { type: "bounded_content_check", confirm_only: true, max_bytes: 200 },
    output: {
      default_state: "probable",
      severity: "critical",
      tags: ["cve", "web", "path_traversal", "safe_validation"],
    },
  },

  // Azure Storage Public Blob Access
  {
    id: "azure_storage_public_access",
    metadata: {
      title: "Azure Storage Public Blob Access Exposure",
      category: "cloud_storage",
      safe_by_default: true,
      references: [],
    },
    targeting: {
      service: ["https"],
      ports: [443],
      products: ["Azure Blob Storage"],
    },
    preconditions: ["hostname matches blob.core.windows.net or provider metadata suggests Azure storage"],
    detection: {
      type: "anonymous_http_probe",
      method: "GET",
      path_candidates: ["/"],
      success_indicators: ["BlobServiceProperties", "ContainerNotFound"],
    },
    verification: { type: "anonymous_listing_guarded", confirm_only: true },
    output: {
      default_state: "probable",
      severity: "high",
      tags: ["cloud", "storage", "exposure", "azure"],
    },
  },

  // NGINX Version Disclosure
  {
    id: "nginx_version_exposure",
    metadata: {
      title: "NGINX Version Disclosure",
      category: "web_server",
      safe_by_default: true,
      references: [],
    },
    targeting: {
      service: ["http", "https"],
      ports: [80, 443, 8080, 8443],
      products: ["nginx"],
    },
    preconditions: ["server header is present or fingerprint confidence >= 0.6"],
    detection: {
      type: "response_header",
      header: "Server",
      regex: "nginx\\/([0-9.]+)",
    },
    verification: { type: "banner_confirmation" },
    output: {
      default_state: "informational",
      severity: "low",
      tags: ["disclosure", "fingerprinting", "web"],
    },
  },

  // Weak TLS Cipher / Protocol Support
  {
    id: "tls_weak_cipher_policy",
    metadata: {
      title: "Weak TLS Cipher / Protocol Support",
      category: "tls",
      safe_by_default: true,
      references: [],
    },
    targeting: {
      service: ["https", "tls", "imaps", "smtps", "rdp"],
      ports: [443, 993, 465, 3389],
      products: [],
    },
    preconditions: ["target negotiates TLS"],
    detection: {
      type: "tls_handshake_matrix",
      reject_if_supported: {
        protocols: ["SSLv3", "TLS1.0", "TLS1.1"],
        cipher_patterns: ["RC4", "3DES"],
      },
    },
    verification: { type: "repeat_handshake" },
    output: {
      default_state: "verified",
      severity: "medium",
      tags: ["tls", "crypto", "configuration"],
    },
  },

  // SSH Weak Ciphers
  {
    id: "ssh_weak_ciphers",
    metadata: {
      title: "SSH Weak Cipher Support",
      category: "network",
      safe_by_default: true,
      references: [],
    },
    targeting: {
      service: ["ssh"],
      ports: [22, 2222],
      products: ["OpenSSH"],
    },
    preconditions: ["target accepts SSH connections"],
    detection: {
      type: "banner_grab",
      port: 22,
      protocol: "tcp",
      regex: "SSH-2\\.0-(.+)",
    },
    verification: { type: "banner_confirmation" },
    output: {
      default_state: "probable",
      severity: "medium",
      tags: ["ssh", "crypto", "configuration"],
    },
  },

  // DNS Zone Transfer
  {
    id: "dns_zone_transfer",
    metadata: {
      title: "DNS Zone Transfer Allowed",
      category: "dns",
      safe_by_default: true,
      references: [],
    },
    targeting: {
      service: ["dns"],
      ports: [53],
      products: [],
    },
    preconditions: ["target is an authoritative DNS server"],
    detection: {
      type: "dns_query",
      record_type: "AXFR",
      success_indicators: ["SOA", "NS"],
    },
    verification: { type: "dns_recheck", delay_ms: 5000 },
    output: {
      default_state: "verified",
      severity: "high",
      tags: ["dns", "zone_transfer", "information_disclosure"],
    },
  },
];

// ─── Plugin Engine ──────────────────────────────────────────────────────────

export interface AssetService {
  port: number;
  protocol: string;
  service_name?: string;
  product?: string;
  version?: string;
}

export interface PluginMatchResult {
  plugin: DetectionPlugin;
  matchedService: AssetService;
  matchReason: string;
}

/**
 * Find all plugins that apply to a given asset's services.
 */
export function matchPlugins(
  services: AssetService[],
  options?: { safeOnly?: boolean; categories?: PluginCategory[]; customPlugins?: DetectionPlugin[] },
): PluginMatchResult[] {
  const allPlugins = [...BUILTIN_PLUGINS, ...(options?.customPlugins ?? [])];
  const results: PluginMatchResult[] = [];

  for (const plugin of allPlugins) {
    // Filter by safety
    if (options?.safeOnly && !plugin.metadata.safe_by_default) continue;

    // Filter by category
    if (options?.categories && !options.categories.includes(plugin.metadata.category)) continue;

    for (const svc of services) {
      const reasons: string[] = [];

      // Check port match
      if (plugin.targeting.ports.length > 0 && plugin.targeting.ports.includes(svc.port)) {
        reasons.push(`port ${svc.port}`);
      }

      // Check service match
      if (plugin.targeting.service.length > 0 && svc.service_name) {
        const svcLower = svc.service_name.toLowerCase();
        if (plugin.targeting.service.some(s => svcLower.includes(s.toLowerCase()))) {
          reasons.push(`service ${svc.service_name}`);
        }
      }

      // Check product match
      if (plugin.targeting.products.length > 0 && svc.product) {
        const prodLower = svc.product.toLowerCase();
        if (plugin.targeting.products.some(p => prodLower.includes(p.toLowerCase()))) {
          reasons.push(`product ${svc.product}`);
        }
      }

      if (reasons.length > 0) {
        results.push({
          plugin,
          matchedService: svc,
          matchReason: reasons.join(", "),
        });
      }
    }
  }

  return results;
}

/**
 * Get a summary of available plugins by category.
 */
export function getPluginSummary(customPlugins?: DetectionPlugin[]): Record<string, { count: number; ids: string[] }> {
  const allPlugins = [...BUILTIN_PLUGINS, ...(customPlugins ?? [])];
  const summary: Record<string, { count: number; ids: string[] }> = {};

  for (const p of allPlugins) {
    if (!summary[p.metadata.category]) {
      summary[p.metadata.category] = { count: 0, ids: [] };
    }
    summary[p.metadata.category].count++;
    summary[p.metadata.category].ids.push(p.id);
  }

  return summary;
}

/**
 * Generate a plugin execution plan for an asset.
 * Returns plugins in recommended execution order (safe first, then by category priority).
 */
export function buildPluginExecutionPlan(
  services: AssetService[],
  options?: { safeOnly?: boolean; maxPlugins?: number; customPlugins?: DetectionPlugin[] },
): PluginMatchResult[] {
  const matches = matchPlugins(services, options);

  // Category priority order
  const categoryPriority: Record<string, number> = {
    tls: 1,
    web_server: 2,
    authentication: 3,
    cloud_storage: 4,
    dns: 5,
    network: 6,
    database: 7,
    api: 8,
    container: 9,
    configuration: 10,
    disclosure: 11,
    iot: 12,
    ics: 13,
  };

  matches.sort((a, b) => {
    // Safe plugins first
    if (a.plugin.metadata.safe_by_default !== b.plugin.metadata.safe_by_default) {
      return a.plugin.metadata.safe_by_default ? -1 : 1;
    }
    // Then by category priority
    const aPrio = categoryPriority[a.plugin.metadata.category] ?? 50;
    const bPrio = categoryPriority[b.plugin.metadata.category] ?? 50;
    return aPrio - bPrio;
  });

  if (options?.maxPlugins) {
    return matches.slice(0, options.maxPlugins);
  }

  return matches;
}

/**
 * Convert a detection plugin to LLM context for the engagement orchestrator.
 */
export function pluginToLlmContext(plugin: DetectionPlugin): string {
  const lines: string[] = [
    `Plugin: ${plugin.id}`,
    `Title: ${plugin.metadata.title}`,
    `Category: ${plugin.metadata.category}`,
    `Safe: ${plugin.metadata.safe_by_default}`,
    `Targets: services=${plugin.targeting.service.join(",")}, ports=${plugin.targeting.ports.join(",")}, products=${plugin.targeting.products.join(",")}`,
    `Detection: ${plugin.detection.type}`,
    `Default output: state=${plugin.output.default_state}, severity=${plugin.output.severity}`,
    `Tags: ${plugin.output.tags.join(", ")}`,
  ];
  if (plugin.metadata.references.length > 0) {
    lines.push(`References: ${plugin.metadata.references.join(", ")}`);
  }
  return lines.join("\n");
}
