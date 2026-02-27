/**
 * Nuclei Credential Mapper
 *
 * Maps confirmed OEM default credentials from the credential-tester engine
 * to Nuclei default-login template IDs. When a vulnerability scan is started,
 * this module:
 *
 * 1. Looks up confirmed/candidate credentials for each scan target
 * 2. Maps service+product combinations to specific Nuclei template IDs
 * 3. Generates custom Nuclei variables (-var) for credential injection
 * 4. Auto-selects the "default-logins" template category when credentials exist
 *
 * This ensures that Nuclei scans automatically test discovered default
 * credentials without the operator needing to manually configure them.
 */

import type { CredentialCandidate, CredentialTestTarget } from "./credential-tester";

// ─── Nuclei Template Mapping ────────────────────────────────────────────────
// Maps service/product/protocol combinations to specific Nuclei template IDs
// from the nuclei-templates/default-logins/ directory.

export interface NucleiCredentialTemplate {
  /** Nuclei template ID (e.g., "default-logins/apache/tomcat-default-login") */
  templateId: string;
  /** Human-readable template name */
  name: string;
  /** Service/product this template targets */
  product: string;
  /** Protocol (http, ssh, ftp, etc.) */
  protocol: string;
  /** Nuclei severity level */
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Custom variables to inject into the template */
  variables: Record<string, string>;
  /** The credential candidate that triggered this mapping */
  credential: CredentialCandidate;
}

export interface NucleiCredentialInjection {
  /** Targets that have credential templates available */
  targets: string[];
  /** Template IDs to add to the scan */
  templateIds: string[];
  /** Custom variables for credential injection */
  variables: Record<string, string>;
  /** Full template mapping details */
  templates: NucleiCredentialTemplate[];
  /** Summary stats */
  stats: {
    totalTargets: number;
    targetsWithCredentials: number;
    totalTemplates: number;
    totalCredentials: number;
    byProtocol: Record<string, number>;
  };
}

/**
 * Nuclei default-login template database.
 * Maps product/service names to their corresponding Nuclei template IDs.
 * These are real template paths from the nuclei-templates repository.
 */
const NUCLEI_DEFAULT_LOGIN_TEMPLATES: Array<{
  /** Keywords to match against product/vendor/banner */
  keywords: string[];
  /** Protocol this template applies to */
  protocol: string;
  /** Nuclei template ID */
  templateId: string;
  /** Template display name */
  name: string;
  /** Severity */
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Variable names for username/password injection */
  usernameVar: string;
  passwordVar: string;
}> = [
  // ─── Web Admin Panels ───────────────────────────────────────────────
  {
    keywords: ["tomcat", "apache tomcat"],
    protocol: "http",
    templateId: "default-logins/apache/tomcat-default-login",
    name: "Apache Tomcat Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["jenkins"],
    protocol: "http",
    templateId: "default-logins/jenkins/jenkins-default-login",
    name: "Jenkins Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["grafana"],
    protocol: "http",
    templateId: "default-logins/grafana/grafana-default-login",
    name: "Grafana Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["rabbitmq"],
    protocol: "http",
    templateId: "default-logins/rabbitmq/rabbitmq-default-login",
    name: "RabbitMQ Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["elasticsearch", "kibana"],
    protocol: "http",
    templateId: "default-logins/elasticsearch/elasticsearch-default-login",
    name: "Elasticsearch Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["phpmyadmin", "pma"],
    protocol: "http",
    templateId: "default-logins/phpmyadmin/phpmyadmin-default-login",
    name: "phpMyAdmin Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["wordpress", "wp-login", "wp-admin"],
    protocol: "http",
    templateId: "default-logins/wordpress/wordpress-default-login",
    name: "WordPress Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["joomla"],
    protocol: "http",
    templateId: "default-logins/joomla/joomla-default-login",
    name: "Joomla Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["drupal"],
    protocol: "http",
    templateId: "default-logins/drupal/drupal-default-login",
    name: "Drupal Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["weblogic", "oracle weblogic"],
    protocol: "http",
    templateId: "default-logins/oracle/weblogic-default-login",
    name: "Oracle WebLogic Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["jboss", "wildfly"],
    protocol: "http",
    templateId: "default-logins/jboss/jboss-default-login",
    name: "JBoss/WildFly Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["sonarqube"],
    protocol: "http",
    templateId: "default-logins/sonarqube/sonarqube-default-login",
    name: "SonarQube Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["nexus", "sonatype nexus"],
    protocol: "http",
    templateId: "default-logins/nexus/nexus-default-login",
    name: "Nexus Repository Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["portainer"],
    protocol: "http",
    templateId: "default-logins/portainer/portainer-default-login",
    name: "Portainer Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["zabbix"],
    protocol: "http",
    templateId: "default-logins/zabbix/zabbix-default-login",
    name: "Zabbix Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["nagios"],
    protocol: "http",
    templateId: "default-logins/nagios/nagios-default-login",
    name: "Nagios Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["airflow", "apache airflow"],
    protocol: "http",
    templateId: "default-logins/apache/airflow-default-login",
    name: "Apache Airflow Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["superset", "apache superset"],
    protocol: "http",
    templateId: "default-logins/apache/superset-default-login",
    name: "Apache Superset Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["minio"],
    protocol: "http",
    templateId: "default-logins/minio/minio-default-login",
    name: "MinIO Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["consul", "hashicorp consul"],
    protocol: "http",
    templateId: "default-logins/consul/consul-default-login",
    name: "Consul Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["vault", "hashicorp vault"],
    protocol: "http",
    templateId: "default-logins/vault/vault-default-login",
    name: "Vault Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  // ─── Network Devices ────────────────────────────────────────────────
  {
    keywords: ["cisco", "ios", "asa"],
    protocol: "http",
    templateId: "default-logins/cisco/cisco-default-login",
    name: "Cisco Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["fortinet", "fortigate", "fortios"],
    protocol: "http",
    templateId: "default-logins/fortinet/fortigate-default-login",
    name: "FortiGate Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["paloalto", "pan-os", "panos"],
    protocol: "http",
    templateId: "default-logins/paloalto/panos-default-login",
    name: "Palo Alto PAN-OS Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["mikrotik", "routeros"],
    protocol: "http",
    templateId: "default-logins/mikrotik/routeros-default-login",
    name: "MikroTik RouterOS Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["ubiquiti", "unifi"],
    protocol: "http",
    templateId: "default-logins/ubiquiti/unifi-default-login",
    name: "Ubiquiti UniFi Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  // ─── Databases ──────────────────────────────────────────────────────
  {
    keywords: ["mysql", "mariadb"],
    protocol: "mysql",
    templateId: "default-logins/mysql/mysql-default-login",
    name: "MySQL Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["postgres", "postgresql"],
    protocol: "postgresql",
    templateId: "default-logins/postgres/postgres-default-login",
    name: "PostgreSQL Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["redis"],
    protocol: "redis",
    templateId: "default-logins/redis/redis-default-login",
    name: "Redis Default Login",
    severity: "high",
    usernameVar: "password",
    passwordVar: "password",
  },
  {
    keywords: ["mongodb", "mongo"],
    protocol: "mongodb",
    templateId: "default-logins/mongodb/mongodb-default-login",
    name: "MongoDB Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  // ─── Remote Access ──────────────────────────────────────────────────
  {
    keywords: ["ssh", "openssh"],
    protocol: "ssh",
    templateId: "default-logins/ssh/ssh-default-login",
    name: "SSH Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["ftp", "vsftpd", "proftpd", "pure-ftpd"],
    protocol: "ftp",
    templateId: "default-logins/ftp/ftp-default-login",
    name: "FTP Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password",
  },
  {
    keywords: ["vnc", "realvnc", "tightvnc"],
    protocol: "vnc",
    templateId: "default-logins/vnc/vnc-default-login",
    name: "VNC Default Login",
    severity: "high",
    usernameVar: "password",
    passwordVar: "password",
  },
  {
    keywords: ["telnet"],
    protocol: "telnet",
    templateId: "default-logins/telnet/telnet-default-login",
    name: "Telnet Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password",
  },
];

/**
 * Find matching Nuclei templates for a credential candidate.
 * Matches based on product name, vendor, and protocol.
 */
function findTemplatesForCredential(
  credential: CredentialCandidate,
): typeof NUCLEI_DEFAULT_LOGIN_TEMPLATES[number][] {
  const matches: typeof NUCLEI_DEFAULT_LOGIN_TEMPLATES[number][] = [];
  const credProduct = credential.product.toLowerCase();
  const credVendor = credential.vendor.toLowerCase();
  const credProtocol = credential.protocol.toLowerCase();

  for (const template of NUCLEI_DEFAULT_LOGIN_TEMPLATES) {
    // Check keyword match against product or vendor
    const keywordMatch = template.keywords.some(
      (kw) => credProduct.includes(kw) || credVendor.includes(kw)
    );

    // Check protocol match (flexible — http covers most web panels)
    const protocolMatch =
      template.protocol === credProtocol ||
      (template.protocol === "http" && ["http", "https", "http_form", "http_basic"].includes(credProtocol));

    if (keywordMatch || (protocolMatch && keywordMatch)) {
      matches.push(template);
    }
  }

  return matches;
}

/**
 * Build Nuclei credential injection for a set of scan targets.
 *
 * This is the main entry point — call it before starting a Nuclei scan to get:
 * - Template IDs to add to the scan
 * - Custom variables for credential injection
 * - Stats about what will be tested
 *
 * @param targets - Array of scan target strings (URLs, IPs, hostnames)
 * @param confirmedCredentials - Credentials from the credential-tester (confirmed or candidates)
 * @returns NucleiCredentialInjection with templates and variables to inject
 */
export function buildNucleiCredentialInjection(
  targets: string[],
  confirmedCredentials: CredentialCandidate[],
): NucleiCredentialInjection {
  const templates: NucleiCredentialTemplate[] = [];
  const templateIdSet = new Set<string>();
  const variables: Record<string, string> = {};
  const targetsWithCreds = new Set<string>();
  const byProtocol: Record<string, number> = {};

  for (const cred of confirmedCredentials) {
    const matchingTemplates = findTemplatesForCredential(cred);

    for (const tmpl of matchingTemplates) {
      // Avoid duplicate template IDs
      const templateKey = `${tmpl.templateId}:${cred.username}:${cred.password}`;
      if (templateIdSet.has(templateKey)) continue;
      templateIdSet.add(templateKey);

      // Build the template mapping
      const nucleiTemplate: NucleiCredentialTemplate = {
        templateId: tmpl.templateId,
        name: tmpl.name,
        product: cred.product,
        protocol: tmpl.protocol,
        severity: tmpl.severity,
        variables: {
          [tmpl.usernameVar]: cred.username,
          [tmpl.passwordVar]: cred.password,
        },
        credential: cred,
      };

      templates.push(nucleiTemplate);

      // Aggregate variables — use indexed keys for multiple credentials
      const varPrefix = tmpl.templateId.replace(/[^a-zA-Z0-9]/g, "_");
      variables[`${varPrefix}_username`] = cred.username;
      variables[`${varPrefix}_password`] = cred.password;

      // Track protocol distribution
      byProtocol[tmpl.protocol] = (byProtocol[tmpl.protocol] || 0) + 1;
    }

    // Track which targets have credentials
    // Match credentials to targets by checking if any target contains the credential's host info
    for (const target of targets) {
      const targetLower = target.toLowerCase();
      if (
        targetLower.includes(cred.vendor.toLowerCase()) ||
        targetLower.includes(cred.product.toLowerCase())
      ) {
        targetsWithCreds.add(target);
      }
    }
  }

  // If we have any credentials, all targets get tested (Nuclei runs templates against all targets)
  if (templates.length > 0) {
    targets.forEach((t) => targetsWithCreds.add(t));
  }

  // Deduplicate template IDs
  const uniqueTemplateIds = [...new Set(templates.map((t) => t.templateId))];

  return {
    targets: [...targetsWithCreds],
    templateIds: uniqueTemplateIds,
    variables,
    templates,
    stats: {
      totalTargets: targets.length,
      targetsWithCredentials: targetsWithCreds.size,
      totalTemplates: uniqueTemplateIds.length,
      totalCredentials: confirmedCredentials.length,
      byProtocol,
    },
  };
}

/**
 * Build Nuclei CLI arguments for credential injection.
 * Returns an array of -var flags to pass to the nuclei binary.
 *
 * Example output:
 * ["-var", "username=admin", "-var", "password=admin123", "-t", "default-logins/tomcat-default-login"]
 */
export function buildNucleiCliArgs(injection: NucleiCredentialInjection): string[] {
  const args: string[] = [];

  // Add template selections
  for (const templateId of injection.templateIds) {
    args.push("-t", templateId);
  }

  // Add variable injections
  for (const [key, value] of Object.entries(injection.variables)) {
    args.push("-var", `${key}=${value}`);
  }

  return args;
}

/**
 * Get a human-readable summary of what credentials will be tested.
 * Useful for displaying in the UI before starting a scan.
 */
export function getCredentialInjectionSummary(injection: NucleiCredentialInjection): string {
  if (injection.templates.length === 0) {
    return "No default credentials found for scan targets.";
  }

  const lines: string[] = [
    `Found ${injection.stats.totalCredentials} credential(s) mapping to ${injection.stats.totalTemplates} Nuclei template(s):`,
  ];

  // Group by product
  const byProduct = new Map<string, NucleiCredentialTemplate[]>();
  for (const tmpl of injection.templates) {
    const key = tmpl.product;
    if (!byProduct.has(key)) byProduct.set(key, []);
    byProduct.get(key)!.push(tmpl);
  }

  for (const [product, tmpls] of byProduct) {
    const creds = tmpls.map((t) => `${t.credential.username}:***`).join(", ");
    lines.push(`  • ${product}: ${tmpls.length} template(s) [${creds}]`);
  }

  return lines.join("\n");
}

/**
 * Convenience function: given scan targets and an engagement context,
 * look up all known credentials and build the Nuclei injection.
 *
 * This is the function the Nuclei scanner router should call.
 */
export async function getCredentialInjectionForTargets(
  targets: string[],
): Promise<NucleiCredentialInjection> {
  const { getCredentialsForService } = await import("./credential-tester");

  // Build credential targets from scan target strings
  const allCredentials: CredentialCandidate[] = [];
  const seen = new Set<string>();

  for (const target of targets) {
    // Parse the target to extract host/port/protocol
    const parsed = parseTarget(target);
    if (!parsed) continue;

    // Get credentials for this service
    const creds = getCredentialsForService({
      host: parsed.host,
      port: parsed.port,
      protocol: parsed.protocol,
    });

    for (const cred of creds) {
      const key = `${cred.vendor}:${cred.product}:${cred.username}:${cred.password}`;
      if (!seen.has(key)) {
        seen.add(key);
        allCredentials.push(cred);
      }
    }
  }

  return buildNucleiCredentialInjection(targets, allCredentials);
}

/**
 * Parse a scan target string into host/port/protocol components.
 */
function parseTarget(target: string): { host: string; port: number; protocol: string } | null {
  try {
    // Try as URL first
    if (target.startsWith("http://") || target.startsWith("https://")) {
      const url = new URL(target);
      return {
        host: url.hostname,
        port: parseInt(url.port) || (url.protocol === "https:" ? 443 : 80),
        protocol: url.protocol === "https:" ? "https" : "http",
      };
    }

    // Try as host:port
    const colonIdx = target.lastIndexOf(":");
    if (colonIdx > 0) {
      const host = target.substring(0, colonIdx);
      const port = parseInt(target.substring(colonIdx + 1));
      if (!isNaN(port)) {
        return { host, port, protocol: guessProtocol(port) };
      }
    }

    // Plain hostname — assume HTTP
    return { host: target, port: 80, protocol: "http" };
  } catch {
    return null;
  }
}

/**
 * Guess protocol from port number.
 */
function guessProtocol(port: number): string {
  const portMap: Record<number, string> = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http",
    8443: "https",
    8888: "http",
    9200: "http", // Elasticsearch
    15672: "http", // RabbitMQ management
    27017: "mongodb",
  };
  return portMap[port] || "http";
}
