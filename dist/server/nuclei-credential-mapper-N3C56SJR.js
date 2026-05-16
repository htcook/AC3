import "./chunk-KFQGP6VL.js";

// server/lib/nuclei-credential-mapper.ts
var NUCLEI_DEFAULT_LOGIN_TEMPLATES = [
  // ─── Web Admin Panels ───────────────────────────────────────────────
  {
    keywords: ["tomcat", "apache tomcat"],
    protocol: "http",
    templateId: "default-logins/apache/tomcat-default-login",
    name: "Apache Tomcat Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["jenkins"],
    protocol: "http",
    templateId: "default-logins/jenkins/jenkins-default-login",
    name: "Jenkins Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["grafana"],
    protocol: "http",
    templateId: "default-logins/grafana/grafana-default-login",
    name: "Grafana Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["rabbitmq"],
    protocol: "http",
    templateId: "default-logins/rabbitmq/rabbitmq-default-login",
    name: "RabbitMQ Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["elasticsearch", "kibana"],
    protocol: "http",
    templateId: "default-logins/elasticsearch/elasticsearch-default-login",
    name: "Elasticsearch Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["phpmyadmin", "pma"],
    protocol: "http",
    templateId: "default-logins/phpmyadmin/phpmyadmin-default-login",
    name: "phpMyAdmin Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["wordpress", "wp-login", "wp-admin"],
    protocol: "http",
    templateId: "default-logins/wordpress/wordpress-default-login",
    name: "WordPress Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["joomla"],
    protocol: "http",
    templateId: "default-logins/joomla/joomla-default-login",
    name: "Joomla Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["drupal"],
    protocol: "http",
    templateId: "default-logins/drupal/drupal-default-login",
    name: "Drupal Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["weblogic", "oracle weblogic"],
    protocol: "http",
    templateId: "default-logins/oracle/weblogic-default-login",
    name: "Oracle WebLogic Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["jboss", "wildfly"],
    protocol: "http",
    templateId: "default-logins/jboss/jboss-default-login",
    name: "JBoss/WildFly Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["sonarqube"],
    protocol: "http",
    templateId: "default-logins/sonarqube/sonarqube-default-login",
    name: "SonarQube Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["nexus", "sonatype nexus"],
    protocol: "http",
    templateId: "default-logins/nexus/nexus-default-login",
    name: "Nexus Repository Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["portainer"],
    protocol: "http",
    templateId: "default-logins/portainer/portainer-default-login",
    name: "Portainer Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["zabbix"],
    protocol: "http",
    templateId: "default-logins/zabbix/zabbix-default-login",
    name: "Zabbix Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["nagios"],
    protocol: "http",
    templateId: "default-logins/nagios/nagios-default-login",
    name: "Nagios Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["airflow", "apache airflow"],
    protocol: "http",
    templateId: "default-logins/apache/airflow-default-login",
    name: "Apache Airflow Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["superset", "apache superset"],
    protocol: "http",
    templateId: "default-logins/apache/superset-default-login",
    name: "Apache Superset Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["minio"],
    protocol: "http",
    templateId: "default-logins/minio/minio-default-login",
    name: "MinIO Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["consul", "hashicorp consul"],
    protocol: "http",
    templateId: "default-logins/consul/consul-default-login",
    name: "Consul Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["vault", "hashicorp vault"],
    protocol: "http",
    templateId: "default-logins/vault/vault-default-login",
    name: "Vault Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  // ─── Network Devices ────────────────────────────────────────────────
  {
    keywords: ["cisco", "ios", "asa"],
    protocol: "http",
    templateId: "default-logins/cisco/cisco-default-login",
    name: "Cisco Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["fortinet", "fortigate", "fortios"],
    protocol: "http",
    templateId: "default-logins/fortinet/fortigate-default-login",
    name: "FortiGate Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["paloalto", "pan-os", "panos"],
    protocol: "http",
    templateId: "default-logins/paloalto/panos-default-login",
    name: "Palo Alto PAN-OS Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["mikrotik", "routeros"],
    protocol: "http",
    templateId: "default-logins/mikrotik/routeros-default-login",
    name: "MikroTik RouterOS Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["ubiquiti", "unifi"],
    protocol: "http",
    templateId: "default-logins/ubiquiti/unifi-default-login",
    name: "Ubiquiti UniFi Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  // ─── Databases ──────────────────────────────────────────────────────
  {
    keywords: ["mysql", "mariadb"],
    protocol: "mysql",
    templateId: "default-logins/mysql/mysql-default-login",
    name: "MySQL Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["postgres", "postgresql"],
    protocol: "postgresql",
    templateId: "default-logins/postgres/postgres-default-login",
    name: "PostgreSQL Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["redis"],
    protocol: "redis",
    templateId: "default-logins/redis/redis-default-login",
    name: "Redis Default Login",
    severity: "high",
    usernameVar: "password",
    passwordVar: "password"
  },
  {
    keywords: ["mongodb", "mongo"],
    protocol: "mongodb",
    templateId: "default-logins/mongodb/mongodb-default-login",
    name: "MongoDB Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  // ─── Remote Access ──────────────────────────────────────────────────
  {
    keywords: ["ssh", "openssh"],
    protocol: "ssh",
    templateId: "default-logins/ssh/ssh-default-login",
    name: "SSH Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["ftp", "vsftpd", "proftpd", "pure-ftpd"],
    protocol: "ftp",
    templateId: "default-logins/ftp/ftp-default-login",
    name: "FTP Default Login",
    severity: "high",
    usernameVar: "username",
    passwordVar: "password"
  },
  {
    keywords: ["vnc", "realvnc", "tightvnc"],
    protocol: "vnc",
    templateId: "default-logins/vnc/vnc-default-login",
    name: "VNC Default Login",
    severity: "high",
    usernameVar: "password",
    passwordVar: "password"
  },
  {
    keywords: ["telnet"],
    protocol: "telnet",
    templateId: "default-logins/telnet/telnet-default-login",
    name: "Telnet Default Login",
    severity: "critical",
    usernameVar: "username",
    passwordVar: "password"
  }
];
function findTemplatesForCredential(credential) {
  const matches = [];
  const credProduct = credential.product.toLowerCase();
  const credVendor = credential.vendor.toLowerCase();
  const credProtocol = credential.protocol.toLowerCase();
  for (const template of NUCLEI_DEFAULT_LOGIN_TEMPLATES) {
    const keywordMatch = template.keywords.some(
      (kw) => credProduct.includes(kw) || credVendor.includes(kw)
    );
    const protocolMatch = template.protocol === credProtocol || template.protocol === "http" && ["http", "https", "http_form", "http_basic"].includes(credProtocol);
    if (keywordMatch || protocolMatch && keywordMatch) {
      matches.push(template);
    }
  }
  return matches;
}
function buildNucleiCredentialInjection(targets, confirmedCredentials) {
  const templates = [];
  const templateIdSet = /* @__PURE__ */ new Set();
  const variables = {};
  const targetsWithCreds = /* @__PURE__ */ new Set();
  const byProtocol = {};
  for (const cred of confirmedCredentials) {
    const matchingTemplates = findTemplatesForCredential(cred);
    for (const tmpl of matchingTemplates) {
      const templateKey = `${tmpl.templateId}:${cred.username}:${cred.password}`;
      if (templateIdSet.has(templateKey)) continue;
      templateIdSet.add(templateKey);
      const nucleiTemplate = {
        templateId: tmpl.templateId,
        name: tmpl.name,
        product: cred.product,
        protocol: tmpl.protocol,
        severity: tmpl.severity,
        variables: {
          [tmpl.usernameVar]: cred.username,
          [tmpl.passwordVar]: cred.password
        },
        credential: cred
      };
      templates.push(nucleiTemplate);
      const varPrefix = tmpl.templateId.replace(/[^a-zA-Z0-9]/g, "_");
      variables[`${varPrefix}_username`] = cred.username;
      variables[`${varPrefix}_password`] = cred.password;
      byProtocol[tmpl.protocol] = (byProtocol[tmpl.protocol] || 0) + 1;
    }
    for (const target of targets) {
      const targetLower = target.toLowerCase();
      if (targetLower.includes(cred.vendor.toLowerCase()) || targetLower.includes(cred.product.toLowerCase())) {
        targetsWithCreds.add(target);
      }
    }
  }
  if (templates.length > 0) {
    targets.forEach((t) => targetsWithCreds.add(t));
  }
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
      byProtocol
    }
  };
}
function buildNucleiCliArgs(injection) {
  const args = [];
  for (const templateId of injection.templateIds) {
    args.push("-t", templateId);
  }
  for (const [key, value] of Object.entries(injection.variables)) {
    args.push("-var", `${key}=${value}`);
  }
  return args;
}
function getCredentialInjectionSummary(injection) {
  if (injection.templates.length === 0) {
    return "No default credentials found for scan targets.";
  }
  const lines = [
    `Found ${injection.stats.totalCredentials} credential(s) mapping to ${injection.stats.totalTemplates} Nuclei template(s):`
  ];
  const byProduct = /* @__PURE__ */ new Map();
  for (const tmpl of injection.templates) {
    const key = tmpl.product;
    if (!byProduct.has(key)) byProduct.set(key, []);
    byProduct.get(key).push(tmpl);
  }
  for (const [product, tmpls] of byProduct) {
    const creds = tmpls.map((t) => `${t.credential.username}:***`).join(", ");
    lines.push(`  \u2022 ${product}: ${tmpls.length} template(s) [${creds}]`);
  }
  return lines.join("\n");
}
async function getCredentialInjectionForTargets(targets) {
  const { getCredentialsForService } = await import("./credential-tester-DU2MDD4C.js");
  const allCredentials = [];
  const seen = /* @__PURE__ */ new Set();
  for (const target of targets) {
    const parsed = parseTarget(target);
    if (!parsed) continue;
    const creds = await getCredentialsForService({
      host: parsed.host,
      port: parsed.port,
      protocol: parsed.protocol
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
function parseTarget(target) {
  try {
    if (target.startsWith("http://") || target.startsWith("https://")) {
      const url = new URL(target);
      return {
        host: url.hostname,
        port: parseInt(url.port) || (url.protocol === "https:" ? 443 : 80),
        protocol: url.protocol === "https:" ? "https" : "http"
      };
    }
    const colonIdx = target.lastIndexOf(":");
    if (colonIdx > 0) {
      const host = target.substring(0, colonIdx);
      const port = parseInt(target.substring(colonIdx + 1));
      if (!isNaN(port)) {
        return { host, port, protocol: guessProtocol(port) };
      }
    }
    return { host: target, port: 80, protocol: "http" };
  } catch {
    return null;
  }
}
function guessProtocol(port) {
  const portMap = {
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
    9200: "http",
    // Elasticsearch
    15672: "http",
    // RabbitMQ management
    27017: "mongodb"
  };
  return portMap[port] || "http";
}
export {
  buildNucleiCliArgs,
  buildNucleiCredentialInjection,
  getCredentialInjectionForTargets,
  getCredentialInjectionSummary
};
