import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/service-template-mapper.ts
function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}
function isVersionInRange(version, range) {
  const numericVersion = version.match(/^[\d.]+/)?.[0];
  if (!numericVersion) return false;
  if (range.min && compareVersions(numericVersion, range.min) < 0) return false;
  if (range.max && compareVersions(numericVersion, range.max) > 0) return false;
  return true;
}
function mapServiceToTemplates(fp) {
  const baseMapping = PROTOCOL_TAG_MAP[fp.protocol] || {
    tags: ["network"],
    networkScan: true,
    priority: 3,
    rationale: `Unknown protocol ${fp.protocol} \u2014 running broad network scan`
  };
  const tags = [...baseMapping.tags];
  let priority = baseMapping.priority;
  const specificTemplates = [];
  const rationale = [baseMapping.rationale];
  if (fp.product) {
    for (const pm of PRODUCT_MAPPINGS) {
      if (pm.pattern.test(fp.product)) {
        for (const tag of pm.tags) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        priority = Math.max(1, priority + pm.priorityBoost);
        rationale.push(`Product match: ${fp.product}`);
        break;
      }
    }
  }
  if (fp.product && fp.version) {
    for (const vcm of VERSION_CVE_MAPPINGS) {
      if (vcm.product.test(fp.product) && isVersionInRange(fp.version, vcm.versionRange)) {
        for (const tag of vcm.tags) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        specificTemplates.push(...vcm.cves);
        priority = 1;
        rationale.push(`Version-matched CVEs: ${vcm.cves.join(", ") || "known vulnerable range"}`);
      }
    }
  }
  if (fp.securityFlags) {
    if (fp.securityFlags.anonymousAccess) {
      if (!tags.includes("unauth")) tags.push("unauth");
      priority = 1;
      rationale.push("Anonymous access detected");
    }
    if (fp.securityFlags.defaultCredentials) {
      if (!tags.includes("default-login")) tags.push("default-login");
      priority = 1;
      rationale.push("Default credentials detected");
    }
    if (!fp.securityFlags.tlsSupported && !fp.securityFlags.encryptionEnabled) {
      rationale.push("No encryption \u2014 cleartext protocol");
    }
  }
  if (fp.potentialCves && fp.potentialCves.length > 0) {
    if (!tags.includes("cve")) tags.push("cve");
    specificTemplates.push(...fp.potentialCves);
    priority = 1;
    rationale.push(`Fingerprint-detected CVEs: ${fp.potentialCves.slice(0, 5).join(", ")}`);
  }
  return {
    tags: [...new Set(tags)],
    // Deduplicate
    networkScan: baseMapping.networkScan,
    priority,
    rationale: rationale.join(" | "),
    specificTemplates: specificTemplates.length > 0 ? [...new Set(specificTemplates)] : void 0
  };
}
function generateServiceScanTasks(host, fingerprintResults, options) {
  const rateLimit = options?.rateLimit || 100;
  const evasionHeaders = options?.evasionHeaders || "";
  const maxTasks = options?.maxTasks || 20;
  const tasks = [];
  for (const fp of fingerprintResults) {
    if (fp.error) continue;
    const mapping = mapServiceToTemplates(fp);
    const tagArgs = mapping.tags.length > 0 ? `-tags ${mapping.tags.join(",")}` : "";
    const severityArg = "-severity critical,high,medium";
    const target = `${host}:${fp.port}`;
    const nucleiArgs = `-target ${target} ${severityArg} ${tagArgs} -jsonl -nc -duc -ni -timeout 10 -retries 1 -rate-limit ${rateLimit}${evasionHeaders}`;
    tasks.push({
      host,
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      version: fp.version,
      mapping,
      nucleiArgs
    });
  }
  tasks.sort((a, b) => a.mapping.priority - b.mapping.priority);
  return tasks.slice(0, maxTasks);
}
function getServiceBasedTags(fingerprintResults) {
  if (!fingerprintResults || fingerprintResults.length === 0) {
    return { tags: [], rationale: [] };
  }
  const allTags = /* @__PURE__ */ new Set();
  const rationale = [];
  for (const fp of fingerprintResults) {
    if (fp.error) continue;
    const mapping = mapServiceToTemplates(fp);
    for (const tag of mapping.tags) {
      allTags.add(tag);
    }
    if (fp.product || fp.version) {
      rationale.push(
        `${fp.port}/${fp.protocol}: ${fp.product || "unknown"} ${fp.version || ""}`.trim()
      );
    }
  }
  return {
    tags: [...allTags],
    rationale
  };
}
function getTemplateMappingSummary(fingerprintResults) {
  const serviceBreakdown = [];
  const allTags = /* @__PURE__ */ new Set();
  const allCves = [];
  let highPriority = 0;
  for (const fp of fingerprintResults) {
    if (fp.error) continue;
    const mapping = mapServiceToTemplates(fp);
    serviceBreakdown.push({
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      tags: mapping.tags,
      priority: mapping.priority
    });
    for (const tag of mapping.tags) allTags.add(tag);
    if (mapping.specificTemplates) allCves.push(...mapping.specificTemplates);
    if (mapping.priority === 1) highPriority++;
  }
  return {
    totalMapped: serviceBreakdown.length,
    highPriority,
    uniqueTags: [...allTags],
    versionMatchedCves: [...new Set(allCves)],
    serviceBreakdown
  };
}
var PROTOCOL_TAG_MAP, PRODUCT_MAPPINGS, VERSION_CVE_MAPPINGS;
var init_service_template_mapper = __esm({
  "server/lib/service-template-mapper.ts"() {
    PROTOCOL_TAG_MAP = {
      ssh: {
        tags: ["ssh", "openssh", "network", "default-login"],
        networkScan: true,
        priority: 2,
        rationale: "SSH service detected \u2014 scan for weak configs, default creds, known CVEs"
      },
      ftp: {
        tags: ["ftp", "network", "default-login", "anonymous"],
        networkScan: true,
        priority: 2,
        rationale: "FTP service detected \u2014 check anonymous access, weak creds, known vulns"
      },
      smtp: {
        tags: ["smtp", "mail", "network"],
        networkScan: true,
        priority: 3,
        rationale: "SMTP service detected \u2014 check open relay, auth bypass, version vulns"
      },
      mysql: {
        tags: ["mysql", "database", "default-login", "network"],
        networkScan: true,
        priority: 1,
        rationale: "MySQL service detected \u2014 check default creds, exposed management, CVEs"
      },
      mssql: {
        tags: ["mssql", "database", "default-login", "network"],
        networkScan: true,
        priority: 1,
        rationale: "MSSQL service detected \u2014 check default creds, xp_cmdshell, CVEs"
      },
      postgresql: {
        tags: ["postgres", "postgresql", "database", "default-login", "network"],
        networkScan: true,
        priority: 1,
        rationale: "PostgreSQL service detected \u2014 check default creds, trust auth, CVEs"
      },
      redis: {
        tags: ["redis", "database", "network", "unauth"],
        networkScan: true,
        priority: 1,
        rationale: "Redis service detected \u2014 check unauthenticated access, RCE via SLAVEOF"
      },
      mongodb: {
        tags: ["mongodb", "database", "network", "unauth"],
        networkScan: true,
        priority: 1,
        rationale: "MongoDB service detected \u2014 check unauthenticated access, exposed management"
      },
      rdp: {
        tags: ["rdp", "network", "default-login"],
        networkScan: true,
        priority: 2,
        rationale: "RDP service detected \u2014 check BlueKeep, NLA bypass, weak creds"
      },
      smb: {
        tags: ["smb", "network", "default-login", "eternalblue"],
        networkScan: true,
        priority: 1,
        rationale: "SMB service detected \u2014 check EternalBlue, null sessions, shares"
      },
      ldap: {
        tags: ["ldap", "network", "default-login"],
        networkScan: true,
        priority: 2,
        rationale: "LDAP service detected \u2014 check anonymous bind, info disclosure"
      },
      snmp: {
        tags: ["snmp", "network"],
        networkScan: true,
        priority: 3,
        rationale: "SNMP service detected \u2014 check default community strings, info leak"
      },
      vnc: {
        tags: ["vnc", "network", "default-login"],
        networkScan: true,
        priority: 2,
        rationale: "VNC service detected \u2014 check no-auth, weak passwords"
      },
      telnet: {
        tags: ["telnet", "network", "default-login"],
        networkScan: true,
        priority: 2,
        rationale: "Telnet service detected \u2014 check default creds, cleartext auth"
      },
      dns: {
        tags: ["dns", "network"],
        networkScan: true,
        priority: 3,
        rationale: "DNS service detected \u2014 check zone transfer, cache poisoning"
      },
      pop3: {
        tags: ["pop3", "mail", "network"],
        networkScan: true,
        priority: 3,
        rationale: "POP3 service detected \u2014 check cleartext auth, known vulns"
      },
      imap: {
        tags: ["imap", "mail", "network"],
        networkScan: true,
        priority: 3,
        rationale: "IMAP service detected \u2014 check cleartext auth, known vulns"
      }
    };
    PRODUCT_MAPPINGS = [
      // SSH products
      { pattern: /openssh/i, tags: ["openssh"], priorityBoost: 0 },
      { pattern: /dropbear/i, tags: ["dropbear", "iot"], priorityBoost: -1 },
      { pattern: /libssh/i, tags: ["libssh"], priorityBoost: -1 },
      // Web servers (in case fingerprinted on non-standard ports)
      { pattern: /nginx/i, tags: ["nginx"], priorityBoost: 0 },
      { pattern: /apache/i, tags: ["apache"], priorityBoost: 0 },
      { pattern: /iis/i, tags: ["iis", "microsoft"], priorityBoost: 0 },
      { pattern: /lighttpd/i, tags: ["lighttpd"], priorityBoost: 0 },
      { pattern: /tomcat/i, tags: ["tomcat", "java"], priorityBoost: -1 },
      // Databases
      { pattern: /mariadb/i, tags: ["mariadb", "mysql"], priorityBoost: 0 },
      { pattern: /percona/i, tags: ["percona", "mysql"], priorityBoost: 0 },
      { pattern: /cockroachdb/i, tags: ["cockroachdb"], priorityBoost: 0 },
      // Message queues
      { pattern: /rabbitmq/i, tags: ["rabbitmq", "default-login"], priorityBoost: -1 },
      { pattern: /kafka/i, tags: ["kafka"], priorityBoost: 0 },
      { pattern: /activemq/i, tags: ["activemq", "default-login"], priorityBoost: -1 },
      // Monitoring/management
      { pattern: /elasticsearch/i, tags: ["elasticsearch", "elastic", "unauth"], priorityBoost: -1 },
      { pattern: /kibana/i, tags: ["kibana", "elastic"], priorityBoost: -1 },
      { pattern: /grafana/i, tags: ["grafana", "default-login"], priorityBoost: -1 },
      { pattern: /prometheus/i, tags: ["prometheus", "unauth"], priorityBoost: -1 },
      { pattern: /consul/i, tags: ["consul", "hashicorp"], priorityBoost: -1 },
      { pattern: /vault/i, tags: ["vault", "hashicorp"], priorityBoost: -1 },
      { pattern: /etcd/i, tags: ["etcd", "unauth"], priorityBoost: -1 },
      { pattern: /zookeeper/i, tags: ["zookeeper"], priorityBoost: 0 },
      // Container/orchestration
      { pattern: /docker/i, tags: ["docker", "container"], priorityBoost: -1 },
      { pattern: /kubernetes|k8s/i, tags: ["kubernetes", "k8s"], priorityBoost: -1 },
      // CI/CD
      { pattern: /jenkins/i, tags: ["jenkins", "default-login"], priorityBoost: -1 },
      { pattern: /gitlab/i, tags: ["gitlab"], priorityBoost: -1 },
      { pattern: /sonarqube/i, tags: ["sonarqube", "default-login"], priorityBoost: -1 },
      // Misc
      { pattern: /memcached/i, tags: ["memcached", "unauth"], priorityBoost: -1 },
      { pattern: /couchdb/i, tags: ["couchdb", "default-login"], priorityBoost: -1 },
      { pattern: /cassandra/i, tags: ["cassandra"], priorityBoost: 0 },
      { pattern: /proftpd/i, tags: ["proftpd"], priorityBoost: 0 },
      { pattern: /vsftpd/i, tags: ["vsftpd"], priorityBoost: 0 },
      { pattern: /pure-ftpd/i, tags: ["pureftpd"], priorityBoost: 0 },
      { pattern: /postfix/i, tags: ["postfix"], priorityBoost: 0 },
      { pattern: /exim/i, tags: ["exim"], priorityBoost: -1 },
      { pattern: /sendmail/i, tags: ["sendmail"], priorityBoost: 0 },
      { pattern: /dovecot/i, tags: ["dovecot"], priorityBoost: 0 }
    ];
    VERSION_CVE_MAPPINGS = [
      // OpenSSH user enumeration
      {
        product: /openssh/i,
        versionRange: { min: "2.3", max: "7.7" },
        cves: ["CVE-2018-15473"],
        tags: ["cve-2018-15473"]
      },
      // OpenSSH regreSSHion
      {
        product: /openssh/i,
        versionRange: { min: "8.5", max: "9.7" },
        cves: ["CVE-2024-6387"],
        tags: ["cve-2024-6387", "regresshion"]
      },
      // ProFTPD RCE
      {
        product: /proftpd/i,
        versionRange: { min: "1.3.0", max: "1.3.5" },
        cves: ["CVE-2015-3306"],
        tags: ["cve-2015-3306"]
      },
      // vsftpd backdoor
      {
        product: /vsftpd/i,
        versionRange: { min: "2.3.4", max: "2.3.4" },
        cves: ["CVE-2011-2523"],
        tags: ["cve-2011-2523"]
      },
      // Redis unauthenticated RCE
      {
        product: /redis/i,
        versionRange: { min: "2.0", max: "5.0.5" },
        cves: ["CVE-2022-0543"],
        tags: ["cve-2022-0543"]
      },
      // Exim RCE
      {
        product: /exim/i,
        versionRange: { min: "4.87", max: "4.91" },
        cves: ["CVE-2019-10149"],
        tags: ["cve-2019-10149"]
      },
      // SMB EternalBlue
      {
        product: /samba|smb/i,
        versionRange: { min: "1.0", max: "3.5.22" },
        cves: ["CVE-2017-7494"],
        tags: ["cve-2017-7494", "sambacry"]
      },
      // Elasticsearch RCE
      {
        product: /elasticsearch/i,
        versionRange: { min: "1.0", max: "1.4.2" },
        cves: ["CVE-2015-1427"],
        tags: ["cve-2015-1427"]
      },
      // MongoDB unauthenticated
      {
        product: /mongodb/i,
        versionRange: { min: "2.0", max: "3.6" },
        cves: [],
        tags: ["mongodb-unauth"]
      }
    ];
  }
});
init_service_template_mapper();
export {
  generateServiceScanTasks,
  getServiceBasedTags,
  getTemplateMappingSummary,
  mapServiceToTemplates
};
