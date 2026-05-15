import {
  getDb,
  init_db
} from "./chunk-TY7YEWON.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-2DDCINQV.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cpe-dictionary-updater.ts
import { sql } from "drizzle-orm";
async function nvdCpeRateLimit() {
  const now = Date.now();
  const elapsed = now - lastNvdCpeRequest;
  if (elapsed < NVD_RATE_LIMIT_MS) {
    await new Promise((resolve) => setTimeout(resolve, NVD_RATE_LIMIT_MS - elapsed));
  }
  lastNvdCpeRequest = Date.now();
}
async function searchNvdCpeDictionary(keyword, maxResults = 20) {
  await nvdCpeRateLimit();
  try {
    const url = `${NVD_CPE_API}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${maxResults}`;
    const res = await fetch(url, {
      headers: { "User-Agent": "AC3-CPEUpdater/1.0" },
      signal: AbortSignal.timeout(15e3)
    });
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        console.warn(`[CPEUpdater] NVD rate limited (${res.status})`);
        return [];
      }
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    const products = data.products || [];
    return products.filter((p) => p.cpe?.cpeName).map((p) => {
      const parts = p.cpe.cpeName.split(":");
      return {
        cpeUri: p.cpe.cpeName,
        vendor: parts[3] || "",
        product: parts[4] || "",
        title: p.cpe.titles?.[0]?.title || ""
      };
    }).filter((entry) => entry.vendor && entry.product);
  } catch (err) {
    console.error(`[CPEUpdater] NVD CPE search failed for "${keyword}": ${err.message}`);
    return [];
  }
}
function seedDictionary() {
  for (const [tech, mapping] of Object.entries(STATIC_SEED)) {
    extendedDictionary.set(tech.toLowerCase(), {
      technology: tech,
      vendor: mapping.vendor,
      product: mapping.product,
      source: "static",
      discoveredAt: 0,
      lastVerifiedAt: 0,
      nvdCpeUri: `cpe:2.3:a:${mapping.vendor}:${mapping.product}:*:*:*:*:*:*:*:*`,
      knownCveCount: 0
    });
  }
}
async function runDictionaryUpdate() {
  const startTime = Date.now();
  let newMappings = 0;
  let updatedMappings = 0;
  let failedLookups = 0;
  const errors = [];
  console.log(`[CPEUpdater] Starting dictionary update. ${unmappedTechnologies.size} unmapped technologies to resolve.`);
  const unmappedList = Array.from(unmappedTechnologies);
  for (const tech of unmappedList) {
    try {
      const results = await searchNvdCpeDictionary(tech, 5);
      if (results.length > 0) {
        const best = results[0];
        extendedDictionary.set(tech.toLowerCase(), {
          technology: tech,
          vendor: best.vendor,
          product: best.product,
          source: "nvd_api",
          discoveredAt: Date.now(),
          lastVerifiedAt: Date.now(),
          nvdCpeUri: best.cpeUri,
          knownCveCount: 0
        });
        unmappedTechnologies.delete(tech);
        newMappings++;
        console.log(`[CPEUpdater] Discovered mapping: ${tech} \u2192 ${best.vendor}:${best.product}`);
      } else {
        failedLookups++;
      }
    } catch (err) {
      errors.push(`Failed to resolve "${tech}": ${err.message}`);
      failedLookups++;
    }
  }
  const staleThreshold = Date.now() - 7 * 24 * 60 * 60 * 1e3;
  const staleEntries = Array.from(extendedDictionary.values()).filter((e) => e.source === "nvd_api" && e.lastVerifiedAt < staleThreshold);
  for (const entry of staleEntries.slice(0, 20)) {
    try {
      const results = await searchNvdCpeDictionary(entry.technology, 3);
      if (results.length > 0) {
        const best = results[0];
        entry.vendor = best.vendor;
        entry.product = best.product;
        entry.lastVerifiedAt = Date.now();
        entry.nvdCpeUri = best.cpeUri;
        updatedMappings++;
      }
    } catch (err) {
      errors.push(`Failed to verify "${entry.technology}": ${err.message}`);
    }
  }
  try {
    await persistDictionary();
  } catch (err) {
    errors.push(`Failed to persist dictionary: ${err.message}`);
  }
  const duration = Date.now() - startTime;
  lastUpdateTime = Date.now();
  lastUpdateDuration = duration;
  updateHistory.push({ time: Date.now(), newMappings, updatedMappings, duration });
  if (updateHistory.length > 50) updateHistory.shift();
  console.log(
    `[CPEUpdater] Update complete in ${Math.round(duration / 1e3)}s: ${newMappings} new, ${updatedMappings} updated, ${failedLookups} failed. Dictionary size: ${extendedDictionary.size}`
  );
  return { newMappings, updatedMappings, failedLookups, duration, errors };
}
async function persistDictionary() {
  const nvdEntries = Array.from(extendedDictionary.values()).filter((e) => e.source === "nvd_api" || e.source === "manual");
  if (nvdEntries.length === 0) return;
  const payload = JSON.stringify(nvdEntries);
  try {
    const db = await getDb();
    await db.execute(sql`
      INSERT INTO system_settings (setting_key, setting_value, updated_at)
      VALUES ('cpe_dictionary_extensions', ${payload}, NOW())
      ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
    `);
    console.log(`[CPEUpdater] Persisted ${nvdEntries.length} dictionary extensions to database`);
  } catch (err) {
    if (err.message?.includes("doesn't exist")) {
      try {
        const db2 = await getDb();
        await db2.execute(sql`
          CREATE TABLE IF NOT EXISTS system_settings (
            setting_key VARCHAR(255) PRIMARY KEY,
            setting_value LONGTEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `);
        await db2.execute(sql`
          INSERT INTO system_settings (setting_key, setting_value, updated_at)
          VALUES ('cpe_dictionary_extensions', ${payload}, NOW())
          ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
        `);
        console.log(`[CPEUpdater] Created system_settings table and persisted ${nvdEntries.length} entries`);
      } catch (innerErr) {
        console.error(`[CPEUpdater] Failed to create system_settings table: ${innerErr.message}`);
      }
    } else {
      throw err;
    }
  }
}
async function loadPersistedDictionary() {
  try {
    const db = await getDb();
    const rows = await db.execute(sql`
      SELECT setting_value FROM system_settings WHERE setting_key = 'cpe_dictionary_extensions'
    `);
    const row = rows?.rows?.[0] || rows?.[0];
    if (!row?.setting_value) return;
    const entries = JSON.parse(row.setting_value);
    let loaded = 0;
    for (const entry of entries) {
      const key = entry.technology.toLowerCase();
      if (!extendedDictionary.has(key) || extendedDictionary.get(key).source !== "static") {
        extendedDictionary.set(key, entry);
        loaded++;
      }
    }
    console.log(`[CPEUpdater] Loaded ${loaded} persisted dictionary extensions from database`);
  } catch (err) {
    const msg = (err.message || "") + (err.sqlMessage || "") + (err.cause?.message || "");
    const isTableMissing = msg.includes("doesn't exist") || msg.includes("ER_NO_SUCH_TABLE") || msg.includes("1146");
    if (!isTableMissing) {
      console.warn(`[CPEUpdater] Failed to load persisted dictionary: ${err.message}`);
    } else {
      try {
        const db2 = await getDb();
        await db2.execute(sql`
          CREATE TABLE IF NOT EXISTS system_settings (
            setting_key VARCHAR(255) PRIMARY KEY,
            setting_value LONGTEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `);
        console.log(`[CPEUpdater] Created system_settings table (first run)`);
      } catch {
      }
    }
  }
}
function lookupCpe(technology) {
  const key = technology.toLowerCase().trim();
  const exact = extendedDictionary.get(key);
  if (exact) return exact;
  for (const [dictKey, entry] of extendedDictionary) {
    if (key.includes(dictKey) || dictKey.includes(key)) {
      return entry;
    }
  }
  return null;
}
function registerUnmappedTechnology(technology) {
  const key = technology.toLowerCase().trim();
  if (!extendedDictionary.has(key) && key.length > 1) {
    unmappedTechnologies.add(key);
  }
}
function addManualMapping(technology, vendor, product) {
  extendedDictionary.set(technology.toLowerCase(), {
    technology,
    vendor,
    product,
    source: "manual",
    discoveredAt: Date.now(),
    lastVerifiedAt: Date.now(),
    nvdCpeUri: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`,
    knownCveCount: 0
  });
}
function getDictionaryStats() {
  const entries = Array.from(extendedDictionary.values());
  return {
    totalEntries: entries.length,
    staticEntries: entries.filter((e) => e.source === "static").length,
    nvdDiscoveredEntries: entries.filter((e) => e.source === "nvd_api").length,
    manualEntries: entries.filter((e) => e.source === "manual").length,
    lastUpdateTime,
    lastUpdateDuration,
    unmappedTechnologies: Array.from(unmappedTechnologies),
    nextScheduledUpdate,
    updateHistory: updateHistory.slice(-10)
  };
}
function getDictionaryEntries() {
  return Array.from(extendedDictionary.values());
}
function startAutoUpdate(intervalMs = 12 * 60 * 60 * 1e3) {
  if (updateInterval) {
    clearInterval(updateInterval);
  }
  loadPersistedDictionary().catch((err) => {
    console.warn(`[CPEUpdater] Failed to load persisted dictionary on startup: ${err.message}`);
  });
  nextScheduledUpdate = Date.now() + intervalMs;
  updateInterval = setInterval(async () => {
    try {
      await runDictionaryUpdate();
      nextScheduledUpdate = Date.now() + intervalMs;
    } catch (err) {
      console.error(`[CPEUpdater] Scheduled update failed: ${err.message}`);
      nextScheduledUpdate = Date.now() + intervalMs;
    }
  }, intervalMs);
  console.log(`[CPEUpdater] Auto-update started. Interval: ${Math.round(intervalMs / 36e5)}h. Dictionary size: ${extendedDictionary.size}`);
  setTimeout(() => {
    runDictionaryUpdate().catch((err) => {
      console.error(`[CPEUpdater] Initial update failed: ${err.message}`);
    });
  }, 3e4);
}
function stopAutoUpdate() {
  if (updateInterval) {
    clearInterval(updateInterval);
    updateInterval = null;
    nextScheduledUpdate = 0;
    console.log("[CPEUpdater] Auto-update stopped");
  }
}
var NVD_CPE_API, NVD_RATE_LIMIT_MS, lastNvdCpeRequest, extendedDictionary, unmappedTechnologies, updateHistory, lastUpdateTime, lastUpdateDuration, updateInterval, nextScheduledUpdate, STATIC_SEED;
var init_cpe_dictionary_updater = __esm({
  "server/lib/cpe-dictionary-updater.ts"() {
    init_db();
    NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    NVD_RATE_LIMIT_MS = 6500;
    lastNvdCpeRequest = 0;
    extendedDictionary = /* @__PURE__ */ new Map();
    unmappedTechnologies = /* @__PURE__ */ new Set();
    updateHistory = [];
    lastUpdateTime = 0;
    lastUpdateDuration = 0;
    updateInterval = null;
    nextScheduledUpdate = 0;
    STATIC_SEED = {
      apache: { vendor: "apache", product: "http_server" },
      "apache httpd": { vendor: "apache", product: "http_server" },
      "apache tomcat": { vendor: "apache", product: "tomcat" },
      nginx: { vendor: "nginx", product: "nginx" },
      iis: { vendor: "microsoft", product: "internet_information_services" },
      "microsoft iis": { vendor: "microsoft", product: "internet_information_services" },
      lighttpd: { vendor: "lighttpd", product: "lighttpd" },
      caddy: { vendor: "caddyserver", product: "caddy" },
      haproxy: { vendor: "haproxy", product: "haproxy" },
      envoy: { vendor: "envoyproxy", product: "envoy" },
      wordpress: { vendor: "wordpress", product: "wordpress" },
      drupal: { vendor: "drupal", product: "drupal" },
      "joomla": { vendor: "joomla\\!", product: "joomla\\!" },
      exchange: { vendor: "microsoft", product: "exchange_server" },
      sharepoint: { vendor: "microsoft", product: "sharepoint_server" },
      openssh: { vendor: "openbsd", product: "openssh" },
      openssl: { vendor: "openssl", product: "openssl" },
      php: { vendor: "php", product: "php" },
      mysql: { vendor: "oracle", product: "mysql" },
      postgresql: { vendor: "postgresql", product: "postgresql" },
      mssql: { vendor: "microsoft", product: "sql_server" },
      "sql server": { vendor: "microsoft", product: "sql_server" },
      log4j: { vendor: "apache", product: "log4j" },
      "spring framework": { vendor: "vmware", product: "spring_framework" },
      "spring boot": { vendor: "vmware", product: "spring_boot" },
      jenkins: { vendor: "jenkins", product: "jenkins" },
      gitlab: { vendor: "gitlab", product: "gitlab" },
      confluence: { vendor: "atlassian", product: "confluence_server" },
      jira: { vendor: "atlassian", product: "jira" },
      "cisco ios": { vendor: "cisco", product: "ios" },
      "cisco asa": { vendor: "cisco", product: "adaptive_security_appliance_software" },
      fortios: { vendor: "fortinet", product: "fortios" },
      fortigate: { vendor: "fortinet", product: "fortios" },
      "palo alto pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
      "pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
      junos: { vendor: "juniper", product: "junos" },
      sonicwall: { vendor: "sonicwall", product: "sma" },
      "pulse secure": { vendor: "ivanti", product: "connect_secure" },
      "citrix adc": { vendor: "citrix", product: "application_delivery_controller_firmware" },
      "citrix netscaler": { vendor: "citrix", product: "netscaler_application_delivery_controller" },
      "vmware vcenter": { vendor: "vmware", product: "vcenter_server" },
      "vmware esxi": { vendor: "vmware", product: "esxi" },
      veeam: { vendor: "veeam", product: "backup_\\&_replication" },
      zimbra: { vendor: "zimbra", product: "collaboration" },
      "solarwinds orion": { vendor: "solarwinds", product: "orion_platform" },
      moveit: { vendor: "progress", product: "moveit_transfer" },
      "barracuda esg": { vendor: "barracuda", product: "email_security_gateway" },
      chrome: { vendor: "google", product: "chrome" },
      firefox: { vendor: "mozilla", product: "firefox" },
      edge: { vendor: "microsoft", product: "edge" },
      java: { vendor: "oracle", product: "jdk" },
      "node.js": { vendor: "nodejs", product: "node.js" },
      redis: { vendor: "redis", product: "redis" },
      mongodb: { vendor: "mongodb", product: "mongodb" },
      elasticsearch: { vendor: "elastic", product: "elasticsearch" },
      docker: { vendor: "docker", product: "docker" },
      kubernetes: { vendor: "kubernetes", product: "kubernetes" },
      grafana: { vendor: "grafana", product: "grafana" },
      prometheus: { vendor: "prometheus", product: "prometheus" },
      // Additional common products not in the original static list
      "apache struts": { vendor: "apache", product: "struts" },
      "apache kafka": { vendor: "apache", product: "kafka" },
      "apache solr": { vendor: "apache", product: "solr" },
      "apache activemq": { vendor: "apache", product: "activemq" },
      "apache airflow": { vendor: "apache", product: "airflow" },
      rabbitmq: { vendor: "vmware", product: "rabbitmq" },
      memcached: { vendor: "memcached", product: "memcached" },
      postfix: { vendor: "postfix", product: "postfix" },
      exim: { vendor: "exim", product: "exim" },
      dovecot: { vendor: "dovecot", product: "dovecot" },
      bind: { vendor: "isc", product: "bind" },
      "isc bind": { vendor: "isc", product: "bind" },
      proftpd: { vendor: "proftpd", product: "proftpd" },
      vsftpd: { vendor: "vsftpd_project", product: "vsftpd" },
      samba: { vendor: "samba", product: "samba" },
      squid: { vendor: "squid-cache", product: "squid" },
      "hashicorp vault": { vendor: "hashicorp", product: "vault" },
      terraform: { vendor: "hashicorp", product: "terraform" },
      ansible: { vendor: "redhat", product: "ansible" },
      puppet: { vendor: "puppet", product: "puppet" },
      nagios: { vendor: "nagios", product: "nagios" },
      zabbix: { vendor: "zabbix", product: "zabbix" },
      splunk: { vendor: "splunk", product: "splunk" },
      kibana: { vendor: "elastic", product: "kibana" },
      logstash: { vendor: "elastic", product: "logstash" },
      keycloak: { vendor: "redhat", product: "keycloak" },
      nextcloud: { vendor: "nextcloud", product: "nextcloud_server" },
      owncloud: { vendor: "owncloud", product: "owncloud" },
      mattermost: { vendor: "mattermost", product: "mattermost_server" },
      rocketchat: { vendor: "rocket.chat", product: "rocket.chat" },
      sonarqube: { vendor: "sonarsource", product: "sonarqube" },
      nexus: { vendor: "sonatype", product: "nexus_repository_manager" },
      artifactory: { vendor: "jfrog", product: "artifactory" },
      harbor: { vendor: "goharbor", product: "harbor" },
      traefik: { vendor: "traefik", product: "traefik" },
      consul: { vendor: "hashicorp", product: "consul" },
      etcd: { vendor: "etcd-io", product: "etcd" },
      cockroachdb: { vendor: "cockroachlabs", product: "cockroachdb" },
      mariadb: { vendor: "mariadb", product: "mariadb" },
      couchdb: { vendor: "apache", product: "couchdb" },
      cassandra: { vendor: "apache", product: "cassandra" },
      neo4j: { vendor: "neo4j", product: "neo4j" },
      influxdb: { vendor: "influxdata", product: "influxdb" },
      "microsoft .net": { vendor: "microsoft", product: ".net" },
      "asp.net": { vendor: "microsoft", product: "asp.net_core" },
      flask: { vendor: "palletsprojects", product: "flask" },
      django: { vendor: "djangoproject", product: "django" },
      rails: { vendor: "rubyonrails", product: "rails" },
      "ruby on rails": { vendor: "rubyonrails", product: "rails" },
      laravel: { vendor: "laravel", product: "laravel" },
      express: { vendor: "expressjs", product: "express" }
    };
    seedDictionary();
  }
});
init_cpe_dictionary_updater();
export {
  addManualMapping,
  getDictionaryEntries,
  getDictionaryStats,
  lookupCpe,
  registerUnmappedTechnology,
  runDictionaryUpdate,
  startAutoUpdate,
  stopAutoUpdate
};
