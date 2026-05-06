import {
  getDb,
  init_db
} from "./chunk-CEPCIPS7.js";
import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/version-threshold-service.ts
var version_threshold_service_exports = {};
__export(version_threshold_service_exports, {
  _testing: () => _testing,
  deleteThreshold: () => deleteThreshold,
  getAllThresholds: () => getAllThresholds,
  getMinSafeVersion: () => getMinSafeVersion,
  getNvdApiKeyStatus: () => getNvdApiKeyStatus,
  getThresholdStats: () => getThresholdStats,
  hasNvdApiKey: () => hasNvdApiKey,
  learnFromDiScan: () => learnFromDiScan,
  refreshFromNvd: () => refreshFromNvd,
  setManualThreshold: () => setManualThreshold,
  startAutoRefresh: () => startAutoRefresh,
  stopAutoRefresh: () => stopAutoRefresh
});
import { sql } from "drizzle-orm";
function getNvdApiKey() {
  return process.env.NVD_API_KEY || null;
}
function hasNvdApiKey() {
  return !!getNvdApiKey();
}
function getNvdApiKeyStatus() {
  const hasKey = hasNvdApiKey();
  const rateLimitMs = hasKey ? NVD_RATE_LIMIT_WITH_KEY_MS : NVD_RATE_LIMIT_NO_KEY_MS;
  return {
    configured: hasKey,
    rateLimitMs,
    requestsPerMinute: Math.floor(6e4 / rateLimitMs)
  };
}
async function nvdRateLimit() {
  const rateLimitMs = hasNvdApiKey() ? NVD_RATE_LIMIT_WITH_KEY_MS : NVD_RATE_LIMIT_NO_KEY_MS;
  const now = Date.now();
  const elapsed = now - lastNvdRequest;
  if (elapsed < rateLimitMs) {
    await new Promise((resolve) => setTimeout(resolve, rateLimitMs - elapsed));
  }
  lastNvdRequest = Date.now();
}
async function queryNvdForLatestAffectedVersion(cpeVendor, cpeProduct, maxResults = 20) {
  await nvdRateLimit();
  try {
    const cpeName = `cpe:2.3:a:${cpeVendor}:${cpeProduct}`;
    const url = `${NVD_CVE_API}?cpeName=${encodeURIComponent(cpeName)}:*&resultsPerPage=${maxResults}&cvssV3Severity=HIGH`;
    const headers = { "User-Agent": "AC3-VersionThresholdService/1.0" };
    const apiKey = getNvdApiKey();
    if (apiKey) headers["apiKey"] = apiKey;
    const res = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(15e3)
    });
    if (!res.ok) {
      if (res.status === 403 || res.status === 429) {
        console.warn(`[VersionThreshold] NVD rate limited (${res.status}) for ${cpeVendor}:${cpeProduct}`);
        return null;
      }
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    if (vulnerabilities.length === 0) return null;
    let highestAffectedVersion = null;
    let latestCveId = null;
    let latestCveCvss = null;
    for (const vuln of vulnerabilities) {
      const cve = vuln.cve;
      if (!cve) continue;
      const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvss = cvssV31 || cvssV30;
      const score = cvss?.baseScore || 0;
      if (score < 7) continue;
      const configs = cve.configurations || [];
      for (const config of configs) {
        const nodes = config.nodes || [];
        for (const node of nodes) {
          const cpeMatches = node.cpeMatch || [];
          for (const match of cpeMatches) {
            if (!match.vulnerable) continue;
            const criteria = (match.criteria || "").toLowerCase();
            if (!criteria.includes(cpeVendor) || !criteria.includes(cpeProduct)) continue;
            const endIncluding = match.versionEndIncluding;
            const endExcluding = match.versionEndExcluding;
            const affectedEnd = endIncluding || endExcluding;
            if (affectedEnd && isValidVersion(affectedEnd)) {
              if (!highestAffectedVersion || compareSemver(affectedEnd, highestAffectedVersion) > 0) {
                highestAffectedVersion = affectedEnd;
                latestCveId = cve.id;
                latestCveCvss = score;
              }
            }
          }
        }
      }
    }
    if (!highestAffectedVersion) return null;
    const minSafe = bumpPatchVersion(highestAffectedVersion);
    return {
      highestAffectedVersion,
      latestCveId,
      latestCveCvss,
      minSafeVersion: minSafe
    };
  } catch (err) {
    console.error(`[VersionThreshold] NVD query failed for ${cpeVendor}:${cpeProduct}: ${err.message}`);
    return null;
  }
}
function isValidVersion(v) {
  return /^\d+(\.\d+)*$/.test(v.replace(/^v/i, ""));
}
function compareSemver(a, b) {
  const pa = a.replace(/^v/i, "").split(".").map(Number);
  const pb = b.replace(/^v/i, "").split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const va = pa[i] || 0;
    const vb = pb[i] || 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}
function bumpPatchVersion(version) {
  const parts = version.split(".").map(Number);
  if (parts.length === 0) return version;
  parts[parts.length - 1] += 1;
  return parts.join(".");
}
function getMinSafeVersion(tech) {
  const key = tech.toLowerCase();
  const dynamic = dynamicThresholds.get(key);
  if (dynamic) return dynamic.minSafeVersion;
  return STATIC_MIN_SAFE[key] || null;
}
function getAllThresholds() {
  const result = /* @__PURE__ */ new Map();
  for (const [tech, version] of Object.entries(STATIC_MIN_SAFE)) {
    result.set(tech, {
      technology: tech,
      minSafeVersion: version,
      source: "static",
      lastUpdated: 0
    });
  }
  for (const [tech, threshold] of dynamicThresholds) {
    result.set(tech, threshold);
  }
  return Array.from(result.values()).sort(
    (a, b) => a.technology.localeCompare(b.technology)
  );
}
async function refreshFromNvd(techKeys) {
  const startTime = Date.now();
  const result = {
    updated: 0,
    added: 0,
    unchanged: 0,
    errors: [],
    duration: 0,
    sources: { nvd: 0, diScan: 0, manual: 0 }
  };
  const keysToRefresh = techKeys || Object.keys(TECH_TO_CPE);
  console.log(`[VersionThreshold] Starting NVD refresh for ${keysToRefresh.length} technologies...`);
  for (const tech of keysToRefresh) {
    const cpe = TECH_TO_CPE[tech.toLowerCase()];
    if (!cpe) {
      result.unchanged++;
      continue;
    }
    try {
      const nvdResult = await queryNvdForLatestAffectedVersion(cpe.vendor, cpe.product);
      if (!nvdResult || !nvdResult.minSafeVersion) {
        result.unchanged++;
        continue;
      }
      const key = tech.toLowerCase();
      const existing = dynamicThresholds.get(key);
      const currentMinSafe = existing?.minSafeVersion || STATIC_MIN_SAFE[key];
      if (currentMinSafe && compareSemver(nvdResult.minSafeVersion, currentMinSafe) <= 0) {
        result.unchanged++;
        continue;
      }
      const threshold = {
        technology: key,
        minSafeVersion: nvdResult.minSafeVersion,
        source: "nvd_cve",
        lastUpdated: Date.now(),
        cpeVendor: cpe.vendor,
        cpeProduct: cpe.product,
        latestCveId: nvdResult.latestCveId || void 0,
        latestCveCvss: nvdResult.latestCveCvss || void 0,
        highestAffectedVersion: nvdResult.highestAffectedVersion || void 0,
        notes: `Auto-updated from NVD CVE ${nvdResult.latestCveId} (CVSS ${nvdResult.latestCveCvss})`
      };
      dynamicThresholds.set(key, threshold);
      result.sources.nvd++;
      if (existing) {
        result.updated++;
        console.log(`[VersionThreshold] Updated ${key}: ${existing.minSafeVersion} \u2192 ${nvdResult.minSafeVersion} (${nvdResult.latestCveId})`);
      } else {
        result.added++;
        console.log(`[VersionThreshold] Added ${key}: ${nvdResult.minSafeVersion} (${nvdResult.latestCveId})`);
      }
    } catch (err) {
      result.errors.push(`${tech}: ${err.message}`);
    }
  }
  result.duration = Date.now() - startTime;
  lastRefreshTime = Date.now();
  lastRefreshDuration = result.duration;
  refreshHistory.push({
    time: lastRefreshTime,
    updated: result.updated,
    added: result.added,
    duration: result.duration
  });
  if (refreshHistory.length > 50) refreshHistory.shift();
  await persistThresholds();
  console.log(
    `[VersionThreshold] NVD refresh complete in ${Math.round(result.duration / 1e3)}s: ${result.added} added, ${result.updated} updated, ${result.unchanged} unchanged, ${result.errors.length} errors`
  );
  return result;
}
function learnFromDiScan(detectedTechnologies) {
  const updated = [];
  const skipped = [];
  for (const tech of detectedTechnologies) {
    if (!tech.version || !isValidVersion(tech.version)) {
      skipped.push(tech.name);
      continue;
    }
    const key = tech.name.toLowerCase();
    const currentMinSafe = getMinSafeVersion(key);
    if (!currentMinSafe) {
      skipped.push(tech.name);
      continue;
    }
    const cleanVer = tech.version.replace(/^v/i, "");
    if (compareSemver(cleanVer, currentMinSafe) < 0) {
      skipped.push(tech.name);
      continue;
    }
    const currentParts = currentMinSafe.split(".").map(Number);
    const detectedParts = cleanVer.split(".").map(Number);
    const majorDiff = (detectedParts[0] || 0) - (currentParts[0] || 0);
    const minorDiff = (detectedParts[1] || 0) - (currentParts[1] || 0);
    if (majorDiff > 0 || majorDiff === 0 && minorDiff >= 2) {
      const newMinSafe = `${detectedParts[0]}.${Math.max(0, (detectedParts[1] || 0) - 1)}.0`;
      if (compareSemver(newMinSafe, currentMinSafe) > 0) {
        const threshold = {
          technology: key,
          minSafeVersion: newMinSafe,
          source: "di_scan",
          lastUpdated: Date.now(),
          notes: `Auto-bumped from DI scan: detected v${cleanVer} in the wild`
        };
        dynamicThresholds.set(key, threshold);
        updated.push(`${tech.name}: ${currentMinSafe} \u2192 ${newMinSafe} (detected v${cleanVer})`);
      } else {
        skipped.push(tech.name);
      }
    } else {
      skipped.push(tech.name);
    }
  }
  if (updated.length > 0) {
    console.log(`[VersionThreshold] DI scan learning: ${updated.length} thresholds bumped`);
    persistThresholds().catch(
      (err) => console.error(`[VersionThreshold] Failed to persist after DI scan learning: ${err.message}`)
    );
  }
  return { updated, skipped };
}
function setManualThreshold(technology, minSafeVersion, notes) {
  const key = technology.toLowerCase();
  const threshold = {
    technology: key,
    minSafeVersion,
    source: "manual",
    lastUpdated: Date.now(),
    notes: notes || "Manually set by admin"
  };
  dynamicThresholds.set(key, threshold);
  persistThresholds().catch(
    (err) => console.error(`[VersionThreshold] Failed to persist manual threshold: ${err.message}`)
  );
  return threshold;
}
function deleteThreshold(technology) {
  const key = technology.toLowerCase();
  const deleted = dynamicThresholds.delete(key);
  if (deleted) {
    persistThresholds().catch(
      (err) => console.error(`[VersionThreshold] Failed to persist after delete: ${err.message}`)
    );
  }
  return deleted;
}
function getThresholdStats() {
  const all = getAllThresholds();
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1e3;
  const bySource = { static: 0, nvd_cve: 0, di_scan: 0, manual: 0 };
  let staleCount = 0;
  for (const t of all) {
    bySource[t.source]++;
    if (t.source !== "static" && t.lastUpdated < thirtyDaysAgo) {
      staleCount++;
    }
  }
  return {
    totalThresholds: all.length,
    bySource,
    lastRefreshTime,
    lastRefreshDuration,
    nextScheduledRefresh,
    refreshHistory: [...refreshHistory],
    staleThresholds: staleCount
  };
}
async function persistThresholds() {
  try {
    const db = await getDb();
    const entries = Array.from(dynamicThresholds.values());
    const payload = JSON.stringify(entries);
    await db.execute(sql`
      INSERT INTO system_settings (setting_key, setting_value, updated_at)
      VALUES ('version_thresholds', ${payload}, NOW())
      ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
    `);
    console.log(`[VersionThreshold] Persisted ${entries.length} dynamic thresholds to database`);
  } catch (err) {
    try {
      const db = await getDb();
      await db.execute(sql`
        CREATE TABLE IF NOT EXISTS system_settings (
          setting_key VARCHAR(255) PRIMARY KEY,
          setting_value LONGTEXT,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      const entries = Array.from(dynamicThresholds.values());
      const payload = JSON.stringify(entries);
      await db.execute(sql`
        INSERT INTO system_settings (setting_key, setting_value, updated_at)
        VALUES ('version_thresholds', ${payload}, NOW())
        ON DUPLICATE KEY UPDATE setting_value = ${payload}, updated_at = NOW()
      `);
      console.log(`[VersionThreshold] Created system_settings table and persisted ${entries.length} entries`);
    } catch (innerErr) {
      console.error(`[VersionThreshold] Failed to persist thresholds: ${innerErr.message}`);
    }
  }
}
async function loadPersistedThresholds() {
  try {
    const db = await getDb();
    const rows = await db.execute(sql`
      SELECT setting_value FROM system_settings WHERE setting_key = 'version_thresholds'
    `);
    const row = rows?.[0]?.[0] || rows?.[0];
    if (!row?.setting_value) return 0;
    const entries = JSON.parse(row.setting_value);
    let loaded = 0;
    for (const entry of entries) {
      if (entry.technology && entry.minSafeVersion) {
        dynamicThresholds.set(entry.technology.toLowerCase(), entry);
        loaded++;
      }
    }
    console.log(`[VersionThreshold] Loaded ${loaded} persisted thresholds from database`);
    return loaded;
  } catch (err) {
    console.warn(`[VersionThreshold] Failed to load persisted thresholds: ${err.message}`);
    return 0;
  }
}
async function startAutoRefresh(intervalMs = 24 * 60 * 60 * 1e3) {
  await loadPersistedThresholds();
  if (refreshInterval) clearInterval(refreshInterval);
  nextScheduledRefresh = Date.now() + intervalMs;
  refreshInterval = setInterval(async () => {
    try {
      nextScheduledRefresh = Date.now() + intervalMs;
      await refreshFromNvd();
    } catch (err) {
      console.error(`[VersionThreshold] Scheduled refresh failed: ${err.message}`);
    }
  }, intervalMs);
  console.log(
    `[VersionThreshold] Auto-refresh started. Interval: ${Math.round(intervalMs / 36e5)}h. Dynamic thresholds: ${dynamicThresholds.size}, Static fallback: ${Object.keys(STATIC_MIN_SAFE).length}`
  );
  if (Date.now() - lastRefreshTime > 12 * 60 * 60 * 1e3) {
    refreshFromNvd().catch(
      (err) => console.error(`[VersionThreshold] Initial refresh failed: ${err.message}`)
    );
  }
}
function stopAutoRefresh() {
  if (refreshInterval) {
    clearInterval(refreshInterval);
    refreshInterval = null;
    nextScheduledRefresh = 0;
    console.log("[VersionThreshold] Auto-refresh stopped");
  }
}
var NVD_CVE_API, NVD_RATE_LIMIT_NO_KEY_MS, NVD_RATE_LIMIT_WITH_KEY_MS, lastNvdRequest, TECH_TO_CPE, dynamicThresholds, lastRefreshTime, lastRefreshDuration, refreshInterval, nextScheduledRefresh, refreshHistory, STATIC_MIN_SAFE, _testing;
var init_version_threshold_service = __esm({
  "server/lib/version-threshold-service.ts"() {
    init_db();
    NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    NVD_RATE_LIMIT_NO_KEY_MS = 6500;
    NVD_RATE_LIMIT_WITH_KEY_MS = 600;
    lastNvdRequest = 0;
    TECH_TO_CPE = {
      nginx: { vendor: "nginx", product: "nginx" },
      apache: { vendor: "apache", product: "http_server" },
      "apache http server": { vendor: "apache", product: "http_server" },
      "apache httpd": { vendor: "apache", product: "http_server" },
      "apache tomcat": { vendor: "apache", product: "tomcat" },
      iis: { vendor: "microsoft", product: "internet_information_services" },
      lighttpd: { vendor: "lighttpd", product: "lighttpd" },
      caddy: { vendor: "caddyserver", product: "caddy" },
      php: { vendor: "php", product: "php" },
      "node.js": { vendor: "nodejs", product: "node.js" },
      nodejs: { vendor: "nodejs", product: "node.js" },
      python: { vendor: "python", product: "python" },
      java: { vendor: "oracle", product: "jdk" },
      ruby: { vendor: "ruby-lang", product: "ruby" },
      mysql: { vendor: "oracle", product: "mysql" },
      mariadb: { vendor: "mariadb", product: "mariadb" },
      postgresql: { vendor: "postgresql", product: "postgresql" },
      mongodb: { vendor: "mongodb", product: "mongodb" },
      redis: { vendor: "redis", product: "redis" },
      wordpress: { vendor: "wordpress", product: "wordpress" },
      drupal: { vendor: "drupal", product: "drupal" },
      joomla: { vendor: "joomla", product: "joomla\\!" },
      jquery: { vendor: "jquery", product: "jquery" },
      react: { vendor: "facebook", product: "react" },
      angular: { vendor: "google", product: "angular" },
      vue: { vendor: "vuejs", product: "vue.js" },
      django: { vendor: "djangoproject", product: "django" },
      laravel: { vendor: "laravel", product: "laravel" },
      spring: { vendor: "vmware", product: "spring_framework" },
      "spring boot": { vendor: "vmware", product: "spring_boot" },
      express: { vendor: "expressjs", product: "express" },
      openssl: { vendor: "openssl", product: "openssl" },
      exchange: { vendor: "microsoft", product: "exchange_server" },
      postfix: { vendor: "postfix", product: "postfix" },
      docker: { vendor: "docker", product: "docker" },
      kubernetes: { vendor: "kubernetes", product: "kubernetes" },
      openssh: { vendor: "openbsd", product: "openssh" },
      jenkins: { vendor: "jenkins", product: "jenkins" },
      gitlab: { vendor: "gitlab", product: "gitlab" },
      confluence: { vendor: "atlassian", product: "confluence_server" },
      jira: { vendor: "atlassian", product: "jira" },
      grafana: { vendor: "grafana", product: "grafana" },
      elasticsearch: { vendor: "elastic", product: "elasticsearch" },
      kibana: { vendor: "elastic", product: "kibana" },
      "log4j": { vendor: "apache", product: "log4j" },
      "apache struts": { vendor: "apache", product: "struts" },
      "apache kafka": { vendor: "apache", product: "kafka" },
      "apache solr": { vendor: "apache", product: "solr" },
      rabbitmq: { vendor: "vmware", product: "rabbitmq" },
      memcached: { vendor: "memcached", product: "memcached" },
      bind: { vendor: "isc", product: "bind" },
      samba: { vendor: "samba", product: "samba" },
      squid: { vendor: "squid-cache", product: "squid" },
      haproxy: { vendor: "haproxy", product: "haproxy" },
      envoy: { vendor: "envoyproxy", product: "envoy" },
      traefik: { vendor: "traefik", product: "traefik" },
      vault: { vendor: "hashicorp", product: "vault" },
      consul: { vendor: "hashicorp", product: "consul" },
      terraform: { vendor: "hashicorp", product: "terraform" },
      nagios: { vendor: "nagios", product: "nagios" },
      zabbix: { vendor: "zabbix", product: "zabbix" },
      splunk: { vendor: "splunk", product: "splunk" },
      nextcloud: { vendor: "nextcloud", product: "nextcloud_server" },
      keycloak: { vendor: "redhat", product: "keycloak" },
      sonarqube: { vendor: "sonarsource", product: "sonarqube" },
      fortios: { vendor: "fortinet", product: "fortios" },
      "pan-os": { vendor: "paloaltonetworks", product: "pan-os" },
      junos: { vendor: "juniper", product: "junos" },
      "cisco ios": { vendor: "cisco", product: "ios" },
      "cisco asa": { vendor: "cisco", product: "adaptive_security_appliance_software" }
    };
    dynamicThresholds = /* @__PURE__ */ new Map();
    lastRefreshTime = 0;
    lastRefreshDuration = 0;
    refreshInterval = null;
    nextScheduledRefresh = 0;
    refreshHistory = [];
    STATIC_MIN_SAFE = {
      nginx: "1.25.0",
      apache: "2.4.58",
      "apache http server": "2.4.58",
      iis: "10.0",
      lighttpd: "1.4.73",
      caddy: "2.7.0",
      php: "8.2.0",
      "node.js": "20.0.0",
      nodejs: "20.0.0",
      python: "3.11.0",
      java: "17.0.0",
      ruby: "3.2.0",
      mysql: "8.0.35",
      mariadb: "10.11.0",
      postgresql: "16.0",
      mongodb: "7.0.0",
      redis: "7.2.0",
      wordpress: "6.4.0",
      drupal: "10.2.0",
      joomla: "5.0.0",
      jquery: "3.7.0",
      react: "18.0.0",
      angular: "17.0.0",
      vue: "3.4.0",
      django: "5.0",
      laravel: "11.0",
      spring: "6.1.0",
      express: "4.18.0",
      openssl: "3.1.0",
      exchange: "2019.0",
      postfix: "3.8.0",
      docker: "24.0.0",
      kubernetes: "1.28.0"
    };
    _testing = {
      compareSemver,
      bumpPatchVersion,
      isValidVersion,
      queryNvdForLatestAffectedVersion,
      TECH_TO_CPE,
      STATIC_MIN_SAFE,
      dynamicThresholds,
      loadPersistedThresholds,
      persistThresholds
    };
  }
});

export {
  hasNvdApiKey,
  getNvdApiKeyStatus,
  getMinSafeVersion,
  getAllThresholds,
  refreshFromNvd,
  learnFromDiScan,
  setManualThreshold,
  deleteThreshold,
  getThresholdStats,
  startAutoRefresh,
  stopAutoRefresh,
  _testing,
  version_threshold_service_exports,
  init_version_threshold_service
};
