import {
  init_knowledge_loader,
  loadKnowledgeData
} from "./chunk-PIYDKQBM.js";
import {
  init_schema,
  oemDefaultCredentials
} from "./chunk-L4JENJ4Z.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/oem-default-creds.ts
import { like, sql, or } from "drizzle-orm";
async function getDb() {
  const { getDb: _getDb } = await import("./db-MOHZQFM5.js");
  return _getDb();
}
async function ensureCreds() {
  if (_credsLoaded) return _creds;
  _creds = await loadKnowledgeData("oem_default_creds.json", []);
  _credsLoaded = true;
  return _creds;
}
function getBuiltinCreds() {
  return _creds;
}
async function initOemCreds() {
  await ensureCreds();
}
async function matchCredentialsForTechnology(tech) {
  const creds = await ensureCreds();
  const matches = [];
  const techName = (tech.name || "").toLowerCase();
  const techVendor = (tech.vendor || "").toLowerCase();
  const techCpe = (tech.cpe || "").toLowerCase();
  const techBanner = (tech.banner || "").toLowerCase();
  const techTitle = (tech.pageTitle || "").toLowerCase();
  const techTags = (tech.tags || []).map((t) => t.toLowerCase());
  const searchText = [techName, techVendor, techCpe, techBanner, techTitle].join(" ");
  for (const cred of creds) {
    const credVendor = cred.vendor.toLowerCase();
    const credProduct = cred.product.toLowerCase();
    const credProductWords = credProduct.split(/\s+/);
    let matched = false;
    if (techName.includes(credVendor) || techName.includes(credProduct)) matched = true;
    if (techVendor.includes(credVendor)) matched = true;
    if (techCpe.includes(credVendor) || techCpe.includes(credProduct.replace(/\s+/g, "_"))) matched = true;
    if (!matched && (techBanner || techTitle)) {
      if (searchText.includes(credVendor) || searchText.includes(credProduct)) matched = true;
      if (!matched && credProductWords.length > 1) {
        if (credProductWords.every((w) => searchText.includes(w))) matched = true;
      }
    }
    if (!matched && techTags.length > 0 && cred.tags.length > 0) {
      if (cred.vendor !== "Generic") {
        if (techTags.some((t) => t.includes(credVendor) || credVendor.includes(t))) matched = true;
      }
    }
    if (!matched && tech.port && cred.port === tech.port && tech.protocol && cred.protocol === tech.protocol.toLowerCase()) {
      if (techName.includes(credVendor.split(" ")[0]) || techName.includes(credProductWords[0])) matched = true;
    }
    if (!matched && cred.vendor === "Generic" && tech.port) {
      const webPorts = [80, 443, 8080, 8443, 8e3, 3e3, 5e3];
      if (cred.product === "Web Admin" && webPorts.includes(tech.port)) matched = true;
      if (cred.product === "Linux SSH" && tech.port === 22) matched = true;
      if (cred.product === "Windows RDP" && tech.port === 3389) matched = true;
    }
    if (matched) matches.push(cred);
  }
  return matches;
}
async function matchCredentialsForAsset(technologies) {
  const serviceMap = /* @__PURE__ */ new Map();
  for (const tech of technologies) {
    const matches = await matchCredentialsForTechnology(tech);
    for (const cred of matches) {
      const serviceKey = `${cred.vendor}:${cred.product}:${cred.port || "any"}`;
      if (!serviceMap.has(serviceKey)) {
        serviceMap.set(serviceKey, { port: cred.port, credentials: /* @__PURE__ */ new Map() });
      }
      const credKey = `${cred.username}:${cred.password}`;
      if (!serviceMap.get(serviceKey).credentials.has(credKey)) {
        serviceMap.get(serviceKey).credentials.set(credKey, {
          vendor: cred.vendor,
          product: cred.product,
          protocol: cred.protocol,
          username: cred.username,
          password: cred.password,
          accessLevel: cred.accessLevel,
          notes: cred.notes
        });
      }
    }
  }
  return Array.from(serviceMap.entries()).map(([key, val]) => ({
    service: key.split(":").slice(0, 2).join(" "),
    port: val.port,
    credentials: Array.from(val.credentials.values())
  }));
}
async function seedBuiltinCredentials() {
  const db = await getDb();
  if (!db) return 0;
  const creds = await ensureCreds();
  const [existing] = await db.select({ count: sql`COUNT(*)` }).from(oemDefaultCredentials);
  if (Number(existing?.count || 0) > 0) return 0;
  let inserted = 0;
  for (let i = 0; i < creds.length; i += 10) {
    const batch = creds.slice(i, i + 10);
    try {
      await db.insert(oemDefaultCredentials).values(
        batch.map((c) => ({
          vendor: c.vendor,
          product: c.product,
          version: c.version || null,
          protocol: c.protocol,
          port: c.port || null,
          username: c.username,
          password: c.password,
          accessLevel: c.accessLevel || null,
          notes: c.notes || null,
          cveReference: c.cveReference || null,
          source: c.source || null,
          tags: c.tags
        }))
      );
      inserted += batch.length;
    } catch (err) {
      console.error("[OemCreds] Batch insert failed, trying individual:", err);
      for (const c of batch) {
        try {
          await db.insert(oemDefaultCredentials).values({
            vendor: c.vendor,
            product: c.product,
            version: c.version || null,
            protocol: c.protocol,
            port: c.port || null,
            username: c.username,
            password: c.password,
            accessLevel: c.accessLevel || null,
            notes: c.notes || null,
            cveReference: c.cveReference || null,
            source: c.source || null,
            tags: c.tags
          });
          inserted++;
        } catch {
        }
      }
    }
  }
  console.log(`[OemCreds] Seeded ${inserted} default credentials`);
  return inserted;
}
async function searchCredentials(query) {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(oemDefaultCredentials).where(
    or(
      like(oemDefaultCredentials.vendor, `%${query}%`),
      like(oemDefaultCredentials.product, `%${query}%`),
      like(oemDefaultCredentials.protocol, `%${query}%`)
    )
  ).limit(50);
}
async function matchCredentialsForAssets(assets) {
  const results = [];
  const seen = /* @__PURE__ */ new Set();
  for (const asset of assets) {
    for (const techName of asset.technologies) {
      const version = asset.technologyVersions?.[techName];
      const matches = await matchCredentialsForTechnology({
        name: techName,
        version: version || void 0
      });
      for (const cred of matches) {
        const dedupeKey = `${asset.hostname}|${cred.vendor}|${cred.product}|${cred.username}|${cred.password}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        results.push({
          vendor: cred.vendor,
          product: cred.product,
          protocol: cred.protocol,
          port: cred.port ?? null,
          username: cred.username,
          password: cred.password,
          accessLevel: cred.accessLevel,
          tags: cred.tags,
          matchedTechnology: techName + (version ? ` ${version}` : ""),
          matchedAsset: asset.hostname
        });
      }
    }
  }
  return results;
}
async function persistMatchedCredentials(domain, credentials) {
  const db = await getDb();
  if (!db || credentials.length === 0) return 0;
  let persisted = 0;
  for (const cred of credentials) {
    try {
      await db.insert(oemDefaultCredentials).values({
        vendor: cred.vendor,
        product: cred.product,
        protocol: cred.protocol,
        port: cred.port,
        username: cred.username,
        password: cred.password,
        accessLevel: cred.accessLevel,
        tags: JSON.stringify(cred.tags),
        notes: `Auto-matched from ${domain} scan: ${cred.matchedTechnology} on ${cred.matchedAsset}`
      }).onDuplicateKeyUpdate({
        set: {
          notes: `Auto-matched from ${domain} scan: ${cred.matchedTechnology} on ${cred.matchedAsset}`
        }
      });
      persisted++;
    } catch (err) {
      if (!err.message?.includes("Duplicate")) {
        console.error(`[OEM Creds] Failed to persist ${cred.vendor}/${cred.product}: ${err.message}`);
      }
    }
  }
  return persisted;
}
var _credsLoaded, _creds, BUILTIN_DEFAULT_CREDS;
var init_oem_default_creds = __esm({
  "server/lib/oem-default-creds.ts"() {
    init_schema();
    init_knowledge_loader();
    _credsLoaded = false;
    _creds = [];
    BUILTIN_DEFAULT_CREDS = new Proxy([], {
      get(target, prop, _receiver) {
        const src = _credsLoaded ? _creds : target;
        const val = Reflect.get(src, prop);
        if (typeof val === "function") return val.bind(src);
        return val;
      }
    });
  }
});

export {
  getBuiltinCreds,
  BUILTIN_DEFAULT_CREDS,
  initOemCreds,
  matchCredentialsForTechnology,
  matchCredentialsForAsset,
  seedBuiltinCredentials,
  searchCredentials,
  matchCredentialsForAssets,
  persistMatchedCredentials,
  init_oem_default_creds
};
