/**
 * DNS Record Automation Service
 * Auto-configure SPF, DKIM, DMARC, and MX records via DigitalOcean DNS API.
 */

const DO_API = "https://api.digitalocean.com/v2";

function getToken(): string {
  const token = process.env.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN is not configured");
  return token;
}

async function doFetch(path: string, opts: RequestInit = {}) {
  const res = await fetch(`${DO_API}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${getToken()}`,
      "Content-Type": "application/json",
      ...(opts.headers as Record<string, string>),
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`DO DNS API ${res.status}: ${body}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface DnsRecord {
  id: number;
  type: string;
  name: string;
  data: string;
  priority: number | null;
  port: number | null;
  ttl: number;
  weight: number | null;
  flags: number | null;
  tag: string | null;
}

export interface DnsDomain {
  name: string;
  ttl: number;
  zoneFile: string;
}

export interface DnsValidation {
  domain: string;
  spf: { present: boolean; valid: boolean; value: string | null };
  dkim: { present: boolean; valid: boolean; selector: string; value: string | null };
  dmarc: { present: boolean; valid: boolean; value: string | null };
  mx: { present: boolean; records: string[] };
  score: number;
  checkedAt: number;
}

// ─── Domain CRUD ──────────────────────────────────────────────────────────────

export async function listDomains(): Promise<DnsDomain[]> {
  const data = await doFetch("/domains");
  return (data.domains ?? []).map((d: any) => ({ name: d.name, ttl: d.ttl, zoneFile: d.zone_file ?? "" }));
}

export async function listRecords(domain: string): Promise<DnsRecord[]> {
  const data = await doFetch(`/domains/${encodeURIComponent(domain)}/records`);
  return (data.domain_records ?? []).map(mapRecord);
}

function mapRecord(r: any): DnsRecord {
  return {
    id: r.id, type: r.type, name: r.name, data: r.data,
    priority: r.priority ?? null, port: r.port ?? null, ttl: r.ttl,
    weight: r.weight ?? null, flags: r.flags ?? null, tag: r.tag ?? null,
  };
}

export async function createRecord(domain: string, record: {
  type: string; name: string; data: string; ttl?: number; priority?: number;
}): Promise<DnsRecord> {
  const data = await doFetch(`/domains/${encodeURIComponent(domain)}/records`, {
    method: "POST",
    body: JSON.stringify({ type: record.type, name: record.name, data: record.data, ttl: record.ttl ?? 3600, priority: record.priority ?? null }),
  });
  return mapRecord(data.domain_record);
}

export async function deleteRecord(domain: string, recordId: number): Promise<void> {
  await doFetch(`/domains/${encodeURIComponent(domain)}/records/${recordId}`, { method: "DELETE" });
}

// ─── SPF / DKIM / DMARC Generators ───────────────────────────────────────────

export function generateSpfRecord(opts: { includes?: string[]; ips?: string[]; policy?: "~all" | "-all" | "?all" }): string {
  const parts = ["v=spf1"];
  for (const ip of opts.ips ?? []) parts.push(`ip4:${ip}`);
  for (const inc of opts.includes ?? []) parts.push(`include:${inc}`);
  parts.push(opts.policy ?? "~all");
  return parts.join(" ");
}

export function generateDmarcRecord(opts: { policy?: "none" | "quarantine" | "reject"; rua?: string; ruf?: string; pct?: number }): string {
  const parts = [`v=DMARC1; p=${opts.policy ?? "none"}`];
  if (opts.rua) parts.push(`rua=mailto:${opts.rua}`);
  if (opts.ruf) parts.push(`ruf=mailto:${opts.ruf}`);
  if (opts.pct !== undefined) parts.push(`pct=${opts.pct}`);
  return parts.join("; ");
}

export function generateDkimPlaceholder(selector: string): string {
  return `v=DKIM1; k=rsa; p=REPLACE_WITH_PUBLIC_KEY (selector: ${selector})`;
}

// ─── Bulk Deploy ──────────────────────────────────────────────────────────────

export interface DeployResult {
  domain: string;
  records: { type: string; name: string; data: string; status: "created" | "exists" | "error"; error?: string }[];
}

export async function deployEmailRecords(domain: string, opts: {
  spfIncludes?: string[]; spfIps?: string[]; spfPolicy?: "~all" | "-all" | "?all";
  dmarcPolicy?: "none" | "quarantine" | "reject"; dmarcRua?: string;
  dkimSelector?: string; mxHost?: string; mxPriority?: number;
}): Promise<DeployResult> {
  const result: DeployResult = { domain, records: [] };
  const existing = await listRecords(domain);

  const spfData = generateSpfRecord({ includes: opts.spfIncludes, ips: opts.spfIps, policy: opts.spfPolicy });
  const existingSpf = existing.find((r) => r.type === "TXT" && r.data.includes("v=spf1"));
  if (existingSpf) {
    result.records.push({ type: "TXT", name: "@", data: spfData, status: "exists" });
  } else {
    try {
      await createRecord(domain, { type: "TXT", name: "@", data: spfData });
      result.records.push({ type: "TXT", name: "@", data: spfData, status: "created" });
    } catch (e: any) {
      result.records.push({ type: "TXT", name: "@", data: spfData, status: "error", error: e.message });
    }
  }

  const dmarcData = generateDmarcRecord({ policy: opts.dmarcPolicy, rua: opts.dmarcRua });
  const existingDmarc = existing.find((r) => r.type === "TXT" && r.name === "_dmarc");
  if (existingDmarc) {
    result.records.push({ type: "TXT", name: "_dmarc", data: dmarcData, status: "exists" });
  } else {
    try {
      await createRecord(domain, { type: "TXT", name: "_dmarc", data: dmarcData });
      result.records.push({ type: "TXT", name: "_dmarc", data: dmarcData, status: "created" });
    } catch (e: any) {
      result.records.push({ type: "TXT", name: "_dmarc", data: dmarcData, status: "error", error: e.message });
    }
  }

  if (opts.dkimSelector) {
    const dkimName = `${opts.dkimSelector}._domainkey`;
    const dkimData = generateDkimPlaceholder(opts.dkimSelector);
    const existingDkim = existing.find((r) => r.type === "TXT" && r.name === dkimName);
    if (existingDkim) {
      result.records.push({ type: "TXT", name: dkimName, data: dkimData, status: "exists" });
    } else {
      try {
        await createRecord(domain, { type: "TXT", name: dkimName, data: dkimData });
        result.records.push({ type: "TXT", name: dkimName, data: dkimData, status: "created" });
      } catch (e: any) {
        result.records.push({ type: "TXT", name: dkimName, data: dkimData, status: "error", error: e.message });
      }
    }
  }

  if (opts.mxHost) {
    const existingMx = existing.find((r) => r.type === "MX");
    if (existingMx) {
      result.records.push({ type: "MX", name: "@", data: opts.mxHost, status: "exists" });
    } else {
      try {
        await createRecord(domain, { type: "MX", name: "@", data: opts.mxHost, priority: opts.mxPriority ?? 10 });
        result.records.push({ type: "MX", name: "@", data: opts.mxHost, status: "created" });
      } catch (e: any) {
        result.records.push({ type: "MX", name: "@", data: opts.mxHost, status: "error", error: e.message });
      }
    }
  }

  return result;
}

// ─── Validation ───────────────────────────────────────────────────────────────

export async function validateEmailDns(domain: string, dkimSelector?: string): Promise<DnsValidation> {
  const records = await listRecords(domain);
  const spfRec = records.find((r) => r.type === "TXT" && r.data.includes("v=spf1"));
  const dmarcRec = records.find((r) => r.type === "TXT" && r.name === "_dmarc");
  const selector = dkimSelector ?? "default";
  const dkimRec = records.find((r) => r.type === "TXT" && r.name === `${selector}._domainkey`);
  const mxRecs = records.filter((r) => r.type === "MX");

  let score = 0;
  const spf = { present: !!spfRec, valid: !!spfRec && spfRec.data.startsWith("v=spf1"), value: spfRec?.data ?? null };
  if (spf.present) score += 25; if (spf.valid) score += 5;
  const dmarc = { present: !!dmarcRec, valid: !!dmarcRec && dmarcRec.data.includes("v=DMARC1"), value: dmarcRec?.data ?? null };
  if (dmarc.present) score += 25; if (dmarc.valid) score += 5;
  const dkim = { present: !!dkimRec, valid: !!dkimRec && dkimRec.data.includes("v=DKIM1"), selector, value: dkimRec?.data ?? null };
  if (dkim.present) score += 20; if (dkim.valid) score += 5;
  const mx = { present: mxRecs.length > 0, records: mxRecs.map((r) => r.data) };
  if (mx.present) score += 15;

  return { domain, spf, dkim, dmarc, mx, score, checkedAt: Date.now() };
}
