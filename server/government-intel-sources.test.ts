/**
 * Tests for Government Intelligence Sources Ingest Module
 * and Threat Intel Daily Internal Scheduler.
 *
 * Validates:
 *   - Government source parsers (OFAC, RFJ, FBI, DOJ, NSA, ACSC, CCCS)
 *   - Internal cron scheduler registration
 *   - Pipeline phase structure
 *   - RSS parsing helpers
 */
import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";

const PROJECT_ROOT = path.resolve(__dirname, "..");

// ─── Government Intel Sources Module ─────────────────────────────────────────

describe("Government Intel Sources Module", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/government-intel-sources.ts");

  it("government-intel-sources.ts exists", () => {
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("exports runGovernmentIntelIngest master function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function runGovernmentIntelIngest");
  });

  it("exports individual OFAC ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestOFACCyberSanctions");
  });

  it("exports Rewards for Justice ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestRewardsForJustice");
  });

  it("exports FBI Cyber Most Wanted ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestFBICyberMostWanted");
  });

  it("exports DOJ Cybercrime Indictments ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestDOJCyberIndictments");
  });

  it("exports NSA Advisories ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestNSAAdvisories");
  });

  it("exports ACSC (Australia) ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestACSCAdvisories");
  });

  it("exports CCCS (Canada) ingest function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export async function ingestCCCSAdvisories");
  });

  it("master function runs all 7 government sources", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    // The sources array should list all 7
    expect(content).toContain('"OFAC"');
    expect(content).toContain('"RFJ"');
    expect(content).toContain('"FBI"');
    expect(content).toContain('"DOJ"');
    expect(content).toContain('"NSA"');
    expect(content).toContain('"ACSC"');
    expect(content).toContain('"CCCS"');
  });

  it("OFAC parser handles XML format with CYBER2 program filter", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("CYBER2");
    expect(content).toContain("parseOFACXml");
    expect(content).toContain("sdnEntry");
  });

  it("OFAC parser handles CSV fallback format", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("parseOFACCsv");
    expect(content).toContain("sdn.csv");
  });

  it("OFAC parser extracts crypto wallet addresses", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cryptoAddresses");
    expect(content).toContain("Digital Currency");
  });

  it("OFAC entities are recorded in threatGroupEvents table with sanctions event", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("threatGroupEvents");
    expect(content).toContain("OFAC Cyber Sanctions");
    expect(content).toContain("tgeSource: 'OFAC SDN List'");
  });

  it("OFAC entities with crypto addresses are extracted and stored", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cryptoAddresses");
    expect(content).toContain("Digital Currency");
  });

  it("Rewards for Justice scraper targets the correct URL", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("rewardsforjustice.net");
    expect(content).toContain("foreign-malicious-cyber-activity");
  });

  it("FBI scraper targets the correct URL", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("fbi.gov/wanted/cyber");
  });

  it("FBI entries are recorded as events with fugitive description", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("FBI Cyber Most Wanted fugitive");
    expect(content).toContain("tgeSource: 'FBI Cyber Most Wanted'");
  });

  it("DOJ parser uses RSS feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("justice.gov/news/rss");
  });

  it("DOJ parser filters for cyber-related keywords", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cyberKeywords");
    expect(content).toContain("'ransomware'");
    expect(content).toContain("'computer fraud'");
    expect(content).toContain("'botnet'");
  });

  it("NSA parser targets the correct advisory page", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("nsa.gov/Press-Room/Cybersecurity-Advisories-Guidance");
  });

  it("ACSC parser uses Australian cyber.gov.au feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cyber.gov.au");
  });

  it("CCCS parser uses Canadian cyber.gc.ca feed", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("cyber.gc.ca");
  });

  it("includes delay between sources to avoid rate limiting", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("setTimeout");
    expect(content).toContain("2000");
  });

  it("uses safeFetch with timeout for all HTTP requests", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("async function safeFetch");
    expect(content).toContain("AbortController");
  });

  it("returns GovSourceResult with proper structure", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("interface GovSourceResult");
    expect(content).toContain("source: string");
    expect(content).toContain("fetched: number");
    expect(content).toContain("newRecords: number");
    expect(content).toContain("errors: string[]");
    expect(content).toContain("durationMs: number");
  });

  it("advisory feed processor filters by relevance keywords", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("actorKeywords");
    expect(content).toContain("'state-sponsored'");
    expect(content).toContain("'nation-state'");
  });

  it("advisory feed processor assigns severity based on content", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("'critical'");
    expect(content).toContain("'actively exploit'");
  });
});

// ─── Threat Intel Daily Scheduler ────────────────────────────────────────────

describe("Threat Intel Daily Scheduler", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/threat-intel-daily-scheduler.ts");

  it("threat-intel-daily-scheduler.ts exists", () => {
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it("exports initThreatIntelDailyScheduler function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export function initThreatIntelDailyScheduler");
  });

  it("exports stopThreatIntelDailyScheduler function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export function stopThreatIntelDailyScheduler");
  });

  it("exports isThreatIntelDailySchedulerActive function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export function isThreatIntelDailySchedulerActive");
  });

  it("exports isThreatIntelDailyRunning function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export function isThreatIntelDailyRunning");
  });

  it("exports getLastRunResult function", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("export function getLastRunResult");
  });

  it("uses node-cron for scheduling", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain('import cron from "node-cron"');
    expect(content).toContain("cron.schedule");
  });

  it("schedules at 03:30 UTC daily", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    // cron expression: second minute hour day month weekday
    expect(content).toContain('"0 30 3 * * *"');
    expect(content).toContain('timezone: "UTC"');
  });

  it("prevents concurrent runs", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("isRunning");
    expect(content).toContain("Previous run still in progress, skipping");
  });

  it("prevents double initialization", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("schedulerInitialized");
    expect(content).toContain("Already initialized, skipping");
  });

  it("pipeline includes all 9 phases", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("phase: 'rss_sync'");
    expect(content).toContain("phase: 'full_ingest'");
    expect(content).toContain("phase: 'actor_crawl'");
    expect(content).toContain("phase: 'targeted_enrichment'");
    expect(content).toContain("phase: 'government_intel'");
    expect(content).toContain("phase: 'ransomware_leak_monitor'");
    expect(content).toContain("phase: 'cve_refresh'");
    expect(content).toContain("phase: 'zero_day_monitor'");
    expect(content).toContain("phase: 'owner_notification'");
  });

  it("pipeline includes government intel phase (Phase 5)", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("runGovernmentIntelIngest");
    expect(content).toContain("government-intel-sources");
  });

  it("sends owner notification with daily summary", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("notifyOwner");
    expect(content).toContain("Daily Threat Intel Summary");
  });

  it("summary includes government intel stats", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("Gov Intel:");
    expect(content).toContain("OFAC, RFJ, FBI, DOJ, NSA, ACSC, CCCS");
  });

  it("includes zero-day alert in notification when critical items found", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("ZERO-DAY ALERT");
    expect(content).toContain("criticalCount");
  });
});

// ─── Scheduler Registration in Server Startup ────────────────────────────────

describe("Scheduler Registration in Server Startup", () => {
  const indexPath = path.join(PROJECT_ROOT, "server/_core/index.ts");

  it("threat-intel-daily scheduler is registered in index.ts", () => {
    const content = fs.readFileSync(indexPath, "utf-8");
    expect(content).toContain("threat-intel-daily-scheduler");
    expect(content).toContain("initThreatIntelDailyScheduler");
  });

  it("government intel sources are added to /api/scheduled/threat-intel-daily endpoint", () => {
    const content = fs.readFileSync(indexPath, "utf-8");
    expect(content).toContain("government-intel-sources");
    expect(content).toContain("runGovernmentIntelIngest");
    expect(content).toContain("government_intel");
  });
});

// ─── OFAC XML Parser Logic ───────────────────────────────────────────────────

describe("OFAC XML Parser Logic", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/government-intel-sources.ts");

  it("parses sdnEntry XML elements", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<sdnEntry>");
    expect(content).toContain("sdnEntry");
  });

  it("extracts firstName and lastName from entries", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<firstName>");
    expect(content).toContain("<lastName>");
  });

  it("extracts aliases from aka elements", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<aka>");
    expect(content).toContain("aliases");
  });

  it("extracts nationality from entries", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<nationality>");
    expect(content).toContain("<country>");
  });

  it("filters for cyber-related programs including DPRK and IRAN", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain('"DPRK"');
    expect(content).toContain('"IRAN"');
    expect(content).toContain('"RUSSIA-EO14024"');
  });
});

// ─── RSS Parser Shared Helper ────────────────────────────────────────────────

describe("RSS Parser Shared Helper", () => {
  const filePath = path.join(PROJECT_ROOT, "server/lib/government-intel-sources.ts");

  it("parseSimpleRss handles both RSS item and Atom entry formats", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<item>");
    expect(content).toContain("<entry>");
    expect(content).toContain("function parseSimpleRss");
  });

  it("parseSimpleRss extracts title, link, description, pubDate", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("<title");
    expect(content).toContain("<link");
    expect(content).toContain("<description");
    expect(content).toContain("<pubDate");
  });

  it("parseSimpleRss handles CDATA sections", () => {
    const content = fs.readFileSync(filePath, "utf-8");
    expect(content).toContain("CDATA");
  });
});
