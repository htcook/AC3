/**
 * IAB Spike Alerting Service
 *
 * Monitors access_broker_listings for anomalous spikes in:
 *   1. Monthly listing volume — sudden increase in new IAB listings
 *   2. Government targeting — spike in listings targeting gov/mil sectors
 *   3. High-value listings — new listings with asking price > threshold
 *   4. New broker emergence — multiple new brokers appearing in short timeframe
 *
 * Integrates with notifyOwner for real-time alerts to the platform owner.
 */

import { getDb } from "../db";
import { accessBrokerListings } from "../../drizzle/schema";
import { sql, gte, and, like, or } from "drizzle-orm";
import { notifyOwner } from "../_core/notification";

// ─── Alert Configuration ────────────────────────────────────────────────

export interface IABAlertThresholds {
  /** Alert when monthly listing count exceeds this value */
  monthlyVolumeThreshold: number;
  /** Alert when monthly gov-targeting count exceeds this value */
  govTargetingThreshold: number;
  /** Alert when a single listing's asking price exceeds this (USD) */
  highValuePriceThreshold: number;
  /** Alert when this many new brokers appear in a single day */
  newBrokerDailyThreshold: number;
  /** Percentage increase over previous month that triggers a spike alert */
  volumeSpikePercent: number;
}

const DEFAULT_THRESHOLDS: IABAlertThresholds = {
  monthlyVolumeThreshold: 20,
  govTargetingThreshold: 5,
  highValuePriceThreshold: 50000,
  newBrokerDailyThreshold: 5,
  volumeSpikePercent: 50,
};

// ─── Types ──────────────────────────────────────────────────────────────

export interface IABAlert {
  type: "volume_spike" | "gov_targeting" | "high_value" | "new_brokers" | "sector_shift";
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  data: Record<string, any>;
  timestamp: Date;
}

export interface SpikeCheckResult {
  checkedAt: Date;
  alerts: IABAlert[];
  notificationsSent: number;
  notificationsFailed: number;
  thresholds: IABAlertThresholds;
}

// ─── Spike Detection Functions ──────────────────────────────────────────

async function checkMonthlyVolumeSpike(
  thresholds: IABAlertThresholds
): Promise<IABAlert[]> {
  const alerts: IABAlert[] = [];
  const db = await getDb();

  // Get current month and previous month listing counts
  const now = new Date();
  const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const prevMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);

  const [currentMonth] = await db.execute(sql`
    SELECT COUNT(*) as cnt FROM access_broker_listings
    WHERE iab_created_at >= ${currentMonthStart.toISOString().slice(0, 19)}
  `);
  const [prevMonth] = await db.execute(sql`
    SELECT COUNT(*) as cnt FROM access_broker_listings
    WHERE iab_created_at >= ${prevMonthStart.toISOString().slice(0, 19)}
      AND iab_created_at < ${currentMonthStart.toISOString().slice(0, 19)}
  `);

  const currentCount = Number((currentMonth as any)?.cnt || 0);
  const prevCount = Number((prevMonth as any)?.cnt || 0);

  // Check absolute threshold
  if (currentCount >= thresholds.monthlyVolumeThreshold) {
    alerts.push({
      type: "volume_spike",
      severity: currentCount >= thresholds.monthlyVolumeThreshold * 2 ? "critical" : "high",
      title: `IAB Volume Alert: ${currentCount} listings this month`,
      description: `Monthly IAB listing volume (${currentCount}) exceeds threshold (${thresholds.monthlyVolumeThreshold}). Previous month: ${prevCount}.`,
      data: { currentCount, prevCount, threshold: thresholds.monthlyVolumeThreshold },
      timestamp: new Date(),
    });
  }

  // Check percentage spike
  if (prevCount > 0) {
    const percentIncrease = ((currentCount - prevCount) / prevCount) * 100;
    if (percentIncrease >= thresholds.volumeSpikePercent && currentCount > 5) {
      alerts.push({
        type: "volume_spike",
        severity: percentIncrease >= 100 ? "critical" : "high",
        title: `IAB Volume Spike: ${percentIncrease.toFixed(0)}% increase`,
        description: `IAB listings increased ${percentIncrease.toFixed(0)}% from ${prevCount} to ${currentCount} (threshold: ${thresholds.volumeSpikePercent}%).`,
        data: { currentCount, prevCount, percentIncrease, threshold: thresholds.volumeSpikePercent },
        timestamp: new Date(),
      });
    }
  }

  return alerts;
}

async function checkGovTargetingSpike(
  thresholds: IABAlertThresholds
): Promise<IABAlert[]> {
  const alerts: IABAlert[] = [];
  const db = await getDb();

  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  // Count government/military sector targeting this month
  const govKeywords = ['government', 'military', 'defense', 'federal', 'state agency', 'public sector', 'intelligence'];
  const govConditions = govKeywords.map(k => sql`LOWER(victim_sector) LIKE ${`%${k}%`}`);

  const [result] = await db.execute(sql`
    SELECT COUNT(*) as cnt FROM access_broker_listings
    WHERE iab_created_at >= ${monthStart.toISOString().slice(0, 19)}
      AND (${sql.join(govConditions, sql` OR `)})
  `);

  const govCount = Number((result as any)?.cnt || 0);

  if (govCount >= thresholds.govTargetingThreshold) {
    // Get details of the gov-targeting listings
    const govListings = await db.execute(sql`
      SELECT broker_name, victim_sector, victim_country, asking_price, iab_created_at
      FROM access_broker_listings
      WHERE iab_created_at >= ${monthStart.toISOString().slice(0, 19)}
        AND (${sql.join(govConditions, sql` OR `)})
      ORDER BY iab_created_at DESC
      LIMIT 10
    `);

    alerts.push({
      type: "gov_targeting",
      severity: govCount >= thresholds.govTargetingThreshold * 2 ? "critical" : "high",
      title: `GOV TARGETING ALERT: ${govCount} government-sector IAB listings this month`,
      description: `${govCount} IAB listings targeting government/military sectors detected this month (threshold: ${thresholds.govTargetingThreshold}). Immediate review recommended.`,
      data: { govCount, threshold: thresholds.govTargetingThreshold, listings: govListings },
      timestamp: new Date(),
    });
  }

  return alerts;
}

async function checkHighValueListings(
  thresholds: IABAlertThresholds
): Promise<IABAlert[]> {
  const alerts: IABAlert[] = [];
  const db = await getDb();

  // Check for listings added in the last 24 hours with high asking prices
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const highValueListings = await db.execute(sql`
    SELECT id, broker_name, listing_type, victim_sector, victim_country, asking_price, iab_description
    FROM access_broker_listings
    WHERE iab_created_at >= ${oneDayAgo.toISOString().slice(0, 19)}
      AND asking_price IS NOT NULL
      AND asking_price != ''
    ORDER BY iab_created_at DESC
  `);

  const rows = highValueListings as any[];
  for (const listing of rows) {
    // Parse price from string (e.g., "$50,000", "50000 USD", "$50k")
    const priceStr = String(listing.asking_price || '').replace(/[,$]/g, '').toLowerCase();
    let price = 0;
    if (priceStr.includes('k')) {
      price = parseFloat(priceStr) * 1000;
    } else if (priceStr.includes('m')) {
      price = parseFloat(priceStr) * 1000000;
    } else {
      price = parseFloat(priceStr);
    }

    if (!isNaN(price) && price >= thresholds.highValuePriceThreshold) {
      alerts.push({
        type: "high_value",
        severity: price >= thresholds.highValuePriceThreshold * 5 ? "critical" : "high",
        title: `HIGH VALUE IAB: ${listing.broker_name} — $${price.toLocaleString()}`,
        description: `New high-value IAB listing detected: "${listing.broker_name}" with asking price $${price.toLocaleString()} (threshold: $${thresholds.highValuePriceThreshold.toLocaleString()}). Sector: ${listing.victim_sector || 'unknown'}. Country: ${listing.victim_country || 'unknown'}.`,
        data: {
          listingId: listing.id,
          brokerName: listing.broker_name,
          price,
          sector: listing.victim_sector,
          country: listing.victim_country,
          type: listing.listing_type,
        },
        timestamp: new Date(),
      });
    }
  }

  return alerts;
}

async function checkNewBrokerEmergence(
  thresholds: IABAlertThresholds
): Promise<IABAlert[]> {
  const alerts: IABAlert[] = [];
  const db = await getDb();

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

  // Count distinct new brokers in the last 24 hours
  const [result] = await db.execute(sql`
    SELECT COUNT(DISTINCT broker_id) as cnt
    FROM access_broker_listings
    WHERE iab_created_at >= ${oneDayAgo.toISOString().slice(0, 19)}
  `);

  const newBrokerCount = Number((result as any)?.cnt || 0);

  if (newBrokerCount >= thresholds.newBrokerDailyThreshold) {
    const newBrokers = await db.execute(sql`
      SELECT DISTINCT broker_name, listing_type, iab_data_source
      FROM access_broker_listings
      WHERE iab_created_at >= ${oneDayAgo.toISOString().slice(0, 19)}
      ORDER BY iab_created_at DESC
      LIMIT 20
    `);

    alerts.push({
      type: "new_brokers",
      severity: newBrokerCount >= thresholds.newBrokerDailyThreshold * 3 ? "critical" : "medium",
      title: `NEW BROKER SURGE: ${newBrokerCount} new IAB actors in 24h`,
      description: `${newBrokerCount} new Initial Access Brokers detected in the last 24 hours (threshold: ${thresholds.newBrokerDailyThreshold}). This may indicate increased underground market activity.`,
      data: { newBrokerCount, threshold: thresholds.newBrokerDailyThreshold, brokers: newBrokers },
      timestamp: new Date(),
    });
  }

  return alerts;
}

// ─── Main Spike Check ───────────────────────────────────────────────────

export async function runIABSpikeCheck(
  customThresholds?: Partial<IABAlertThresholds>
): Promise<SpikeCheckResult> {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...customThresholds };
  const checkedAt = new Date();
  console.log("[IAB-Alerting] Running spike detection checks...");

  const allAlerts: IABAlert[] = [];

  // Run all checks in parallel
  const [volumeAlerts, govAlerts, highValueAlerts, brokerAlerts] = await Promise.allSettled([
    checkMonthlyVolumeSpike(thresholds),
    checkGovTargetingSpike(thresholds),
    checkHighValueListings(thresholds),
    checkNewBrokerEmergence(thresholds),
  ]);

  for (const result of [volumeAlerts, govAlerts, highValueAlerts, brokerAlerts]) {
    if (result.status === "fulfilled") {
      allAlerts.push(...result.value);
    } else {
      console.error("[IAB-Alerting] Check failed:", result.reason?.message);
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allAlerts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Send notifications for critical and high severity alerts
  let notificationsSent = 0;
  let notificationsFailed = 0;

  for (const alert of allAlerts.filter(a => a.severity === "critical" || a.severity === "high")) {
    try {
      const sent = await notifyOwner({
        title: `🚨 ${alert.title}`,
        content: `**Severity:** ${alert.severity.toUpperCase()}\n**Type:** ${alert.type}\n\n${alert.description}\n\n**Detected at:** ${alert.timestamp.toISOString()}\n\n---\n*Automated alert from Caldera IAB Spike Detection*`,
      });
      if (sent) {
        notificationsSent++;
      } else {
        notificationsFailed++;
      }
    } catch (err: any) {
      console.error(`[IAB-Alerting] Failed to send notification for ${alert.type}:`, err.message);
      notificationsFailed++;
    }
  }

  console.log(`[IAB-Alerting] Spike check complete: ${allAlerts.length} alerts, ${notificationsSent} notifications sent, ${notificationsFailed} failed`);

  return {
    checkedAt,
    alerts: allAlerts,
    notificationsSent,
    notificationsFailed,
    thresholds,
  };
}

// ─── Get Current Thresholds ─────────────────────────────────────────────

export function getDefaultThresholds(): IABAlertThresholds {
  return { ...DEFAULT_THRESHOLDS };
}
