import {
  init_notification,
  notifyOwner
} from "./chunk-V73EMRJ6.js";
import {
  getDb,
  init_db
} from "./chunk-AGW4B7XR.js";

// server/lib/iab-spike-alerting.ts
init_db();
init_notification();
import { sql } from "drizzle-orm";
var DEFAULT_THRESHOLDS = {
  monthlyVolumeThreshold: 20,
  govTargetingThreshold: 5,
  highValuePriceThreshold: 5e4,
  newBrokerDailyThreshold: 5,
  volumeSpikePercent: 50
};
async function checkMonthlyVolumeSpike(thresholds) {
  const alerts = [];
  const db = await getDb();
  const now = /* @__PURE__ */ new Date();
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
  const currentCount = Number(currentMonth?.cnt || 0);
  const prevCount = Number(prevMonth?.cnt || 0);
  if (currentCount >= thresholds.monthlyVolumeThreshold) {
    alerts.push({
      type: "volume_spike",
      severity: currentCount >= thresholds.monthlyVolumeThreshold * 2 ? "critical" : "high",
      title: `IAB Volume Alert: ${currentCount} listings this month`,
      description: `Monthly IAB listing volume (${currentCount}) exceeds threshold (${thresholds.monthlyVolumeThreshold}). Previous month: ${prevCount}.`,
      data: { currentCount, prevCount, threshold: thresholds.monthlyVolumeThreshold },
      timestamp: /* @__PURE__ */ new Date()
    });
  }
  if (prevCount > 0) {
    const percentIncrease = (currentCount - prevCount) / prevCount * 100;
    if (percentIncrease >= thresholds.volumeSpikePercent && currentCount > 5) {
      alerts.push({
        type: "volume_spike",
        severity: percentIncrease >= 100 ? "critical" : "high",
        title: `IAB Volume Spike: ${percentIncrease.toFixed(0)}% increase`,
        description: `IAB listings increased ${percentIncrease.toFixed(0)}% from ${prevCount} to ${currentCount} (threshold: ${thresholds.volumeSpikePercent}%).`,
        data: { currentCount, prevCount, percentIncrease, threshold: thresholds.volumeSpikePercent },
        timestamp: /* @__PURE__ */ new Date()
      });
    }
  }
  return alerts;
}
async function checkGovTargetingSpike(thresholds) {
  const alerts = [];
  const db = await getDb();
  const now = /* @__PURE__ */ new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const govKeywords = ["government", "military", "defense", "federal", "state agency", "public sector", "intelligence"];
  const govConditions = govKeywords.map((k) => sql`LOWER(victim_sector) LIKE ${`%${k}%`}`);
  const [result] = await db.execute(sql`
    SELECT COUNT(*) as cnt FROM access_broker_listings
    WHERE iab_created_at >= ${monthStart.toISOString().slice(0, 19)}
      AND (${sql.join(govConditions, sql` OR `)})
  `);
  const govCount = Number(result?.cnt || 0);
  if (govCount >= thresholds.govTargetingThreshold) {
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
      timestamp: /* @__PURE__ */ new Date()
    });
  }
  return alerts;
}
async function checkHighValueListings(thresholds) {
  const alerts = [];
  const db = await getDb();
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1e3);
  const highValueListings = await db.execute(sql`
    SELECT id, broker_name, listing_type, victim_sector, victim_country, asking_price, iab_description
    FROM access_broker_listings
    WHERE iab_created_at >= ${oneDayAgo.toISOString().slice(0, 19)}
      AND asking_price IS NOT NULL
      AND asking_price != ''
    ORDER BY iab_created_at DESC
  `);
  const rows = highValueListings;
  for (const listing of rows) {
    const priceStr = String(listing.asking_price || "").replace(/[,$]/g, "").toLowerCase();
    let price = 0;
    if (priceStr.includes("k")) {
      price = parseFloat(priceStr) * 1e3;
    } else if (priceStr.includes("m")) {
      price = parseFloat(priceStr) * 1e6;
    } else {
      price = parseFloat(priceStr);
    }
    if (!isNaN(price) && price >= thresholds.highValuePriceThreshold) {
      alerts.push({
        type: "high_value",
        severity: price >= thresholds.highValuePriceThreshold * 5 ? "critical" : "high",
        title: `HIGH VALUE IAB: ${listing.broker_name} \u2014 $${price.toLocaleString()}`,
        description: `New high-value IAB listing detected: "${listing.broker_name}" with asking price $${price.toLocaleString()} (threshold: $${thresholds.highValuePriceThreshold.toLocaleString()}). Sector: ${listing.victim_sector || "unknown"}. Country: ${listing.victim_country || "unknown"}.`,
        data: {
          listingId: listing.id,
          brokerName: listing.broker_name,
          price,
          sector: listing.victim_sector,
          country: listing.victim_country,
          type: listing.listing_type
        },
        timestamp: /* @__PURE__ */ new Date()
      });
    }
  }
  return alerts;
}
async function checkNewBrokerEmergence(thresholds) {
  const alerts = [];
  const db = await getDb();
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1e3);
  const [result] = await db.execute(sql`
    SELECT COUNT(DISTINCT broker_id) as cnt
    FROM access_broker_listings
    WHERE iab_created_at >= ${oneDayAgo.toISOString().slice(0, 19)}
  `);
  const newBrokerCount = Number(result?.cnt || 0);
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
      timestamp: /* @__PURE__ */ new Date()
    });
  }
  return alerts;
}
async function runIABSpikeCheck(customThresholds) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...customThresholds };
  const checkedAt = /* @__PURE__ */ new Date();
  console.log("[IAB-Alerting] Running spike detection checks...");
  const allAlerts = [];
  const [volumeAlerts, govAlerts, highValueAlerts, brokerAlerts] = await Promise.allSettled([
    checkMonthlyVolumeSpike(thresholds),
    checkGovTargetingSpike(thresholds),
    checkHighValueListings(thresholds),
    checkNewBrokerEmergence(thresholds)
  ]);
  for (const result of [volumeAlerts, govAlerts, highValueAlerts, brokerAlerts]) {
    if (result.status === "fulfilled") {
      allAlerts.push(...result.value);
    } else {
      console.error("[IAB-Alerting] Check failed:", result.reason?.message);
    }
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  allAlerts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  let notificationsSent = 0;
  let notificationsFailed = 0;
  for (const alert of allAlerts.filter((a) => a.severity === "critical" || a.severity === "high")) {
    try {
      const sent = await notifyOwner({
        title: `\u{1F6A8} ${alert.title}`,
        content: `**Severity:** ${alert.severity.toUpperCase()}
**Type:** ${alert.type}

${alert.description}

**Detected at:** ${alert.timestamp.toISOString()}

---
*Automated alert from Caldera IAB Spike Detection*`
      });
      if (sent) {
        notificationsSent++;
      } else {
        notificationsFailed++;
      }
    } catch (err) {
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
    thresholds
  };
}
function getDefaultThresholds() {
  return { ...DEFAULT_THRESHOLDS };
}

export {
  runIABSpikeCheck,
  getDefaultThresholds
};
