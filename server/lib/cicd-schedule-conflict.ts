/**
 * CI/CD Schedule Conflict Detection
 * 
 * Detects overlapping cron schedules across pipelines that could
 * cause concurrent scan resource contention.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ScheduledPipeline {
  id: number;
  name: string;
  cronExpression: string;
  enabled: boolean;
  targetUrl?: string;
}

export interface ScheduleConflict {
  pipelineA: { id: number; name: string; cron: string };
  pipelineB: { id: number; name: string; cron: string };
  overlapType: "exact" | "near" | "frequent";
  description: string;
  severity: "high" | "medium" | "low";
  overlappingTimes: string[];
}

export interface ConflictReport {
  conflicts: ScheduleConflict[];
  totalPipelines: number;
  scheduledPipelines: number;
  hasConflicts: boolean;
  summary: string;
}

// ─── Cron Expansion ──────────────────────────────────────────────────────────

interface CronField {
  values: number[];
}

/**
 * Parse a single cron field (supports *, ranges, steps, lists)
 */
function parseCronField(field: string, min: number, max: number): CronField {
  const values: Set<number> = new Set();

  for (const part of field.split(",")) {
    const trimmed = part.trim();

    if (trimmed === "*") {
      for (let i = min; i <= max; i++) values.add(i);
    } else if (trimmed.includes("/")) {
      const [range, stepStr] = trimmed.split("/");
      const step = parseInt(stepStr, 10);
      let start = min;
      let end = max;
      if (range !== "*") {
        if (range.includes("-")) {
          const [s, e] = range.split("-").map(Number);
          start = s;
          end = e;
        } else {
          start = parseInt(range, 10);
        }
      }
      for (let i = start; i <= end; i += step) values.add(i);
    } else if (trimmed.includes("-")) {
      const [start, end] = trimmed.split("-").map(Number);
      for (let i = start; i <= end; i++) values.add(i);
    } else {
      const val = parseInt(trimmed, 10);
      if (!isNaN(val) && val >= min && val <= max) values.add(val);
    }
  }

  return { values: Array.from(values).sort((a, b) => a - b) };
}

/**
 * Parse a 5-field cron expression into expanded fields
 */
function parseCron(expr: string): { minute: CronField; hour: CronField; dom: CronField; month: CronField; dow: CronField } | null {
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 5) return null;

  try {
    return {
      minute: parseCronField(parts[0], 0, 59),
      hour: parseCronField(parts[1], 0, 23),
      dom: parseCronField(parts[2], 1, 31),
      month: parseCronField(parts[3], 1, 12),
      dow: parseCronField(parts[4], 0, 6),
    };
  } catch {
    return null;
  }
}

/**
 * Generate the next N execution times for a cron expression starting from a reference date
 */
export function getNextExecutions(cronExpr: string, count: number, from?: Date): Date[] {
  const cron = parseCron(cronExpr);
  if (!cron) return [];

  const results: Date[] = [];
  const start = from ? new Date(from) : new Date();
  const cursor = new Date(start);
  cursor.setSeconds(0, 0);

  // Advance by 1 minute to avoid matching the current time
  cursor.setMinutes(cursor.getMinutes() + 1);

  const maxIterations = 525960; // ~1 year of minutes
  let iterations = 0;

  while (results.length < count && iterations < maxIterations) {
    iterations++;

    const minute = cursor.getMinutes();
    const hour = cursor.getHours();
    const dom = cursor.getDate();
    const month = cursor.getMonth() + 1;
    const dow = cursor.getDay();

    if (
      cron.minute.values.includes(minute) &&
      cron.hour.values.includes(hour) &&
      cron.dom.values.includes(dom) &&
      cron.month.values.includes(month) &&
      cron.dow.values.includes(dow)
    ) {
      results.push(new Date(cursor));
    }

    cursor.setMinutes(cursor.getMinutes() + 1);
  }

  return results;
}

// ─── Conflict Detection ──────────────────────────────────────────────────────

/**
 * Check if two cron expressions have overlapping execution times
 * within a 24-hour window
 */
function findOverlaps(
  cronA: string,
  cronB: string,
  windowMinutes: number = 5,
  lookAheadHours: number = 168 // 1 week
): { overlapType: "exact" | "near" | "frequent"; overlappingTimes: Date[] } | null {
  const from = new Date();
  const execsA = getNextExecutions(cronA, 100, from);
  const execsB = getNextExecutions(cronB, 100, from);

  if (execsA.length === 0 || execsB.length === 0) return null;

  const cutoff = new Date(from.getTime() + lookAheadHours * 60 * 60 * 1000);
  const overlaps: Date[] = [];
  let exactCount = 0;

  for (const a of execsA) {
    if (a > cutoff) break;
    for (const b of execsB) {
      if (b > cutoff) break;
      const diffMs = Math.abs(a.getTime() - b.getTime());
      const diffMinutes = diffMs / 60_000;

      if (diffMinutes === 0) {
        exactCount++;
        overlaps.push(a);
      } else if (diffMinutes <= windowMinutes) {
        overlaps.push(a);
      }
    }
  }

  if (overlaps.length === 0) return null;

  let overlapType: "exact" | "near" | "frequent";
  if (exactCount > 0) {
    overlapType = "exact";
  } else if (overlaps.length >= 10) {
    overlapType = "frequent";
  } else {
    overlapType = "near";
  }

  // Deduplicate by rounding to minute
  const seen = new Set<number>();
  const unique = overlaps.filter(d => {
    const key = Math.floor(d.getTime() / 60_000);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { overlapType, overlappingTimes: unique.slice(0, 20) };
}

/**
 * Detect schedule conflicts across all provided pipelines
 */
export function detectConflicts(pipelines: ScheduledPipeline[]): ConflictReport {
  const scheduled = pipelines.filter(p => p.enabled && p.cronExpression);
  const conflicts: ScheduleConflict[] = [];

  // Compare every pair
  for (let i = 0; i < scheduled.length; i++) {
    for (let j = i + 1; j < scheduled.length; j++) {
      const a = scheduled[i];
      const b = scheduled[j];

      const overlap = findOverlaps(a.cronExpression, b.cronExpression);
      if (!overlap) continue;

      let severity: "high" | "medium" | "low";
      let description: string;

      switch (overlap.overlapType) {
        case "exact":
          severity = "high";
          description = `"${a.name}" and "${b.name}" have identical execution times. This will cause concurrent scans competing for resources.`;
          break;
        case "frequent":
          severity = "medium";
          description = `"${a.name}" and "${b.name}" have ${overlap.overlappingTimes.length} near-overlapping executions within the next week. Consider staggering their schedules.`;
          break;
        case "near":
          severity = "low";
          description = `"${a.name}" and "${b.name}" have ${overlap.overlappingTimes.length} executions within 5 minutes of each other. Minor resource contention possible.`;
          break;
      }

      conflicts.push({
        pipelineA: { id: a.id, name: a.name, cron: a.cronExpression },
        pipelineB: { id: b.id, name: b.name, cron: b.cronExpression },
        overlapType: overlap.overlapType,
        description,
        severity,
        overlappingTimes: overlap.overlappingTimes.map(d => d.toISOString()),
      });
    }
  }

  // Sort by severity
  const severityOrder = { high: 0, medium: 1, low: 2 };
  conflicts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const highCount = conflicts.filter(c => c.severity === "high").length;
  const mediumCount = conflicts.filter(c => c.severity === "medium").length;

  let summary: string;
  if (conflicts.length === 0) {
    summary = `No schedule conflicts detected across ${scheduled.length} scheduled pipeline(s).`;
  } else {
    const parts: string[] = [];
    if (highCount > 0) parts.push(`${highCount} high-severity`);
    if (mediumCount > 0) parts.push(`${mediumCount} medium-severity`);
    const lowCount = conflicts.length - highCount - mediumCount;
    if (lowCount > 0) parts.push(`${lowCount} low-severity`);
    summary = `${conflicts.length} conflict(s) detected: ${parts.join(", ")}. Consider staggering overlapping schedules.`;
  }

  return {
    conflicts,
    totalPipelines: pipelines.length,
    scheduledPipelines: scheduled.length,
    hasConflicts: conflicts.length > 0,
    summary,
  };
}

/**
 * Suggest a non-conflicting cron expression for a new pipeline
 */
export function suggestNonConflictingSchedule(
  existingPipelines: ScheduledPipeline[],
  desiredFrequency: "hourly" | "every_6h" | "every_12h" | "daily" | "weekly"
): { cron: string; description: string } {
  const baseSchedules: Record<string, string[]> = {
    hourly: ["0 * * * *", "15 * * * *", "30 * * * *", "45 * * * *"],
    every_6h: ["0 0 */6 * *", "0 15 */6 * *", "0 30 */6 * *", "0 45 */6 * *"],
    every_12h: ["0 0 */12 * *", "0 6 */12 * *", "0 3 */12 * *", "0 9 */12 * *"],
    daily: ["0 0 * * *", "0 2 * * *", "0 4 * * *", "0 6 * * *", "0 8 * * *", "0 10 * * *"],
    weekly: ["0 0 * * 0", "0 0 * * 1", "0 0 * * 2", "0 0 * * 3", "0 0 * * 4", "0 0 * * 5", "0 0 * * 6"],
  };

  const candidates = baseSchedules[desiredFrequency] || baseSchedules.daily;

  // Find the candidate with the least overlap
  let bestCron = candidates[0];
  let bestOverlaps = Infinity;

  for (const candidate of candidates) {
    let totalOverlaps = 0;
    for (const pipeline of existingPipelines.filter(p => p.enabled && p.cronExpression)) {
      const overlap = findOverlaps(candidate, pipeline.cronExpression);
      if (overlap) totalOverlaps += overlap.overlappingTimes.length;
    }
    if (totalOverlaps < bestOverlaps) {
      bestOverlaps = totalOverlaps;
      bestCron = candidate;
    }
  }

  const freqLabels: Record<string, string> = {
    hourly: "Every hour",
    every_6h: "Every 6 hours",
    every_12h: "Every 12 hours",
    daily: "Daily",
    weekly: "Weekly",
  };

  return {
    cron: bestCron,
    description: `${freqLabels[desiredFrequency]} at ${bestCron} (${bestOverlaps === 0 ? "no conflicts" : `${bestOverlaps} near-overlaps`})`,
  };
}
