import "./chunk-KFQGP6VL.js";

// server/lib/cicd-schedule-conflict.ts
function parseCronField(field, min, max) {
  const values = /* @__PURE__ */ new Set();
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
function parseCron(expr) {
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 5) return null;
  try {
    return {
      minute: parseCronField(parts[0], 0, 59),
      hour: parseCronField(parts[1], 0, 23),
      dom: parseCronField(parts[2], 1, 31),
      month: parseCronField(parts[3], 1, 12),
      dow: parseCronField(parts[4], 0, 6)
    };
  } catch {
    return null;
  }
}
function getNextExecutions(cronExpr, count, from) {
  const cron = parseCron(cronExpr);
  if (!cron) return [];
  const results = [];
  const start = from ? new Date(from) : /* @__PURE__ */ new Date();
  const cursor = new Date(start);
  cursor.setSeconds(0, 0);
  cursor.setMinutes(cursor.getMinutes() + 1);
  const maxIterations = 525960;
  let iterations = 0;
  while (results.length < count && iterations < maxIterations) {
    iterations++;
    const minute = cursor.getMinutes();
    const hour = cursor.getHours();
    const dom = cursor.getDate();
    const month = cursor.getMonth() + 1;
    const dow = cursor.getDay();
    if (cron.minute.values.includes(minute) && cron.hour.values.includes(hour) && cron.dom.values.includes(dom) && cron.month.values.includes(month) && cron.dow.values.includes(dow)) {
      results.push(new Date(cursor));
    }
    cursor.setMinutes(cursor.getMinutes() + 1);
  }
  return results;
}
function findOverlaps(cronA, cronB, windowMinutes = 5, lookAheadHours = 168) {
  const from = /* @__PURE__ */ new Date();
  const execsA = getNextExecutions(cronA, 100, from);
  const execsB = getNextExecutions(cronB, 100, from);
  if (execsA.length === 0 || execsB.length === 0) return null;
  const cutoff = new Date(from.getTime() + lookAheadHours * 60 * 60 * 1e3);
  const overlaps = [];
  let exactCount = 0;
  for (const a of execsA) {
    if (a > cutoff) break;
    for (const b of execsB) {
      if (b > cutoff) break;
      const diffMs = Math.abs(a.getTime() - b.getTime());
      const diffMinutes = diffMs / 6e4;
      if (diffMinutes === 0) {
        exactCount++;
        overlaps.push(a);
      } else if (diffMinutes <= windowMinutes) {
        overlaps.push(a);
      }
    }
  }
  if (overlaps.length === 0) return null;
  let overlapType;
  if (exactCount > 0) {
    overlapType = "exact";
  } else if (overlaps.length >= 10) {
    overlapType = "frequent";
  } else {
    overlapType = "near";
  }
  const seen = /* @__PURE__ */ new Set();
  const unique = overlaps.filter((d) => {
    const key = Math.floor(d.getTime() / 6e4);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { overlapType, overlappingTimes: unique.slice(0, 20) };
}
function detectConflicts(pipelines) {
  const scheduled = pipelines.filter((p) => p.enabled && p.cronExpression);
  const conflicts = [];
  for (let i = 0; i < scheduled.length; i++) {
    for (let j = i + 1; j < scheduled.length; j++) {
      const a = scheduled[i];
      const b = scheduled[j];
      const overlap = findOverlaps(a.cronExpression, b.cronExpression);
      if (!overlap) continue;
      let severity;
      let description;
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
        overlappingTimes: overlap.overlappingTimes.map((d) => d.toISOString())
      });
    }
  }
  const severityOrder = { high: 0, medium: 1, low: 2 };
  conflicts.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  const highCount = conflicts.filter((c) => c.severity === "high").length;
  const mediumCount = conflicts.filter((c) => c.severity === "medium").length;
  let summary;
  if (conflicts.length === 0) {
    summary = `No schedule conflicts detected across ${scheduled.length} scheduled pipeline(s).`;
  } else {
    const parts = [];
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
    summary
  };
}
function suggestNonConflictingSchedule(existingPipelines, desiredFrequency) {
  const baseSchedules = {
    hourly: ["0 * * * *", "15 * * * *", "30 * * * *", "45 * * * *"],
    every_6h: ["0 0 */6 * *", "0 15 */6 * *", "0 30 */6 * *", "0 45 */6 * *"],
    every_12h: ["0 0 */12 * *", "0 6 */12 * *", "0 3 */12 * *", "0 9 */12 * *"],
    daily: ["0 0 * * *", "0 2 * * *", "0 4 * * *", "0 6 * * *", "0 8 * * *", "0 10 * * *"],
    weekly: ["0 0 * * 0", "0 0 * * 1", "0 0 * * 2", "0 0 * * 3", "0 0 * * 4", "0 0 * * 5", "0 0 * * 6"]
  };
  const candidates = baseSchedules[desiredFrequency] || baseSchedules.daily;
  let bestCron = candidates[0];
  let bestOverlaps = Infinity;
  for (const candidate of candidates) {
    let totalOverlaps = 0;
    for (const pipeline of existingPipelines.filter((p) => p.enabled && p.cronExpression)) {
      const overlap = findOverlaps(candidate, pipeline.cronExpression);
      if (overlap) totalOverlaps += overlap.overlappingTimes.length;
    }
    if (totalOverlaps < bestOverlaps) {
      bestOverlaps = totalOverlaps;
      bestCron = candidate;
    }
  }
  const freqLabels = {
    hourly: "Every hour",
    every_6h: "Every 6 hours",
    every_12h: "Every 12 hours",
    daily: "Daily",
    weekly: "Weekly"
  };
  return {
    cron: bestCron,
    description: `${freqLabels[desiredFrequency]} at ${bestCron} (${bestOverlaps === 0 ? "no conflicts" : `${bestOverlaps} near-overlaps`})`
  };
}
export {
  detectConflicts,
  getNextExecutions,
  suggestNonConflictingSchedule
};
