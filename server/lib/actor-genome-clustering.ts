/**
 * Actor Genome Engine — Campaign Clustering & Temporal Analysis
 *
 * Extends the core genome engine with:
 * 1. Campaign Clustering — groups incidents by behavioral similarity
 *    to detect unnamed actors or new campaigns from known actors
 * 2. Temporal Pattern Analysis — UTC offset extraction, operational
 *    tempo computation, holiday/geopolitical correlation
 * 3. Infrastructure Overlap Detection — identifies shared C2, hosting,
 *    and TLS patterns across incidents
 * 4. Malware Lineage Tracking — code genealogy and family evolution
 *
 * Author: Harrison Cook / AC3 Platform
 */

import type {
  IncidentObservation,
  ActorGenomeProfile,
  CampaignRecord,
  OperationalTempo,
  TradecraftFingerprint,
} from "./actor-genome-engine";
import { getAllActorProfiles, scoreIncident } from "./actor-genome-engine";

// ─── Campaign Clustering Types ──────────────────────────────────────────────────

export interface IncidentCluster {
  clusterId: string;
  name: string;
  incidents: IncidentObservation[];
  centroid: ClusterCentroid;
  /** Best-matching known actor (if any) */
  attributedActor: { actorId: string; name: string; confidence: number } | null;
  /** Whether this cluster represents a potentially new/unnamed actor */
  potentialNewActor: boolean;
  /** Cohesion score — how tightly grouped the incidents are */
  cohesion: number;
  /** Computed temporal pattern for this cluster */
  temporalPattern: OperationalTempo | null;
  /** Shared infrastructure across cluster incidents */
  sharedInfrastructure: string[];
  /** Common techniques across all incidents in cluster */
  commonTechniques: string[];
  /** Common malware across all incidents in cluster */
  commonMalware: string[];
}

export interface ClusterCentroid {
  primarySector: string;
  primaryCountry: string;
  avgDwellDays: number;
  dominantTechniques: string[];
  dominantMalware: string[];
  dominantInitialAccess: string[];
  dominantImpact: string;
  hasIcsComponent: boolean;
}

export interface TemporalAnalysisResult {
  /** Estimated primary UTC offset */
  estimatedUtcOffset: number;
  /** Confidence in the UTC offset estimate */
  offsetConfidence: number;
  /** Hourly activity distribution (24 buckets) */
  hourlyDistribution: number[];
  /** Daily activity distribution (7 buckets, Mon=0) */
  dailyDistribution: number[];
  /** Detected campaign cadence */
  campaignCadence: {
    avgIntervalDays: number;
    stdDevDays: number;
    pattern: "regular" | "burst" | "continuous" | "sporadic";
  };
  /** Holiday correlation analysis */
  holidayCorrelation: HolidayCorrelation[];
  /** Geopolitical event correlation */
  geopoliticalCorrelation: GeopoliticalCorrelation[];
}

export interface HolidayCorrelation {
  country: string;
  holiday: string;
  dateRange: { start: string; end: string };
  activityDuringHoliday: number; // 0-1, lower = avoidance
  significance: number; // statistical significance 0-1
}

export interface GeopoliticalCorrelation {
  event: string;
  eventDate: number;
  activitySpike: boolean;
  responseDelayHours: number;
  confidence: number;
}

export interface InfrastructureOverlap {
  type: "ip" | "domain" | "asn" | "jarm" | "ja3" | "tls_cert" | "hosting_provider";
  value: string;
  incidentIds: string[];
  actorAssociation: { actorId: string; name: string; confidence: number } | null;
  firstSeen: number;
  lastSeen: number;
}

// ─── Campaign Clustering Engine ─────────────────────────────────────────────────

/**
 * Cluster incidents by behavioral similarity using agglomerative approach
 */
export function clusterIncidents(
  incidents: IncidentObservation[],
  options?: {
    similarityThreshold?: number; // 0-1, default 0.6
    minClusterSize?: number; // default 2
    maxClusters?: number; // default 20
  }
): IncidentCluster[] {
  const threshold = options?.similarityThreshold ?? 0.6;
  const minSize = options?.minClusterSize ?? 2;
  const maxClusters = options?.maxClusters ?? 20;

  if (incidents.length === 0) return [];
  if (incidents.length === 1) {
    return [{
      clusterId: `cluster-${incidents[0].id}`,
      name: `Single incident: ${incidents[0].title}`,
      incidents,
      centroid: computeCentroid(incidents),
      attributedActor: null,
      potentialNewActor: false,
      cohesion: 1.0,
      temporalPattern: null,
      sharedInfrastructure: [],
      commonTechniques: incidents[0].techniques,
      commonMalware: incidents[0].malwareObserved,
    }];
  }

  // Compute pairwise similarity matrix
  const n = incidents.length;
  const similarity: number[][] = Array.from({ length: n }, () => Array(n).fill(0));

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const sim = computeIncidentSimilarity(incidents[i], incidents[j]);
      similarity[i][j] = sim;
      similarity[j][i] = sim;
    }
    similarity[i][i] = 1.0;
  }

  // Agglomerative clustering (average linkage)
  let clusters: number[][] = incidents.map((_, i) => [i]);

  while (clusters.length > maxClusters) {
    let bestI = -1, bestJ = -1, bestSim = -1;

    for (let i = 0; i < clusters.length; i++) {
      for (let j = i + 1; j < clusters.length; j++) {
        const avgSim = computeClusterSimilarity(clusters[i], clusters[j], similarity);
        if (avgSim > bestSim) {
          bestSim = avgSim;
          bestI = i;
          bestJ = j;
        }
      }
    }

    if (bestSim < threshold) break;

    // Merge clusters
    clusters[bestI] = [...clusters[bestI], ...clusters[bestJ]];
    clusters.splice(bestJ, 1);
  }

  // Filter by minimum size and build cluster objects
  const result: IncidentCluster[] = [];
  let clusterIdx = 0;

  for (const cluster of clusters) {
    if (cluster.length < minSize) continue;

    const clusterIncidents = cluster.map(i => incidents[i]);
    const centroid = computeCentroid(clusterIncidents);
    const temporalPattern = analyzeClusterTemporal(clusterIncidents);
    const sharedInfra = findSharedInfrastructure(clusterIncidents);
    const commonTech = findCommonElements(clusterIncidents.map(i => i.techniques));
    const commonMalware = findCommonElements(clusterIncidents.map(i => i.malwareObserved));

    // Try to attribute the cluster to a known actor
    const attribution = attributeCluster(clusterIncidents);

    const cohesion = computeClusterCohesion(cluster, similarity);

    result.push({
      clusterId: `cluster-${clusterIdx++}`,
      name: generateClusterName(centroid, attribution),
      incidents: clusterIncidents,
      centroid,
      attributedActor: attribution,
      potentialNewActor: attribution === null || attribution.confidence < 0.5,
      cohesion,
      temporalPattern,
      sharedInfrastructure: sharedInfra,
      commonTechniques: commonTech,
      commonMalware: commonMalware,
    });
  }

  return result.sort((a, b) => b.incidents.length - a.incidents.length);
}

// ─── Similarity Computation ─────────────────────────────────────────────────────

/**
 * Compute behavioral similarity between two incidents (0-1)
 */
function computeIncidentSimilarity(a: IncidentObservation, b: IncidentObservation): number {
  let totalWeight = 0;
  let weightedSim = 0;

  // Technique overlap (Jaccard similarity) — weight 30
  const techSim = jaccardSimilarity(a.techniques, b.techniques);
  weightedSim += techSim * 30;
  totalWeight += 30;

  // Malware overlap — weight 25
  const malwareSim = jaccardSimilarity(a.malwareObserved, b.malwareObserved);
  weightedSim += malwareSim * 25;
  totalWeight += 25;

  // Victim sector match — weight 10
  const sectorSim = a.victimSector.toLowerCase() === b.victimSector.toLowerCase() ? 1 : 0;
  weightedSim += sectorSim * 10;
  totalWeight += 10;

  // Victim geography match — weight 5
  const geoSim = a.victimCountry.toLowerCase() === b.victimCountry.toLowerCase() ? 1 : 0;
  weightedSim += geoSim * 5;
  totalWeight += 5;

  // Initial access overlap — weight 15
  const accessSim = jaccardSimilarity(a.initialAccess, b.initialAccess);
  weightedSim += accessSim * 15;
  totalWeight += 15;

  // Tools overlap — weight 10
  const toolSim = jaccardSimilarity(a.toolsUsed, b.toolsUsed);
  weightedSim += toolSim * 10;
  totalWeight += 10;

  // Infrastructure overlap — weight 15
  const infraSim = jaccardSimilarity(
    [...a.sourceIps, ...a.domains, ...a.jarmHashes],
    [...b.sourceIps, ...b.domains, ...b.jarmHashes]
  );
  weightedSim += infraSim * 15;
  totalWeight += 15;

  // ICS-specific overlap — weight 15
  const icsSim = jaccardSimilarity(
    [...a.plcVendors, ...a.icsProtocols],
    [...b.plcVendors, ...b.icsProtocols]
  );
  weightedSim += icsSim * 15;
  totalWeight += 15;

  // Impact type match — weight 8
  const impactSim = a.impactType.toLowerCase() === b.impactType.toLowerCase() ? 1 : 0;
  weightedSim += impactSim * 8;
  totalWeight += 8;

  // Credential behavior match — weight 5
  const credSim = a.credentialReuse === b.credentialReuse ? 1 : 0;
  weightedSim += credSim * 5;
  totalWeight += 5;

  // Propaganda behavior match — weight 7
  const propSim = a.propagandaLeft === b.propagandaLeft ? 1 : 0;
  weightedSim += propSim * 7;
  totalWeight += 7;

  // Dwell time similarity — weight 5
  if (a.dwellTimeDays !== null && b.dwellTimeDays !== null) {
    const maxDwell = Math.max(a.dwellTimeDays, b.dwellTimeDays, 1);
    const dwellSim = 1 - Math.abs(a.dwellTimeDays - b.dwellTimeDays) / maxDwell;
    weightedSim += dwellSim * 5;
  }
  totalWeight += 5;

  return totalWeight > 0 ? weightedSim / totalWeight : 0;
}

function jaccardSimilarity(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  const setA = new Set(a.map(s => s.toLowerCase()));
  const setB = new Set(b.map(s => s.toLowerCase()));
  const intersection = [...setA].filter(x => setB.has(x)).length;
  const union = new Set([...setA, ...setB]).size;
  return union > 0 ? intersection / union : 0;
}

function computeClusterSimilarity(clusterA: number[], clusterB: number[], similarity: number[][]): number {
  let total = 0;
  let count = 0;
  for (const i of clusterA) {
    for (const j of clusterB) {
      total += similarity[i][j];
      count++;
    }
  }
  return count > 0 ? total / count : 0;
}

function computeClusterCohesion(cluster: number[], similarity: number[][]): number {
  if (cluster.length <= 1) return 1.0;
  let total = 0;
  let count = 0;
  for (let i = 0; i < cluster.length; i++) {
    for (let j = i + 1; j < cluster.length; j++) {
      total += similarity[cluster[i]][cluster[j]];
      count++;
    }
  }
  return count > 0 ? total / count : 0;
}

// ─── Centroid & Attribution ─────────────────────────────────────────────────────

function computeCentroid(incidents: IncidentObservation[]): ClusterCentroid {
  const sectors = incidents.map(i => i.victimSector);
  const countries = incidents.map(i => i.victimCountry);
  const techniques = incidents.flatMap(i => i.techniques);
  const malware = incidents.flatMap(i => i.malwareObserved);
  const access = incidents.flatMap(i => i.initialAccess);
  const impacts = incidents.map(i => i.impactType);
  const dwellTimes = incidents.filter(i => i.dwellTimeDays !== null).map(i => i.dwellTimeDays!);

  return {
    primarySector: mode(sectors) || "unknown",
    primaryCountry: mode(countries) || "unknown",
    avgDwellDays: dwellTimes.length > 0 ? dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length : 0,
    dominantTechniques: topN(techniques, 5),
    dominantMalware: topN(malware, 3),
    dominantInitialAccess: topN(access, 3),
    dominantImpact: mode(impacts) || "unknown",
    hasIcsComponent: incidents.some(i => i.plcVendors.length > 0 || i.icsProtocols.length > 0),
  };
}

function attributeCluster(incidents: IncidentObservation[]): { actorId: string; name: string; confidence: number } | null {
  // Score the first incident (representative) against all actors
  if (incidents.length === 0) return null;

  const report = scoreIncident(incidents[0]);
  if (report.topCandidate.overallScore >= 40) {
    return {
      actorId: report.topCandidate.actorId,
      name: report.topCandidate.actorName,
      confidence: report.topCandidate.overallScore / 100,
    };
  }
  return null;
}

function generateClusterName(centroid: ClusterCentroid, attribution: { actorId: string; name: string; confidence: number } | null): string {
  if (attribution && attribution.confidence >= 0.6) {
    return `${attribution.name} Campaign — ${centroid.primarySector} (${centroid.primaryCountry})`;
  }
  const icsLabel = centroid.hasIcsComponent ? "ICS/" : "";
  return `Unnamed ${icsLabel}${centroid.primarySector} Campaign (${centroid.primaryCountry})`;
}

// ─── Temporal Analysis ──────────────────────────────────────────────────────────

/**
 * Analyze temporal patterns from a set of incidents
 */
export function analyzeTemporalPatterns(
  incidents: IncidentObservation[],
  knownEvents?: { event: string; date: number }[]
): TemporalAnalysisResult {
  // Extract operating hours
  const allHours = incidents
    .filter(i => i.operatingHoursUtc && i.operatingHoursUtc.length > 0)
    .flatMap(i => i.operatingHoursUtc!);

  // Estimate UTC offset by finding the offset that best aligns activity to work hours
  const estimatedOffset = estimateUtcOffset(allHours);

  // Build hourly distribution
  const hourlyDist = buildHourlyDistribution(allHours, estimatedOffset.offset);

  // Build daily distribution from timestamps
  const dailyDist = buildDailyDistribution(incidents.map(i => i.timestamp));

  // Compute campaign cadence
  const cadence = computeCampaignCadence(incidents.map(i => i.timestamp));

  // Holiday correlation
  const holidays = analyzeHolidayCorrelation(incidents.map(i => i.timestamp));

  // Geopolitical correlation
  const geopolitical = knownEvents
    ? analyzeGeopoliticalCorrelation(incidents.map(i => i.timestamp), knownEvents)
    : [];

  return {
    estimatedUtcOffset: estimatedOffset.offset,
    offsetConfidence: estimatedOffset.confidence,
    hourlyDistribution: hourlyDist,
    dailyDistribution: dailyDist,
    campaignCadence: cadence,
    holidayCorrelation: holidays,
    geopoliticalCorrelation: geopolitical,
  };
}

function estimateUtcOffset(utcHours: number[]): { offset: number; confidence: number } {
  if (utcHours.length === 0) return { offset: 0, confidence: 0 };

  // Try each half-hour offset from -12 to +12
  let bestOffset = 0;
  let bestScore = 0;

  for (let offset = -12; offset <= 12; offset += 0.5) {
    const localHours = utcHours.map(h => ((h + offset) % 24 + 24) % 24);
    // Score: how many fall in 7-18 (work hours)
    const workHourCount = localHours.filter(h => h >= 7 && h <= 18).length;
    const score = workHourCount / utcHours.length;

    if (score > bestScore) {
      bestScore = score;
      bestOffset = offset;
    }
  }

  return { offset: bestOffset, confidence: Math.min(bestScore * 1.2, 1.0) };
}

function buildHourlyDistribution(utcHours: number[], offset: number): number[] {
  const dist = Array(24).fill(0);
  for (const h of utcHours) {
    const local = Math.floor(((h + offset) % 24 + 24) % 24);
    dist[local]++;
  }
  const max = Math.max(...dist, 1);
  return dist.map(v => v / max);
}

function buildDailyDistribution(timestamps: number[]): number[] {
  const dist = Array(7).fill(0);
  for (const ts of timestamps) {
    const day = new Date(ts).getUTCDay();
    // Convert to Mon=0 format
    const monBased = (day + 6) % 7;
    dist[monBased]++;
  }
  const max = Math.max(...dist, 1);
  return dist.map(v => v / max);
}

function computeCampaignCadence(timestamps: number[]): { avgIntervalDays: number; stdDevDays: number; pattern: "regular" | "burst" | "continuous" | "sporadic" } {
  if (timestamps.length < 2) {
    return { avgIntervalDays: 0, stdDevDays: 0, pattern: "sporadic" };
  }

  const sorted = [...timestamps].sort((a, b) => a - b);
  const intervals: number[] = [];

  for (let i = 1; i < sorted.length; i++) {
    intervals.push((sorted[i] - sorted[i - 1]) / (1000 * 60 * 60 * 24));
  }

  const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const variance = intervals.reduce((sum, v) => sum + Math.pow(v - avg, 2), 0) / intervals.length;
  const stdDev = Math.sqrt(variance);

  // Classify pattern
  let pattern: "regular" | "burst" | "continuous" | "sporadic";
  if (avg < 3) pattern = "continuous";
  else if (stdDev < avg * 0.3) pattern = "regular";
  else if (intervals.some(i => i < 1) && intervals.some(i => i > 30)) pattern = "burst";
  else pattern = "sporadic";

  return { avgIntervalDays: Math.round(avg * 10) / 10, stdDevDays: Math.round(stdDev * 10) / 10, pattern };
}

function analyzeHolidayCorrelation(timestamps: number[]): HolidayCorrelation[] {
  // Major holidays that might correlate with nation-state activity patterns
  const holidays = [
    { country: "Iran", holiday: "Nowruz", start: "03-20", end: "04-02" },
    { country: "Iran", holiday: "Ramadan (approx)", start: "03-01", end: "03-30" },
    { country: "Russia", holiday: "New Year/Orthodox Christmas", start: "12-31", end: "01-08" },
    { country: "Russia", holiday: "Victory Day", start: "05-09", end: "05-09" },
    { country: "China", holiday: "Chinese New Year (approx)", start: "01-20", end: "02-10" },
    { country: "China", holiday: "Golden Week", start: "10-01", end: "10-07" },
    { country: "US", holiday: "Independence Day", start: "07-04", end: "07-04" },
    { country: "US", holiday: "Thanksgiving", start: "11-22", end: "11-28" },
  ];

  const results: HolidayCorrelation[] = [];

  for (const holiday of holidays) {
    const [startMonth, startDay] = holiday.start.split("-").map(Number);
    const [endMonth, endDay] = holiday.end.split("-").map(Number);

    let duringCount = 0;
    let outsideCount = 0;

    for (const ts of timestamps) {
      const date = new Date(ts);
      const month = date.getUTCMonth() + 1;
      const day = date.getUTCDate();

      const isDuring = (month > startMonth || (month === startMonth && day >= startDay)) &&
                       (month < endMonth || (month === endMonth && day <= endDay));

      if (isDuring) duringCount++;
      else outsideCount++;
    }

    const totalDays = 365;
    const holidayDays = Math.max(1, (endMonth - startMonth) * 30 + (endDay - startDay) + 1);
    const expectedRate = holidayDays / totalDays;
    const actualRate = timestamps.length > 0 ? duringCount / timestamps.length : 0;

    const activity = expectedRate > 0 ? actualRate / expectedRate : 0;
    const significance = timestamps.length >= 10 ? Math.min(Math.abs(activity - 1) * 2, 1) : 0.2;

    if (significance > 0.3) {
      results.push({
        country: holiday.country,
        holiday: holiday.holiday,
        dateRange: { start: holiday.start, end: holiday.end },
        activityDuringHoliday: Math.min(activity, 2),
        significance,
      });
    }
  }

  return results.sort((a, b) => b.significance - a.significance);
}

function analyzeGeopoliticalCorrelation(
  timestamps: number[],
  events: { event: string; date: number }[]
): GeopoliticalCorrelation[] {
  const results: GeopoliticalCorrelation[] = [];

  for (const event of events) {
    // Look for activity spikes within 7 days after the event
    const windowStart = event.date;
    const windowEnd = event.date + 7 * 24 * 60 * 60 * 1000;

    const incidentsInWindow = timestamps.filter(ts => ts >= windowStart && ts <= windowEnd);
    const baselineRate = timestamps.length / 365; // avg incidents per day
    const windowRate = incidentsInWindow.length / 7;

    const spike = windowRate > baselineRate * 2;

    if (incidentsInWindow.length > 0) {
      const firstResponse = Math.min(...incidentsInWindow);
      const delayHours = (firstResponse - event.date) / (1000 * 60 * 60);

      results.push({
        event: event.event,
        eventDate: event.date,
        activitySpike: spike,
        responseDelayHours: Math.round(delayHours),
        confidence: spike ? 0.7 : 0.3,
      });
    }
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}

// ─── Infrastructure Overlap Detection ───────────────────────────────────────────

/**
 * Find infrastructure overlaps across incidents
 */
export function detectInfrastructureOverlap(incidents: IncidentObservation[]): InfrastructureOverlap[] {
  const overlaps: Map<string, InfrastructureOverlap> = new Map();

  // Collect all infrastructure indicators
  for (const incident of incidents) {
    const indicators: { type: InfrastructureOverlap["type"]; value: string }[] = [
      ...incident.sourceIps.map(v => ({ type: "ip" as const, value: v })),
      ...incident.domains.map(v => ({ type: "domain" as const, value: v })),
      ...incident.jarmHashes.map(v => ({ type: "jarm" as const, value: v })),
      ...incident.ja3Hashes.map(v => ({ type: "ja3" as const, value: v })),
      ...incident.tlsCerts.map(v => ({ type: "tls_cert" as const, value: v })),
      ...incident.asnNumbers.map(v => ({ type: "asn" as const, value: v })),
    ];

    for (const ind of indicators) {
      const key = `${ind.type}:${ind.value}`;
      if (overlaps.has(key)) {
        const existing = overlaps.get(key)!;
        if (!existing.incidentIds.includes(incident.id)) {
          existing.incidentIds.push(incident.id);
        }
        existing.lastSeen = Math.max(existing.lastSeen, incident.timestamp);
      } else {
        overlaps.set(key, {
          type: ind.type,
          value: ind.value,
          incidentIds: [incident.id],
          actorAssociation: null,
          firstSeen: incident.timestamp,
          lastSeen: incident.timestamp,
        });
      }
    }
  }

  // Filter to only overlaps (seen in 2+ incidents)
  const results = [...overlaps.values()].filter(o => o.incidentIds.length >= 2);

  // Try to associate with known actors
  const actors = getAllActorProfiles();
  for (const overlap of results) {
    for (const actor of actors) {
      const match = actor.infrastructurePatterns.find(p =>
        p.value.toLowerCase().includes(overlap.value.toLowerCase()) ||
        overlap.value.toLowerCase().includes(p.value.toLowerCase())
      );
      if (match) {
        overlap.actorAssociation = {
          actorId: actor.actorId,
          name: actor.name,
          confidence: match.confidence,
        };
        break;
      }
    }
  }

  return results.sort((a, b) => b.incidentIds.length - a.incidentIds.length);
}

// ─── Cluster Temporal Analysis ──────────────────────────────────────────────────

function analyzeClusterTemporal(incidents: IncidentObservation[]): OperationalTempo | null {
  const allHours = incidents
    .filter(i => i.operatingHoursUtc && i.operatingHoursUtc.length > 0)
    .flatMap(i => i.operatingHoursUtc!);

  if (allHours.length < 3) return null;

  const offsetResult = estimateUtcOffset(allHours);
  const hourlyDist = buildHourlyDistribution(allHours, offsetResult.offset);
  const dailyDist = buildDailyDistribution(incidents.map(i => i.timestamp));
  const cadence = computeCampaignCadence(incidents.map(i => i.timestamp));

  return {
    primaryUtcOffset: offsetResult.offset,
    secondaryUtcOffset: null,
    hourlyDistribution: hourlyDist,
    dailyDistribution: dailyDist,
    avgCampaignIntervalDays: cadence.avgIntervalDays,
    avgCampaignDurationDays: 0,
    holidayCorrelation: [],
    geopoliticalTriggers: [],
  };
}

// ─── Shared Infrastructure ──────────────────────────────────────────────────────

function findSharedInfrastructure(incidents: IncidentObservation[]): string[] {
  if (incidents.length < 2) return [];

  const allInfra = incidents.map(i => new Set([
    ...i.sourceIps,
    ...i.domains,
    ...i.jarmHashes,
    ...i.asnNumbers,
  ]));

  // Find elements present in at least 2 incidents
  const counts = new Map<string, number>();
  for (const infraSet of allInfra) {
    for (const item of infraSet) {
      counts.set(item, (counts.get(item) || 0) + 1);
    }
  }

  return [...counts.entries()]
    .filter(([_, count]) => count >= 2)
    .map(([item]) => item);
}

// ─── Utility Functions ──────────────────────────────────────────────────────────

function findCommonElements(arrays: string[][]): string[] {
  if (arrays.length === 0) return [];
  if (arrays.length === 1) return [...new Set(arrays[0])];

  const counts = new Map<string, number>();
  for (const arr of arrays) {
    const unique = new Set(arr.map(s => s.toLowerCase()));
    for (const item of unique) {
      counts.set(item, (counts.get(item) || 0) + 1);
    }
  }

  // Elements present in at least half the arrays
  const threshold = Math.ceil(arrays.length / 2);
  return [...counts.entries()]
    .filter(([_, count]) => count >= threshold)
    .map(([item]) => item);
}

function mode(arr: string[]): string | null {
  if (arr.length === 0) return null;
  const counts = new Map<string, number>();
  for (const item of arr) {
    counts.set(item.toLowerCase(), (counts.get(item.toLowerCase()) || 0) + 1);
  }
  let best = "";
  let bestCount = 0;
  for (const [item, count] of counts) {
    if (count > bestCount) {
      best = item;
      bestCount = count;
    }
  }
  return best;
}

function topN(arr: string[], n: number): string[] {
  const counts = new Map<string, number>();
  for (const item of arr) {
    counts.set(item, (counts.get(item) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([item]) => item);
}
