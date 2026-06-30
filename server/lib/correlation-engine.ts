/**
 * SSIL Cross-Scanner Correlation Engine
 * 
 * Aggregates observations from all scanners by target asset to produce a unified
 * attack surface view. Computes per-asset risk scores, open port inventories,
 * technology stacks, and vulnerability summaries.
 */

// ─── Types ──────────────────────────────────────────────────────────────────

export interface CorrelatedAsset {
  assetId: string;
  host: string;
  firstSeenAt: number;
  lastSeenAt: number;
  // Aggregated risk
  compositeRiskScore: number;
  highestSeverity: string;
  // Port inventory
  openPorts: PortEntry[];
  totalOpenPorts: number;
  // Technology stack
  technologies: TechEntry[];
  // Vulnerabilities
  vulnerabilities: VulnSummary[];
  totalVulnerabilities: number;
  criticalVulnCount: number;
  highVulnCount: number;
  // Misconfigurations
  misconfigurations: MisconfigSummary[];
  totalMisconfigurations: number;
  // TLS status
  tlsStatus: TlsStatus[];
  // Scanner coverage
  scannerCoverage: ScannerCoverage[];
  totalObservations: number;
  // Tags
  tags: string[];
}

export interface PortEntry {
  port: number;
  protocol: string;
  service?: string;
  version?: string;
  state: string;
  firstSeenAt: number;
  lastSeenAt: number;
  scannerSource: string;
}

export interface TechEntry {
  name: string;
  version?: string;
  category: string; // web-server, framework, cms, cdn, etc.
  confidence: number;
  scannerSource: string;
}

export interface VulnSummary {
  observationId: string;
  cve?: string;
  cvss?: number;
  severity: string;
  title: string;
  scannerSource: string;
  detectedAt: number;
}

export interface MisconfigSummary {
  observationId: string;
  severity: string;
  title: string;
  scannerSource: string;
  detectedAt: number;
}

export interface TlsStatus {
  port: number;
  version?: string;
  cipher?: string;
  certIssuer?: string;
  certExpiry?: number;
  grade?: string;
  scannerSource: string;
}

export interface ScannerCoverage {
  scannerName: string;
  observationCount: number;
  lastScanAt: number;
  observationTypes: string[];
}

export interface AttackSurfaceSummary {
  totalAssets: number;
  totalOpenPorts: number;
  totalVulnerabilities: number;
  totalMisconfigurations: number;
  criticalVulnCount: number;
  highVulnCount: number;
  mediumVulnCount: number;
  uniqueTechnologies: number;
  averageRiskScore: number;
  highestRiskScore: number;
  scannerCount: number;
  totalObservations: number;
  lastUpdatedAt: number;
  severityDistribution: Record<string, number>;
  topVulnerablAssets: Array<{ host: string; score: number; vulnCount: number }>;
  topTechnologies: Array<{ name: string; count: number }>;
}

export interface CorrelationTimeline {
  timestamp: number;
  observationCount: number;
  signalCount: number;
  newVulnerabilities: number;
  newPorts: number;
  scannerName: string;
}

// ─── Severity Helpers ───────────────────────────────────────────────────────

const SEVERITY_WEIGHT: Record<string, number> = {
  info: 0,
  low: 10,
  medium: 30,
  high: 60,
  critical: 100,
};

const SEVERITY_ORDER: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(severities: string[]): string {
  let max = "info";
  for (const s of severities) {
    if ((SEVERITY_ORDER[s] ?? 0) > (SEVERITY_ORDER[max] ?? 0)) max = s;
  }
  return max;
}

// ─── Observation Row Type (from DB) ─────────────────────────────────────────

export interface ObservationRow {
  observationId: string;
  assetId: string;
  assetHost: string;
  assetPort: number;
  assetProtocol?: string | null;
  assetTags?: string[] | null;
  scannerName: string;
  scannerVersion?: string | null;
  scannerAdapter: string;
  scannerMode?: string | null;
  observationType: string;
  severity?: string | null;
  confidence: number;
  evidenceSummary: string;
  evidenceTemplateId?: string | null;
  evidenceCve?: string | null;
  evidenceCvss?: number | null;
  evidenceFingerprint?: string | null;
  evidenceArtifacts?: unknown;
  metadata?: unknown;
  observedAt?: number | null;
  ingestedAt?: number | null;
}

export interface SignalRow {
  signalId: string;
  assetId: string;
  signalType: string;
  category: string;
  severity?: string | null;
  confidence: number;
  rationale: string;
  enrichmentCvss?: number | null;
  enrichmentCve?: string | null;
  createdAt?: number | null;
}

export interface RiskCardRow {
  assetId: string;
  compositeScore: number;
  cvssScore: number;
  carverScore: number;
  biaScore: number;
  signalIds?: string[] | null;
  createdAt?: number | null;
}

// ─── Correlation Engine ─────────────────────────────────────────────────────

export class CorrelationEngine {

  /**
   * Correlate observations into per-asset views.
   */
  correlateByAsset(
    observations: ObservationRow[],
    signals: SignalRow[] = [],
    riskCards: RiskCardRow[] = []
  ): CorrelatedAsset[] {
    // Group observations by assetId
    const assetMap = new Map<string, ObservationRow[]>();
    for (const obs of observations) {
      const key = obs.assetId;
      if (!assetMap.has(key)) assetMap.set(key, []);
      assetMap.get(key)!.push(obs);
    }

    // Index risk cards by assetId
    const riskCardMap = new Map<string, RiskCardRow>();
    for (const rc of riskCards) {
      riskCardMap.set(rc.assetId, rc);
    }

    // Index signals by assetId
    const signalMap = new Map<string, SignalRow[]>();
    for (const sig of signals) {
      if (!signalMap.has(sig.assetId)) signalMap.set(sig.assetId, []);
      signalMap.get(sig.assetId)!.push(sig);
    }

    const correlatedAssets: CorrelatedAsset[] = [];

    for (const [assetId, assetObs] of assetMap) {
      const host = assetObs[0].assetHost;
      const riskCard = riskCardMap.get(assetId);
      const assetSignals = signalMap.get(assetId) || [];

      // Time range
      const timestamps = assetObs
        .map((o) => o.observedAt || o.ingestedAt || 0)
        .filter((t) => t > 0);
      const firstSeenAt = timestamps.length > 0 ? Math.min(...timestamps) : Date.now();
      const lastSeenAt = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();

      // Open ports
      const portMap = new Map<string, PortEntry>();
      for (const obs of assetObs) {
        if (
          obs.observationType === "service_banner" ||
          obs.observationType === "exposure_surface"
        ) {
          const portKey = `${obs.assetPort}:${obs.assetProtocol || "tcp"}`;
          const existing = portMap.get(portKey);
          const ts = obs.observedAt || obs.ingestedAt || Date.now();
          if (!existing || ts > existing.lastSeenAt) {
            const evidence = obs.evidenceArtifacts as Record<string, unknown> | null;
            portMap.set(portKey, {
              port: obs.assetPort,
              protocol: obs.assetProtocol || "tcp",
              service: evidence?.service as string | undefined,
              version: evidence?.version as string | undefined,
              state: "open",
              firstSeenAt: existing ? Math.min(existing.firstSeenAt, ts) : ts,
              lastSeenAt: ts,
              scannerSource: obs.scannerName,
            });
          }
        }
      }
      const openPorts = Array.from(portMap.values()).sort((a, b) => a.port - b.port);

      // Technologies
      const techMap = new Map<string, TechEntry>();
      for (const obs of assetObs) {
        if (obs.observationType === "http_headers") {
          const evidence = obs.evidenceArtifacts as Record<string, unknown> | null;
          const techs = (evidence?.technologies || []) as Array<{
            name: string;
            version?: string;
            category?: string;
          }>;
          for (const tech of techs) {
            const key = tech.name.toLowerCase();
            if (!techMap.has(key)) {
              techMap.set(key, {
                name: tech.name,
                version: tech.version,
                category: tech.category || "unknown",
                confidence: obs.confidence,
                scannerSource: obs.scannerName,
              });
            }
          }
          // Also extract from server header
          const server = evidence?.webServer as string | undefined;
          if (server && !techMap.has(server.toLowerCase())) {
            techMap.set(server.toLowerCase(), {
              name: server,
              category: "web-server",
              confidence: 0.9,
              scannerSource: obs.scannerName,
            });
          }
        }
      }
      const technologies = Array.from(techMap.values());

      // Vulnerabilities
      const vulnerabilities: VulnSummary[] = assetObs
        .filter((o) => o.observationType === "vulnerability_finding")
        .map((o) => ({
          observationId: o.observationId,
          cve: o.evidenceCve || undefined,
          cvss: o.evidenceCvss || undefined,
          severity: o.severity || "info",
          title: o.evidenceSummary.substring(0, 200),
          scannerSource: o.scannerName,
          detectedAt: o.observedAt || o.ingestedAt || Date.now(),
        }))
        .sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

      // Misconfigurations
      const misconfigurations: MisconfigSummary[] = assetObs
        .filter((o) => o.observationType === "misconfiguration")
        .map((o) => ({
          observationId: o.observationId,
          severity: o.severity || "info",
          title: o.evidenceSummary.substring(0, 200),
          scannerSource: o.scannerName,
          detectedAt: o.observedAt || o.ingestedAt || Date.now(),
        }));

      // TLS status
      const tlsStatus: TlsStatus[] = assetObs
        .filter((o) => o.observationType === "tls")
        .map((o) => {
          const evidence = o.evidenceArtifacts as Record<string, unknown> | null;
          return {
            port: o.assetPort,
            version: evidence?.tlsVersion as string | undefined,
            cipher: evidence?.cipher as string | undefined,
            certIssuer: evidence?.certIssuer as string | undefined,
            certExpiry: evidence?.certExpiry as number | undefined,
            grade: evidence?.grade as string | undefined,
            scannerSource: o.scannerName,
          };
        });

      // Scanner coverage
      const scannerMap = new Map<
        string,
        { count: number; lastScan: number; types: Set<string> }
      >();
      for (const obs of assetObs) {
        const entry = scannerMap.get(obs.scannerName) || {
          count: 0,
          lastScan: 0,
          types: new Set<string>(),
        };
        entry.count += 1;
        entry.lastScan = Math.max(
          entry.lastScan,
          obs.observedAt || obs.ingestedAt || 0
        );
        entry.types.add(obs.observationType);
        scannerMap.set(obs.scannerName, entry);
      }
      const scannerCoverage: ScannerCoverage[] = Array.from(
        scannerMap.entries()
      ).map(([name, data]) => ({
        scannerName: name,
        observationCount: data.count,
        lastScanAt: data.lastScan,
        observationTypes: Array.from(data.types),
      }));

      // Compute composite risk score
      let compositeRiskScore = riskCard?.compositeScore ?? 0;
      if (!riskCard && (vulnerabilities.length > 0 || misconfigurations.length > 0)) {
        // Heuristic: weighted sum of severity counts
        let score = 0;
        for (const v of vulnerabilities) {
          score += SEVERITY_WEIGHT[v.severity] || 0;
        }
        for (const m of misconfigurations) {
          score += (SEVERITY_WEIGHT[m.severity] || 0) * 0.5;
        }
        compositeRiskScore = Math.min(100, score);
      }

      // Tags
      const allTags = new Set<string>();
      for (const obs of assetObs) {
        if (obs.assetTags) {
          for (const tag of obs.assetTags) allTags.add(tag);
        }
      }

      const allSeverities = [
        ...vulnerabilities.map((v) => v.severity),
        ...misconfigurations.map((m) => m.severity),
      ];

      correlatedAssets.push({
        assetId,
        host,
        firstSeenAt,
        lastSeenAt,
        compositeRiskScore,
        highestSeverity: maxSeverity(allSeverities),
        openPorts,
        totalOpenPorts: openPorts.length,
        technologies,
        vulnerabilities,
        totalVulnerabilities: vulnerabilities.length,
        criticalVulnCount: vulnerabilities.filter((v) => v.severity === "critical").length,
        highVulnCount: vulnerabilities.filter((v) => v.severity === "high").length,
        misconfigurations,
        totalMisconfigurations: misconfigurations.length,
        tlsStatus,
        scannerCoverage,
        totalObservations: assetObs.length,
        tags: Array.from(allTags),
      });
    }

    // Sort by risk score descending
    return correlatedAssets.sort(
      (a, b) => b.compositeRiskScore - a.compositeRiskScore
    );
  }

  /**
   * Generate attack surface summary from correlated assets.
   */
  generateAttackSurfaceSummary(assets: CorrelatedAsset[]): AttackSurfaceSummary {
    const totalAssets = assets.length;
    const totalOpenPorts = assets.reduce((s, a) => s + a.totalOpenPorts, 0);
    const totalVulnerabilities = assets.reduce(
      (s, a) => s + a.totalVulnerabilities,
      0
    );
    const totalMisconfigurations = assets.reduce(
      (s, a) => s + a.totalMisconfigurations,
      0
    );
    const criticalVulnCount = assets.reduce(
      (s, a) => s + a.criticalVulnCount,
      0
    );
    const highVulnCount = assets.reduce((s, a) => s + a.highVulnCount, 0);
    const mediumVulnCount = assets.reduce(
      (s, a) =>
        s + a.vulnerabilities.filter((v) => v.severity === "medium").length,
      0
    );

    // Unique technologies
    const techSet = new Set<string>();
    for (const a of assets) {
      for (const t of a.technologies) techSet.add(t.name.toLowerCase());
    }

    // Scanner count
    const scannerSet = new Set<string>();
    for (const a of assets) {
      for (const sc of a.scannerCoverage) scannerSet.add(sc.scannerName);
    }

    const totalObservations = assets.reduce(
      (s, a) => s + a.totalObservations,
      0
    );

    const scores = assets.map((a) => a.compositeRiskScore);
    const averageRiskScore =
      scores.length > 0
        ? scores.reduce((s, v) => s + v, 0) / scores.length
        : 0;
    const highestRiskScore = scores.length > 0 ? Math.max(...scores) : 0;

    // Severity distribution
    const severityDistribution: Record<string, number> = {
      critical: criticalVulnCount,
      high: highVulnCount,
      medium: mediumVulnCount,
      low: 0,
      info: 0,
    };
    for (const a of assets) {
      for (const v of a.vulnerabilities) {
        if (v.severity === "low") severityDistribution.low += 1;
        if (v.severity === "info") severityDistribution.info += 1;
      }
    }

    // Top vulnerable assets
    const topVulnerablAssets = assets
      .filter((a) => a.totalVulnerabilities > 0)
      .sort((a, b) => b.compositeRiskScore - a.compositeRiskScore)
      .slice(0, 10)
      .map((a) => ({
        host: a.host,
        score: a.compositeRiskScore,
        vulnCount: a.totalVulnerabilities,
      }));

    // Top technologies
    const techCounts = new Map<string, number>();
    for (const a of assets) {
      for (const t of a.technologies) {
        const key = t.name;
        techCounts.set(key, (techCounts.get(key) || 0) + 1);
      }
    }
    const topTechnologies = Array.from(techCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([name, count]) => ({ name, count }));

    const lastUpdatedAt = Math.max(
      ...assets.map((a) => a.lastSeenAt),
      Date.now()
    );

    return {
      totalAssets,
      totalOpenPorts,
      totalVulnerabilities,
      totalMisconfigurations,
      criticalVulnCount,
      highVulnCount,
      mediumVulnCount,
      uniqueTechnologies: techSet.size,
      averageRiskScore: Math.round(averageRiskScore * 10) / 10,
      highestRiskScore: Math.round(highestRiskScore * 10) / 10,
      scannerCount: scannerSet.size,
      totalObservations,
      lastUpdatedAt,
      severityDistribution,
      topVulnerablAssets,
      topTechnologies,
    };
  }

  /**
   * Build a timeline of observations for a specific asset.
   */
  buildAssetTimeline(
    observations: ObservationRow[],
    assetId: string,
    bucketMinutes = 60
  ): CorrelationTimeline[] {
    const assetObs = observations.filter((o) => o.assetId === assetId);
    if (assetObs.length === 0) return [];

    const bucketMs = bucketMinutes * 60 * 1000;
    const buckets = new Map<
      number,
      {
        observationCount: number;
        signalCount: number;
        newVulnerabilities: number;
        newPorts: number;
        scanners: Set<string>;
      }
    >();

    for (const obs of assetObs) {
      const ts = obs.observedAt || obs.ingestedAt || Date.now();
      const bucketKey = Math.floor(ts / bucketMs) * bucketMs;

      const bucket = buckets.get(bucketKey) || {
        observationCount: 0,
        signalCount: 0,
        newVulnerabilities: 0,
        newPorts: 0,
        scanners: new Set<string>(),
      };

      bucket.observationCount += 1;
      bucket.scanners.add(obs.scannerName);

      if (obs.observationType === "vulnerability_finding") {
        bucket.newVulnerabilities += 1;
      }
      if (
        obs.observationType === "service_banner" ||
        obs.observationType === "exposure_surface"
      ) {
        bucket.newPorts += 1;
      }

      buckets.set(bucketKey, bucket);
    }

    return Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([timestamp, data]) => ({
        timestamp,
        observationCount: data.observationCount,
        signalCount: data.signalCount,
        newVulnerabilities: data.newVulnerabilities,
        newPorts: data.newPorts,
        scannerName: Array.from(data.scanners).join(", "),
      }));
  }
}

// ─── Singleton ──────────────────────────────────────────────────────────────

let engineInstance: CorrelationEngine | null = null;

export function getCorrelationEngine(): CorrelationEngine {
  if (!engineInstance) {
    engineInstance = new CorrelationEngine();
  }
  return engineInstance;
}
