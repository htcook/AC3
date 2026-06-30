/**
 * Scan Coverage Heatmap
 *
 * Visualizes which ports, services, and paths were tested per asset,
 * highlighting coverage gaps that need manual follow-up.
 * Shows which tools tested each port/service and overall coverage scores.
 */

import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, Globe, Server,
  Crosshair, Search, Bug, Layers, BarChart3, Eye, EyeOff,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

interface ToolResult {
  tool: string;
  command: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  findingCount: number;
  findings: Array<{ severity: string; title: string; cve?: string }>;
  outputPreview: string;
  executedAt: number;
  phase: string;
}

interface AssetStatus {
  hostname: string;
  ip?: string;
  type: string;
  ports: Array<{ port: number; service: string; version?: string }>;
  vulns: Array<{ id: string; severity: string; title: string; cve?: string }>;
  zapFindings: Array<{ alert: string; risk: string; url: string; cweId?: number }>;
  exploitAttempts: Array<{ module: string; success: boolean; port?: number; service?: string }>;
  toolResults: ToolResult[];
  status: string;
  wafDetected?: string;
}

// ─── Coverage Computation ───────────────────────────────────────────────────

export interface PortCoverage {
  port: number;
  service: string;
  version?: string;
  discovered: boolean;
  portScanned: boolean;
  serviceIdentified: boolean;
  vulnScanned: boolean;
  exploitTested: boolean;
  zapScanned: boolean;
  toolsCovering: string[];
  findings: Array<{ severity: string; title: string }>;
  coverageScore: number; // 0-100
}

export interface AssetCoverage {
  hostname: string;
  ip?: string;
  type: string;
  status: string;
  ports: PortCoverage[];
  pathsCovered: number;
  pathsDiscovered: string[];
  toolsRun: string[];
  overallScore: number; // 0-100
  gaps: string[];
}

export interface EngagementCoverage {
  assets: AssetCoverage[];
  overallScore: number;
  totalPorts: number;
  coveredPorts: number;
  totalGaps: number;
}

/**
 * Compute coverage metrics from asset data.
 * Exported for testing.
 */
export function computeCoverage(assets: AssetStatus[]): EngagementCoverage {
  const assetCoverages: AssetCoverage[] = assets.map((asset) => {
    const toolsRun = [...new Set(asset.toolResults.map((t) => t.tool))];

    // Determine which tools cover which ports
    const portCoverages: PortCoverage[] = asset.ports.map((p) => {
      const portStr = String(p.port);
      const toolsCovering: string[] = [];

      // Check which tools touched this port
      for (const tr of asset.toolResults) {
        const cmd = tr.command || "";
        // Tool ran against this specific port or all ports
        if (
          cmd.includes(portStr) ||
          cmd.includes("-p-") ||
          cmd.includes("--top-ports") ||
          tr.tool === "httpx" ||
          tr.tool === "nuclei" ||
          tr.tool === "zap"
        ) {
          if (!toolsCovering.includes(tr.tool)) toolsCovering.push(tr.tool);
        }
      }

      // Check if port was vuln-scanned
      const vulnScanned =
        toolsCovering.some((t) => ["nuclei", "zap", "nikto"].includes(t)) ||
        asset.vulns.some((v) => v.title?.toLowerCase().includes(p.service?.toLowerCase() || "")) ||
        asset.zapFindings.length > 0;

      // Check if port was exploit-tested
      const exploitTested = asset.exploitAttempts.some(
        (e) => e.port === p.port || e.service === p.service
      );

      // Check if ZAP scanned (for web ports)
      const isWebPort = [80, 443, 8080, 8443, 8000, 3000, 5000, 9090].includes(p.port);
      const zapScanned =
        isWebPort &&
        (asset.zapFindings.length > 0 || toolsCovering.includes("zap"));

      // Findings for this port
      const findings = asset.vulns
        .filter(
          (v) =>
            v.title?.toLowerCase().includes(p.service?.toLowerCase() || "") ||
            v.title?.toLowerCase().includes(portStr)
        )
        .map((v) => ({ severity: v.severity, title: v.title }));

      // Coverage score for this port
      let score = 0;
      if (true) score += 20; // discovered
      if (p.service && p.service !== "unknown") score += 20; // service identified
      if (vulnScanned) score += 30; // vuln scanned
      if (exploitTested) score += 20; // exploit tested
      if (toolsCovering.length >= 2) score += 10; // multi-tool coverage

      return {
        port: p.port,
        service: p.service,
        version: p.version,
        discovered: true,
        portScanned: true,
        serviceIdentified: !!p.service && p.service !== "unknown",
        vulnScanned,
        exploitTested,
        zapScanned,
        toolsCovering,
        findings,
        coverageScore: Math.min(100, score),
      };
    });

    // Paths discovered from ZAP
    const pathsDiscovered = [...new Set(
      asset.zapFindings.map((f) => {
        try {
          return new URL(f.url).pathname;
        } catch {
          return f.url;
        }
      })
    )];

    // Identify gaps
    const gaps: string[] = [];
    for (const pc of portCoverages) {
      if (!pc.serviceIdentified) gaps.push(`Port ${pc.port}: service not identified`);
      if (!pc.vulnScanned) gaps.push(`Port ${pc.port}/${pc.service}: not vulnerability scanned`);
      if (pc.service && ["http", "https", "http-proxy"].includes(pc.service) && !pc.zapScanned) {
        gaps.push(`Port ${pc.port}/${pc.service}: no web application scan (ZAP)`);
      }
      if (pc.findings.some((f) => ["critical", "high"].includes(f.severity)) && !pc.exploitTested) {
        gaps.push(`Port ${pc.port}/${pc.service}: critical/high vuln found but not exploit-tested`);
      }
    }
    // Check for common ports not discovered
    const commonPorts = [21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
    const discoveredPorts = new Set(asset.ports.map((p) => p.port));
    const hasFullPortScan = asset.toolResults.some((t) => t.command?.includes("-p-") || t.command?.includes("--top-ports 1000"));
    if (!hasFullPortScan && asset.ports.length < 10) {
      gaps.push("Limited port scan — consider full port range (-p-)");
    }

    // Overall score
    const portScores = portCoverages.map((p) => p.coverageScore);
    const avgPortScore = portScores.length > 0 ? portScores.reduce((a, b) => a + b, 0) / portScores.length : 0;
    const toolDiversity = Math.min(100, toolsRun.length * 15);
    const overallScore = Math.round(avgPortScore * 0.7 + toolDiversity * 0.3);

    return {
      hostname: asset.hostname,
      ip: asset.ip,
      type: asset.type,
      status: asset.status,
      ports: portCoverages,
      pathsCovered: pathsDiscovered.length,
      pathsDiscovered,
      toolsRun,
      overallScore,
      gaps,
    };
  });

  const totalPorts = assetCoverages.reduce((s, a) => s + a.ports.length, 0);
  const coveredPorts = assetCoverages.reduce(
    (s, a) => s + a.ports.filter((p) => p.vulnScanned).length,
    0
  );
  const totalGaps = assetCoverages.reduce((s, a) => s + a.gaps.length, 0);
  const overallScore =
    assetCoverages.length > 0
      ? Math.round(assetCoverages.reduce((s, a) => s + a.overallScore, 0) / assetCoverages.length)
      : 0;

  return { assets: assetCoverages, overallScore, totalPorts, coveredPorts, totalGaps };
}

// ─── Score Color Helper ─────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-green-500/20 border-green-500/30";
  if (score >= 60) return "bg-yellow-500/20 border-yellow-500/30";
  if (score >= 40) return "bg-orange-500/20 border-orange-500/30";
  return "bg-red-500/20 border-red-500/30";
}

function cellColor(score: number): string {
  if (score >= 80) return "bg-green-500/40";
  if (score >= 60) return "bg-yellow-500/40";
  if (score >= 40) return "bg-orange-500/40";
  if (score > 0) return "bg-red-500/40";
  return "bg-zinc-800/40";
}

// ─── Component ──────────────────────────────────────────────────────────────

interface ScanCoverageHeatmapProps {
  assets: AssetStatus[];
}

export default function ScanCoverageHeatmap({ assets }: ScanCoverageHeatmapProps) {
  const [selectedAsset, setSelectedAsset] = useState<string>("all");
  const [showGaps, setShowGaps] = useState(true);

  const coverage = useMemo(() => computeCoverage(assets), [assets]);

  const displayAssets =
    selectedAsset === "all"
      ? coverage.assets
      : coverage.assets.filter((a) => a.hostname === selectedAsset);

  if (assets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
        <Search className="h-12 w-12 mb-3 opacity-30" />
        <p className="text-sm">No assets scanned yet. Coverage data will appear after the enumeration phase completes.</p>
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="space-y-4">
        {/* Description */}
        <p className="text-xs text-muted-foreground leading-relaxed">
          This heatmap shows which ports, services, and paths were tested per asset. Green cells indicate
          thorough coverage, yellow indicates partial coverage, and red highlights gaps that may need manual
          follow-up. Use this to identify areas where additional testing is needed.
        </p>

        {/* ── Summary Stats ── */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="bg-card/60 border-border/30">
            <CardContent className="p-3 flex items-center gap-2">
              <div className={`text-2xl font-bold ${scoreColor(coverage.overallScore)}`}>
                {coverage.overallScore}%
              </div>
              <div className="text-[10px] text-muted-foreground leading-tight">Overall<br />Coverage</div>
            </CardContent>
          </Card>
          <Card className="bg-card/60 border-border/30">
            <CardContent className="p-3 flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-cyan-400" />
              <div>
                <div className="text-sm font-semibold text-foreground">{coverage.assets.length}</div>
                <div className="text-[10px] text-muted-foreground">Assets</div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/60 border-border/30">
            <CardContent className="p-3 flex items-center gap-2">
              <Layers className="h-5 w-5 text-blue-400" />
              <div>
                <div className="text-sm font-semibold text-foreground">
                  {coverage.coveredPorts}/{coverage.totalPorts}
                </div>
                <div className="text-[10px] text-muted-foreground">Ports Scanned</div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/60 border-border/30">
            <CardContent className="p-3 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-orange-400" />
              <div>
                <div className="text-sm font-semibold text-foreground">{coverage.totalGaps}</div>
                <div className="text-[10px] text-muted-foreground">Gaps Found</div>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card/60 border-border/30">
            <CardContent className="p-3 flex items-center gap-2">
              <Crosshair className="h-5 w-5 text-green-400" />
              <div>
                <div className="text-sm font-semibold text-foreground">
                  {coverage.assets.reduce((s, a) => s + a.toolsRun.length, 0)}
                </div>
                <div className="text-[10px] text-muted-foreground">Tool Runs</div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ── Controls ── */}
        <div className="flex items-center gap-3">
          <Select value={selectedAsset} onValueChange={setSelectedAsset}>
            <SelectTrigger className="w-[220px] h-8 text-xs bg-card/60 border-border/30">
              <SelectValue placeholder="Filter by asset" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Assets</SelectItem>
              {coverage.assets.map((a) => (
                <SelectItem key={a.hostname} value={a.hostname}>
                  {a.hostname}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <button
            onClick={() => setShowGaps(!showGaps)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors ${
              showGaps
                ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                : "bg-card/60 text-muted-foreground border border-border/30"
            }`}
          >
            {showGaps ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
            {showGaps ? "Gaps Visible" : "Gaps Hidden"}
          </button>
        </div>

        {/* ── Per-Asset Heatmaps ── */}
        {displayAssets.map((asset) => (
          <Card key={asset.hostname} className="bg-card/60 border-border/30 overflow-hidden">
            <CardHeader className="pb-2 px-4 pt-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-400" />
                  <CardTitle className="text-sm font-medium text-foreground">
                    {asset.hostname}
                  </CardTitle>
                  {asset.ip && (
                    <span className="text-[10px] text-muted-foreground font-mono">{asset.ip}</span>
                  )}
                  <Badge variant="outline" className="text-[9px]">{asset.type}</Badge>
                  <Badge
                    variant="outline"
                    className={`text-[9px] ${
                      asset.status === "compromised"
                        ? "bg-red-500/10 text-red-400 border-red-500/20"
                        : asset.status === "vulnerable"
                        ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                        : "bg-green-500/10 text-green-400 border-green-500/20"
                    }`}
                  >
                    {asset.status}
                  </Badge>
                </div>
                <div className={`text-lg font-bold ${scoreColor(asset.overallScore)}`}>
                  {asset.overallScore}%
                </div>
              </div>
            </CardHeader>
            <CardContent className="px-4 pb-3 space-y-3">
              {/* Tools Run */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] text-muted-foreground mr-1">Tools:</span>
                {asset.toolsRun.map((tool) => (
                  <Badge key={tool} variant="outline" className="text-[9px] bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
                    {tool}
                  </Badge>
                ))}
                {asset.toolsRun.length === 0 && (
                  <span className="text-[10px] text-muted-foreground italic">No tools run yet</span>
                )}
              </div>

              {/* Port Coverage Grid */}
              {asset.ports.length > 0 && (
                <div>
                  <div className="text-[10px] text-muted-foreground mb-1.5 font-medium">Port Coverage</div>
                  <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(auto-fill, minmax(100px, 1fr))` }}>
                    {asset.ports.map((pc) => (
                      <Tooltip key={pc.port}>
                        <TooltipTrigger asChild>
                          <div
                            className={`rounded-md px-2 py-1.5 border border-border/20 cursor-pointer transition-colors hover:border-border/50 ${cellColor(pc.coverageScore)}`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-mono font-semibold text-foreground">{pc.port}</span>
                              <span className={`text-[9px] font-bold ${scoreColor(pc.coverageScore)}`}>
                                {pc.coverageScore}%
                              </span>
                            </div>
                            <div className="text-[9px] text-muted-foreground truncate">
                              {pc.service || "unknown"}
                            </div>
                            {/* Coverage indicators */}
                            <div className="flex items-center gap-0.5 mt-1">
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <div className={`w-2 h-2 rounded-full ${pc.serviceIdentified ? "bg-green-400" : "bg-red-400"}`} />
                                </TooltipTrigger>
                                <TooltipContent side="bottom" className="text-[10px]">
                                  Service: {pc.serviceIdentified ? "Identified" : "Unknown"}
                                </TooltipContent>
                              </Tooltip>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <div className={`w-2 h-2 rounded-full ${pc.vulnScanned ? "bg-green-400" : "bg-red-400"}`} />
                                </TooltipTrigger>
                                <TooltipContent side="bottom" className="text-[10px]">
                                  Vuln Scan: {pc.vulnScanned ? "Done" : "Missing"}
                                </TooltipContent>
                              </Tooltip>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <div className={`w-2 h-2 rounded-full ${pc.exploitTested ? "bg-green-400" : "bg-zinc-600"}`} />
                                </TooltipTrigger>
                                <TooltipContent side="bottom" className="text-[10px]">
                                  Exploit: {pc.exploitTested ? "Tested" : "Not tested"}
                                </TooltipContent>
                              </Tooltip>
                              {pc.zapScanned && (
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <div className="w-2 h-2 rounded-full bg-blue-400" />
                                  </TooltipTrigger>
                                  <TooltipContent side="bottom" className="text-[10px]">
                                    ZAP: Scanned
                                  </TooltipContent>
                                </Tooltip>
                              )}
                            </div>
                          </div>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-xs">
                          <div className="space-y-1">
                            <div className="font-semibold text-xs">
                              Port {pc.port}/{pc.service} {pc.version ? `(${pc.version})` : ""}
                            </div>
                            <div className="text-[10px] space-y-0.5">
                              <div className="flex items-center gap-1">
                                {pc.serviceIdentified ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                                Service identification
                              </div>
                              <div className="flex items-center gap-1">
                                {pc.vulnScanned ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-red-400" />}
                                Vulnerability scan
                              </div>
                              <div className="flex items-center gap-1">
                                {pc.exploitTested ? <CheckCircle2 className="h-3 w-3 text-green-400" /> : <XCircle className="h-3 w-3 text-zinc-500" />}
                                Exploit testing
                              </div>
                              {pc.zapScanned && (
                                <div className="flex items-center gap-1">
                                  <CheckCircle2 className="h-3 w-3 text-blue-400" />
                                  Web app scan (ZAP)
                                </div>
                              )}
                            </div>
                            {pc.toolsCovering.length > 0 && (
                              <div className="text-[10px] text-muted-foreground">
                                Tools: {pc.toolsCovering.join(", ")}
                              </div>
                            )}
                            {pc.findings.length > 0 && (
                              <div className="text-[10px]">
                                <span className="text-orange-400">{pc.findings.length} finding(s)</span>
                              </div>
                            )}
                          </div>
                        </TooltipContent>
                      </Tooltip>
                    ))}
                  </div>
                  {/* Legend */}
                  <div className="flex items-center gap-3 mt-2 text-[9px] text-muted-foreground">
                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-green-400" /> Service ID</span>
                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-green-400" /> Vuln Scan</span>
                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-green-400" /> Exploit</span>
                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-blue-400" /> ZAP</span>
                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-400" /> Missing</span>
                  </div>
                </div>
              )}

              {/* Path Coverage */}
              {asset.pathsCovered > 0 && (
                <div>
                  <div className="text-[10px] text-muted-foreground mb-1 font-medium">
                    Web Paths Discovered: {asset.pathsCovered}
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-20 overflow-y-auto">
                    {asset.pathsDiscovered.slice(0, 30).map((path, i) => (
                      <Badge key={i} variant="outline" className="text-[9px] font-mono bg-blue-500/5 text-blue-300 border-blue-500/15">
                        {path}
                      </Badge>
                    ))}
                    {asset.pathsDiscovered.length > 30 && (
                      <Badge variant="outline" className="text-[9px] text-muted-foreground">
                        +{asset.pathsDiscovered.length - 30} more
                      </Badge>
                    )}
                  </div>
                </div>
              )}

              {/* Coverage Gaps */}
              {showGaps && asset.gaps.length > 0 && (
                <div className="bg-orange-500/5 border border-orange-500/15 rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] text-orange-400 font-medium mb-1.5">
                    <AlertTriangle className="h-3 w-3" />
                    Coverage Gaps ({asset.gaps.length})
                  </div>
                  <div className="space-y-0.5">
                    {asset.gaps.map((gap, i) => (
                      <div key={i} className="text-[10px] text-orange-300/80 flex items-start gap-1.5">
                        <XCircle className="h-3 w-3 flex-none mt-0.5 text-orange-400/60" />
                        {gap}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </TooltipProvider>
  );
}
