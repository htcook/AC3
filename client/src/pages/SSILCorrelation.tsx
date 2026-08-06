/**
 * SSIL Cross-Scanner Correlation Dashboard
 * Aggregates observations by target asset for unified attack surface view
 * Author: Harrison Cook — AceofCloud
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  GitMerge,
  Search,
  Globe,
  Shield,
  AlertTriangle,
  Server,
  Lock,
  Wifi,
  Bug,
  Eye,
  ChevronRight,
  BarChart3,
  Layers,
  Radar,
} from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

function RiskGauge({ score, size = "lg" }: { score: number; size?: "sm" | "lg" }) {
  const color =
    score >= 80 ? "text-red-400" :
    score >= 60 ? "text-orange-400" :
    score >= 40 ? "text-yellow-400" :
    score >= 20 ? "text-blue-400" : "text-green-400";
  const bgColor =
    score >= 80 ? "bg-red-500" :
    score >= 60 ? "bg-orange-500" :
    score >= 40 ? "bg-yellow-500" :
    score >= 20 ? "bg-blue-500" : "bg-green-500";

  if (size === "sm") {
    return (
      <div className="flex items-center gap-2">
        <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
          <div className={`h-full ${bgColor} rounded-full`} style={{ width: `${score}%` }} />
        </div>
        <span className={`font-mono text-xs font-bold ${color}`}>{score.toFixed(0)}</span>
      </div>
    );
  }

  return (
    <div className="text-center">
      <div className={`text-4xl font-mono font-black ${color}`}>{score.toFixed(1)}</div>
      <Progress value={score} className="h-2 mt-2" />
      <p className="text-[10px] text-muted-foreground mt-1">COMPOSITE RISK</p>
    </div>
  );
}

function SummaryCards() {
  const { data: summary } = trpc.ssil.getAttackSurfaceSummary.useQuery();
  if (!summary) return null;

  const cards = [
    { label: "Total Assets", value: summary.totalAssets, icon: Globe, color: "text-blue-400" },
    { label: "Open Ports", value: summary.totalOpenPorts, icon: Wifi, color: "text-yellow-400" },
    { label: "Vulnerabilities", value: summary.totalVulnerabilities, icon: Bug, color: "text-red-400" },
    { label: "Technologies", value: summary.topTechnologies?.length || 0, icon: Server, color: "text-teal-400" },
    { label: "Observations", value: summary.totalObservations, icon: Eye, color: "text-purple-400" },
    { label: "Avg Risk Score", value: summary.averageRiskScore?.toFixed(1) || "0", icon: BarChart3, color: "text-orange-400" },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((c) => (
        <Card key={c.label} className="bg-card/50 border-border/50">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <c.icon className={`w-4 h-4 ${c.color} opacity-60`} />
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{c.label}</span>
            </div>
            <p className={`text-xl font-mono font-bold mt-1 ${c.color}`}>{c.value}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ScannerBreakdown({ summary }: { summary: any }) {
  if (!summary?.scannerBreakdown) return null;
  const entries = Object.entries(summary.scannerBreakdown) as [string, number][];
  const maxCount = Math.max(...entries.map(([, c]) => c), 1);

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-display tracking-wider">SCANNER COVERAGE</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {entries.map(([scanner, count]) => (
          <div key={scanner} className="flex items-center gap-3">
            <span className="text-xs font-mono w-28 truncate text-muted-foreground">{scanner}</span>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary/60 rounded-full transition-all"
                style={{ width: `${(count / maxCount) * 100}%` }}
              />
            </div>
            <span className="text-xs font-mono text-muted-foreground w-8 text-right">{count}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function SeverityDistribution({ summary }: { summary: any }) {
  if (!summary?.severityDistribution) return null;
  const entries = Object.entries(summary.severityDistribution) as [string, number][];
  const total = entries.reduce((s, [, c]) => s + c, 0) || 1;

  return (
    <Card className="bg-card/50 border-border/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-display tracking-wider">SEVERITY DISTRIBUTION</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex h-6 rounded-full overflow-hidden">
          {["critical", "high", "medium", "low", "info"].map((sev) => {
            const count = (summary.severityDistribution[sev] as number) || 0;
            const pct = (count / total) * 100;
            if (pct === 0) return null;
            const colors: Record<string, string> = {
              critical: "bg-red-500",
              high: "bg-orange-500",
              medium: "bg-yellow-500",
              low: "bg-blue-500",
              info: "bg-gray-500",
            };
            return (
              <div
                key={sev}
                className={`${colors[sev]} transition-all`}
                style={{ width: `${pct}%` }}
                title={`${sev}: ${count}`}
              />
            );
          })}
        </div>
        <div className="flex justify-between mt-2">
          {["critical", "high", "medium", "low", "info"].map((sev) => {
            const count = (summary.severityDistribution[sev] as number) || 0;
            return (
              <div key={sev} className="text-center">
                <Badge className={`${SEVERITY_COLORS[sev]} text-[9px]`}>{count}</Badge>
                <p className="text-[9px] text-muted-foreground mt-0.5 capitalize">{sev}</p>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function AssetDetail({ assetId }: { assetId: string }) {
  const { data } = trpc.ssil.getAssetCorrelationDetail.useQuery({ assetId });
  if (!data?.asset) return <div className="text-center py-8 text-muted-foreground">Loading asset details...</div>;

  const asset = data.asset;
  const timeline = data.timeline || [];

  return (
    <div className="space-y-4">
      {/* Asset header */}
      <Card className="bg-card/50 border-border/50">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-display tracking-wider text-lg">{asset.host}</h3>
              <p className="text-xs text-muted-foreground mt-1">
                Asset ID: <span className="font-mono">{asset.assetId}</span>
              </p>
            </div>
            <RiskGauge score={asset.compositeRiskScore} />
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Open Ports */}
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-display tracking-wider flex items-center gap-2">
              <Wifi className="w-3.5 h-3.5 text-yellow-400" /> OPEN PORTS ({asset.openPorts?.length || 0})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1">
              {(asset.openPorts || []).map((p: any, i: number) => (
                <Badge key={i} variant="outline" className="font-mono text-[10px]">{typeof p === 'number' ? p : p.port}</Badge>
              ))}
              {(!asset.openPorts || asset.openPorts.length === 0) && (
                <span className="text-xs text-muted-foreground">None detected</span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Technologies */}
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-display tracking-wider flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-teal-400" /> TECHNOLOGIES ({asset.technologies?.length || 0})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1">
              {(asset.technologies || []).map((t: any, i: number) => (
                <Badge key={i} variant="outline" className="text-[10px]">{typeof t === 'string' ? t : t.name}</Badge>
              ))}
              {(!asset.technologies || asset.technologies.length === 0) && (
                <span className="text-xs text-muted-foreground">None detected</span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Vulnerabilities */}
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-display tracking-wider flex items-center gap-2">
              <Bug className="w-3.5 h-3.5 text-red-400" /> VULNERABILITIES ({asset.vulnerabilities?.length || 0})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1">
              {(asset.vulnerabilities || []).slice(0, 10).map((v: any, i: number) => (
                <Badge key={i} className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]">{typeof v === 'string' ? v : v.cveId || v.id || 'CVE'}</Badge>
              ))}
              {(!asset.vulnerabilities || asset.vulnerabilities.length === 0) && (
                <span className="text-xs text-muted-foreground">None detected</span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Scanner breakdown */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-display tracking-wider">SCANNER OBSERVATIONS</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {Object.entries((asset as any).scannerBreakdown || {}).map(([scanner, count]) => (
              <div key={scanner} className="flex items-center justify-between text-xs">
                <span className="font-mono text-muted-foreground">{scanner}</span>
                <Badge variant="outline" className="font-mono">{count as number}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Timeline */}
      {timeline.length > 0 && (
        <Card className="bg-card/50 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-display tracking-wider">OBSERVATION TIMELINE</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {timeline.map((bucket: any, i: number) => {
                const maxCount = Math.max(...timeline.map((b: any) => b.count), 1);
                return (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className="font-mono text-muted-foreground w-32 text-[10px]">
                      {new Date(bucket.startTime).toLocaleString()}
                    </span>
                    <div className="flex-1 h-3 bg-muted rounded overflow-hidden">
                      <div
                        className="h-full bg-primary/50 rounded"
                        style={{ width: `${(bucket.count / maxCount) * 100}%` }}
                      />
                    </div>
                    <span className="font-mono w-6 text-right">{bucket.count}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AssetsTab() {
  const [hostFilter, setHostFilter] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const { data, isLoading } = trpc.ssil.getCorrelatedAssets.useQuery({
    limit: 100,
    hostFilter: hostFilter || undefined,
  });

  if (selectedAssetId) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => setSelectedAssetId(null)} className="gap-1">
          ← Back to Assets
        </Button>
        <AssetDetail assetId={selectedAssetId} />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
            placeholder="Filter by hostname..."
            className="pl-9"
          />
        </div>
        <span className="text-xs text-muted-foreground">{data?.total || 0} assets</span>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Correlating observations across scanners...</div>
      ) : !data?.assets?.length ? (
        <Card className="bg-card/30 border-dashed border-border/50">
          <CardContent className="p-8 text-center">
            <Radar className="w-12 h-12 mx-auto text-muted-foreground/30 mb-3" />
            <p className="text-muted-foreground">No correlated assets found</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Run scans to populate the observation pipeline.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {data.assets.map((asset: any) => (
            <Card
              key={asset.assetId}
              className="bg-card/50 border-border/50 hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => setSelectedAssetId(asset.assetId)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 flex-1 min-w-0">
                    <Globe className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-display tracking-wider text-sm">{asset.host}</span>
                        {asset.vulnerabilities?.length > 0 && (
                          <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-[10px]">
                            {asset.vulnerabilities.length} CVE
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                        <span>{asset.totalObservations} obs</span>
                        <span>{asset.openPorts?.length || 0} ports</span>
                        <span>{asset.technologies?.length || 0} tech</span>
                        <span>{Object.keys(asset.scannerBreakdown || {}).length} scanners</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <RiskGauge score={asset.compositeRiskScore} size="sm" />
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SSILCorrelation() {
  const { data: summary } = trpc.ssil.getAttackSurfaceSummary.useQuery();

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-display tracking-wider">CROSS-SCANNER CORRELATION</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Unified attack surface view aggregating observations across all scanners
            </p>
          </div>
          <GitMerge className="w-8 h-8 text-primary opacity-50" />
        </div>

        {/* Summary Cards */}
        <SummaryCards />

        {/* Tabs */}
        <Tabs defaultValue="assets">
          <TabsList>
            <TabsTrigger value="assets">Correlated Assets</TabsTrigger>
            <TabsTrigger value="coverage">Scanner Coverage</TabsTrigger>
          </TabsList>
          <TabsContent value="assets" className="mt-4">
            <AssetsTab />
          </TabsContent>
          <TabsContent value="coverage" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ScannerBreakdown summary={summary} />
              <SeverityDistribution summary={summary} />
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
