import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RefreshCw, Zap, Database, ArrowRight, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";

const SOURCE_ICONS: Record<string, string> = {
  "vuln-scanner": "🔍",
  "web-app-scanning": "🌐",
  "nuclei-scanner": "⚛️",
  "osint-recon": "🕵️",
  "phishing-ops": "🎣",
  "siem-connectors": "📊",
  "edr-validation": "🛡️",
  "ngfw-validation": "🔥",
  "ad-attack-sim": "🏰",
  "cloud-misconfigs": "☁️",
  "threat-intel": "🎯",
  "unified-pipeline": "🔗",
  "atomic-red-team": "☢️",
  "exploit-arsenal": "💣",
  "darkweb-intel": "🌑",
  "credential-alerts": "🔑",
  "compliance-mapper": "📋",
};

export default function KsiAutoCollector() {
  const [isCollecting, setIsCollecting] = useState(false);
  const [sweepResults, setSweepResults] = useState<any>(null);

  const { data: mappings } = trpc.ksiAutoCollector.getSourceMappings.useQuery();
  const { data: stats, refetch: refetchStats } = trpc.ksiAutoCollector.getCollectionStats.useQuery();

  const fullSweep = trpc.ksiAutoCollector.runFullCollection.useMutation({
    onSuccess: (data) => {
      setSweepResults(data);
      refetchStats();
      toast.success(`Collected ${data.totalCollected} evidence items from ${data.results.length} sources`);
      setIsCollecting(false);
    },
    onError: (err) => {
      toast.error(err.message);
      setIsCollecting(false);
    },
  });

  const collectVuln = trpc.ksiAutoCollector.collectFromVulnScanner.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from vuln scanner`); },
    onError: (e) => toast.error(e.message),
  });
  const collectWebApp = trpc.ksiAutoCollector.collectFromWebAppScanner.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from web app scanner`); },
    onError: (e) => toast.error(e.message),
  });
  const collectOsint = trpc.ksiAutoCollector.collectFromOsint.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from OSINT`); },
    onError: (e) => toast.error(e.message),
  });
  const collectPhishing = trpc.ksiAutoCollector.collectFromPhishing.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from phishing ops`); },
    onError: (e) => toast.error(e.message),
  });
  const collectEdr = trpc.ksiAutoCollector.collectFromEdr.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from EDR`); },
    onError: (e) => toast.error(e.message),
  });
  const collectNgfw = trpc.ksiAutoCollector.collectFromNgfw.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from NGFW`); },
    onError: (e) => toast.error(e.message),
  });
  const collectAd = trpc.ksiAutoCollector.collectFromAdAttackSim.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from AD attack sim`); },
    onError: (e) => toast.error(e.message),
  });
  const collectCloud = trpc.ksiAutoCollector.collectFromCloudMisconfigs.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from cloud misconfigs`); },
    onError: (e) => toast.error(e.message),
  });
  const collectAtomic = trpc.ksiAutoCollector.collectFromAtomicRedTeam.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from Atomic Red Team`); },
    onError: (e) => toast.error(e.message),
  });
  const collectThreat = trpc.ksiAutoCollector.collectFromThreatIntel.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Collected ${d.collected} items from threat intel`); },
    onError: (e) => toast.error(e.message),
  });

  const collectorMap: Record<string, any> = {
    "vuln-scanner": collectVuln,
    "web-app-scanning": collectWebApp,
    "osint-recon": collectOsint,
    "phishing-ops": collectPhishing,
    "edr-validation": collectEdr,
    "ngfw-validation": collectNgfw,
    "ad-attack-sim": collectAd,
    "cloud-misconfigs": collectCloud,
    "atomic-red-team": collectAtomic,
    "threat-intel": collectThreat,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Indicator Auto-Collection</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Configure and run automated collection of Key Security Indicators from multiple intelligence sources. This tool continuously gathers threat data, vulnerability feeds, and security metrics to keep your knowledge base current. Set up collection schedules, monitor feed health, and review newly collected indicators before they're integrated into your threat intelligence pipeline.</p>
          <p className="text-muted-foreground">
            Automatically feed evidence from existing scanners and tools into the Indicator Evidence Chain
          </p>
        </div>
        <Button
          size="lg"
          onClick={() => { setIsCollecting(true); fullSweep.mutate(); }}
          disabled={isCollecting}
          className="gap-2"
        >
          {isCollecting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
          Run Full Collection Sweep
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Evidence</CardDescription>
            <CardTitle className="text-3xl">{stats?.totalEvidence ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Auto-Collected</CardDescription>
            <CardTitle className="text-3xl text-emerald-500">{stats?.autoCollected ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Manual</CardDescription>
            <CardTitle className="text-3xl text-blue-500">{stats?.manualCollected ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Source Mappings</CardDescription>
            <CardTitle className="text-3xl">{stats?.sourceMappingCount ?? 0}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Sweep Results */}
      {sweepResults && (
        <Card className="border-emerald-500/30 bg-emerald-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              Collection Sweep Complete
            </CardTitle>
            <CardDescription>
              {sweepResults.totalCollected} evidence items collected at {new Date(sweepResults.sweepTime).toLocaleString()}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {sweepResults.results.map((r: any) => (
                <div key={r.source} className="flex items-center gap-2 text-sm">
                  <span>{SOURCE_ICONS[r.source] || "📦"}</span>
                  <span className="text-muted-foreground">{r.source}</span>
                  <Badge variant={r.collected > 0 ? "default" : "outline"} className="ml-auto">
                    {r.collected}
                  </Badge>
                  {r.error && <AlertTriangle className="h-3 w-3 text-amber-500" />}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Source Mappings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5" />
            Source-to-KSI Mappings
          </CardTitle>
          <CardDescription>
            Each scanner module maps to specific FedRAMP KSIs. Click "Collect" to pull evidence from individual sources.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {mappings?.map((m) => (
              <div key={m.sourceModule} className="flex items-center gap-4 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors">
                <span className="text-2xl">{SOURCE_ICONS[m.sourceModule] || "📦"}</span>
                <div className="flex-1 min-w-0">
                  <div className="font-medium">{m.sourceModule}</div>
                  <div className="text-xs text-muted-foreground truncate">{m.description}</div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {m.ksiIds.map((id) => (
                      <Badge key={id} variant="outline" className="text-[10px] px-1.5 py-0">
                        {id}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Badge variant="secondary" className="shrink-0">{m.evidenceType}</Badge>
                <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0" />
                {collectorMap[m.sourceModule] ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => collectorMap[m.sourceModule].mutate()}
                    disabled={collectorMap[m.sourceModule].isPending}
                    className="shrink-0"
                  >
                    {collectorMap[m.sourceModule].isPending ? (
                      <Loader2 className="h-3 w-3 animate-spin" />
                    ) : (
                      <RefreshCw className="h-3 w-3" />
                    )}
                    <span className="ml-1">Collect</span>
                  </Button>
                ) : (
                  <Badge variant="outline" className="text-muted-foreground shrink-0">Manual</Badge>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Evidence by Source */}
      {stats?.bySource && stats.bySource.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Evidence by Source</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {stats.bySource.map((s) => (
                <div key={s.sourceModule} className="flex items-center gap-3">
                  <span className="text-lg">{SOURCE_ICONS[s.sourceModule || ""] || "📦"}</span>
                  <span className="text-sm flex-1">{s.sourceModule}</span>
                  <div className="w-48 bg-muted rounded-full h-2 overflow-hidden">
                    <div
                      className="bg-emerald-500 h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, ((s.count || 0) / Math.max(stats.totalEvidence, 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono w-12 text-right">{s.count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
