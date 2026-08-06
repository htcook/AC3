import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RefreshCw, Zap, Database, ArrowRight, CheckCircle2, AlertTriangle, Loader2, Radio, Cloud, Shield, Server, Crosshair, Atom, BarChart3, Globe } from "lucide-react";
import AppShell from "@/components/AppShell";
import { getKsiLabel } from "@/lib/ksi-labels";
import { getKsiEnriched } from "@/lib/ksi-enriched-data";
import CollectionHealthPanel from "@/components/CollectionHealthPanel";

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
  const [isLiveSweeping, setIsLiveSweeping] = useState(false);
  const [sweepResults, setSweepResults] = useState<any>(null);
  const [liveSweepResults, setLiveSweepResults] = useState<any>(null);

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

  // DB-based collectors
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

  // Live API collectors
  const liveCloudMisconfigs = trpc.ksiAutoCollector.collectCloudMisconfigsLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.misconfigsFound} cloud misconfigs found, ${d.collected} KSI evidence items`); },
    onError: (e) => toast.error(`Cloud Misconfigs: ${e.message}`),
  });
  const liveNgfw = trpc.ksiAutoCollector.collectNgfwLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.testsRun} NGFW tests — ${d.passed} passed, ${d.failed} failed`); },
    onError: (e) => toast.error(`NGFW: ${e.message}`),
  });
  const liveAdSim = trpc.ksiAutoCollector.collectAdAttackSimLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.simsFound} AD attack simulations from Cyber C2`); },
    onError: (e) => toast.error(`AD Sim: ${e.message}`),
  });
  const liveEdr = trpc.ksiAutoCollector.collectEdrLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.testsProcessed} EDR tests — ${d.detected} detected, ${d.missed} missed`); },
    onError: (e) => toast.error(`EDR: ${e.message}`),
  });
  const liveAtomic = trpc.ksiAutoCollector.collectAtomicRedTeamLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.executionsProcessed} Atomic Red Team executions from Cyber C2`); },
    onError: (e) => toast.error(`Atomic: ${e.message}`),
  });
  const liveSiem = trpc.ksiAutoCollector.collectSiemLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.connectionsFound} SIEM connections — ${d.connected} connected`); },
    onError: (e) => toast.error(`SIEM: ${e.message}`),
  });
  const liveThreatIntel = trpc.ksiAutoCollector.collectThreatIntelLive.useMutation({
    onSuccess: (d) => { refetchStats(); toast.success(`Live: ${d.feedsProcessed} threat intel feeds, ${d.totalIocs} IOCs`); },
    onError: (e) => toast.error(`Threat Intel: ${e.message}`),
  });
  const liveSweep = trpc.ksiAutoCollector.runLiveCollectionSweep.useMutation({
    onSuccess: (data) => {
      setLiveSweepResults(data);
      refetchStats();
      toast.success(`Live sweep: ${data.totalCollected} items from ${data.totalSources} sources`);
      setIsLiveSweeping(false);
    },
    onError: (err) => {
      toast.error(err.message);
      setIsLiveSweeping(false);
    },
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

  const liveCollectors = [
    { key: "cloud-misconfigs", name: "Cloud Misconfigs", desc: "DigitalOcean droplets, firewalls, load balancers, databases", icon: Cloud, mutation: liveCloudMisconfigs, color: "text-sky-500" },
    { key: "ngfw-validation", name: "NGFW Validation", desc: "DigitalOcean firewall rule validation & port probes", icon: Shield, mutation: liveNgfw, color: "text-orange-500" },
    { key: "ad-attack-sim", name: "AD Attack Sim", desc: "Cyber C2 AD techniques (Kerberoasting, DCSync, Pass-the-Hash)", icon: Crosshair, mutation: liveAdSim, color: "text-red-500" },
    { key: "edr-validation", name: "EDR Validation", desc: "Cyber C2 operation detection coverage analysis", icon: Shield, mutation: liveEdr, color: "text-emerald-500" },
    { key: "atomic-red-team", name: "Atomic Red Team", desc: "Cyber C2 ability executions mapped to MITRE ATT&CK", icon: Atom, mutation: liveAtomic, color: "text-yellow-500" },
    { key: "siem-connectors", name: "SIEM Connectors", desc: "Wazuh & Elasticsearch connectivity and alert counts", icon: BarChart3, mutation: liveSiem, color: "text-purple-500" },
    { key: "threat-intel", name: "Threat Intel", desc: "abuse.ch URLhaus/ThreatFox, Shodan, SecurityTrails", icon: Globe, mutation: liveThreatIntel, color: "text-rose-500" },
  ];

  return (
    <AppShell activePath="/ksi-auto-collector">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Indicator Auto-Collection</h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">
              Automatically feed evidence from existing scanners, live APIs, and security tools into the Key Security Indicator Evidence Chain.
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => { setIsCollecting(true); fullSweep.mutate(); }}
              disabled={isCollecting}
              className="gap-2"
            >
              {isCollecting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
              DB Sweep
            </Button>
            <Button
              size="lg"
              onClick={() => { setIsLiveSweeping(true); liveSweep.mutate(); }}
              disabled={isLiveSweeping}
              className="gap-2"
            >
              {isLiveSweeping ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radio className="h-4 w-4" />}
              Run Live API Sweep
            </Button>
          </div>
        </div>

        {/* Collection Health Panel */}
        <CollectionHealthPanel stats={stats} mappings={mappings} />

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

        {/* Live Sweep Results */}
        {liveSweepResults && (
          <Card className="border-blue-500/30 bg-blue-500/5">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Radio className="h-5 w-5 text-blue-500" />
                Live API Sweep Complete
              </CardTitle>
              <CardDescription>
                {liveSweepResults.totalCollected} items from {liveSweepResults.totalSources} live API sources at {new Date(liveSweepResults.sweepTime).toLocaleString()}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {liveSweepResults.results.map((r: any) => (
                  <div key={r.source} className="flex items-center gap-2 text-sm p-2 rounded-md bg-background/50">
                    <span>{SOURCE_ICONS[r.source.replace("-live", "")] || "📦"}</span>
                    <span className="flex-1 text-muted-foreground">{r.source}</span>
                    <Badge variant={r.collected > 0 ? "default" : "outline"}>
                      {r.collected}
                    </Badge>
                    {r.error && (
                      <span className="text-amber-500 text-xs truncate max-w-[200px]" title={r.error}>
                        <AlertTriangle className="h-3 w-3 inline mr-1" />{r.error.slice(0, 40)}
                      </span>
                    )}
                    {r.details && !r.error && (
                      <span className="text-xs text-muted-foreground">
                        {Object.entries(r.details).map(([k, v]) => `${k}: ${v}`).join(" | ")}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* DB Sweep Results */}
        {sweepResults && (
          <Card className="border-emerald-500/30 bg-emerald-500/5">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                DB Collection Sweep Complete
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

        {/* Live API Collectors */}
        <Card className="border-blue-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radio className="h-5 w-5 text-blue-500" />
              Live API Collectors
            </CardTitle>
            <CardDescription>
              Real-time evidence collection from external APIs. Each collector calls live endpoints (DigitalOcean, Cyber C2, Shodan, abuse.ch, SecurityTrails, Wazuh) and stores results in the database.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {liveCollectors.map((lc) => {
                const Icon = lc.icon;
                return (
                  <div key={lc.key} className="flex items-center gap-3 p-3 rounded-lg border bg-card hover:bg-accent/50 transition-colors">
                    <div className={`p-2 rounded-md bg-muted ${lc.color}`}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm">{lc.name}</div>
                      <div className="text-xs text-muted-foreground truncate">{lc.desc}</div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => lc.mutation.mutate()}
                      disabled={lc.mutation.isPending}
                      className="shrink-0 gap-1"
                    >
                      {lc.mutation.isPending ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Radio className="h-3 w-3" />
                      )}
                      Collect Live
                    </Button>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Source Mappings (DB-based) */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              Source-to-KSI Mappings (Database)
            </CardTitle>
            <CardDescription>
              Each scanner module maps to specific FedRAMP KSIs. Click "Collect" to pull evidence from individual DB sources.
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
                        <Badge key={id} variant="outline" className="text-[10px] px-1.5 py-0" title={getKsiEnriched(id)?.requirement || getKsiLabel(id)}>
                          {id}: {getKsiEnriched(id)?.name || getKsiLabel(id)}
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
    </AppShell>
  );
}
