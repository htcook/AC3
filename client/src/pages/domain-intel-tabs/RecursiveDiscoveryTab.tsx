// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { Slider } from "@/components/ui/slider";
import {
  ArrowLeft, Shield, Target, AlertTriangle, Brain, Globe, Server,
  ChevronDown, ChevronUp, Crosshair, Zap, FileText, ExternalLink,
  Activity, Lock, Eye, Network, Loader2, BarChart3, Bug, Skull, Database, Cpu,
  TrendingUp, Fingerprint, Radar, Info, Search, Radio, Scan, Flag, Undo2, MessageSquare,
  Download, FlaskConical, Mail, ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, RefreshCw,
  Layers, Play, Pause, Settings2, GitBranch, Link2, Users, Hash, Clock, Unplug, Wifi,
  Workflow, Lightbulb, Route, Telescope, ShieldQuestion, ArrowRightLeft, KeyRound,
  Box, ClipboardCheck, PackageSearch, GitCompareArrows
} from "lucide-react";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

export default function RecursiveDiscoveryTab({ scanId, domain }: { scanId: number; domain: string }) {
  const [maxDepth, setMaxDepth] = useState(3);
  const [maxEntities, setMaxEntities] = useState(50);
  const [mode, setMode] = useState<string>("balanced");
  const [isRunning, setIsRunning] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<any>(null);

  const startDiscovery = trpc.domainIntel.startRecursiveDiscovery.useMutation({
    onSuccess: (data) => {
      setDiscoveryResult(data);
      setIsRunning(false);
      toast.success(`Spider complete — discovered ${data.stats?.totalEntities ?? 0} entities across ${data.stats?.maxDepthReached ?? 0} levels`);
    },
    onError: (err) => {
      setIsRunning(false);
      toast.error(sanitizeErrorForToast(err.message));
    },
  });

  const handleStart = () => {
    setIsRunning(true);
    startDiscovery.mutate({
      scanId,
      maxDepth,
      maxEntities,
    });
  };

  const entityTypeIcons: Record<string, any> = {
    domain: Globe,
    ip: Server,
    email: Mail,
    hostname: Network,
    asn: GitBranch,
    org: Users,
    hash: Hash,
    url: Link2,
    username: Users,
    certificate: Lock,
    nameserver: Server,
  };

  return (
    <div className="space-y-6">
      {/* Spider Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-primary" />
            Recursive Discovery Engine
          </CardTitle>
          <CardDescription>
            Automatically discover new entities from scan results and investigate them recursively — like a spider crawling the OSINT web. Discovered IPs lead to new domains, which reveal new emails, which expose new breaches.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Mode Selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Discovery Mode</label>
            <div className="grid grid-cols-3 gap-3">
              {[
                { value: "passive", label: "Passive", desc: "Free sources only, no API keys consumed", icon: Eye },
                { value: "balanced", label: "Balanced", desc: "Mix of free and paid sources", icon: Activity },
                { value: "aggressive", label: "Aggressive", desc: "All sources, maximum coverage", icon: Zap },
              ].map((m) => (
                <button
                  key={m.value}
                  onClick={() => setMode(m.value)}
                  className={`p-3 rounded-lg border text-left transition-all ${
                    mode === m.value
                      ? "border-primary bg-primary/10 ring-1 ring-primary/30"
                      : "border-border hover:border-muted-foreground/30"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <m.icon className={`w-4 h-4 ${mode === m.value ? "text-primary" : "text-muted-foreground"}`} />
                    <span className="font-medium text-sm">{m.label}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{m.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Depth Control */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Max Recursion Depth</label>
              <span className="text-sm text-muted-foreground">{maxDepth} levels</span>
            </div>
            <Slider
              value={[maxDepth]}
              onValueChange={(v) => setMaxDepth(v[0])}
              min={1}
              max={5}
              step={1}
            />
            <p className="text-xs text-muted-foreground">
              Higher depth discovers more entities but takes longer. Level 1 = direct associations only. Level 5 = deep recursive crawl.
            </p>
          </div>

          {/* Max Entities */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Max Entities to Investigate</label>
              <span className="text-sm text-muted-foreground">{maxEntities}</span>
            </div>
            <Slider
              value={[maxEntities]}
              onValueChange={(v) => setMaxEntities(v[0])}
              min={10}
              max={200}
              step={10}
            />
            <p className="text-xs text-muted-foreground">
              Safety limit to prevent runaway discovery. The spider stops after investigating this many unique entities.
            </p>
          </div>

          {/* Launch Button */}
          <Button
            onClick={handleStart}
            disabled={isRunning}
            className="w-full"
            size="lg"
          >
            {isRunning ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Spidering from {domain}... This may take a few minutes.
              </>
            ) : (
              <>
                <Play className="w-4 h-4 mr-2" />
                Start Recursive Discovery from {domain}
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {discoveryResult && (
        <>
          {/* Summary Stats */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Radar className="w-5 h-5 text-green-400" />
                Discovery Results
              </CardTitle>
              <CardDescription>
                Spidered {discoveryResult.stats?.maxDepthReached ?? 0} levels deep, investigating {discoveryResult.stats?.totalEntities ?? 0} unique entities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="text-center p-3 rounded-lg bg-primary/10 border border-primary/20">
                  <div className="text-2xl font-bold text-primary">{discoveryResult.stats?.totalEntities ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Entities Found</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                  <div className="text-2xl font-bold text-green-400">{discoveryResult.stats?.totalObservations ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Observations</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                  <div className="text-2xl font-bold text-blue-400">{discoveryResult.stats?.maxDepthReached ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Depth Reached</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                  <div className="text-2xl font-bold text-amber-400">{discoveryResult.stats?.investigatedEntities ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Investigated</div>
                </div>
              </div>

              {/* Entity Type Breakdown */}
              <h4 className="text-sm font-medium mb-3">Entities by Type</h4>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                {Object.entries(discoveryResult.stats?.byEntityType || {}).map(([type, count]) => {
                  const Icon = entityTypeIcons[type] || Database;
                  return (
                    <div key={type} className="flex items-center gap-2 p-2 rounded-lg bg-muted/50 border border-border">
                      <Icon className="w-4 h-4 text-muted-foreground shrink-0" />
                      <span className="text-sm capitalize">{type.replace(/_/g, " ")}</span>
                      <span className="ml-auto text-sm font-mono font-medium">{count as number}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Discovery Tree — Depth Levels */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-blue-400" />
                Discovery Tree
              </CardTitle>
              <CardDescription>
                How entities were discovered at each recursion level
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {Object.entries(discoveryResult.stats?.byDepth || {}).map(([depthStr, count], idx) => (
                <div key={depthStr} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                      idx === 0 ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                    }`}>
                      {depthStr}
                    </div>
                    <div className="text-left">
                      <div className="text-sm font-medium">
                        Level {depthStr} — {count as number} entities
                      </div>
                    </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* High-Value Discoveries */}
          {discoveryResult.highValueFindings && discoveryResult.highValueFindings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                  High-Value Discoveries
                </CardTitle>
                <CardDescription>
                  Notable findings surfaced during recursive discovery
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {discoveryResult.highValueFindings.map((finding: any, idx: number) => (
                    <div key={idx} className="flex items-start gap-3 p-3 rounded-lg border border-amber-500/20 bg-amber-500/5">
                      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <div>
                        <div className="text-sm font-medium">{finding.title}</div>
                        <div className="text-xs text-muted-foreground mt-0.5">{finding.description}</div>
                        <div className="flex gap-2 mt-1">
                          <Badge variant="outline" className="text-[10px]">{finding.entityType}: {finding.entityValue}</Badge>
                          <Badge variant="outline" className="text-[10px]">Depth {finding.depth}</Badge>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Empty State */}
      {!discoveryResult && !isRunning && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <GitBranch className="w-12 h-12 text-muted-foreground/40 mb-4" />
            <h3 className="text-lg font-medium mb-2">No Discovery Run Yet</h3>
            <p className="text-sm text-muted-foreground max-w-md">
              Configure the spider settings above and launch a recursive discovery. The engine will extract entities from your existing scan results and automatically investigate each one, building a complete intelligence graph.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════
// Change Detection Tab — Subdomain diff across successive scans
// ═══════════════════════════════════════════════════════════════════════════

