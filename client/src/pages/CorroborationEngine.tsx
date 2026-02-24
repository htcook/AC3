"use client";

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Shield, Search, CheckCircle, XCircle, AlertTriangle, HelpCircle,
  Loader2, Microscope, Activity, BarChart3, Zap, Globe, Database,
  Eye, TrendingUp, ArrowRight, Copy, RefreshCw
} from "lucide-react";

const FINDING_TYPES = ["vulnerability", "credential", "domain", "ip", "indicator"] as const;
const SOURCE_OPTIONS = ["nvd", "shodan", "censys", "urlscan", "abuseipdb", "virustotal", "securitytrails", "dehashed"] as const;

const verdictConfig: Record<string, { color: string; bgColor: string; icon: typeof CheckCircle; label: string }> = {
  confirmed: { color: "text-red-400", bgColor: "bg-red-500/20 border-red-500/30", icon: CheckCircle, label: "Confirmed Threat" },
  false_positive: { color: "text-green-400", bgColor: "bg-green-500/20 border-green-500/30", icon: XCircle, label: "False Positive" },
  suspicious: { color: "text-yellow-400", bgColor: "bg-yellow-500/20 border-yellow-500/30", icon: AlertTriangle, label: "Suspicious" },
  unverified: { color: "text-zinc-400", bgColor: "bg-zinc-500/20 border-zinc-500/30", icon: HelpCircle, label: "Unverified" },
};

const sourceIcons: Record<string, typeof Globe> = {
  nvd: Database,
  shodan: Eye,
  censys: Search,
  urlscan: Globe,
  abuseipdb: Shield,
  virustotal: Microscope,
  securitytrails: Activity,
  dehashed: Zap,
};

export default function CorroborationEngine() {
  const [findingType, setFindingType] = useState<string>("vulnerability");
  const [findingValue, setFindingValue] = useState("");
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [results, setResults] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);

  const sourcesQuery = trpc.corroborationEngine.getSources.useQuery();

  const corroborateMut = trpc.corroborationEngine.corroborate.useMutation({
    onSuccess: (data) => {
      setResults(data);
      setHistory(prev => [{ ...data, timestamp: new Date(), query: findingValue, type: findingType }, ...prev].slice(0, 20));
      toast.success("Corroboration complete");
    },
    onError: (err) => toast.error(err.message),
  });

  const batchMut = trpc.corroborationEngine.batchCorroborate.useMutation({
    onSuccess: (data) => {
      setResults(data);
      toast.success(`Batch corroboration complete: ${data.total} findings analyzed`);
    },
    onError: (err) => toast.error(err.message),
  });

  const handleCorroborate = () => {
    if (!findingValue.trim()) { toast.error("Enter a finding value"); return; }
    corroborateMut.mutate({
      findingType: findingType as any,
      findingValue: findingValue.trim(),
      sources: selectedSources.length > 0 ? selectedSources as any : undefined,
    });
  };

  const toggleSource = (src: string) => {
    setSelectedSources(prev =>
      prev.includes(src) ? prev.filter(s => s !== src) : [...prev, src]
    );
  };

  // Compute stats from history
  const historyStats = useMemo(() => {
    if (history.length === 0) return null;
    const confirmed = history.filter(h => h.overallVerdict === "confirmed").length;
    const falsePositive = history.filter(h => h.overallVerdict === "false_positive").length;
    const suspicious = history.filter(h => h.overallVerdict === "suspicious").length;
    const avgConfidence = Math.round(history.reduce((s, h) => s + (h.confidenceScore || 0), 0) / history.length);
    return { confirmed, falsePositive, suspicious, avgConfidence, total: history.length };
  }, [history]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Microscope className="h-6 w-6 text-blue-500" />
          Cross-Source Corroboration Engine
        </h1>
        <p className="text-muted-foreground mt-1">
          Validate findings across 7+ intelligence sources (NVD, Shodan, Censys, URLScan, AbuseIPDB, VirusTotal, SecurityTrails, DeHashed) to reduce false positives by 30-40%. Each finding is independently verified and scored.
        </p>
      </div>

      {/* Source Health Grid */}
      {sourcesQuery.data && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          {sourcesQuery.data.map((src: any) => {
            const Icon = sourceIcons[src.name] || Globe;
            const isSelected = selectedSources.includes(src.name);
            return (
              <Card
                key={src.name}
                className={`cursor-pointer transition-all hover:border-primary/50 ${isSelected ? "border-primary ring-1 ring-primary/20" : ""} ${!src.available ? "opacity-50" : ""}`}
                onClick={() => src.available && toggleSource(src.name)}
              >
                <CardContent className="p-3 flex flex-col items-center text-center gap-1">
                  <div className={`h-8 w-8 rounded-lg flex items-center justify-center ${src.available ? "bg-green-500/10" : "bg-zinc-500/10"}`}>
                    <Icon className={`h-4 w-4 ${src.available ? "text-green-500" : "text-zinc-400"}`} />
                  </div>
                  <span className="text-xs font-medium uppercase">{src.name}</span>
                  <div className={`w-1.5 h-1.5 rounded-full ${src.available ? "bg-green-500" : "bg-zinc-400"}`} />
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Session Stats */}
      {historyStats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card>
            <CardContent className="pt-3 pb-2">
              <p className="text-xs text-muted-foreground uppercase">Analyzed</p>
              <p className="text-xl font-bold">{historyStats.total}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-3 pb-2">
              <p className="text-xs text-muted-foreground uppercase">Confirmed</p>
              <p className="text-xl font-bold text-red-400">{historyStats.confirmed}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-3 pb-2">
              <p className="text-xs text-muted-foreground uppercase">False Positives</p>
              <p className="text-xl font-bold text-green-400">{historyStats.falsePositive}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-3 pb-2">
              <p className="text-xs text-muted-foreground uppercase">Suspicious</p>
              <p className="text-xl font-bold text-yellow-400">{historyStats.suspicious}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-3 pb-2">
              <p className="text-xs text-muted-foreground uppercase">Avg Confidence</p>
              <p className="text-xl font-bold">{historyStats.avgConfidence}%</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Input Form */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Corroborate Finding</CardTitle>
          <CardDescription>Enter a finding to validate across selected intelligence sources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-3">
            <Select value={findingType} onValueChange={setFindingType}>
              <SelectTrigger className="w-[180px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                {FINDING_TYPES.map(t => (
                  <SelectItem key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              placeholder="e.g., CVE-2021-44228, 192.168.1.1, example.com"
              value={findingValue}
              onChange={e => setFindingValue(e.target.value)}
              className="flex-1"
              onKeyDown={e => e.key === "Enter" && handleCorroborate()}
            />
            <Button onClick={handleCorroborate} disabled={corroborateMut.isPending} className="gap-2">
              {corroborateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Corroborate
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            {selectedSources.length === 0
              ? "All available sources will be queried. Click source cards above to select specific ones."
              : `${selectedSources.length} source(s) selected: ${selectedSources.join(", ")}`}
          </p>
        </CardContent>
      </Card>

      {/* Results */}
      {results && !("total" in results && "results" in results && "confirmedCount" in results) && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                Corroboration Result
                {results.overallVerdict && (() => {
                  const cfg = verdictConfig[results.overallVerdict] || verdictConfig.unverified;
                  const Icon = cfg.icon;
                  return (
                    <Badge className={`${cfg.bgColor} border ${cfg.color}`}>
                      <Icon className="h-3 w-3 mr-1" />{cfg.label}
                    </Badge>
                  );
                })()}
              </CardTitle>
              <Button
                size="sm"
                variant="outline"
                className="gap-1"
                onClick={() => {
                  navigator.clipboard.writeText(JSON.stringify(results, null, 2));
                  toast.success("Copied to clipboard");
                }}
              >
                <Copy className="h-3 w-3" /> Export
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Score Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="text-center p-4 rounded-lg bg-muted/50 border">
                <div className="text-3xl font-bold">{results.confidenceScore ?? 0}%</div>
                <div className="text-xs text-muted-foreground mt-1">Confidence Score</div>
                <Progress value={results.confidenceScore ?? 0} className="h-1.5 mt-2" />
              </div>
              <div className="text-center p-4 rounded-lg bg-muted/50 border">
                <div className="text-3xl font-bold">{results.sourcesQueried ?? 0}</div>
                <div className="text-xs text-muted-foreground mt-1">Sources Queried</div>
              </div>
              <div className="text-center p-4 rounded-lg bg-muted/50 border">
                <div className="text-3xl font-bold text-red-400">{results.sourcesConfirming ?? 0}</div>
                <div className="text-xs text-muted-foreground mt-1">Confirming</div>
              </div>
              <div className="text-center p-4 rounded-lg bg-muted/50 border">
                <div className="text-3xl font-bold text-green-400">{results.sourcesDenying ?? 0}</div>
                <div className="text-xs text-muted-foreground mt-1">Denying</div>
              </div>
            </div>

            {/* Source Details */}
            {results.sourceResults && results.sourceResults.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-semibold">Source-by-Source Breakdown</h4>
                {results.sourceResults.map((sr: any, i: number) => {
                  const Icon = sourceIcons[sr.source] || Globe;
                  const verdictColor = sr.verdict === "confirmed" ? "text-red-400 bg-red-500/10" :
                    sr.verdict === "denied" ? "text-green-400 bg-green-500/10" :
                    "text-yellow-400 bg-yellow-500/10";
                  return (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-lg border hover:bg-accent/30 transition-colors">
                      <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center shrink-0">
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium uppercase">{sr.source}</span>
                          <Badge className={`${verdictColor} text-xs`}>{sr.verdict}</Badge>
                        </div>
                        {sr.detail && <p className="text-xs text-muted-foreground mt-0.5 truncate">{sr.detail}</p>}
                      </div>
                      {sr.confidence != null && (
                        <div className="text-right shrink-0">
                          <span className="text-sm font-mono">{sr.confidence}%</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Reasoning */}
            {results.reasoning && (
              <div className="p-4 rounded-lg bg-muted/50 border">
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-1">
                  <TrendingUp className="h-4 w-4" /> Analysis Reasoning
                </h4>
                <p className="text-sm text-muted-foreground leading-relaxed">{results.reasoning}</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Batch Results */}
      {results && "total" in results && "results" in results && "confirmedCount" in results && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle>Batch Corroboration Results</CardTitle>
            <CardDescription>
              {results.total} findings analyzed — {results.confirmedCount} confirmed, {results.falsePositiveCount} false positives
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-3 mb-4">
              <div className="text-center p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                <div className="text-2xl font-bold text-red-400">{results.confirmedCount}</div>
                <div className="text-xs text-muted-foreground">Confirmed</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                <div className="text-2xl font-bold text-green-400">{results.falsePositiveCount}</div>
                <div className="text-xs text-muted-foreground">False Positives</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                <div className="text-2xl font-bold text-yellow-400">{results.total - results.confirmedCount - results.falsePositiveCount}</div>
                <div className="text-xs text-muted-foreground">Suspicious</div>
              </div>
            </div>
            <div className="space-y-2">
              {results.results?.map((r: any, i: number) => {
                const cfg = verdictConfig[r.overallVerdict] || verdictConfig.unverified;
                const Icon = cfg.icon;
                return (
                  <div key={i} className="flex items-center justify-between p-2 rounded border">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-xs">{r.findingValue}</Badge>
                      <span className="text-xs text-muted-foreground">{r.sourcesQueried} sources</span>
                    </div>
                    <Badge className={`${cfg.bgColor} border ${cfg.color} text-xs`}>
                      <Icon className="h-3 w-3 mr-1" />{cfg.label}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* History */}
      {history.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Session History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {history.map((h, i) => {
                const cfg = verdictConfig[h.overallVerdict] || verdictConfig.unverified;
                const Icon = cfg.icon;
                return (
                  <div
                    key={i}
                    className="flex items-center justify-between p-2 rounded hover:bg-accent/30 cursor-pointer transition-colors"
                    onClick={() => setResults(h)}
                  >
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-xs">{h.type}</Badge>
                      <span className="text-sm font-mono">{h.query}</span>
                      <span className="text-xs text-muted-foreground">
                        {h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : ""}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono">{h.confidenceScore}%</span>
                      <Badge className={`${cfg.bgColor} border ${cfg.color} text-xs`}>
                        <Icon className="h-3 w-3 mr-1" />{cfg.label}
                      </Badge>
                    </div>
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
