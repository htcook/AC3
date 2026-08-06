import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Wifi, Search, Loader2, CheckCircle2, XCircle, Copy, Download,
  ChevronDown, ChevronUp, Clock, Shield, Cpu, Globe, Lock
} from "lucide-react";

export default function HttpxPage() {
  const [targetsText, setTargetsText] = useState("");
  const [ports, setPorts] = useState("80,443,8080,8443");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [tlsProbe, setTlsProbe] = useState(true);
  const [techDetect, setTechDetect] = useState(true);
  const [jarm, setJarm] = useState(false);
  const [sortField, setSortField] = useState<"host" | "statusCode" | "responseTime">("host");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filter, setFilter] = useState("");

  const statusQuery = trpc.projectDiscovery.getStatus.useQuery();
  const scanMutation = trpc.projectDiscovery.httpx.run.useMutation({
    onSuccess: (data) => {
      toast.success(`Probed ${data.stats.total} targets (${data.stats.alive} alive)`);
    },
    onError: (err) => {
      toast.error(`Scan failed: ${err.message}`);
    },
  });

  const result = scanMutation.data;

  const filteredTargets = useMemo(() => {
    if (!result?.targets) return [];
    let items = [...result.targets];
    if (filter) {
      const f = filter.toLowerCase();
      items = items.filter(
        (t) =>
          (t.host || '').toLowerCase().includes(f) ||
          (t.url || '').toLowerCase().includes(f) ||
          (t.title || '').toLowerCase().includes(f) ||
          (t.webServer || '').toLowerCase().includes(f) ||
          t.technologies.some((tech) => tech.toLowerCase().includes(f))
      );
    }
    items.sort((a, b) => {
      let cmp = 0;
      if (sortField === "host") cmp = a.host.localeCompare(b.host);
      else if (sortField === "statusCode") cmp = a.statusCode - b.statusCode;
      else if (sortField === "responseTime") cmp = a.responseTime - b.responseTime;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return items;
  }, [result?.targets, filter, sortField, sortDir]);

  const handleScan = () => {
    const targets = targetsText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (targets.length === 0) {
      toast.error("Please enter at least one target");
      return;
    }
    scanMutation.mutate({
      targets,
      ports,
      followRedirects,
      tlsProbe,
      tech: techDetect,
      jarm,
    });
  };

  const handleExportCSV = () => {
    if (!result?.targets) return;
    const header = "url,host,port,status,title,server,technologies,tls_version,response_time\n";
    const rows = result.targets
      .map((t) =>
        `"${t.url}","${t.host}",${t.port},${t.statusCode},"${t.title}","${t.webServer}","${t.technologies.join(";")}","${t.tlsVersion || ""}",${t.responseTime}`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `httpx-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Exported CSV");
  };

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  };

  const SortIcon = ({ field }: { field: typeof sortField }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-30" />;
    return sortDir === "asc" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />;
  };

  const statusColor = (code: number) => {
    if (code >= 200 && code < 300) return "text-green-400";
    if (code >= 300 && code < 400) return "text-yellow-400";
    if (code >= 400 && code < 500) return "text-orange-400";
    return "text-red-400";
  };

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Wifi className="h-6 w-6 text-emerald-400" />
              httpx
            </h1>
            <p className="text-muted-foreground mt-1">
              Fast and multi-purpose HTTP toolkit — probes hosts for web servers, technologies, TLS certificates, and response metadata
            </p>
          </div>
          <Badge variant="outline" className={
            statusQuery.data?.mode === "cloud"
              ? "border-green-500/50 text-green-400"
              : "border-yellow-500/50 text-yellow-400"
          }>
            {statusQuery.data?.mode === "cloud" ? "PDCP Cloud" : "Local Mode"}
          </Badge>
        </div>

        {/* Scan Form */}
        <Card className="border-emerald-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-sm font-medium">New HTTP Probe</CardTitle>
            <CardDescription>Enter targets (one per line or comma-separated)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs text-muted-foreground mb-1 block">Targets</Label>
                  <Textarea
                    placeholder="example.com&#10;api.example.com&#10;10.0.0.1"
                    value={targetsText}
                    onChange={(e) => setTargetsText(e.target.value)}
                    className="bg-background/50 font-mono text-xs min-h-[100px]"
                  />
                </div>
                <div className="space-y-3">
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1 block">Ports</Label>
                    <Input
                      value={ports}
                      onChange={(e) => setPorts(e.target.value)}
                      placeholder="80,443,8080,8443"
                      className="bg-background/50 font-mono text-xs"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="flex items-center gap-2">
                      <Switch id="redirects" checked={followRedirects} onCheckedChange={setFollowRedirects} />
                      <Label htmlFor="redirects" className="text-xs">Follow Redirects</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch id="tls" checked={tlsProbe} onCheckedChange={setTlsProbe} />
                      <Label htmlFor="tls" className="text-xs">TLS Probe</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch id="tech" checked={techDetect} onCheckedChange={setTechDetect} />
                      <Label htmlFor="tech" className="text-xs">Tech Detection</Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch id="jarm" checked={jarm} onCheckedChange={setJarm} />
                      <Label htmlFor="jarm" className="text-xs">JARM Hash</Label>
                    </div>
                  </div>
                </div>
              </div>
              <Button
                onClick={handleScan}
                disabled={scanMutation.isPending || !targetsText.trim()}
                className="bg-emerald-600 hover:bg-emerald-700 text-white"
              >
                {scanMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Probing...</>
                ) : (
                  <><Search className="h-4 w-4 mr-2" /> Run httpx</>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {result && (
          <>
            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <Card className="border-emerald-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{result.stats.total}</div>
                  <div className="text-xs text-muted-foreground">Total Probed</div>
                </CardContent>
              </Card>
              <Card className="border-green-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-green-400">{result.stats.alive}</div>
                  <div className="text-xs text-muted-foreground">Alive</div>
                </CardContent>
              </Card>
              <Card className="border-purple-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-purple-400">{Object.keys(result.stats.byTech).length}</div>
                  <div className="text-xs text-muted-foreground">Technologies</div>
                </CardContent>
              </Card>
              <Card className="border-yellow-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{(result.stats.duration / 1000).toFixed(1)}s</div>
                  <div className="text-xs text-muted-foreground">Duration</div>
                </CardContent>
              </Card>
            </div>

            {/* Tech + Status Breakdown */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-emerald-500/10 bg-card/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-purple-400" /> Technologies Detected
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(result.stats.byTech)
                      .sort(([, a], [, b]) => (b as number) - (a as number))
                      .map(([tech, count]) => (
                        <Badge key={tech} variant="outline" className="border-purple-500/30 text-purple-300 text-xs">
                          {tech}: {count as number}
                        </Badge>
                      ))}
                    {Object.keys(result.stats.byTech).length === 0 && (
                      <span className="text-xs text-muted-foreground">No technologies detected</span>
                    )}
                  </div>
                </CardContent>
              </Card>
              <Card className="border-emerald-500/10 bg-card/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Globe className="h-4 w-4 text-emerald-400" /> Status Codes
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(result.stats.byStatusCode)
                      .sort(([a], [b]) => Number(a) - Number(b))
                      .map(([code, count]) => (
                        <Badge key={code} variant="outline" className={`text-xs ${
                          Number(code) < 300 ? "border-green-500/30 text-green-300" :
                          Number(code) < 400 ? "border-yellow-500/30 text-yellow-300" :
                          Number(code) < 500 ? "border-orange-500/30 text-orange-300" :
                          "border-red-500/30 text-red-300"
                        }`}>
                          {code}: {count as number}
                        </Badge>
                      ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Results Table */}
            <Card className="border-emerald-500/10 bg-card/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">
                    Probe Results ({filteredTargets.length})
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="Filter..."
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      className="w-48 h-8 text-xs bg-background/50"
                    />
                    <Button variant="outline" size="sm" onClick={handleExportCSV} className="h-8">
                      <Download className="h-3 w-3 mr-1" /> CSV
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="border rounded-lg overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/30 border-b">
                        <th className="text-left p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("host")}>
                          <span className="flex items-center gap-1">Host <SortIcon field="host" /></span>
                        </th>
                        <th className="text-center p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("statusCode")}>
                          <span className="flex items-center justify-center gap-1">Status <SortIcon field="statusCode" /></span>
                        </th>
                        <th className="text-left p-3 font-medium">Title</th>
                        <th className="text-left p-3 font-medium">Server</th>
                        <th className="text-left p-3 font-medium">Technologies</th>
                        <th className="text-left p-3 font-medium">TLS</th>
                        <th className="text-center p-3 font-medium cursor-pointer hover:bg-muted/50 select-none" onClick={() => toggleSort("responseTime")}>
                          <span className="flex items-center justify-center gap-1">Time <SortIcon field="responseTime" /></span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredTargets.map((entry, i) => (
                        <tr key={`${entry.url}-${i}`} className="border-b last:border-0 hover:bg-muted/20">
                          <td className="p-3">
                            <div className="font-mono text-xs text-emerald-300">{entry.url}</div>
                            {entry.ip && <div className="text-xs text-muted-foreground mt-0.5">{entry.ip}{entry.cdn ? ` (${entry.cdn})` : ""}</div>}
                          </td>
                          <td className="p-3 text-center">
                            <span className={`font-mono font-bold ${statusColor(entry.statusCode)}`}>
                              {entry.statusCode}
                            </span>
                          </td>
                          <td className="p-3 text-xs text-muted-foreground max-w-[200px] truncate">{entry.title || "—"}</td>
                          <td className="p-3 text-xs font-mono text-muted-foreground">{entry.webServer || "—"}</td>
                          <td className="p-3">
                            <div className="flex flex-wrap gap-1">
                              {entry.technologies.slice(0, 3).map((tech) => (
                                <Badge key={tech} variant="outline" className="text-[10px] px-1.5 py-0 border-purple-500/30 text-purple-300">
                                  {tech}
                                </Badge>
                              ))}
                              {entry.technologies.length > 3 && (
                                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-muted-foreground/30">
                                  +{entry.technologies.length - 3}
                                </Badge>
                              )}
                            </div>
                          </td>
                          <td className="p-3 text-xs">
                            {entry.tlsVersion ? (
                              <div className="flex items-center gap-1">
                                <Lock className="h-3 w-3 text-green-400" />
                                <span className="text-muted-foreground">{entry.tlsVersion}</span>
                              </div>
                            ) : (
                              <span className="text-muted-foreground/40">—</span>
                            )}
                          </td>
                          <td className="p-3 text-center text-xs font-mono text-muted-foreground">
                            {entry.responseTime}ms
                          </td>
                        </tr>
                      ))}
                      {filteredTargets.length === 0 && (
                        <tr>
                          <td colSpan={7} className="p-8 text-center text-muted-foreground">
                            {filter ? "No results match filter" : "No results"}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </>
        )}

        {/* Empty State */}
        {!result && !scanMutation.isPending && (
          <Card className="border-dashed border-muted-foreground/20 bg-card/30">
            <CardContent className="py-16 text-center">
              <Wifi className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-muted-foreground mb-2">No Probe Results</h3>
              <p className="text-sm text-muted-foreground/60 max-w-md mx-auto">
                Enter targets above and click Run httpx to probe web servers, detect technologies,
                and gather TLS certificate information. Results feed into the SSIL observation pipeline.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
