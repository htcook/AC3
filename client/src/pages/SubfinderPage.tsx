import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  Globe, Search, Loader2, CheckCircle2, XCircle, Copy, Download,
  ChevronDown, ChevronUp, Clock, Server, Activity, ExternalLink
} from "lucide-react";

export default function SubfinderPage() {
  const [domain, setDomain] = useState("");
  const [recursive, setRecursive] = useState(false);
  const [sortField, setSortField] = useState<"subdomain" | "source" | "alive">("subdomain");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filter, setFilter] = useState("");

  const statusQuery = trpc.projectDiscovery.getStatus.useQuery();
  const scanMutation = trpc.projectDiscovery.subfinder.run.useMutation({
    onSuccess: (data) => {
      toast.success(`Found ${data.stats.total} subdomains (${data.stats.alive} alive)`);
    },
    onError: (err) => {
      toast.error(`Scan failed: ${err.message}`);
    },
  });

  const result = scanMutation.data;

  const filteredSubdomains = useMemo(() => {
    if (!result?.subdomains) return [];
    let items = [...result.subdomains];
    if (filter) {
      const f = filter.toLowerCase();
      items = items.filter(
        (s) =>
          s.subdomain.toLowerCase().includes(f) ||
          s.source.toLowerCase().includes(f) ||
          (s.ip && s.ip.includes(f))
      );
    }
    items.sort((a, b) => {
      let cmp = 0;
      if (sortField === "subdomain") cmp = a.subdomain.localeCompare(b.subdomain);
      else if (sortField === "source") cmp = a.source.localeCompare(b.source);
      else if (sortField === "alive") cmp = (a.alive ? 1 : 0) - (b.alive ? 1 : 0);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return items;
  }, [result?.subdomains, filter, sortField, sortDir]);

  const handleScan = () => {
    if (!domain.trim()) {
      toast.error("Please enter a domain");
      return;
    }
    scanMutation.mutate({ domain: domain.trim(), recursive });
  };

  const handleCopyAll = () => {
    if (!result?.subdomains) return;
    const text = result.subdomains.map((s) => s.subdomain).join("\n");
    navigator.clipboard.writeText(text);
    toast.success("Copied all subdomains to clipboard");
  };

  const handleExportCSV = () => {
    if (!result?.subdomains) return;
    const header = "subdomain,source,ip,alive,cname\n";
    const rows = result.subdomains
      .map((s) => `${s.subdomain},${s.source},${s.ip || ""},${s.alive},${s.cname || ""}`)
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `subfinder-${domain}-${Date.now()}.csv`;
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

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Globe className="h-6 w-6 text-cyan-400" />
              Subfinder
            </h1>
            <p className="text-muted-foreground mt-1">
              Fast passive subdomain enumeration tool — discovers subdomains via certificate transparency, DNS datasets, and search engines
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
        <Card className="border-cyan-500/20 bg-card/50">
          <CardHeader>
            <CardTitle className="text-sm font-medium">New Subdomain Enumeration</CardTitle>
            <CardDescription>Enter a root domain to discover subdomains</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1">
                <Label htmlFor="domain" className="text-xs text-muted-foreground mb-1 block">Target Domain</Label>
                <Input
                  id="domain"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleScan()}
                  className="bg-background/50"
                />
              </div>
              <div className="flex items-end gap-4">
                <div className="flex items-center gap-2">
                  <Switch id="recursive" checked={recursive} onCheckedChange={setRecursive} />
                  <Label htmlFor="recursive" className="text-xs">Recursive</Label>
                </div>
                <Button
                  onClick={handleScan}
                  disabled={scanMutation.isPending || !domain.trim()}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white"
                >
                  {scanMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Scanning...</>
                  ) : (
                    <><Search className="h-4 w-4 mr-2" /> Enumerate</>
                  )}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {result && (
          <>
            {/* Stats Row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <Card className="border-cyan-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-cyan-400">{result.stats.total}</div>
                  <div className="text-xs text-muted-foreground">Total Found</div>
                </CardContent>
              </Card>
              <Card className="border-green-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-green-400">{result.stats.alive}</div>
                  <div className="text-xs text-muted-foreground">Alive</div>
                </CardContent>
              </Card>
              <Card className="border-red-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-red-400">{result.stats.total - result.stats.alive}</div>
                  <div className="text-xs text-muted-foreground">Dead</div>
                </CardContent>
              </Card>
              <Card className="border-purple-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-purple-400">{Object.keys(result.stats.sources).length}</div>
                  <div className="text-xs text-muted-foreground">Sources</div>
                </CardContent>
              </Card>
              <Card className="border-yellow-500/10 bg-card/50">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{(result.stats.duration / 1000).toFixed(1)}s</div>
                  <div className="text-xs text-muted-foreground">Duration</div>
                </CardContent>
              </Card>
            </div>

            {/* Source Breakdown */}
            <Card className="border-cyan-500/10 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Sources</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(result.stats.sources)
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .map(([source, count]) => (
                      <Badge key={source} variant="outline" className="border-cyan-500/30 text-cyan-300">
                        {source}: {count as number}
                      </Badge>
                    ))}
                </div>
              </CardContent>
            </Card>

            {/* Results Table */}
            <Card className="border-cyan-500/10 bg-card/50">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">
                    Subdomains ({filteredSubdomains.length})
                  </CardTitle>
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="Filter..."
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                      className="w-48 h-8 text-xs bg-background/50"
                    />
                    <Button variant="outline" size="sm" onClick={handleCopyAll} className="h-8">
                      <Copy className="h-3 w-3 mr-1" /> Copy All
                    </Button>
                    <Button variant="outline" size="sm" onClick={handleExportCSV} className="h-8">
                      <Download className="h-3 w-3 mr-1" /> CSV
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="border rounded-lg overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="bg-muted/30 border-b">
                        <th
                          className="text-left p-3 font-medium cursor-pointer hover:bg-muted/50 select-none"
                          onClick={() => toggleSort("subdomain")}
                        >
                          <span className="flex items-center gap-1">Subdomain <SortIcon field="subdomain" /></span>
                        </th>
                        <th
                          className="text-left p-3 font-medium cursor-pointer hover:bg-muted/50 select-none"
                          onClick={() => toggleSort("source")}
                        >
                          <span className="flex items-center gap-1">Source <SortIcon field="source" /></span>
                        </th>
                        <th className="text-left p-3 font-medium">IP</th>
                        <th className="text-left p-3 font-medium">CNAME</th>
                        <th
                          className="text-center p-3 font-medium cursor-pointer hover:bg-muted/50 select-none"
                          onClick={() => toggleSort("alive")}
                        >
                          <span className="flex items-center justify-center gap-1">Status <SortIcon field="alive" /></span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSubdomains.map((entry, i) => (
                        <tr key={entry.subdomain} className="border-b last:border-0 hover:bg-muted/20">
                          <td className="p-3 font-mono text-xs text-cyan-300">{entry.subdomain}</td>
                          <td className="p-3">
                            <Badge variant="outline" className="text-xs border-muted-foreground/30">
                              {entry.source}
                            </Badge>
                          </td>
                          <td className="p-3 font-mono text-xs text-muted-foreground">{entry.ip || "—"}</td>
                          <td className="p-3 font-mono text-xs text-muted-foreground">{entry.cname || "—"}</td>
                          <td className="p-3 text-center">
                            {entry.alive ? (
                              <CheckCircle2 className="h-4 w-4 text-green-400 inline" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-400/50 inline" />
                            )}
                          </td>
                        </tr>
                      ))}
                      {filteredSubdomains.length === 0 && (
                        <tr>
                          <td colSpan={5} className="p-8 text-center text-muted-foreground">
                            {filter ? "No subdomains match filter" : "No subdomains found"}
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
              <Globe className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-muted-foreground mb-2">No Scan Results</h3>
              <p className="text-sm text-muted-foreground/60 max-w-md mx-auto">
                Enter a domain above and click Enumerate to discover subdomains using passive reconnaissance sources.
                Results are automatically ingested into the SSIL observation pipeline.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
