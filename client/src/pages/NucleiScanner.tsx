import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import {
  Loader2, ScanLine, Play, Target, Shield, Bug, AlertTriangle,
  BarChart3, Clock, CheckCircle2, XCircle, FileText, Zap, Activity
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function NucleiScanner() {
  const [activeTab, setActiveTab] = useState("scans");
  const [showNewScan, setShowNewScan] = useState(false);
  const [targets, setTargets] = useState("");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [rateLimit, setRateLimit] = useState("150");
  const [concurrency, setConcurrency] = useState("25");
  const [headless, setHeadless] = useState(false);
  const [interactsh, setInteractsh] = useState(true);

  const statsQuery = trpc.nucleiScanner.getStats.useQuery(undefined, { refetchInterval: 10000 });
  const scansQuery = trpc.nucleiScanner.listScans.useQuery(undefined, { refetchInterval: 5000 });
  const categoriesQuery = trpc.nucleiScanner.listTemplateCategories.useQuery();

  const startScan = trpc.nucleiScanner.startScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan started: ${data.scanId}`);
      setShowNewScan(false);
      setTargets("");
      setSelectedCategories([]);
      scansQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(`Scan failed: ${e.message}`),
  });

  const completeScan = trpc.nucleiScanner.completeScan.useMutation({
    onSuccess: () => { toast.success("Scan completed"); scansQuery.refetch(); statsQuery.refetch(); },
    onError: (e) => toast.error(`Complete failed: ${e.message}`),
  });

  const stats = statsQuery.data;
  const scans = scansQuery.data?.scans || [];
  const categories = categoriesQuery.data || [];

  const toggleCategory = (cat: string) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    );
  };

  return (
    <AppShell activePath="/nuclei-scanner">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
              <ScanLine className="w-7 h-7 text-purple-400" />
              Template Scanner
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Template-based vulnerability scanning with 7,900+ community templates. Covers CVEs, misconfigurations, exposures, default logins, and subdomain takeovers.
            </p>
          </div>
          <Dialog open={showNewScan} onOpenChange={setShowNewScan}>
            <DialogTrigger asChild>
              <Button className="bg-purple-600 hover:bg-purple-700">
                <Play className="w-4 h-4 mr-2" /> New Scan
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Start Template Scan</DialogTitle>
                <DialogDescription>Configure targets and template categories for the scan.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Targets (one per line)</Label>
                  <textarea className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm min-h-[100px]" value={targets} onChange={e => setTargets(e.target.value)} placeholder="https://example.com&#10;10.0.0.1&#10;subdomain.example.com" />
                </div>
                <div>
                  <Label className="mb-2 block">Template Categories</Label>
                  <div className="flex flex-wrap gap-2">
                    {categories.map((cat: any) => (
                      <Badge
                        key={cat.category}
                        variant="outline"
                        className={`cursor-pointer transition-colors ${selectedCategories.includes(cat.category) ? "bg-purple-500/20 text-purple-400 border-purple-500/50" : "hover:border-purple-500/30"}`}
                        onClick={() => toggleCategory(cat.category)}
                      >
                        {cat.category} ({cat.templateCount})
                      </Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">Leave empty to use all templates.</p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label>Rate Limit (req/s)</Label>
                    <Input value={rateLimit} onChange={e => setRateLimit(e.target.value)} />
                  </div>
                  <div>
                    <Label>Concurrency</Label>
                    <Input value={concurrency} onChange={e => setConcurrency(e.target.value)} />
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="flex items-center gap-2">
                    <Switch checked={headless} onCheckedChange={setHeadless} />
                    <Label>Headless Mode</Label>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={interactsh} onCheckedChange={setInteractsh} />
                    <Label>Interactsh OOB</Label>
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowNewScan(false)}>Cancel</Button>
                <Button
                  className="bg-purple-600 hover:bg-purple-700"
                  disabled={!targets.trim() || startScan.isPending}
                  onClick={() => startScan.mutate({
                    targets: targets.split("\n").map(s => s.trim()).filter(Boolean),
                    templateCategories: selectedCategories.length > 0 ? selectedCategories : undefined,
                    rateLimit: parseInt(rateLimit) || 150,
                    concurrency: parseInt(concurrency) || 25,
                    headless,
                    interactsh,
                  })}
                >
                  {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
                  Start Scan
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground">Templates</p>
              <p className="text-2xl font-bold text-purple-400">{stats?.totalTemplates?.toLocaleString() || "7,900+"}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground">Total Scans</p>
              <p className="text-2xl font-bold">{stats?.totalScans || 0}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground">Active Scans</p>
              <p className="text-2xl font-bold text-cyan-400">{stats?.activeScans || 0}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground">Total Findings</p>
              <p className="text-2xl font-bold text-amber-400">{stats?.totalFindings || 0}</p>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground">Critical/High</p>
              <p className="text-2xl font-bold text-red-400">{(stats?.bySeverity?.critical || 0) + (stats?.bySeverity?.high || 0)}</p>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="scans">Scans</TabsTrigger>
            <TabsTrigger value="templates">Templates</TabsTrigger>
          </TabsList>

          {/* Scans */}
          <TabsContent value="scans" className="space-y-3">
            {scans.length === 0 ? (
              <Card className="border-dashed border-border/50">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                  <ScanLine className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground">No scans yet. Start a new scan to begin template-based vulnerability assessment.</p>
                </CardContent>
              </Card>
            ) : (
              scans.map((scan: any) => (
                <Card key={scan.id} className="border-border/50 hover:border-purple-500/30 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between mb-3">
                      <div>
                        <p className="font-medium flex items-center gap-2">
                          {scan.status === "running" ? <Activity className="w-4 h-4 text-cyan-400 animate-pulse" /> : scan.status === "completed" ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                          Scan #{scan.id}
                        </p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {scan.targets?.length || 0} target(s) · {scan.stats?.templatesLoaded?.toLocaleString() || 0} templates · {scan.stats?.matchesFound || 0} matches
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={scan.status === "running" ? "text-cyan-400 border-cyan-500/30" : scan.status === "completed" ? "text-emerald-400 border-emerald-500/30" : "text-red-400 border-red-500/30"}>
                          {scan.status}
                        </Badge>
                        {scan.status === "running" && (
                          <Button size="sm" variant="outline" onClick={() => completeScan.mutate({ scanId: scan.id })}>
                            <CheckCircle2 className="w-3 h-3 mr-1" /> Complete
                          </Button>
                        )}
                      </div>
                    </div>
                    {/* Findings severity breakdown */}
                    {scan.findings?.length > 0 && (
                      <div className="flex gap-2 flex-wrap">
                        {["critical", "high", "medium", "low", "info"].map(sev => {
                          const count = scan.findings.filter((f: any) => f.severity === sev).length;
                          return count > 0 ? (
                            <Badge key={sev} variant="outline" className={SEVERITY_COLORS[sev]}>
                              {sev}: {count}
                            </Badge>
                          ) : null;
                        })}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>

          {/* Templates */}
          <TabsContent value="templates" className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {categories.map((cat: any) => (
                <Card key={cat.category} className="border-border/50 hover:border-purple-500/20 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium capitalize">{cat.category}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{cat.description}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-lg font-bold text-purple-400">{cat.templateCount.toLocaleString()}</p>
                        <Badge variant="outline" className={SEVERITY_COLORS[cat.defaultSeverity] || "border-border"}>
                          {cat.defaultSeverity}
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
