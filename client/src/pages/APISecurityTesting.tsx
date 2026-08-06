import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Globe, Plus, Search, RefreshCw, Shield, AlertTriangle,
  CheckCircle2, XCircle, Zap, Code, Lock
} from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const RESULT_COLORS: Record<string, string> = {
  vulnerable: "bg-red-500/20 text-red-400",
  secure: "bg-green-500/20 text-green-400",
  error: "bg-red-500/20 text-red-400",
  inconclusive: "bg-yellow-500/20 text-yellow-400",
  skipped: "bg-slate-500/20 text-slate-400",
};

export default function APISecurityTesting() {
  const [activeTab, setActiveTab] = useState("catalog");
  const [searchQuery, setSearchQuery] = useState("");
  const [showAddTarget, setShowAddTarget] = useState(false);
  const [newTarget, setNewTarget] = useState({
    name: "",
    baseUrl: "",
    authType: "bearer" as "bearer" | "api_key" | "oauth2" | "basic" | "none",
  });

  const catalog = trpc.apiSecurity.getTestCatalog.useQuery({});
  const targets = trpc.apiSecurity.listTargets.useQuery({});
  const testResults = trpc.apiSecurity.listTestResults.useQuery({});
  const stats = trpc.apiSecurity.getStats.useQuery();
  const fuzzingStrategies = trpc.apiSecurity.getFuzzingStrategies.useQuery();

  const addTargetMut = trpc.apiSecurity.addTarget.useMutation({
    onSuccess: () => {
      toast.success("API target added.");
      setShowAddTarget(false);
      targets.refetch();
      stats.refetch();
    },
    onError: (err: { message: string }) => toast.error(err.message),
  });

  const filteredCatalog = useMemo(() => {
    if (!catalog.data) return [] as NonNullable<typeof catalog.data>["tests"];
    let items = [...catalog.data.tests];
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter((t) =>
        (t.testName || '').toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
      );
    }
    return items;
  }, [catalog.data, searchQuery]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Code className="h-7 w-7 text-orange-400" />
              API Security Testing
            </h1>
            <p className="text-muted-foreground mt-1">
              OWASP API Top 10 testing, endpoint fuzzing, and authentication bypass detection
            </p>
          </div>
          <div className="flex gap-2">
            <Dialog open={showAddTarget} onOpenChange={setShowAddTarget}>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Plus className="h-4 w-4 mr-1" /> Add API Target
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Add API Target</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <Label>Target Name</Label>
                    <Input value={newTarget.name} onChange={(e) => setNewTarget(p => ({ ...p, name: e.target.value }))} placeholder="Production API" />
                  </div>
                  <div>
                    <Label>Base URL</Label>
                    <Input value={newTarget.baseUrl} onChange={(e) => setNewTarget(p => ({ ...p, baseUrl: e.target.value }))} placeholder="https://api.example.com/v1" />
                  </div>
                  <div>
                    <Label>Auth Type</Label>
                    <Select value={newTarget.authType} onValueChange={(v) => setNewTarget(p => ({ ...p, authType: v as typeof newTarget.authType }))}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="bearer">Bearer Token</SelectItem>
                        <SelectItem value="api_key">API Key</SelectItem>
                        <SelectItem value="oauth2">OAuth 2.0</SelectItem>
                        <SelectItem value="basic">Basic Auth</SelectItem>
                        <SelectItem value="none">None</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button className="w-full" onClick={() => addTargetMut.mutate(newTarget)} disabled={addTargetMut.isPending || !newTarget.name || !newTarget.baseUrl}>
                    {addTargetMut.isPending ? "Adding..." : "Add Target"}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">API Targets</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalTargets ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Endpoints</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalEndpoints ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Test Results</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalTestResults ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Fuzzing Runs</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.totalFuzzingRuns ?? 0}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3">
              <p className="text-xs text-muted-foreground uppercase tracking-wider">Catalog Size</p>
              <p className="text-2xl font-bold text-foreground">{stats.data?.catalogSize ?? 0}</p>
            </CardContent>
          </Card>
        </div>

        {/* Search */}
        <div className="flex gap-3 items-center">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input placeholder="Search tests..." className="pl-9" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} />
          </div>
          <Button variant="outline" size="sm" onClick={() => { catalog.refetch(); targets.refetch(); testResults.refetch(); stats.refetch(); }}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="catalog">OWASP Catalog ({catalog.data?.total ?? 0})</TabsTrigger>
            <TabsTrigger value="results">Test Results ({testResults.data?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="targets">Targets ({targets.data?.length ?? 0})</TabsTrigger>
            <TabsTrigger value="fuzzing">Fuzzing Strategies</TabsTrigger>
          </TabsList>

          <TabsContent value="catalog" className="space-y-3">
            {filteredCatalog.map((test: (typeof filteredCatalog)[number]) => (
              <Card key={test.id} className="bg-card/50 border-border/50 hover:border-orange-500/30 transition-colors">
                <CardContent className="py-4">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="font-mono text-xs">{test.owaspCategory}</Badge>
                        <h3 className="font-semibold text-foreground">{test.testName}</h3>
                        <Badge variant="outline" className={SEVERITY_COLORS[test.severity]}>{test.severity}</Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{test.description}</p>
                      <div className="flex gap-1 flex-wrap mt-1">
                        <Badge variant="secondary" className="text-xs">{test.testType}</Badge>
                        <Badge variant="secondary" className="text-xs font-mono">{test.owaspId}</Badge>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </TabsContent>

          <TabsContent value="results" className="space-y-3">
            {testResults.data?.map((test) => (
              <Card key={test.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {test.result === "vulnerable" ? (
                          <XCircle className="h-4 w-4 text-red-400" />
                        ) : test.result === "secure" ? (
                          <CheckCircle2 className="h-4 w-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="h-4 w-4 text-yellow-400" />
                        )}
                        <h3 className="font-semibold text-foreground">Test #{test.testId}</h3>
                        <Badge variant="outline" className={RESULT_COLORS[test.result]}>{test.result}</Badge>
                        {test.severity && <Badge variant="outline" className={SEVERITY_COLORS[test.severity]}>{test.severity}</Badge>}
                      </div>
                      {test.notes && <p className="text-sm text-muted-foreground">{test.notes}</p>}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!testResults.data || testResults.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No test results yet</p>
                <p className="text-sm mt-1">Record test results to see them here</p>
              </div>
            )}
          </TabsContent>

          <TabsContent value="targets" className="space-y-3">
            {targets.data?.map((target) => (
              <Card key={target.id} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Globe className="h-8 w-8 text-orange-400/60" />
                      <div>
                        <h3 className="font-semibold text-foreground">{target.name}</h3>
                        <p className="text-sm text-muted-foreground font-mono">{target.baseUrl}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <Badge variant="secondary" className="text-xs">
                            <Lock className="h-3 w-3 mr-1" />{target.authType}
                          </Badge>
                        </div>
                      </div>
                    </div>
                    <Badge variant="outline" className={target.status === "active" ? "text-green-400 border-green-500/30" : "text-yellow-400 border-yellow-500/30"}>
                      {target.status}
                    </Badge>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!targets.data || targets.data.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Globe className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p>No API targets configured</p>
                <Button variant="outline" size="sm" className="mt-3" onClick={() => setShowAddTarget(true)}>
                  <Plus className="h-4 w-4 mr-1" /> Add First Target
                </Button>
              </div>
            )}
          </TabsContent>

          <TabsContent value="fuzzing" className="space-y-3">
            {fuzzingStrategies.data ? Object.entries(fuzzingStrategies.data).map(([key, strategy]) => (
              <Card key={key} className="bg-card/50 border-border/50">
                <CardContent className="py-4">
                  <div className="space-y-2">
                    <h3 className="font-semibold text-foreground">{(strategy as { name: string; description: string }).name}</h3>
                    <p className="text-sm text-muted-foreground">{(strategy as { name: string; description: string }).description}</p>
                    <Badge variant="secondary" className="text-xs capitalize">{key.replace(/_/g, " ")}</Badge>
                  </div>
                </CardContent>
              </Card>
            )) : null}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
