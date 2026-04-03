import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import {
  Webhook, Plus, Copy, RotateCw, Trash2, Play, Code2,
  Shield, Activity, Clock, CheckCircle2, XCircle, Loader2,
  ChevronDown, ChevronRight, Eye, EyeOff, Zap, Globe, Terminal
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import AppShell from "@/components/AppShell";

// ─── Scan type config ────────────────────────────────────────────────────────

const SCAN_TYPE_CONFIG: Record<string, { label: string; icon: typeof Zap; color: string }> = {
  zap_dast: { label: "ZAP DAST", icon: Zap, color: "text-orange-400" },
  nmap: { label: "Port Discovery", icon: Terminal, color: "text-cyan-400" },
  nuclei: { label: "Nuclei", icon: Globe, color: "text-purple-400" },
  custom: { label: "Custom", icon: Code2, color: "text-emerald-400" },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof CheckCircle2 }> = {
  queued: { label: "Queued", color: "bg-yellow-500/20 text-yellow-400", icon: Clock },
  running: { label: "Running", color: "bg-blue-500/20 text-blue-400", icon: Loader2 },
  completed: { label: "Completed", color: "bg-emerald-500/20 text-emerald-400", icon: CheckCircle2 },
  failed: { label: "Failed", color: "bg-red-500/20 text-red-400", icon: XCircle },
};

export default function ScanWebhooks() {
  const { user } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [showSnippet, setShowSnippet] = useState<string | null>(null);
  const [showTest, setShowTest] = useState<string | null>(null);
  const [snippetPlatform, setSnippetPlatform] = useState<string>("curl");
  const [testTarget, setTestTarget] = useState("https://example.com");
  const [newName, setNewName] = useState("");
  const [newScanType, setNewScanType] = useState<string>("zap_dast");
  const [newProfile, setNewProfile] = useState<string>("");
  const [showSecrets, setShowSecrets] = useState<Set<string>>(new Set());
  const [expandedExec, setExpandedExec] = useState<string | null>(null);

  const utils = trpc.useUtils();
  const { data: endpoints, isLoading } = trpc.scanWebhooks.list.useQuery();
  const { data: profiles } = trpc.scanWebhooks.getProfiles.useQuery();
  const { data: stats } = trpc.scanWebhooks.getStats.useQuery();
  const { data: executions } = trpc.scanWebhooks.getExecutions.useQuery({});
  const { data: snippet } = trpc.scanWebhooks.getIntegrationSnippet.useQuery(
    { endpointId: showSnippet || "", platform: snippetPlatform as any },
    { enabled: !!showSnippet }
  );

  const createMutation = trpc.scanWebhooks.create.useMutation({
    onSuccess: (data) => {
      toast.success(`Webhook created! Secret: ${data.secret.substring(0, 20)}...`);
      utils.scanWebhooks.list.invalidate();
      utils.scanWebhooks.getStats.invalidate();
      setShowCreate(false);
      setNewName("");
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.scanWebhooks.delete.useMutation({
    onSuccess: () => {
      toast.success("Webhook endpoint deleted");
      utils.scanWebhooks.list.invalidate();
      utils.scanWebhooks.getStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const rotateMutation = trpc.scanWebhooks.rotateSecret.useMutation({
    onSuccess: (data) => {
      toast.success(`New secret: ${data.secret.substring(0, 20)}...`);
      utils.scanWebhooks.list.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleMutation = trpc.scanWebhooks.update.useMutation({
    onSuccess: () => {
      toast.success("Webhook updated");
      utils.scanWebhooks.list.invalidate();
    },
  });

  const testMutation = trpc.scanWebhooks.testTrigger.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan queued: ${data.scanId}`);
      utils.scanWebhooks.getExecutions.invalidate();
      utils.scanWebhooks.getStats.invalidate();
      setShowTest(null);
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredProfiles = useMemo(() => {
    if (!profiles) return [];
    return profiles.filter((p: any) => p.scanType === newScanType);
  }, [profiles, newScanType]);

  const isAdmin = user?.role === "admin" || user?.role === "team_lead";

  return (
      <AppShell activePath="/scan-webhooks">
      <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Webhook className="h-6 w-6 text-cyan-400" />
            Scan Webhook Automation
          </h1>
          <p className="text-muted-foreground mt-1">
            Trigger scans from SOAR platforms via authenticated webhooks
          </p>
        </div>
        {isAdmin && (
          <Button onClick={() => setShowCreate(true)} className="gap-2">
            <Plus className="h-4 w-4" /> Create Endpoint
          </Button>
        )}
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4">
              <div className="text-sm text-muted-foreground">Active Endpoints</div>
              <div className="text-2xl font-bold mt-1">{stats.activeEndpoints}/{stats.totalEndpoints}</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4">
              <div className="text-sm text-muted-foreground">24h Executions</div>
              <div className="text-2xl font-bold mt-1">{stats.last24hExecutions}</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4">
              <div className="text-sm text-muted-foreground">Success Rate</div>
              <div className="text-2xl font-bold mt-1 text-emerald-400">{stats.successRate}%</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4">
              <div className="text-sm text-muted-foreground">Avg Duration</div>
              <div className="text-2xl font-bold mt-1">{Math.round(stats.avgScanDuration)}s</div>
            </CardContent>
          </Card>
        </div>
      )}

      <Tabs defaultValue="endpoints" className="space-y-4">
        <TabsList>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="executions">Execution History</TabsTrigger>
          <TabsTrigger value="profiles">Scan Profiles</TabsTrigger>
        </TabsList>

        {/* Endpoints Tab */}
        <TabsContent value="endpoints" className="space-y-4">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !endpoints?.length ? (
            <Card className="bg-card/50 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Webhook className="h-12 w-12 text-muted-foreground mb-4" />
                <p className="text-muted-foreground">No webhook endpoints configured</p>
                {isAdmin && (
                  <Button variant="outline" className="mt-4" onClick={() => setShowCreate(true)}>
                    Create First Endpoint
                  </Button>
                )}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {endpoints.map((ep: any) => {
                const typeConfig = SCAN_TYPE_CONFIG[ep.scanType] || SCAN_TYPE_CONFIG.custom;
                const TypeIcon = typeConfig.icon;
                return (
                  <Card key={ep.id} className="bg-card/50 border-border/50">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg bg-background/50 ${typeConfig.color}`}>
                            <TypeIcon className="h-5 w-5" />
                          </div>
                          <div>
                            <div className="font-medium flex items-center gap-2">
                              {ep.name}
                              <Badge variant={ep.enabled ? "default" : "secondary"} className="text-xs">
                                {ep.enabled ? "Active" : "Disabled"}
                              </Badge>
                            </div>
                            <div className="text-xs text-muted-foreground mt-0.5 font-mono">
                              {ep.path}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="text-right text-xs text-muted-foreground mr-4">
                            <div>{ep.triggerCount} triggers</div>
                            {ep.lastTriggered && (
                              <div>Last: {new Date(ep.lastTriggered).toLocaleDateString()}</div>
                            )}
                          </div>
                          <Switch
                            checked={ep.enabled}
                            onCheckedChange={(enabled) =>
                              toggleMutation.mutate({ id: ep.id, enabled })
                            }
                          />
                          <Button
                            variant="ghost" size="icon"
                            onClick={() => { setShowSnippet(ep.id); setSnippetPlatform("curl"); }}
                            title="Integration Code"
                          >
                            <Code2 className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost" size="icon"
                            onClick={() => { setShowTest(ep.id); setTestTarget("https://example.com"); }}
                            title="Test Trigger"
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost" size="icon"
                            onClick={() => rotateMutation.mutate({ id: ep.id })}
                            title="Rotate Secret"
                          >
                            <RotateCw className="h-4 w-4" />
                          </Button>
                          {isAdmin && (
                            <Button
                              variant="ghost" size="icon"
                              onClick={() => deleteMutation.mutate({ id: ep.id })}
                              className="text-red-400 hover:text-red-300"
                              title="Delete"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                      {/* Secret row */}
                      <div className="mt-3 flex items-center gap-2 text-xs">
                        <Shield className="h-3 w-3 text-muted-foreground" />
                        <span className="text-muted-foreground">Secret:</span>
                        <code className="bg-background/50 px-2 py-0.5 rounded font-mono">
                          {showSecrets.has(ep.id) ? ep.secret : "••••••••••••••••"}
                        </code>
                        <Button
                          variant="ghost" size="icon" className="h-5 w-5"
                          onClick={() => {
                            const next = new Set(showSecrets);
                            if (next.has(ep.id)) next.delete(ep.id); else next.add(ep.id);
                            setShowSecrets(next);
                          }}
                        >
                          {showSecrets.has(ep.id) ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                        </Button>
                        <Button
                          variant="ghost" size="icon" className="h-5 w-5"
                          onClick={() => { navigator.clipboard.writeText(ep.secret); toast.success("Secret copied"); }}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* Executions Tab */}
        <TabsContent value="executions" className="space-y-3">
          {!executions?.length ? (
            <Card className="bg-card/50 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-12">
                <Activity className="h-12 w-12 text-muted-foreground mb-4" />
                <p className="text-muted-foreground">No webhook executions yet</p>
              </CardContent>
            </Card>
          ) : (
            executions.map((exec: any) => {
              const statusCfg = STATUS_CONFIG[exec.status] || STATUS_CONFIG.queued;
              const StatusIcon = statusCfg.icon;
              const isExpanded = expandedExec === exec.id;
              return (
                <Card key={exec.id} className="bg-card/50 border-border/50">
                  <CardContent className="p-4">
                    <div
                      className="flex items-center justify-between cursor-pointer"
                      onClick={() => setExpandedExec(isExpanded ? null : exec.id)}
                    >
                      <div className="flex items-center gap-3">
                        <Badge className={statusCfg.color}>
                          <StatusIcon className={`h-3 w-3 mr-1 ${exec.status === "running" ? "animate-spin" : ""}`} />
                          {statusCfg.label}
                        </Badge>
                        <div>
                          <div className="text-sm font-mono">{exec.scanId || "—"}</div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(exec.triggeredAt).toLocaleString()} · {exec.sourceIp}
                          </div>
                        </div>
                      </div>
                      {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </div>
                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-border/50 space-y-2">
                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="text-muted-foreground">Target:</span>{" "}
                            <span className="font-mono">{exec.payload?.target || "—"}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Endpoint:</span>{" "}
                            <span className="font-mono">{exec.endpointId.substring(0, 12)}...</span>
                          </div>
                        </div>
                        {exec.result && (
                          <div className="grid grid-cols-5 gap-2 mt-2">
                            {[
                              { label: "Critical", value: exec.result.criticalCount, color: "text-red-400" },
                              { label: "High", value: exec.result.highCount, color: "text-orange-400" },
                              { label: "Medium", value: exec.result.mediumCount, color: "text-yellow-400" },
                              { label: "Low", value: exec.result.lowCount, color: "text-blue-400" },
                              { label: "Duration", value: `${exec.result.scanDuration}s`, color: "text-muted-foreground" },
                            ].map((item) => (
                              <div key={item.label} className="text-center p-2 bg-background/50 rounded">
                                <div className={`text-lg font-bold ${item.color}`}>{item.value}</div>
                                <div className="text-xs text-muted-foreground">{item.label}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        {/* Profiles Tab */}
        <TabsContent value="profiles" className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {profiles?.map((profile: any) => {
              const typeConfig = SCAN_TYPE_CONFIG[profile.scanType] || SCAN_TYPE_CONFIG.custom;
              const TypeIcon = typeConfig.icon;
              return (
                <Card key={profile.id} className="bg-card/50 border-border/50">
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <TypeIcon className={`h-4 w-4 ${typeConfig.color}`} />
                      <CardTitle className="text-sm">{profile.name}</CardTitle>
                    </div>
                    <CardDescription className="text-xs font-mono">{profile.id}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-1 text-xs">
                      {Object.entries(profile.config).map(([key, val]) => (
                        <div key={key} className="flex justify-between">
                          <span className="text-muted-foreground">{key}:</span>
                          <span className="font-mono">{String(val)}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Webhook Endpoint</DialogTitle>
            <DialogDescription>
              Configure a new webhook endpoint for SOAR-triggered scans
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Endpoint Name</Label>
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g., Splunk SOAR → ZAP Full Scan"
              />
            </div>
            <div>
              <Label>Scan Type</Label>
              <Select value={newScanType} onValueChange={setNewScanType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="zap_dast">ZAP DAST</SelectItem>
                  <SelectItem value="nmap">Port Discovery</SelectItem>
                  <SelectItem value="nuclei">Nuclei</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Scan Profile</Label>
              <Select value={newProfile} onValueChange={setNewProfile}>
                <SelectTrigger><SelectValue placeholder="Select a profile" /></SelectTrigger>
                <SelectContent>
                  {filteredProfiles.map((p: any) => (
                    <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button
              onClick={() => createMutation.mutate({
                name: newName,
                scanType: newScanType as any,
                profileId: newProfile || undefined,
              })}
              disabled={!newName || createMutation.isPending}
            >
              {createMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Create Endpoint
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Integration Snippet Dialog */}
      <Dialog open={!!showSnippet} onOpenChange={() => setShowSnippet(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Integration Code</DialogTitle>
            <DialogDescription>Copy this snippet into your SOAR platform</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Select value={snippetPlatform} onValueChange={setSnippetPlatform}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="curl">cURL</SelectItem>
                <SelectItem value="python">Python</SelectItem>
                <SelectItem value="splunk_soar">Splunk SOAR</SelectItem>
                <SelectItem value="cortex_xsoar">Cortex XSOAR</SelectItem>
                <SelectItem value="tines">Tines</SelectItem>
                <SelectItem value="shuffle">Shuffle</SelectItem>
              </SelectContent>
            </Select>
            <div className="relative">
              <pre className="bg-background/80 border border-border/50 rounded-lg p-4 text-xs font-mono overflow-x-auto max-h-80">
                {snippet?.snippet || "Loading..."}
              </pre>
              <Button
                variant="ghost" size="icon"
                className="absolute top-2 right-2"
                onClick={() => {
                  if (snippet?.snippet) {
                    navigator.clipboard.writeText(snippet.snippet);
                    toast.success("Copied to clipboard");
                  }
                }}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Test Trigger Dialog */}
      <Dialog open={!!showTest} onOpenChange={() => setShowTest(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Test Webhook Trigger</DialogTitle>
            <DialogDescription>Simulate a SOAR-triggered scan</DialogDescription>
          </DialogHeader>
          <div>
            <Label>Target URL</Label>
            <Input
              value={testTarget}
              onChange={(e) => setTestTarget(e.target.value)}
              placeholder="https://target.example.com"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowTest(null)}>Cancel</Button>
            <Button
              onClick={() => showTest && testMutation.mutate({ id: showTest, target: testTarget })}
              disabled={!testTarget || testMutation.isPending}
            >
              {testMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
              Trigger Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
      </AppShell>
  );
}
