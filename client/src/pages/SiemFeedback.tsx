import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Activity, Plus, Trash2, TestTube, CheckCircle, XCircle, AlertTriangle, Loader2 } from "lucide-react";

export default function SiemFeedback() {

  const [showAddForm, setShowAddForm] = useState(false);
  const [newProvider, setNewProvider] = useState<string>("");
  const [newName, setNewName] = useState("");
  const [newEndpoint, setNewEndpoint] = useState("");
  const [newApiKey, setNewApiKey] = useState("");
  const [queryText, setQueryText] = useState("");
  const [selectedIntegration, setSelectedIntegration] = useState<number | null>(null);

  const integrations = trpc.siemFeedback.listIntegrations.useQuery();
  const detectionResults = trpc.siemFeedback.getDetectionResults.useQuery({ limit: 50 });
  const createMut = trpc.siemFeedback.createIntegration.useMutation({
    onSuccess: () => {
      toast.success("SIEM integration created");
      integrations.refetch();
      setShowAddForm(false);
    },
    onError: (e) => toast.error(e.message),
  });
  const testMut = trpc.siemFeedback.testConnection.useMutation({
    onSuccess: (d) => toast(d.success ? "Connection OK" : "Connection Failed", { description: `Latency: ${d.latencyMs}ms` }),
    onError: (e) => toast.error(e.message),
  });
  const queryMut = trpc.siemFeedback.executeQuery.useMutation({
    onSuccess: (d) => {
      toast.success(`Query returned ${d.alertCount} alerts in ${d.latencyMs}ms`);
      detectionResults.refetch();
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteMut = trpc.siemFeedback.deleteIntegration.useMutation({
    onSuccess: () => { toast.success("Deleted"); integrations.refetch(); },
  });

  const stats = useMemo(() => {
    const results = detectionResults.data ?? [];
    const detected = results.filter((r: any) => r.status === "detected").length;
    const missed = results.filter((r: any) => r.status === "missed").length;
    const partial = results.filter((r: any) => r.status === "partial").length;
    const total = results.length;
    const rate = total > 0 ? Math.round((detected / total) * 100) : 0;
    return { detected, missed, partial, total, rate };
  }, [detectionResults.data]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Activity className="h-6 w-6 text-blue-400" />
            SIEM Detection Feedback
          </h1>
          <p className="text-muted-foreground mt-1">Real-time detection validation against Splunk, Elastic, Sentinel, and QRadar</p>
        </div>
        <Button onClick={() => setShowAddForm(!showAddForm)}>
          <Plus className="h-4 w-4 mr-2" /> Add Integration
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Detection Rate</div><div className="text-3xl font-bold text-green-400">{stats.rate}%</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Detected</div><div className="text-3xl font-bold text-green-400">{stats.detected}</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Missed</div><div className="text-3xl font-bold text-red-400">{stats.missed}</div></CardContent></Card>
        <Card><CardContent className="pt-6"><div className="text-sm text-muted-foreground">Partial</div><div className="text-3xl font-bold text-yellow-400">{stats.partial}</div></CardContent></Card>
      </div>

      {showAddForm && (
        <Card>
          <CardHeader><CardTitle>New SIEM Integration</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div><Label>Provider</Label>
                <Select value={newProvider} onValueChange={setNewProvider}>
                  <SelectTrigger><SelectValue placeholder="Select provider" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="splunk">Splunk</SelectItem>
                    <SelectItem value="elastic">Elastic</SelectItem>
                    <SelectItem value="sentinel">Sentinel</SelectItem>
                    <SelectItem value="qradar">QRadar</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div><Label>Name</Label><Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Production Splunk" /></div>
              <div><Label>Endpoint URL</Label><Input value={newEndpoint} onChange={(e) => setNewEndpoint(e.target.value)} placeholder="https://splunk.corp.com:8089" /></div>
              <div><Label>API Key</Label><Input type="password" value={newApiKey} onChange={(e) => setNewApiKey(e.target.value)} placeholder="Bearer token" /></div>
            </div>
            <Button disabled={!newProvider || !newName || !newEndpoint || createMut.isPending}
              onClick={() => createMut.mutate({ provider: newProvider as any, name: newName, endpoint: newEndpoint, apiKey: newApiKey })}>
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Create Integration
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Connected Integrations</CardTitle><CardDescription>{integrations.data?.length ?? 0} SIEM connections</CardDescription></CardHeader>
        <CardContent>
          {integrations.isLoading ? <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin" /></div>
          : !integrations.data?.length ? <p className="text-muted-foreground text-center py-8">No SIEM integrations configured yet</p>
          : <div className="space-y-3">{integrations.data.map((integ: any) => (
              <div key={integ.id} className="flex items-center justify-between p-3 rounded-lg border bg-card">
                <div className="flex items-center gap-3">
                  <Badge variant="outline">{integ.provider}</Badge>
                  <span className="font-medium">{integ.name}</span>
                  <span className="text-xs text-muted-foreground">{integ.endpoint}</span>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => testMut.mutate({ integrationId: integ.id })}><TestTube className="h-3 w-3 mr-1" /> Test</Button>
                  <Button size="sm" variant="outline" onClick={() => setSelectedIntegration(integ.id)}>Query</Button>
                  <Button size="sm" variant="ghost" onClick={() => deleteMut.mutate({ id: integ.id })}><Trash2 className="h-3 w-3 text-red-400" /></Button>
                </div>
              </div>
            ))}</div>}
        </CardContent>
      </Card>

      {selectedIntegration && (
        <Card>
          <CardHeader><CardTitle>Execute Detection Query</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div><Label>Query</Label><Input value={queryText} onChange={(e) => setQueryText(e.target.value)} placeholder="index=main sourcetype=syslog T1059" /></div>
            <Button disabled={!queryText || queryMut.isPending}
              onClick={() => queryMut.mutate({ integrationId: selectedIntegration, query: queryText })}>
              {queryMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null} Run Query
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Recent Detection Results</CardTitle></CardHeader>
        <CardContent>
          {detectionResults.isLoading ? <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin" /></div>
          : !detectionResults.data?.length ? <p className="text-muted-foreground text-center py-8">No detection results yet</p>
          : <div className="space-y-2">{detectionResults.data.map((r: any) => (
              <div key={r.id} className="flex items-center justify-between p-3 rounded-lg border">
                <div className="flex items-center gap-3">
                  {r.status === "detected" && <CheckCircle className="h-4 w-4 text-green-400" />}
                  {r.status === "missed" && <XCircle className="h-4 w-4 text-red-400" />}
                  {r.status === "partial" && <AlertTriangle className="h-4 w-4 text-yellow-400" />}
                  <span className="font-mono text-sm">{r.technique || "\u2014"}</span>
                  <Badge variant={r.status === "detected" ? "default" : r.status === "missed" ? "destructive" : "secondary"}>{r.status}</Badge>
                </div>
                <div className="text-xs text-muted-foreground">{r.alertCount} alerts \u00b7 {r.latencyMs}ms \u00b7 {new Date(r.executedAt).toLocaleString()}</div>
              </div>
            ))}</div>}
        </CardContent>
      </Card>
    </div>
  );
}
