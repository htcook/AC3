import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { safeJsonParse } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import {
  Webhook, Plus, Search, Trash2, Send, CheckCircle,
  XCircle, Globe, Clock, Zap, Settings, Copy
} from "lucide-react";
import AppShell from "@/components/AppShell";

export default function Webhooks() {
  const [search, setSearch] = useState("");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedWebhook, setSelectedWebhook] = useState<string | null>(null);

  // Form state
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newFormat, setNewFormat] = useState("json");
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);

  const searchInput = useMemo(() => ({ search: search || undefined }), [search]);
  const { data: webhooks, isLoading, refetch } = trpc.webhookEndpoints.list.useQuery(searchInput);
  const { data: stats } = trpc.webhookEndpoints.stats.useQuery();
  const { data: selectedWh } = trpc.webhookEndpoints.get.useQuery(
    { webhookId: selectedWebhook! },
    { enabled: !!selectedWebhook }
  );
  const { data: availableEvents } = trpc.webhookEndpoints.availableEvents.useQuery(undefined, { enabled: showCreateDialog });

  const createMutation = trpc.webhookEndpoints.create.useMutation({
    onSuccess: (data) => {
      toast.success("Webhook created");
      setShowCreateDialog(false);
      setNewName("");
      setNewUrl("");
      setSelectedEvents([]);
      setSelectedWebhook(data.webhookId);
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateMutation = trpc.webhookEndpoints.update.useMutation({
    onSuccess: () => {
      toast.success("Webhook updated");
      refetch();
    },
  });

  const testMutation = trpc.webhookEndpoints.test.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Test delivery successful (HTTP ${data.status})`);
      } else {
        toast.error(`Test delivery failed (HTTP ${data.status}): ${data.body?.slice(0, 100)}`);
      }
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deleteMutation = trpc.webhookEndpoints.delete.useMutation({
    onSuccess: () => {
      toast.success("Webhook deleted");
      setSelectedWebhook(null);
      refetch();
    },
  });

  const toggleEvent = (event: string) => {
    setSelectedEvents(prev =>
      prev.includes(event) ? prev.filter(e => e !== event) : [...prev, event]
    );
  };

  return (
    <AppShell activePath="/webhooks">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Webhook className="h-6 w-6 text-emerald-400" />
            Webhooks &amp; Integrations
          </h1>
          <p className="text-muted-foreground mt-1">
            Configure outbound webhooks for SIEM, SOAR, and notification integrations
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              New Webhook
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>Create Webhook Endpoint</DialogTitle>
              <DialogDescription>Configure a new outbound webhook</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div>
                <Label>Name</Label>
                <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g., Splunk SIEM" />
              </div>
              <div>
                <Label>Endpoint URL</Label>
                <Input value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://..." />
              </div>
              <div>
                <Label>Format</Label>
                <Select value={newFormat} onValueChange={setNewFormat}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="json">JSON</SelectItem>
                    <SelectItem value="cef">CEF (Common Event Format)</SelectItem>
                    <SelectItem value="leef">LEEF (Log Event Extended Format)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="mb-2 block">Events</Label>
                <div className="grid grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                  {availableEvents?.map((ev: any) => (
                    <label
                      key={ev.event}
                      className={`flex items-center gap-2 p-2 rounded border cursor-pointer text-sm transition-colors ${
                        selectedEvents.includes(ev.event)
                          ? "border-emerald-500 bg-emerald-500/10"
                          : "border-zinc-700 hover:border-zinc-500"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedEvents.includes(ev.event)}
                        onChange={() => toggleEvent(ev.event)}
                        className="rounded"
                      />
                      <span>{ev.event}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createMutation.mutate({
                  name: newName,
                  url: newUrl,
                  format: newFormat as "json" | "cef" | "leef",
                  events: selectedEvents,
                })}
                disabled={!newName || !newUrl || selectedEvents.length === 0 || createMutation.isPending}
              >
                Create Webhook
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold">{stats?.totalWebhooks ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total Webhooks</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-emerald-400">{stats?.activeWebhooks ?? 0}</div>
            <div className="text-xs text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-blue-400">{stats?.totalDeliveries ?? 0}</div>
            <div className="text-xs text-muted-foreground">Deliveries</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="text-2xl font-bold text-red-400">{stats?.failedDeliveries ?? 0}</div>
            <div className="text-xs text-muted-foreground">Failed</div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder="Search webhooks..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
      </div>

      {/* Webhook List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* List */}
        <div className="lg:col-span-1 space-y-3">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading...</div>
          ) : !webhooks?.items?.length ? (
            <Card>
              <CardContent className="py-8 text-center text-muted-foreground">
                <Webhook className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p>No webhooks configured</p>
                <p className="text-sm mt-1">Add one to start receiving events</p>
              </CardContent>
            </Card>
          ) : (
            webhooks.items.map((wh: any) => (
              <Card
                key={wh.webhookId}
                className={`cursor-pointer transition-colors hover:border-emerald-500/50 ${
                  selectedWebhook === wh.webhookId ? "border-emerald-500" : ""
                }`}
                onClick={() => setSelectedWebhook(wh.webhookId)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-sm truncate">{wh.name}</h3>
                      <p className="text-xs text-muted-foreground truncate mt-0.5">{wh.url}</p>
                    </div>
                    <div className={`w-2 h-2 rounded-full mt-1 ${wh.enabled ? "bg-emerald-400" : "bg-zinc-500"}`} />
                  </div>
                  <div className="flex items-center gap-2 mt-2">
                    <Badge variant="outline" className="text-[10px]">{wh.format}</Badge>
                    <span className="text-xs text-muted-foreground">
                      {(() => {
                        const events = typeof wh.events === "string" ? safeJsonParse<string[]>(wh.events, []) : wh.events;
                        return `${Array.isArray(events) ? events.length : 0} events`;
                      })()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2">
          {selectedWh ? (
            <Card>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Webhook className="h-5 w-5 text-emerald-400" />
                      {selectedWh.name}
                    </CardTitle>
                    <CardDescription className="mt-1 break-all">{selectedWh.url}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1"
                      onClick={() => testMutation.mutate({ webhookId: selectedWh.webhookId })}
                      disabled={testMutation.isPending}
                    >
                      <Send className="h-3 w-3" />
                      {testMutation.isPending ? "Testing..." : "Test"}
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => deleteMutation.mutate({ webhookId: selectedWh.webhookId })}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Config */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Enabled</span>
                    <Switch
                      checked={selectedWh.enabled ?? false}
                      onCheckedChange={(checked) => updateMutation.mutate({
                        webhookId: selectedWh.webhookId,
                        enabled: checked,
                      })}
                    />
                  </div>
                  <div>
                    <span className="text-muted-foreground">Format:</span>{" "}
                    <Badge variant="outline" className="text-[10px]">{selectedWh.format}</Badge>
                  </div>
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Secret:</span>{" "}
                    <code className="text-xs bg-zinc-800 px-2 py-0.5 rounded">
                      {selectedWh.secret?.slice(0, 12)}...
                    </code>
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-6 w-6 ml-1"
                      onClick={() => {
                        navigator.clipboard.writeText(selectedWh.secret || "");
                        toast.success("Secret copied");
                      }}
                    >
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                </div>

                {/* Events */}
                <div>
                  <h4 className="text-sm font-semibold mb-2">Subscribed Events</h4>
                  <div className="flex flex-wrap gap-1">
                    {(() => {
                      const events = typeof selectedWh.events === "string"
                        ? safeJsonParse<string[]>(selectedWh.events, [])
                        : selectedWh.events;
                      return (events as string[] || []).map((ev: string) => (
                        <Badge key={ev} variant="outline" className="text-[10px]">
                          {ev}
                        </Badge>
                      ));
                    })()}
                  </div>
                </div>

                {/* Recent Deliveries */}
                <div>
                  <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                    <Clock className="h-4 w-4 text-emerald-400" />
                    Recent Deliveries
                  </h4>
                  {!selectedWh.deliveries?.length ? (
                    <p className="text-sm text-muted-foreground">No deliveries yet</p>
                  ) : (
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {selectedWh.deliveries.map((d: any, idx: number) => (
                        <div key={idx} className="flex items-center gap-3 text-sm border rounded p-2">
                          {d.success ? (
                            <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                          )}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="text-[10px]">{d.event}</Badge>
                              <span className="text-xs text-muted-foreground">
                                HTTP {d.responseStatus}
                              </span>
                            </div>
                          </div>
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {new Date(d.deliveredAt).toLocaleString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-muted-foreground">
                <Webhook className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p className="text-lg">Select a webhook to view details</p>
                <p className="text-sm mt-1">Or create a new one to start receiving events</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
}
