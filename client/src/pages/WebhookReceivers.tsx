import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
import {
  Webhook, Plus, Search, Trash2, Send, CheckCircle, XCircle,
  Clock, Copy, RotateCcw, Play, Pause, Shield, Activity,
  ArrowDownToLine, Key, RefreshCw, Eye, AlertTriangle, Zap,
  BarChart3, Filter
} from "lucide-react";

// ─── Category & Stage metadata ──────────────────────────────────────────────

const CATEGORIES = [
  { value: "osint", label: "OSINT", color: "text-blue-400" },
  { value: "exploit_db", label: "Exploit DB", color: "text-red-400" },
  { value: "threat_intel", label: "Threat Intel", color: "text-amber-400" },
  { value: "scanner", label: "Scanner", color: "text-cyan-400" },
  { value: "pentest_tool", label: "Pentest Tool", color: "text-purple-400" },
  { value: "phishing", label: "Phishing", color: "text-orange-400" },
  { value: "c2", label: "C2", color: "text-rose-400" },
  { value: "siem_soar", label: "SIEM/SOAR", color: "text-emerald-400" },
  { value: "cloud", label: "Cloud", color: "text-sky-400" },
  { value: "credential", label: "Credential", color: "text-yellow-400" },
  { value: "custom", label: "Custom", color: "text-zinc-400" },
];

const PIPELINE_STAGES = [
  { value: "recon", label: "Recon" },
  { value: "passive_discovery", label: "Passive Discovery" },
  { value: "enumeration", label: "Enumeration" },
  { value: "vuln_detection", label: "Vuln Detection" },
  { value: "exploitation", label: "Exploitation" },
  { value: "post_exploit", label: "Post-Exploit" },
  { value: "threat_intel", label: "Threat Intel" },
  { value: "monitoring", label: "Monitoring" },
  { value: "reporting", label: "Reporting" },
  { value: "c2_ops", label: "C2 Ops" },
];

const SIG_ALGORITHMS = [
  { value: "hmac_sha256", label: "HMAC-SHA256" },
  { value: "hmac_sha1", label: "HMAC-SHA1" },
  { value: "hmac_sha512", label: "HMAC-SHA512" },
  { value: "none", label: "None (no validation)" },
];

const PAYLOAD_FORMATS = [
  { value: "json", label: "JSON" },
  { value: "form", label: "Form-encoded" },
  { value: "xml", label: "XML" },
  { value: "raw", label: "Raw" },
];

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    active: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    paused: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    disabled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
    error: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[status] || colors.disabled}`}>{status}</Badge>;
}

function eventStatusBadge(status: string) {
  const colors: Record<string, string> = {
    processed: "bg-emerald-500/20 text-emerald-400",
    failed: "bg-red-500/20 text-red-400",
    skipped: "bg-amber-500/20 text-amber-400",
    replayed: "bg-blue-500/20 text-blue-400",
    received: "bg-zinc-500/20 text-zinc-400",
    processing: "bg-cyan-500/20 text-cyan-400",
  };
  return <Badge variant="outline" className={`text-[10px] ${colors[status] || ""}`}>{status}</Badge>;
}

// ═══════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════

export default function WebhookReceivers() {
  const [view, setView] = useState<"endpoints" | "events" | "analytics">("endpoints");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
  const [showSecretDialog, setShowSecretDialog] = useState(false);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [eventFilter, setEventFilter] = useState<string | undefined>(undefined);

  // ─── Form state ─────────────────────────────────────────────────────
  const [formName, setFormName] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formCategory, setFormCategory] = useState("custom");
  const [formSigAlgo, setFormSigAlgo] = useState("hmac_sha256");
  const [formSigHeader, setFormSigHeader] = useState("x-webhook-signature");
  const [formPayloadFormat, setFormPayloadFormat] = useState("json");
  const [formStages, setFormStages] = useState<string[]>([]);
  const [formRateMinute, setFormRateMinute] = useState(60);
  const [formRateHour, setFormRateHour] = useState(1000);
  const [formTransform, setFormTransform] = useState("");

  // ─── Queries ────────────────────────────────────────────────────────
  const listInput = useMemo(() => ({}), []);
  const { data: endpoints, isLoading: endpointsLoading, refetch: refetchEndpoints } = trpc.webhooks.listEndpoints.useQuery(listInput);
  const { data: dashStats } = trpc.webhooks.getDashboardStats.useQuery();

  const eventsInput = useMemo(() => ({
    endpointId: selectedEndpoint || undefined,
    hoursBack: 48,
    limit: 50,
  }), [selectedEndpoint]);
  const { data: events, refetch: refetchEvents } = trpc.webhooks.getEvents.useQuery(eventsInput, { enabled: view === "events" || !!selectedEndpoint });

  const endpointInput = useMemo(() => ({ endpointId: selectedEndpoint! }), [selectedEndpoint]);
  const { data: endpointDetail } = trpc.webhooks.getEndpoint.useQuery(endpointInput, { enabled: !!selectedEndpoint });

  // ─── Mutations ──────────────────────────────────────────────────────
  const createMut = trpc.webhooks.createEndpoint.useMutation({
    onSuccess: (data) => {
      setNewSecret(data.secret);
      setShowCreateDialog(false);
      setShowSecretDialog(true);
      resetForm();
      refetchEndpoints();
      toast.success("Webhook receiver created");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const updateMut = trpc.webhooks.updateEndpoint.useMutation({
    onSuccess: () => {
      refetchEndpoints();
      toast.success("Endpoint updated");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const deleteMut = trpc.webhooks.deleteEndpoint.useMutation({
    onSuccess: () => {
      setSelectedEndpoint(null);
      refetchEndpoints();
      toast.success("Endpoint deleted");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const rotateSecretMut = trpc.webhooks.rotateSecret.useMutation({
    onSuccess: (data) => {
      setNewSecret(data.newSecret);
      setShowSecretDialog(true);
      toast.success("Secret rotated");
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const testMut = trpc.webhooks.sendTestEvent.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Test event processed (${data.processingDurationMs}ms)`);
        refetchEvents();
      } else {
        toast.error(`Test failed: ${data.message}`);
      }
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const replayMut = trpc.webhooks.replayEvent.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success("Event replayed successfully");
        refetchEvents();
      } else {
        toast.error(`Replay failed: ${data.message}`);
      }
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const retryMut = trpc.webhooks.retryFailed.useMutation({
    onSuccess: (data) => {
      toast.success(`Retried ${data.retried} events: ${data.succeeded} succeeded, ${data.failed} failed`);
      refetchEvents();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  function resetForm() {
    setFormName(""); setFormDesc(""); setFormCategory("custom");
    setFormSigAlgo("hmac_sha256"); setFormSigHeader("x-webhook-signature");
    setFormPayloadFormat("json"); setFormStages([]); setFormRateMinute(60);
    setFormRateHour(1000); setFormTransform("");
  }

  function toggleStage(stage: string) {
    setFormStages(prev => prev.includes(stage) ? prev.filter(s => s !== stage) : [...prev, stage]);
  }

  // ═══════════════════════════════════════════════════════════════════
  // Render
  // ═══════════════════════════════════════════════════════════════════

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <ArrowDownToLine className="h-5 w-5 text-cyan-400" />
            Inbound Webhook Receivers
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Receive real-time data from external APIs — auto-routed to pipeline stages
          </p>
        </div>
        <div className="flex gap-2">
          <div className="flex rounded-lg border border-zinc-700 overflow-hidden">
            {(["endpoints", "events", "analytics"] as const).map(v => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                  view === v ? "bg-cyan-500/20 text-cyan-400" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {v === "endpoints" ? "Endpoints" : v === "events" ? "Event Log" : "Analytics"}
              </button>
            ))}
          </div>
          <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
            <DialogTrigger asChild>
              <Button size="sm" className="gap-1">
                <Plus className="h-3.5 w-3.5" />
                New Receiver
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle>Create Webhook Receiver</DialogTitle>
                <DialogDescription>
                  Configure an inbound webhook endpoint to receive real-time data from external APIs
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Name *</Label>
                    <Input value={formName} onChange={e => setFormName(e.target.value)} placeholder="e.g., Shodan Alerts" />
                  </div>
                  <div>
                    <Label>Data Category</Label>
                    <Select value={formCategory} onValueChange={setFormCategory}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {CATEGORIES.map(c => (
                          <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div>
                  <Label>Description</Label>
                  <Textarea value={formDesc} onChange={e => setFormDesc(e.target.value)} placeholder="What data does this webhook receive?" rows={2} />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Signature Algorithm</Label>
                    <Select value={formSigAlgo} onValueChange={setFormSigAlgo}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {SIG_ALGORITHMS.map(a => (
                          <SelectItem key={a.value} value={a.value}>{a.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label>Signature Header</Label>
                    <Input value={formSigHeader} onChange={e => setFormSigHeader(e.target.value)} placeholder="x-webhook-signature" />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label>Payload Format</Label>
                    <Select value={formPayloadFormat} onValueChange={setFormPayloadFormat}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {PAYLOAD_FORMATS.map(f => (
                          <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label>Rate/min</Label>
                      <Input type="number" value={formRateMinute} onChange={e => setFormRateMinute(Number(e.target.value))} />
                    </div>
                    <div>
                      <Label>Rate/hr</Label>
                      <Input type="number" value={formRateHour} onChange={e => setFormRateHour(Number(e.target.value))} />
                    </div>
                  </div>
                </div>

                <div>
                  <Label className="mb-2 block">Target Pipeline Stages *</Label>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {PIPELINE_STAGES.map(s => (
                      <label
                        key={s.value}
                        className={`flex items-center gap-2 p-2 rounded border cursor-pointer text-sm transition-colors ${
                          formStages.includes(s.value)
                            ? "border-cyan-500 bg-cyan-500/10 text-cyan-300"
                            : "border-zinc-700 hover:border-zinc-500"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={formStages.includes(s.value)}
                          onChange={() => toggleStage(s.value)}
                          className="rounded"
                        />
                        <span>{s.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div>
                  <Label>Transform Template (optional JSON mapping)</Label>
                  <Textarea
                    value={formTransform}
                    onChange={e => setFormTransform(e.target.value)}
                    placeholder={'{\n  "cve": "$.vulnerability.cve_id",\n  "severity": "$.vulnerability.severity"\n}'}
                    rows={3}
                    className="font-mono text-xs"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowCreateDialog(false)}>Cancel</Button>
                <Button
                  onClick={() => createMut.mutate({
                    name: formName,
                    description: formDesc || undefined,
                    dataCategory: formCategory as any,
                    signatureAlgorithm: formSigAlgo as any,
                    signatureHeader: formSigHeader,
                    payloadFormat: formPayloadFormat as any,
                    targetPipelineStages: formStages as any[],
                    rateLimitPerMinute: formRateMinute,
                    rateLimitPerHour: formRateHour,
                    transformTemplate: formTransform || undefined,
                  })}
                  disabled={!formName || formStages.length === 0 || createMut.isPending}
                >
                  {createMut.isPending ? "Creating..." : "Create Receiver"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Secret reveal dialog */}
      <Dialog open={showSecretDialog} onOpenChange={setShowSecretDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="h-5 w-5 text-amber-400" />
              Webhook Signing Secret
            </DialogTitle>
            <DialogDescription>
              Save this secret now — it will not be shown again. Use it to verify webhook signatures.
            </DialogDescription>
          </DialogHeader>
          <div className="bg-zinc-900 border rounded-lg p-4 font-mono text-sm break-all text-amber-300">
            {newSecret}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="gap-1"
              onClick={() => {
                navigator.clipboard.writeText(newSecret || "");
                toast.success("Secret copied to clipboard");
              }}
            >
              <Copy className="h-3.5 w-3.5" />
              Copy Secret
            </Button>
            <Button onClick={() => { setShowSecretDialog(false); setNewSecret(null); }}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Dashboard Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="text-xl font-bold">{dashStats?.endpoints?.total ?? 0}</div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Endpoints</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="text-xl font-bold text-emerald-400">
              {dashStats?.endpoints?.byStatus?.find((s: any) => s.status === "active")?.count ?? 0}
            </div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Active</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="text-xl font-bold text-blue-400">{dashStats?.events24h?.total ?? 0}</div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Events (24h)</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="text-xl font-bold text-cyan-400">
              {dashStats?.events24h?.avgProcessingMs ? `${Math.round(Number(dashStats.events24h.avgProcessingMs))}ms` : "—"}
            </div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Latency</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-3 pb-3">
            <div className="text-xl font-bold text-red-400">
              {dashStats?.events24h?.byStatus?.find((s: any) => s.status === "failed")?.count ?? 0}
            </div>
            <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Failed (24h)</div>
          </CardContent>
        </Card>
      </div>

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* ENDPOINTS VIEW */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {view === "endpoints" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Endpoint List */}
          <div className="lg:col-span-1 space-y-3">
            {endpointsLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading...</div>
            ) : !endpoints?.length ? (
              <Card>
                <CardContent className="py-8 text-center text-muted-foreground">
                  <ArrowDownToLine className="h-10 w-10 mx-auto mb-3 opacity-40" />
                  <p>No webhook receivers configured</p>
                  <p className="text-sm mt-1">Create one to start receiving real-time data</p>
                </CardContent>
              </Card>
            ) : (
              endpoints.map((ep: any) => (
                <Card
                  key={ep.endpointId}
                  className={`cursor-pointer transition-colors hover:border-cyan-500/50 ${
                    selectedEndpoint === ep.endpointId ? "border-cyan-500" : ""
                  }`}
                  onClick={() => setSelectedEndpoint(ep.endpointId)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <h3 className="font-semibold text-sm truncate">{ep.name}</h3>
                        <p className="text-xs text-muted-foreground truncate mt-0.5">
                          {ep.webhookUrl}
                        </p>
                      </div>
                      {statusBadge(ep.status)}
                    </div>
                    <div className="flex items-center gap-2 mt-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] ${CATEGORIES.find(c => c.value === ep.dataCategory)?.color || ""}`}>
                        {CATEGORIES.find(c => c.value === ep.dataCategory)?.label || ep.dataCategory}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">
                        {ep.totalEventsReceived || 0} events
                      </span>
                      {ep.lastEventAt && (
                        <span className="text-[10px] text-muted-foreground">
                          Last: {new Date(ep.lastEventAt).toLocaleString()}
                        </span>
                      )}
                    </div>
                    {(ep.targetPipelineStages || []).length > 0 && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {(ep.targetPipelineStages as string[]).slice(0, 3).map((s: string) => (
                          <Badge key={s} variant="outline" className="text-[9px] border-zinc-700">
                            {PIPELINE_STAGES.find(ps => ps.value === s)?.label || s}
                          </Badge>
                        ))}
                        {(ep.targetPipelineStages as string[]).length > 3 && (
                          <Badge variant="outline" className="text-[9px] border-zinc-700">
                            +{(ep.targetPipelineStages as string[]).length - 3}
                          </Badge>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </div>

          {/* Endpoint Detail */}
          <div className="lg:col-span-2">
            {endpointDetail ? (
              <Card>
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Webhook className="h-5 w-5 text-cyan-400" />
                        {endpointDetail.name}
                      </CardTitle>
                      <CardDescription className="mt-1">
                        {(endpointDetail as any).description || "No description"}
                      </CardDescription>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="gap-1"
                        onClick={() => testMut.mutate({ endpointId: selectedEndpoint! })}
                        disabled={testMut.isPending}
                      >
                        <Send className="h-3 w-3" />
                        {testMut.isPending ? "Testing..." : "Test"}
                      </Button>
                      {(endpointDetail as any).status === "active" ? (
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-1"
                          onClick={() => updateMut.mutate({ endpointId: selectedEndpoint!, status: "paused" })}
                        >
                          <Pause className="h-3 w-3" />
                          Pause
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-1"
                          onClick={() => updateMut.mutate({ endpointId: selectedEndpoint!, status: "active" })}
                        >
                          <Play className="h-3 w-3" />
                          Activate
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => {
                          if (confirm("Delete this webhook receiver? This cannot be undone.")) {
                            deleteMut.mutate({ endpointId: selectedEndpoint! });
                          }
                        }}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  {/* Webhook URL */}
                  <div className="bg-zinc-900 border rounded-lg p-3">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Webhook URL</div>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-cyan-300 flex-1 break-all">
                        {(endpointDetail as any).webhookUrl}
                      </code>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-7 w-7 shrink-0"
                        onClick={() => {
                          navigator.clipboard.writeText((endpointDetail as any).webhookUrl || "");
                          toast.success("URL copied");
                        }}
                      >
                        <Copy className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>

                  {/* Config Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Status</span>
                      {statusBadge((endpointDetail as any).status || "active")}
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Category</span>
                      <Badge variant="outline" className={`text-[10px] ${CATEGORIES.find(c => c.value === (endpointDetail as any).dataCategory)?.color || ""}`}>
                        {CATEGORIES.find(c => c.value === (endpointDetail as any).dataCategory)?.label || (endpointDetail as any).dataCategory}
                      </Badge>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Format</span>
                      <span>{(endpointDetail as any).payloadFormat || "json"}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Signature</span>
                      <span className="text-xs">{(endpointDetail as any).signatureAlgorithm || "hmac_sha256"}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Rate Limit</span>
                      <span className="text-xs">{(endpointDetail as any).rateLimitPerMinute || 60}/min, {(endpointDetail as any).rateLimitPerHour || 1000}/hr</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">Secret</span>
                      <div className="flex items-center gap-1">
                        <Shield className="h-3 w-3 text-amber-400" />
                        <span className="text-xs">{(endpointDetail as any).hasSecret ? "Configured" : "None"}</span>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-5 w-5 ml-1"
                          onClick={() => rotateSecretMut.mutate({ endpointId: selectedEndpoint! })}
                          title="Rotate secret"
                        >
                          <RefreshCw className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {/* Pipeline Stages */}
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <Zap className="h-4 w-4 text-cyan-400" />
                      Target Pipeline Stages
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {((endpointDetail as any).targetPipelineStages || []).map((s: string) => (
                        <Badge key={s} variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-300">
                          {PIPELINE_STAGES.find(ps => ps.value === s)?.label || s}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-zinc-900 rounded-lg p-3 text-center">
                      <div className="text-lg font-bold">{(endpointDetail as any).totalEventsReceived || 0}</div>
                      <div className="text-[10px] text-muted-foreground">Received</div>
                    </div>
                    <div className="bg-zinc-900 rounded-lg p-3 text-center">
                      <div className="text-lg font-bold text-emerald-400">{(endpointDetail as any).totalEventsProcessed || 0}</div>
                      <div className="text-[10px] text-muted-foreground">Processed</div>
                    </div>
                    <div className="bg-zinc-900 rounded-lg p-3 text-center">
                      <div className="text-lg font-bold text-red-400">{(endpointDetail as any).totalEventsFailed || 0}</div>
                      <div className="text-[10px] text-muted-foreground">Failed</div>
                    </div>
                  </div>

                  {/* Recent Events for this endpoint */}
                  <div>
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <Clock className="h-4 w-4 text-cyan-400" />
                      Recent Events
                    </h4>
                    {!events?.length ? (
                      <p className="text-sm text-muted-foreground">No events received yet. Send a test event to verify the endpoint.</p>
                    ) : (
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {events.filter((e: any) => e.endpointId === selectedEndpoint).slice(0, 10).map((e: any) => (
                          <div key={e.eventId} className="flex items-center gap-3 text-sm border rounded p-2">
                            {e.status === "processed" ? (
                              <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
                            ) : e.status === "failed" ? (
                              <XCircle className="h-4 w-4 text-red-400 shrink-0" />
                            ) : (
                              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
                            )}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                {eventStatusBadge(e.status)}
                                <Badge variant="outline" className="text-[10px]">{e.eventType || "unknown"}</Badge>
                                {e.routedToStage && (
                                  <span className="text-[10px] text-cyan-400">→ {e.routedToStage}</span>
                                )}
                              </div>
                              {e.error && <p className="text-[10px] text-red-400 mt-0.5 truncate">{e.error}</p>}
                            </div>
                            <div className="flex items-center gap-1">
                              {e.processingDurationMs && (
                                <span className="text-[10px] text-muted-foreground">{e.processingDurationMs}ms</span>
                              )}
                              {e.status === "failed" && (
                                <Button
                                  size="icon"
                                  variant="ghost"
                                  className="h-6 w-6"
                                  onClick={(ev) => { ev.stopPropagation(); replayMut.mutate({ eventId: e.eventId }); }}
                                  title="Replay event"
                                >
                                  <RotateCcw className="h-3 w-3" />
                                </Button>
                              )}
                            </div>
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
                  <ArrowDownToLine className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p className="text-lg">Select an endpoint to view details</p>
                  <p className="text-sm mt-1">Or create a new receiver to start ingesting data</p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* EVENTS VIEW */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {view === "events" && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Select value={eventFilter || "all"} onValueChange={v => setEventFilter(v === "all" ? undefined : v)}>
                <SelectTrigger className="w-40"><SelectValue placeholder="All statuses" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="processed">Processed</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                  <SelectItem value="skipped">Skipped</SelectItem>
                  <SelectItem value="replayed">Replayed</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="gap-1 ml-auto"
              onClick={() => retryMut.mutate({})}
              disabled={retryMut.isPending}
            >
              <RotateCcw className="h-3 w-3" />
              Retry Failed
            </Button>
          </div>

          <div className="border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-zinc-900/50 border-b">
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Status</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Event ID</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Type</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Endpoint</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Routed To</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Duration</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Received</th>
                  <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(events || [])
                  .filter((e: any) => !eventFilter || e.status === eventFilter)
                  .map((e: any) => (
                  <tr key={e.eventId} className="border-b hover:bg-zinc-900/30">
                    <td className="p-3">{eventStatusBadge(e.status)}</td>
                    <td className="p-3 font-mono text-xs">{e.eventId?.slice(0, 12)}</td>
                    <td className="p-3">
                      <Badge variant="outline" className="text-[10px]">{e.eventType || "—"}</Badge>
                    </td>
                    <td className="p-3 text-xs text-muted-foreground">{e.endpointId?.slice(0, 8)}</td>
                    <td className="p-3 text-xs text-cyan-400">{e.routedToStage || "—"}</td>
                    <td className="p-3 text-xs">{e.processingDurationMs ? `${e.processingDurationMs}ms` : "—"}</td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {e.receivedAt ? new Date(e.receivedAt).toLocaleString() : "—"}
                    </td>
                    <td className="p-3">
                      <div className="flex gap-1">
                        <Button
                          size="icon"
                          variant="ghost"
                          className="h-6 w-6"
                          onClick={() => replayMut.mutate({ eventId: e.eventId })}
                          title="Replay"
                        >
                          <RotateCcw className="h-3 w-3" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
                {(!events || events.length === 0) && (
                  <tr>
                    <td colSpan={8} className="p-8 text-center text-muted-foreground">
                      No events in the last 48 hours
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════ */}
      {/* ANALYTICS VIEW */}
      {/* ═══════════════════════════════════════════════════════════════ */}
      {view === "analytics" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Status Breakdown */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-cyan-400" />
                  Event Status Breakdown (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(dashStats?.events24h?.byStatus || []).map((s: any) => {
                    const total = dashStats?.events24h?.total || 1;
                    const pct = Math.round((Number(s.count) / Number(total)) * 100);
                    const colors: Record<string, string> = {
                      processed: "bg-emerald-500",
                      failed: "bg-red-500",
                      skipped: "bg-amber-500",
                      replayed: "bg-blue-500",
                    };
                    return (
                      <div key={s.status}>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="capitalize">{s.status}</span>
                          <span className="text-muted-foreground">{s.count} ({pct}%)</span>
                        </div>
                        <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${colors[s.status] || "bg-zinc-500"}`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                  {(!dashStats?.events24h?.byStatus || dashStats.events24h.byStatus.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No events in the last 24 hours</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Top Endpoints */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  Top Endpoints by Volume (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(dashStats?.topEndpoints || []).map((ep: any, idx: number) => (
                    <div key={ep.endpointId} className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground w-4">{idx + 1}.</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-mono truncate">{ep.endpointId}</div>
                      </div>
                      <Badge variant="outline" className="text-[10px]">{ep.count} events</Badge>
                    </div>
                  ))}
                  {(!dashStats?.topEndpoints || dashStats.topEndpoints.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No activity yet</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Endpoint Summary Table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">All Endpoints Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="border rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-zinc-900/50 border-b">
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Name</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Status</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Category</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Received</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Processed</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Failed</th>
                      <th className="text-left p-3 text-[10px] uppercase tracking-wider text-muted-foreground">Last Event</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(endpoints || []).map((ep: any) => (
                      <tr key={ep.endpointId} className="border-b hover:bg-zinc-900/30">
                        <td className="p-3 font-medium">{ep.name}</td>
                        <td className="p-3">{statusBadge(ep.status)}</td>
                        <td className="p-3">
                          <Badge variant="outline" className={`text-[10px] ${CATEGORIES.find(c => c.value === ep.dataCategory)?.color || ""}`}>
                            {CATEGORIES.find(c => c.value === ep.dataCategory)?.label || ep.dataCategory}
                          </Badge>
                        </td>
                        <td className="p-3">{ep.totalEventsReceived || 0}</td>
                        <td className="p-3 text-emerald-400">{ep.totalEventsProcessed || 0}</td>
                        <td className="p-3 text-red-400">{ep.totalEventsFailed || 0}</td>
                        <td className="p-3 text-xs text-muted-foreground">
                          {ep.lastEventAt ? new Date(ep.lastEventAt).toLocaleString() : "Never"}
                        </td>
                      </tr>
                    ))}
                    {(!endpoints || endpoints.length === 0) && (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-muted-foreground">
                          No endpoints configured
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
