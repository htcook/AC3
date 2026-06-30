import { useState, useMemo, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield, Search, Plus, CheckCircle2, XCircle, AlertTriangle, Loader2,
  Globe, Zap, Database, Target, Eye, Activity, BarChart3, Layers,
  ChevronRight, ArrowRight, RefreshCw, Pause, Play, Trash2, Info,
  Network, Bug, Lock, Cloud, Radio, Crosshair, FileText, Monitor,
  Sparkles, Brain, GitBranch, Check, X, ExternalLink, Cpu
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════
// §1 — CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const CATEGORY_CONFIG: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  osint: { icon: <Globe className="h-4 w-4" />, color: "text-blue-400", label: "OSINT" },
  threat_intel: { icon: <Shield className="h-4 w-4" />, color: "text-amber-400", label: "Threat Intel" },
  credential: { icon: <Lock className="h-4 w-4" />, color: "text-red-400", label: "Credential" },
  scanner: { icon: <Target className="h-4 w-4" />, color: "text-green-400", label: "Scanner" },
  pentest_tool: { icon: <Crosshair className="h-4 w-4" />, color: "text-orange-400", label: "Pentest Tool" },
  exploit_db: { icon: <Bug className="h-4 w-4" />, color: "text-rose-400", label: "Exploit DB" },
  phishing: { icon: <Radio className="h-4 w-4" />, color: "text-purple-400", label: "Phishing" },
  c2: { icon: <Cpu className="h-4 w-4" />, color: "text-pink-400", label: "C2 Framework" },
  siem_soar: { icon: <Monitor className="h-4 w-4" />, color: "text-cyan-400", label: "SIEM/SOAR" },
  cloud: { icon: <Cloud className="h-4 w-4" />, color: "text-sky-400", label: "Cloud" },
  custom: { icon: <Layers className="h-4 w-4" />, color: "text-gray-400", label: "Custom" },
};

const STAGE_CONFIG: Record<string, { label: string; color: string }> = {
  recon: { label: "Recon", color: "bg-blue-500/20 text-blue-300 border-blue-500/30" },
  passive_discovery: { label: "Passive Discovery", color: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30" },
  enumeration: { label: "Enumeration", color: "bg-teal-500/20 text-teal-300 border-teal-500/30" },
  vuln_detection: { label: "Vuln Detection", color: "bg-amber-500/20 text-amber-300 border-amber-500/30" },
  social_engineering: { label: "Social Engineering", color: "bg-purple-500/20 text-purple-300 border-purple-500/30" },
  exploitation: { label: "Exploitation", color: "bg-red-500/20 text-red-300 border-red-500/30" },
  post_exploit: { label: "Post-Exploit", color: "bg-rose-500/20 text-rose-300 border-rose-500/30" },
  reporting: { label: "Reporting", color: "bg-green-500/20 text-green-300 border-green-500/30" },
  monitoring: { label: "Monitoring", color: "bg-indigo-500/20 text-indigo-300 border-indigo-500/30" },
  enrichment: { label: "Enrichment", color: "bg-orange-500/20 text-orange-300 border-orange-500/30" },
};

const RECOMMENDATION_CONFIG: Record<string, { color: string; label: string }> = {
  strongly_recommended: { color: "bg-green-500/20 text-green-300 border-green-500/30", label: "Strongly Recommended" },
  recommended: { color: "bg-blue-500/20 text-blue-300 border-blue-500/30", label: "Recommended" },
  optional: { color: "bg-amber-500/20 text-amber-300 border-amber-500/30", label: "Optional" },
  redundant: { color: "bg-red-500/20 text-red-300 border-red-500/30", label: "Redundant" },
};

// ═══════════════════════════════════════════════════════════════════════
// §2 — SUB-COMPONENTS
// ═══════════════════════════════════════════════════════════════════════

function CategoryBadge({ category }: { category: string }) {
  const config = CATEGORY_CONFIG[category] || CATEGORY_CONFIG.custom;
  return (
    <Badge variant="outline" className={`gap-1 ${config.color} border-current/30`}>
      {config.icon}
      {config.label}
    </Badge>
  );
}

function StageBadge({ stage }: { stage: string }) {
  const config = STAGE_CONFIG[stage] || { label: stage, color: "bg-gray-500/20 text-gray-300" };
  return (
    <Badge variant="outline" className={`text-xs ${config.color}`}>
      {config.label}
    </Badge>
  );
}

function CoverageBar({ level, count }: { level: string; count: number }) {
  const pct = level === "none" ? 0 : level === "minimal" ? 25 : level === "adequate" ? 50 : level === "strong" ? 75 : 100;
  const color = pct === 0 ? "bg-red-500" : pct <= 25 ? "bg-amber-500" : pct <= 50 ? "bg-yellow-500" : pct <= 75 ? "bg-green-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-muted-foreground w-20 text-right">{count} source{count !== 1 ? "s" : ""}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — CATALOG BROWSER TAB
// ═══════════════════════════════════════════════════════════════════════

function CatalogBrowser() {
  const [search, setSearch] = useState("");
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [filterStage, setFilterStage] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data: catalog, isLoading } = trpc.integrationRegistry.getBuiltIn.useQuery();
  const { data: categorySummary } = trpc.integrationRegistry.getCategorySummary.useQuery();

  const filtered = useMemo(() => {
    if (!catalog) return [];
    return catalog.filter((item: any) => {
      const matchesSearch = !search ||
        item.displayName?.toLowerCase().includes(search.toLowerCase()) ||
        item.description?.toLowerCase().includes(search.toLowerCase()) ||
        item.id?.toLowerCase().includes(search.toLowerCase());
      const matchesCategory = filterCategory === "all" || item.category === filterCategory;
      const matchesStage = filterStage === "all" || item.pipelineStages?.includes(filterStage);
      return matchesSearch && matchesCategory && matchesStage;
    });
  }, [catalog, search, filterCategory, filterStage]);

  const selected = useMemo(() => {
    if (!selectedId || !catalog) return null;
    return catalog.find((item: any) => item.id === selectedId);
  }, [selectedId, catalog]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Left: Filters + List */}
      <div className="lg:col-span-2 space-y-4">
        {/* Category summary cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
          {categorySummary?.slice(0, 8).map((cat: any) => {
            const config = CATEGORY_CONFIG[cat.category] || CATEGORY_CONFIG.custom;
            return (
              <button
                key={cat.category}
                onClick={() => setFilterCategory(filterCategory === cat.category ? "all" : cat.category)}
                className={`p-3 rounded-lg border text-left transition-all hover:border-primary/50 ${
                  filterCategory === cat.category ? "border-primary bg-primary/5" : "border-border bg-card"
                }`}
              >
                <div className={`flex items-center gap-2 ${config.color}`}>
                  {config.icon}
                  <span className="text-xs font-medium">{config.label}</span>
                </div>
                <p className="text-lg font-bold mt-1">{cat.totalCount}</p>
              </button>
            );
          })}
        </div>

        {/* Search + Stage filter */}
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search integrations..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <Select value={filterStage} onValueChange={setFilterStage}>
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Pipeline stage" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Stages</SelectItem>
              {Object.entries(STAGE_CONFIG).map(([key, val]) => (
                <SelectItem key={key} value={key}>{val.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Integration list */}
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">{filtered.length} integration{filtered.length !== 1 ? "s" : ""}</p>
          <ScrollArea className="h-[500px]">
            <div className="space-y-2 pr-4">
              {filtered.map((item: any) => (
                <button
                  key={item.id}
                  onClick={() => setSelectedId(item.id)}
                  className={`w-full text-left p-4 rounded-lg border transition-all hover:border-primary/50 ${
                    selectedId === item.id ? "border-primary bg-primary/5" : "border-border bg-card"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium truncate">{item.displayName}</span>
                        <CategoryBadge category={item.category} />
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2">{item.description}</p>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {item.pipelineStages?.slice(0, 3).map((s: string) => (
                          <StageBadge key={s} stage={s} />
                        ))}
                        {(item.pipelineStages?.length || 0) > 3 && (
                          <Badge variant="outline" className="text-xs">+{item.pipelineStages.length - 3}</Badge>
                        )}
                      </div>
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 mt-1" />
                  </div>
                </button>
              ))}
            </div>
          </ScrollArea>
        </div>
      </div>

      {/* Right: Detail panel */}
      <div className="space-y-4">
        {selected ? (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <CategoryBadge category={selected.category} />
                <Badge variant="outline" className="text-xs capitalize">{selected.licenseModel?.replace("_", " ")}</Badge>
              </div>
              <CardTitle className="text-lg mt-2">{selected.displayName}</CardTitle>
              <CardDescription>{selected.description}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="text-xs text-muted-foreground">Pipeline Stages</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selected.pipelineStages?.map((s: string) => <StageBadge key={s} stage={s} />)}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Data Types</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selected.dataTypes?.map((d: string) => (
                    <Badge key={d} variant="secondary" className="text-xs">{d}</Badge>
                  ))}
                </div>
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Authentication</Label>
                <p className="text-sm mt-1 capitalize">{selected.authMethod?.replace("_", " ") || "API Key"}</p>
              </div>
              {selected.envVars && selected.envVars.length > 0 && (
                <div>
                  <Label className="text-xs text-muted-foreground">Required Env Vars</Label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selected.envVars.map((v: string) => (
                      <Badge key={v} variant="outline" className="text-xs font-mono">{v}</Badge>
                    ))}
                  </div>
                </div>
              )}
              <Separator />
              <div className="text-xs text-muted-foreground">
                <span className="font-medium">Built-in integration</span> — pre-configured and ready to use when credentials are provided.
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-16 text-center">
              <Info className="h-8 w-8 text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">Select an integration to view details</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — DISCOVER NEW SOURCE TAB
// ═══════════════════════════════════════════════════════════════════════

function DiscoverNewSource() {
  const [baseUrl, setBaseUrl] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiKeyHeader, setApiKeyHeader] = useState("");
  const [docsUrl, setDocsUrl] = useState("");
  const [description, setDescription] = useState("");
  const [discoveryResult, setDiscoveryResult] = useState<any>(null);
  const [reviewOpen, setReviewOpen] = useState(false);

  const discoverMutation = trpc.integrationRegistry.discover.useMutation({
    onSuccess: (data) => {
      setDiscoveryResult(data);
      toast.success("API analyzed successfully — review the proposal below");
    },
    onError: (err) => {
      toast.error(`Discovery failed: ${err.message}`);
    },
  });

  const submitReviewMutation = trpc.integrationRegistry.submitReview.useMutation({
    onSuccess: (data) => {
      if (data.success && data.integration) {
        toast.success(`Integration "${data.integration.displayName}" approved and registered!`);
        setDiscoveryResult(null);
        setBaseUrl("");
        setApiKey("");
        setDocsUrl("");
        setDescription("");
      } else if (data.success) {
        toast.info("Integration rejected");
        setDiscoveryResult(null);
      } else {
        toast.error(data.error || "Review submission failed");
      }
    },
    onError: (err) => {
      toast.error(`Review failed: ${err.message}`);
    },
  });

  const handleDiscover = () => {
    if (!baseUrl) {
      toast.error("Please enter an API base URL");
      return;
    }
    discoverMutation.mutate({
      baseUrl,
      apiKey: apiKey || undefined,
      apiKeyHeader: apiKeyHeader || undefined,
      docsUrl: docsUrl || undefined,
      customerDescription: description || undefined,
    });
  };

  const handleApprove = (corrections?: {
    category?: string;
    stages?: string[];
    dataTypes?: string[];
    notes?: string;
  }) => {
    if (!discoveryResult) return;
    submitReviewMutation.mutate({
      discoveryId: discoveryResult.discoveryId,
      approved: true,
      correctedCategory: corrections?.category as any,
      correctedPipelineStages: corrections?.stages as any,
      correctedDataTypes: corrections?.dataTypes,
      notes: corrections?.notes,
    });
  };

  const handleReject = (notes?: string) => {
    if (!discoveryResult) return;
    submitReviewMutation.mutate({
      discoveryId: discoveryResult.discoveryId,
      approved: false,
      notes,
    });
  };

  return (
    <div className="space-y-6">
      {/* Input form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-primary" />
            Add New API Source
          </CardTitle>
          <CardDescription>
            Paste an API base URL and our AI engine will automatically classify it, determine which pipeline stages
            it enhances, and propose how to wire it into your engagement workflows. You review and approve before anything goes live.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>API Base URL *</Label>
              <Input
                placeholder="https://api.example.com/v1"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Documentation URL</Label>
              <Input
                placeholder="https://docs.example.com"
                value={docsUrl}
                onChange={(e) => setDocsUrl(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>API Key (optional)</Label>
              <Input
                type="password"
                placeholder="For authenticated probing"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>API Key Header</Label>
              <Input
                placeholder="X-API-Key (default)"
                value={apiKeyHeader}
                onChange={(e) => setApiKeyHeader(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>Description (helps AI classify better)</Label>
            <Textarea
              placeholder="What does this API do? e.g., 'Provides threat intelligence feeds with IOC data from dark web monitoring'"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
            />
          </div>
          <Button
            onClick={handleDiscover}
            disabled={discoverMutation.isPending || !baseUrl}
            className="gap-2"
          >
            {discoverMutation.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Analyzing API...
              </>
            ) : (
              <>
                <Brain className="h-4 w-4" />
                Discover & Classify
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Discovery result */}
      {discoveryResult && (
        <DiscoveryResultPanel
          result={discoveryResult}
          onApprove={handleApprove}
          onReject={handleReject}
          isSubmitting={submitReviewMutation.isPending}
        />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — DISCOVERY RESULT PANEL (REVIEW FLOW)
// ═══════════════════════════════════════════════════════════════════════

function DiscoveryResultPanel({
  result,
  onApprove,
  onReject,
  isSubmitting,
}: {
  result: any;
  onApprove: (corrections?: any) => void;
  onReject: (notes?: string) => void;
  isSubmitting: boolean;
}) {
  const classification = result.result?.classification;
  const wiring = result.wiringProposal;
  const value = result.valueComparison;
  const probe = result.result?.probe;

  const [editMode, setEditMode] = useState(false);
  const [correctedCategory, setCorrectedCategory] = useState(classification?.category || "");
  const [correctedStages, setCorrectedStages] = useState<string[]>(classification?.pipelineStages || []);
  const [notes, setNotes] = useState("");

  const toggleStage = (stage: string) => {
    setCorrectedStages(prev =>
      prev.includes(stage) ? prev.filter(s => s !== stage) : [...prev, stage]
    );
  };

  const hasCorrections = correctedCategory !== classification?.category ||
    JSON.stringify(correctedStages.sort()) !== JSON.stringify((classification?.pipelineStages || []).sort());

  return (
    <div className="space-y-4">
      {/* Classification result */}
      <Card className="border-primary/30">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                <Brain className="h-5 w-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg">{classification?.suggestedDisplayName || "Unknown API"}</CardTitle>
                <CardDescription>
                  AI Classification — Confidence: {classification?.confidence || 0}%
                </CardDescription>
              </div>
            </div>
            <Badge variant="outline" className={`${
              (classification?.confidence || 0) >= 80 ? "text-green-400 border-green-500/30" :
              (classification?.confidence || 0) >= 50 ? "text-amber-400 border-amber-500/30" :
              "text-red-400 border-red-500/30"
            }`}>
              {(classification?.confidence || 0) >= 80 ? "High" :
               (classification?.confidence || 0) >= 50 ? "Medium" : "Low"} Confidence
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">{classification?.description}</p>

          {/* API probe results */}
          {probe && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-muted/50">
                <p className="text-xs text-muted-foreground">Reachable</p>
                <div className="flex items-center gap-1 mt-1">
                  {probe.reachable ? <CheckCircle2 className="h-4 w-4 text-green-400" /> : <XCircle className="h-4 w-4 text-red-400" />}
                  <span className="text-sm font-medium">{probe.reachable ? "Yes" : "No"}</span>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-muted/50">
                <p className="text-xs text-muted-foreground">Auth Method</p>
                <p className="text-sm font-medium mt-1 capitalize">{classification?.detectedAuthMethod?.replace("_", " ") || "Unknown"}</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/50">
                <p className="text-xs text-muted-foreground">Data Format</p>
                <p className="text-sm font-medium mt-1 uppercase">{probe.dataFormat || "Unknown"}</p>
              </div>
              <div className="p-3 rounded-lg bg-muted/50">
                <p className="text-xs text-muted-foreground">OpenAPI Spec</p>
                <div className="flex items-center gap-1 mt-1">
                  {classification?.hasOpenApiSpec ? <CheckCircle2 className="h-4 w-4 text-green-400" /> : <XCircle className="h-4 w-4 text-muted-foreground" />}
                  <span className="text-sm font-medium">{classification?.hasOpenApiSpec ? "Detected" : "Not found"}</span>
                </div>
              </div>
            </div>
          )}

          <Separator />

          {/* Classification details (editable) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-medium">Classification</Label>
              <Button variant="ghost" size="sm" onClick={() => setEditMode(!editMode)} className="gap-1 text-xs">
                {editMode ? <Check className="h-3 w-3" /> : <Zap className="h-3 w-3" />}
                {editMode ? "Done Editing" : "Correct Classification"}
              </Button>
            </div>

            {/* Category */}
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted-foreground w-24">Category:</span>
              {editMode ? (
                <Select value={correctedCategory} onValueChange={setCorrectedCategory}>
                  <SelectTrigger className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(CATEGORY_CONFIG).map(([key, val]) => (
                      <SelectItem key={key} value={key}>{val.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <CategoryBadge category={classification?.category || "custom"} />
              )}
              {hasCorrections && !editMode && (
                <Badge variant="outline" className="text-xs text-amber-400 border-amber-500/30">Modified</Badge>
              )}
            </div>

            {/* Pipeline stages */}
            <div>
              <span className="text-sm text-muted-foreground">Pipeline Stages:</span>
              <div className="flex flex-wrap gap-1.5 mt-1.5">
                {editMode ? (
                  Object.entries(STAGE_CONFIG).map(([key, val]) => (
                    <button
                      key={key}
                      onClick={() => toggleStage(key)}
                      className={`px-2 py-1 rounded text-xs border transition-all ${
                        correctedStages.includes(key)
                          ? val.color + " border-current"
                          : "bg-muted/30 text-muted-foreground border-border hover:border-primary/50"
                      }`}
                    >
                      {val.label}
                    </button>
                  ))
                ) : (
                  (correctedStages.length > 0 ? correctedStages : classification?.pipelineStages || []).map((s: string) => (
                    <StageBadge key={s} stage={s} />
                  ))
                )}
              </div>
            </div>

            {/* Data types */}
            <div>
              <span className="text-sm text-muted-foreground">Data Types:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {(classification?.dataTypes || []).map((d: string) => (
                  <Badge key={d} variant="secondary" className="text-xs">{d}</Badge>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Value assessment */}
      {value && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-4 w-4" />
              Value Assessment
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted-foreground">Recommendation:</span>
              <Badge variant="outline" className={RECOMMENDATION_CONFIG[value.recommendation]?.color || ""}>
                {RECOMMENDATION_CONFIG[value.recommendation]?.label || value.recommendation}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">{value.explanation}</p>

            {value.netNewDataTypes?.length > 0 && (
              <div>
                <span className="text-xs text-muted-foreground">New data types this source provides:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {value.netNewDataTypes.map((d: string) => (
                    <Badge key={d} variant="secondary" className="text-xs bg-green-500/10 text-green-400">{d}</Badge>
                  ))}
                </div>
              </div>
            )}

            {value.overlaps?.length > 0 && (
              <div>
                <span className="text-xs text-muted-foreground">Overlaps with:</span>
                <div className="space-y-1 mt-1">
                  {value.overlaps.slice(0, 5).map((o: any) => (
                    <div key={o.existingId} className="flex items-center justify-between text-xs">
                      <span>{o.existingName}</span>
                      <Badge variant="outline" className="text-xs">{o.overlapPercent}% overlap</Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Wiring proposal */}
      {wiring && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              Pipeline Wiring Proposal
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">{wiring.explanation}</p>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-2 rounded bg-muted/50">
                <p className="text-xs text-muted-foreground">Priority</p>
                <p className="text-sm font-medium">{wiring.config?.priority || "—"}</p>
              </div>
              <div className="p-2 rounded bg-muted/50">
                <p className="text-xs text-muted-foreground">Parallel</p>
                <p className="text-sm font-medium">{wiring.config?.parallel ? "Yes" : "Sequential"}</p>
              </div>
              <div className="p-2 rounded bg-muted/50">
                <p className="text-xs text-muted-foreground">Timeout</p>
                <p className="text-sm font-medium">{Math.round((wiring.config?.maxDurationMs || 0) / 1000)}s</p>
              </div>
              <div className="p-2 rounded bg-muted/50">
                <p className="text-xs text-muted-foreground">On Failure</p>
                <p className="text-sm font-medium capitalize">{wiring.config?.failurePolicy || "continue"}</p>
              </div>
            </div>

            {wiring.warnings?.length > 0 && (
              <div className="space-y-1">
                {wiring.warnings.map((w: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-amber-400">
                    <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                    <span>{w}</span>
                  </div>
                ))}
              </div>
            )}

            {wiring.optimizations?.length > 0 && (
              <div className="space-y-1">
                {wiring.optimizations.map((o: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-blue-400">
                    <Sparkles className="h-3 w-3 mt-0.5 shrink-0" />
                    <span>{o}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Review notes + action buttons */}
      <Card>
        <CardContent className="pt-6 space-y-4">
          <div className="space-y-2">
            <Label>Review Notes (optional)</Label>
            <Textarea
              placeholder="Any notes about this integration..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={2}
            />
          </div>
          <div className="flex gap-3">
            <Button
              onClick={() => onApprove(hasCorrections ? {
                category: correctedCategory,
                stages: correctedStages,
                notes,
              } : notes ? { notes } : undefined)}
              disabled={isSubmitting}
              className="gap-2 flex-1"
            >
              {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
              Approve & Register
            </Button>
            <Button
              variant="outline"
              onClick={() => onReject(notes)}
              disabled={isSubmitting}
              className="gap-2"
            >
              <XCircle className="h-4 w-4" />
              Reject
            </Button>
          </div>
          {hasCorrections && (
            <p className="text-xs text-amber-400 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              Your corrections will be applied and used to improve future classifications.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — PIPELINE COVERAGE TAB
// ═══════════════════════════════════════════════════════════════════════

function PipelineCoverage() {
  const { data: coverage, isLoading } = trpc.integrationRegistry.getCoverage.useQuery();
  const { data: health } = trpc.integrationRegistry.getHealth.useQuery();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Health summary */}
      {health && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-muted-foreground">Total Integrations</p>
              <p className="text-2xl font-bold">{health.total}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-muted-foreground">Built-In</p>
              <p className="text-2xl font-bold text-blue-400">{health.builtIn}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-muted-foreground">Customer-Added</p>
              <p className="text-2xl font-bold text-green-400">{health.customer}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-muted-foreground">Pipeline Score</p>
              <p className="text-2xl font-bold">{coverage?.overallScore || 0}%</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Stage-by-stage coverage */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Pipeline Stage Coverage
          </CardTitle>
          <CardDescription>
            How well each engagement pipeline stage is covered by your active integrations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {coverage?.stages && Object.entries(coverage.stages).map(([stage, info]: [string, any]) => (
            <div key={stage} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StageBadge stage={stage} />
                  <span className="text-xs text-muted-foreground capitalize">{info.coverageLevel}</span>
                </div>
              </div>
              <CoverageBar level={info.coverageLevel} count={info.integrationCount} />
              {info.gaps?.length > 0 && (
                <div className="pl-2 space-y-0.5">
                  {info.gaps.map((gap: string, i: number) => (
                    <p key={i} className="text-xs text-amber-400 flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3 shrink-0" />
                      {gap}
                    </p>
                  ))}
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Recommendations */}
      {coverage?.topRecommendations && coverage.topRecommendations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-primary" />
              Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {coverage.topRecommendations.map((rec: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <ArrowRight className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — ACTIVE INTEGRATIONS TAB
// ═══════════════════════════════════════════════════════════════════════

function ActiveIntegrations() {
  const { data: customerIntegrations, isLoading, refetch } = trpc.integrationRegistry.getCustomer.useQuery();
  const activateMutation = trpc.integrationRegistry.activate.useMutation({
    onSuccess: () => { toast.success("Integration activated"); refetch(); },
    onError: (err) => toast.error(err.message),
  });
  const pauseMutation = trpc.integrationRegistry.pause.useMutation({
    onSuccess: () => { toast.success("Integration paused"); refetch(); },
    onError: (err) => toast.error(err.message),
  });
  const removeMutation = trpc.integrationRegistry.remove.useMutation({
    onSuccess: () => { toast.success("Integration removed"); refetch(); },
    onError: (err) => toast.error(err.message),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!customerIntegrations || customerIntegrations.length === 0) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-16 text-center">
          <Database className="h-10 w-10 text-muted-foreground mb-4" />
          <h3 className="font-medium mb-1">No Custom Integrations Yet</h3>
          <p className="text-sm text-muted-foreground max-w-sm">
            Use the "Add New Source" tab to discover and register new API integrations.
            Built-in integrations are always available in the catalog.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {customerIntegrations.map((integration: any) => (
        <Card key={integration.id}>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`h-2 w-2 rounded-full ${
                  integration.status === "active" ? "bg-green-400" :
                  integration.status === "paused" ? "bg-amber-400" :
                  integration.status === "error" ? "bg-red-400" :
                  "bg-muted-foreground"
                }`} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{integration.displayName}</span>
                    <CategoryBadge category={integration.category} />
                    <Badge variant="outline" className="text-xs capitalize">{integration.status}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{integration.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {integration.status === "approved" && (
                  <Button size="sm" variant="outline" onClick={() => activateMutation.mutate({ id: integration.id })} className="gap-1">
                    <Play className="h-3 w-3" /> Activate
                  </Button>
                )}
                {integration.status === "active" && (
                  <Button size="sm" variant="outline" onClick={() => pauseMutation.mutate({ id: integration.id })} className="gap-1">
                    <Pause className="h-3 w-3" /> Pause
                  </Button>
                )}
                {integration.status === "paused" && (
                  <Button size="sm" variant="outline" onClick={() => activateMutation.mutate({ id: integration.id })} className="gap-1">
                    <Play className="h-3 w-3" /> Resume
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    if (confirm("Remove this integration?")) {
                      removeMutation.mutate({ id: integration.id });
                    }
                  }}
                  className="text-red-400 hover:text-red-300"
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </div>
            {/* Pipeline stages */}
            <div className="flex flex-wrap gap-1 mt-2 ml-5">
              {(integration.capabilities?.pipelineStages || integration.pipelineWiring?.stages || []).map((s: string) => (
                <StageBadge key={s} stage={s} />
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════

export default function IntegrationRegistry() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Network className="h-6 w-6 text-primary" />
          Integration Registry
        </h1>
        <p className="text-muted-foreground mt-1">
          Auto-discover, classify, and wire new API sources into your engagement pipelines.
          Review every proposal before it goes live.
        </p>
      </div>

      <Tabs defaultValue="catalog" className="space-y-4">
        <TabsList>
          <TabsTrigger value="catalog" className="gap-1.5">
            <Database className="h-3.5 w-3.5" />
            Catalog
          </TabsTrigger>
          <TabsTrigger value="discover" className="gap-1.5">
            <Sparkles className="h-3.5 w-3.5" />
            Add New Source
          </TabsTrigger>
          <TabsTrigger value="coverage" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" />
            Pipeline Coverage
          </TabsTrigger>
          <TabsTrigger value="active" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" />
            My Integrations
          </TabsTrigger>
        </TabsList>

        <TabsContent value="catalog">
          <CatalogBrowser />
        </TabsContent>
        <TabsContent value="discover">
          <DiscoverNewSource />
        </TabsContent>
        <TabsContent value="coverage">
          <PipelineCoverage />
        </TabsContent>
        <TabsContent value="active">
          <ActiveIntegrations />
        </TabsContent>
      </Tabs>
    </div>
  );
}
