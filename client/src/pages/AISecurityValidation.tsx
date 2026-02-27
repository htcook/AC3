/**
 * AI Security Validation — MITRE ATLAS Dashboard
 * ────────────────────────────────────────────────
 * Validates customer AI/LLM deployments against prompt injection,
 * model extraction, adversarial evasion, data poisoning, and supply chain attacks.
 * Includes Prompt Guardrail Recommender and ATLAS Technique Drill-Down.
 *
 * Author: Harrison Cook — AceofCloud
 */
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  BrainCircuit,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Target,
  Play,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Crosshair,
  Zap,
  Eye,
  Database,
  Package,
  RefreshCw,
  Trash2,
  ChevronRight,
  Clock,
  BarChart3,
  FileText,
  Bot,
  Lock,
  Code,
  Copy,
  ExternalLink,
  BookOpen,
  Wrench,
  Layers,
  ArrowLeft,
  Download,
  Sparkles,
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────
type TestCategory =
  | "prompt-injection"
  | "model-extraction"
  | "adversarial-evasion"
  | "data-poisoning"
  | "supply-chain"
  | "model-inversion"
  | "membership-inference"
  | "denial-of-service";

const CATEGORY_META: Record<TestCategory, { label: string; icon: React.ReactNode; color: string; desc: string }> = {
  "prompt-injection":     { label: "Prompt Injection",     icon: <Zap className="w-4 h-4" />,       color: "text-red-400",     desc: "Test for direct/indirect prompt injection, jailbreaks, and system prompt leaks" },
  "model-extraction":     { label: "Model Extraction",     icon: <Eye className="w-4 h-4" />,       color: "text-amber-400",   desc: "Probe for model theft, weight extraction, and decision boundary mapping" },
  "adversarial-evasion":  { label: "Adversarial Evasion",  icon: <Target className="w-4 h-4" />,    color: "text-orange-400",  desc: "Test classifier robustness against adversarial perturbations" },
  "data-poisoning":       { label: "Data Poisoning",       icon: <Database className="w-4 h-4" />,  color: "text-purple-400",  desc: "Validate training data integrity and RAG context injection" },
  "supply-chain":         { label: "Supply Chain",         icon: <Package className="w-4 h-4" />,   color: "text-blue-400",    desc: "Check model provenance, dependency integrity, and serialization safety" },
  "model-inversion":      { label: "Model Inversion",      icon: <RefreshCw className="w-4 h-4" />, color: "text-cyan-400",    desc: "Test for training data reconstruction and membership inference" },
  "membership-inference": { label: "Membership Inference", icon: <Crosshair className="w-4 h-4" />, color: "text-teal-400",    desc: "Determine if specific data was used in model training" },
  "denial-of-service":    { label: "Denial of Service",    icon: <ShieldX className="w-4 h-4" />,   color: "text-rose-400",    desc: "Test resource exhaustion and sponge example attacks" },
};

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function scoreBg(score: number): string {
  if (score >= 80) return "bg-green-500/20 border-green-500/30";
  if (score >= 60) return "bg-yellow-500/20 border-yellow-500/30";
  if (score >= 40) return "bg-orange-500/20 border-orange-500/30";
  return "bg-red-500/20 border-red-500/30";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Strong";
  if (score >= 60) return "Moderate";
  if (score >= 40) return "Weak";
  return "Critical";
}

function severityBadge(severity: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return (
    <Badge variant="outline" className={colors[severity] || colors.info}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function effortBadge(effort: string) {
  const colors: Record<string, string> = {
    low: "bg-green-500/20 text-green-400 border-green-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  };
  return (
    <Badge variant="outline" className={colors[effort] || colors.medium}>
      {effort.toUpperCase()} EFFORT
    </Badge>
  );
}

// ─── Overview Tab ────────────────────────────────────────────────────────────
function OverviewTab({ onTechniqueClick }: { onTechniqueClick: (id: string) => void }) {
  const { data: overview, isLoading } = trpc.aiSecurityValidation.getOverview.useQuery();
  const { data: techniques } = trpc.aiSecurityValidation.getTechniques.useQuery();
  const { data: categories } = trpc.aiSecurityValidation.getCategories.useQuery();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-2" />
        <span className="text-muted-foreground">Loading overview...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Hero stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-primary">{overview?.totalTechniques ?? 0}</div>
            <div className="text-xs text-muted-foreground mt-1">ATLAS TECHNIQUES</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-amber-400">{overview?.totalPayloads ?? 0}</div>
            <div className="text-xs text-muted-foreground mt-1">TEST PAYLOADS</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-green-400">{overview?.completedScans ?? 0}</div>
            <div className="text-xs text-muted-foreground mt-1">COMPLETED SCANS</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className={`text-3xl font-bold ${overview?.averagePostureScore !== null ? scoreColor(overview?.averagePostureScore ?? 0) : "text-muted-foreground"}`}>
              {overview?.averagePostureScore !== null ? `${overview?.averagePostureScore}%` : "—"}
            </div>
            <div className="text-xs text-muted-foreground mt-1">AVG POSTURE SCORE</div>
          </CardContent>
        </Card>
      </div>

      {/* MITRE ATLAS Technique Catalog — clickable for drill-down */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <BrainCircuit className="w-5 h-5 text-primary" />
            MITRE ATLAS Technique Catalog
          </CardTitle>
          <CardDescription>
            Click any technique to view detailed information, related payloads, and remediation guidance
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2">
              {techniques?.map((t: any) => (
                <div
                  key={t.id}
                  className="flex items-start gap-3 p-3 bg-muted/30 border border-border rounded-md hover:border-primary/30 hover:bg-primary/5 transition-colors cursor-pointer group"
                  onClick={() => onTechniqueClick(t.id)}
                >
                  <code className="text-xs font-mono text-primary bg-primary/10 px-2 py-0.5 rounded shrink-0 mt-0.5">
                    {t.id}
                  </code>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-sm">{t.name}</div>
                    <div className="text-xs text-muted-foreground mt-0.5">{t.description}</div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0">{t.category}</Badge>
                      {severityBadge(t.severity)}
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0 mt-1" />
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Attack Category Breakdown */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="w-5 h-5 text-amber-400" />
            Attack Categories
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {categories && Object.entries(categories).map(([key, cat]: [string, any]) => {
              const meta = CATEGORY_META[key as TestCategory];
              if (!meta) return null;
              return (
                <div key={key} className="p-3 bg-muted/30 border border-border rounded-md">
                  <div className={`flex items-center gap-2 ${meta.color} mb-1`}>
                    {meta.icon}
                    <span className="text-sm font-medium">{meta.label}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">{cat.description}</div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {cat.payloadCount} payloads · {cat.techniqueCount} techniques
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Recent Scans */}
      {overview?.recentScans && overview.recentScans.length > 0 && (
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="w-5 h-5 text-cyan-400" />
              Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {overview.recentScans.map((scan: any) => (
                <div key={scan.scanId} className="flex items-center justify-between p-3 bg-muted/30 border border-border rounded-md">
                  <div>
                    <div className="font-medium text-sm">{scan.targetName}</div>
                    <div className="text-xs text-muted-foreground">
                      {scan.status === "completed" ? "Completed" : scan.status === "running" ? "Running..." : scan.status}
                      {scan.startedAt && ` · ${new Date(scan.startedAt).toLocaleString()}`}
                    </div>
                  </div>
                  <div className={`text-lg font-bold ${scoreColor(scan.postureScore?.overall ?? 0)}`}>
                    {scan.postureScore?.overall ?? "—"}%
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── New Scan Tab ────────────────────────────────────────────────────────────
function NewScanTab({ onScanStarted }: { onScanStarted: (scanId: string) => void }) {
  const [name, setName] = useState("");
  const [type, setType] = useState<string>("llm-api");
  const [endpoint, setEndpoint] = useState("");
  const [authType, setAuthType] = useState<string>("bearer");
  const [authToken, setAuthToken] = useState("");
  const [authHeader, setAuthHeader] = useState("Authorization");
  const [bodyTemplate, setBodyTemplate] = useState('{"prompt": "{{payload}}"}');
  const [responseField, setResponseField] = useState("choices.0.message.content");
  const [enabledCategories, setEnabledCategories] = useState<TestCategory[]>([
    "prompt-injection",
    "model-extraction",
    "adversarial-evasion",
    "data-poisoning",
    "supply-chain",
  ]);
  const [maxConcurrency, setMaxConcurrency] = useState(3);
  const [timeoutMs, setTimeoutMs] = useState(30000);

  const startScan = trpc.aiSecurityValidation.startScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan started: ${data.totalTests} tests queued`);
      onScanStarted(data.scanId);
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleCategory = (cat: TestCategory) => {
    setEnabledCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    );
  };

  const handleSubmit = () => {
    if (!name.trim()) return toast.error("Target name is required");
    if (!endpoint.trim()) return toast.error("Endpoint URL is required");

    startScan.mutate({
      name: name.trim(),
      type: type as any,
      endpoint: endpoint.trim(),
      auth: authType !== "none" ? {
        type: authType as any,
        token: authToken || undefined,
        headerName: authType === "api-key" ? authHeader : undefined,
      } : { type: "none" },
      requestFormat: {
        method: "POST",
        bodyTemplate: bodyTemplate || undefined,
        responseField: responseField || undefined,
      },
      enabledCategories,
      maxConcurrency,
      timeoutMs,
    });
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Bot className="w-5 h-5 text-primary" />
            Target AI System
          </CardTitle>
          <CardDescription>Configure the AI/LLM endpoint to validate</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Target Name</Label>
              <Input placeholder="e.g., Production ChatBot API" value={name} onChange={e => setName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>System Type</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="llm-api">LLM API (OpenAI-compatible)</SelectItem>
                  <SelectItem value="chat-endpoint">Chat Endpoint</SelectItem>
                  <SelectItem value="classification-api">Classification API</SelectItem>
                  <SelectItem value="embedding-api">Embedding API</SelectItem>
                  <SelectItem value="rag-system">RAG System</SelectItem>
                  <SelectItem value="custom">Custom Endpoint</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label>Endpoint URL</Label>
            <Input placeholder="https://api.example.com/v1/chat/completions" value={endpoint} onChange={e => setEndpoint(e.target.value)} />
          </div>
          <Separator />
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label>Auth Type</Label>
              <Select value={authType} onValueChange={setAuthType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="bearer">Bearer Token</SelectItem>
                  <SelectItem value="api-key">API Key Header</SelectItem>
                  <SelectItem value="basic">Basic Auth</SelectItem>
                  <SelectItem value="none">No Auth</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {authType !== "none" && (
              <div className="space-y-2 col-span-2">
                <Label>{authType === "api-key" ? "API Key" : authType === "basic" ? "Credentials (user:pass)" : "Bearer Token"}</Label>
                <Input type="password" placeholder={authType === "api-key" ? "sk-..." : authType === "basic" ? "user:password" : "Bearer token"} value={authToken} onChange={e => setAuthToken(e.target.value)} />
              </div>
            )}
          </div>
          {authType === "api-key" && (
            <div className="space-y-2">
              <Label>Header Name</Label>
              <Input placeholder="X-API-Key" value={authHeader} onChange={e => setAuthHeader(e.target.value)} />
            </div>
          )}
          <Separator />
          <div className="space-y-2">
            <Label>Request Body Template</Label>
            <Input placeholder='{"prompt": "{{payload}}"}' value={bodyTemplate} onChange={e => setBodyTemplate(e.target.value)} className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">Use {"{{payload}}"} as placeholder for test payloads</p>
          </div>
          <div className="space-y-2">
            <Label>Response Field Path</Label>
            <Input placeholder="choices.0.message.content" value={responseField} onChange={e => setResponseField(e.target.value)} className="font-mono text-xs" />
            <p className="text-xs text-muted-foreground">Dot-notation path to extract the AI response from JSON</p>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Target className="w-5 h-5 text-amber-400" />
            Test Categories
          </CardTitle>
          <CardDescription>Select which attack categories to validate</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(Object.entries(CATEGORY_META) as [TestCategory, typeof CATEGORY_META[TestCategory]][]).map(([key, meta]) => (
              <div
                key={key}
                className={`flex items-center justify-between p-3 border rounded-md cursor-pointer transition-colors ${
                  enabledCategories.includes(key) ? "border-primary/50 bg-primary/5" : "border-border bg-muted/20 opacity-60"
                }`}
                onClick={() => toggleCategory(key)}
              >
                <div className="flex items-center gap-2">
                  <span className={meta.color}>{meta.icon}</span>
                  <div>
                    <div className="text-sm font-medium">{meta.label}</div>
                    <div className="text-xs text-muted-foreground">{meta.desc}</div>
                  </div>
                </div>
                <Switch checked={enabledCategories.includes(key)} onCheckedChange={() => toggleCategory(key)} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Scan Settings
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Max Concurrency</Label>
              <Select value={String(maxConcurrency)} onValueChange={v => setMaxConcurrency(Number(v))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 (Sequential)</SelectItem>
                  <SelectItem value="3">3 (Conservative)</SelectItem>
                  <SelectItem value="5">5 (Standard)</SelectItem>
                  <SelectItem value="10">10 (Aggressive)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Timeout per Test (ms)</Label>
              <Select value={String(timeoutMs)} onValueChange={v => setTimeoutMs(Number(v))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="10000">10s</SelectItem>
                  <SelectItem value="30000">30s</SelectItem>
                  <SelectItem value="60000">60s</SelectItem>
                  <SelectItem value="120000">120s</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      <Button onClick={handleSubmit} disabled={startScan.isPending || !name.trim() || !endpoint.trim()} className="w-full h-12 text-base">
        {startScan.isPending ? (
          <><Loader2 className="w-5 h-5 animate-spin mr-2" /> Starting Scan...</>
        ) : (
          <><Play className="w-5 h-5 mr-2" /> Launch AI Security Validation</>
        )}
      </Button>
    </div>
  );
}

// ─── Scan Results Tab ────────────────────────────────────────────────────────
function ScanResultsTab({ onViewGuardrails }: { onViewGuardrails: (scanId: string) => void }) {
  const { data: scans, isLoading, refetch } = trpc.aiSecurityValidation.listScans.useQuery();
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const { data: scanDetail } = trpc.aiSecurityValidation.getScan.useQuery(
    { scanId: selectedScanId! },
    { enabled: !!selectedScanId, refetchInterval: (query) => {
      const d = query.state.data;
      return d && (d as any).status === "running" ? 3000 : false;
    }},
  );
  const deleteScan = trpc.aiSecurityValidation.deleteScan.useMutation({
    onSuccess: () => { toast.success("Scan deleted"); refetch(); setSelectedScanId(null); },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-2" />
        <span className="text-muted-foreground">Loading scans...</span>
      </div>
    );
  }

  if (!scans || scans.length === 0) {
    return (
      <div className="text-center py-20">
        <BrainCircuit className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">No Scans Yet</h3>
        <p className="text-muted-foreground text-sm">Start a new AI security validation scan to see results here.</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="space-y-2">
        <h3 className="text-sm font-medium text-muted-foreground mb-3">SCAN HISTORY</h3>
        <ScrollArea className="h-[600px]">
          {scans.map((scan: any) => (
            <div
              key={scan.scanId}
              className={`p-3 border rounded-md cursor-pointer mb-2 transition-colors ${
                selectedScanId === scan.scanId ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
              }`}
              onClick={() => setSelectedScanId(scan.scanId)}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-sm truncate">{scan.targetName}</span>
                {scan.status === "running" ? (
                  <Badge variant="outline" className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                    <Loader2 className="w-3 h-3 animate-spin mr-1" /> Running
                  </Badge>
                ) : scan.status === "completed" ? (
                  <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                    <CheckCircle2 className="w-3 h-3 mr-1" /> Done
                  </Badge>
                ) : (
                  <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30">
                    <XCircle className="w-3 h-3 mr-1" /> Failed
                  </Badge>
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{scan.targetType}</span>
                <span className={`text-sm font-bold ${scoreColor(scan.postureScore?.overall ?? 0)}`}>
                  {scan.postureScore?.overall ?? "—"}%
                </span>
              </div>
              {scan.status === "running" && (
                <Progress value={(scan.completedTests / scan.totalTests) * 100} className="h-1 mt-2" />
              )}
            </div>
          ))}
        </ScrollArea>
      </div>

      <div className="lg:col-span-2">
        {!selectedScanId ? (
          <div className="text-center py-20 text-muted-foreground">
            <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
            <p>Select a scan to view results</p>
          </div>
        ) : !scanDetail ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
          </div>
        ) : (
          <ScanDetailView
            scan={scanDetail}
            onDelete={() => deleteScan.mutate({ scanId: selectedScanId })}
            onViewGuardrails={() => onViewGuardrails(selectedScanId)}
          />
        )}
      </div>
    </div>
  );
}

// ─── Scan Detail View ────────────────────────────────────────────────────────
function ScanDetailView({ scan, onDelete, onViewGuardrails }: { scan: any; onDelete: () => void; onViewGuardrails: () => void }) {
  const posture = scan.postureScore;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold">{scan.targetName}</h3>
          <p className="text-xs text-muted-foreground">
            {scan.targetType} · {scan.totalTests} tests · Started {new Date(scan.startedAt).toLocaleString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {scan.status === "completed" && (
            <Button variant="outline" size="sm" className="text-primary border-primary/30" onClick={onViewGuardrails}>
              <Lock className="w-4 h-4 mr-1" /> Generate Guardrails
            </Button>
          )}
          <Button variant="outline" size="sm" className="text-red-400 border-red-500/30" onClick={onDelete}>
            <Trash2 className="w-4 h-4 mr-1" /> Delete
          </Button>
        </div>
      </div>

      <Card className={`border ${scoreBg(posture.overall)}`}>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-muted-foreground">Overall AI Security Posture</div>
              <div className={`text-4xl font-bold ${scoreColor(posture.overall)}`}>{posture.overall}%</div>
              <div className={`text-sm font-medium ${scoreColor(posture.overall)}`}>{scoreLabel(posture.overall)}</div>
            </div>
            <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
              {posture.categories && Object.entries(posture.categories).map(([cat, score]: [string, any]) => {
                const meta = CATEGORY_META[cat as TestCategory];
                return meta ? (
                  <div key={cat} className="flex items-center gap-2">
                    <span className={meta.color}>{meta.icon}</span>
                    <span className="text-muted-foreground">{meta.label}:</span>
                    <span className={`font-bold ${scoreColor(score)}`}>{score}%</span>
                  </div>
                ) : null;
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {scan.summary && (
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="grid grid-cols-4 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold text-red-400">{scan.summary.critical}</div>
                <div className="text-xs text-muted-foreground">CRITICAL</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-orange-400">{scan.summary.high}</div>
                <div className="text-xs text-muted-foreground">HIGH</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-yellow-400">{scan.summary.medium}</div>
                <div className="text-xs text-muted-foreground">MEDIUM</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-blue-400">{scan.summary.low}</div>
                <div className="text-xs text-muted-foreground">LOW</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-base">Test Results</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2">
              {scan.results?.map((result: any, idx: number) => (
                <div key={idx} className="p-3 bg-muted/30 border border-border rounded-md">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      {result.passed ? (
                        <ShieldCheck className="w-4 h-4 text-green-400" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                      )}
                      <span className="text-sm font-medium">{result.testName}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {severityBadge(result.severity)}
                      <Badge variant="outline" className="text-[10px]">{result.category}</Badge>
                    </div>
                  </div>
                  {result.atlasId && (
                    <code className="text-[10px] font-mono text-primary bg-primary/10 px-1.5 py-0.5 rounded">
                      {result.atlasId}
                    </code>
                  )}
                  {result.finding && (
                    <p className="text-xs text-muted-foreground mt-1">{result.finding}</p>
                  )}
                  {result.recommendation && (
                    <p className="text-xs text-cyan-400 mt-1">
                      <Info className="w-3 h-3 inline mr-1" />
                      {result.recommendation}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Guardrail Recommender Tab ──────────────────────────────────────────────
function GuardrailRecommenderTab({ preselectedScanId }: { preselectedScanId: string | null }) {
  const { data: scans } = trpc.aiSecurityValidation.listScans.useQuery();
  const completedScans = useMemo(() => scans?.filter((s: any) => s.status === "completed") ?? [], [scans]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(preselectedScanId);
  const [exportLang, setExportLang] = useState<string>("python");

  // Update selection when preselected changes
  useMemo(() => {
    if (preselectedScanId) setSelectedScanId(preselectedScanId);
  }, [preselectedScanId]);

  const { data: guardrails, isLoading: loadingGuardrails } = trpc.aiSecurityValidation.generateGuardrails.useQuery(
    { scanId: selectedScanId! },
    { enabled: !!selectedScanId },
  );

  const { data: exportData, isLoading: loadingExport } = trpc.aiSecurityValidation.exportGuardrails.useQuery(
    { scanId: selectedScanId!, language: exportLang as any },
    { enabled: !!selectedScanId && !!guardrails },
  );

  const { data: guardrailTypes } = trpc.aiSecurityValidation.getGuardrailTypes.useQuery();

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  if (completedScans.length === 0) {
    return (
      <div className="text-center py-20">
        <Lock className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
        <h3 className="text-lg font-medium mb-2">No Completed Scans</h3>
        <p className="text-muted-foreground text-sm">
          Complete an AI security scan first, then guardrail recommendations will be auto-generated based on which tests failed.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Scan Selector */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Sparkles className="w-5 h-5 text-primary" />
            Guardrail Recommender
          </CardTitle>
          <CardDescription>
            Auto-generates custom guardrail rules based on which tests failed in your scan. Select a completed scan to generate recommendations.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <div className="flex-1 space-y-2">
              <Label>Select Completed Scan</Label>
              <Select value={selectedScanId ?? ""} onValueChange={setSelectedScanId}>
                <SelectTrigger><SelectValue placeholder="Choose a scan..." /></SelectTrigger>
                <SelectContent>
                  {completedScans.map((scan: any) => (
                    <SelectItem key={scan.scanId} value={scan.scanId}>
                      {scan.targetName} — {scan.postureScore?.overall ?? 0}% ({new Date(scan.completedAt ?? scan.startedAt).toLocaleDateString()})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {loadingGuardrails && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-primary mr-2" />
          <span className="text-muted-foreground">Generating guardrail recommendations...</span>
        </div>
      )}

      {guardrails && (
        <>
          {/* Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="bg-card border-border">
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold text-primary">{guardrails.totalRules}</div>
                <div className="text-xs text-muted-foreground mt-1">TOTAL RULES</div>
              </CardContent>
            </Card>
            <Card className="bg-card border-border">
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold text-red-400">{guardrails.criticalRules}</div>
                <div className="text-xs text-muted-foreground mt-1">CRITICAL RULES</div>
              </CardContent>
            </Card>
            <Card className="bg-card border-border">
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold text-amber-400">{guardrails.categoriesAffected}</div>
                <div className="text-xs text-muted-foreground mt-1">CATEGORIES</div>
              </CardContent>
            </Card>
            <Card className="bg-card border-border">
              <CardContent className="p-4 text-center">
                <div className={`text-3xl font-bold ${scoreColor(guardrails.estimatedPostureImprovement ?? 0)}`}>
                  +{guardrails.estimatedPostureImprovement ?? 0}%
                </div>
                <div className="text-xs text-muted-foreground mt-1">EST. IMPROVEMENT</div>
              </CardContent>
            </Card>
          </div>

          {/* Guardrail Rules by Category */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="w-5 h-5 text-amber-400" />
                Recommended Guardrail Rules
              </CardTitle>
              <CardDescription>
                Rules are prioritized by severity and estimated effectiveness
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {guardrails.rules?.map((rule: any, idx: number) => (
                    <div key={idx} className="p-4 bg-muted/30 border border-border rounded-md">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Lock className="w-4 h-4 text-primary shrink-0" />
                          <span className="text-sm font-medium">{rule.name}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {severityBadge(rule.priority)}
                          {effortBadge(rule.effort)}
                        </div>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">{rule.description}</p>
                      <div className="flex flex-wrap gap-1.5 mb-2">
                        <Badge variant="outline" className="text-[10px] bg-primary/10 text-primary border-primary/30">
                          {rule.type}
                        </Badge>
                        <Badge variant="outline" className="text-[10px]">
                          {rule.category}
                        </Badge>
                        {rule.atlasIds?.map((id: string) => (
                          <code key={id} className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                            {id}
                          </code>
                        ))}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>Effectiveness: <span className="text-green-400 font-medium">{rule.effectiveness}%</span></span>
                        {rule.falsePositiveRate && (
                          <span>False Positive Rate: <span className="text-yellow-400 font-medium">{rule.falsePositiveRate}%</span></span>
                        )}
                      </div>
                      {rule.implementation && (
                        <div className="mt-2 p-2 bg-background/50 rounded border border-border">
                          <code className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap">{rule.implementation}</code>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Export Code */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Code className="w-5 h-5 text-green-400" />
                Export Guardrail Code
              </CardTitle>
              <CardDescription>
                Export all recommended guardrails as deployable code in your preferred language
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <Select value={exportLang} onValueChange={setExportLang}>
                  <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="typescript">TypeScript</SelectItem>
                    <SelectItem value="regex">Regex Rules</SelectItem>
                  </SelectContent>
                </Select>
                {exportData && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <CheckCircle2 className="w-4 h-4 text-green-400" />
                    {exportData.ruleCount} rules exported
                  </div>
                )}
              </div>

              {loadingExport ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-primary mr-2" />
                  <span className="text-sm text-muted-foreground">Generating code...</span>
                </div>
              ) : exportData?.code ? (
                <div className="relative">
                  <Button
                    variant="outline"
                    size="sm"
                    className="absolute top-2 right-2 z-10"
                    onClick={() => copyToClipboard(exportData.code)}
                  >
                    <Copy className="w-3 h-3 mr-1" /> Copy
                  </Button>
                  <ScrollArea className="h-[400px] bg-background/50 rounded border border-border p-4">
                    <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap">{exportData.code}</pre>
                  </ScrollArea>
                </div>
              ) : null}
            </CardContent>
          </Card>

          {/* Guardrail Types Reference */}
          {guardrailTypes && (
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Layers className="w-5 h-5 text-purple-400" />
                  Guardrail Type Reference
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {guardrailTypes.map((gt: any) => (
                    <div key={gt.type} className="p-3 bg-muted/30 border border-border rounded-md">
                      <div className="flex items-center gap-2 mb-1">
                        <Wrench className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">{gt.label}</span>
                      </div>
                      <p className="text-xs text-muted-foreground">{gt.description}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

// ─── ATLAS Technique Drill-Down Tab ─────────────────────────────────────────
function ATLASDrillDownTab({ preselectedTechniqueId }: { preselectedTechniqueId: string | null }) {
  const { data: summaries, isLoading } = trpc.aiSecurityValidation.getTechniqueSummaries.useQuery();
  const [selectedId, setSelectedId] = useState<string | null>(preselectedTechniqueId);
  const [searchQuery, setSearchQuery] = useState("");

  // Update selection when preselected changes
  useMemo(() => {
    if (preselectedTechniqueId) setSelectedId(preselectedTechniqueId);
  }, [preselectedTechniqueId]);

  const { data: detail, isLoading: loadingDetail } = trpc.aiSecurityValidation.getTechniqueDetail.useQuery(
    { techniqueId: selectedId! },
    { enabled: !!selectedId },
  );

  const { data: remediation } = trpc.aiSecurityValidation.getRemediation.useQuery(
    { techniqueId: selectedId! },
    { enabled: !!selectedId },
  );

  const filteredSummaries = useMemo(() => {
    if (!summaries) return [];
    if (!searchQuery.trim()) return summaries;
    const q = searchQuery.toLowerCase();
    return summaries.filter((s: any) =>
      s.id.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.tactic.toLowerCase().includes(q)
    );
  }, [summaries, searchQuery]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="w-6 h-6 animate-spin text-primary mr-2" />
        <span className="text-muted-foreground">Loading ATLAS techniques...</span>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Technique List */}
      <div className="space-y-3">
        <div className="space-y-2">
          <Input
            placeholder="Search techniques..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="bg-muted/30"
          />
        </div>
        <h3 className="text-sm font-medium text-muted-foreground">
          {filteredSummaries.length} ATLAS TECHNIQUES
        </h3>
        <ScrollArea className="h-[650px]">
          <div className="space-y-1.5">
            {filteredSummaries.map((t: any) => (
              <div
                key={t.id}
                className={`p-3 border rounded-md cursor-pointer transition-colors ${
                  selectedId === t.id ? "border-primary bg-primary/5" : "border-border hover:border-primary/30"
                }`}
                onClick={() => setSelectedId(t.id)}
              >
                <div className="flex items-center justify-between mb-1">
                  <code className="text-xs font-mono text-primary">{t.id}</code>
                  {severityBadge(t.severity)}
                </div>
                <div className="text-sm font-medium">{t.name}</div>
                <div className="flex items-center gap-2 mt-1">
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0">{t.tactic}</Badge>
                  <span className="text-[10px] text-muted-foreground">{t.payloadCount} payloads</span>
                  {t.hasRemediation && (
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 bg-green-500/10 text-green-400 border-green-500/30">
                      <Wrench className="w-2.5 h-2.5 mr-0.5" /> Remediation
                    </Badge>
                  )}
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </div>

      {/* Technique Detail */}
      <div className="lg:col-span-2">
        {!selectedId ? (
          <div className="text-center py-20 text-muted-foreground">
            <BookOpen className="w-10 h-10 mx-auto mb-3 opacity-50" />
            <p>Select a technique to view details</p>
          </div>
        ) : loadingDetail ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
          </div>
        ) : detail ? (
          <TechniqueDetailView detail={detail} remediation={remediation} />
        ) : (
          <div className="text-center py-20 text-muted-foreground">
            <AlertTriangle className="w-10 h-10 mx-auto mb-3 opacity-50" />
            <p>Technique not found</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Technique Detail View ──────────────────────────────────────────────────
function TechniqueDetailView({ detail, remediation }: { detail: any; remediation: any }) {
  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-2">
          <code className="text-sm font-mono text-primary bg-primary/10 px-2 py-1 rounded">{detail.technique.id}</code>
          {severityBadge(detail.technique.severity)}
          <Badge variant="outline" className="text-[10px]">{detail.technique.category}</Badge>
        </div>
        <h2 className="text-xl font-bold">{detail.technique.name}</h2>
        <p className="text-sm text-muted-foreground mt-1">{detail.technique.description}</p>
      </div>

      {/* Key Info */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-primary">{detail.relatedPayloads?.length ?? 0}</div>
            <div className="text-xs text-muted-foreground">PAYLOADS</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-amber-400">{detail.technique.tactic}</div>
            <div className="text-xs text-muted-foreground">TACTIC</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-cyan-400">{detail.historicalResults?.length ?? 0}</div>
            <div className="text-xs text-muted-foreground">HISTORICAL RESULTS</div>
          </CardContent>
        </Card>
      </div>

      {/* Related Payloads */}
      {detail.relatedPayloads && detail.relatedPayloads.length > 0 && (
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Zap className="w-5 h-5 text-red-400" />
              Related Test Payloads
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[250px]">
              <div className="space-y-2">
                {detail.relatedPayloads.map((payload: any, idx: number) => (
                  <div key={idx} className="p-3 bg-muted/30 border border-border rounded-md">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{payload.name}</span>
                      {severityBadge(payload.severity)}
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{payload.description}</p>
                    <div className="p-2 bg-background/50 rounded border border-border">
                      <code className="text-[11px] font-mono text-red-300 break-all">{payload.payload}</code>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Historical Results */}
      {detail.historicalResults && detail.historicalResults.length > 0 && (
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="w-5 h-5 text-cyan-400" />
              Historical Scan Results
            </CardTitle>
            <CardDescription>
              Past scan results for this technique across all targets
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[200px]">
              <div className="space-y-2">
                {detail.historicalResults.map((result: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-muted/30 border border-border rounded-md">
                    <div className="flex items-center gap-2">
                      {result.passed ? (
                        <ShieldCheck className="w-4 h-4 text-green-400" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                      )}
                      <div>
                        <div className="text-sm font-medium">{result.targetName}</div>
                        <div className="text-xs text-muted-foreground">{new Date(result.testedAt).toLocaleString()}</div>
                      </div>
                    </div>
                    <Badge variant="outline" className={result.passed ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-red-500/20 text-red-400 border-red-500/30"}>
                      {result.passed ? "PASSED" : "FAILED"}
                    </Badge>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Remediation Guidance */}
      {remediation && (
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Wrench className="w-5 h-5 text-green-400" />
              Remediation Guidance
            </CardTitle>
            <CardDescription>
              Step-by-step guidance to mitigate this technique
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Overview */}
            <div>
              <h4 className="text-sm font-medium mb-2">Overview</h4>
              <p className="text-sm text-muted-foreground">{remediation.overview}</p>
            </div>

            <Separator />

            {/* Steps */}
            {remediation.steps && remediation.steps.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-3">Implementation Steps</h4>
                <div className="space-y-3">
                  {remediation.steps.map((step: any, idx: number) => (
                    <div key={idx} className="flex gap-3">
                      <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/20 text-primary text-xs font-bold shrink-0 mt-0.5">
                        {idx + 1}
                      </div>
                      <div className="flex-1">
                        <div className="text-sm font-medium">{step.title}</div>
                        <p className="text-xs text-muted-foreground mt-0.5">{step.description}</p>
                        {step.code && (
                          <div className="mt-2 p-2 bg-background/50 rounded border border-border">
                            <code className="text-[11px] font-mono text-muted-foreground whitespace-pre-wrap">{step.code}</code>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <Separator />

            {/* References */}
            {remediation.references && remediation.references.length > 0 && (
              <div>
                <h4 className="text-sm font-medium mb-2">References</h4>
                <div className="space-y-1">
                  {remediation.references.map((ref: any, idx: number) => (
                    <div key={idx} className="flex items-center gap-2 text-xs">
                      <ExternalLink className="w-3 h-3 text-primary shrink-0" />
                      <a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                        {ref.title}
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Difficulty & Effectiveness */}
            <div className="flex items-center gap-6 text-xs text-muted-foreground pt-2">
              {remediation.difficulty && (
                <span>Difficulty: <span className="font-medium text-foreground">{remediation.difficulty}</span></span>
              )}
              {remediation.estimatedEffectiveness && (
                <span>Effectiveness: <span className="font-medium text-green-400">{remediation.estimatedEffectiveness}%</span></span>
              )}
              {remediation.timeToImplement && (
                <span>Time: <span className="font-medium text-foreground">{remediation.timeToImplement}</span></span>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Quick Assessment Tab ────────────────────────────────────────────────────
function QuickAssessmentTab() {
  const [answers, setAnswers] = useState({
    hasInputValidation: false,
    hasOutputFiltering: false,
    hasRateLimiting: false,
    hasModelAccessControls: false,
    hasDataProvenance: false,
    hasDependencyScanning: false,
    hasPromptGuardrails: false,
    hasAuditLogging: false,
    hasAdversarialTesting: false,
    hasIncidentResponse: false,
  });
  const [result, setResult] = useState<any>(null);

  const assess = trpc.aiSecurityValidation.quickAssessment.useMutation({
    onSuccess: (data) => setResult(data),
    onError: (err) => toast.error(err.message),
  });

  const questions: { key: keyof typeof answers; label: string; desc: string }[] = [
    { key: "hasInputValidation", label: "Input Validation", desc: "Do you validate and sanitize all inputs to your AI system?" },
    { key: "hasOutputFiltering", label: "Output Filtering", desc: "Do you filter AI outputs for sensitive data, PII, or harmful content?" },
    { key: "hasRateLimiting", label: "Rate Limiting", desc: "Are rate limits enforced on AI API endpoints?" },
    { key: "hasModelAccessControls", label: "Model Access Controls", desc: "Are model weights and parameters access-controlled?" },
    { key: "hasDataProvenance", label: "Data Provenance", desc: "Do you track the provenance and integrity of training data?" },
    { key: "hasDependencyScanning", label: "Dependency Scanning", desc: "Do you scan ML dependencies (PyTorch, TensorFlow, etc.) for vulnerabilities?" },
    { key: "hasPromptGuardrails", label: "Prompt Guardrails", desc: "Are system prompts protected against injection and extraction?" },
    { key: "hasAuditLogging", label: "Audit Logging", desc: "Are all AI interactions logged for forensic analysis?" },
    { key: "hasAdversarialTesting", label: "Adversarial Testing", desc: "Do you regularly test models against adversarial inputs?" },
    { key: "hasIncidentResponse", label: "Incident Response", desc: "Do you have an AI-specific incident response plan?" },
  ];

  return (
    <div className="space-y-6 max-w-3xl">
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="w-5 h-5 text-green-400" />
            Quick AI Security Posture Assessment
          </CardTitle>
          <CardDescription>
            Answer these 10 questions to get an instant posture score — no live endpoint required.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {questions.map(q => (
            <div key={q.key} className="flex items-center justify-between p-3 bg-muted/30 border border-border rounded-md">
              <div>
                <div className="text-sm font-medium">{q.label}</div>
                <div className="text-xs text-muted-foreground">{q.desc}</div>
              </div>
              <Switch
                checked={answers[q.key]}
                onCheckedChange={v => setAnswers(prev => ({ ...prev, [q.key]: v }))}
              />
            </div>
          ))}

          <Button onClick={() => assess.mutate(answers)} disabled={assess.isPending} className="w-full mt-4">
            {assess.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin mr-2" /> Assessing...</>
            ) : (
              <><ShieldCheck className="w-4 h-4 mr-2" /> Run Assessment</>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card className={`border ${scoreBg(result.overallScore)}`}>
          <CardContent className="p-6">
            <div className="text-center mb-6">
              <div className={`text-5xl font-bold ${scoreColor(result.overallScore)}`}>
                {result.overallScore}%
              </div>
              <div className={`text-lg font-medium ${scoreColor(result.overallScore)} mt-1`}>
                {scoreLabel(result.overallScore)} AI Security Posture
              </div>
            </div>

            <Separator className="my-4" />

            <div className="space-y-2">
              <h4 className="text-sm font-medium mb-2">Recommendations</h4>
              {result.recommendations?.map((rec: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span className="text-muted-foreground">{rec}</span>
                </div>
              ))}
            </div>

            {result.atlasGaps && result.atlasGaps.length > 0 && (
              <>
                <Separator className="my-4" />
                <div className="space-y-2">
                  <h4 className="text-sm font-medium mb-2">ATLAS Coverage Gaps</h4>
                  <div className="flex flex-wrap gap-1">
                    {result.atlasGaps.map((gap: string, i: number) => (
                      <code key={i} className="text-[10px] font-mono text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded">
                        {gap}
                      </code>
                    ))}
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────
export default function AISecurityValidation() {
  const [activeTab, setActiveTab] = useState("overview");
  const [guardrailScanId, setGuardrailScanId] = useState<string | null>(null);
  const [drilldownTechniqueId, setDrilldownTechniqueId] = useState<string | null>(null);

  const handleViewGuardrails = (scanId: string) => {
    setGuardrailScanId(scanId);
    setActiveTab("guardrails");
  };

  const handleTechniqueClick = (techniqueId: string) => {
    setDrilldownTechniqueId(techniqueId);
    setActiveTab("atlas-drilldown");
  };

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <BrainCircuit className="w-7 h-7 text-primary" />
              AI Security Validation
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              MITRE ATLAS-aligned testing for AI/LLM systems — prompt injection, model extraction, adversarial evasion, and more
            </p>
          </div>
          <Badge variant="outline" className="bg-primary/10 text-primary border-primary/30 px-3 py-1">
            MITRE ATLAS v4.0
          </Badge>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/50 flex-wrap h-auto gap-1 p-1">
            <TabsTrigger value="overview" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <Shield className="w-4 h-4 mr-1.5" /> Overview
            </TabsTrigger>
            <TabsTrigger value="new-scan" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <Play className="w-4 h-4 mr-1.5" /> New Scan
            </TabsTrigger>
            <TabsTrigger value="results" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <BarChart3 className="w-4 h-4 mr-1.5" /> Scan Results
            </TabsTrigger>
            <TabsTrigger value="guardrails" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <Lock className="w-4 h-4 mr-1.5" /> Guardrails
            </TabsTrigger>
            <TabsTrigger value="atlas-drilldown" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <BookOpen className="w-4 h-4 mr-1.5" /> ATLAS Drill-Down
            </TabsTrigger>
            <TabsTrigger value="quick-assessment" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
              <ShieldCheck className="w-4 h-4 mr-1.5" /> Quick Assessment
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <OverviewTab onTechniqueClick={handleTechniqueClick} />
          </TabsContent>
          <TabsContent value="new-scan">
            <NewScanTab onScanStarted={(id) => setActiveTab("results")} />
          </TabsContent>
          <TabsContent value="results">
            <ScanResultsTab onViewGuardrails={handleViewGuardrails} />
          </TabsContent>
          <TabsContent value="guardrails">
            <GuardrailRecommenderTab preselectedScanId={guardrailScanId} />
          </TabsContent>
          <TabsContent value="atlas-drilldown">
            <ATLASDrillDownTab preselectedTechniqueId={drilldownTechniqueId} />
          </TabsContent>
          <TabsContent value="quick-assessment">
            <QuickAssessmentTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
