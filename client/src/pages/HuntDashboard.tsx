/**
 * Hunt Dashboard — DHS/GSA HACS-Compliant Threat Hunting Workflow
 * ═══════════════════════════════════════════════════════════════
 * Provides a full UI for the Prepare → Execute → Act hunt state machine.
 * Supports hypothesis-driven, baseline, and model-assisted hunt types.
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Shield,
  Target,
  Brain,
  Play,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Plus,
  ArrowRight,
  FileText,
  AlertTriangle,
  Activity,
  Crosshair,
  Clock,
  BarChart3,
  ChevronDown,
  ChevronRight,
  Copy,
  Loader2,
  Search,
  Zap,
  BookOpen,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

interface HuntSession {
  id: number;
  name: string;
  description: string | null;
  phase: string;
  huntType: string;
  siemPlatform: string | null;
  dataSources: any;
  targetEnvironment: string | null;
  threatActorId: string | null;
  threatActorName: string | null;
  mitreTechniques: any;
  hypothesisCount: number;
  confirmedFindings: number;
  detectionRulesGenerated: number;
  priority: string;
  createdByName: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

interface HuntHypothesis {
  id: number;
  huntSessionId: number;
  statement: string;
  status: string;
  confidence: string;
  mitreTechniqueId: string | null;
  mitreTechniqueName: string | null;
  mitreTactic: string | null;
  requiredDataSources: any;
  sigmaRule: string | null;
  splQuery: string | null;
  kqlQuery: string | null;
  analysisNotes: string | null;
  detectionRule: string | null;
  remediation: string | null;
  attackChainRef: string | null;
  priority: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SIEM_PLATFORMS = [
  { value: "splunk", label: "Splunk" },
  { value: "elastic", label: "Elastic/OpenSearch" },
  { value: "sentinel", label: "Microsoft Sentinel" },
  { value: "qradar", label: "IBM QRadar" },
  { value: "chronicle", label: "Google Chronicle" },
  { value: "other", label: "Other" },
];

const HUNT_TYPES = [
  { value: "hypothesis_driven", label: "Hypothesis-Driven", desc: "Generate and test specific threat hypotheses" },
  { value: "baseline", label: "Baseline", desc: "Establish behavioral baselines and detect anomalies" },
  { value: "model_assisted", label: "Model-Assisted", desc: "LLM-powered pattern recognition across data" },
];

const COMMON_DATA_SOURCES = [
  "Windows Event Logs", "Sysmon", "DNS Logs", "Proxy/Web Logs", "EDR Telemetry",
  "Firewall Logs", "VPN Logs", "Active Directory", "Cloud Audit Logs", "Email Gateway",
  "Network Flow (NetFlow/IPFIX)", "DHCP Logs", "Authentication Logs", "File Integrity Monitoring",
];

const PHASE_COLORS: Record<string, string> = {
  prepare: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  execute: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  act: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  completed: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  pending: <Clock className="h-3.5 w-3.5 text-zinc-400" />,
  investigating: <Search className="h-3.5 w-3.5 text-amber-400" />,
  confirmed: <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />,
  refuted: <XCircle className="h-3.5 w-3.5 text-red-400" />,
  inconclusive: <HelpCircle className="h-3.5 w-3.5 text-zinc-400" />,
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high: "bg-emerald-500/20 text-emerald-400",
  medium: "bg-amber-500/20 text-amber-400",
  low: "bg-red-500/20 text-red-400",
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function HuntDashboard() {
  // toast imported from sonner
  const [activeTab, setActiveTab] = useState("sessions");
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);
  const [showNewHuntForm, setShowNewHuntForm] = useState(false);

  // Queries
  const sessionsQ = trpc.huntEngine.listSessions.useQuery({ limit: 50 });
  const statsQ = trpc.huntEngine.getStats.useQuery();
  const sessionDetailQ = trpc.huntEngine.getSession.useQuery(
    { id: selectedSessionId! },
    { enabled: !!selectedSessionId }
  );

  // Mutations
  const createSessionM = trpc.huntEngine.createSession.useMutation({
    onSuccess: (data) => {
      toast.success(`Hunt Created — Session #${data.id} created in PREPARE phase`);
      sessionsQ.refetch();
      setSelectedSessionId(data.id);
      setShowNewHuntForm(false);
      setActiveTab("detail");
    },
    onError: (err) => toast.error(err.message),
  });

  const generateHypothesesM = trpc.huntEngine.generateHypotheses.useMutation({
    onSuccess: (data) => {
      toast.success(`Hypotheses Generated — ${data.generated} hypotheses created`);
      sessionDetailQ.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const advanceToExecuteM = trpc.huntEngine.advanceToExecute.useMutation({
    onSuccess: () => {
      toast.success("Phase Advanced — Hunt moved to EXECUTE phase");
      sessionDetailQ.refetch();
      sessionsQ.refetch();
    },
  });

  const advanceToActM = trpc.huntEngine.advanceToAct.useMutation({
    onSuccess: () => {
      toast.success("Phase Advanced — Hunt moved to ACT phase");
      sessionDetailQ.refetch();
      sessionsQ.refetch();
    },
  });

  const generateDeliverableM = trpc.huntEngine.generateDeliverable.useMutation({
    onSuccess: (data) => {
      toast.success(`Deliverable Generated — Report ready with ${data.findings.length} findings`);
      sessionDetailQ.refetch();
      sessionsQ.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const cancelSessionM = trpc.huntEngine.cancelSession.useMutation({
    onSuccess: () => {
      toast.success("Hunt Cancelled");
      sessionDetailQ.refetch();
      sessionsQ.refetch();
    },
  });

  const translateSigmaM = trpc.huntEngine.translateSigma.useMutation();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            Threat Hunt Operations
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            DHS/GSA HACS-compliant threat hunting — Prepare → Execute → Act
          </p>
        </div>
        <Button onClick={() => { setShowNewHuntForm(true); setActiveTab("new"); }} size="sm" className="gap-1.5">
          <Plus className="h-4 w-4" /> New Hunt
        </Button>
      </div>

      {/* Stats Row */}
      {statsQ.data && (
        <div className="grid grid-cols-5 gap-3">
          <StatCard label="Total Hunts" value={statsQ.data.totalHunts} icon={<Target className="h-4 w-4" />} />
          <StatCard label="Active" value={statsQ.data.activeHunts} icon={<Activity className="h-4 w-4 text-amber-400" />} />
          <StatCard label="Completed" value={statsQ.data.completedHunts} icon={<CheckCircle2 className="h-4 w-4 text-emerald-400" />} />
          <StatCard label="Findings" value={statsQ.data.totalFindings} icon={<AlertTriangle className="h-4 w-4 text-red-400" />} />
          <StatCard label="Detection Rules" value={statsQ.data.totalDetectionRules} icon={<Shield className="h-4 w-4 text-blue-400" />} />
        </div>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="sessions">Hunt Sessions</TabsTrigger>
          <TabsTrigger value="detail" disabled={!selectedSessionId}>Session Detail</TabsTrigger>
          {showNewHuntForm && <TabsTrigger value="new">New Hunt</TabsTrigger>}
        </TabsList>

        {/* Sessions List */}
        <TabsContent value="sessions" className="space-y-3">
          {sessionsQ.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (sessionsQ.data?.length || 0) === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="flex flex-col items-center justify-center py-12 gap-3">
                <Shield className="h-12 w-12 text-muted-foreground/30" />
                <p className="text-muted-foreground">No hunt sessions yet. Create your first hunt.</p>
                <Button onClick={() => { setShowNewHuntForm(true); setActiveTab("new"); }} size="sm" variant="outline">
                  <Plus className="h-4 w-4 mr-1" /> New Hunt
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {sessionsQ.data?.map((s: any) => (
                <Card
                  key={s.id}
                  className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 cursor-pointer transition-colors"
                  onClick={() => { setSelectedSessionId(s.id); setActiveTab("detail"); }}
                >
                  <CardContent className="py-3 px-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className={PHASE_COLORS[s.phase] || ""}>
                          {s.phase?.toUpperCase()}
                        </Badge>
                        <div>
                          <p className="font-medium text-sm">{s.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {s.huntType?.replace(/_/g, " ")} · {s.siemPlatform || "N/A"} · Priority: {s.priority}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>{s.hypothesisCount} hypotheses</span>
                        <span>{s.confirmedFindings} findings</span>
                        <span>{s.detectionRulesGenerated} rules</span>
                        <span>{new Date(s.createdAt).toLocaleDateString()}</span>
                        <ArrowRight className="h-4 w-4" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* New Hunt Form */}
        <TabsContent value="new">
          <NewHuntForm
            onSubmit={(data) => createSessionM.mutate(data)}
            isLoading={createSessionM.isPending}
            onCancel={() => { setShowNewHuntForm(false); setActiveTab("sessions"); }}
          />
        </TabsContent>

        {/* Session Detail */}
        <TabsContent value="detail">
          {selectedSessionId && sessionDetailQ.data && (
            <SessionDetail
              session={sessionDetailQ.data as any}
              onGenerateHypotheses={(params) => generateHypothesesM.mutate(params)}
              onAdvanceToExecute={() => advanceToExecuteM.mutate({ sessionId: selectedSessionId })}
              onAdvanceToAct={() => advanceToActM.mutate({ sessionId: selectedSessionId })}
              onGenerateDeliverable={(params) => generateDeliverableM.mutate(params)}
              onCancel={() => cancelSessionM.mutate({ sessionId: selectedSessionId })}
              onTranslateSigma={(rule, platform) => translateSigmaM.mutateAsync({ sigmaRule: rule, targetPlatform: platform })}
              isGeneratingHypotheses={generateHypothesesM.isPending}
              isGeneratingDeliverable={generateDeliverableM.isPending}
              deliverable={generateDeliverableM.data || null}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardContent className="py-3 px-4 flex items-center justify-between">
        <div>
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className="text-xl font-bold">{value}</p>
        </div>
        {icon}
      </CardContent>
    </Card>
  );
}

// ─── New Hunt Form ────────────────────────────────────────────────────────────

function NewHuntForm({
  onSubmit,
  isLoading,
  onCancel,
}: {
  onSubmit: (data: any) => void;
  isLoading: boolean;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [huntType, setHuntType] = useState("hypothesis_driven");
  const [siemPlatform, setSiemPlatform] = useState("splunk");
  const [dataSources, setDataSources] = useState<string[]>([]);
  const [targetEnv, setTargetEnv] = useState("");
  const [threatActorName, setThreatActorName] = useState("");
  const [priority, setPriority] = useState("medium");
  const [techniques, setTechniques] = useState("");

  const parsedTechniques = useMemo(() => {
    if (!techniques.trim()) return [];
    return techniques.split("\n").filter(Boolean).map(line => {
      const match = line.match(/^(T\d{4}(?:\.\d{3})?)\s*[-:]\s*(.+?)(?:\s*\((.+?)\))?$/);
      if (match) return { id: match[1], name: match[2].trim(), tactic: match[3]?.trim() || "unknown" };
      return { id: line.trim(), name: line.trim(), tactic: "unknown" };
    });
  }, [techniques]);

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Plus className="h-5 w-5" /> Create New Hunt Session
        </CardTitle>
        <CardDescription>Define the scope, targets, and methodology for your threat hunt.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {/* Hunt Name & Description */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Hunt Name *</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g., APT29 Persistence Hunt" className="bg-zinc-800/50" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Priority</label>
            <div className="flex gap-2">
              {["critical", "high", "medium", "low"].map(p => (
                <Button key={p} size="sm" variant={priority === p ? "default" : "outline"} onClick={() => setPriority(p)} className="text-xs capitalize">
                  {p}
                </Button>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">Description</label>
          <Textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="Hunt objective and scope..." rows={2} className="bg-zinc-800/50" />
        </div>

        {/* Hunt Type */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">Hunt Type (PEAK Framework)</label>
          <div className="grid grid-cols-3 gap-3">
            {HUNT_TYPES.map(ht => (
              <Card
                key={ht.value}
                className={`cursor-pointer transition-colors border ${huntType === ht.value ? "border-primary bg-primary/5" : "border-zinc-800 bg-zinc-900/30 hover:border-zinc-700"}`}
                onClick={() => setHuntType(ht.value)}
              >
                <CardContent className="py-3 px-3">
                  <p className="text-sm font-medium">{ht.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{ht.desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>

        {/* SIEM & Data Sources */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">SIEM Platform</label>
            <div className="flex flex-wrap gap-1.5">
              {SIEM_PLATFORMS.map(sp => (
                <Button key={sp.value} size="sm" variant={siemPlatform === sp.value ? "default" : "outline"} onClick={() => setSiemPlatform(sp.value)} className="text-xs">
                  {sp.label}
                </Button>
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Target Environment</label>
            <Input value={targetEnv} onChange={e => setTargetEnv(e.target.value)} placeholder="e.g., Corporate Windows domain" className="bg-zinc-800/50" />
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground">Available Data Sources</label>
          <div className="flex flex-wrap gap-1.5">
            {COMMON_DATA_SOURCES.map(ds => (
              <Button
                key={ds}
                size="sm"
                variant={dataSources.includes(ds) ? "default" : "outline"}
                onClick={() => setDataSources(prev => prev.includes(ds) ? prev.filter(d => d !== ds) : [...prev, ds])}
                className="text-xs"
              >
                {ds}
              </Button>
            ))}
          </div>
        </div>

        {/* Threat Actor & Techniques */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Threat Actor (optional)</label>
            <Input value={threatActorName} onChange={e => setThreatActorName(e.target.value)} placeholder="e.g., APT29 / Cozy Bear" className="bg-zinc-800/50" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">MITRE Techniques (one per line: T1059.001 - PowerShell (execution))</label>
            <Textarea value={techniques} onChange={e => setTechniques(e.target.value)} placeholder="T1059.001 - PowerShell (execution)&#10;T1053.005 - Scheduled Task (persistence)" rows={3} className="bg-zinc-800/50 text-xs font-mono" />
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onCancel}>Cancel</Button>
          <Button
            onClick={() => onSubmit({
              name,
              description: description || undefined,
              huntType,
              siemPlatform,
              dataSources,
              targetEnvironment: targetEnv || undefined,
              threatActorName: threatActorName || undefined,
              mitreTechniques: parsedTechniques.length > 0 ? parsedTechniques : undefined,
              priority,
            })}
            disabled={!name.trim() || isLoading}
          >
            {isLoading ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Plus className="h-4 w-4 mr-1" />}
            Create Hunt Session
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Session Detail ───────────────────────────────────────────────────────────

function SessionDetail({
  session,
  onGenerateHypotheses,
  onAdvanceToExecute,
  onAdvanceToAct,
  onGenerateDeliverable,
  onCancel,
  onTranslateSigma,
  isGeneratingHypotheses,
  isGeneratingDeliverable,
  deliverable,
}: {
  session: any;
  onGenerateHypotheses: (params: any) => void;
  onAdvanceToExecute: () => void;
  onAdvanceToAct: () => void;
  onGenerateDeliverable: (params: any) => void;
  onCancel: () => void;
  onTranslateSigma: (rule: string, platform: any) => Promise<any>;
  isGeneratingHypotheses: boolean;
  isGeneratingDeliverable: boolean;
  deliverable: any;
}) {
  const [detailTab, setDetailTab] = useState("overview");
  const [orgName, setOrgName] = useState("");
  const [orgSector, setOrgSector] = useState("technology");

  const hypotheses: HuntHypothesis[] = session.hypotheses || [];
  const phaseIndex = ["prepare", "execute", "act", "completed"].indexOf(session.phase);

  return (
    <div className="space-y-4">
      {/* Session Header */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardContent className="py-4 px-5">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Badge variant="outline" className={PHASE_COLORS[session.phase] || ""}>
                  {session.phase?.toUpperCase()}
                </Badge>
                <h2 className="text-lg font-bold">{session.name}</h2>
              </div>
              <p className="text-xs text-muted-foreground">
                {session.huntType?.replace(/_/g, " ")} · {session.siemPlatform || "N/A"} · Priority: {session.priority}
                {session.threatActorName && ` · Threat Actor: ${session.threatActorName}`}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {session.phase !== "completed" && session.phase !== "cancelled" && (
                <Button size="sm" variant="outline" className="text-red-400 border-red-500/30 hover:bg-red-500/10" onClick={onCancel}>
                  Cancel Hunt
                </Button>
              )}
            </div>
          </div>

          {/* Phase Progress */}
          <div className="flex items-center gap-1 mt-4">
            {["PREPARE", "EXECUTE", "ACT", "COMPLETE"].map((phase, i) => (
              <div key={phase} className="flex items-center gap-1 flex-1">
                <div className={`h-1.5 flex-1 rounded-full ${i <= phaseIndex ? "bg-primary" : "bg-zinc-800"}`} />
                <span className={`text-[10px] font-medium ${i <= phaseIndex ? "text-primary" : "text-muted-foreground"}`}>
                  {phase}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Detail Tabs */}
      <Tabs value={detailTab} onValueChange={setDetailTab}>
        <TabsList className="bg-zinc-900/50 border border-zinc-800">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="hypotheses">Hypotheses ({hypotheses.length})</TabsTrigger>
          <TabsTrigger value="queries">SIEM Queries</TabsTrigger>
          {deliverable && <TabsTrigger value="deliverable">Deliverable</TabsTrigger>}
        </TabsList>

        {/* Overview */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            {/* Phase Actions */}
            <Card className="bg-zinc-900/50 border-zinc-800 col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Phase Actions</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {session.phase === "prepare" && (
                  <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                      Generate hypotheses using LLM + training bundles (300 attack chains, asset ontology, bug bounty patterns).
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-muted-foreground">Organization Name *</label>
                        <Input value={orgName} onChange={e => setOrgName(e.target.value)} placeholder="e.g., Acme Corp" className="bg-zinc-800/50" />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-muted-foreground">Sector *</label>
                        <Input value={orgSector} onChange={e => setOrgSector(e.target.value)} placeholder="e.g., healthcare" className="bg-zinc-800/50" />
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        onClick={() => onGenerateHypotheses({
                          sessionId: session.id,
                          orgName: orgName || "Target Organization",
                          orgSector: orgSector || "technology",
                        })}
                        disabled={isGeneratingHypotheses}
                      >
                        {isGeneratingHypotheses ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Brain className="h-4 w-4 mr-1" />}
                        Generate Hypotheses
                      </Button>
                      {hypotheses.length > 0 && (
                        <Button size="sm" variant="outline" onClick={onAdvanceToExecute}>
                          <ArrowRight className="h-4 w-4 mr-1" /> Advance to EXECUTE
                        </Button>
                      )}
                    </div>
                  </div>
                )}

                {session.phase === "execute" && (
                  <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                      Run SIEM queries against each hypothesis. Submit evidence for LLM evaluation.
                      When all hypotheses are evaluated, advance to ACT phase.
                    </p>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={onAdvanceToAct}>
                        <ArrowRight className="h-4 w-4 mr-1" /> Advance to ACT
                      </Button>
                    </div>
                  </div>
                )}

                {session.phase === "act" && (
                  <div className="space-y-3">
                    <p className="text-xs text-muted-foreground">
                      Generate the GSA HACS-compliant hunt deliverable with findings, detection rules, and recommendations.
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-muted-foreground">Organization Name</label>
                        <Input value={orgName} onChange={e => setOrgName(e.target.value)} placeholder="e.g., Acme Corp" className="bg-zinc-800/50" />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs font-medium text-muted-foreground">Sector</label>
                        <Input value={orgSector} onChange={e => setOrgSector(e.target.value)} placeholder="e.g., healthcare" className="bg-zinc-800/50" />
                      </div>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => onGenerateDeliverable({
                        sessionId: session.id,
                        orgName: orgName || "Target Organization",
                        orgSector: orgSector || "technology",
                      })}
                      disabled={isGeneratingDeliverable}
                    >
                      {isGeneratingDeliverable ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <FileText className="h-4 w-4 mr-1" />}
                      Generate Deliverable
                    </Button>
                  </div>
                )}

                {session.phase === "completed" && (
                  <div className="flex items-center gap-2 text-emerald-400">
                    <CheckCircle2 className="h-5 w-5" />
                    <span className="text-sm font-medium">Hunt completed</span>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Session Stats */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Hunt Stats</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Hypotheses</span>
                  <span className="font-medium">{session.hypothesisCount}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Confirmed</span>
                  <span className="font-medium text-emerald-400">{session.confirmedFindings}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Detection Rules</span>
                  <span className="font-medium text-blue-400">{session.detectionRulesGenerated}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Data Sources</span>
                  <span className="font-medium">{(session.dataSources as any[])?.length || 0}</span>
                </div>
                {session.threatActorName && (
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Threat Actor</span>
                    <span className="font-medium text-red-400">{session.threatActorName}</span>
                  </div>
                )}
                {session.startedAt && (
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Started</span>
                    <span className="font-medium">{new Date(session.startedAt).toLocaleString()}</span>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Hypotheses */}
        <TabsContent value="hypotheses" className="space-y-3">
          {hypotheses.length === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="flex flex-col items-center justify-center py-8 gap-2">
                <Brain className="h-10 w-10 text-muted-foreground/30" />
                <p className="text-sm text-muted-foreground">No hypotheses generated yet.</p>
              </CardContent>
            </Card>
          ) : (
            hypotheses.map((h: HuntHypothesis) => (
              <HypothesisCard
                key={h.id}
                hypothesis={h}
                siemPlatform={session.siemPlatform || "splunk"}
                onTranslateSigma={onTranslateSigma}
              />
            ))
          )}
        </TabsContent>

        {/* SIEM Queries */}
        <TabsContent value="queries" className="space-y-3">
          {hypotheses.filter((h: HuntHypothesis) => h.sigmaRule || h.splQuery || h.kqlQuery).length === 0 ? (
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="flex flex-col items-center justify-center py-8 gap-2">
                <Search className="h-10 w-10 text-muted-foreground/30" />
                <p className="text-sm text-muted-foreground">No queries generated yet. Generate hypotheses first.</p>
              </CardContent>
            </Card>
          ) : (
            hypotheses.filter((h: HuntHypothesis) => h.sigmaRule || h.splQuery || h.kqlQuery).map((h: HuntHypothesis) => (
              <QueryCard key={h.id} hypothesis={h} />
            ))
          )}
        </TabsContent>

        {/* Deliverable */}
        {deliverable && (
          <TabsContent value="deliverable">
            <DeliverableView deliverable={deliverable} />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

// ─── Hypothesis Card ──────────────────────────────────────────────────────────

function HypothesisCard({
  hypothesis,
  siemPlatform,
  onTranslateSigma,
}: {
  hypothesis: HuntHypothesis;
  siemPlatform: string;
  onTranslateSigma: (rule: string, platform: any) => Promise<any>;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardContent className="py-3 px-4">
        <div className="flex items-start gap-3">
          <div className="mt-0.5">{STATUS_ICONS[hypothesis.status] || STATUS_ICONS.pending}</div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Badge variant="outline" className={CONFIDENCE_COLORS[hypothesis.confidence] || ""}>
                {hypothesis.confidence}
              </Badge>
              {hypothesis.mitreTechniqueId && (
                <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30 text-[10px]">
                  {hypothesis.mitreTechniqueId}
                </Badge>
              )}
              {hypothesis.mitreTactic && (
                <Badge variant="outline" className="text-[10px]">
                  {hypothesis.mitreTactic}
                </Badge>
              )}
              {hypothesis.attackChainRef && (
                <Badge variant="outline" className="bg-purple-500/10 text-purple-400 border-purple-500/30 text-[10px]">
                  Chain: {hypothesis.attackChainRef}
                </Badge>
              )}
              <span className="text-[10px] text-muted-foreground ml-auto">Priority #{hypothesis.priority}</span>
            </div>
            <p className="text-sm">{hypothesis.statement}</p>

            {/* Expandable Details */}
            <button
              onClick={() => setExpanded(!expanded)}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground mt-2 transition-colors"
            >
              {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              Details
            </button>

            {expanded && (
              <div className="mt-2 space-y-2 text-xs">
                {hypothesis.mitreTechniqueName && (
                  <div>
                    <span className="text-muted-foreground">Technique: </span>
                    <span>{hypothesis.mitreTechniqueId} — {hypothesis.mitreTechniqueName}</span>
                  </div>
                )}
                {(hypothesis.requiredDataSources as any[])?.length > 0 && (
                  <div>
                    <span className="text-muted-foreground">Required Data Sources: </span>
                    <span>{(hypothesis.requiredDataSources as string[]).join(", ")}</span>
                  </div>
                )}
                {hypothesis.analysisNotes && (
                  <div className="bg-zinc-800/50 rounded p-2 mt-1">
                    <span className="text-muted-foreground block mb-1">Analysis Notes:</span>
                    <span className="whitespace-pre-wrap">{hypothesis.analysisNotes}</span>
                  </div>
                )}
                {hypothesis.detectionRule && (
                  <div className="bg-zinc-800/50 rounded p-2 mt-1">
                    <span className="text-muted-foreground block mb-1">Detection Rule:</span>
                    <pre className="text-[10px] font-mono whitespace-pre-wrap">{hypothesis.detectionRule}</pre>
                  </div>
                )}
                {hypothesis.remediation && (
                  <div className="bg-zinc-800/50 rounded p-2 mt-1">
                    <span className="text-muted-foreground block mb-1">Remediation:</span>
                    <span className="whitespace-pre-wrap">{hypothesis.remediation}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Query Card ───────────────────────────────────────────────────────────────

function QueryCard({ hypothesis }: { hypothesis: HuntHypothesis }) {
  // toast imported from sonner
  const [showSigma, setShowSigma] = useState(false);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardContent className="py-3 px-4 space-y-2">
        <div className="flex items-center gap-2">
          <Search className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium">{hypothesis.mitreTechniqueId} — {hypothesis.mitreTechniqueName}</span>
        </div>
        <p className="text-xs text-muted-foreground">{hypothesis.statement}</p>

        {hypothesis.splQuery && (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-medium text-amber-400">SPL (Splunk)</span>
              <Button size="sm" variant="ghost" className="h-5 px-1" onClick={() => copyToClipboard(hypothesis.splQuery!, "SPL query")}>
                <Copy className="h-3 w-3" />
              </Button>
            </div>
            <pre className="bg-zinc-800/50 rounded p-2 text-[10px] font-mono whitespace-pre-wrap overflow-x-auto">{hypothesis.splQuery}</pre>
          </div>
        )}

        {hypothesis.kqlQuery && (
          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-medium text-blue-400">KQL (Sentinel/Elastic)</span>
              <Button size="sm" variant="ghost" className="h-5 px-1" onClick={() => copyToClipboard(hypothesis.kqlQuery!, "KQL query")}>
                <Copy className="h-3 w-3" />
              </Button>
            </div>
            <pre className="bg-zinc-800/50 rounded p-2 text-[10px] font-mono whitespace-pre-wrap overflow-x-auto">{hypothesis.kqlQuery}</pre>
          </div>
        )}

        {hypothesis.sigmaRule && (
          <div className="space-y-1">
            <button onClick={() => setShowSigma(!showSigma)} className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground">
              {showSigma ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              Sigma Rule
            </button>
            {showSigma && (
              <div className="relative">
                <Button size="sm" variant="ghost" className="absolute top-1 right-1 h-5 px-1" onClick={() => copyToClipboard(hypothesis.sigmaRule!, "Sigma rule")}>
                  <Copy className="h-3 w-3" />
                </Button>
                <pre className="bg-zinc-800/50 rounded p-2 text-[10px] font-mono whitespace-pre-wrap overflow-x-auto">{hypothesis.sigmaRule}</pre>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Deliverable View ─────────────────────────────────────────────────────────

function DeliverableView({ deliverable }: { deliverable: any }) {
  return (
    <div className="space-y-4">
      {/* Executive Summary */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <FileText className="h-4 w-4" /> Executive Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm whitespace-pre-wrap">{deliverable.executiveSummary}</p>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <StatCard label="Hypotheses Tested" value={deliverable.hypothesesTested} icon={<Brain className="h-4 w-4" />} />
        <StatCard label="Confirmed" value={deliverable.hypothesesConfirmed} icon={<CheckCircle2 className="h-4 w-4 text-emerald-400" />} />
        <StatCard label="Refuted" value={deliverable.hypothesesRefuted} icon={<XCircle className="h-4 w-4 text-red-400" />} />
        <StatCard label="Inconclusive" value={deliverable.hypothesesInconclusive} icon={<HelpCircle className="h-4 w-4 text-zinc-400" />} />
      </div>

      {/* Findings */}
      {deliverable.findings?.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" /> Findings ({deliverable.findings.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {deliverable.findings.map((f: any, i: number) => (
              <div key={i} className="bg-zinc-800/50 rounded p-3 space-y-1">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={
                    f.severity === "critical" ? "bg-red-500/20 text-red-400" :
                    f.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                    f.severity === "medium" ? "bg-amber-500/20 text-amber-400" :
                    "bg-zinc-500/20 text-zinc-400"
                  }>
                    {f.severity}
                  </Badge>
                  <span className="text-sm font-medium">{f.title}</span>
                  {f.mitreTechniqueId && (
                    <Badge variant="outline" className="text-[10px] bg-blue-500/10 text-blue-400">
                      {f.mitreTechniqueId}
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground">{f.description}</p>
                {f.remediation && (
                  <p className="text-xs"><span className="text-muted-foreground">Remediation: </span>{f.remediation}</p>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Detection Rules */}
      {deliverable.detectionRules?.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" /> Detection Rules ({deliverable.detectionRules.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {deliverable.detectionRules.map((r: any, i: number) => (
              <div key={i} className="bg-zinc-800/50 rounded p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-medium">{r.name}</span>
                  <Badge variant="outline" className="text-[10px]">{r.format}</Badge>
                  <Badge variant="outline" className="text-[10px] bg-blue-500/10 text-blue-400">{r.mitreTechniqueId}</Badge>
                </div>
                <pre className="text-[10px] font-mono whitespace-pre-wrap">{r.content}</pre>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Recommendations */}
      {deliverable.recommendations?.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" /> Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="list-decimal list-inside space-y-1">
              {deliverable.recommendations.map((r: string, i: number) => (
                <li key={i} className="text-xs">{r}</li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {/* Data Source Gaps */}
      {deliverable.dataSourceGaps?.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" /> Data Source Gaps
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1">
              {deliverable.dataSourceGaps.map((g: string, i: number) => (
                <li key={i} className="text-xs flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-amber-400" />
                  {g}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}

      {/* HACS Compliance Notes */}
      {deliverable.hacsComplianceNotes?.length > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-emerald-400" /> GSA HACS Compliance Notes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1">
              {deliverable.hacsComplianceNotes.map((n: string, i: number) => (
                <li key={i} className="text-xs flex items-center gap-1.5">
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  {n}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
