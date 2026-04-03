/**
 * Training & Test Lab — Self-Learning Pentest Validation
 *
 * Operators can run quick scans against known vulnerable training sites,
 * review LLM analysis results, provide feedback to improve accuracy,
 * and track the LLM's learning progress over time.
 */
import { useState, useMemo, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import ContinuousTraining from "@/components/ContinuousTraining";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  FlaskConical,
  Play,
  Target,
  Brain,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle2,
  XCircle,
  AlertCircle,
  AlertTriangle,
  Loader2,
  RefreshCw,
  ThumbsUp,
  ThumbsDown,
  MessageSquarePlus,
  BarChart3,
  Shield,
  Bug,
  Crosshair,
  Clock,
  Zap,
  Eye,
  ChevronDown,
  ChevronUp,
  Plus,
  Activity,
  Sparkles,
  GraduationCap,
  Search,
  Globe,
  Server,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Ban,
  ExternalLink,
  Gauge,
  Lock,
  Repeat,
} from "lucide-react";
import { toast } from "sonner";

// ─── Types ────────────────────────────────────────────────────────────────

interface TrainingTargetRoE {
  provider: string;
  termsUrl: string | null;
  summary: string;
  allowed: string[];
  prohibited: string[];
  rateLimit: string | null;
  requiresOwnInstance: boolean;
  noBruteForce: boolean;
  noDoS: boolean;
  noExfiltration: boolean;
  maxScansPerDay: number | null;
  notes: string | null;
}

interface TrainingTarget {
  id: string;
  name: string;
  url: string;
  description: string;
  difficulty: string;
  category: string;
  knownVulns: string[];
  owaspCategories: string[];
  tags: string[];
  roe: TrainingTargetRoE;
}

interface SessionListItem {
  sessionId: string;
  name: string;
  targetUrl: string;
  targetPreset: string;
  scanProfile: string;
  status: string;
  phase: string;
  progress: number;
  stats: any;
  startedAt: number | null;
  completedAt: number | null;
  durationMs: number | null;
  createdAt: number;
}

// ─── Constants ────────────────────────────────────────────────────────────

const DIFFICULTY_COLORS: Record<string, string> = {
  beginner: "bg-green-500/20 text-green-400 border-green-500/30",
  intermediate: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  advanced: "bg-red-500/20 text-red-400 border-red-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  completed: "bg-green-500/20 text-green-400",
  scanning: "bg-blue-500/20 text-blue-400",
  analyzing: "bg-purple-500/20 text-purple-400",
  queued: "bg-muted text-muted-foreground",
  failed: "bg-red-500/20 text-red-400",
  cancelled: "bg-muted text-muted-foreground",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-muted text-muted-foreground border-border",
  informational: "bg-muted text-muted-foreground border-border",
};

const FEEDBACK_LABELS: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  correct: { label: "Correct", color: "text-green-400", icon: <ThumbsUp className="w-3 h-3" /> },
  incorrect: { label: "Incorrect", color: "text-red-400", icon: <ThumbsDown className="w-3 h-3" /> },
  partial: { label: "Partial", color: "text-amber-400", icon: <AlertCircle className="w-3 h-3" /> },
  missed_finding: { label: "Missed", color: "text-purple-400", icon: <Plus className="w-3 h-3" /> },
  false_positive: { label: "False Positive", color: "text-red-400", icon: <XCircle className="w-3 h-3" /> },
};

// ─── Component ────────────────────────────────────────────────────────────

export default function TrainingLab() {
  const [activeTab, setActiveTab] = useState("launcher");
  const [selectedTarget, setSelectedTarget] = useState<string>("");
  const [customUrl, setCustomUrl] = useState("");
  const [scanProfile, setScanProfile] = useState<string>("standard");
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [targetSearch, setTargetSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [difficultyFilter, setDifficultyFilter] = useState<string>("all");
  const [showRoEModal, setShowRoEModal] = useState(false);
  const [pendingScanConfig, setPendingScanConfig] = useState<{ targetId?: string; customUrl?: string; scanProfile: string } | null>(null);

  // Data queries
  const { data: targets } = trpc.trainingLab.targets.useQuery();
  const { data: sessions, refetch: refetchSessions } = trpc.trainingLab.listSessions.useQuery();
  const { data: learningStats } = trpc.trainingLab.learningStats.useQuery();
  const { data: accuracyTrend } = trpc.trainingLab.accuracyTrend.useQuery();
  const { data: groundTruthTargets } = trpc.trainingLab.groundTruthTargets.useQuery();

  // Active session polling
  const { data: activeSession, refetch: refetchSession } = trpc.trainingLab.getSession.useQuery(
    { sessionId: activeSessionId! },
    { enabled: !!activeSessionId, refetchInterval: activeSessionId ? 3000 : false }
  );

  // Mutations
  const startSession = trpc.trainingLab.startSession.useMutation({
    onSuccess: (data) => {
      setActiveSessionId(data.sessionId);
      setActiveTab("session");
      toast.success(`Training session started: ${data.name}`);
      refetchSessions();
    },
    onError: (err) => toast.error(`Failed to start session: ${err.message}`),
  });

  const rerunAnalysis = trpc.trainingLab.rerunAnalysis.useMutation({
    onSuccess: () => {
      toast.success("LLM re-analysis started with learning context");
      refetchSession();
    },
    onError: (err) => toast.error(`Re-analysis failed: ${err.message}`),
  });

  // Stop polling when session completes
  useEffect(() => {
    if (activeSession && !activeSession.isRunning && activeSession.phase === "completed") {
      refetchSessions();
    }
  }, [activeSession?.isRunning, activeSession?.phase]);

  // Find the selected target object for RoE checks
  const selectedTargetObj = useMemo(() => {
    if (!selectedTarget || selectedTarget === "custom") return null;
    return targets?.find(t => t.id === selectedTarget) || null;
  }, [selectedTarget, targets]);

  const acknowledgeRoE = trpc.trainingLab.acknowledgeRoE.useMutation({
    onError: (err) => toast.error(`RoE acknowledgment failed: ${err.message}`),
  });

  function handleStartScan() {
    if (!selectedTarget && !customUrl) {
      toast.error("Select a target or enter a custom URL");
      return;
    }

    const config = {
      targetId: selectedTarget || undefined,
      customUrl: selectedTarget === "custom" || !selectedTarget ? customUrl || undefined : undefined,
      scanProfile: scanProfile,
    };

    // Check if the target has restrictions that require acknowledgment
    const target = selectedTargetObj;
    if (target && target.roe) {
      const hasRestrictions = target.roe.noBruteForce || target.roe.noDoS || target.roe.noExfiltration ||
        target.roe.requiresOwnInstance || target.roe.maxScansPerDay !== null || target.roe.prohibited.length > 0;
      if (hasRestrictions) {
        setPendingScanConfig(config);
        setShowRoEModal(true);
        return;
      }
    }

    // Custom target always requires acknowledgment
    if (selectedTarget === "custom" || !selectedTarget) {
      setPendingScanConfig(config);
      setShowRoEModal(true);
      return;
    }

    // Unrestricted target — launch directly
    startSession.mutate({
      targetId: config.targetId,
      customUrl: config.customUrl,
      scanProfile: config.scanProfile as any,
    });
  }

  function handleRoEAccepted() {
    if (!pendingScanConfig) return;

    // Log the acknowledgment
    const target = selectedTargetObj;
    acknowledgeRoE.mutate({
      targetId: pendingScanConfig.targetId || "custom",
      scanProfile: pendingScanConfig.scanProfile,
    });

    // Launch the scan
    startSession.mutate({
      targetId: pendingScanConfig.targetId,
      customUrl: pendingScanConfig.customUrl,
      scanProfile: pendingScanConfig.scanProfile as any,
    });

    setShowRoEModal(false);
    setPendingScanConfig(null);
  }

  function handleRoERejected() {
    setShowRoEModal(false);
    setPendingScanConfig(null);
    toast.info("Scan cancelled — RoE not accepted.");
  }

  function handleViewSession(sessionId: string) {
    setActiveSessionId(sessionId);
    setActiveTab("session");
  }

  return (
    <AppShell>
      <div className="min-h-screen bg-background">
        <div className="container max-w-[1600px] py-6 space-y-6">
          {/* Header */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <FlaskConical className="w-7 h-7 text-primary" />
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Training & Test Lab
              </h1>
              <Badge variant="outline" className="text-xs border-primary/30 text-primary">
                Self-Learning
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground max-w-3xl">
              Test the platform's LLM-driven pentest capabilities against known vulnerable
              training sites. The AI learns from operator feedback — rate findings, correct
              mistakes, and watch accuracy improve over time.
            </p>
          </div>

          {/* Quick Stats Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <QuickStat
              label="Total Sessions"
              value={sessions?.length || 0}
              icon={<FlaskConical className="w-4 h-4" />}
            />
            <QuickStat
              label="Feedback Entries"
              value={learningStats?.totalFeedbackEntries || 0}
              icon={<MessageSquarePlus className="w-4 h-4" />}
            />
            <QuickStat
              label="Correct Findings"
              value={learningStats?.correctCount || 0}
              icon={<ThumbsUp className="w-4 h-4 text-green-400" />}
            />
            <QuickStat
              label="Corrections Made"
              value={(learningStats?.incorrectCount || 0) + (learningStats?.missedCount || 0)}
              icon={<ThumbsDown className="w-4 h-4 text-red-400" />}
            />
            <QuickStat
              label="Targets Trained"
              value={learningStats?.uniqueTargets || 0}
              icon={<Target className="w-4 h-4 text-amber-400" />}
            />
            <QuickStat
              label="Avg F1 Score"
              value={
                learningStats?.accuracyStats?.length
                  ? `${(learningStats.accuracyStats.reduce((s: number, a: any) => s + (a.avgF1 || 0), 0) / learningStats.accuracyStats.length * 100).toFixed(0)}%`
                  : "N/A"
              }
              icon={<Brain className="w-4 h-4 text-purple-400" />}
            />
          </div>

          {/* Main Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="bg-card border border-border">
              <TabsTrigger value="launcher" className="gap-1.5">
                <Play className="w-3.5 h-3.5" /> Launch Scan
              </TabsTrigger>
              <TabsTrigger value="session" className="gap-1.5" disabled={!activeSessionId}>
                <Crosshair className="w-3.5 h-3.5" /> Active Session
              </TabsTrigger>
              <TabsTrigger value="history" className="gap-1.5">
                <Clock className="w-3.5 h-3.5" /> Session History
              </TabsTrigger>
              <TabsTrigger value="learning" className="gap-1.5">
                <GraduationCap className="w-3.5 h-3.5" /> Learning Dashboard
              </TabsTrigger>
              <TabsTrigger value="continuous" className="gap-1.5">
                <Repeat className="w-3.5 h-3.5" /> Continuous Training
              </TabsTrigger>
              <TabsTrigger value="roe" className="gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" /> Rules of Engagement
              </TabsTrigger>
            </TabsList>

            {/* ─── LAUNCHER TAB ─── */}
            <TabsContent value="launcher" className="space-y-6 mt-4">
              <div className="grid lg:grid-cols-3 gap-6">
                {/* Target Selection */}
                <div className="lg:col-span-2 space-y-4">
                  <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                    <Target className="w-5 h-5 text-primary" /> Select Training Target
                    <Badge variant="outline" className="text-[10px] ml-auto">
                      {targets?.length || 0} targets
                    </Badge>
                  </h2>

                  {/* Search & Filters */}
                  <div className="flex flex-wrap gap-2">
                    <div className="relative flex-1 min-w-[200px]">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                      <Input
                        placeholder="Search targets by name, tech, or vuln type..."
                        value={targetSearch}
                        onChange={(e) => setTargetSearch(e.target.value)}
                        className="pl-8 text-xs h-8"
                      />
                    </div>
                    <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                      <SelectTrigger className="w-[150px] text-xs h-8">
                        <SelectValue placeholder="Category" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Categories</SelectItem>
                        {[...new Set(targets?.map((t: TrainingTarget) => t.category) || [])].sort().map((cat) => (
                          <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Select value={difficultyFilter} onValueChange={setDifficultyFilter}>
                      <SelectTrigger className="w-[140px] text-xs h-8">
                        <SelectValue placeholder="Difficulty" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Levels</SelectItem>
                        <SelectItem value="beginner">Beginner</SelectItem>
                        <SelectItem value="intermediate">Intermediate</SelectItem>
                        <SelectItem value="advanced">Advanced</SelectItem>
                      </SelectContent>
                    </Select>
                    {(targetSearch || categoryFilter !== "all" || difficultyFilter !== "all") && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 text-xs"
                        onClick={() => { setTargetSearch(""); setCategoryFilter("all"); setDifficultyFilter("all"); }}
                      >
                        <XCircle className="w-3 h-3 mr-1" /> Clear
                      </Button>
                    )}
                  </div>

                  <div className="grid sm:grid-cols-2 gap-3 max-h-[600px] overflow-y-auto pr-1">
                    {targets?.filter((t: TrainingTarget) => {
                      const q = targetSearch.toLowerCase();
                      const matchesSearch = !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q) || t.tags.some(tag => tag.toLowerCase().includes(q)) || t.knownVulns.some(v => v.toLowerCase().includes(q)) || t.category.toLowerCase().includes(q);
                      const matchesCategory = categoryFilter === "all" || t.category === categoryFilter;
                      const matchesDifficulty = difficultyFilter === "all" || t.difficulty === difficultyFilter;
                      return matchesSearch && matchesCategory && matchesDifficulty;
                    }).map((t: TrainingTarget) => (
                      <Card
                        key={t.id}
                        className={`cursor-pointer transition-all hover:border-primary/50 ${
                          selectedTarget === t.id
                            ? "border-primary bg-primary/5"
                            : "border-border"
                        }`}
                        onClick={() => {
                          setSelectedTarget(t.id);
                          setCustomUrl("");
                        }}
                      >
                        <CardContent className="p-4 space-y-2">
                          <div className="flex items-start justify-between">
                            <div>
                              <h3 className="font-medium text-foreground text-sm">{t.name}</h3>
                              <p className="text-xs text-muted-foreground mt-0.5">{t.category}</p>
                            </div>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${DIFFICULTY_COLORS[t.difficulty] || ""}`}
                            >
                              {t.difficulty}
                            </Badge>
                          </div>
                          <p className="text-[10px] text-primary/60 font-mono truncate">{t.url}</p>
                          <p className="text-xs text-muted-dim leading-relaxed line-clamp-2">
                            {t.description}
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {t.knownVulns.slice(0, 4).map((v) => (
                              <Badge key={v} variant="outline" className="text-[9px] border-border">
                                {v}
                              </Badge>
                            ))}
                            {t.knownVulns.length > 4 && (
                              <Badge variant="outline" className="text-[9px] border-border text-primary/70">
                                +{t.knownVulns.length - 4} more
                              </Badge>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-1 pt-0.5">
                            {t.tags.slice(0, 5).map((tag) => (
                              <span key={tag} className="text-[9px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                                {tag}
                              </span>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    ))}

                    {/* Custom Target */}
                    <Card
                      className={`cursor-pointer transition-all hover:border-primary/50 ${
                        selectedTarget === "custom"
                          ? "border-primary bg-primary/5"
                          : "border-border"
                      }`}
                      onClick={() => setSelectedTarget("custom")}
                    >
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-start justify-between">
                          <div>
                            <h3 className="font-medium text-foreground text-sm">Custom Target</h3>
                            <p className="text-xs text-muted-foreground mt-0.5">Advanced</p>
                          </div>
                          <Globe className="w-5 h-5 text-muted-foreground" />
                        </div>
                        <p className="text-xs text-muted-dim leading-relaxed">
                          Enter a custom URL to test. Ensure you have authorization to scan the target.
                        </p>
                        {selectedTarget === "custom" && (
                          <Input
                            placeholder="https://target.example.com"
                            value={customUrl}
                            onChange={(e) => setCustomUrl(e.target.value)}
                            className="mt-2 text-xs"
                            onClick={(e) => e.stopPropagation()}
                          />
                        )}
                      </CardContent>
                    </Card>
                  </div>
                </div>

                {/* Scan Config & Launch */}
                <div className="space-y-4">
                  <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                    <Zap className="w-5 h-5 text-amber-400" /> Scan Configuration
                  </h2>
                  <Card className="border-border">
                    <CardContent className="p-4 space-y-4">
                      <div className="space-y-2">
                        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Scan Profile
                        </label>
                        <Select value={scanProfile} onValueChange={setScanProfile}>
                          <SelectTrigger className="text-sm">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="quick">Quick (httpx + nuclei)</SelectItem>
                            <SelectItem value="standard">Standard (+ naabu + gobuster)</SelectItem>
                            <SelectItem value="deep">Deep (+ ZAP full scan)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <Separator />

                      <div className="space-y-2">
                        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Selected Target
                        </label>
                        <div className="text-sm text-foreground">
                          {selectedTarget && selectedTarget !== "custom"
                            ? targets?.find((t: TrainingTarget) => t.id === selectedTarget)?.name || "Unknown"
                            : selectedTarget === "custom"
                            ? customUrl || "Enter URL..."
                            : "None selected"}
                        </div>
                      </div>

                      <Separator />

                      <div className="p-3 rounded bg-primary/5 border border-primary/20">
                        <div className="flex items-center gap-2 text-xs text-primary">
                          <Brain className="w-4 h-4" />
                          <span className="font-medium">Self-Learning Active</span>
                        </div>
                        <p className="text-[10px] text-muted-foreground mt-1">
                          The LLM will use correction history and ground truth from previous sessions
                          to improve its analysis accuracy.
                        </p>
                      </div>

                      <Button
                        className="w-full"
                        disabled={
                          startSession.isPending ||
                          acknowledgeRoE.isPending ||
                          (!selectedTarget && !customUrl) ||
                          (selectedTarget === "custom" && !customUrl)
                        }
                        onClick={handleStartScan}
                      >
                        {startSession.isPending ? (
                          <Loader2 className="w-4 h-4 animate-spin mr-2" />
                        ) : (
                          <Play className="w-4 h-4 mr-2" />
                        )}
                        Start Training Scan
                      </Button>

                      {/* RoE Acknowledgment Modal */}
                      <RoEAcknowledgmentModal
                        open={showRoEModal}
                        target={selectedTargetObj}
                        customUrl={customUrl}
                        scanProfile={scanProfile}
                        onAccept={handleRoEAccepted}
                        onReject={handleRoERejected}
                      />
                    </CardContent>
                  </Card>

                  {/* Ground Truth Info */}
                  {groundTruthTargets && groundTruthTargets.length > 0 && (
                    <Card className="border-border">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Shield className="w-4 h-4 text-primary" />
                          Ground Truth Library
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="p-4 pt-0 space-y-2">
                        {groundTruthTargets.map((gt: any) => (
                          <div
                            key={gt.targetPreset}
                            className="flex items-center justify-between text-xs"
                          >
                            <span className="text-muted-foreground capitalize">
                              {gt.targetPreset.replace(/-/g, " ")}
                            </span>
                            <Badge variant="outline" className="text-[10px]">
                              {gt.vulnCount} vulns
                            </Badge>
                          </div>
                        ))}
                        <p className="text-[10px] text-muted-dim mt-2">
                          LLM findings are automatically scored against these known vulnerabilities.
                        </p>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* ─── ACTIVE SESSION TAB ─── */}
            <TabsContent value="session" className="space-y-6 mt-4">
              {activeSession ? (
                <ActiveSessionView
                  session={activeSession}
                  onRerunAnalysis={() => {
                    if (activeSessionId) rerunAnalysis.mutate({ sessionId: activeSessionId });
                  }}
                  isRerunning={rerunAnalysis.isPending}
                  refetchSession={refetchSession}
                />
              ) : (
                <Card className="border-border">
                  <CardContent className="p-12 text-center">
                    <FlaskConical className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">
                      No active session. Launch a scan from the Launcher tab or select one from History.
                    </p>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            {/* ─── HISTORY TAB ─── */}
            <TabsContent value="history" className="space-y-4 mt-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-foreground">Session History</h2>
                <Button variant="outline" size="sm" onClick={() => refetchSessions()}>
                  <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
                </Button>
              </div>
              {sessions && sessions.length > 0 ? (
                <div className="space-y-2">
                  {sessions.map((s: SessionListItem) => (
                    <Card
                      key={s.sessionId}
                      className="border-border hover:border-primary/30 transition-colors cursor-pointer"
                      onClick={() => handleViewSession(s.sessionId)}
                    >
                      <CardContent className="p-4 flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="flex flex-col gap-1">
                            <span className="text-sm font-medium text-foreground">{s.name}</span>
                            <span className="text-xs text-muted-foreground">{s.targetUrl}</span>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <Badge variant="outline" className="text-[10px]">
                            {s.scanProfile}
                          </Badge>
                          <Badge className={`text-[10px] ${STATUS_COLORS[s.status] || ""}`}>
                            {s.status}
                          </Badge>
                          {s.stats && (
                            <span className="text-xs text-muted-foreground">
                              {(s.stats as any).vulnsFound || 0} vulns
                            </span>
                          )}
                          {s.durationMs && (
                            <span className="text-xs text-muted-dim">
                              {(s.durationMs / 1000).toFixed(0)}s
                            </span>
                          )}
                          <span className="text-xs text-muted-dim">
                            {s.createdAt ? new Date(s.createdAt).toLocaleDateString() : ""}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              ) : (
                <Card className="border-border">
                  <CardContent className="p-12 text-center">
                    <Clock className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                    <p className="text-muted-foreground">No sessions yet. Launch your first scan!</p>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            {/* ─── LEARNING DASHBOARD TAB ─── */}
            <TabsContent value="learning" className="space-y-6 mt-4">
              <LearningDashboard
                learningStats={learningStats}
                accuracyTrend={accuracyTrend}
                groundTruthTargets={groundTruthTargets}
              />
            </TabsContent>

            {/* ─── CONTINUOUS TRAINING TAB ─── */}
            <TabsContent value="continuous" className="space-y-6 mt-4">
              <ContinuousTraining />
            </TabsContent>

            {/* ─── ROE TAB ─── */}
            <TabsContent value="roe" className="space-y-6 mt-4">
              <RoECards targets={targets || []} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </AppShell>
  );
}

// ─── Sub-Components ───────────────────────────────────────────────────────

function QuickStat({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <Card className="border-border">
      <CardContent className="p-3 flex items-center gap-3">
        <div className="p-2 rounded bg-muted">{icon}</div>
        <div>
          <p className="text-lg font-bold text-foreground">{value}</p>
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Active Session View ──────────────────────────────────────────────────

function ActiveSessionView({
  session,
  onRerunAnalysis,
  isRerunning,
  refetchSession,
}: {
  session: any;
  onRerunAnalysis: () => void;
  isRerunning: boolean;
  refetchSession: () => void;
}) {
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());
  const [feedbackDialog, setFeedbackDialog] = useState<{ findingIndex: number; finding: any } | null>(null);
  const [missedFindingDialog, setMissedFindingDialog] = useState(false);

  const toggleFinding = (idx: number) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const llmAnalysis = session.llmAnalysis;
  const accuracyScore = llmAnalysis?.__accuracyScore;

  return (
    <div className="space-y-6">
      {/* Session Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">{session.name || "Training Session"}</h2>
          <p className="text-xs text-muted-foreground mt-0.5">{session.targetUrl || session.sessionId}</p>
        </div>
        <div className="flex items-center gap-2">
          {session.isRunning && (
            <Badge className="bg-blue-500/20 text-blue-400 animate-pulse">
              <Loader2 className="w-3 h-3 animate-spin mr-1" />
              {session.phase}
            </Badge>
          )}
          {!session.isRunning && session.phase === "completed" && (
            <>
              <Button variant="outline" size="sm" onClick={onRerunAnalysis} disabled={isRerunning}>
                {isRerunning ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
                Re-run Analysis
              </Button>
              <Button variant="outline" size="sm" onClick={() => setMissedFindingDialog(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5" /> Add Missed Finding
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      {session.isRunning && (
        <div className="space-y-2">
          <Progress value={session.progress} className="h-2" />
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>{session.phase}</span>
            <span>{session.progress}%</span>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <MiniStat label="Hosts" value={session.stats?.hostsScanned || session.assets?.length || 0} />
        <MiniStat label="Ports" value={session.stats?.portsFound || 0} />
        <MiniStat label="Vulns Found" value={session.stats?.vulnsFound || 0} />
        <MiniStat label="Tools Run" value={session.stats?.toolsRun || 0} />
        <MiniStat
          label="Risk Score"
          value={llmAnalysis?.riskScore ? `${llmAnalysis.riskScore}/10` : "—"}
          highlight={llmAnalysis?.riskRating === "critical" || llmAnalysis?.riskRating === "high"}
        />
      </div>

      {/* Accuracy Score Card (if available) */}
      {accuracyScore && (
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Brain className="w-5 h-5 text-primary" />
                <div>
                  <h3 className="text-sm font-semibold text-foreground">Ground Truth Accuracy</h3>
                  <p className="text-xs text-muted-foreground">
                    Scored against {accuracyScore.totalGroundTruth} known vulnerabilities
                  </p>
                </div>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold text-primary">
                  {(accuracyScore.f1Score * 100).toFixed(0)}%
                </span>
                <p className="text-[10px] text-muted-foreground">F1 Score</p>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-4 mt-4">
              <div className="text-center">
                <p className="text-sm font-bold text-green-400">{accuracyScore.truePositives}</p>
                <p className="text-[10px] text-muted-foreground">True Positives</p>
              </div>
              <div className="text-center">
                <p className="text-sm font-bold text-red-400">{accuracyScore.falsePositives}</p>
                <p className="text-[10px] text-muted-foreground">False Positives</p>
              </div>
              <div className="text-center">
                <p className="text-sm font-bold text-amber-400">{accuracyScore.falseNegatives}</p>
                <p className="text-[10px] text-muted-foreground">Missed (FN)</p>
              </div>
              <div className="text-center">
                <p className="text-sm font-bold text-foreground">
                  {(accuracyScore.precision * 100).toFixed(0)}% / {(accuracyScore.recall * 100).toFixed(0)}%
                </p>
                <p className="text-[10px] text-muted-foreground">Precision / Recall</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Two-column layout: Findings + Log */}
      <div className="grid lg:grid-cols-3 gap-6">
        {/* LLM Findings */}
        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Brain className="w-4 h-4 text-purple-400" />
            LLM Analysis Findings
            {llmAnalysis?.findings && (
              <Badge variant="outline" className="text-[10px]">
                {llmAnalysis.findings.length} findings
              </Badge>
            )}
          </h3>

          {llmAnalysis?.executiveSummary && (
            <Card className="border-border">
              <CardContent className="p-4">
                <p className="text-sm text-foreground leading-relaxed">{llmAnalysis.executiveSummary}</p>
              </CardContent>
            </Card>
          )}

          {llmAnalysis?.findings?.map((finding: any, idx: number) => (
            <FindingCard
              key={idx}
              finding={finding}
              index={idx}
              expanded={expandedFindings.has(idx)}
              onToggle={() => toggleFinding(idx)}
              onFeedback={() => setFeedbackDialog({ findingIndex: idx, finding })}
              sessionId={session.sessionId}
              refetchSession={refetchSession}
            />
          ))}

          {/* Attack Chains */}
          {llmAnalysis?.attackChains && llmAnalysis.attackChains.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Zap className="w-4 h-4 text-amber-400" /> Attack Chains
              </h3>
              {llmAnalysis.attackChains.map((chain: any, idx: number) => (
                <Card key={idx} className="border-border">
                  <CardContent className="p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="text-sm font-medium text-foreground">{chain.name}</h4>
                      <Badge
                        variant="outline"
                        className={`text-[10px] ${
                          chain.likelihood === "high"
                            ? "text-red-400 border-red-500/30"
                            : chain.likelihood === "medium"
                            ? "text-amber-400 border-amber-500/30"
                            : "text-muted-foreground"
                        }`}
                      >
                        {chain.likelihood} likelihood
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{chain.description}</p>
                    {chain.steps && (
                      <ol className="text-xs text-muted-dim space-y-1 ml-4 list-decimal">
                        {chain.steps.map((step: string, i: number) => (
                          <li key={i}>{step}</li>
                        ))}
                      </ol>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Missed Areas */}
          {llmAnalysis?.missedAreas && llmAnalysis.missedAreas.length > 0 && (
            <Card className="border-amber-500/30 bg-amber-500/5">
              <CardContent className="p-4 space-y-2">
                <h4 className="text-sm font-medium text-amber-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> Areas Not Covered
                </h4>
                <ul className="text-xs text-muted-foreground space-y-1 ml-4 list-disc">
                  {llmAnalysis.missedAreas.map((area: string, i: number) => (
                    <li key={i}>{area}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          {!llmAnalysis && !session.isRunning && (
            <Card className="border-border">
              <CardContent className="p-8 text-center">
                <Brain className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">
                  No LLM analysis available yet.
                  {session.phase === "completed" && " Click 'Re-run Analysis' to generate findings."}
                </p>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Scan Log */}
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
            <Activity className="w-4 h-4 text-primary" /> Scan Log
          </h3>
          <Card className="border-border">
            <CardContent className="p-0">
              <ScrollArea className="h-[600px]">
                <div className="p-3 space-y-1">
                  {(session.log || []).map((entry: any, idx: number) => (
                    <div key={idx} className="flex gap-2 text-[11px] py-1 border-b border-border/30 last:border-0">
                      <span className="text-muted-dim shrink-0 w-14 font-mono">
                        {entry.ts ? new Date(entry.ts).toLocaleTimeString() : ""}
                      </span>
                      <Badge
                        variant="outline"
                        className={`text-[9px] shrink-0 ${
                          entry.type === "error"
                            ? "text-red-400 border-red-500/30"
                            : entry.type === "warning"
                            ? "text-amber-400 border-amber-500/30"
                            : entry.type === "scan_result"
                            ? "text-green-400 border-green-500/30"
                            : "text-muted-foreground"
                        }`}
                      >
                        {entry.phase}
                      </Badge>
                      <div>
                        <span className="text-foreground font-medium">{entry.title}</span>
                        {entry.detail && (
                          <span className="text-muted-foreground ml-1">— {entry.detail}</span>
                        )}
                      </div>
                    </div>
                  ))}
                  {(!session.log || session.log.length === 0) && (
                    <p className="text-xs text-muted-foreground text-center py-8">
                      Waiting for scan to start...
                    </p>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* OWASP Coverage */}
          {session.owaspCoverage && (
            <Card className="border-border">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" /> OWASP Coverage
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0">
                <div className="text-center mb-3">
                  <span className="text-2xl font-bold text-primary">
                    {session.owaspCoverage.overallScore?.toFixed(0) || 0}%
                  </span>
                </div>
                {session.owaspCoverage.criticalGaps?.slice(0, 5).map((gap: any, i: number) => (
                  <div key={i} className="flex justify-between text-xs py-1 border-b border-border/30">
                    <span className="text-muted-foreground">{gap.categoryId}</span>
                    <Badge variant="outline" className="text-[9px] text-amber-400 border-amber-500/30">
                      Gap
                    </Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* Feedback Dialog */}
      {feedbackDialog && (
        <FeedbackDialog
          sessionId={session.sessionId}
          findingIndex={feedbackDialog.findingIndex}
          finding={feedbackDialog.finding}
          onClose={() => setFeedbackDialog(null)}
          refetchSession={refetchSession}
        />
      )}

      {/* Missed Finding Dialog */}
      {missedFindingDialog && (
        <MissedFindingDialog
          sessionId={session.sessionId}
          onClose={() => setMissedFindingDialog(false)}
          refetchSession={refetchSession}
        />
      )}
    </div>
  );
}

// ─── Finding Card ─────────────────────────────────────────────────────────

function FindingCard({
  finding,
  index,
  expanded,
  onToggle,
  onFeedback,
  sessionId,
  refetchSession,
}: {
  finding: any;
  index: number;
  expanded: boolean;
  onToggle: () => void;
  onFeedback: () => void;
  sessionId: string;
  refetchSession: () => void;
}) {
  const submitFeedback = trpc.trainingLab.submitFeedback.useMutation({
    onSuccess: () => {
      toast.success("Feedback recorded — learning engine updated");
      refetchSession();
    },
    onError: (err) => toast.error(`Feedback failed: ${err.message}`),
  });

  const quickFeedback = (type: "correct" | "incorrect" | "false_positive") => {
    submitFeedback.mutate({
      sessionId,
      findingIndex: index,
      feedbackType: type,
      findingTitle: finding.title,
      llmSeverity: finding.severity,
      llmCategory: finding.category,
    });
  };

  return (
    <Card className="border-border">
      <CardContent className="p-0">
        <div
          className="p-4 cursor-pointer flex items-start justify-between hover:bg-muted/30 transition-colors"
          onClick={onToggle}
        >
          <div className="flex items-start gap-3">
            <Badge
              variant="outline"
              className={`text-[10px] shrink-0 mt-0.5 ${SEVERITY_COLORS[finding.severity?.toLowerCase()] || ""}`}
            >
              {finding.severity?.toUpperCase()}
            </Badge>
            <div>
              <h4 className="text-sm font-medium text-foreground">{finding.title}</h4>
              {finding.category && (
                <p className="text-xs text-muted-foreground mt-0.5">{finding.category}</p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {finding.confidence && (
              <Badge variant="outline" className="text-[9px]">
                {finding.confidence}
              </Badge>
            )}
            {expanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
          </div>
        </div>

        {expanded && (
          <div className="px-4 pb-4 space-y-3 border-t border-border/50">
            {finding.description && (
              <p className="text-xs text-muted-foreground leading-relaxed mt-3">{finding.description}</p>
            )}

            {finding.exploitationPath && finding.exploitationPath.length > 0 && (
              <div>
                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">
                  Exploitation Path
                </p>
                <ol className="text-xs text-muted-dim space-y-0.5 ml-4 list-decimal">
                  {finding.exploitationPath.map((step: string, i: number) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>
            )}

            {finding.impact && (
              <div>
                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Impact</p>
                <p className="text-xs text-muted-dim">{finding.impact}</p>
              </div>
            )}

            {finding.remediation && (
              <div>
                <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">Remediation</p>
                <p className="text-xs text-muted-dim">{finding.remediation}</p>
              </div>
            )}

            {finding.cve && (
              <Badge variant="outline" className="text-[10px]">
                {finding.cve}
              </Badge>
            )}

            {/* Feedback Buttons */}
            <Separator />
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider mr-2">
                Rate this finding:
              </span>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs text-green-400 border-green-500/30 hover:bg-green-500/10"
                onClick={(e) => { e.stopPropagation(); quickFeedback("correct"); }}
                disabled={submitFeedback.isPending}
              >
                <ThumbsUp className="w-3 h-3 mr-1" /> Correct
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs text-red-400 border-red-500/30 hover:bg-red-500/10"
                onClick={(e) => { e.stopPropagation(); quickFeedback("incorrect"); }}
                disabled={submitFeedback.isPending}
              >
                <ThumbsDown className="w-3 h-3 mr-1" /> Incorrect
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs text-red-400 border-red-500/30 hover:bg-red-500/10"
                onClick={(e) => { e.stopPropagation(); quickFeedback("false_positive"); }}
                disabled={submitFeedback.isPending}
              >
                <XCircle className="w-3 h-3 mr-1" /> False Positive
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs text-amber-400 border-amber-500/30 hover:bg-amber-500/10"
                onClick={(e) => { e.stopPropagation(); onFeedback(); }}
              >
                <MessageSquarePlus className="w-3 h-3 mr-1" /> Detailed
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Feedback Dialog ──────────────────────────────────────────────────────

function FeedbackDialog({
  sessionId,
  findingIndex,
  finding,
  onClose,
  refetchSession,
}: {
  sessionId: string;
  findingIndex: number;
  finding: any;
  onClose: () => void;
  refetchSession: () => void;
}) {
  const [feedbackType, setFeedbackType] = useState<string>("partial");
  const [notes, setNotes] = useState("");
  const [expectedSeverity, setExpectedSeverity] = useState("");
  const [expectedCategory, setExpectedCategory] = useState("");

  const submitFeedback = trpc.trainingLab.submitFeedback.useMutation({
    onSuccess: () => {
      toast.success("Detailed feedback submitted — learning engine updated");
      refetchSession();
      onClose();
    },
    onError: (err) => toast.error(`Feedback failed: ${err.message}`),
  });

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-sm">Feedback: {finding.title}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Feedback Type</label>
            <Select value={feedbackType} onValueChange={setFeedbackType}>
              <SelectTrigger className="text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="correct">Correct</SelectItem>
                <SelectItem value="incorrect">Incorrect</SelectItem>
                <SelectItem value="partial">Partially Correct</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Expected Severity</label>
              <Select value={expectedSeverity} onValueChange={setExpectedSeverity}>
                <SelectTrigger className="text-sm">
                  <SelectValue placeholder="Select..." />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Expected Category</label>
              <Input
                placeholder="e.g., A03:2025 Injection"
                value={expectedCategory}
                onChange={(e) => setExpectedCategory(e.target.value)}
                className="text-sm"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Notes</label>
            <Textarea
              placeholder="Explain what the LLM got wrong or how to improve..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              className="text-sm"
            />
          </div>

          <Button
            className="w-full"
            onClick={() =>
              submitFeedback.mutate({
                sessionId,
                findingIndex,
                feedbackType: feedbackType as any,
                operatorNotes: notes || undefined,
                expectedSeverity: expectedSeverity || undefined,
                expectedCategory: expectedCategory || undefined,
                findingTitle: finding.title,
                llmSeverity: finding.severity,
                llmCategory: finding.category,
              })
            }
            disabled={submitFeedback.isPending}
          >
            {submitFeedback.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
            Submit Feedback
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Missed Finding Dialog ────────────────────────────────────────────────

function MissedFindingDialog({
  sessionId,
  onClose,
  refetchSession,
}: {
  sessionId: string;
  onClose: () => void;
  refetchSession: () => void;
}) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [category, setCategory] = useState("");
  const [description, setDescription] = useState("");

  const addMissed = trpc.trainingLab.addMissedFinding.useMutation({
    onSuccess: () => {
      toast.success("Missed finding recorded — learning engine updated");
      refetchSession();
      onClose();
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-sm">Add Missed Finding</DialogTitle>
        </DialogHeader>
        <p className="text-xs text-muted-foreground">
          Record a vulnerability the LLM should have found. This will be stored in the learning
          knowledge base and used to improve future analysis.
        </p>
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Finding Title</label>
            <Input
              placeholder="e.g., SQL Injection in Login Form"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="text-sm"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Severity</label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground">Category</label>
              <Input
                placeholder="e.g., A03:2025 Injection"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="text-sm"
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Description</label>
            <Textarea
              placeholder="Describe the vulnerability and how to detect it..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="text-sm"
            />
          </div>

          <Button
            className="w-full"
            onClick={() =>
              addMissed.mutate({
                sessionId,
                findingTitle: title,
                severity,
                category: category || undefined,
                description: description || undefined,
              })
            }
            disabled={addMissed.isPending || !title}
          >
            {addMissed.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
            Add Missed Finding
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Mini Stat ────────────────────────────────────────────────────────────

function MiniStat({ label, value, highlight }: { label: string; value: string | number; highlight?: boolean }) {
  return (
    <div className={`p-3 rounded border ${highlight ? "border-red-500/30 bg-red-500/5" : "border-border bg-card"}`}>
      <p className={`text-lg font-bold ${highlight ? "text-red-400" : "text-foreground"}`}>{value}</p>
      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
    </div>
  );
}

// ─── Learning Dashboard ───────────────────────────────────────────────────

function LearningDashboard({
  learningStats,
  accuracyTrend,
  groundTruthTargets,
}: {
  learningStats: any;
  accuracyTrend: any;
  groundTruthTargets: any;
}) {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <GraduationCap className="w-6 h-6 text-primary" />
        <div>
          <h2 className="text-lg font-semibold text-foreground">LLM Learning Dashboard</h2>
          <p className="text-xs text-muted-foreground">
            Track how the LLM's vulnerability analysis accuracy improves with operator feedback.
          </p>
        </div>
      </div>

      {/* Feedback Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-border">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-foreground">{learningStats?.totalFeedbackEntries || 0}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Feedback</p>
          </CardContent>
        </Card>
        <Card className="border-green-500/30 bg-green-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-green-400">{learningStats?.correctCount || 0}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Correct</p>
          </CardContent>
        </Card>
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-red-400">{learningStats?.incorrectCount || 0}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Incorrect</p>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-amber-400">{learningStats?.partialCount || 0}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Partial</p>
          </CardContent>
        </Card>
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-purple-400">{learningStats?.missedCount || 0}</p>
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Missed</p>
          </CardContent>
        </Card>
      </div>

      {/* Accuracy by Target */}
      <Card className="border-border">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-primary" /> Accuracy by Target
          </CardTitle>
        </CardHeader>
        <CardContent>
          {learningStats?.accuracyStats && learningStats.accuracyStats.length > 0 ? (
            <div className="space-y-4">
              {learningStats.accuracyStats.map((stat: any) => (
                <div key={stat.targetPreset} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground capitalize">
                        {stat.targetPreset.replace(/-/g, " ")}
                      </span>
                      <Badge variant="outline" className="text-[10px]">
                        {stat.sessionCount} sessions
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3">
                      <TrendIndicator trend={stat.trend} />
                      <span className="text-sm font-bold text-primary">
                        {(stat.latestF1 * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <Progress value={stat.avgF1 * 100} className="h-1.5" />
                      <p className="text-[10px] text-muted-foreground mt-1">
                        F1: {(stat.avgF1 * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <Progress value={stat.avgPrecision * 100} className="h-1.5" />
                      <p className="text-[10px] text-muted-foreground mt-1">
                        Precision: {(stat.avgPrecision * 100).toFixed(1)}%
                      </p>
                    </div>
                    <div>
                      <Progress value={stat.avgRecall * 100} className="h-1.5" />
                      <p className="text-[10px] text-muted-foreground mt-1">
                        Recall: {(stat.avgRecall * 100).toFixed(1)}%
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <Brain className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">
                No accuracy data yet. Run training sessions to start tracking LLM performance.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Ground Truth Coverage */}
      {groundTruthTargets && groundTruthTargets.length > 0 && (
        <Card className="border-border">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" /> Ground Truth Library
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {groundTruthTargets.map((gt: any) => (
                <Card key={gt.targetPreset} className="border-border">
                  <CardContent className="p-3 space-y-2">
                    <h4 className="text-sm font-medium text-foreground capitalize">
                      {gt.targetPreset.replace(/-/g, " ")}
                    </h4>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{gt.vulnCount} known vulns</span>
                      <span className="text-xs text-muted-foreground">
                        {gt.categories.length} categories
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {gt.severities.map((s: string) => (
                        <Badge
                          key={s}
                          variant="outline"
                          className={`text-[9px] ${SEVERITY_COLORS[s] || ""}`}
                        >
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* How It Works */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-6">
          <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-primary" /> How Self-Learning Works
          </h3>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-2">
              <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center text-primary font-bold text-sm">
                1
              </div>
              <h4 className="text-xs font-medium text-foreground">Feedback Knowledge Base</h4>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Operator corrections are stored persistently. When you mark a finding as incorrect or
                add a missed vulnerability, it becomes permanent context for future scans.
              </p>
            </div>
            <div className="space-y-2">
              <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center text-primary font-bold text-sm">
                2
              </div>
              <h4 className="text-xs font-medium text-foreground">Ground Truth Scoring</h4>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Each training target has known vulnerabilities. After every scan, the LLM's findings
                are scored against ground truth (precision, recall, F1).
              </p>
            </div>
            <div className="space-y-2">
              <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center text-primary font-bold text-sm">
                3
              </div>
              <h4 className="text-xs font-medium text-foreground">Progressive Refinement</h4>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                A correction history is prepended to every LLM prompt: "In previous sessions you
                missed X, over-rated Y, and misclassified Z."
              </p>
            </div>
            <div className="space-y-2">
              <div className="w-8 h-8 rounded bg-primary/20 flex items-center justify-center text-primary font-bold text-sm">
                4
              </div>
              <h4 className="text-xs font-medium text-foreground">Accuracy Trending</h4>
              <p className="text-[10px] text-muted-foreground leading-relaxed">
                Track F1 score, precision, and recall over time per target type. See whether the
                system is genuinely improving with each training session.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Trend Indicator ──────────────────────────────────────────────────────

function TrendIndicator({ trend }: { trend: string }) {
  if (trend === "improving")
    return (
      <Badge className="bg-green-500/20 text-green-400 text-[10px] gap-1">
        <TrendingUp className="w-3 h-3" /> Improving
      </Badge>
    );
  if (trend === "declining")
    return (
      <Badge className="bg-red-500/20 text-red-400 text-[10px] gap-1">
        <TrendingDown className="w-3 h-3" /> Declining
      </Badge>
    );
  if (trend === "stable")
    return (
      <Badge className="bg-muted text-muted-foreground text-[10px] gap-1">
        <Minus className="w-3 h-3" /> Stable
      </Badge>
    );
  return (
    <Badge className="bg-muted text-muted-foreground text-[10px]">
      Insufficient Data
    </Badge>
  );
}


// ─── RoE Cards Component ─────────────────────────────────────────────────

function RoECards({ targets }: { targets: TrainingTarget[] }) {
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!searchQuery.trim()) return targets.filter(t => t.id !== "custom");
    const q = searchQuery.toLowerCase();
    return targets.filter(t =>
      t.id !== "custom" &&
      ((t.name || '').toLowerCase().includes(q) ||
       (t.roe.provider || '').toLowerCase().includes(q) ||
       (t.category || '').toLowerCase().includes(q) ||
       t.tags.some(tag => tag.toLowerCase().includes(q)))
    );
  }, [targets, searchQuery]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-primary" /> Rules of Engagement
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Review the terms, allowed activities, and restrictions for each training target before scanning.
          </p>
        </div>
        <Badge variant="outline" className="text-xs">
          {filtered.length} targets
        </Badge>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search by name, provider, category, or tag..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9 bg-card border-border"
        />
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-green-400" /> Allowed</span>
        <span className="flex items-center gap-1"><Ban className="w-3.5 h-3.5 text-red-400" /> Prohibited</span>
        <span className="flex items-center gap-1"><ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Restriction</span>
        <span className="flex items-center gap-1"><Gauge className="w-3.5 h-3.5 text-blue-400" /> Rate Limit</span>
        <span className="flex items-center gap-1"><Lock className="w-3.5 h-3.5 text-purple-400" /> Requires Own Instance</span>
      </div>

      {/* Cards Grid */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {filtered.map((target) => (
          <RoECard
            key={target.id}
            target={target}
            expanded={expandedId === target.id}
            onToggle={() => setExpandedId(expandedId === target.id ? null : target.id)}
          />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
          <p>No targets match your search.</p>
        </div>
      )}

      {/* Custom Target Warning */}
      <Card className="border-amber-500/30 bg-amber-500/5">
        <CardContent className="p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-400">Custom Targets</p>
            <p className="text-xs text-muted-foreground mt-1">
              When scanning custom URLs not listed above, <strong>you</strong> are responsible for ensuring you have written authorization (Rules of Engagement) from the target owner. Scanning without authorization is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function RoECard({ target, expanded, onToggle }: { target: TrainingTarget; expanded: boolean; onToggle: () => void }) {
  const roe = target.roe;
  const hasRestrictions = roe.noBruteForce || roe.noDoS || roe.noExfiltration || roe.requiresOwnInstance || roe.maxScansPerDay !== null;

  return (
    <Card className={`border-border transition-all duration-200 ${expanded ? "ring-1 ring-primary/30" : "hover:border-primary/20"}`}>
      <CardHeader className="pb-2 space-y-2">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <CardTitle className="text-sm font-semibold text-foreground truncate">{target.name}</CardTitle>
            <p className="text-[10px] text-muted-foreground mt-0.5">{roe.provider}</p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <Badge className={DIFFICULTY_COLORS[target.difficulty] || "bg-muted text-muted-foreground"} variant="outline">
              {target.difficulty}
            </Badge>
            {hasRestrictions ? (
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-green-400" />
            )}
          </div>
        </div>

        {/* URL */}
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Globe className="w-3 h-3 shrink-0" />
          <a href={target.url} target="_blank" rel="noopener noreferrer" className="hover:text-primary truncate">
            {target.url}
          </a>
        </div>
      </CardHeader>

      <CardContent className="pt-0 space-y-3">
        {/* Summary */}
        <p className="text-xs text-muted-foreground leading-relaxed">{roe.summary}</p>

        {/* Quick restriction badges */}
        <div className="flex flex-wrap gap-1.5">
          {roe.noBruteForce && (
            <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400 bg-red-500/10">
              <Ban className="w-2.5 h-2.5 mr-1" /> No Brute-Force
            </Badge>
          )}
          {roe.noDoS && (
            <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400 bg-red-500/10">
              <Ban className="w-2.5 h-2.5 mr-1" /> No DoS
            </Badge>
          )}
          {roe.noExfiltration && (
            <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400 bg-red-500/10">
              <Ban className="w-2.5 h-2.5 mr-1" /> No Exfiltration
            </Badge>
          )}
          {roe.requiresOwnInstance && (
            <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400 bg-purple-500/10">
              <Lock className="w-2.5 h-2.5 mr-1" /> Own Instance Required
            </Badge>
          )}
          {roe.maxScansPerDay !== null && (
            <Badge variant="outline" className="text-[10px] border-blue-500/30 text-blue-400 bg-blue-500/10">
              <Gauge className="w-2.5 h-2.5 mr-1" /> Max {roe.maxScansPerDay}/day
            </Badge>
          )}
          {!hasRestrictions && (
            <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400 bg-green-500/10">
              <ShieldCheck className="w-2.5 h-2.5 mr-1" /> Unrestricted
            </Badge>
          )}
        </div>

        {/* Expand/Collapse */}
        <Button variant="ghost" size="sm" onClick={onToggle} className="w-full text-xs h-7">
          {expanded ? <ChevronUp className="w-3.5 h-3.5 mr-1" /> : <ChevronDown className="w-3.5 h-3.5 mr-1" />}
          {expanded ? "Hide Details" : "View Full RoE"}
        </Button>

        {/* Expanded Details */}
        {expanded && (
          <div className="space-y-3 pt-2 border-t border-border">
            {/* Allowed Activities */}
            {roe.allowed.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-green-400 font-medium mb-1.5 flex items-center gap-1">
                  <ShieldCheck className="w-3 h-3" /> Allowed Activities
                </p>
                <div className="flex flex-wrap gap-1">
                  {roe.allowed.map((item, i) => (
                    <Badge key={i} variant="outline" className="text-[10px] border-green-500/20 text-green-400/80 bg-green-500/5">
                      {item}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Prohibited Activities */}
            {roe.prohibited.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-red-400 font-medium mb-1.5 flex items-center gap-1">
                  <Ban className="w-3 h-3" /> Prohibited Activities
                </p>
                <div className="flex flex-wrap gap-1">
                  {roe.prohibited.map((item, i) => (
                    <Badge key={i} variant="outline" className="text-[10px] border-red-500/20 text-red-400/80 bg-red-500/5">
                      {item}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Rate Limit */}
            {roe.rateLimit && (
              <div className="flex items-start gap-2 text-xs text-muted-foreground bg-blue-500/5 rounded p-2 border border-blue-500/20">
                <Gauge className="w-3.5 h-3.5 text-blue-400 mt-0.5 shrink-0" />
                <span><strong className="text-blue-400">Rate Limit:</strong> {roe.rateLimit}</span>
              </div>
            )}

            {/* Notes */}
            {roe.notes && (
              <div className="flex items-start gap-2 text-xs text-muted-foreground bg-muted/50 rounded p-2">
                <AlertCircle className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
                <span>{roe.notes}</span>
              </div>
            )}

            {/* Terms URL */}
            {roe.termsUrl && (
              <a
                href={roe.termsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs text-primary hover:underline"
              >
                <ExternalLink className="w-3 h-3" /> View Official Terms
              </a>
            )}

            {/* Tech Tags */}
            <div className="flex flex-wrap gap-1 pt-1">
              {target.tags.map((tag) => (
                <Badge key={tag} variant="outline" className="text-[10px] bg-muted/30 text-muted-foreground border-border">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}


// ─── RoE Acknowledgment Modal ─────────────────────────────────────────────

interface RoEAcknowledgmentModalProps {
  open: boolean;
  target: any | null;
  customUrl: string;
  scanProfile: string;
  onAccept: () => void;
  onReject: () => void;
}

function RoEAcknowledgmentModal({ open, target, customUrl, scanProfile, onAccept, onReject }: RoEAcknowledgmentModalProps) {
  const [accepted, setAccepted] = useState(false);
  const [scrolledToBottom, setScrolledToBottom] = useState(false);

  // Reset state when modal opens
  useEffect(() => {
    if (open) {
      setAccepted(false);
      setScrolledToBottom(false);
    }
  }, [open]);

  const roe = target?.roe;
  const isCustom = !target;
  const targetName = target?.name || customUrl || "Custom Target";
  const targetUrl = target?.url || customUrl || "";

  const restrictions: string[] = [];
  if (roe) {
    if (roe.noBruteForce) restrictions.push("Brute-force attacks are PROHIBITED");
    if (roe.noDoS) restrictions.push("Denial of Service (DoS) attacks are PROHIBITED");
    if (roe.noExfiltration) restrictions.push("Data exfiltration is PROHIBITED");
    if (roe.requiresOwnInstance) restrictions.push("You MUST deploy your own instance before scanning");
    if (roe.maxScansPerDay) restrictions.push(`Maximum ${roe.maxScansPerDay} scans per day allowed`);
    if (roe.prohibited?.length > 0) {
      restrictions.push(`Prohibited activities: ${roe.prohibited.join(", ")}`);
    }
    if (roe.allowed?.length > 0 && roe.allowed.length < 5) {
      restrictions.push(`Only these activities are allowed: ${roe.allowed.join(", ")}`);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onReject(); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            Rules of Engagement
          </DialogTitle>
          <DialogDescription className="text-muted-foreground">
            Review and accept the rules before scanning <span className="font-semibold text-foreground">{targetName}</span>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Target Info */}
          <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-1">
            <div className="flex items-center gap-2">
              <Target className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium">{targetName}</span>
            </div>
            {targetUrl && (
              <p className="text-xs text-muted-foreground pl-6">{targetUrl}</p>
            )}
            <div className="flex items-center gap-2 pl-6">
              <Badge variant="outline" className="text-[10px]">{scanProfile} scan</Badge>
              {roe?.provider && <Badge variant="outline" className="text-[10px]">{roe.provider}</Badge>}
            </div>
          </div>

          {/* Rules ScrollArea */}
          <ScrollArea
            className="h-[200px] rounded-lg border border-border p-3"
            onScrollCapture={(e) => {
              const el = e.currentTarget.querySelector("[data-radix-scroll-area-viewport]") as HTMLElement;
              if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 20) {
                setScrolledToBottom(true);
              }
            }}
          >
            <div className="space-y-3">
              {isCustom ? (
                <div className="space-y-2">
                  <div className="flex items-start gap-2 p-2 rounded bg-red-500/10 border border-red-500/20">
                    <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div className="text-xs text-red-300">
                      <p className="font-semibold">Custom Target Warning</p>
                      <p className="mt-1">You are scanning a custom URL that is NOT in the pre-approved training catalog.
                      You MUST have explicit written authorization from the target owner before proceeding.</p>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground space-y-1.5 pl-1">
                    <p>By proceeding, you confirm that:</p>
                    <ul className="list-disc pl-4 space-y-1">
                      <li>You have written authorization to scan this target</li>
                      <li>You understand unauthorized scanning is illegal</li>
                      <li>You accept full responsibility for this scan</li>
                      <li>AceofCloud is not liable for unauthorized use</li>
                    </ul>
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  {/* Summary */}
                  <p className="text-xs text-muted-foreground">{roe?.summary || "No specific rules documented."}</p>

                  {/* Restrictions */}
                  {restrictions.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" /> Restrictions
                      </p>
                      {restrictions.map((r, i) => (
                        <div key={i} className="flex items-start gap-2 p-2 rounded bg-amber-500/10 border border-amber-500/20">
                          <XCircle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                          <span className="text-xs text-amber-200">{r}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Allowed Activities */}
                  {roe?.allowed?.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-semibold text-green-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Allowed Activities
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {roe.allowed.map((a: string) => (
                          <Badge key={a} variant="outline" className="text-[10px] bg-green-500/10 text-green-400 border-green-500/30">
                            {a}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Notes */}
                  {roe?.notes && (
                    <div className="p-2 rounded bg-muted/30 border border-border">
                      <p className="text-[10px] text-muted-foreground">{roe.notes}</p>
                    </div>
                  )}

                  {/* Terms URL */}
                  {roe?.termsUrl && (
                    <a
                      href={roe.termsUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs text-primary hover:underline"
                    >
                      <ExternalLink className="w-3 h-3" /> View Official Terms
                    </a>
                  )}
                </div>
              )}

              {/* Enforcement Notice */}
              <div className="p-2 rounded bg-primary/5 border border-primary/20 mt-2">
                <p className="text-[10px] text-primary">
                  <Shield className="w-3 h-3 inline mr-1" />
                  The platform will automatically enforce these rules by blocking prohibited scan types,
                  sanitizing scan flags, and filtering nuclei templates.
                </p>
              </div>
            </div>
          </ScrollArea>

          {/* Acceptance Checkbox */}
          <label className="flex items-start gap-3 cursor-pointer group">
            <input
              type="checkbox"
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
              className="mt-1 w-4 h-4 rounded border-border accent-primary"
            />
            <span className="text-xs text-muted-foreground group-hover:text-foreground transition-colors">
              I have read and agree to the Rules of Engagement for this target.
              I understand that violations may result in legal consequences and
              that this acknowledgment is logged for audit purposes.
            </span>
          </label>
        </div>

        <DialogFooter className="flex gap-2 sm:gap-2">
          <Button variant="outline" onClick={onReject} className="flex-1">
            Cancel
          </Button>
          <Button
            onClick={onAccept}
            disabled={!accepted}
            className="flex-1"
          >
            <Shield className="w-4 h-4 mr-2" />
            Accept & Launch Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
