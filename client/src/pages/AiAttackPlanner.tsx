"use client";

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Loader2, AlertTriangle, Trash2, PlusCircle, Eye, Brain, Target,
  Shield, Crosshair, Zap, ChevronRight, Clock, CheckCircle2, XCircle,
  BarChart3, Network, Swords, ArrowRight, Play, Copy, FileDown
} from "lucide-react";
import { exportToPdf } from "@/lib/export-pdf";
import AppShell from "@/components/AppShell";

// ─── Types ─────────────────────────────────────────────────────────────────────
type PlanPhase = {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  description: string;
  stealthRating?: number;
  prerequisites?: string[];
};

type AttackPlan = {
  id: number;
  name: string;
  targetDescription: string;
  threatActorProfile: string | null;
  environmentContext: string | null;
  estimatedRiskScore: number | null;
  status: string;
  generatedPlan: string | null;
  attackSteps: any;
  createdBy: string | null;
  createdAt: any;
  acceptedAt: any;
};

// ─── Constants ─────────────────────────────────────────────────────────────────
const THREAT_ACTORS = [
  { value: "apt28", label: "APT28 (Fancy Bear)", origin: "Russia/GRU", focus: "Government, Military, Media" },
  { value: "apt29", label: "APT29 (Cozy Bear)", origin: "Russia/SVR", focus: "Government, Think Tanks" },
  { value: "apt41", label: "APT41 (Barium)", origin: "China", focus: "Healthcare, Telecom, Gaming" },
  { value: "fin7", label: "FIN7", origin: "Eastern Europe", focus: "Financial, Retail, Hospitality" },
  { value: "lazarus", label: "Lazarus Group", origin: "North Korea", focus: "Financial, Crypto, Defense" },
  { value: "custom", label: "Custom Profile", origin: "User-defined", focus: "Custom" },
];

const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "bg-blue-500/20 text-blue-400 border-blue-500/30",
  "resource-development": "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
  "initial-access": "bg-red-500/20 text-red-400 border-red-500/30",
  "execution": "bg-orange-500/20 text-orange-400 border-orange-500/30",
  "persistence": "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  "privilege-escalation": "bg-amber-500/20 text-amber-400 border-amber-500/30",
  "defense-evasion": "bg-purple-500/20 text-purple-400 border-purple-500/30",
  "credential-access": "bg-pink-500/20 text-pink-400 border-pink-500/30",
  "discovery": "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  "lateral-movement": "bg-teal-500/20 text-teal-400 border-teal-500/30",
  "collection": "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  "command-and-control": "bg-violet-500/20 text-violet-400 border-violet-500/30",
  "exfiltration": "bg-rose-500/20 text-rose-400 border-rose-500/30",
  "impact": "bg-red-600/20 text-red-300 border-red-600/30",
};

const STATUS_CONFIG: Record<string, { color: string; icon: typeof CheckCircle2 }> = {
  generating: { color: "bg-blue-500/20 text-blue-400", icon: Loader2 },
  completed: { color: "bg-green-500/20 text-green-400", icon: CheckCircle2 },
  ready: { color: "bg-emerald-500/20 text-emerald-400", icon: Play },
  executing: { color: "bg-orange-500/20 text-orange-400", icon: Zap },
};

// ─── Main Page ─────────────────────────────────────────────────────────────────
const AiAttackPlannerPage = () => {
  const [isGenerateDialogOpen, setGenerateDialogOpen] = useState(false);
  const [selectedPlanId, setSelectedPlanId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState("plans");

  const utils = trpc.useUtils();
  const plansQuery = trpc.aiAttackPlanner.list.useQuery({});
  const statsQuery = trpc.aiAttackPlanner.getStats.useQuery();
  const profilesQuery = trpc.aiAttackPlanner.listThreatActorProfiles.useQuery();

  const generatePlanMutation = trpc.aiAttackPlanner.generate.useMutation({
    onSuccess: () => {
      toast.success("Attack plan generated successfully!");
      utils.aiAttackPlanner.list.invalidate();
      utils.aiAttackPlanner.getStats.invalidate();
      setGenerateDialogOpen(false);
    },
    onError: (error: any) => {
      toast.error("Failed to generate attack plan", { description: error.message });
    },
  });

  const [calderaOpId, setCalderaOpId] = useState<string | null>(null);

  const acceptPlanMutation = trpc.aiAttackPlanner.accept.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      if (data.calderaOperationId) setCalderaOpId(data.calderaOperationId);
      utils.aiAttackPlanner.list.invalidate();
    },
  });

  const deletePlanMutation = trpc.aiAttackPlanner.delete.useMutation({
    onSuccess: () => {
      toast.success("Attack plan deleted");
      utils.aiAttackPlanner.list.invalidate();
      utils.aiAttackPlanner.getStats.invalidate();
      if (selectedPlanId) setSelectedPlanId(null);
    },
    onError: (error: any) => {
      toast.error("Failed to delete", { description: error.message });
    },
  });

  const handleGenerateSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    generatePlanMutation.mutate({
      name: formData.get("name") as string,
      targetDescription: formData.get("targetDescription") as string,
      threatActorProfile: formData.get("threatActorProfile") as string,
      environmentContext: (formData.get("environmentContext") as string) || undefined,
      constraints: (formData.get("constraints") as string) || undefined,
    });
  };

  const plans = plansQuery.data ?? [];
  const selectedPlan = plans.find((p) => p.id === selectedPlanId);

  return (
    <AppShell activePath="/ai-attack-planner">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-6 w-6 text-purple-500" />
            AI Attack Planner
          </h1>
          <p className="text-muted-foreground mt-1">
            Generate intelligent attack plans using graph-based path analysis and threat actor emulation. Plans are built from a 45+ node MITRE ATT&CK technique graph, then enhanced with LLM reasoning.
          </p>
        </div>
        <Dialog open={isGenerateDialogOpen} onOpenChange={setGenerateDialogOpen}>
          <DialogTrigger asChild>
            <Button size="lg" className="gap-2">
              <PlusCircle className="h-4 w-4" /> Generate Plan
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[700px]">
            <form onSubmit={handleGenerateSubmit}>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Brain className="h-5 w-5 text-purple-500" />
                  Generate Attack Plan
                </DialogTitle>
                <DialogDescription>
                  The planner builds a graph-based attack path from MITRE ATT&CK techniques, then uses AI to refine and contextualize the plan for your specific target.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-5 py-5">
                <div>
                  <Label htmlFor="name">Plan Name</Label>
                  <Input id="name" name="name" placeholder="e.g., Q1 Red Team — Corporate Network" className="mt-1.5" required />
                </div>
                <div>
                  <Label htmlFor="targetDescription">Target Description</Label>
                  <Textarea
                    id="targetDescription"
                    name="targetDescription"
                    placeholder="Describe the target: network topology, key assets, known defenses, OS landscape..."
                    className="mt-1.5 min-h-[100px]"
                    required
                  />
                </div>
                <div>
                  <Label>Threat Actor Profile</Label>
                  <Select name="threatActorProfile" required defaultValue="apt28">
                    <SelectTrigger className="mt-1.5">
                      <SelectValue placeholder="Select threat actor" />
                    </SelectTrigger>
                    <SelectContent>
                      {THREAT_ACTORS.map((actor) => (
                        <SelectItem key={actor.value} value={actor.value}>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{actor.label}</span>
                            <span className="text-xs text-muted-foreground">— {actor.origin}</span>
                          </div>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground mt-1">
                    The planner will emulate this actor's known TTPs, preferred techniques, and operational patterns.
                  </p>
                </div>
                <div>
                  <Label htmlFor="environmentContext">Environment Context (Optional)</Label>
                  <Textarea
                    id="environmentContext"
                    name="environmentContext"
                    placeholder="Windows AD domain, cloud (AWS/Azure), EDR deployed (CrowdStrike), SIEM (Splunk)..."
                    className="mt-1.5"
                  />
                </div>
                <div>
                  <Label htmlFor="constraints">Rules of Engagement (Optional)</Label>
                  <Textarea
                    id="constraints"
                    name="constraints"
                    placeholder="No destructive actions, avoid production databases, stealth priority..."
                    className="mt-1.5"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setGenerateDialogOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={generatePlanMutation.isPending} className="gap-2">
                  {generatePlanMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                  {generatePlanMutation.isPending ? "Generating..." : "Generate Plan"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Total Plans</p>
                <p className="text-3xl font-bold mt-1">{statsQuery.data?.total ?? 0}</p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-purple-500/10 flex items-center justify-center">
                <Brain className="h-5 w-5 text-purple-500" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Completed</p>
                <p className="text-3xl font-bold mt-1">{plans.filter(p => p.status === "completed").length}</p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-green-500/10 flex items-center justify-center">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Ready</p>
                <p className="text-3xl font-bold mt-1">{plans.filter(p => p.status === "ready").length}</p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <Play className="h-5 w-5 text-emerald-500" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-5 pb-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Threat Actors</p>
                <p className="text-3xl font-bold mt-1">{new Set(plans.map(p => p.threatActorProfile).filter(Boolean)).size || THREAT_ACTORS.length}</p>
              </div>
              <div className="h-10 w-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <Swords className="h-5 w-5 text-red-500" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Plans List */}
        <div className="lg:col-span-1 space-y-3">
          <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Attack Plans</h3>
          {plansQuery.isLoading && (
            <div className="flex items-center justify-center p-10">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          )}
          {plansQuery.isError && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{plansQuery.error.message}</AlertDescription>
            </Alert>
          )}
          {plans.length === 0 && !plansQuery.isLoading && (
            <Card className="border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-10 text-center">
                <Brain className="h-12 w-12 text-muted-foreground/30 mb-3" />
                <p className="text-sm text-muted-foreground">No attack plans yet.</p>
                <p className="text-xs text-muted-foreground mt-1">Click "Generate Plan" to create your first AI-powered attack plan.</p>
              </CardContent>
            </Card>
          )}
          {plans.map((plan) => {
            const isSelected = selectedPlanId === plan.id;
            const statusCfg = STATUS_CONFIG[plan.status] || STATUS_CONFIG.completed;
            const StatusIcon = statusCfg.icon;
            const actor = THREAT_ACTORS.find(a => a.value === plan.threatActorProfile);
            return (
              <Card
                key={plan.id}
                className={`cursor-pointer transition-all hover:border-primary/50 ${isSelected ? "border-primary ring-1 ring-primary/20" : ""}`}
                onClick={() => setSelectedPlanId(plan.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <h4 className="font-semibold text-sm truncate">{plan.name}</h4>
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">{plan.targetDescription}</p>
                    </div>
                    <Badge className={`${statusCfg.color} text-xs shrink-0`}>
                      <StatusIcon className={`h-3 w-3 mr-1 ${plan.status === "generating" ? "animate-spin" : ""}`} />
                      {plan.status}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3 mt-3">
                    {actor && (
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Swords className="h-3 w-3" /> {actor.label}
                      </span>
                    )}
                    {plan.estimatedRiskScore != null && (
                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                        <Target className="h-3 w-3" /> Risk: {plan.estimatedRiskScore}/10
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Plan Detail */}
        <div className="lg:col-span-2">
          {!selectedPlan ? (
            <Card className="h-full min-h-[400px] flex items-center justify-center">
              <CardContent className="text-center">
                <Network className="h-16 w-16 text-muted-foreground/20 mx-auto mb-4" />
                <p className="text-muted-foreground">Select a plan to view its attack path and details</p>
              </CardContent>
            </Card>
          ) : (
            <PlanDetail
              plan={selectedPlan}
              onAccept={() => acceptPlanMutation.mutate({ id: selectedPlan.id })}
              onDelete={() => {
                if (window.confirm("Delete this plan?")) {
                  deletePlanMutation.mutate({ id: selectedPlan.id });
                }
              }}
              isAccepting={acceptPlanMutation.isPending}
              isDeleting={deletePlanMutation.isPending}
              calderaOpId={calderaOpId}
            />
          )}
        </div>
      </div>
    </div>
    </AppShell>
  );
};

// ─── Plan Detail Component ─────────────────────────────────────────────────────
function PlanDetail({
  plan,
  onAccept,
  onDelete,
  isAccepting,
  isDeleting,
  calderaOpId,
}: {
  plan: AttackPlan;
  onAccept: () => void;
  onDelete: () => void;
  isAccepting: boolean;
  isDeleting: boolean;
  calderaOpId: string | null;
}) {
  const actor = THREAT_ACTORS.find(a => a.value === plan.threatActorProfile);

  // Parse attack steps
  let steps: PlanPhase[] = [];
  try {
    const raw = plan.attackSteps;
    if (typeof raw === "string") steps = JSON.parse(raw);
    else if (Array.isArray(raw)) steps = raw;
  } catch {}

  // Parse generated plan
  let planData: any = null;
  try {
    if (plan.generatedPlan) {
      planData = typeof plan.generatedPlan === "string" ? JSON.parse(plan.generatedPlan) : plan.generatedPlan;
    }
  } catch {}

  // Group steps by tactic for the kill chain view
  const tacticGroups = useMemo(() => {
    const groups: Record<string, PlanPhase[]> = {};
    for (const step of steps) {
      const tactic = step.tactic || "unknown";
      if (!groups[tactic]) groups[tactic] = [];
      groups[tactic].push(step);
    }
    return groups;
  }, [steps]);

  const tacticOrder = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
  ];

  const orderedTactics = tacticOrder.filter(t => tacticGroups[t]);

  return (
    <Card>
      <CardHeader className="pb-4">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="text-xl">{plan.name}</CardTitle>
            <CardDescription className="mt-1">{plan.targetDescription}</CardDescription>
          </div>
          <div className="flex gap-2">
            {plan.status === "completed" && (
              <Button size="sm" onClick={onAccept} disabled={isAccepting} className="gap-1">
                {isAccepting ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 className="h-3 w-3" />}
                Accept Plan
              </Button>
            )}
            <ExportPlanButton planId={plan.id} />
            <Button size="sm" variant="destructive" onClick={onDelete} disabled={isDeleting} className="gap-1">
              {isDeleting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
              Delete
            </Button>
          </div>
        </div>

        {/* Metadata Row */}
        <div className="flex flex-wrap gap-3 mt-4">
          {actor && (
            <Badge variant="outline" className="gap-1">
              <Swords className="h-3 w-3" /> {actor.label}
              <span className="text-muted-foreground ml-1">({actor.origin})</span>
            </Badge>
          )}
          {plan.estimatedRiskScore != null && (
            <Badge variant="outline" className={`gap-1 ${plan.estimatedRiskScore >= 8 ? "border-red-500/50 text-red-400" : plan.estimatedRiskScore >= 5 ? "border-yellow-500/50 text-yellow-400" : "border-green-500/50 text-green-400"}`}>
              <Target className="h-3 w-3" /> Risk Score: {plan.estimatedRiskScore}/10
            </Badge>
          )}
          <Badge variant="outline" className="gap-1">
            <Crosshair className="h-3 w-3" /> {steps.length} Techniques
          </Badge>
          <Badge variant="outline" className="gap-1">
            <Network className="h-3 w-3" /> {orderedTactics.length} Tactics
          </Badge>
        </div>
      </CardHeader>

      <CardContent>
        {/* Live Operation Progress Bar */}
        {(plan.status === "executing" || plan.status === "ready") && (
          <OperationProgressBar operationId={calderaOpId} planStatus={plan.status} />
        )}

        <Tabs defaultValue="killchain" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="killchain">Kill Chain</TabsTrigger>
            <TabsTrigger value="techniques">Techniques ({steps.length})</TabsTrigger>
            <TabsTrigger value="raw">Raw Plan</TabsTrigger>
          </TabsList>

          {/* Kill Chain View */}
          <TabsContent value="killchain" className="space-y-4">
            {orderedTactics.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                <p>No attack steps available. Plan may still be generating.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {orderedTactics.map((tactic, idx) => {
                  const techniques = tacticGroups[tactic];
                  const colorClass = TACTIC_COLORS[tactic] || "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
                  return (
                    <div key={tactic}>
                      <div className="flex items-center gap-2 mb-2">
                        {idx > 0 && (
                          <div className="flex items-center text-muted-foreground/40">
                            <ArrowRight className="h-4 w-4" />
                          </div>
                        )}
                        <Badge className={`${colorClass} border font-semibold uppercase text-xs tracking-wider`}>
                          {tactic.replace(/-/g, " ")}
                        </Badge>
                        <span className="text-xs text-muted-foreground">{techniques.length} technique{techniques.length > 1 ? "s" : ""}</span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 ml-6">
                        {techniques.map((tech, tIdx) => (
                          <div
                            key={`${tech.techniqueId}-${tIdx}`}
                            className="p-3 rounded-lg border bg-card hover:bg-accent/30 transition-colors"
                          >
                            <div className="flex items-center gap-2">
                              <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{tech.techniqueId}</code>
                              <span className="text-sm font-medium truncate">{tech.techniqueName}</span>
                            </div>
                            {tech.description && (
                              <p className="text-xs text-muted-foreground mt-1.5 line-clamp-2">{tech.description}</p>
                            )}
                            {tech.stealthRating != null && (
                              <div className="flex items-center gap-2 mt-2">
                                <span className="text-xs text-muted-foreground">Stealth:</span>
                                <Progress value={tech.stealthRating * 10} className="h-1.5 flex-1" />
                                <span className="text-xs font-mono">{tech.stealthRating}/10</span>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </TabsContent>

          {/* Techniques Table View */}
          <TabsContent value="techniques">
            <div className="space-y-2">
              {steps.map((step, idx) => {
                const colorClass = TACTIC_COLORS[step.tactic] || "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
                return (
                  <div key={idx} className="flex items-start gap-3 p-3 rounded-lg border bg-card">
                    <div className="flex items-center justify-center h-7 w-7 rounded-full bg-muted text-xs font-bold shrink-0">
                      {idx + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-xs font-mono bg-muted px-1.5 py-0.5 rounded">{step.techniqueId}</code>
                        <span className="text-sm font-medium">{step.techniqueName}</span>
                        <Badge className={`${colorClass} border text-xs`}>
                          {step.tactic?.replace(/-/g, " ")}
                        </Badge>
                      </div>
                      {step.description && (
                        <p className="text-xs text-muted-foreground mt-1">{step.description}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </TabsContent>

          {/* Raw Plan View */}
          <TabsContent value="raw">
            <div className="relative">
              <Button
                size="sm"
                variant="outline"
                className="absolute top-2 right-2 gap-1 z-10"
                onClick={() => {
                  navigator.clipboard.writeText(typeof plan.generatedPlan === "string" ? plan.generatedPlan : JSON.stringify(plan.generatedPlan, null, 2));
                  toast.success("Copied to clipboard");
                }}
              >
                <Copy className="h-3 w-3" /> Copy
              </Button>
              <pre className="p-4 bg-muted rounded-lg text-xs font-mono whitespace-pre-wrap max-h-[500px] overflow-y-auto">
                {typeof plan.generatedPlan === "string"
                  ? plan.generatedPlan
                  : JSON.stringify(plan.generatedPlan, null, 2)}
              </pre>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

// ─── Export Plan Button ───────────────────────────────────────────────────────
function ExportPlanButton({ planId }: { planId: number }) {
  const [isExporting, setIsExporting] = useState(false);
  const exportQuery = trpc.aiAttackPlanner.exportReport.useQuery(
    { id: planId },
    { enabled: false }
  );

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const result = await exportQuery.refetch();
      if (result.data) {
        exportToPdf(result.data.html, result.data.filename);
        toast.success("Report opened for PDF export");
      }
    } catch (err) {
      toast.error("Failed to generate report");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <Button size="sm" variant="outline" onClick={handleExport} disabled={isExporting} className="gap-1">
      {isExporting ? <Loader2 className="h-3 w-3 animate-spin" /> : <FileDown className="h-3 w-3" />}
      Export PDF
    </Button>
  );
}

function OperationProgressBar({ operationId, planStatus }: { operationId: string | null; planStatus: string }) {
  const statusQuery = trpc.aiAttackPlanner.operationStatus.useQuery(
    { operationId: operationId || "" },
    {
      enabled: !!operationId,
      refetchInterval: operationId ? 5000 : false, // Poll every 5s when active
    }
  );

  const status = statusQuery.data;

  if (!operationId) {
    return (
      <Alert className="mb-4 border-emerald-500/30 bg-emerald-500/5">
        <CheckCircle2 className="h-4 w-4 text-emerald-400" />
        <AlertTitle>Plan Accepted</AlertTitle>
        <AlertDescription>Caldera not configured — plan accepted locally. Set CALDERA_BASE_URL and CALDERA_API_KEY to enable live operations.</AlertDescription>
      </Alert>
    );
  }

  if (!status || statusQuery.isLoading) {
    return (
      <div className="mb-4 p-4 rounded-lg border bg-card">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">Connecting to Caldera operation...</span>
        </div>
      </div>
    );
  }

  const stateColors: Record<string, string> = {
    running: "text-orange-400",
    paused: "text-yellow-400",
    finished: "text-green-400",
    error: "text-red-400",
    unknown: "text-muted-foreground",
  };

  const progressColor = status.state === "finished" ? "bg-green-500" : status.state === "running" ? "bg-orange-500" : "bg-yellow-500";

  return (
    <div className="mb-4 p-4 rounded-lg border bg-card space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {status.state === "running" ? (
            <Zap className={`h-4 w-4 ${stateColors[status.state]} animate-pulse`} />
          ) : status.state === "finished" ? (
            <CheckCircle2 className={`h-4 w-4 ${stateColors[status.state]}`} />
          ) : status.state === "paused" ? (
            <Clock className={`h-4 w-4 ${stateColors[status.state]}`} />
          ) : (
            <AlertTriangle className={`h-4 w-4 ${stateColors[status.state] || stateColors.unknown}`} />
          )}
          <span className={`text-sm font-medium ${stateColors[status.state] || stateColors.unknown}`}>
            {status.operationName || "Caldera Operation"}
          </span>
          <Badge variant="outline" className="text-xs">{status.state?.toUpperCase()}</Badge>
        </div>
        <span className="text-xs text-muted-foreground">
          {status.completedAbilities}/{status.totalAbilities} abilities
        </span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-muted rounded-full h-2.5 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${progressColor}`}
          style={{ width: `${status.progress}%` }}
        />
      </div>

      {/* Ability Breakdown */}
      <div className="flex gap-4 text-xs">
        <span className="text-green-400">\u2713 {status.succeededAbilities || 0} succeeded</span>
        <span className="text-red-400">\u2717 {status.failedAbilities || 0} failed</span>
        <span className="text-muted-foreground">\u25CB {status.queuedAbilities || 0} queued</span>
      </div>

      {/* Status Message */}
      <p className="text-xs text-muted-foreground">{status.message}</p>

      {/* Ability List (collapsed by default, expandable) */}
      {status.abilities && status.abilities.length > 0 && (
        <details className="mt-2">
          <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
            View {status.abilities.length} ability details
          </summary>
          <div className="mt-2 space-y-1 max-h-60 overflow-y-auto">
            {status.abilities.map((ability: any, idx: number) => (
              <div key={idx} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/30">
                <span className={ability.status === "success" ? "text-green-400" : ability.status === "running" ? "text-orange-400 animate-pulse" : ability.status === "failed" || ability.status === "timeout" ? "text-red-400" : "text-muted-foreground"}>
                  {ability.status === "success" ? "\u2713" : ability.status === "running" ? "\u25CF" : ability.status === "failed" || ability.status === "timeout" ? "\u2717" : "\u25CB"}
                </span>
                <code className="font-mono text-[10px] bg-muted px-1 rounded">{ability.techniqueId || "—"}</code>
                <span className="truncate">{ability.abilityName}</span>
                {ability.paw && <span className="text-muted-foreground ml-auto">paw: {ability.paw}</span>}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

export default AiAttackPlannerPage;
