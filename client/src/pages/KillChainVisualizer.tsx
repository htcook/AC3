import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Workflow, ChevronRight, CheckCircle2, Circle, ArrowRight,
  Brain, Crosshair, ScanLine, Zap, Shield, Server, Database,
  ArrowUpDown, FileText, Trash2, Play, Clock
} from "lucide-react";
import AppShell from "@/components/AppShell";

/** Kill Chain Visualizer — Track engagement progress through the full attack lifecycle.
 *  This page provides a visual representation of your engagement's position in the kill chain,
 *  shows phase-by-phase progress, and uses AI to recommend when to advance to the next phase. */

const PHASE_ICONS: Record<string, any> = {
  pre_engagement: Clock,
  recon: Crosshair,
  scanning: ScanLine,
  gaining_access: Zap,
  maintaining_access: Shield,
  escalation: ArrowUpDown,
  lateral_movement: Server,
  collection: Database,
  exfiltration: ArrowUpDown,
  reporting: FileText,
  cleanup: Trash2,
};

const PHASE_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  pre_engagement: { bg: "bg-slate-500/20", border: "border-slate-500/50", text: "text-slate-300", glow: "shadow-slate-500/20" },
  recon: { bg: "bg-blue-500/20", border: "border-blue-500/50", text: "text-blue-300", glow: "shadow-blue-500/20" },
  scanning: { bg: "bg-cyan-500/20", border: "border-cyan-500/50", text: "text-cyan-300", glow: "shadow-cyan-500/20" },
  gaining_access: { bg: "bg-orange-500/20", border: "border-orange-500/50", text: "text-orange-300", glow: "shadow-orange-500/20" },
  maintaining_access: { bg: "bg-yellow-500/20", border: "border-yellow-500/50", text: "text-yellow-300", glow: "shadow-yellow-500/20" },
  escalation: { bg: "bg-red-500/20", border: "border-red-500/50", text: "text-red-300", glow: "shadow-red-500/20" },
  lateral_movement: { bg: "bg-purple-500/20", border: "border-purple-500/50", text: "text-purple-300", glow: "shadow-purple-500/20" },
  collection: { bg: "bg-indigo-500/20", border: "border-indigo-500/50", text: "text-indigo-300", glow: "shadow-indigo-500/20" },
  exfiltration: { bg: "bg-pink-500/20", border: "border-pink-500/50", text: "text-pink-300", glow: "shadow-pink-500/20" },
  reporting: { bg: "bg-emerald-500/20", border: "border-emerald-500/50", text: "text-emerald-300", glow: "shadow-emerald-500/20" },
  cleanup: { bg: "bg-teal-500/20", border: "border-teal-500/50", text: "text-teal-300", glow: "shadow-teal-500/20" },
};

export default function KillChainVisualizer() {
  // Using sonner toast
  const [currentPhase, setCurrentPhase] = useState("recon");
  const [phaseProgress, setPhaseProgress] = useState<Record<string, number>>({});

  // Queries
  const { data: killChain } = trpc.engagementWorkflow.killChain.useQuery();
  const { data: phases } = trpc.engagementWorkflow.phases.useQuery();

  // LLM readiness check
  const evaluateState = trpc.engagementWorkflow.evaluateState.useMutation({
    onSuccess: (data) => {
      toast.success(`Phase Analysis Complete — ${data.reasoning?.slice(0, 100) || "Analysis complete"}`);
    },
  });

  const allPhases = killChain?.phases || [];
  const currentIdx = allPhases.indexOf(currentPhase);

  const handleAdvancePhase = () => {
    if (currentIdx < allPhases.length - 1) {
      const nextPhase = allPhases[currentIdx + 1];
      setPhaseProgress(prev => ({ ...prev, [currentPhase]: 100 }));
      setCurrentPhase(nextPhase);
      toast.success(`Phase Advanced — Now in: ${nextPhase.replace(/_/g, " ").toUpperCase()}`);
    }
  };

  const handleEvaluate = () => {
    const progress: Record<string, any> = {};
    for (const p of allPhases) progress[p] = phaseProgress[p] || 0;
    evaluateState.mutate({
      currentPhase,
      engagementData: { phaseProgress: progress },
    });
  };

  const overallProgress = useMemo(() => {
    if (allPhases.length === 0) return 0;
    const total = allPhases.reduce((sum, p) => sum + (phaseProgress[p] || 0), 0);
    return Math.round(total / allPhases.length);
  }, [allPhases, phaseProgress]);

  return (
      <AppShell activePath="/kill-chain">
      <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Workflow className="w-7 h-7 text-purple-400" />
          Kill Chain Visualizer
        </h1>
        <p className="text-muted-foreground mt-1">
          Track your engagement through the full attack lifecycle. The AI advisor analyzes your progress and recommends when to advance to the next phase based on findings, coverage, and objectives.
        </p>
      </div>

      {/* Overall Progress */}
      <Card className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 border-purple-500/30">
        <CardContent className="py-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">Overall Engagement Progress</span>
            <span className="text-sm text-muted-foreground">{overallProgress}%</span>
          </div>
          <Progress value={overallProgress} className="h-2" />
          <div className="flex items-center justify-between mt-2">
            <span className="text-xs text-muted-foreground">
              Current Phase: <span className="text-primary font-medium">{currentPhase.replace(/_/g, " ").toUpperCase()}</span>
            </span>
            <span className="text-xs text-muted-foreground">
              {currentIdx + 1} of {allPhases.length} phases
            </span>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="chain" className="space-y-4">
        <TabsList className="bg-background/50 border">
          <TabsTrigger value="chain"><Workflow className="w-4 h-4 mr-1" />KILL CHAIN</TabsTrigger>
          <TabsTrigger value="details"><FileText className="w-4 h-4 mr-1" />PHASE DETAILS</TabsTrigger>
          <TabsTrigger value="advisor"><Brain className="w-4 h-4 mr-1" />AI ADVISOR</TabsTrigger>
        </TabsList>

        {/* Kill Chain Visual Tab */}
        <TabsContent value="chain" className="space-y-4">
          {/* Horizontal Chain */}
          <Card>
            <CardContent className="py-6">
              <div className="flex items-center overflow-x-auto pb-2 gap-1">
                {allPhases.map((phase, idx) => {
                  const Icon = PHASE_ICONS[phase] || Circle;
                  const colors = PHASE_COLORS[phase] || PHASE_COLORS.recon;
                  const isActive = phase === currentPhase;
                  const isComplete = (phaseProgress[phase] || 0) >= 100;
                  const isPast = idx < currentIdx;
                  return (
                    <div key={phase} className="flex items-center shrink-0">
                      <button
                        onClick={() => setCurrentPhase(phase)}
                        className={`relative flex flex-col items-center p-3 rounded-xl border-2 transition-all min-w-[90px]
                          ${isActive ? `${colors.bg} ${colors.border} shadow-lg ${colors.glow}` :
                            isComplete || isPast ? "bg-emerald-500/10 border-emerald-500/40" :
                            "bg-card/50 border-border/30 opacity-60 hover:opacity-100"}`}
                      >
                        {isComplete || isPast ? (
                          <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                        ) : (
                          <Icon className={`w-6 h-6 ${isActive ? colors.text : "text-muted-foreground"}`} />
                        )}
                        <span className={`text-[10px] mt-1 font-medium text-center leading-tight ${isActive ? colors.text : ""}`}>
                          {phase.replace(/_/g, " ").toUpperCase()}
                        </span>
                        {isActive && (
                          <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-primary animate-pulse" />
                        )}
                      </button>
                      {idx < allPhases.length - 1 && (
                        <ArrowRight className={`w-4 h-4 mx-1 shrink-0 ${isPast ? "text-emerald-400" : "text-muted-foreground/30"}`} />
                      )}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Phase Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {allPhases.map((phase, idx) => {
              const Icon = PHASE_ICONS[phase] || Circle;
              const colors = PHASE_COLORS[phase] || PHASE_COLORS.recon;
              const isActive = phase === currentPhase;
              const progress = phaseProgress[phase] || 0;
              const phaseDef = phases?.find((p: any) => p.id === phase || p.phase === phase);
              return (
                <Card key={phase} className={`transition-all ${isActive ? `ring-2 ring-primary/50 ${colors.bg}` : ""}`}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Icon className={`w-4 h-4 ${colors.text}`} />
                      {phase.replace(/_/g, " ").toUpperCase()}
                      {isActive && <Badge className="text-xs bg-primary/20 text-primary">ACTIVE</Badge>}
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <Progress value={progress} className="h-1.5" />
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>{progress}% complete</span>
                      <button
                        onClick={() => setPhaseProgress(prev => ({
                          ...prev,
                          [phase]: Math.min(100, (prev[phase] || 0) + 25)
                        }))}
                        className="text-primary hover:underline"
                      >
                        +25%
                      </button>
                    </div>
                    {phaseDef?.description && (
                      <p className="text-xs text-muted-foreground">{phaseDef.description}</p>
                    )}
                    {phaseDef?.objectives && (
                      <div className="space-y-1 mt-2">
                        {phaseDef.objectives.slice(0, 3).map((obj: string, i: number) => (
                          <div key={i} className="text-xs flex items-start gap-1">
                            <ChevronRight className="w-3 h-3 text-muted-foreground mt-0.5 shrink-0" />
                            <span>{obj}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        {/* Phase Details Tab */}
        <TabsContent value="details" className="space-y-4">
          {phases && phases.length > 0 ? (
            <div className="space-y-4">
              {phases.map((phaseDef: any) => {
                const phaseId = phaseDef.id || phaseDef.phase;
                const Icon = PHASE_ICONS[phaseId] || Circle;
                const colors = PHASE_COLORS[phaseId] || PHASE_COLORS.recon;
                return (
                  <Card key={phaseId}>
                    <CardHeader>
                      <CardTitle className="text-base flex items-center gap-2">
                        <Icon className={`w-5 h-5 ${colors.text}`} />
                        {phaseDef.name || phaseId.replace(/_/g, " ").toUpperCase()}
                      </CardTitle>
                      {phaseDef.description && <CardDescription>{phaseDef.description}</CardDescription>}
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {phaseDef.objectives && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">Objectives:</span>
                          <div className="mt-1 space-y-1">
                            {phaseDef.objectives.map((obj: string, i: number) => (
                              <div key={i} className="text-sm flex items-start gap-2">
                                <Circle className="w-3 h-3 mt-1 shrink-0 text-muted-foreground" />
                                <span>{obj}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {phaseDef.tools && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">Recommended Tools:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {phaseDef.tools.map((tool: string, i: number) => (
                              <Badge key={i} variant="secondary" className="text-xs">{tool}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                      {phaseDef.autoHandoffTriggers && (
                        <div>
                          <span className="text-xs font-medium text-yellow-400">Auto-Handoff Triggers:</span>
                          <div className="mt-1 space-y-1">
                            {phaseDef.autoHandoffTriggers.map((trigger: any, i: number) => (
                              <div key={i} className="text-xs text-muted-foreground flex items-start gap-1">
                                <Zap className="w-3 h-3 text-yellow-400 mt-0.5 shrink-0" />
                                <span>{trigger.description || `Min findings: ${trigger.minFindings}`}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading phase definitions...</div>
          )}
        </TabsContent>

        {/* AI Advisor Tab */}
        <TabsContent value="advisor" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Brain className="w-5 h-5 text-purple-400" />
                AI Phase Advisor
              </CardTitle>
              <CardDescription>
                The AI analyzes your current engagement state and recommends whether to continue in the current phase or advance to the next one.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Button onClick={handleEvaluate} className="bg-purple-600 hover:bg-purple-700" disabled={evaluateState.isPending}>
                  <Brain className="w-4 h-4 mr-1" />
                  {evaluateState.isPending ? "Analyzing..." : "Evaluate Current Phase"}
                </Button>
                <Button onClick={handleAdvancePhase} variant="outline" disabled={currentIdx >= allPhases.length - 1}>
                  <Play className="w-4 h-4 mr-1" />
                  Advance to Next Phase
                </Button>
              </div>

              {evaluateState.data && (
                <div className="p-4 rounded-lg bg-purple-500/10 border border-purple-500/30 space-y-3">
                  <div className="flex items-center gap-2">
                    <Brain className="w-5 h-5 text-purple-400" />
                    <span className="font-medium">AI Recommendation</span>
                  </div>
                  {evaluateState.data.reasoning && (
                    <p className="text-sm">{evaluateState.data.reasoning}</p>
                  )}
                  {evaluateState.data.recommendedActions && (
                    <div>
                      <span className="text-xs font-medium text-muted-foreground">Recommended Actions:</span>
                      <div className="mt-1 space-y-1">
                        {evaluateState.data.recommendedActions.map((action: any, i: number) => (
                          <div key={i} className="text-sm flex items-start gap-2">
                            <ChevronRight className="w-3 h-3 text-purple-400 mt-1 shrink-0" />
                            <span>{typeof action === "string" ? action : action.description || action.action}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
