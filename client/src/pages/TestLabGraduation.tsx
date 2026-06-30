import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  GraduationCap, TrendingUp, RefreshCw, Brain, Target,
  CheckCircle2, ArrowUp, Clock, Star, Zap,
} from "lucide-react";

const MODEL_LABELS: Record<string, string> = {
  recon_analyst: "Recon Analyst",
  exploit_selector: "Exploit Selector",
  evasion_optimizer: "Evasion Optimizer",
  lateral_planner: "Lateral Planner",
  persistence_engineer: "Persistence Engineer",
  cognitive_core: "Cognitive Core",
};

const TIER_LABELS: Record<number, string> = {
  1: "Novice",
  2: "Apprentice",
  3: "Operator",
  4: "Expert",
  5: "Master",
};

const TIER_COLORS: Record<number, string> = {
  1: "bg-slate-500",
  2: "bg-blue-500",
  3: "bg-amber-500",
  4: "bg-purple-500",
  5: "bg-red-500",
};

export default function TestLabGraduation() {
  // toast from sonner is already imported
  const { data: graduation, isLoading, refetch } = trpc.testLab.getGraduationStatus.useQuery();
  const { data: events } = trpc.testLab.getGraduationEvents.useQuery();
  const { data: recommendations } = trpc.testLab.getRecommendedScenarios.useQuery();

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center gap-3">
          <GraduationCap className="h-8 w-8 text-amber-400" />
          <h1 className="text-2xl font-bold">Graduation Engine</h1>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map(i => (
            <Card key={i} className="animate-pulse"><CardContent className="p-6"><div className="h-32 bg-muted rounded" /></CardContent></Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-500/10 rounded-lg">
            <GraduationCap className="h-7 w-7 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Graduation Engine</h1>
            <p className="text-muted-foreground">
              Track model progression through tiers — lab performance drives graduation
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-amber-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Average Tier</p>
                <p className="text-3xl font-bold">
                  {graduation?.modelStates?.length
                    ? (graduation.modelStates.reduce((s: number, m: any) => s + (m.currentTier ?? 1), 0) / graduation.modelStates.length).toFixed(1)
                    : "1.0"}
                </p>
              </div>
              <Star className="h-8 w-8 text-amber-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-emerald-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Graduations</p>
                <p className="text-3xl font-bold">{events?.length ?? 0}</p>
              </div>
              <ArrowUp className="h-8 w-8 text-emerald-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Models at Tier 4+</p>
                <p className="text-3xl font-bold">
                  {graduation?.modelStates?.filter((m: any) => (m.currentTier ?? 1) >= 4).length ?? 0}
                </p>
              </div>
              <Brain className="h-8 w-8 text-blue-400 opacity-50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Model Tier Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {graduation?.modelStates?.map((state: any) => (
          <Card key={state.model} className="overflow-hidden">
            <div className={`h-1 ${TIER_COLORS[state.currentTier ?? 1]}`} />
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="font-medium">{MODEL_LABELS[state.model] || state.model}</h3>
                  <p className="text-xs text-muted-foreground">
                    {TIER_LABELS[state.currentTier ?? 1]} — Tier {state.currentTier ?? 1}
                  </p>
                </div>
                <div className={`w-10 h-10 rounded-full ${TIER_COLORS[state.currentTier ?? 1]} flex items-center justify-center text-white font-bold`}>
                  {state.currentTier ?? 1}
                </div>
              </div>

              <div className="space-y-2 mb-3">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Scenarios</span>
                  <span>{state.scenariosCompleted ?? 0} completed</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Avg Score</span>
                  <span className={`font-medium ${
                    (state.averageScore ?? 0) >= 80 ? "text-emerald-400" :
                    (state.averageScore ?? 0) >= 60 ? "text-amber-400" : "text-red-400"
                  }`}>{state.averageScore ?? 0}%</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Benchmarks</span>
                  <span>{state.benchmarksRun ?? 0} run</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Lab Access</span>
                  <Badge variant="outline" className="text-xs">{state.labAccess ?? "basic"}</Badge>
                </div>
              </div>

              {/* Tier Progress */}
              <div className="mt-3">
                <div className="flex gap-1 mb-1">
                  {[1, 2, 3, 4, 5].map(tier => (
                    <div
                      key={tier}
                      className={`h-3 flex-1 rounded-sm transition-all ${
                        tier <= (state.currentTier ?? 1) ? TIER_COLORS[tier] : "bg-muted"
                      }`}
                    />
                  ))}
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Novice</span>
                  <span>Master</span>
                </div>
              </div>

              {/* Next tier requirements */}
              {(state.currentTier ?? 1) < 5 && state.nextTierRequirements && (
                <div className="mt-3 p-2 bg-muted/30 rounded text-xs">
                  <p className="text-muted-foreground mb-1">Next tier requires:</p>
                  <ul className="space-y-0.5">
                    {state.nextTierRequirements.map((req: string, idx: number) => (
                      <li key={idx} className="flex items-center gap-1">
                        <span className="w-1 h-1 rounded-full bg-muted-foreground" />
                        {req}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>
        )) ?? (
          <Card className="col-span-3">
            <CardContent className="p-12 text-center">
              <GraduationCap className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
              <p className="text-muted-foreground">No model states yet. Run lab scenarios to begin graduation tracking.</p>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Recommended Scenarios */}
      {recommendations?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-amber-400" />
              Recommended Next Scenarios
            </CardTitle>
            <CardDescription>Based on current model tiers and performance gaps</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recommendations.map((rec: any) => (
                <div key={rec.scenarioId} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                  <div>
                    <p className="text-sm font-medium">{rec.scenarioName || rec.scenarioId}</p>
                    <p className="text-xs text-muted-foreground">
                      For: {MODEL_LABELS[rec.model] || rec.model} — {rec.reason}
                    </p>
                  </div>
                  <Badge variant="outline">{rec.difficulty}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Graduation Events Timeline */}
      {events?.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Graduation Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {events.slice(0, 10).map((event: any) => (
                <div key={event.id} className="flex items-center gap-3 p-2 bg-muted/20 rounded">
                  <div className={`w-8 h-8 rounded-full ${TIER_COLORS[event.newTier ?? 1]} flex items-center justify-center text-white text-xs font-bold`}>
                    {event.newTier ?? "?"}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm">
                      <span className="font-medium">{MODEL_LABELS[event.model] || event.model}</span>
                      {" "}graduated to{" "}
                      <span className="font-medium">Tier {event.newTier}</span>
                      {" "}({TIER_LABELS[event.newTier ?? 1]})
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(event.timestamp).toLocaleString()} — {event.reason}
                    </p>
                  </div>
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
