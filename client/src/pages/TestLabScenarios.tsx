import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Target, Play, RefreshCw, Shield, Skull, Radio, Eye,
  GraduationCap, Clock, CheckCircle2, XCircle, AlertTriangle,
  ChevronDown, ChevronUp, Zap,
} from "lucide-react";

const CATEGORY_ICONS: Record<string, any> = {
  deployment: Skull,
  c2_communication: Radio,
  operational: Target,
  stealth: Eye,
  training: GraduationCap,
  graduation: GraduationCap,
};

const CATEGORY_COLORS: Record<string, string> = {
  deployment: "text-red-400",
  c2_communication: "text-blue-400",
  operational: "text-amber-400",
  stealth: "text-purple-400",
  training: "text-emerald-400",
  graduation: "text-yellow-400",
};

export default function TestLabScenarios() {
  // toast from sonner is already imported
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedEnv, setSelectedEnv] = useState("");
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null);

  const { data: scenarios, isLoading } = trpc.testLab.listScenarios.useQuery();
  const { data: environments } = trpc.testLab.listEnvironments.useQuery();
  const runScenario = trpc.testLab.runScenario.useMutation({
    onSuccess: (data) => {
      toast.success(`Scenario Started: Running ${data.scenarioId || "scenario"}...`);
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredScenarios = scenarios?.filter((s: any) =>
    selectedCategory === "all" || s.category === selectedCategory
  ) ?? [];

  const categories = [...new Set(scenarios?.map((s: any) => s.category) ?? [])];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-500/10 rounded-lg">
            <Target className="h-7 w-7 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Attack Scenarios</h1>
            <p className="text-muted-foreground">Pre-built scenarios for Ember testing, C2 validation, and model training</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <Select value={selectedCategory} onValueChange={setSelectedCategory}>
          <SelectTrigger className="w-48"><SelectValue placeholder="Category" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {categories.map((cat: string) => (
              <SelectItem key={cat} value={cat}>{cat.replace(/_/g, " ")}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={selectedEnv} onValueChange={setSelectedEnv}>
          <SelectTrigger className="w-64"><SelectValue placeholder="Select environment..." /></SelectTrigger>
          <SelectContent>
            {environments?.filter((e: any) => e.state === "running").map((env: any) => (
              <SelectItem key={env.id} value={env.id}>{env.name}</SelectItem>
            )) ?? []}
            {(!environments || environments.filter((e: any) => e.state === "running").length === 0) && (
              <SelectItem value="none" disabled>No running environments</SelectItem>
            )}
          </SelectContent>
        </Select>
      </div>

      {/* Scenario Cards */}
      <div className="space-y-3">
        {isLoading ? (
          [1, 2, 3].map(i => (
            <Card key={i} className="animate-pulse">
              <CardContent className="p-6"><div className="h-20 bg-muted rounded" /></CardContent>
            </Card>
          ))
        ) : filteredScenarios.length > 0 ? (
          filteredScenarios.map((scenario: any) => {
            const Icon = CATEGORY_ICONS[scenario.category] || Target;
            const colorClass = CATEGORY_COLORS[scenario.category] || "text-muted-foreground";
            const isExpanded = expandedScenario === scenario.id;

            return (
              <Card key={scenario.id} className="hover:border-muted-foreground/30 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <Icon className={`h-5 w-5 mt-0.5 ${colorClass}`} />
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="font-medium">{scenario.name}</h3>
                          <Badge variant="outline" className="text-xs">{scenario.category?.replace(/_/g, " ")}</Badge>
                          <Badge variant={
                            scenario.difficulty === "advanced" ? "destructive" :
                            scenario.difficulty === "intermediate" ? "default" : "secondary"
                          } className="text-xs">
                            {scenario.difficulty}
                          </Badge>
                          {scenario.requiredTier && (
                            <Badge variant="outline" className="text-xs">
                              <GraduationCap className="h-3 w-3 mr-1" />
                              Tier {scenario.requiredTier}+
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground">{scenario.description}</p>

                        {isExpanded && (
                          <div className="mt-3 space-y-3">
                            {scenario.phases?.length > 0 && (
                              <div>
                                <p className="text-xs font-medium mb-1">Phases:</p>
                                <div className="space-y-1">
                                  {scenario.phases.map((phase: any, idx: number) => (
                                    <div key={idx} className="flex items-center gap-2 text-xs">
                                      <span className="w-5 h-5 rounded-full bg-muted flex items-center justify-center text-xs">{idx + 1}</span>
                                      <span>{phase.name || phase}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {scenario.scoringRubric && (
                              <div>
                                <p className="text-xs font-medium mb-1">Scoring Rubric:</p>
                                <div className="grid grid-cols-2 gap-1">
                                  {Object.entries(scenario.scoringRubric).map(([key, val]: [string, any]) => (
                                    <div key={key} className="flex justify-between text-xs p-1 bg-muted/30 rounded">
                                      <span className="text-muted-foreground">{key.replace(/_/g, " ")}</span>
                                      <span className="font-mono">{val}pts</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setExpandedScenario(isExpanded ? null : scenario.id)}
                      >
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </Button>
                      <Button
                        size="sm"
                        disabled={!selectedEnv || runScenario.isPending}
                        onClick={() => runScenario.mutate({
                          scenarioId: scenario.id,
                          environmentId: selectedEnv,
                        })}
                      >
                        <Play className="h-4 w-4 mr-1" /> Run
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })
        ) : (
          <Card>
            <CardContent className="p-12 text-center">
              <Target className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
              <p className="text-muted-foreground">No scenarios found for the selected category.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
