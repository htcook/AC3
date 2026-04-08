import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Shield,
  Target,
  Clock,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Circle,
  Crosshair,
  Bug,
  Zap,
  DollarSign,
  AlertTriangle,
  BookOpen,
  Wrench,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AttackPlaybookPanelProps {
  engagementId: number;
}

export function AttackPlaybookPanel({ engagementId }: AttackPlaybookPanelProps) {
  const { toast } = useToast();
  const [expandedPhases, setExpandedPhases] = useState<Set<string>>(new Set());
  const [expandedTests, setExpandedTests] = useState<Set<string>>(new Set());
  const [completedTests, setCompletedTests] = useState<Set<string>>(new Set());

  const { data: playbook, isLoading } = trpc.bugBounty.getAttackPlaybook.useQuery({
    engagementId,
  });

  const { data: stats } = trpc.bugBounty.getPlaybookStats.useQuery();

  const togglePhase = (id: string) => {
    setExpandedPhases((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleTest = (id: string) => {
    setExpandedTests((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleCompleted = (id: string) => {
    setCompletedTests((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const priorityColor = (p: string) => {
    switch (p) {
      case "critical": return "bg-red-500/10 text-red-400 border-red-500/30";
      case "high": return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "medium": return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      case "low": return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const severityIcon = (s: string) => {
    switch (s) {
      case "critical": return <AlertTriangle className="h-3.5 w-3.5 text-red-400" />;
      case "high": return <Zap className="h-3.5 w-3.5 text-orange-400" />;
      case "medium": return <Bug className="h-3.5 w-3.5 text-yellow-400" />;
      case "low": return <Circle className="h-3.5 w-3.5 text-blue-400" />;
      default: return <Circle className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="h-32 bg-muted/50 animate-pulse rounded-lg" />
        <div className="h-48 bg-muted/50 animate-pulse rounded-lg" />
      </div>
    );
  }

  if (!playbook) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <BookOpen className="h-12 w-12 text-muted-foreground/50 mb-4" />
          <p className="text-muted-foreground">No attack playbook available</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Playbook Header Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <Target className="h-3.5 w-3.5" /> Phases
            </div>
            <div className="text-2xl font-bold">{playbook.totalPhases}</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <Crosshair className="h-3.5 w-3.5" /> Test Cases
            </div>
            <div className="text-2xl font-bold">
              {playbook.totalTestCases}
              <span className="text-sm font-normal text-muted-foreground ml-1">
                ({completedTests.size} done)
              </span>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <Clock className="h-3.5 w-3.5" /> Est. Hours
            </div>
            <div className="text-2xl font-bold">{playbook.estimatedTotalHours}h</div>
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
              <DollarSign className="h-3.5 w-3.5" /> Max Bounty
            </div>
            <div className="text-2xl font-bold text-emerald-400">
              ${playbook.maxBounty.toLocaleString()}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Stats Bar */}
      {stats && (
        <Card className="bg-card/50">
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-4 text-sm">
              <span className="text-muted-foreground">
                <Shield className="h-3.5 w-3.5 inline mr-1" />
                {stats.uniqueAttackTechniques} ATT&CK Techniques
              </span>
              <span className="text-muted-foreground">
                <Bug className="h-3.5 w-3.5 inline mr-1" />
                {stats.uniqueCwes} Target CWEs
              </span>
              <span className="text-muted-foreground">
                <Zap className="h-3.5 w-3.5 inline mr-1" />
                {stats.automatedTestCases} Automated / {stats.manualTestCases} Manual
              </span>
              <span className="text-muted-foreground">
                <DollarSign className="h-3.5 w-3.5 inline mr-1" />
                Total Range: ${stats.totalBountyRange.min.toLocaleString()} – ${stats.totalBountyRange.max.toLocaleString()}
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Attack Phases */}
      <div className="space-y-3">
        {playbook.phases.map((phase: any, idx: number) => {
          const isExpanded = expandedPhases.has(phase.id);
          const phaseCompleted = phase.testCases.every((tc: any) => completedTests.has(tc.id));
          const phaseProgress = phase.testCases.filter((tc: any) => completedTests.has(tc.id)).length;

          return (
            <Card key={phase.id} className={`transition-colors ${phaseCompleted ? "border-emerald-500/30 bg-emerald-500/5" : ""}`}>
              <Collapsible open={isExpanded} onOpenChange={() => togglePhase(phase.id)}>
                <CollapsibleTrigger asChild>
                  <CardHeader className="cursor-pointer hover:bg-muted/30 transition-colors py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div className="flex items-center gap-2 mt-0.5">
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" />
                          )}
                          <span className="text-xs font-mono text-muted-foreground">
                            {String(idx + 1).padStart(2, "0")}
                          </span>
                        </div>
                        <div>
                          <CardTitle className="text-base">{phase.name}</CardTitle>
                          <CardDescription className="mt-1 text-xs line-clamp-2">
                            {phase.description}
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge variant="outline" className={priorityColor(phase.priority)}>
                          {phase.priority}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {phaseProgress}/{phase.testCases.length}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {phase.estimatedHours}h
                        </Badge>
                        <Badge variant="outline" className="text-xs text-emerald-400 border-emerald-500/30">
                          ${phase.bountyRange.min}–${phase.bountyRange.max}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                </CollapsibleTrigger>

                <CollapsibleContent>
                  <CardContent className="pt-0 space-y-4">
                    <Tabs defaultValue="tests" className="w-full">
                      <TabsList className="h-8">
                        <TabsTrigger value="tests" className="text-xs h-7">
                          Test Cases ({phase.testCases.length})
                        </TabsTrigger>
                        <TabsTrigger value="techniques" className="text-xs h-7">
                          ATT&CK ({phase.attackTechniques.length})
                        </TabsTrigger>
                        <TabsTrigger value="cwes" className="text-xs h-7">
                          CWEs ({phase.targetCwes.length})
                        </TabsTrigger>
                        <TabsTrigger value="tools" className="text-xs h-7">
                          Tools
                        </TabsTrigger>
                      </TabsList>

                      <TabsContent value="tests" className="mt-3 space-y-2">
                        {phase.testCases.map((tc: any) => {
                          const isTestExpanded = expandedTests.has(tc.id);
                          const isDone = completedTests.has(tc.id);

                          return (
                            <div
                              key={tc.id}
                              className={`border rounded-lg transition-colors ${isDone ? "border-emerald-500/30 bg-emerald-500/5" : "border-border"}`}
                            >
                              <div className="flex items-center gap-3 p-3">
                                <button
                                  onClick={(e) => { e.stopPropagation(); toggleCompleted(tc.id); }}
                                  className="shrink-0"
                                >
                                  {isDone ? (
                                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                                  ) : (
                                    <Circle className="h-5 w-5 text-muted-foreground hover:text-foreground transition-colors" />
                                  )}
                                </button>
                                <button
                                  onClick={() => toggleTest(tc.id)}
                                  className="flex-1 text-left"
                                >
                                  <div className="flex items-center gap-2">
                                    <span className={`text-sm font-medium ${isDone ? "line-through text-muted-foreground" : ""}`}>
                                      {tc.name}
                                    </span>
                                    {severityIcon(tc.severity)}
                                    {tc.automated && (
                                      <Badge variant="outline" className="text-[10px] h-4 px-1 bg-blue-500/10 text-blue-400 border-blue-500/30">
                                        AUTO
                                      </Badge>
                                    )}
                                    {tc.burpProfile && (
                                      <Badge variant="outline" className="text-[10px] h-4 px-1 bg-purple-500/10 text-purple-400 border-purple-500/30">
                                        BURP
                                      </Badge>
                                    )}
                                  </div>
                                  <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                                    {tc.description}
                                  </p>
                                </button>
                                <button onClick={() => toggleTest(tc.id)} className="shrink-0">
                                  {isTestExpanded ? (
                                    <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                  ) : (
                                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                                  )}
                                </button>
                              </div>

                              {isTestExpanded && (
                                <div className="px-3 pb-3 pt-0 border-t border-border/50 mt-1">
                                  <div className="mt-3 space-y-3">
                                    <div>
                                      <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
                                        Steps
                                      </h5>
                                      <ol className="space-y-1">
                                        {tc.steps.map((step: string, i: number) => (
                                          <li key={i} className="text-xs text-muted-foreground flex gap-2">
                                            <span className="text-foreground/50 shrink-0">{i + 1}.</span>
                                            <span>{step}</span>
                                          </li>
                                        ))}
                                      </ol>
                                    </div>
                                    <div>
                                      <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                                        Expected Result
                                      </h5>
                                      <p className="text-xs text-emerald-400">{tc.expectedResult}</p>
                                    </div>
                                    {tc.burpProfile && (
                                      <div className="text-xs text-muted-foreground">
                                        <Wrench className="h-3 w-3 inline mr-1" />
                                        Covered by Burp scan profile: <code className="text-purple-400">{tc.burpProfile}</code>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </TabsContent>

                      <TabsContent value="techniques" className="mt-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {phase.attackTechniques.map((t: any) => (
                            <div key={t.id} className="flex items-center gap-2 p-2 rounded border border-border/50 text-xs">
                              <Badge variant="outline" className="font-mono text-[10px] shrink-0">
                                {t.id}
                              </Badge>
                              <span className="truncate">{t.name}</span>
                              <span className="text-muted-foreground ml-auto shrink-0">{t.tactic}</span>
                            </div>
                          ))}
                        </div>
                      </TabsContent>

                      <TabsContent value="cwes" className="mt-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {phase.targetCwes.map((c: any) => (
                            <div key={c.id} className="flex items-center gap-2 p-2 rounded border border-border/50 text-xs">
                              <Badge variant="outline" className={`font-mono text-[10px] shrink-0 ${priorityColor(c.severity)}`}>
                                {c.id}
                              </Badge>
                              <span className="truncate">{c.name}</span>
                            </div>
                          ))}
                        </div>
                      </TabsContent>

                      <TabsContent value="tools" className="mt-3">
                        <div className="flex flex-wrap gap-2">
                          {phase.tools.map((tool: string) => (
                            <Badge key={tool} variant="outline" className="text-xs">
                              <Wrench className="h-3 w-3 mr-1" />
                              {tool}
                            </Badge>
                          ))}
                        </div>
                        <div className="mt-3">
                          <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
                            Target Components
                          </h5>
                          <div className="flex flex-wrap gap-1.5">
                            {phase.targetComponents.map((comp: string) => (
                              <code key={comp} className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                                {comp}
                              </code>
                            ))}
                          </div>
                        </div>
                        <div className="mt-3">
                          <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1.5">
                            Prerequisites
                          </h5>
                          <ul className="space-y-1">
                            {phase.prerequisites.map((p: string, i: number) => (
                              <li key={i} className="text-xs text-muted-foreground flex items-center gap-1.5">
                                <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                                {p}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </CollapsibleContent>
              </Collapsible>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
