import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Target, Play, RefreshCw, Shield, Skull, Radio, Eye,
  GraduationCap, Clock, CheckCircle2, XCircle, AlertTriangle,
  ChevronDown, ChevronUp, Zap, Server, Globe, Activity,
  Monitor, Cpu, Bug, ExternalLink, Wifi, WifiOff, Cloud,
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

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

export default function TestLabScenarios() {
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [selectedEnv, setSelectedEnv] = useState("");
  const [expandedScenario, setExpandedScenario] = useState<string | null>(null);
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);
  const [healthChecks, setHealthChecks] = useState<Record<string, { status: string; checkedAt: number }>>({});
  const [checkingHealth, setCheckingHealth] = useState<string | null>(null);

  const { data: scenarios, isLoading } = trpc.testLab.listScenarios.useQuery();
  const { data: environments } = trpc.testLab.listEnvironments.useQuery();
  const { data: liveTargets, isLoading: loadingTargets } = trpc.testLab.getLiveTargets.useQuery();
  const { data: labTemplates } = trpc.testLab.getLabTemplates.useQuery();

  const checkHealth = trpc.testLab.checkTargetHealth.useMutation({
    onSuccess: (data) => {
      setHealthChecks(prev => ({ ...prev, [data.targetId]: { status: data.status, checkedAt: data.checkedAt } }));
      setCheckingHealth(null);
      toast.success(`${data.targetId}: ${data.status === "online" ? "Online" : "Offline"}`);
    },
    onError: (err) => {
      setCheckingHealth(null);
      toast.error(err.message);
    },
  });

  const runScenario = trpc.testLab.runScenario.useMutation({
    onSuccess: (data) => {
      toast.success(`Scenario Started: Running ${data.scenarioId || "scenario"}...`);
    },
    onError: (err) => toast.error(err.message),
  });

  const provisionEnv = trpc.testLab.provisionEnvironment.useMutation({
    onSuccess: (data) => {
      toast.success(`Environment provisioned: ${data.name || data.id}`);
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredScenarios = scenarios?.filter((s: any) =>
    selectedCategory === "all" || s.category === selectedCategory
  ) ?? [];

  const categories = [...new Set(scenarios?.map((s: any) => s.category) ?? [])];

  const runningEnvs = useMemo(() =>
    environments?.filter((e: any) => e.state === "running") ?? [],
    [environments]
  );

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-500/10 rounded-lg">
            <Target className="h-7 w-7 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Attack Scenarios</h1>
            <p className="text-muted-foreground">Live targets, lab environments, and pre-built attack scenarios</p>
          </div>
        </div>
      </div>

      <Tabs defaultValue="targets" className="space-y-4">
        <TabsList>
          <TabsTrigger value="targets" className="gap-2">
            <Server className="h-4 w-4" /> Live Targets
            {liveTargets && <Badge variant="secondary" className="ml-1 text-xs">{liveTargets.length}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="environments" className="gap-2">
            <Cloud className="h-4 w-4" /> Environments
            {runningEnvs.length > 0 && <Badge variant="secondary" className="ml-1 text-xs">{runningEnvs.length}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="scenarios" className="gap-2">
            <Skull className="h-4 w-4" /> Scenarios
            {scenarios && <Badge variant="secondary" className="ml-1 text-xs">{scenarios.length}</Badge>}
          </TabsTrigger>
        </TabsList>

        {/* ─── Live Targets Tab ─── */}
        <TabsContent value="targets" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Always-online vulnerable applications on the scan server for testing and training.
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                liveTargets?.forEach((t: any) => {
                  setCheckingHealth(t.id);
                  checkHealth.mutate({ targetId: t.id });
                });
              }}
              disabled={checkHealth.isPending}
            >
              <Activity className="h-4 w-4 mr-1" /> Check All Health
            </Button>
          </div>

          {loadingTargets ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[1, 2, 3, 4, 5].map(i => (
                <Card key={i} className="animate-pulse">
                  <CardContent className="p-6"><div className="h-32 bg-muted rounded" /></CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {liveTargets?.map((target: any) => {
                const health = healthChecks[target.id];
                const isExpanded = expandedTarget === target.id;

                return (
                  <Card key={target.id} className="hover:border-muted-foreground/30 transition-colors">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Monitor className="h-5 w-5 text-cyan-400" />
                          <CardTitle className="text-base">{target.name}</CardTitle>
                        </div>
                        <div className="flex items-center gap-1">
                          {health ? (
                            health.status === "online" ? (
                              <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-xs gap-1">
                                <Wifi className="h-3 w-3" /> Online
                              </Badge>
                            ) : (
                              <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-xs gap-1">
                                <WifiOff className="h-3 w-3" /> Offline
                              </Badge>
                            )
                          ) : (
                            <Badge variant="outline" className="text-xs gap-1">
                              <Activity className="h-3 w-3" /> Unchecked
                            </Badge>
                          )}
                        </div>
                      </div>
                      <CardDescription className="text-xs">{target.description}</CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <div className="flex items-center gap-2 text-xs">
                        <Globe className="h-3 w-3 text-muted-foreground" />
                        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{target.url}</code>
                      </div>

                      <div className="flex flex-wrap gap-1">
                        <Badge variant="outline" className="text-xs">
                          <Bug className="h-3 w-3 mr-1" /> {target.totalVulns} vulns
                        </Badge>
                        <Badge className={`text-xs ${SEVERITY_COLORS.critical}`}>
                          {target.criticalVulns} critical
                        </Badge>
                        {target.rceCapable > 0 && (
                          <Badge className="bg-red-600/20 text-red-300 border-red-600/30 text-xs">
                            <Zap className="h-3 w-3 mr-1" /> {target.rceCapable} RCE
                          </Badge>
                        )}
                      </div>

                      {target.technologies && (
                        <div className="flex flex-wrap gap-1">
                          {target.technologies.map((tech: string) => (
                            <Badge key={tech} variant="secondary" className="text-xs">{tech}</Badge>
                          ))}
                        </div>
                      )}

                      {isExpanded && target.knownVulns && (
                        <div className="mt-2 space-y-1.5 border-t pt-2">
                          <p className="text-xs font-medium">Known Vulnerabilities:</p>
                          {target.knownVulns.map((vuln: any, idx: number) => (
                            <div key={idx} className="flex items-center justify-between text-xs p-1.5 bg-muted/30 rounded">
                              <div className="flex items-center gap-2">
                                <Badge className={`text-xs ${SEVERITY_COLORS[vuln.severity] || ""}`}>
                                  {vuln.severity}
                                </Badge>
                                <span>{vuln.name || vuln.type}</span>
                              </div>
                              <div className="flex items-center gap-1">
                                {vuln.rceCapable && (
                                  <Badge className="bg-red-600/20 text-red-300 border-red-600/30 text-xs">RCE</Badge>
                                )}
                                {vuln.cve && <code className="text-xs text-muted-foreground">{vuln.cve}</code>}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="flex gap-2 pt-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="flex-1 text-xs"
                          onClick={() => setExpandedTarget(isExpanded ? null : target.id)}
                        >
                          {isExpanded ? <ChevronUp className="h-3 w-3 mr-1" /> : <ChevronDown className="h-3 w-3 mr-1" />}
                          {isExpanded ? "Hide" : "Vulns"}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          onClick={() => {
                            setCheckingHealth(target.id);
                            checkHealth.mutate({ targetId: target.id });
                          }}
                          disabled={checkingHealth === target.id}
                        >
                          <RefreshCw className={`h-3 w-3 mr-1 ${checkingHealth === target.id ? "animate-spin" : ""}`} />
                          Ping
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs"
                          onClick={() => window.open(target.url, "_blank")}
                        >
                          <ExternalLink className="h-3 w-3 mr-1" /> Open
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ─── Environments Tab ─── */}
        <TabsContent value="environments" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Running Environments */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium flex items-center gap-2">
                <Server className="h-4 w-4 text-emerald-400" /> Active Environments
              </h3>
              {runningEnvs.length > 0 ? (
                runningEnvs.map((env: any) => (
                  <Card key={env.id}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30 text-xs">Running</Badge>
                          <span className="font-medium text-sm">{env.name}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">{env.type}</Badge>
                      </div>
                      <div className="text-xs text-muted-foreground space-y-1">
                        {env.targetIp && <p>IP: <code className="bg-muted px-1 rounded">{env.targetIp}</code></p>}
                        {env.os && <p>OS: {env.os}</p>}
                        {env.createdAt && <p>Created: {new Date(env.createdAt).toLocaleDateString()}</p>}
                      </div>
                    </CardContent>
                  </Card>
                ))
              ) : (
                <Card>
                  <CardContent className="p-8 text-center">
                    <Server className="h-8 w-8 text-muted-foreground mx-auto mb-2 opacity-30" />
                    <p className="text-sm text-muted-foreground">No active environments.</p>
                    <p className="text-xs text-muted-foreground mt-1">Provision one from the templates below.</p>
                  </CardContent>
                </Card>
              )}

              {/* All Environments */}
              {environments && environments.filter((e: any) => e.state !== "running").length > 0 && (
                <>
                  <h3 className="text-sm font-medium flex items-center gap-2 mt-4">
                    <Clock className="h-4 w-4 text-muted-foreground" /> Other Environments
                  </h3>
                  {environments.filter((e: any) => e.state !== "running").map((env: any) => (
                    <Card key={env.id} className="opacity-60">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">{env.state}</Badge>
                            <span className="text-sm">{env.name}</span>
                          </div>
                          <Badge variant="outline" className="text-xs">{env.type}</Badge>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </>
              )}
            </div>

            {/* Lab Templates */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium flex items-center gap-2">
                <Cloud className="h-4 w-4 text-blue-400" /> Lab Templates (DigitalOcean)
              </h3>
              {labTemplates?.map((template: any) => (
                <Card key={template.id} className="hover:border-muted-foreground/30 transition-colors">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">{template.name}</span>
                      <Badge variant="outline" className="text-xs">{template.size || template.region}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{template.description}</p>
                    {template.os && (
                      <div className="flex items-center gap-2 text-xs mb-2">
                        <Cpu className="h-3 w-3 text-muted-foreground" />
                        <span>{template.os}</span>
                      </div>
                    )}
                    {template.preInstalledVulns && (
                      <div className="flex flex-wrap gap-1 mb-2">
                        {template.preInstalledVulns.map((vuln: string) => (
                          <Badge key={vuln} variant="secondary" className="text-xs">{vuln}</Badge>
                        ))}
                      </div>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      className="w-full text-xs"
                      disabled={provisionEnv.isPending}
                      onClick={() => {
                        provisionEnv.mutate({
                          name: `lab-${template.id}-${Date.now().toString(36)}`,
                          type: "digitalocean",
                          config: { templateId: template.id },
                        });
                      }}
                    >
                      <Cloud className="h-3 w-3 mr-1" /> Provision
                    </Button>
                  </CardContent>
                </Card>
              )) ?? (
                <Card>
                  <CardContent className="p-8 text-center">
                    <Cloud className="h-8 w-8 text-muted-foreground mx-auto mb-2 opacity-30" />
                    <p className="text-sm text-muted-foreground">No templates available.</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ─── Scenarios Tab ─── */}
        <TabsContent value="scenarios" className="space-y-4">
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
                {runningEnvs.map((env: any) => (
                  <SelectItem key={env.id} value={env.id}>{env.name}</SelectItem>
                ))}
                {runningEnvs.length === 0 && (
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
        </TabsContent>
      </Tabs>
    </div>
  );
}
