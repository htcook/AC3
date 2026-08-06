import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Brain, ChevronLeft, Flame, Zap, Shield, Eye, Network,
  Activity, RefreshCw, Target, Cpu, Lock, AlertTriangle,
  TrendingUp, Lightbulb, GitBranch
} from "lucide-react";
import { Link } from "wouter";

export default function EmberCognitiveEngine() {
  const [activeTab, setActiveTab] = useState("overview");
  const dashboardQuery = trpc.ember.getDashboard.useQuery(undefined, { refetchInterval: 10000 });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/ember">
            <Button variant="ghost" size="icon" className="h-8 w-8">
              <ChevronLeft className="w-4 h-4" />
            </Button>
          </Link>
          <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-600/20 border border-violet-500/30">
            <Brain className="w-5 h-5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Cognitive Engine</h1>
            <p className="text-sm text-muted-foreground">LLM-powered autonomous decision making and attack planning</p>
          </div>
        </div>
        <Button variant="outline" size="icon" onClick={() => dashboardQuery.refetch()}>
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="overview">Architecture</TabsTrigger>
          <TabsTrigger value="decision">Decision Log</TabsTrigger>
          <TabsTrigger value="playbooks">Playbooks</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          {/* Architecture Overview */}
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Brain className="w-4 h-4 text-violet-400" />
                Cognitive Architecture
              </CardTitle>
              <CardDescription>
                The Ember Cognitive Engine uses a multi-layer LLM architecture for autonomous decision-making
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="bg-violet-500/5 border-violet-500/20">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="p-2 rounded-lg bg-violet-500/20">
                        <Eye className="w-4 h-4 text-violet-400" />
                      </div>
                      <h3 className="text-sm font-semibold text-foreground">Perception Layer</h3>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                      Processes raw intelligence from agents — system enumeration, network topology, security product detection.
                      Builds a real-time situational awareness model.
                    </p>
                    <div className="flex flex-wrap gap-1">
                      <Badge variant="outline" className="text-[9px]">Host Analysis</Badge>
                      <Badge variant="outline" className="text-[9px]">Network Mapping</Badge>
                      <Badge variant="outline" className="text-[9px]">Threat Assessment</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-amber-500/5 border-amber-500/20">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="p-2 rounded-lg bg-amber-500/20">
                        <Lightbulb className="w-4 h-4 text-amber-400" />
                      </div>
                      <h3 className="text-sm font-semibold text-foreground">Reasoning Layer</h3>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                      Plans attack paths using MITRE ATT&CK knowledge, evaluates risk/reward for each action,
                      and generates task sequences optimized for the current environment.
                    </p>
                    <div className="flex flex-wrap gap-1">
                      <Badge variant="outline" className="text-[9px]">Attack Planning</Badge>
                      <Badge variant="outline" className="text-[9px]">Risk Analysis</Badge>
                      <Badge variant="outline" className="text-[9px]">Path Optimization</Badge>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-emerald-500/5 border-emerald-500/20">
                  <CardContent className="p-4">
                    <div className="flex items-center gap-2 mb-3">
                      <div className="p-2 rounded-lg bg-emerald-500/20">
                        <Shield className="w-4 h-4 text-emerald-400" />
                      </div>
                      <h3 className="text-sm font-semibold text-foreground">Safety Layer</h3>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                      Validates all planned actions against the AC3 Safety Engine. Blocks operations that exceed
                      the engagement's safety level. Ensures compliance with rules of engagement.
                    </p>
                    <div className="flex flex-wrap gap-1">
                      <Badge variant="outline" className="text-[9px]">Safety Gating</Badge>
                      <Badge variant="outline" className="text-[9px]">RoE Compliance</Badge>
                      <Badge variant="outline" className="text-[9px]">Audit Trail</Badge>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </CardContent>
          </Card>

          {/* Autonomy Levels */}
          <Card className="bg-card/50 border-border/50">
            <CardHeader>
              <CardTitle className="text-base">Autonomy Levels</CardTitle>
              <CardDescription>Configure how much decision-making authority the cognitive engine has</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  {
                    level: "Manual",
                    desc: "Operator controls all actions. Cognitive engine provides analysis and suggestions only.",
                    color: "border-blue-500/30 bg-blue-500/5",
                    icon: <Cpu className="w-4 h-4 text-blue-400" />,
                    features: ["Situational analysis", "Attack path suggestions", "Risk assessment"],
                  },
                  {
                    level: "Guided",
                    desc: "Agent suggests next actions based on intelligence. Operator approves or rejects each step.",
                    color: "border-amber-500/30 bg-amber-500/5",
                    icon: <Lightbulb className="w-4 h-4 text-amber-400" />,
                    features: ["Action recommendations", "Operator approval gate", "Rollback capability"],
                  },
                  {
                    level: "Semi-Autonomous",
                    desc: "Agent operates within an approved playbook. Escalates to operator for out-of-scope decisions.",
                    color: "border-orange-500/30 bg-orange-500/5",
                    icon: <GitBranch className="w-4 h-4 text-orange-400" />,
                    features: ["Playbook execution", "Boundary enforcement", "Escalation triggers"],
                  },
                  {
                    level: "Full Autonomous",
                    desc: "Agent operates independently with full cognitive capabilities. Safety engine provides the only constraint.",
                    color: "border-red-500/30 bg-red-500/5",
                    icon: <Brain className="w-4 h-4 text-red-400" />,
                    features: ["Independent planning", "Dynamic adaptation", "Safety-only constraints"],
                  },
                ].map((item) => (
                  <Card key={item.level} className={`${item.color}`}>
                    <CardContent className="p-4 flex items-start gap-4">
                      <div className="mt-0.5">{item.icon}</div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="text-sm font-semibold text-foreground">{item.level}</h3>
                        </div>
                        <p className="text-xs text-muted-foreground mb-2">{item.desc}</p>
                        <div className="flex flex-wrap gap-1">
                          {item.features.map((f) => (
                            <Badge key={f} variant="outline" className="text-[9px]">{f}</Badge>
                          ))}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="decision">
          <Card className="bg-card/30 border-border/30">
            <CardContent className="p-12 text-center">
              <Activity className="w-16 h-16 text-violet-400/20 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">Decision Log</h3>
              <p className="text-sm text-muted-foreground">
                Every cognitive decision is logged with full reasoning chain, risk assessment, and safety validation.
                Deploy agents with guided or autonomous mode to populate this log.
              </p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="playbooks">
          <Card className="bg-card/30 border-border/30">
            <CardContent className="p-12 text-center">
              <Target className="w-16 h-16 text-violet-400/20 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-foreground mb-2">Attack Playbooks</h3>
              <p className="text-sm text-muted-foreground">
                Pre-built and custom attack playbooks that define the cognitive engine's operational boundaries
                in semi-autonomous mode. Create playbooks from successful engagement patterns.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
