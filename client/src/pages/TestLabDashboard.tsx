import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  FlaskConical, Server, Target, Brain, GraduationCap, Radio,
  Skull, TrendingUp, Activity, Play, RefreshCw, AlertTriangle,
  CheckCircle2, Clock, Zap, Shield,
} from "lucide-react";

export default function TestLabDashboard() {
  // toast from sonner is already imported
  const { data: dashboard, isLoading, refetch } = trpc.testLab.getDashboard.useQuery();

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center gap-3">
          <FlaskConical className="h-8 w-8 text-emerald-400" />
          <div>
            <h1 className="text-2xl font-bold">AC3 Test Lab</h1>
            <p className="text-muted-foreground">Loading lab environment...</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <Card key={i} className="animate-pulse"><CardContent className="p-6"><div className="h-16 bg-muted rounded" /></CardContent></Card>
          ))}
        </div>
      </div>
    );
  }

  const stats = dashboard;

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <FlaskConical className="h-8 w-8 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">AC3 Test Lab</h1>
            <p className="text-muted-foreground">
              Ember agent testing, C2 validation, LLM training, and graduation
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-emerald-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Environments</p>
                <p className="text-3xl font-bold">{stats?.activeEnvironments ?? 0}</p>
              </div>
              <Server className="h-8 w-8 text-emerald-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-amber-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Scenarios Run</p>
                <p className="text-3xl font-bold">{stats?.totalScenarios ?? 0}</p>
              </div>
              <Target className="h-8 w-8 text-amber-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Training Runs</p>
                <p className="text-3xl font-bold">{stats?.totalTrainingRuns ?? 0}</p>
              </div>
              <Brain className="h-8 w-8 text-blue-400 opacity-50" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-purple-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Implant Tests</p>
                <p className="text-3xl font-bold">{stats?.totalImplantTests ?? 0}</p>
              </div>
              <Skull className="h-8 w-8 text-purple-400 opacity-50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Graduation Summary */}
      {stats?.graduationSummary && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GraduationCap className="h-5 w-5 text-amber-400" />
              Graduation Engine Bridge
            </CardTitle>
            <CardDescription>Model tier progression and lab access levels</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {stats.graduationSummary.modelStates?.map((model: any) => (
                <div key={model.model} className="p-3 bg-muted/50 rounded-lg text-center">
                  <p className="text-xs text-muted-foreground mb-1">{model.model?.replace(/_/g, " ")}</p>
                  <p className="text-lg font-bold">Tier {model.currentTier ?? 1}</p>
                  <Badge variant={model.currentTier >= 4 ? "default" : "secondary"} className="mt-1 text-xs">
                    {model.labAccess ?? "basic"}
                  </Badge>
                </div>
              )) ?? (
                <p className="text-muted-foreground col-span-6 text-center py-4">No model states available yet. Run scenarios to begin training.</p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-400" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Button
              variant="outline"
              className="h-auto py-4 flex-col gap-2"
              onClick={() => toast.success("Navigate to Environments: " + "Use the sidebar to manage lab environments")}
            >
              <Server className="h-5 w-5 text-emerald-400" />
              <span className="text-xs">New Environment</span>
            </Button>
            <Button
              variant="outline"
              className="h-auto py-4 flex-col gap-2"
              onClick={() => toast.success("Navigate to Scenarios: " + "Use the sidebar to run attack scenarios")}
            >
              <Target className="h-5 w-5 text-amber-400" />
              <span className="text-xs">Run Scenario</span>
            </Button>
            <Button
              variant="outline"
              className="h-auto py-4 flex-col gap-2"
              onClick={() => toast.success("Navigate to Implant Testing: " + "Use the sidebar to test Ember deployment")}
            >
              <Skull className="h-5 w-5 text-red-400" />
              <span className="text-xs">Test Implant</span>
            </Button>
            <Button
              variant="outline"
              className="h-auto py-4 flex-col gap-2"
              onClick={() => toast.success("Navigate to LLM Training: " + "Use the sidebar to manage model training")}
            >
              <Brain className="h-5 w-5 text-blue-400" />
              <span className="text-xs">Train Models</span>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4" />
              Recent Scenario Runs
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.recentScenarios?.length ? (
              <div className="space-y-2">
                {stats.recentScenarios.slice(0, 5).map((run: any) => (
                  <div key={run.id} className="flex items-center justify-between p-2 bg-muted/30 rounded">
                    <div>
                      <p className="text-sm font-medium">{run.scenarioId}</p>
                      <p className="text-xs text-muted-foreground">{new Date(run.createdAt).toLocaleString()}</p>
                    </div>
                    <Badge variant={run.status === "completed" ? "default" : run.status === "failed" ? "destructive" : "secondary"}>
                      {run.status}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm text-center py-6">No scenario runs yet. Start a scenario to begin testing.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Radio className="h-4 w-4" />
              C2 Channel Health
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.channelSuccessRates && Object.keys(stats.channelSuccessRates).length > 0 ? (
              <div className="space-y-2">
                {Object.entries(stats.channelSuccessRates).map(([channel, rate]: [string, any]) => (
                  <div key={channel} className="flex items-center justify-between p-2 bg-muted/30 rounded">
                    <span className="text-sm">{channel.replace(/_/g, " ")}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${rate >= 80 ? "bg-emerald-500" : rate >= 50 ? "bg-amber-500" : "bg-red-500"}`}
                          style={{ width: `${rate}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono w-10 text-right">{rate}%</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm text-center py-6">No C2 channel data yet. Run validation tests to populate.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
