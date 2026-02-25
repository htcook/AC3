import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  BadgeCheck, ShieldAlert, FileOutput, Clock, CheckCircle2, XCircle,
  AlertTriangle, Activity, TrendingUp, Loader2, RefreshCw, Database,
  Shield, BarChart3
} from "lucide-react";

export default function KsiDashboard() {
  
  const [seeding, setSeeding] = useState(false);

  const coverageSummary = trpc.ksiEvidenceChain.getCoverageSummary.useQuery();
  const evidenceStats = trpc.ksiEvidenceChain.getDashboardStats.useQuery();
  const validationDashboard = trpc.ksiValidationScheduler.getDashboard.useQuery();
  const oscalStats = trpc.oscalExport.getStats.useQuery();

  const seedMutation = trpc.ksiEvidenceChain.seedCatalog.useMutation({
    onSuccess: (data) => {
      toast.success(`Indicator Catalog Seeded: ${data.seeded} of ${data.total} KSIs added to database`);
      coverageSummary.refetch();
    },
    onError: (err) => {
      toast.error("Seed Failed: " + err.message);
    },
  });

  const initSchedulesMutation = trpc.ksiValidationScheduler.initializeSchedules.useMutation({
    onSuccess: (data) => {
      toast.success(`Schedules Initialized: ${data.created} validation schedules created`);
      validationDashboard.refetch();
    },
  });

  const handleSeedCatalog = async () => {
    setSeeding(true);
    try {
      await seedMutation.mutateAsync();
    } finally {
      setSeeding(false);
    }
  };

  const coverage = coverageSummary.data;
  const evStats = evidenceStats.data;
  const valDash = validationDashboard.data;
  const oscStats = oscalStats.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BadgeCheck className="h-7 w-7 text-blue-500" />
            Key Security Indicators Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Continuous monitoring of FedRAMP's Key Security Indicators — the industry standard for cloud security posture and compliance readiness
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={handleSeedCatalog} disabled={seeding}>
            {seeding ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Database className="h-4 w-4 mr-1" />}
            Seed Indicator Catalog
          </Button>
          <Button variant="outline" size="sm" onClick={() => initSchedulesMutation.mutate({})}>
            <Clock className="h-4 w-4 mr-1" />
            Init Schedules
          </Button>
          <Button variant="outline" size="sm" onClick={() => {
            coverageSummary.refetch();
            evidenceStats.refetch();
            validationDashboard.refetch();
            oscalStats.refetch();
          }}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Top-Level KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Overall Coverage</div>
            <div className="text-3xl font-bold text-blue-500 mt-1">{coverage?.overallCoverage || 0}%</div>
            <div className="text-xs text-muted-foreground">{coverage?.totalKSIs || 58} indicators tracked</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Direct Coverage</div>
            <div className="text-3xl font-bold text-emerald-500 mt-1">{coverage?.directCount || 0}</div>
            <div className="text-xs text-muted-foreground">indicators directly addressed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Supporting</div>
            <div className="text-3xl font-bold text-amber-500 mt-1">{coverage?.supportingCount || 0}</div>
            <div className="text-xs text-muted-foreground">indicators with support</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Evidence Items</div>
            <div className="text-3xl font-bold text-purple-500 mt-1">{evStats?.totalEvidence || 0}</div>
            <div className="text-xs text-muted-foreground">collected artifacts</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Validations</div>
            <div className="text-3xl font-bold text-cyan-500 mt-1">{valDash?.totalRuns || 0}</div>
            <div className="text-xs text-muted-foreground">{valDash?.passRate || 0}% pass rate</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">OSCAL Exports</div>
            <div className="text-3xl font-bold text-orange-500 mt-1">{oscStats?.totalExports || 0}</div>
            <div className="text-xs text-muted-foreground">documents generated</div>
          </CardContent>
        </Card>
      </div>

      {/* Theme Coverage Breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Indicator Theme Coverage
          </CardTitle>
          <CardDescription>Coverage across all 11 Key Security Indicator themes defined by FedRAMP</CardDescription>
        </CardHeader>
        <CardContent>
          {coverage?.themeStats && coverage.themeStats.length > 0 ? (
            <div className="space-y-3">
              {coverage.themeStats.map((theme) => (
                <div key={theme.themeCode} className="flex items-center gap-4">
                  <div className="w-48 text-sm font-medium truncate">{theme.themeName}</div>
                  <div className="flex-1">
                    <div className="h-6 bg-muted rounded-full overflow-hidden flex">
                      <div
                        className="h-full bg-emerald-500 transition-all"
                        style={{ width: `${(theme.direct / theme.total) * 100}%` }}
                        title={`Direct: ${theme.direct}`}
                      />
                      <div
                        className="h-full bg-amber-500 transition-all"
                        style={{ width: `${(theme.supporting / theme.total) * 100}%` }}
                        title={`Supporting: ${theme.supporting}`}
                      />
                      <div
                        className="h-full bg-slate-400 transition-all"
                        style={{ width: `${(theme.planned / theme.total) * 100}%` }}
                        title={`Planned: ${theme.planned}`}
                      />
                    </div>
                  </div>
                  <div className="w-16 text-right">
                    <Badge variant={theme.coveragePercent >= 80 ? "default" : theme.coveragePercent >= 50 ? "secondary" : "destructive"}>
                      {theme.coveragePercent}%
                    </Badge>
                  </div>
                  <div className="w-32 text-xs text-muted-foreground">
                    {theme.direct}D / {theme.supporting}S / {theme.planned}P
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <Database className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No KSI data loaded. Click "Seed Indicator Catalog" to initialize.</p>
            </div>
          )}
          <div className="flex gap-4 mt-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-emerald-500 inline-block" /> Direct</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-amber-500 inline-block" /> Supporting</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-slate-400 inline-block" /> Planned</span>
          </div>
        </CardContent>
      </Card>

      {/* Tabs for detailed views */}
      <Tabs defaultValue="validation" className="space-y-4">
        <TabsList>
          <TabsTrigger value="validation">Validation Status</TabsTrigger>
          <TabsTrigger value="evidence">Evidence Collection</TabsTrigger>
          <TabsTrigger value="alerts">Alerts & Overdue</TabsTrigger>
        </TabsList>

        <TabsContent value="validation" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                  <span className="font-medium">Passed</span>
                </div>
                <div className="text-2xl font-bold">{valDash?.passedRuns || 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <XCircle className="h-5 w-5 text-red-500" />
                  <span className="font-medium">Failed</span>
                </div>
                <div className="text-2xl font-bold">{valDash?.failedRuns || 0}</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-5 w-5 text-amber-500" />
                  <span className="font-medium">Overdue</span>
                </div>
                <div className="text-2xl font-bold">{valDash?.overdueSchedules || 0}</div>
              </CardContent>
            </Card>
          </div>

          {/* Recent Validation Runs */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Recent Validation Runs</CardTitle>
            </CardHeader>
            <CardContent>
              {valDash?.recentRuns && valDash.recentRuns.length > 0 ? (
                <div className="space-y-2">
                  {valDash.recentRuns.map((run: any) => (
                    <div key={run.runId} className="flex items-center justify-between py-2 border-b last:border-0">
                      <div className="flex items-center gap-3">
                        {run.status === "passed" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                        {run.status === "failed" && <XCircle className="h-4 w-4 text-red-500" />}
                        {run.status === "running" && <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />}
                        {run.status === "warning" && <AlertTriangle className="h-4 w-4 text-amber-500" />}
                        {!["passed", "failed", "running", "warning"].includes(run.status) && <Activity className="h-4 w-4 text-muted-foreground" />}
                        <div>
                          <div className="text-sm font-medium">{run.ksiId}</div>
                          <div className="text-xs text-muted-foreground">{run.triggerType} · {run.validationType}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={
                          run.status === "passed" ? "default" :
                          run.status === "failed" ? "destructive" :
                          "secondary"
                        }>
                          {run.status}
                        </Badge>
                        {run.score !== null && run.maxScore && (
                          <span className="text-xs text-muted-foreground">{run.score}/{run.maxScore}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">No validation runs yet. Initialize schedules to begin.</p>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="evidence" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Evidence by Status</CardTitle>
              </CardHeader>
              <CardContent>
                {evStats?.byStatus && evStats.byStatus.length > 0 ? (
                  <div className="space-y-2">
                    {evStats.byStatus.map((s: any) => (
                      <div key={s.status} className="flex justify-between items-center">
                        <span className="text-sm capitalize">{s.status}</span>
                        <Badge variant="outline">{s.count}</Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">No evidence collected yet.</p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Evidence by Type</CardTitle>
              </CardHeader>
              <CardContent>
                {evStats?.byType && evStats.byType.length > 0 ? (
                  <div className="space-y-2">
                    {evStats.byType.map((t: any) => (
                      <div key={t.type} className="flex justify-between items-center">
                        <span className="text-sm">{t.type.replace(/_/g, " ")}</span>
                        <Badge variant="outline">{t.count}</Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground text-center py-4">No evidence collected yet.</p>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Chain Integrity</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-4 bg-emerald-500/10 rounded-lg">
                  <Shield className="h-6 w-6 mx-auto text-emerald-500 mb-1" />
                  <div className="text-2xl font-bold">{evStats?.validChains || 0}</div>
                  <div className="text-xs text-muted-foreground">Valid Chains</div>
                </div>
                <div className="text-center p-4 bg-red-500/10 rounded-lg">
                  <ShieldAlert className="h-6 w-6 mx-auto text-red-500 mb-1" />
                  <div className="text-2xl font-bold">{evStats?.brokenChains || 0}</div>
                  <div className="text-xs text-muted-foreground">Broken Chains</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-amber-500" />
                Failing KSIs (Consecutive Failures)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {valDash?.failingKSIs && valDash.failingKSIs.length > 0 ? (
                <div className="space-y-2">
                  {valDash.failingKSIs.map((s: any) => (
                    <div key={s.scheduleId} className="flex items-center justify-between py-2 border-b last:border-0">
                      <div>
                        <div className="text-sm font-medium">{s.ksiId}</div>
                        <div className="text-xs text-muted-foreground">
                          {s.consecutiveFailures} consecutive failures (threshold: {s.alertThreshold})
                        </div>
                      </div>
                      <Badge variant="destructive">ALERT</Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-emerald-500" />
                  <p>No KSIs are currently in alert state.</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
