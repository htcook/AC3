import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  ClipboardCheck, Clock, Play, Search, CheckCircle2, XCircle,
  AlertTriangle, Loader2, RefreshCw, Calendar, Timer, Pause, SkipForward
} from "lucide-react";
import AppShell from "@/components/AppShell";

export default function KsiValidation() {
  
  const [searchTerm, setSearchTerm] = useState("");
  const [showOverdueOnly, setShowOverdueOnly] = useState(false);

  const utils = trpc.useUtils();

  const schedulesQuery = trpc.ksiValidationScheduler.listSchedules.useQuery(
    showOverdueOnly ? { overdue: true } : undefined
  );
  const runsQuery = trpc.ksiValidationScheduler.listRuns.useQuery({ limit: 100 });
  const dashboardQuery = trpc.ksiValidationScheduler.getDashboard.useQuery();
  const overdueQuery = trpc.ksiValidationScheduler.getOverdueValidations.useQuery();

  const startValidation = trpc.ksiValidationScheduler.startValidation.useMutation({
    onSuccess: (data) => {
      toast.success(`Validation Started: Run ID: ${data.runId}`);
      utils.ksiValidationScheduler.listRuns.invalidate();
      utils.ksiValidationScheduler.getDashboard.invalidate();
    },
    onError: (err) => toast.error("Error: " + err.message),
  });

  const completeValidation = trpc.ksiValidationScheduler.completeValidation.useMutation({
    onSuccess: () => {
      toast.success("Validation Completed");
      utils.ksiValidationScheduler.listRuns.invalidate();
      utils.ksiValidationScheduler.listSchedules.invalidate();
      utils.ksiValidationScheduler.getDashboard.invalidate();
    },
  });

  const updateSchedule = trpc.ksiValidationScheduler.updateSchedule.useMutation({
    onSuccess: () => {
      toast.success("Schedule Updated");
      utils.ksiValidationScheduler.listSchedules.invalidate();
    },
  });

  const schedules = schedulesQuery.data || [];
  const runs = runsQuery.data?.runs || [];
  const dashboard = dashboardQuery.data;
  const overdue = overdueQuery.data || [];

  const filteredSchedules = useMemo(() => {
    if (!searchTerm) return schedules;
    const lower = searchTerm.toLowerCase();
    return schedules.filter((s: any) =>
      s.ksiId?.toLowerCase().includes(lower) ||
      s.scheduleId?.toLowerCase().includes(lower)
    );
  }, [schedules, searchTerm]);

  const formatHours = (hours: number) => {
    if (hours < 24) return `${hours}h`;
    if (hours < 168) return `${Math.round(hours / 24)}d`;
    return `${Math.round(hours / 168)}w`;
  };

  const formatDate = (date: any) => {
    if (!date) return "—";
    return new Date(date).toLocaleString();
  };

  return (
      <AppShell activePath="/ksi-validation">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ClipboardCheck className="h-7 w-7 text-blue-500" />
            Indicator Validation Scheduler
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Validate Key Security Indicators against multiple corroborating sources. This page runs automated cross-checks to confirm or refute collected intelligence — verifying IOCs against threat feeds, checking CVE applicability against your asset inventory, and scoring indicator reliability. Review validation results and promote confirmed indicators to your active threat model.</p>
          <p className="text-muted-foreground mt-1">
            Automated validation scheduling and tracking for FedRAMP KSIs
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => {
          schedulesQuery.refetch();
          runsQuery.refetch();
          dashboardQuery.refetch();
          overdueQuery.refetch();
        }}>
          <RefreshCw className="h-4 w-4 mr-1" />
          Refresh
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <Calendar className="h-4 w-4 text-blue-500" />
              <span className="text-xs text-muted-foreground uppercase">Schedules</span>
            </div>
            <div className="text-2xl font-bold">{dashboard?.enabledSchedules || 0}</div>
            <div className="text-xs text-muted-foreground">of {dashboard?.totalSchedules || 0} total</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              <span className="text-xs text-muted-foreground uppercase">Pass Rate</span>
            </div>
            <div className="text-2xl font-bold">{dashboard?.passRate || 0}%</div>
            <div className="text-xs text-muted-foreground">{dashboard?.passedRuns || 0} passed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <XCircle className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground uppercase">Failed</span>
            </div>
            <div className="text-2xl font-bold">{dashboard?.failedRuns || 0}</div>
            <div className="text-xs text-muted-foreground">of {dashboard?.totalRuns || 0} runs</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <span className="text-xs text-muted-foreground uppercase">Overdue</span>
            </div>
            <div className="text-2xl font-bold text-amber-500">{dashboard?.overdueSchedules || 0}</div>
            <div className="text-xs text-muted-foreground">need attention</div>
          </CardContent>
        </Card>
      </div>

      {/* Overdue Alert */}
      {overdue.length > 0 && (
        <Card className="border-amber-500/50 bg-amber-500/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2 text-amber-500">
              <AlertTriangle className="h-5 w-5" />
              {overdue.length} Overdue Validations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {overdue.slice(0, 10).map((s: any) => (
                <Button
                  key={s.scheduleId}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => startValidation.mutate({ ksiId: s.ksiId, triggerType: "manual" })}
                >
                  <Play className="h-3 w-3 mr-1" />
                  {s.ksiId}
                </Button>
              ))}
              {overdue.length > 10 && (
                <Badge variant="outline">+{overdue.length - 10} more</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="schedules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="schedules">Schedules ({schedules.length})</TabsTrigger>
          <TabsTrigger value="runs">Validation Runs ({runs.length})</TabsTrigger>
        </TabsList>

        {/* Schedules Tab */}
        <TabsContent value="schedules" className="space-y-4">
          <div className="flex gap-3 items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input className="pl-9" placeholder="Search schedules..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={showOverdueOnly} onCheckedChange={setShowOverdueOnly} />
              <span className="text-sm text-muted-foreground">Overdue only</span>
            </div>
          </div>

          {filteredSchedules.length > 0 ? (
            <div className="space-y-2">
              {filteredSchedules.map((schedule: any) => {
                const isOverdue = schedule.nextRunAt && new Date(schedule.nextRunAt) < new Date();
                return (
                  <Card key={schedule.scheduleId} className={isOverdue ? "border-amber-500/30" : ""}>
                    <CardContent className="py-3 px-4">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs font-mono">{schedule.ksiId}</Badge>
                            <span className="text-sm">
                              Every {formatHours(schedule.frequencyHours)}
                            </span>
                            {isOverdue && <Badge variant="destructive" className="text-xs">OVERDUE</Badge>}
                            {schedule.consecutiveFailures > 0 && (
                              <Badge variant="destructive" className="text-xs">
                                {schedule.consecutiveFailures} failures
                              </Badge>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            Last: {formatDate(schedule.lastRunAt)} · Next: {formatDate(schedule.nextRunAt)}
                            {schedule.lastRunStatus && (
                              <span className={`ml-2 ${schedule.lastRunStatus === "passed" ? "text-emerald-500" : schedule.lastRunStatus === "failed" ? "text-red-500" : ""}`}>
                                ({schedule.lastRunStatus})
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={schedule.enabled}
                            onCheckedChange={(enabled) => updateSchedule.mutate({ scheduleId: schedule.scheduleId, enabled })}
                          />
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => startValidation.mutate({ ksiId: schedule.ksiId, triggerType: "manual" })}
                            disabled={startValidation.isPending}
                          >
                            <Play className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Calendar className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p className="font-medium">No validation schedules</p>
                <p className="text-sm mt-1">Go to KSI Dashboard and click "Init Schedules"</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Runs Tab */}
        <TabsContent value="runs" className="space-y-4">
          {runs.length > 0 ? (
            <div className="space-y-2">
              {runs.map((run: any) => (
                <Card key={run.runId}>
                  <CardContent className="py-3 px-4">
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          {run.status === "passed" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                          {run.status === "failed" && <XCircle className="h-4 w-4 text-red-500" />}
                          {run.status === "running" && <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />}
                          {run.status === "warning" && <AlertTriangle className="h-4 w-4 text-amber-500" />}
                          {run.status === "pending" && <Clock className="h-4 w-4 text-muted-foreground" />}
                          {run.status === "error" && <XCircle className="h-4 w-4 text-red-500" />}
                          {run.status === "skipped" && <SkipForward className="h-4 w-4 text-muted-foreground" />}
                          <Badge variant="outline" className="text-xs font-mono">{run.ksiId}</Badge>
                          <span className="text-sm">{run.runId}</span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {run.validationType} · {run.triggerType} · Started: {formatDate(run.startedAt)}
                          {run.completedAt && ` · Completed: ${formatDate(run.completedAt)}`}
                        </div>
                        {run.errorMessage && (
                          <div className="text-xs text-red-400 mt-1">{run.errorMessage}</div>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={
                          run.status === "passed" ? "default" :
                          run.status === "failed" || run.status === "error" ? "destructive" :
                          run.status === "warning" ? "secondary" :
                          "outline"
                        }>
                          {run.status}
                        </Badge>
                        {run.score !== null && run.maxScore && (
                          <span className="text-xs font-mono">{run.score}/{run.maxScore}</span>
                        )}
                        {run.status === "running" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => completeValidation.mutate({ runId: run.runId, status: "passed", score: 100, maxScore: 100 })}
                          >
                            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="py-12 text-center text-muted-foreground">
                <Timer className="h-10 w-10 mx-auto mb-3 opacity-40" />
                <p className="font-medium">No validation runs yet</p>
                <p className="text-sm mt-1">Start a manual validation or wait for scheduled runs</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
