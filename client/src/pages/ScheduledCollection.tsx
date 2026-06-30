import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import {
  Clock, Zap, RefreshCw, CheckCircle2, XCircle, AlertTriangle,
  Loader2, Play, Calendar, Database, Activity, BarChart3, Settings
} from "lucide-react";
import AppShell from "@/components/AppShell";

const CADENCE_LABELS: Record<string, string> = {
  hourly: "Every Hour",
  every_6h: "Every 6 Hours",
  every_12h: "Every 12 Hours",
  daily: "Daily",
  weekly: "Weekly",
};

const STATUS_CONFIG: Record<string, { icon: React.ComponentType<{ className?: string }>; color: string }> = {
  success: { icon: CheckCircle2, color: "text-emerald-500" },
  failure: { icon: XCircle, color: "text-red-500" },
  never_run: { icon: Clock, color: "text-muted-foreground" },
  running: { icon: Loader2, color: "text-blue-500" },
};

export default function ScheduledCollection() {
  const [runningSource, setRunningSource] = useState<string | null>(null);

  const schedules = trpc.ksiScheduledCollection.listSchedules.useQuery();
  const dashboard = trpc.ksiScheduledCollection.getDashboardStats.useQuery();
  const jobHistory = trpc.ksiScheduledCollection.getJobHistory.useQuery({ limit: 20 });

  const initMutation = trpc.ksiScheduledCollection.initializeSchedules.useMutation({
    onSuccess: (data) => {
      toast.success(`Initialized ${data.created} collection schedules`);
      schedules.refetch();
      dashboard.refetch();
    },
    onError: (err) => toast.error("Init failed: " + err.message),
  });

  const updateMutation = trpc.ksiScheduledCollection.updateSchedule.useMutation({
    onSuccess: () => {
      schedules.refetch();
      dashboard.refetch();
    },
  });

  const runMutation = trpc.ksiScheduledCollection.runCollection.useMutation({
    onSuccess: (data) => {
      toast.success(`Collection complete: ${data.evidenceCollected} evidence items collected`);
      setRunningSource(null);
      schedules.refetch();
      dashboard.refetch();
      jobHistory.refetch();
    },
    onError: (err) => {
      toast.error("Collection failed: " + err.message);
      setRunningSource(null);
    },
  });

  const runDueMutation = trpc.ksiScheduledCollection.runDueCollections.useMutation({
    onSuccess: (data) => {
      toast.success(`Ran ${data.schedulesRun} due collections, collected ${data.totalEvidence} evidence items`);
      schedules.refetch();
      dashboard.refetch();
      jobHistory.refetch();
    },
    onError: (err) => toast.error("Batch run failed: " + err.message),
  });

  const stats = dashboard.data;

  return (
      <AppShell activePath="/scheduled-collection">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Calendar className="h-7 w-7 text-blue-500" />
            Scheduled Auto-Collection
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Set up and manage scheduled intelligence collection tasks that run automatically. Configure recurring scans, OSINT collection, vulnerability checks, and threat feed updates on daily, weekly, or custom schedules. Monitor upcoming and past collection runs, review their results, and adjust schedules based on your operational tempo. This ensures your intelligence stays current without manual intervention.</p>
          <p className="text-muted-foreground mt-1">
            Automated evidence collection from all security sources at configurable cadences — feeding FedRAMP's Key Security Indicators evidence chain continuously
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => initMutation.mutate()}>
            <Database className="h-4 w-4 mr-1" />
            Init Schedules
          </Button>
          <Button variant="outline" size="sm" onClick={() => runDueMutation.mutate()} disabled={runDueMutation.isPending}>
            {runDueMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
            Run Due Now
          </Button>
          <Button variant="outline" size="sm" onClick={() => {
            schedules.refetch();
            dashboard.refetch();
            jobHistory.refetch();
          }}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Dashboard KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Total Schedules</div>
            <div className="text-3xl font-bold text-blue-500 mt-1">{stats?.totalSchedules || 0}</div>
            <div className="text-xs text-muted-foreground">configured</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Enabled</div>
            <div className="text-3xl font-bold text-emerald-500 mt-1">{stats?.enabledCount || 0}</div>
            <div className="text-xs text-muted-foreground">active sources</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Due Now</div>
            <div className="text-3xl font-bold text-amber-500 mt-1">{stats?.dueCount || 0}</div>
            <div className="text-xs text-muted-foreground">ready to run</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Failed</div>
            <div className="text-3xl font-bold text-red-500 mt-1">{stats?.failedCount || 0}</div>
            <div className="text-xs text-muted-foreground">last run failed</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Total Runs</div>
            <div className="text-3xl font-bold text-purple-500 mt-1">{stats?.totalRuns || 0}</div>
            <div className="text-xs text-muted-foreground">executions</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Evidence</div>
            <div className="text-3xl font-bold text-cyan-500 mt-1">{stats?.totalEvidence || 0}</div>
            <div className="text-xs text-muted-foreground">items collected</div>
          </CardContent>
        </Card>
      </div>

      {/* Collection Schedules */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Collection Schedules
          </CardTitle>
          <CardDescription>
            Configure collection cadence per source — each run automatically feeds evidence into the indicator chain
          </CardDescription>
        </CardHeader>
        <CardContent>
          {schedules.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !schedules.data || schedules.data.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Calendar className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No schedules configured. Click "Init Schedules" to set up default collection cadences.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {schedules.data.map((schedule: any) => {
                const statusCfg = STATUS_CONFIG[schedule.lastStatus] || STATUS_CONFIG.never_run;
                const StatusIcon = statusCfg.icon;
                const isRunning = runningSource === schedule.sourceType;

                return (
                  <div key={schedule.id} className="flex items-center gap-4 p-3 border rounded-lg hover:bg-muted/30 transition-colors">
                    <Switch
                      checked={schedule.enabled}
                      onCheckedChange={(checked) => {
                        updateMutation.mutate({ scheduleId: schedule.id, enabled: checked });
                      }}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{schedule.displayName}</span>
                        <StatusIcon className={`h-4 w-4 ${statusCfg.color} ${schedule.lastStatus === 'running' ? 'animate-spin' : ''}`} />
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                        <span>{schedule.totalRuns || 0} runs</span>
                        <span>{schedule.totalEvidenceCollected || 0} evidence items</span>
                        {schedule.lastRunAt && (
                          <span>Last: {new Date(schedule.lastRunAt).toLocaleString()}</span>
                        )}
                        {schedule.nextRunAt && schedule.enabled && (
                          <span>Next: {new Date(schedule.nextRunAt).toLocaleString()}</span>
                        )}
                      </div>
                    </div>
                    <Select
                      value={schedule.cadence}
                      onValueChange={(v) => updateMutation.mutate({ scheduleId: schedule.id, cadence: v as any })}
                    >
                      <SelectTrigger className="w-40">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="hourly">Every Hour</SelectItem>
                        <SelectItem value="every_6h">Every 6 Hours</SelectItem>
                        <SelectItem value="every_12h">Every 12 Hours</SelectItem>
                        <SelectItem value="daily">Daily</SelectItem>
                        <SelectItem value="weekly">Weekly</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={isRunning}
                      onClick={() => {
                        setRunningSource(schedule.sourceType);
                        runMutation.mutate({ sourceType: schedule.sourceType });
                      }}
                    >
                      {isRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                    </Button>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Job History */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Recent Collection Jobs
          </CardTitle>
        </CardHeader>
        <CardContent>
          {jobHistory.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !jobHistory.data || jobHistory.data.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No collection jobs have run yet. Trigger a manual run or wait for scheduled execution.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {jobHistory.data.map((job: any) => (
                <div key={job.id} className="flex items-center justify-between py-2 border-b last:border-0">
                  <div className="flex items-center gap-3">
                    {job.status === "completed" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
                    {job.status === "failed" && <XCircle className="h-4 w-4 text-red-500" />}
                    {job.status === "running" && <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />}
                    <div>
                      <span className="text-sm font-medium">{job.sourceType.replace(/_/g, " ")}</span>
                      <span className="text-xs text-muted-foreground ml-2">by {job.triggeredBy}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    {job.evidenceCollected > 0 && (
                      <Badge variant="secondary">{job.evidenceCollected} items</Badge>
                    )}
                    <span>{new Date(job.startedAt).toLocaleString()}</span>
                    {job.completedAt && (
                      <span className="text-muted-foreground">
                        ({Math.round((job.completedAt - job.startedAt) / 1000)}s)
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
      </AppShell>
  );
}
