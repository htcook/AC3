import AppShell from "@/components/AppShell";
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Clock, Play, Pause, RefreshCw, Loader2, CheckCircle2, XCircle,
  AlertTriangle, Globe, Activity, Zap, Calendar, Timer, Shield, Radio
} from "lucide-react";
import { toast } from "sonner";
import { sanitizeErrorForToast } from "@/lib/error-sanitizer";

export default function ScanScheduler() {
  const { data: status, isLoading, error, refetch } = trpc.monitor.schedulerStatus.useQuery(undefined, {
    refetchInterval: 30_000,
  });
  const forceCheck = trpc.monitor.forceSchedulerCheck.useMutation();

  const handleForceCheck = async () => {
    try {
      const result = await forceCheck.mutateAsync();
      toast.success(`Scheduler check complete: ${result.monitorsChecked} monitors checked, ${result.scansTriggered} scans triggered`);
      refetch();
    } catch (err: any) {
      toast.error(`Force check failed: ${sanitizeErrorForToast(err)}`);
    }
  };

  if (isLoading) return (
    <AppShell activePath="/scan-scheduler">
      <div className="flex items-center justify-center py-24">
        <Loader2 className="w-8 h-8 animate-spin text-cyan-400" />
      </div>
    </AppShell>
  );

  if (error) return (
    <AppShell activePath="/scan-scheduler">
      <Card><CardContent className="py-8 text-center">
        <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto mb-2" />
        <p className="text-sm text-muted-foreground">{error.message}</p>
      </CardContent></Card>
    </AppShell>
  );

  const d = status as any;
  const monitors = (d?.monitors || []) as any[];
  const recentRuns = (d?.recentRuns || []) as any[];

  return (
    <AppShell activePath="/scan-scheduler">
      <div className="space-y-6">
        {/* Scheduler Status Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${d?.running ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
            <span className="text-sm font-semibold">{d?.running ? 'Scheduler Active' : 'Scheduler Stopped'}</span>
            {d?.cronExpression && (
              <Badge variant="outline" className="text-[10px] font-mono">{d.cronExpression}</Badge>
            )}
          </div>
          <Button
            onClick={handleForceCheck}
            disabled={forceCheck.isPending}
            size="sm"
            className="bg-cyan-600 hover:bg-cyan-700"
          >
            {forceCheck.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin mr-2" /> Checking...</>
            ) : (
              <><Zap className="w-4 h-4 mr-2" /> Force Check Now</>
            )}
          </Button>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="bg-muted/30 border-border/50">
            <CardContent className="p-4 text-center">
              <Radio className="w-5 h-5 text-cyan-400 mx-auto mb-2" />
              <div className="text-3xl font-bold text-cyan-400">{d?.activeMonitors || 0}</div>
              <div className="text-xs text-muted-foreground mt-1">Active Monitors</div>
            </CardContent>
          </Card>
          <Card className="bg-muted/30 border-border/50">
            <CardContent className="p-4 text-center">
              <Activity className="w-5 h-5 text-purple-400 mx-auto mb-2" />
              <div className="text-3xl font-bold text-purple-400">{d?.totalScansTriggered || 0}</div>
              <div className="text-xs text-muted-foreground mt-1">Total Scans Triggered</div>
            </CardContent>
          </Card>
          <Card className="bg-muted/30 border-border/50">
            <CardContent className="p-4 text-center">
              <Clock className="w-5 h-5 text-amber-400 mx-auto mb-2" />
              <div className="text-sm font-mono font-bold text-amber-400 mt-1">
                {d?.lastCheckAt ? new Date(d.lastCheckAt).toLocaleTimeString() : 'Never'}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Last Check</div>
            </CardContent>
          </Card>
          <Card className="bg-muted/30 border-border/50">
            <CardContent className="p-4 text-center">
              <Timer className="w-5 h-5 text-emerald-400 mx-auto mb-2" />
              <div className="text-sm font-mono font-bold text-emerald-400 mt-1">
                {d?.nextCheckAt ? new Date(d.nextCheckAt).toLocaleTimeString() : 'Pending'}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Next Check</div>
            </CardContent>
          </Card>
        </div>

        {/* Monitored Domains */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              Monitored Domains ({monitors.length})
            </CardTitle>
            <CardDescription className="text-xs">
              Domains with active OSINT monitors. Scans are triggered automatically when the configured interval elapses.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {monitors.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground text-sm">
                <Shield className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No active monitors configured.</p>
                <p className="text-xs mt-1">Create an OSINT monitor from the Domain Intel page to enable automated scanning.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {monitors.map((m: any) => (
                  <div key={m.id} className={`flex items-center justify-between p-3 rounded-lg border ${m.isDue ? 'bg-amber-500/5 border-amber-500/30' : 'bg-muted/20 border-border/50'}`}>
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${m.isDue ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400'}`} />
                      <div>
                        <div className="font-mono text-sm font-semibold">{m.domain}</div>
                        <div className="text-[10px] text-muted-foreground flex items-center gap-2">
                          <span>Every {m.intervalHours}h</span>
                          <span>•</span>
                          <span>{m.totalScans || 0} scans</span>
                          <span>•</span>
                          <span>{m.totalChangesDetected || 0} changes</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {m.isDue ? (
                        <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-[10px]">DUE NOW</Badge>
                      ) : (
                        <div className="text-right">
                          <div className="text-[10px] text-muted-foreground">Next scan</div>
                          <div className="text-xs font-mono">{m.nextScanDue === 'now' ? 'Pending' : new Date(m.nextScanDue).toLocaleString()}</div>
                        </div>
                      )}
                      {m.lastScanAt && (
                        <div className="text-right">
                          <div className="text-[10px] text-muted-foreground">Last scan</div>
                          <div className="text-xs font-mono">{new Date(m.lastScanAt).toLocaleString()}</div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recent Scheduler Runs */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" />
              Recent Scheduler Runs ({recentRuns.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {recentRuns.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-sm">
                <Calendar className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No scheduler runs yet.</p>
                <p className="text-xs mt-1">Runs will appear here once the scheduler triggers scans.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {recentRuns.slice(0, 20).map((run: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between p-2 rounded bg-muted/20 border border-border/30">
                    <div className="flex items-center gap-3">
                      {run.status === 'running' && <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />}
                      {run.status === 'completed' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                      {run.status === 'failed' && <XCircle className="w-4 h-4 text-red-400" />}
                      <span className="font-mono text-xs">{run.domain}</span>
                      <Badge variant="outline" className={`text-[10px] ${run.status === 'completed' ? 'text-emerald-400' : run.status === 'failed' ? 'text-red-400' : 'text-cyan-400'}`}>
                        {run.status}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-[10px] text-muted-foreground">
                      {run.assetsFound !== undefined && <span>{run.assetsFound} assets</span>}
                      {run.changesDetected !== undefined && run.changesDetected > 0 && (
                        <Badge variant="outline" className="text-[10px] text-amber-400">{run.changesDetected} changes</Badge>
                      )}
                      {run.error && <span className="text-red-400 max-w-[200px] truncate">{run.error}</span>}
                      <span className="font-mono">{new Date(run.triggeredAt).toLocaleTimeString()}</span>
                      {run.completedAt && (
                        <span className="font-mono">({Math.round((run.completedAt - run.triggeredAt) / 1000)}s)</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* How It Works */}
        <Card className="bg-muted/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-muted-foreground" />
              How the Scan Scheduler Works
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground space-y-1">
            <p>The automated scan scheduler continuously monitors your configured domains:</p>
            <ul className="list-disc list-inside space-y-0.5 ml-2">
              <li>Checks every 5 minutes for monitors whose scan interval has elapsed</li>
              <li>Triggers full domain intel pipeline scans with asset discovery, tech detection, and risk scoring</li>
              <li>Runs advanced analysis including subdomain change detection, CVE cross-referencing, and takeover detection</li>
              <li>Compares results against the previous baseline to detect infrastructure changes</li>
              <li>Sends notifications when significant changes are detected (if configured)</li>
              <li>Respects a concurrency limit of 2 simultaneous scans to avoid overwhelming external APIs</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
