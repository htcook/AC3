import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/switch";
import {
  Calendar, Clock, Plus, Trash2, RefreshCw, Target,
  Shield, Radar, Crosshair, CheckCircle2
} from "lucide-react";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";

const SCHEDULE_TYPE_META: Record<string, { icon: any; label: string; color: string }> = {
  domain_scan: { icon: Radar, label: "Domain Scan", color: "text-purple-400" },
  emulation_run: { icon: Crosshair, label: "Emulation Run", color: "text-cyan-400" },
  campaign_retest: { icon: Target, label: "Campaign Retest", color: "text-orange-400" },
  detection_validation: { icon: Shield, label: "Detection Validation", color: "text-emerald-400" },
};

const INTERVAL_OPTIONS = [
  { value: 24, label: "Daily (24h)" },
  { value: 168, label: "Weekly (168h)" },
  { value: 336, label: "Bi-Weekly (336h)" },
  { value: 720, label: "Monthly (720h)" },
  { value: 2160, label: "Quarterly (2160h)" },
];

function intervalLabel(hours: number): string {
  if (hours <= 24) return "Daily";
  if (hours <= 168) return "Weekly";
  if (hours <= 336) return "Bi-Weekly";
  if (hours <= 720) return "Monthly";
  return "Quarterly";
}

export default function ValidationScheduler() {
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState<string>("domain_scan");
  const [newInterval, setNewInterval] = useState<number>(168);
  const [newTarget, setNewTarget] = useState("");

  const schedulesQ = trpc.validationScheduler.listSchedules.useQuery();
  const createMut = trpc.validationScheduler.createSchedule.useMutation({
    onSuccess: () => {
      toast.success("Schedule created");
      setShowCreate(false);
      resetForm();
      schedulesQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const toggleMut = trpc.validationScheduler.toggleSchedule.useMutation({
    onSuccess: () => {
      toast.success("Schedule updated");
      schedulesQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });
  const deleteMut = trpc.validationScheduler.deleteSchedule.useMutation({
    onSuccess: () => {
      toast.success("Schedule deleted");
      schedulesQ.refetch();
    },
    onError: (e: any) => toast.error(e.message),
  });

  const resetForm = () => {
    setNewName("");
    setNewType("domain_scan");
    setNewInterval(168);
    setNewTarget("");
  };

  const schedules = schedulesQ.data ?? [];
  const activeCount = schedules.filter((s) => s.enabled).length;

  return (
    <AppShell activePath="/continuous-validation">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Calendar className="h-7 w-7 text-purple-400" />
              Continuous Validation Scheduler
            </h1>
            <p className="text-muted-foreground mt-1 max-w-2xl">
              Schedule recurring domain scans, emulation runs, campaign retests, and detection validations to maintain continuous security posture awareness.
            </p>
          </div>
          <Button onClick={() => setShowCreate(true)} className="bg-purple-600 hover:bg-purple-700">
            <Plus className="h-4 w-4 mr-2" />
            New Schedule
          </Button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card className="border-border/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold">{schedules.length}</p>
              <p className="text-xs text-muted-foreground">Total Schedules</p>
            </CardContent>
          </Card>
          <Card className="border-emerald-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-emerald-400">{activeCount}</p>
              <p className="text-xs text-muted-foreground">Active</p>
            </CardContent>
          </Card>
          <Card className="border-amber-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-amber-400">{schedules.length - activeCount}</p>
              <p className="text-xs text-muted-foreground">Paused</p>
            </CardContent>
          </Card>
          <Card className="border-purple-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-purple-400">
                {schedules.filter((s) => s.lastRunAt).length}
              </p>
              <p className="text-xs text-muted-foreground">Has Run</p>
            </CardContent>
          </Card>
        </div>

        {/* Schedule List */}
        {schedules.length === 0 ? (
          <Card className="border-border/60">
            <CardContent className="p-12 text-center">
              <Calendar className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-muted-foreground">No Validation Schedules</h3>
              <p className="text-sm text-muted-foreground/70 mt-1 max-w-md mx-auto">
                Create your first schedule to automate recurring domain scans, emulation runs, or campaign retests.
              </p>
              <Button onClick={() => setShowCreate(true)} className="mt-4 bg-purple-600 hover:bg-purple-700">
                <Plus className="h-4 w-4 mr-2" />
                Create First Schedule
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-3">
            {schedules.map((schedule) => {
              const meta = SCHEDULE_TYPE_META[schedule.scheduleType] || SCHEDULE_TYPE_META.domain_scan;
              const Icon = meta.icon;
              return (
                <Card key={schedule.id} className={`border-border/60 ${!schedule.enabled ? 'opacity-60' : ''}`}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className="p-2 rounded-lg bg-background/50 border border-border/40">
                          <Icon className={`h-5 w-5 ${meta.color}`} />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-semibold text-sm">{schedule.name}</span>
                            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${meta.color}`}>
                              {meta.label}
                            </Badge>
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                              {intervalLabel(schedule.intervalHours)}
                            </Badge>
                            {schedule.enabled ? (
                              <Badge className="text-[10px] px-1.5 py-0 bg-emerald-500/10 text-emerald-400 border-0">Active</Badge>
                            ) : (
                              <Badge className="text-[10px] px-1.5 py-0 bg-amber-500/10 text-amber-400 border-0">Paused</Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
                            {schedule.targetLabel && (
                              <span className="flex items-center gap-1">
                                <Target className="h-3 w-3" />
                                <span className="font-mono">{schedule.targetLabel}</span>
                              </span>
                            )}
                            {schedule.nextRunAt && (
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                Next: {new Date(schedule.nextRunAt).toLocaleDateString()}
                              </span>
                            )}
                            {schedule.lastRunAt && (
                              <span className="flex items-center gap-1">
                                <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                                Last: {new Date(schedule.lastRunAt).toLocaleDateString()}
                              </span>
                            )}
                            <span>Runs: {schedule.runCount ?? 0}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Switch
                          checked={schedule.enabled}
                          onCheckedChange={(checked) => toggleMut.mutate({ id: schedule.id, enabled: checked })}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive hover:text-destructive"
                          onClick={() => {
                            if (confirm("Delete this schedule?")) {
                              deleteMut.mutate({ id: schedule.id });
                            }
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Create Dialog */}
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Create Validation Schedule</DialogTitle>
              <DialogDescription>
                Set up a recurring validation task to continuously monitor your security posture.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>Schedule Name</Label>
                <Input
                  placeholder="e.g., Weekly Tesla.com Scan"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Type</Label>
                <Select value={newType} onValueChange={setNewType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(SCHEDULE_TYPE_META).map(([k, v]) => (
                      <SelectItem key={k} value={k}>{v.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Frequency</Label>
                <Select value={String(newInterval)} onValueChange={(v) => setNewInterval(Number(v))}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INTERVAL_OPTIONS.map((f) => (
                      <SelectItem key={f.value} value={String(f.value)}>{f.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Target (optional)</Label>
                <Input
                  placeholder="e.g., tesla.com or engagement name"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setShowCreate(false); resetForm(); }}>Cancel</Button>
              <Button
                className="bg-purple-600 hover:bg-purple-700"
                disabled={!newName.trim() || createMut.isPending}
                onClick={() => {
                  createMut.mutate({
                    name: newName.trim(),
                    scheduleType: newType as any,
                    intervalHours: newInterval,
                    targetLabel: newTarget.trim() || undefined,
                    config: {},
                  });
                }}
              >
                {createMut.isPending ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                Create Schedule
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </AppShell>
  );
}
