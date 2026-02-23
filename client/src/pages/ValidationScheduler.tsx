import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import {
  Calendar, Plus, Search, Clock, Play, Pause,
  Trash2, RefreshCw, AlertTriangle, CheckCircle,
  XCircle, Loader2, Target, Shield, Globe, Zap,
  Timer, BarChart3
} from "lucide-react";

const SCHEDULE_TYPES = [
  { value: "domain_scan", label: "Domain Scan", icon: Globe, color: "text-cyan-400", bg: "bg-cyan-500/20" },
  { value: "emulation", label: "Emulation Run", icon: Target, color: "text-violet-400", bg: "bg-violet-500/20" },
  { value: "campaign_retest", label: "Campaign Retest", icon: Zap, color: "text-amber-400", bg: "bg-amber-500/20" },
  { value: "detection_retest", label: "Detection Retest", icon: Shield, color: "text-emerald-400", bg: "bg-emerald-500/20" },
];

const INTERVAL_PRESETS = [
  { label: "Every 6 hours", hours: 6 },
  { label: "Every 12 hours", hours: 12 },
  { label: "Daily", hours: 24 },
  { label: "Every 3 days", hours: 72 },
  { label: "Weekly", hours: 168 },
  { label: "Bi-weekly", hours: 336 },
  { label: "Monthly", hours: 720 },
];

function formatRelativeTime(date: string | Date | null | undefined): string {
  if (!date) return "—";
  const d = new Date(date);
  const now = new Date();
  const diffMs = d.getTime() - now.getTime();
  const absDiff = Math.abs(diffMs);
  const isPast = diffMs < 0;

  if (absDiff < 60000) return isPast ? "just now" : "in < 1m";
  if (absDiff < 3600000) {
    const mins = Math.floor(absDiff / 60000);
    return isPast ? `${mins}m ago` : `in ${mins}m`;
  }
  if (absDiff < 86400000) {
    const hrs = Math.floor(absDiff / 3600000);
    return isPast ? `${hrs}h ago` : `in ${hrs}h`;
  }
  const days = Math.floor(absDiff / 86400000);
  return isPast ? `${days}d ago` : `in ${days}d`;
}

function formatInterval(hours: number): string {
  if (hours < 24) return `${hours}h`;
  if (hours < 168) return `${Math.floor(hours / 24)}d`;
  if (hours < 720) return `${Math.floor(hours / 168)}w`;
  return `${Math.floor(hours / 720)}mo`;
}

function sanitizeErrorForToast(err: any): string {
  const msg = err?.message || String(err);
  return msg.length > 120 ? msg.slice(0, 120) + "…" : msg;
}

export default function ValidationScheduler() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  // Create form state
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState("domain_scan");
  const [newTargetId, setNewTargetId] = useState("");
  const [newTargetLabel, setNewTargetLabel] = useState("");
  const [newInterval, setNewInterval] = useState(168);

  const listInput = useMemo(() => ({
    type: typeFilter || undefined,
  } as any), [typeFilter]);

  const { data, isLoading, refetch } = trpc.validationScheduler.list.useQuery(
    typeFilter ? listInput : undefined
  );
  const { data: stats } = trpc.validationScheduler.stats.useQuery();

  const createMutation = trpc.validationScheduler.create.useMutation({
    onSuccess: () => {
      toast.success("Validation schedule created");
      setShowCreate(false);
      setNewName("");
      setNewTargetId("");
      setNewTargetLabel("");
      refetch();
    },
    onError: (err) => toast.error(sanitizeErrorForToast(err)),
  });

  const toggleMutation = trpc.validationScheduler.toggle.useMutation({
    onSuccess: () => {
      toast.success("Schedule updated");
      refetch();
    },
  });

  const deleteMutation = trpc.validationScheduler.delete.useMutation({
    onSuccess: () => {
      toast.success("Schedule deleted");
      refetch();
    },
  });

  const filtered = (data?.items || []).filter(s =>
    !search || s.name.toLowerCase().includes(search.toLowerCase()) ||
    s.targetLabel?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <Calendar className="h-7 w-7 text-cyan-400" />
            Continuous Validation
          </h1>
          <p className="text-muted-foreground mt-1">
            Schedule recurring scans, emulations, and campaign retests to maintain continuous security validation
          </p>
        </div>
        <Button className="gap-2" onClick={() => setShowCreate(true)}>
          <Plus className="h-4 w-4" />
          New Schedule
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4 text-center">
            <Calendar className="h-5 w-5 mx-auto mb-1 text-cyan-400" />
            <div className="text-2xl font-bold">{stats?.total ?? 0}</div>
            <div className="text-xs text-muted-foreground">Total</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4 text-center">
            <Play className="h-5 w-5 mx-auto mb-1 text-emerald-400" />
            <div className="text-2xl font-bold text-emerald-400">{stats?.active ?? 0}</div>
            <div className="text-xs text-muted-foreground">Active</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4 text-center">
            <Loader2 className="h-5 w-5 mx-auto mb-1 text-blue-400" />
            <div className="text-2xl font-bold text-blue-400">{stats?.running ?? 0}</div>
            <div className="text-xs text-muted-foreground">Running</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4 text-center">
            <AlertTriangle className="h-5 w-5 mx-auto mb-1 text-amber-400" />
            <div className="text-2xl font-bold text-amber-400">{stats?.overdue ?? 0}</div>
            <div className="text-xs text-muted-foreground">Overdue</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4 text-center">
            <XCircle className="h-5 w-5 mx-auto mb-1 text-red-400" />
            <div className="text-2xl font-bold text-red-400">{stats?.failed ?? 0}</div>
            <div className="text-xs text-muted-foreground">Failed</div>
          </CardContent>
        </Card>
      </div>

      {/* Type Distribution */}
      {stats?.byType && Object.keys(stats.byType).length > 0 && (
        <div className="flex gap-3 flex-wrap">
          {SCHEDULE_TYPES.map(st => {
            const count = stats.byType[st.value] || 0;
            if (!count) return null;
            return (
              <Badge key={st.value} variant="outline" className={`gap-1.5 ${st.color}`}>
                <st.icon className="h-3 w-3" />
                {st.label}: {count}
              </Badge>
            );
          })}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search schedules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="All Types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {SCHEDULE_TYPES.map(st => (
              <SelectItem key={st.value} value={st.value}>{st.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Schedule List */}
      {isLoading ? (
        <div className="text-center py-12 text-muted-foreground">Loading schedules...</div>
      ) : filtered.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Calendar className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
            <h3 className="text-lg font-medium mb-2">No Validation Schedules</h3>
            <p className="text-muted-foreground mb-4">
              Create your first schedule to start continuous security validation
            </p>
            <Button onClick={() => setShowCreate(true)} className="gap-2">
              <Plus className="h-4 w-4" />
              Create Schedule
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {filtered.map(schedule => {
            const typeConfig = SCHEDULE_TYPES.find(t => t.value === schedule.scheduleType) || SCHEDULE_TYPES[0];
            const TypeIcon = typeConfig.icon;
            const isOverdue = schedule.enabled && schedule.nextRunAt && new Date(schedule.nextRunAt) < new Date();

            return (
              <Card key={schedule.id} className={`transition-all ${!schedule.enabled ? "opacity-50" : ""} ${isOverdue ? "border-amber-500/30" : ""}`}>
                <CardContent className="p-4">
                  <div className="flex items-center gap-4">
                    {/* Type Icon */}
                    <div className={`p-2.5 rounded-lg ${typeConfig.bg}`}>
                      <TypeIcon className={`h-5 w-5 ${typeConfig.color}`} />
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium truncate">{schedule.name}</h3>
                        <Badge variant="outline" className={`text-[10px] ${typeConfig.color}`}>
                          {typeConfig.label}
                        </Badge>
                        {schedule.lastStatus === "running" && (
                          <Badge className="bg-blue-500/20 text-blue-400 text-[10px]">
                            <Loader2 className="h-2.5 w-2.5 mr-1 animate-spin" />
                            Running
                          </Badge>
                        )}
                        {schedule.lastStatus === "failed" && (
                          <Badge className="bg-red-500/20 text-red-400 text-[10px]">
                            <XCircle className="h-2.5 w-2.5 mr-1" />
                            Failed
                          </Badge>
                        )}
                        {isOverdue && (
                          <Badge className="bg-amber-500/20 text-amber-400 text-[10px]">
                            <AlertTriangle className="h-2.5 w-2.5 mr-1" />
                            Overdue
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                        {schedule.targetLabel && (
                          <span className="flex items-center gap-1">
                            <Target className="h-3 w-3" />
                            {schedule.targetLabel}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Timer className="h-3 w-3" />
                          Every {formatInterval(schedule.intervalHours)}
                        </span>
                        <span className="flex items-center gap-1">
                          <RefreshCw className="h-3 w-3" />
                          {schedule.runCount} runs
                        </span>
                        {schedule.lastRunAt && (
                          <span>Last: {formatRelativeTime(schedule.lastRunAt)}</span>
                        )}
                        {schedule.nextRunAt && (
                          <span className={isOverdue ? "text-amber-400" : ""}>
                            Next: {formatRelativeTime(schedule.nextRunAt)}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-3">
                      <Switch
                        checked={schedule.enabled}
                        onCheckedChange={(enabled) => toggleMutation.mutate({ id: schedule.id, enabled })}
                      />
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-red-400 hover:text-red-300"
                        onClick={() => {
                          if (confirm("Delete this schedule?")) {
                            deleteMutation.mutate({ id: schedule.id });
                          }
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  {/* Error Display */}
                  {schedule.lastError && (
                    <div className="mt-2 p-2 rounded bg-red-500/10 border border-red-500/20 text-xs text-red-400">
                      <AlertTriangle className="h-3 w-3 inline mr-1" />
                      {schedule.lastError}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Calendar className="h-5 w-5 text-cyan-400" />
              New Validation Schedule
            </DialogTitle>
            <DialogDescription>
              Set up a recurring validation task to continuously test your security posture
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <Label>Schedule Name</Label>
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g., Weekly Domain Scan - tesla.com"
              />
            </div>
            <div>
              <Label>Validation Type</Label>
              <Select value={newType} onValueChange={setNewType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SCHEDULE_TYPES.map(st => (
                    <SelectItem key={st.value} value={st.value}>
                      <span className="flex items-center gap-2">
                        <st.icon className={`h-4 w-4 ${st.color}`} />
                        {st.label}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Target ID</Label>
                <Input
                  value={newTargetId}
                  onChange={(e) => setNewTargetId(e.target.value)}
                  placeholder="e.g., tesla.com"
                />
              </div>
              <div>
                <Label>Target Label</Label>
                <Input
                  value={newTargetLabel}
                  onChange={(e) => setNewTargetLabel(e.target.value)}
                  placeholder="e.g., Tesla Inc."
                />
              </div>
            </div>
            <div>
              <Label>Run Interval</Label>
              <Select value={String(newInterval)} onValueChange={(v) => setNewInterval(Number(v))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTERVAL_PRESETS.map(p => (
                    <SelectItem key={p.hours} value={String(p.hours)}>{p.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button
              disabled={!newName || createMutation.isPending}
              onClick={() => createMutation.mutate({
                name: newName,
                scheduleType: newType as any,
                targetId: newTargetId || undefined,
                targetLabel: newTargetLabel || undefined,
                intervalHours: newInterval,
              })}
            >
              {createMutation.isPending ? "Creating..." : "Create Schedule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
