/**
 * Remediation Tracking Dashboard
 *
 * Track vulnerability remediation tasks across engagements — assign to teams,
 * monitor SLA compliance, track fix rates, and verify fixes via re-scans.
 * This page gives executives and operators visibility into the remediation
 * pipeline from finding to verified fix.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast as sonnerToast } from "sonner";
import {
  Shield, Clock, CheckCircle2, AlertTriangle, Users, TrendingUp,
  Plus, Filter, ArrowUpDown, Timer, Target, XCircle, Pause,
  RotateCcw, ChevronRight, BarChart3, Calendar, Search,
} from "lucide-react";

// ─── Constants ───────────────────────────────────────────────────────────────
const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  open: "bg-red-500/20 text-red-400",
  assigned: "bg-blue-500/20 text-blue-400",
  in_progress: "bg-yellow-500/20 text-yellow-400",
  fixed: "bg-green-500/20 text-green-400",
  verified: "bg-emerald-500/20 text-emerald-400",
  wont_fix: "bg-slate-500/20 text-slate-400",
  deferred: "bg-purple-500/20 text-purple-400",
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  open: <AlertTriangle className="h-3.5 w-3.5" />,
  assigned: <Users className="h-3.5 w-3.5" />,
  in_progress: <Timer className="h-3.5 w-3.5" />,
  fixed: <CheckCircle2 className="h-3.5 w-3.5" />,
  verified: <Shield className="h-3.5 w-3.5" />,
  wont_fix: <XCircle className="h-3.5 w-3.5" />,
  deferred: <Pause className="h-3.5 w-3.5" />,
};

const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  assigned: "Assigned",
  in_progress: "In Progress",
  fixed: "Fixed",
  verified: "Verified",
  wont_fix: "Won't Fix",
  deferred: "Deferred",
};

const TEAMS = [
  "Infrastructure",
  "Application Security",
  "Cloud Security",
  "Network Security",
  "Identity & Access",
  "Endpoint Security",
  "SOC",
  "DevSecOps",
];

export default function RemediationTracking() {
  const toast = (opts: { title: string; description?: string; variant?: string }) => {
    if (opts.variant === "destructive") sonnerToast.error(opts.title);
    else sonnerToast.success(opts.title, { description: opts.description });
  };
  const [activeTab, setActiveTab] = useState("overview");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterTeam, setFilterTeam] = useState<string>("all");
  const [showOverdueOnly, setShowOverdueOnly] = useState(false);
  const [selectedTasks, setSelectedTasks] = useState<number[]>([]);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showAssignDialog, setShowAssignDialog] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // ─── Data Queries ──────────────────────────────────────────────────────────
  const statsQuery = trpc.remediation.getStats.useQuery();
  const teamsQuery = trpc.remediation.getTeams.useQuery();
  const slaQuery = trpc.remediation.getSlaTimeline.useQuery({ daysAhead: 14 });
  const tasksQuery = trpc.remediation.list.useQuery({
    status: filterStatus !== "all" ? filterStatus as any : undefined,
    severity: filterSeverity !== "all" ? filterSeverity as any : undefined,
    assignedTeam: filterTeam !== "all" ? filterTeam : undefined,
    overdueSlaOnly: showOverdueOnly || undefined,
    limit: 100,
  });

  // ─── Mutations ─────────────────────────────────────────────────────────────
  const utils = trpc.useUtils();
  const createMutation = trpc.remediation.create.useMutation({
    onSuccess: () => {
      utils.remediation.invalidate();
      setShowCreateDialog(false);
      toast({ title: "Task created", description: "Remediation task has been created successfully." });
    },
  });
  const updateMutation = trpc.remediation.update.useMutation({
    onSuccess: () => {
      utils.remediation.invalidate();
      toast({ title: "Task updated" });
    },
  });
  const bulkAssignMutation = trpc.remediation.bulkAssign.useMutation({
    onSuccess: (data) => {
      utils.remediation.invalidate();
      setSelectedTasks([]);
      setShowAssignDialog(false);
      toast({ title: "Tasks assigned", description: `${data.updated} tasks assigned successfully.` });
    },
  });

  // ─── Create Form State ─────────────────────────────────────────────────────
  const [newTask, setNewTask] = useState({
    engagementId: 1,
    title: "",
    description: "",
    severity: "medium" as const,
    assignedTeam: "",
    cveId: "",
    affectedAsset: "",
    remediationGuidance: "",
  });

  const [bulkTeam, setBulkTeam] = useState("");

  const stats = statsQuery.data;
  const tasks = tasksQuery.data?.tasks ?? [];
  const slaTimeline = slaQuery.data ?? [];

  // Filter tasks by search
  const filteredTasks = useMemo(() => {
    if (!searchQuery) return tasks;
    const q = searchQuery.toLowerCase();
    return tasks.filter(
      (t) =>
        t.title.toLowerCase().includes(q) ||
        t.affectedAsset?.toLowerCase().includes(q) ||
        t.cveId?.toLowerCase().includes(q) ||
        t.assignedTeam?.toLowerCase().includes(q)
    );
  }, [tasks, searchQuery]);

  // ─── Helpers ───────────────────────────────────────────────────────────────
  function formatTimeRemaining(hours: number | null): string {
    if (hours === null) return "No SLA";
    if (hours < 0) return `${Math.abs(hours)}h overdue`;
    if (hours < 24) return `${hours}h remaining`;
    return `${Math.floor(hours / 24)}d ${hours % 24}h remaining`;
  }

  function handleStatusChange(taskId: number, newStatus: string) {
    updateMutation.mutate({ id: taskId, status: newStatus as any });
  }

  function handleToggleSelect(taskId: number) {
    setSelectedTasks((prev) =>
      prev.includes(taskId) ? prev.filter((id) => id !== taskId) : [...prev, taskId]
    );
  }

  function handleSelectAll() {
    if (selectedTasks.length === filteredTasks.length) {
      setSelectedTasks([]);
    } else {
      setSelectedTasks(filteredTasks.map((t) => t.id));
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Remediation Tracking</h1>
          <p className="text-muted-foreground mt-1">
            Track vulnerability fixes from finding to verified remediation. Assign to teams, monitor SLA compliance, and verify fixes through re-scans.
          </p>
        </div>
        <Button onClick={() => setShowCreateDialog(true)} className="gap-2">
          <Plus className="h-4 w-4" />
          New Task
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="gap-2">
            <BarChart3 className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="tasks" className="gap-2">
            <Target className="h-4 w-4" />
            Tasks
          </TabsTrigger>
          <TabsTrigger value="sla" className="gap-2">
            <Clock className="h-4 w-4" />
            SLA Timeline
          </TabsTrigger>
          <TabsTrigger value="teams" className="gap-2">
            <Users className="h-4 w-4" />
            Team Performance
          </TabsTrigger>
        </TabsList>

        {/* ═══════════════════ OVERVIEW TAB ═══════════════════ */}
        <TabsContent value="overview" className="space-y-6">
          {/* KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <Card className="border-border/50">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-muted-foreground uppercase tracking-wider">Total Tasks</div>
                <div className="text-2xl font-bold mt-1">{stats?.total ?? 0}</div>
              </CardContent>
            </Card>
            <Card className="border-red-500/30">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-red-400 uppercase tracking-wider flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> Overdue
                </div>
                <div className="text-2xl font-bold mt-1 text-red-400">{stats?.overdue ?? 0}</div>
              </CardContent>
            </Card>
            <Card className="border-green-500/30">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-green-400 uppercase tracking-wider">Fix Rate</div>
                <div className="text-2xl font-bold mt-1 text-green-400">{stats?.fixRate ?? 0}%</div>
              </CardContent>
            </Card>
            <Card className="border-blue-500/30">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-blue-400 uppercase tracking-wider">SLA Compliance</div>
                <div className="text-2xl font-bold mt-1 text-blue-400">{stats?.slaComplianceRate ?? 0}%</div>
              </CardContent>
            </Card>
            <Card className="border-yellow-500/30">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-yellow-400 uppercase tracking-wider">Avg Fix Time</div>
                <div className="text-2xl font-bold mt-1 text-yellow-400">
                  {stats?.avgFixTimeHours ? `${stats.avgFixTimeHours}h` : "N/A"}
                </div>
              </CardContent>
            </Card>
            <Card className="border-orange-500/30">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="text-xs text-orange-400 uppercase tracking-wider">Critical Open</div>
                <div className="text-2xl font-bold mt-1 text-orange-400">
                  {(stats?.critical ?? 0) - (stats?.fixed ?? 0) - (stats?.verified ?? 0)}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Status Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Status Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { key: "open", label: "Open", count: stats?.open ?? 0 },
                    { key: "assigned", label: "Assigned", count: stats?.assigned ?? 0 },
                    { key: "in_progress", label: "In Progress", count: stats?.inProgress ?? 0 },
                    { key: "fixed", label: "Fixed", count: stats?.fixed ?? 0 },
                    { key: "verified", label: "Verified", count: stats?.verified ?? 0 },
                    { key: "wont_fix", label: "Won't Fix", count: stats?.wontFix ?? 0 },
                    { key: "deferred", label: "Deferred", count: stats?.deferred ?? 0 },
                  ].map(({ key, label, count }) => (
                    <div key={key} className="flex items-center gap-3">
                      <div className="w-24 text-sm text-muted-foreground">{label}</div>
                      <div className="flex-1">
                        <Progress
                          value={stats?.total ? (count / stats.total) * 100 : 0}
                          className="h-2"
                        />
                      </div>
                      <div className="w-10 text-right text-sm font-medium">{count}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Severity Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { key: "critical", label: "Critical", count: stats?.critical ?? 0, color: "bg-red-500" },
                    { key: "high", label: "High", count: stats?.high ?? 0, color: "bg-orange-500" },
                    { key: "medium", label: "Medium", count: stats?.medium ?? 0, color: "bg-yellow-500" },
                    { key: "low", label: "Low", count: stats?.low ?? 0, color: "bg-blue-500" },
                  ].map(({ key, label, count, color }) => (
                    <div key={key} className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${color}`} />
                      <div className="w-20 text-sm text-muted-foreground">{label}</div>
                      <div className="flex-1">
                        <Progress
                          value={stats?.total ? (count / stats.total) * 100 : 0}
                          className="h-2"
                        />
                      </div>
                      <div className="w-10 text-right text-sm font-medium">{count}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Overdue SLA Alert */}
          {(stats?.overdue ?? 0) > 0 && (
            <Card className="border-red-500/50 bg-red-500/5">
              <CardContent className="pt-4 pb-3 px-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  <div>
                    <div className="font-medium text-red-400">
                      {stats?.overdue} tasks have exceeded their SLA deadline
                    </div>
                    <div className="text-sm text-muted-foreground mt-0.5">
                      Review overdue tasks and escalate or adjust SLA targets as needed.
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="ml-auto border-red-500/30 text-red-400 hover:bg-red-500/10"
                    onClick={() => {
                      setShowOverdueOnly(true);
                      setActiveTab("tasks");
                    }}
                  >
                    View Overdue
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ═══════════════════ TASKS TAB ═══════════════════ */}
        <TabsContent value="tasks" className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search tasks, assets, CVEs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="assigned">Assigned</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="fixed">Fixed</SelectItem>
                <SelectItem value="verified">Verified</SelectItem>
                <SelectItem value="wont_fix">Won't Fix</SelectItem>
                <SelectItem value="deferred">Deferred</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterSeverity} onValueChange={setFilterSeverity}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterTeam} onValueChange={setFilterTeam}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Team" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Teams</SelectItem>
                {(teamsQuery.data ?? TEAMS).map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <Checkbox
                id="overdue-only"
                checked={showOverdueOnly}
                onCheckedChange={(v) => setShowOverdueOnly(!!v)}
              />
              <label htmlFor="overdue-only" className="text-sm text-muted-foreground cursor-pointer">
                Overdue only
              </label>
            </div>
            {selectedTasks.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                onClick={() => setShowAssignDialog(true)}
              >
                <Users className="h-3.5 w-3.5" />
                Assign {selectedTasks.length} selected
              </Button>
            )}
          </div>

          {/* Tasks Table */}
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      checked={selectedTasks.length === filteredTasks.length && filteredTasks.length > 0}
                      onCheckedChange={handleSelectAll}
                    />
                  </TableHead>
                  <TableHead>Task</TableHead>
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-36">Team</TableHead>
                  <TableHead className="w-36">SLA</TableHead>
                  <TableHead className="w-32">Asset</TableHead>
                  <TableHead className="w-28">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredTasks.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
                      {tasksQuery.isLoading ? "Loading tasks..." : "No remediation tasks found. Create one to get started."}
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredTasks.map((task) => {
                    const isOverdue = task.slaDeadline && new Date(task.slaDeadline) < new Date() &&
                      !["fixed", "verified", "wont_fix"].includes(task.status);
                    const hoursRemaining = task.slaDeadline
                      ? Math.round((new Date(task.slaDeadline).getTime() - Date.now()) / (60 * 60 * 1000))
                      : null;

                    return (
                      <TableRow key={task.id} className={isOverdue ? "bg-red-500/5" : ""}>
                        <TableCell>
                          <Checkbox
                            checked={selectedTasks.includes(task.id)}
                            onCheckedChange={() => handleToggleSelect(task.id)}
                          />
                        </TableCell>
                        <TableCell>
                          <div>
                            <div className="font-medium text-sm line-clamp-1">{task.title}</div>
                            {task.cveId && (
                              <span className="text-xs text-muted-foreground font-mono">{task.cveId}</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-xs ${SEVERITY_COLORS[task.severity]}`}>
                            {task.severity.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-xs gap-1 ${STATUS_COLORS[task.status]}`}>
                            {STATUS_ICONS[task.status]}
                            {STATUS_LABELS[task.status]}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="text-sm text-muted-foreground">
                            {task.assignedTeam || "Unassigned"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`text-xs ${isOverdue ? "text-red-400 font-medium" : "text-muted-foreground"}`}>
                            {isOverdue && <AlertTriangle className="h-3 w-3 inline mr-1" />}
                            {formatTimeRemaining(hoursRemaining)}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground font-mono line-clamp-1">
                            {task.affectedAsset || "-"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Select
                            value={task.status}
                            onValueChange={(v) => handleStatusChange(task.id, v)}
                          >
                            <SelectTrigger className="h-7 text-xs w-[100px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="open">Open</SelectItem>
                              <SelectItem value="assigned">Assigned</SelectItem>
                              <SelectItem value="in_progress">In Progress</SelectItem>
                              <SelectItem value="fixed">Fixed</SelectItem>
                              <SelectItem value="verified">Verified</SelectItem>
                              <SelectItem value="wont_fix">Won't Fix</SelectItem>
                              <SelectItem value="deferred">Deferred</SelectItem>
                            </SelectContent>
                          </Select>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </Card>
          <div className="text-sm text-muted-foreground">
            Showing {filteredTasks.length} of {tasksQuery.data?.total ?? 0} tasks
          </div>
        </TabsContent>

        {/* ═══════════════════ SLA TIMELINE TAB ═══════════════════ */}
        <TabsContent value="sla" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4" />
                SLA Timeline (Next 14 Days)
              </CardTitle>
              <CardDescription>
                Tasks approaching or past their SLA deadline, ordered by urgency.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {slaTimeline.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No tasks with upcoming SLA deadlines.
                </div>
              ) : (
                <div className="space-y-3">
                  {slaTimeline.map((task) => (
                    <div
                      key={task.id}
                      className={`flex items-center gap-4 p-3 rounded-lg border ${
                        task.isOverdue ? "border-red-500/30 bg-red-500/5" : "border-border/50"
                      }`}
                    >
                      <div className={`w-2 h-2 rounded-full ${task.isOverdue ? "bg-red-500 animate-pulse" : "bg-yellow-500"}`} />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-sm line-clamp-1">{task.title}</div>
                        <div className="flex items-center gap-3 mt-1">
                          <Badge variant="outline" className={`text-xs ${SEVERITY_COLORS[task.severity]}`}>
                            {task.severity}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {task.assignedTeam || "Unassigned"}
                          </span>
                          {task.affectedAsset && (
                            <span className="text-xs text-muted-foreground font-mono">
                              {task.affectedAsset}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        <div className={`text-sm font-medium ${task.isOverdue ? "text-red-400" : "text-yellow-400"}`}>
                          {formatTimeRemaining(task.hoursRemaining)}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {task.slaDeadline ? new Date(task.slaDeadline).toLocaleDateString() : ""}
                        </div>
                      </div>
                      <Select
                        value={task.status}
                        onValueChange={(v) => handleStatusChange(task.id, v)}
                      >
                        <SelectTrigger className="h-7 text-xs w-[100px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="open">Open</SelectItem>
                          <SelectItem value="assigned">Assigned</SelectItem>
                          <SelectItem value="in_progress">In Progress</SelectItem>
                          <SelectItem value="fixed">Fixed</SelectItem>
                          <SelectItem value="verified">Verified</SelectItem>
                          <SelectItem value="wont_fix">Won't Fix</SelectItem>
                          <SelectItem value="deferred">Deferred</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ═══════════════════ TEAM PERFORMANCE TAB ═══════════════════ */}
        <TabsContent value="teams" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Users className="h-4 w-4" />
                Team Performance
              </CardTitle>
              <CardDescription>
                Fix rates, SLA compliance, and workload distribution by team.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {(stats?.teamBreakdown ?? []).length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  No team assignments yet. Assign tasks to teams to see performance metrics.
                </div>
              ) : (
                <div className="space-y-4">
                  {stats?.teamBreakdown.map((team) => (
                    <div key={team.team} className="p-4 rounded-lg border border-border/50">
                      <div className="flex items-center justify-between mb-3">
                        <div className="font-medium">{team.team}</div>
                        <div className="flex items-center gap-4 text-sm">
                          <span className="text-muted-foreground">
                            {team.total} tasks
                          </span>
                          <span className="text-green-400">
                            {team.fixRate}% fixed
                          </span>
                          {team.overdue > 0 && (
                            <span className="text-red-400 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" />
                              {team.overdue} overdue
                            </span>
                          )}
                        </div>
                      </div>
                      <Progress value={team.fixRate} className="h-2" />
                      <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                        <span>{team.fixed} fixed</span>
                        <span>{team.total - team.fixed} remaining</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ═══════════════════ CREATE TASK DIALOG ═══════════════════ */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Create Remediation Task</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-1 block">Title</label>
              <Input
                placeholder="e.g., Patch CVE-2024-1234 on web server"
                value={newTask.title}
                onChange={(e) => setNewTask({ ...newTask, title: e.target.value })}
              />
            </div>
            <div>
              <label className="text-sm font-medium mb-1 block">Description</label>
              <Textarea
                placeholder="Detailed description of the vulnerability and remediation steps..."
                value={newTask.description}
                onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                rows={3}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-1 block">Severity</label>
                <Select
                  value={newTask.severity}
                  onValueChange={(v) => setNewTask({ ...newTask, severity: v as any })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="info">Info</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-sm font-medium mb-1 block">Assign Team</label>
                <Select
                  value={newTask.assignedTeam || "none"}
                  onValueChange={(v) => setNewTask({ ...newTask, assignedTeam: v === "none" ? "" : v })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select team" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">Unassigned</SelectItem>
                    {TEAMS.map((t) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium mb-1 block">CVE ID</label>
                <Input
                  placeholder="CVE-2024-XXXX"
                  value={newTask.cveId}
                  onChange={(e) => setNewTask({ ...newTask, cveId: e.target.value })}
                />
              </div>
              <div>
                <label className="text-sm font-medium mb-1 block">Affected Asset</label>
                <Input
                  placeholder="e.g., web-server-01"
                  value={newTask.affectedAsset}
                  onChange={(e) => setNewTask({ ...newTask, affectedAsset: e.target.value })}
                />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium mb-1 block">Remediation Guidance</label>
              <Textarea
                placeholder="Steps to fix this vulnerability..."
                value={newTask.remediationGuidance}
                onChange={(e) => setNewTask({ ...newTask, remediationGuidance: e.target.value })}
                rows={2}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!newTask.title.trim()) {
                  toast({ title: "Title required", variant: "destructive" });
                  return;
                }
                createMutation.mutate({
                  engagementId: newTask.engagementId,
                  title: newTask.title,
                  description: newTask.description || undefined,
                  severity: newTask.severity,
                  assignedTeam: newTask.assignedTeam || undefined,
                  cveId: newTask.cveId || undefined,
                  affectedAsset: newTask.affectedAsset || undefined,
                  remediationGuidance: newTask.remediationGuidance || undefined,
                });
              }}
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? "Creating..." : "Create Task"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ═══════════════════ BULK ASSIGN DIALOG ═══════════════════ */}
      <Dialog open={showAssignDialog} onOpenChange={setShowAssignDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign {selectedTasks.length} Tasks</DialogTitle>
          </DialogHeader>
          <div>
            <label className="text-sm font-medium mb-1 block">Team</label>
            <Select value={bulkTeam || "none"} onValueChange={(v) => setBulkTeam(v === "none" ? "" : v)}>
              <SelectTrigger>
                <SelectValue placeholder="Select team" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Select a team</SelectItem>
                {TEAMS.map((t) => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAssignDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={() => {
                if (!bulkTeam) {
                  toast({ title: "Select a team", variant: "destructive" });
                  return;
                }
                bulkAssignMutation.mutate({
                  taskIds: selectedTasks,
                  assignedTeam: bulkTeam,
                });
              }}
              disabled={bulkAssignMutation.isPending || !bulkTeam}
            >
              {bulkAssignMutation.isPending ? "Assigning..." : "Assign"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
