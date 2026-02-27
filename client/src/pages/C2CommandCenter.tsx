import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import {
  Radio, Server, Shield, Activity, Cpu, Network, Terminal,
  Play, Square, RefreshCw, Loader2, AlertTriangle, CheckCircle,
  XCircle, Zap, GitBranch, Layers, Target, Eye, Lock,
  ArrowRight, Clock, BarChart3, Brain, Hexagon, Crosshair,
  Package, Settings, Code, FileCode, Download, Upload,
  Workflow, ArrowLeftRight, Gauge, Sparkles, Swords, Diamond,
} from "lucide-react";

// ─── Types ──────────────────────────────────────────────────────────────────

type C2Framework = "caldera" | "metasploit" | "sliver" | "empire" | "cobaltstrike";

const FRAMEWORK_META: Record<C2Framework, { label: string; color: string; icon: React.ReactNode; description: string }> = {
  caldera: { label: "CALDERA", color: "bg-red-500/10 text-red-400 border-red-500/20", icon: <Target className="h-5 w-5 text-red-400" />, description: "MITRE ATT&CK adversary emulation" },
  metasploit: { label: "METASPLOIT", color: "bg-blue-500/10 text-blue-400 border-blue-500/20", icon: <Crosshair className="h-5 w-5 text-blue-400" />, description: "Exploitation framework" },
  sliver: { label: "SLIVER", color: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20", icon: <Hexagon className="h-5 w-5 text-emerald-400" />, description: "Implant C2 framework" },
  empire: { label: "EMPIRE", color: "bg-purple-500/10 text-purple-400 border-purple-500/20", icon: <Swords className="h-5 w-5 text-purple-400" />, description: "PowerShell/Python post-exploitation" },
  cobaltstrike: { label: "COBALT STRIKE", color: "bg-orange-500/10 text-orange-400 border-orange-500/20", icon: <Diamond className="h-5 w-5 text-orange-400" />, description: "Commercial red team C2 platform" },
};

const FRAMEWORK_BAR_COLORS: Record<C2Framework, string> = {
  caldera: "bg-red-500",
  metasploit: "bg-blue-500",
  sliver: "bg-emerald-500",
  empire: "bg-purple-500",
  cobaltstrike: "bg-orange-500",
};

// ─── Framework Status Card ──────────────────────────────────────────────────

function FrameworkStatusCard({ framework }: { framework: C2Framework }) {
  const meta = FRAMEWORK_META[framework];
  const healthQuery = trpc.abilityGraph.c2Health.useQuery();
  const health = healthQuery.data?.find((h: any) => h.framework === framework);

  return (
    <Card className="bg-zinc-900/50 border-zinc-800">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${meta.color.split(" ")[0]}`}>
              {meta.icon}
            </div>
            <div>
              <CardTitle className="text-sm font-mono">{meta.label}</CardTitle>
              <CardDescription className="text-xs">{meta.description}</CardDescription>
            </div>
          </div>
          {healthQuery.isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />
          ) : health?.connected ? (
            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
              <CheckCircle className="h-3 w-3 mr-1" /> ONLINE
            </Badge>
          ) : (
            <Badge className="bg-zinc-700/50 text-zinc-400 border-zinc-600/30">
              <XCircle className="h-3 w-3 mr-1" /> OFFLINE
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div className="text-lg font-mono font-bold text-white">{health?.agentCount ?? "—"}</div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Agents</div>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div className="text-lg font-mono font-bold text-white">{health?.activeJobs ?? "—"}</div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Active Jobs</div>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <div className="text-lg font-mono font-bold text-white">
              {health?.details?.moduleCount ?? health?.details?.listenerCount ?? "—"}
            </div>
            <div className="text-[10px] text-zinc-500 uppercase tracking-wider">
              {framework === "cobaltstrike" ? "Listeners" : "Modules"}
            </div>
          </div>
        </div>
        {health?.version && (
          <div className="mt-3 text-[10px] text-zinc-600 font-mono">v{health.version}</div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Unified Agent Table ────────────────────────────────────────────────────

function UnifiedAgentView() {
  const [frameworkFilter, setFrameworkFilter] = useState<string>("all");
  const agentsQuery = trpc.abilityGraph.c2Agents.useQuery(
    frameworkFilter !== "all" ? { framework: frameworkFilter as any } : undefined
  );
  const [filter, setFilter] = useState("");

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Input
          placeholder="Filter agents by hostname, platform, or framework..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="bg-zinc-900 border-zinc-700 max-w-md"
        />
        <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
          <SelectTrigger className="bg-zinc-900 border-zinc-700 w-48">
            <SelectValue placeholder="All Frameworks" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Frameworks</SelectItem>
            {Object.entries(FRAMEWORK_META).map(([k, v]) => (
              <SelectItem key={k} value={k}>{v.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => agentsQuery.refetch()} className="border-zinc-700">
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-zinc-900/80 border-b border-zinc-800">
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">AGENT</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">FRAMEWORK</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">PLATFORM</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">STATUS</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">LAST SEEN</th>
              <th className="text-right p-3 text-zinc-400 font-mono text-xs">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {agentsQuery.isLoading ? (
              <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                <Loader2 className="h-5 w-5 animate-spin mx-auto mb-2" /> Loading agents...
              </td></tr>
            ) : !(agentsQuery.data as any)?.length ? (
              <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                <Server className="h-8 w-8 mx-auto mb-2 opacity-30" />
                No agents connected. Deploy agents from each C2 framework to see them here.
              </td></tr>
            ) : (
              (agentsQuery.data as any[])
                .filter((a: any) => !filter || a.hostname?.toLowerCase().includes(filter.toLowerCase()) || a.platform?.toLowerCase().includes(filter.toLowerCase()) || a.framework?.toLowerCase().includes(filter.toLowerCase()))
                .map((agent: any, i: number) => (
                  <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                    <td className="p-3">
                      <div className="font-mono text-white">{agent.hostname || agent.id}</div>
                      <div className="text-[10px] text-zinc-500">{agent.id}</div>
                    </td>
                    <td className="p-3">
                      <Badge className={FRAMEWORK_META[agent.framework as C2Framework]?.color || "bg-zinc-700"}>
                        {agent.framework?.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="p-3 text-zinc-300 font-mono text-xs">{agent.platform || "—"}</td>
                    <td className="p-3">
                      <Badge className={agent.status === "active" ? "bg-emerald-500/10 text-emerald-400" : agent.status === "dormant" ? "bg-amber-500/10 text-amber-400" : "bg-red-500/10 text-red-400"}>
                        {agent.status?.toUpperCase() || "UNKNOWN"}
                      </Badge>
                    </td>
                    <td className="p-3 text-zinc-400 text-xs font-mono">{agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "—"}</td>
                    <td className="p-3 text-right">
                      <Button variant="outline" size="sm" className="border-zinc-700 h-7 text-xs" onClick={() => toast.info("Task dispatch coming soon")}>
                        <Terminal className="h-3 w-3 mr-1" /> Task
                      </Button>
                    </td>
                  </tr>
                ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Module Builder ─────────────────────────────────────────────────────────

function ModuleBuilder() {
  const [framework, setFramework] = useState<C2Framework>("caldera");
  const [techniqueId, setTechniqueId] = useState("");
  const [techniqueName, setTechniqueName] = useState("");
  const [platform, setPlatform] = useState("windows");
  const [targetService, setTargetService] = useState("");
  const [cveId, setCveId] = useState("");
  const [evasionLevel, setEvasionLevel] = useState("basic");
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);

  const generateMut = trpc.abilityGraph.generateModule.useMutation({
    onSuccess: (data: any) => {
      setGeneratedCode(data?.code || "// Module generated successfully");
      toast.success("Module generated");
    },
    onError: (err: any) => toast.error(err.message),
  });

  const pushMut = trpc.abilityGraph.pushModules.useMutation({
    onSuccess: () => toast.success("Module pushed to C2"),
    onError: (err: any) => toast.error(err.message),
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <Settings className="h-4 w-4 text-amber-400" /> MODULE CONFIGURATION
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-zinc-400">Target Framework</Label>
              <Select value={framework} onValueChange={(v) => setFramework(v as C2Framework)}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {Object.entries(FRAMEWORK_META).map(([k, v]) => (
                    <SelectItem key={k} value={k}>{v.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-zinc-400">Platform</Label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="darwin">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div>
            <Label className="text-xs text-zinc-400">MITRE ATT&CK Technique ID</Label>
            <Input value={techniqueId} onChange={(e) => setTechniqueId(e.target.value)} placeholder="T1059.001" className="bg-zinc-800 border-zinc-700" />
          </div>

          <div>
            <Label className="text-xs text-zinc-400">Technique Name</Label>
            <Input value={techniqueName} onChange={(e) => setTechniqueName(e.target.value)} placeholder="PowerShell Execution" className="bg-zinc-800 border-zinc-700" />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-zinc-400">Target Service (optional)</Label>
              <Input value={targetService} onChange={(e) => setTargetService(e.target.value)} placeholder="SMB, HTTP, SSH..." className="bg-zinc-800 border-zinc-700" />
            </div>
            <div>
              <Label className="text-xs text-zinc-400">CVE ID (optional)</Label>
              <Input value={cveId} onChange={(e) => setCveId(e.target.value)} placeholder="CVE-2024-1234" className="bg-zinc-800 border-zinc-700" />
            </div>
          </div>

          <div>
            <Label className="text-xs text-zinc-400">Evasion Level</Label>
            <Select value={evasionLevel} onValueChange={setEvasionLevel}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="basic">Basic</SelectItem>
                <SelectItem value="advanced">Advanced</SelectItem>
                <SelectItem value="maximum">Maximum</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Button
            onClick={() => generateMut.mutate({ framework, techniqueId, techniqueName, platform, targetService: targetService || undefined, cveId: cveId || undefined, evasionLevel: evasionLevel as any })}
            disabled={!techniqueId || !techniqueName || generateMut.isPending}
            className="w-full bg-amber-600 hover:bg-amber-500"
          >
            {generateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Sparkles className="h-4 w-4 mr-2" />}
            Generate Module
          </Button>
        </CardContent>
      </Card>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Code className="h-4 w-4 text-cyan-400" /> GENERATED CODE
            </CardTitle>
            {generatedCode && (
              <div className="flex gap-2">
                <Button variant="outline" size="sm" className="border-zinc-700 h-7 text-xs" onClick={() => {
                  navigator.clipboard.writeText(generatedCode);
                  toast.success("Copied to clipboard");
                }}>
                  <Download className="h-3 w-3 mr-1" /> Copy
                </Button>
                <Button
                  size="sm"
                  className="h-7 text-xs bg-emerald-600 hover:bg-emerald-500"
                  onClick={() => pushMut.mutate({
                    modules: [{ code: generatedCode, filename: `${techniqueId.replace(/\./g, "_")}_${framework}.py` }],
                    framework,
                  })}
                  disabled={pushMut.isPending}
                >
                  {pushMut.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Upload className="h-3 w-3 mr-1" />}
                  Push to {FRAMEWORK_META[framework].label}
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {generatedCode ? (
            <pre className="bg-zinc-950 rounded-lg p-4 text-xs font-mono text-emerald-300 overflow-auto max-h-[500px] border border-zinc-800">
              {generatedCode}
            </pre>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-zinc-600">
              <FileCode className="h-12 w-12 mb-3 opacity-30" />
              <p className="text-sm">Configure and generate a module to see code here</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Orchestration Dashboard ────────────────────────────────────────────────

function OrchestrationDashboard() {
  const statsQuery = trpc.abilityGraph.orchestrationStats.useQuery();
  const listQuery = trpc.abilityGraph.listOrchestrations.useQuery();
  const [showCreate, setShowCreate] = useState(false);
  const [orchName, setOrchName] = useState("");
  const [orchGraphId, setOrchGraphId] = useState("");
  const [orchScanMode, setOrchScanMode] = useState("active-standard");

  const graphsQuery = trpc.abilityGraph.list.useQuery();
  const createMut = trpc.abilityGraph.createOrchestration.useMutation({
    onSuccess: () => {
      toast.success("Orchestration plan created");
      setShowCreate(false);
      listQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const startMut = trpc.abilityGraph.startOrchestration.useMutation({
    onSuccess: () => {
      toast.success("Orchestration started");
      listQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const abortMut = trpc.abilityGraph.abortOrchestration.useMutation({
    onSuccess: () => {
      toast.success("Orchestration aborted");
      listQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const stats = statsQuery.data;

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Plans", value: stats?.totalPlans ?? 0, icon: <Workflow className="h-4 w-4 text-blue-400" /> },
          { label: "Active", value: stats?.activePlans ?? 0, icon: <Play className="h-4 w-4 text-emerald-400" /> },
          { label: "Completed", value: stats?.completedPlans ?? 0, icon: <CheckCircle className="h-4 w-4 text-green-400" /> },
          { label: "Failed", value: stats?.failedPlans ?? 0, icon: <XCircle className="h-4 w-4 text-red-400" /> },
        ].map((s, i) => (
          <Card key={i} className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="p-4 flex items-center gap-3">
              <div className="p-2 bg-zinc-800 rounded-lg">{s.icon}</div>
              <div>
                <div className="text-xl font-mono font-bold text-white">{s.value}</div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider">{s.label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Actions */}
      <div className="flex gap-3">
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button className="bg-red-600 hover:bg-red-500">
              <Zap className="h-4 w-4 mr-2" /> New Orchestration
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-zinc-900 border-zinc-700">
            <DialogHeader>
              <DialogTitle>Create Cross-C2 Orchestration</DialogTitle>
              <DialogDescription>Coordinate operations across Caldera, Metasploit, Sliver, Empire, and Cobalt Strike</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-xs text-zinc-400">Operation Name</Label>
                <Input value={orchName} onChange={(e) => setOrchName(e.target.value)} placeholder="APT29 Full Kill Chain" className="bg-zinc-800 border-zinc-700" />
              </div>
              <div>
                <Label className="text-xs text-zinc-400">Source Ability Graph</Label>
                <Select value={orchGraphId} onValueChange={setOrchGraphId}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue placeholder="Select graph..." /></SelectTrigger>
                  <SelectContent>
                    {(graphsQuery.data as any)?.items?.map((g: any) => (
                      <SelectItem key={g.id} value={String(g.id)}>{g.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs text-zinc-400">Scan Mode</Label>
                <Select value={orchScanMode} onValueChange={setOrchScanMode}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="passive">Passive</SelectItem>
                    <SelectItem value="active-low">Active Low</SelectItem>
                    <SelectItem value="active-standard">Active Standard</SelectItem>
                    <SelectItem value="active-aggressive">Active Aggressive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreate(false)} className="border-zinc-700">Cancel</Button>
              <Button
                onClick={() => createMut.mutate({ name: orchName, graphId: orchGraphId, targetHost: "target", scanMode: orchScanMode as any })}
                disabled={!orchName || !orchGraphId || createMut.isPending}
                className="bg-red-600 hover:bg-red-500"
              >
                {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Zap className="h-4 w-4 mr-2" />}
                Create Plan
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
        <Button variant="outline" className="border-zinc-700" onClick={() => listQuery.refetch()}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {/* Orchestration List */}
      <div className="rounded-lg border border-zinc-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-zinc-900/80 border-b border-zinc-800">
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">NAME</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">STATUS</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">STEPS</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">FRAMEWORKS</th>
              <th className="text-left p-3 text-zinc-400 font-mono text-xs">PROGRESS</th>
              <th className="text-right p-3 text-zinc-400 font-mono text-xs">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {listQuery.isLoading ? (
              <tr><td colSpan={6} className="p-8 text-center text-zinc-500"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></td></tr>
            ) : !listQuery.data?.length ? (
              <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                <Workflow className="h-8 w-8 mx-auto mb-2 opacity-30" />
                No orchestration plans yet. Create one to coordinate cross-C2 operations.
              </td></tr>
            ) : (
              listQuery.data.map((plan: any) => {
                const completed = plan.steps?.filter((s: any) => s.status === "completed").length || 0;
                const total = plan.steps?.length || 0;
                const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
                const frameworks = [...new Set(plan.steps?.map((s: any) => s.framework) || [])];

                return (
                  <tr key={plan.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                    <td className="p-3">
                      <div className="font-mono text-white text-sm">{plan.name}</div>
                      <div className="text-[10px] text-zinc-500">{plan.id}</div>
                    </td>
                    <td className="p-3">
                      <Badge className={
                        plan.status === "completed" ? "bg-emerald-500/10 text-emerald-400" :
                        plan.status === "executing" ? "bg-blue-500/10 text-blue-400" :
                        plan.status === "failed" ? "bg-red-500/10 text-red-400" :
                        "bg-zinc-700/50 text-zinc-400"
                      }>
                        {plan.status?.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="p-3 text-zinc-300 font-mono text-xs">{completed}/{total}</td>
                    <td className="p-3">
                      <div className="flex gap-1 flex-wrap">
                        {(frameworks as string[]).map((f: string) => (
                          <Badge key={f} className={FRAMEWORK_META[f as C2Framework]?.color || "bg-zinc-700"} variant="outline">
                            {f}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-zinc-800 rounded-full h-2 overflow-hidden">
                          <div className="bg-emerald-500 h-full rounded-full transition-all" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-xs text-zinc-400 font-mono">{pct}%</span>
                      </div>
                    </td>
                    <td className="p-3 text-right">
                      <div className="flex gap-1 justify-end">
                        {plan.status === "planned" && (
                          <Button size="sm" className="h-7 text-xs bg-emerald-600 hover:bg-emerald-500" onClick={() => startMut.mutate({ orchestrationId: plan.id })} disabled={startMut.isPending}>
                            <Play className="h-3 w-3 mr-1" /> Start
                          </Button>
                        )}
                        {plan.status === "executing" && (
                          <Button size="sm" variant="destructive" className="h-7 text-xs" onClick={() => abortMut.mutate({ orchestrationId: plan.id })} disabled={abortMut.isPending}>
                            <Square className="h-3 w-3 mr-1" /> Abort
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Learning Dashboard ─────────────────────────────────────────────────────

function LearningDashboard() {
  const learningQuery = trpc.abilityGraph.learningStats.useQuery();
  const historyQuery = trpc.abilityGraph.learningHistory.useQuery();

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Brain className="h-4 w-4 text-purple-400" /> EXECUTION HISTORY
            </CardTitle>
            <CardDescription className="text-xs">Recent technique executions and their outcomes</CardDescription>
          </CardHeader>
          <CardContent>
            {historyQuery.isLoading ? (
              <div className="flex items-center justify-center h-40"><Loader2 className="h-5 w-5 animate-spin text-zinc-500" /></div>
            ) : (historyQuery.data as any)?.records?.length ? (
              <div className="space-y-2 max-h-64 overflow-auto">
                {((historyQuery.data as any)?.records as any[] || []).slice(0, 20).map((entry: any, i: number) => (
                  <div key={i} className="flex items-center justify-between bg-zinc-800/50 rounded p-2">
                    <div>
                      <div className="text-xs font-mono text-white">{entry.techniqueId}</div>
                      <div className="text-[10px] text-zinc-500">{entry.framework}</div>
                    </div>
                    <Badge className={entry.result === "success" ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}>
                      {entry.result?.toUpperCase() || "UNKNOWN"}
                    </Badge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center text-zinc-500 py-8">
                <Activity className="h-8 w-8 mx-auto mb-2 opacity-30" />
                <p className="text-sm">Execute operations to see execution history</p>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Gauge className="h-4 w-4 text-amber-400" /> FRAMEWORK EFFECTIVENESS
            </CardTitle>
            <CardDescription className="text-xs">Success rates across C2 frameworks based on execution history</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {Object.entries(FRAMEWORK_META).map(([fw, meta]) => {
                const fwStats = (learningQuery.data as any)?.byFramework?.[fw];
                const successRate = fwStats?.rate ? Math.round(fwStats.rate * 100) : 0;
                return (
                  <div key={fw} className="space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {meta.icon}
                        <span className="text-xs font-mono text-zinc-300">{meta.label}</span>
                      </div>
                      <span className="text-xs font-mono text-zinc-400">{successRate}%</span>
                    </div>
                    <div className="bg-zinc-800 rounded-full h-2 overflow-hidden">
                      <div className={`h-full rounded-full ${FRAMEWORK_BAR_COLORS[fw as C2Framework]}`} style={{ width: `${successRate}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-cyan-400" /> CROSS-C2 LEARNING INSIGHTS
          </CardTitle>
          <CardDescription className="text-xs">Patterns discovered from coordinated multi-framework operations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-zinc-800/50 rounded-lg p-4">
              <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Best Initial Access</div>
              <div className="text-sm font-mono text-white">GoPhish → Cobalt Strike</div>
              <div className="text-[10px] text-zinc-500 mt-1">Phishing + beacon deployment pipeline</div>
            </div>
            <div className="bg-zinc-800/50 rounded-lg p-4">
              <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Best Lateral Movement</div>
              <div className="text-sm font-mono text-white">Cobalt Strike → Sliver</div>
              <div className="text-[10px] text-zinc-500 mt-1">Beacon + implant handoff chain</div>
            </div>
            <div className="bg-zinc-800/50 rounded-lg p-4">
              <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Best Persistence</div>
              <div className="text-sm font-mono text-white">Empire → Cobalt Strike</div>
              <div className="text-[10px] text-zinc-500 mt-1">PowerShell staging + beacon fallback</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function C2CommandCenter() {
  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-mono font-bold text-white tracking-tight flex items-center gap-3">
              <div className="p-2 bg-red-500/10 rounded-lg">
                <Radio className="h-6 w-6 text-red-400" />
              </div>
              C2 COMMAND CENTER
            </h1>
            <p className="text-sm text-zinc-400 mt-1">Unified multi-framework C2 orchestration — Caldera · Metasploit · Sliver · Empire · Cobalt Strike · GoPhish</p>
          </div>
        </div>

        {/* Framework Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {(Object.keys(FRAMEWORK_META) as C2Framework[]).map((fw) => (
            <FrameworkStatusCard key={fw} framework={fw} />
          ))}
        </div>

        {/* Tabs */}
        <Tabs defaultValue="agents" className="space-y-4">
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="agents" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Server className="h-3.5 w-3.5 mr-1.5" /> AGENTS
            </TabsTrigger>
            <TabsTrigger value="orchestration" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Workflow className="h-3.5 w-3.5 mr-1.5" /> ORCHESTRATION
            </TabsTrigger>
            <TabsTrigger value="modules" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Package className="h-3.5 w-3.5 mr-1.5" /> MODULE BUILDER
            </TabsTrigger>
            <TabsTrigger value="learning" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Brain className="h-3.5 w-3.5 mr-1.5" /> LEARNING
            </TabsTrigger>
          </TabsList>

          <TabsContent value="agents">
            <UnifiedAgentView />
          </TabsContent>

          <TabsContent value="orchestration">
            <OrchestrationDashboard />
          </TabsContent>

          <TabsContent value="modules">
            <ModuleBuilder />
          </TabsContent>

          <TabsContent value="learning">
            <LearningDashboard />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
