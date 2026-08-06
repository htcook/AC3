import React, { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import {
  Brain, Shield, Crosshair, Zap, Network, Eye, Server,
  Terminal, Radio, Cpu, Flame, Crown, Target, ChevronRight,
  BarChart3, Lock, Unlock, AlertTriangle, CheckCircle2,
  Play, Loader2, BookOpen, Layers, Swords, ArrowRight,
  Upload, RefreshCw, Clock, Rocket, Activity, Settings2,
  CloudUpload, Workflow, Sparkles, XCircle, Pause, Square,
  SkipForward, Trash2, FileText, Users, MonitorPlay,
} from "lucide-react";

// ─── Operation Launcher Tab ─────────────────────────────────────────────────

function OperationLauncherTab() {
  const [launchName, setLaunchName] = useState("");
  const [selectedAdversary, setSelectedAdversary] = useState("");
  const [selectedPlanner, setSelectedPlanner] = useState("batch");
  const [selectedGroup, setSelectedGroup] = useState("");
  const [jitter, setJitter] = useState("2/8");
  const [obfuscator, setObfuscator] = useState("plain-text");
  const [autonomous, setAutonomous] = useState(true);
  const [autoClose, setAutoClose] = useState(false);
  const [selectedOpId, setSelectedOpId] = useState<string | null>(null);

  const deploymentStatus = trpc.c2KnowledgeBase.getDeploymentStatus.useQuery();
  const agents = trpc.c2KnowledgeBase.getAvailableAgents.useQuery();
  const planners = trpc.c2KnowledgeBase.getAvailablePlanners.useQuery();
  const operations = trpc.c2KnowledgeBase.listOperations.useQuery(undefined, { refetchInterval: 10000 });
  const opStats = trpc.c2KnowledgeBase.getOperationStats.useQuery(undefined, { refetchInterval: 10000 });
  const trackedOps = trpc.c2KnowledgeBase.getTrackedOperations.useQuery(undefined, { refetchInterval: 10000 });
  const opDetail = trpc.c2KnowledgeBase.getOperationStatus.useQuery(
    { operationId: selectedOpId! },
    { enabled: !!selectedOpId, refetchInterval: 5000 },
  );
  const utils = trpc.useUtils();

  const launchMut = trpc.c2KnowledgeBase.launchOperation.useMutation({
    onSuccess: (r) => {
      if (r.success) {
        toast.success(`Operation "${r.operationName}" launched successfully`);
        utils.c2KnowledgeBase.listOperations.invalidate();
        utils.c2KnowledgeBase.getOperationStats.invalidate();
        utils.c2KnowledgeBase.getTrackedOperations.invalidate();
        setLaunchName("");
      } else {
        toast.error(r.error || "Failed to launch operation");
      }
    },
    onError: (e) => toast.error(e.message),
  });

  const controlMut = trpc.c2KnowledgeBase.controlOperation.useMutation({
    onSuccess: (r) => {
      if (r.success) {
        toast.success("Operation state updated");
        utils.c2KnowledgeBase.listOperations.invalidate();
        utils.c2KnowledgeBase.getTrackedOperations.invalidate();
      } else toast.error(r.error || "Failed");
    },
  });

  const deleteMut = trpc.c2KnowledgeBase.deleteOperation.useMutation({
    onSuccess: (r) => {
      if (r.success) {
        toast.success("Operation deleted");
        utils.c2KnowledgeBase.listOperations.invalidate();
        utils.c2KnowledgeBase.getTrackedOperations.invalidate();
        setSelectedOpId(null);
      } else toast.error(r.error || "Failed");
    },
  });

  const deployedProfiles = deploymentStatus.data?.filter((d) => d.status === "deployed") || [];

  const handleLaunch = () => {
    if (!launchName || !selectedAdversary) {
      toast.error("Operation name and adversary are required");
      return;
    }
    const adv = deployedProfiles.find((d) => d.actorId === selectedAdversary);
    launchMut.mutate({
      name: launchName,
      adversaryId: selectedAdversary,
      adversaryName: adv?.actorName || selectedAdversary,
      group: selectedGroup || undefined,
      planner: selectedPlanner as "batch" | "buckets" | "atomic",
      jitter,
      obfuscator: obfuscator as "plain-text" | "base64" | "caesar",
      autonomous,
      autoClose,
    });
  };

  const stateColor = (s: string) => {
    switch (s) {
      case "running": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      case "paused": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "finished": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      case "cleanup": return "bg-red-500/20 text-red-400 border-red-500/30";
      default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Total Launched", value: opStats.data?.totalLaunched ?? 0, icon: Rocket, color: "text-blue-400" },
          { label: "Running", value: opStats.data?.running ?? 0, icon: Play, color: "text-emerald-400" },
          { label: "Completed", value: opStats.data?.completed ?? 0, icon: CheckCircle2, color: "text-cyan-400" },
          { label: "Adversaries Used", value: opStats.data?.uniqueAdversaries ?? 0, icon: Target, color: "text-purple-400" },
        ].map((s) => (
          <Card key={s.label} className="bg-zinc-900/60 border-zinc-800">
            <CardContent className="p-4 flex items-center gap-3">
              <s.icon className={`h-5 w-5 ${s.color}`} />
              <div>
                <p className="text-2xl font-bold text-white">{s.value}</p>
                <p className="text-xs text-zinc-400">{s.label}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Launch Panel */}
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Rocket className="h-4 w-4 text-orange-400" /> Launch Operation
            </CardTitle>
            <CardDescription className="text-xs">
              Create a Caldera operation from a deployed adversary profile
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {deployedProfiles.length === 0 ? (
              <div className="text-center py-8 text-zinc-500">
                <CloudUpload className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No deployed profiles available</p>
                <p className="text-xs mt-1">Deploy adversary profiles to Caldera first from the Deploy & Pipeline tab</p>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <label className="text-xs text-zinc-400">Operation Name</label>
                  <input
                    className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-white placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-orange-500/50"
                    placeholder="e.g., APT29 Emulation - Sprint 3"
                    value={launchName}
                    onChange={(e) => setLaunchName(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-xs text-zinc-400">Adversary Profile</label>
                  <Select value={selectedAdversary} onValueChange={setSelectedAdversary}>
                    <SelectTrigger className="bg-zinc-800 border-zinc-700">
                      <SelectValue placeholder="Select deployed adversary" />
                    </SelectTrigger>
                    <SelectContent>
                      {deployedProfiles.map((p) => (
                        <SelectItem key={p.actorId} value={p.actorId}>
                          {p.actorName} ({p.abilityCount} abilities)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <label className="text-xs text-zinc-400">Planner</label>
                    <Select value={selectedPlanner} onValueChange={setSelectedPlanner}>
                      <SelectTrigger className="bg-zinc-800 border-zinc-700">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {(planners.data?.planners || [
                          { id: "batch", name: "Batch" },
                          { id: "buckets", name: "Buckets" },
                          { id: "atomic", name: "Atomic" },
                        ]).map((p) => (
                          <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs text-zinc-400">Agent Group</label>
                    <input
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-white placeholder:text-zinc-500 focus:outline-none focus:ring-1 focus:ring-orange-500/50"
                      placeholder="All agents (blank)"
                      value={selectedGroup}
                      onChange={(e) => setSelectedGroup(e.target.value)}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="space-y-2">
                    <label className="text-xs text-zinc-400">Jitter</label>
                    <input
                      className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-white placeholder:text-zinc-500 focus:outline-none"
                      value={jitter}
                      onChange={(e) => setJitter(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-zinc-400">Obfuscator</label>
                    <Select value={obfuscator} onValueChange={setObfuscator}>
                      <SelectTrigger className="bg-zinc-800 border-zinc-700">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="plain-text">Plain Text</SelectItem>
                        <SelectItem value="base64">Base64</SelectItem>
                        <SelectItem value="caesar">Caesar</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs text-zinc-400">Agents</label>
                    <div className="flex items-center gap-2 h-9 px-3 bg-zinc-800 border border-zinc-700 rounded text-sm">
                      <Users className="h-3.5 w-3.5 text-zinc-400" />
                      <span className="text-white">{agents.data?.agents?.length ?? "?"}</span>
                      <span className="text-zinc-500 text-xs">available</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-6">
                  <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={autonomous} onChange={(e) => setAutonomous(e.target.checked)} className="rounded" />
                    Autonomous
                  </label>
                  <label className="flex items-center gap-2 text-xs text-zinc-400 cursor-pointer">
                    <input type="checkbox" checked={autoClose} onChange={(e) => setAutoClose(e.target.checked)} className="rounded" />
                    Auto-close
                  </label>
                </div>

                <Button
                  onClick={handleLaunch}
                  disabled={launchMut.isPending || !launchName || !selectedAdversary}
                  className="w-full bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-500 hover:to-red-500"
                >
                  {launchMut.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Launching...</>
                  ) : (
                    <><Rocket className="h-4 w-4 mr-2" /> Launch Operation</>
                  )}
                </Button>
              </>
            )}
          </CardContent>
        </Card>

        {/* Operation Detail / Agent List */}
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <MonitorPlay className="h-4 w-4 text-cyan-400" />
              {selectedOpId ? "Operation Detail" : "Available Agents"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {selectedOpId && opDetail.data?.success && opDetail.data.operation ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-medium text-white">{opDetail.data.operation.name}</h4>
                    <p className="text-xs text-zinc-500">ID: {opDetail.data.operation.id}</p>
                  </div>
                  <Badge className={stateColor(opDetail.data.operation.state)}>
                    {opDetail.data.operation.state}
                  </Badge>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center">
                  <div className="bg-zinc-800/50 rounded p-2">
                    <p className="text-lg font-bold text-white">{opDetail.data.operation.hostGroup?.length || 0}</p>
                    <p className="text-xs text-zinc-500">Agents</p>
                  </div>
                  <div className="bg-zinc-800/50 rounded p-2">
                    <p className="text-lg font-bold text-emerald-400">
                      {opDetail.data.operation.chain?.filter((l) => l.status === 0).length || 0}
                    </p>
                    <p className="text-xs text-zinc-500">Succeeded</p>
                  </div>
                  <div className="bg-zinc-800/50 rounded p-2">
                    <p className="text-lg font-bold text-red-400">
                      {opDetail.data.operation.chain?.filter((l) => l.status === 1 || l.status === -2).length || 0}
                    </p>
                    <p className="text-xs text-zinc-500">Failed</p>
                  </div>
                </div>

                {/* Control Buttons */}
                <div className="flex gap-2">
                  {opDetail.data.operation.state === "running" && (
                    <>
                      <Button size="sm" variant="outline" className="flex-1" onClick={() => controlMut.mutate({ operationId: selectedOpId, state: "paused" })}>
                        <Pause className="h-3.5 w-3.5 mr-1" /> Pause
                      </Button>
                      <Button size="sm" variant="outline" className="flex-1" onClick={() => controlMut.mutate({ operationId: selectedOpId, state: "run_one_link" })}>
                        <SkipForward className="h-3.5 w-3.5 mr-1" /> Step
                      </Button>
                      <Button size="sm" variant="destructive" className="flex-1" onClick={() => controlMut.mutate({ operationId: selectedOpId, state: "finished" })}>
                        <Square className="h-3.5 w-3.5 mr-1" /> Stop
                      </Button>
                    </>
                  )}
                  {opDetail.data.operation.state === "paused" && (
                    <Button size="sm" variant="outline" className="flex-1" onClick={() => controlMut.mutate({ operationId: selectedOpId, state: "running" })}>
                      <Play className="h-3.5 w-3.5 mr-1" /> Resume
                    </Button>
                  )}
                  {opDetail.data.operation.state === "finished" && (
                    <Button size="sm" variant="destructive" className="flex-1" onClick={() => deleteMut.mutate({ operationId: selectedOpId })}>
                      <Trash2 className="h-3.5 w-3.5 mr-1" /> Delete
                    </Button>
                  )}
                  <Button size="sm" variant="ghost" onClick={() => setSelectedOpId(null)}>
                    Back
                  </Button>
                </div>

                {/* Chain Steps */}
                <ScrollArea className="h-48">
                  <div className="space-y-1">
                    {(opDetail.data.operation.chain || []).map((link, i) => (
                      <div key={link.id || i} className="flex items-center gap-2 px-2 py-1.5 bg-zinc-800/40 rounded text-xs">
                        <span className={`h-2 w-2 rounded-full ${link.status === 0 ? "bg-emerald-400" : link.status === 1 || link.status === -2 ? "bg-red-400" : link.status === -3 ? "bg-zinc-500" : "bg-amber-400"}`} />
                        <span className="text-zinc-300 truncate flex-1">{link.abilityName || link.abilityId}</span>
                        <span className="text-zinc-500">{link.paw}</span>
                      </div>
                    ))}
                    {(!opDetail.data.operation.chain || opDetail.data.operation.chain.length === 0) && (
                      <p className="text-xs text-zinc-500 text-center py-4">No links executed yet</p>
                    )}
                  </div>
                </ScrollArea>
              </div>
            ) : (
              <ScrollArea className="h-72">
                <div className="space-y-2">
                  {agents.data?.agents?.map((a) => (
                    <div key={a.paw} className="flex items-center gap-3 px-3 py-2 bg-zinc-800/40 rounded">
                      <Terminal className="h-4 w-4 text-emerald-400" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-white truncate">{a.host}</p>
                        <p className="text-xs text-zinc-500">{a.platform} • {a.group || "default"} • {a.paw}</p>
                      </div>
                      <Badge variant="outline" className="text-xs">{a.executors.join(", ")}</Badge>
                    </div>
                  ))}
                  {(!agents.data?.agents || agents.data.agents.length === 0) && (
                    <div className="text-center py-8 text-zinc-500">
                      <Users className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">No agents connected</p>
                      <p className="text-xs mt-1">Deploy Caldera agents to target systems first</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Active & Recent Operations */}
      <Card className="bg-zinc-900/60 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Activity className="h-4 w-4 text-emerald-400" /> Operations
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-64">
            <div className="space-y-2">
              {(operations.data?.operations || []).map((op) => (
                <div
                  key={op.id}
                  className={`flex items-center gap-3 px-3 py-2.5 rounded cursor-pointer transition-colors ${
                    String(selectedOpId) === String(op.id)
                      ? "bg-orange-500/10 border border-orange-500/30"
                      : "bg-zinc-800/40 hover:bg-zinc-800/60 border border-transparent"
                  }`}
                  onClick={() => setSelectedOpId(String(op.id))}
                >
                  <div className={`h-2.5 w-2.5 rounded-full ${
                    op.state === "running" ? "bg-emerald-400 animate-pulse" :
                    op.state === "paused" ? "bg-amber-400" :
                    op.state === "finished" ? "bg-blue-400" : "bg-zinc-500"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white truncate">{op.name}</p>
                    <p className="text-xs text-zinc-500">
                      {op.adversaryName || op.adversaryId} • {new Date(op.startedAt).toLocaleString()}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-zinc-400"><Users className="h-3 w-3 inline mr-1" />{op.agentCount}</span>
                    <span className="text-emerald-400">{op.successCount} ok</span>
                    {op.failCount > 0 && <span className="text-red-400">{op.failCount} fail</span>}
                    {op.inProgressCount > 0 && <span className="text-amber-400">{op.inProgressCount} pending</span>}
                  </div>
                  <Badge className={stateColor(op.state)}>{op.state}</Badge>
                </div>
              ))}
              {(!operations.data?.operations || operations.data.operations.length === 0) && (
                <div className="text-center py-8 text-zinc-500">
                  <Rocket className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No operations yet</p>
                  <p className="text-xs mt-1">Launch an operation from a deployed adversary profile</p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Framework Profiles Tab ─────────────────────────────────────────────────

function FrameworkProfilesTab() {
  const { data: profiles, isLoading } = trpc.c2KnowledgeBase.getFrameworkProfiles.useQuery();
  const [selectedFw, setSelectedFw] = useState<string | null>(null);

  const fwIcons: Record<string, React.ReactNode> = {
    caldera: <Target className="h-5 w-5 text-red-400" />,
    metasploit: <Terminal className="h-5 w-5 text-blue-400" />,
    sliver: <Cpu className="h-5 w-5 text-green-400" />,
    empire: <Crown className="h-5 w-5 text-purple-400" />,
    cobaltstrike: <Crosshair className="h-5 w-5 text-orange-400" />,
    manjusaka: <Flame className="h-5 w-5 text-pink-400" />,
  };

  const detectionColors: Record<string, string> = {
    "very-hard": "text-green-400",
    hard: "text-emerald-400",
    moderate: "text-yellow-400",
    easy: "text-red-400",
  };

  const noiseColors: Record<string, string> = {
    minimal: "text-green-400",
    low: "text-emerald-400",
    moderate: "text-yellow-400",
    high: "text-red-400",
  };

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[1, 2, 3, 4, 5, 6].map(i => (
          <Card key={i} className="animate-pulse bg-card/50">
            <CardContent className="h-48" />
          </Card>
        ))}
      </div>
    );
  }

  const selected = profiles?.find(p => p.id === selectedFw);

  return (
    <div className="space-y-6">
      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {profiles?.map(profile => (
          <Card
            key={profile.id}
            className={`cursor-pointer transition-all hover:border-primary/50 ${selectedFw === profile.id ? "border-primary ring-1 ring-primary/30" : ""}`}
            onClick={() => setSelectedFw(selectedFw === profile.id ? null : profile.id)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                {fwIcons[profile.id]}
                <div className="min-w-0">
                  <CardTitle className="text-base">{profile.displayName}</CardTitle>
                  <CardDescription className="text-xs line-clamp-2 mt-1">
                    {profile.description.split(".")[0]}
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Detection:</span>{" "}
                  <span className={detectionColors[profile.opsecProfile.detectionDifficulty]}>
                    {profile.opsecProfile.detectionDifficulty}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Noise:</span>{" "}
                  <span className={noiseColors[profile.opsecProfile.networkNoise]}>
                    {profile.opsecProfile.networkNoise}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Techniques:</span>{" "}
                  <span className="text-foreground font-mono">{profile.totalTechniques}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Post-Exploit:</span>{" "}
                  <span className="text-foreground font-mono">{profile.totalPostExploitCapabilities}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1">
                {profile.platforms.map(p => (
                  <Badge key={p} variant="outline" className="text-[10px] px-1.5 py-0">
                    {p}
                  </Badge>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {profile.bestPhases.slice(0, 3).map(phase => (
                  <Badge key={phase} className="text-[10px] px-1.5 py-0 bg-primary/20 text-primary">
                    {phase.replace(/_/g, " ")}
                  </Badge>
                ))}
                {profile.bestPhases.length > 3 && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                    +{profile.bestPhases.length - 3}
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Expanded Detail Panel */}
      {selected && (
        <Card className="border-primary/30">
          <CardHeader>
            <div className="flex items-center gap-3">
              {fwIcons[selected.id]}
              <div>
                <CardTitle>{selected.displayName} — Tactical Profile</CardTitle>
                <CardDescription>{selected.description}</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Primary Use Cases */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Zap className="h-4 w-4 text-yellow-400" /> Primary Use Cases
              </h4>
              <div className="flex flex-wrap gap-2">
                {selected.primaryUseCases.map(uc => (
                  <Badge key={uc} variant="secondary" className="text-xs">{uc}</Badge>
                ))}
              </div>
            </div>

            {/* OPSEC Profile */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Eye className="h-4 w-4 text-green-400" /> OPSEC Profile
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Network Noise</div>
                  <div className={`text-sm font-semibold ${noiseColors[selected.opsecProfile.networkNoise]}`}>
                    {selected.opsecProfile.networkNoise}
                  </div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Disk Artifacts</div>
                  <div className="text-sm font-semibold">{selected.opsecProfile.diskArtifacts}</div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Memory</div>
                  <div className="text-sm font-semibold">{selected.opsecProfile.memoryFootprint}</div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Sleep/Jitter</div>
                  <div className="text-sm font-semibold text-xs">{selected.opsecProfile.defaultSleepJitter}</div>
                </div>
              </div>
            </div>

            {/* Evasion Capabilities */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-blue-400" /> Evasion Capabilities
              </h4>
              <div className="space-y-2">
                {selected.evasionCapabilities.map((ev, i) => (
                  <div key={i} className="flex items-start gap-3 bg-muted/20 rounded-lg p-3">
                    <Badge
                      variant={ev.effectiveness === "high" ? "default" : "secondary"}
                      className={`text-[10px] shrink-0 ${ev.effectiveness === "high" ? "bg-green-500/20 text-green-400" : ev.effectiveness === "medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-red-500/20 text-red-400"}`}
                    >
                      {ev.effectiveness}
                    </Badge>
                    <div className="min-w-0">
                      <div className="text-sm font-medium">{ev.technique}</div>
                      <div className="text-xs text-muted-foreground">{ev.description}</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {ev.bypassesDefenses.map(d => (
                          <Badge key={d} variant="outline" className="text-[9px] px-1 py-0">{d}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Post-Exploitation Capabilities */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Swords className="h-4 w-4 text-red-400" /> Post-Exploitation Capabilities
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {selected.postExploitCapabilities.map((cap, i) => (
                  <div key={i} className="bg-muted/20 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium">{cap.name}</span>
                      <Badge variant="outline" className="text-[9px] px-1 py-0">
                        {cap.requiredPrivilege}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">{cap.description}</div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {cap.techniqueIds.slice(0, 4).map(t => (
                        <Badge key={t} className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400">{t}</Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* When to Use / Avoid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400" /> Prefer When
                </h4>
                <ul className="space-y-1">
                  {selected.preferWhen.map((w, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-green-400 shrink-0" />
                      {w}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" /> Avoid When
                </h4>
                <ul className="space-y-1">
                  {selected.avoidWhen.map((w, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-yellow-400 shrink-0" />
                      {w}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Framework Recommendation Tab ───────────────────────────────────────────

function RecommendationTab() {
  const [platform, setPlatform] = useState<string>("windows");
  const [phase, setPhase] = useState<string>("initial_access");
  const [stealth, setStealth] = useState<string>("high");
  const [hasAD, setHasAD] = useState(true);

  const { data: recommendation, isLoading } = trpc.c2KnowledgeBase.getRecommendation.useQuery({
    targetPlatform: platform as any,
    engagementPhase: phase as any,
    stealthRequired: stealth as any,
    hasActiveDirectory: hasAD,
  });

  const fwColors: Record<string, string> = {
    caldera: "text-red-400",
    metasploit: "text-blue-400",
    sliver: "text-green-400",
    empire: "text-purple-400",
    cobaltstrike: "text-orange-400",
    manjusaka: "text-pink-400",
  };

  return (
    <div className="space-y-6">
      {/* Selection Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Brain className="h-5 w-5 text-primary" /> Engagement Context
          </CardTitle>
          <CardDescription>Configure your engagement parameters to get a C2 framework recommendation</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Platform</label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="mixed">Mixed</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Engagement Phase</label>
              <Select value={phase} onValueChange={setPhase}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="initial_access">Initial Access</SelectItem>
                  <SelectItem value="execution">Execution</SelectItem>
                  <SelectItem value="persistence">Persistence</SelectItem>
                  <SelectItem value="privilege_escalation">Privilege Escalation</SelectItem>
                  <SelectItem value="defense_evasion">Defense Evasion</SelectItem>
                  <SelectItem value="credential_access">Credential Access</SelectItem>
                  <SelectItem value="discovery">Discovery</SelectItem>
                  <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                  <SelectItem value="collection_exfiltration">Collection/Exfil</SelectItem>
                  <SelectItem value="impact">Impact</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Stealth Required</label>
              <Select value={stealth} onValueChange={setStealth}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="maximum">Maximum</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="moderate">Moderate</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Active Directory</label>
              <Select value={hasAD ? "yes" : "no"} onValueChange={v => setHasAD(v === "yes")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="yes">Yes — AD Environment</SelectItem>
                  <SelectItem value="no">No — Standalone</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recommendation Result */}
      {recommendation && (
        <div className="space-y-4">
          <Card className="border-primary/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-primary" /> Recommendation
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="bg-primary/10 rounded-xl p-4 text-center">
                  <div className="text-xs text-muted-foreground">Primary</div>
                  <div className={`text-lg font-bold ${fwColors[recommendation.primary]}`}>
                    {recommendation.primary.toUpperCase()}
                  </div>
                </div>
                {recommendation.secondary && (
                  <>
                    <ArrowRight className="h-5 w-5 text-muted-foreground" />
                    <div className="bg-muted/30 rounded-xl p-4 text-center">
                      <div className="text-xs text-muted-foreground">Fallback</div>
                      <div className={`text-lg font-bold ${fwColors[recommendation.secondary]}`}>
                        {recommendation.secondary.toUpperCase()}
                      </div>
                    </div>
                  </>
                )}
              </div>
              <p className="text-sm text-muted-foreground">{recommendation.reasoning}</p>

              {recommendation.suggestedModules.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold mb-2">Suggested Modules</h4>
                  <ul className="space-y-1">
                    {recommendation.suggestedModules.map((mod, i) => (
                      <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                        <ChevronRight className="h-3 w-3 mt-0.5 text-primary shrink-0" />
                        {mod}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {recommendation.opsecWarnings.length > 0 && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                  <h4 className="text-sm font-semibold text-yellow-400 mb-1 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" /> OPSEC Warnings
                  </h4>
                  {recommendation.opsecWarnings.map((w, i) => (
                    <p key={i} className="text-xs text-yellow-300/80">{w}</p>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Chain Strategy */}
          {recommendation.chainStrategy && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Layers className="h-5 w-5 text-blue-400" /> Multi-Framework Chain Strategy
                </CardTitle>
                <CardDescription>{recommendation.chainStrategy.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {recommendation.chainStrategy.stages.map((stage, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <div className="bg-primary/20 rounded-full w-7 h-7 flex items-center justify-center text-xs font-bold shrink-0">
                        {i + 1}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge className={`text-[10px] ${fwColors[stage.framework]}`}>
                            {stage.framework}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {stage.phase.replace(/_/g, " ")}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{stage.purpose}</p>
                        <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                          Handoff: {stage.handoffTrigger}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Adversary Profile Generator Tab ────────────────────────────────────────

function AdversaryProfileTab() {
  const { data: topActors, isLoading: loadingActors } = trpc.c2KnowledgeBase.getTopActors.useQuery({ limit: 20 });
  const { data: batchScores, isLoading: loadingScores } = trpc.c2KnowledgeBase.batchScoreCompleteness.useQuery({ limit: 30, minAbilities: 5 });
  const [selectedActor, setSelectedActor] = useState<string | null>(null);

  const { data: actorMapping } = trpc.c2KnowledgeBase.mapActorToC2.useQuery(
    { actorId: selectedActor! },
    { enabled: !!selectedActor },
  );

  const { data: completeness } = trpc.c2KnowledgeBase.scoreCompleteness.useQuery(
    { actorId: selectedActor! },
    { enabled: !!selectedActor },
  );

  const generateMutation = trpc.c2KnowledgeBase.generateProfile.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Generated adversary profile: ${data.profile?.name}`);
      } else {
        toast.error(data.error || "Failed to generate profile");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const qualityColors: Record<string, string> = {
    excellent: "text-green-400 bg-green-500/10",
    good: "text-emerald-400 bg-emerald-500/10",
    fair: "text-yellow-400 bg-yellow-500/10",
    insufficient: "text-red-400 bg-red-500/10",
  };

  return (
    <div className="space-y-6">
      {/* Top Actors with Abilities */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Target className="h-5 w-5 text-red-400" /> Threat Actors with C2 Ability Mappings
          </CardTitle>
          <CardDescription>
            Select an actor to view their TTP-to-C2 mapping and generate adversary emulation profiles
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingActors ? (
            <div className="text-sm text-muted-foreground">Loading actors...</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
              {topActors?.map(actor => (
                <button
                  key={actor.actorId}
                  onClick={() => setSelectedActor(actor.actorId)}
                  className={`text-left p-3 rounded-lg border transition-all hover:border-primary/50 ${selectedActor === actor.actorId ? "border-primary bg-primary/5" : "border-border/50"}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium truncate">{actor.name}</span>
                    {actor.hasCalderaProfile && (
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {actor.abilityCount} abilities
                    {actor.country && ` · ${actor.country}`}
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Selected Actor Detail */}
      {selectedActor && completeness && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Completeness Score */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Profile Completeness</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-center">
                <div className="text-4xl font-bold">{completeness.score}</div>
                <div className="text-xs text-muted-foreground">/100</div>
                <Badge className={`mt-2 ${qualityColors[completeness.profileQuality]}`}>
                  {completeness.profileQuality}
                </Badge>
              </div>
              <Separator />
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">TTPs</span>
                  <span className="font-mono">{completeness.totalTTPs}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Abilities</span>
                  <span className="font-mono">{completeness.totalAbilities}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Tactics</span>
                  <span className="font-mono">{completeness.tacticsRepresented}/{completeness.totalTactics}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Kill Chain</span>
                  <span className="font-mono">{completeness.killChainCoverage}%</span>
                </div>
                <Progress value={completeness.killChainCoverage} className="h-1.5" />
              </div>
              <Separator />
              <div className="flex items-center gap-2">
                {completeness.hasCalderaProfile ? (
                  <Badge className="bg-green-500/10 text-green-400 text-xs">
                    <CheckCircle2 className="h-3 w-3 mr-1" /> Has Profile
                  </Badge>
                ) : completeness.readyForAutoGeneration ? (
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={() => generateMutation.mutate({ actorId: selectedActor })}
                    disabled={generateMutation.isPending}
                  >
                    {generateMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    Generate Profile
                  </Button>
                ) : (
                  <Badge className="bg-yellow-500/10 text-yellow-400 text-xs">
                    <AlertTriangle className="h-3 w-3 mr-1" /> Not Ready
                  </Badge>
                )}
              </div>
              {completeness.missingPhases.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Missing Phases:</div>
                  <div className="flex flex-wrap gap-1">
                    {completeness.missingPhases.slice(0, 5).map(p => (
                      <Badge key={p} variant="outline" className="text-[9px] px-1 py-0">{p}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* C2 Framework Breakdown */}
          {actorMapping && (
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base">
                  {actorMapping.actorName} — C2 Module Mapping
                </CardTitle>
                <CardDescription>
                  {actorMapping.mappedToC2}/{actorMapping.totalTTPs} TTPs mapped ({actorMapping.coveragePercent}% coverage)
                  · Recommended: {actorMapping.recommendedPrimaryC2.toUpperCase()}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Framework breakdown bars */}
                <div className="space-y-2">
                  {Object.entries(actorMapping.frameworkBreakdown)
                    .filter(([, data]) => data.moduleCount > 0)
                    .sort(([, a], [, b]) => b.moduleCount - a.moduleCount)
                    .map(([fw, data]) => (
                      <div key={fw} className="flex items-center gap-3">
                        <span className="text-xs font-mono w-24 text-right">{fw}</span>
                        <div className="flex-1">
                          <Progress
                            value={Math.min(100, (data.moduleCount / Math.max(1, actorMapping.totalTTPs)) * 100)}
                            className="h-2"
                          />
                        </div>
                        <span className="text-xs font-mono w-12">{data.moduleCount}</span>
                      </div>
                    ))}
                </div>

                {/* Emulation Plan Preview */}
                {actorMapping.emulationPlan.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2">Emulation Plan (Kill Chain Order)</h4>
                    <ScrollArea className="h-64">
                      <div className="space-y-1">
                        {actorMapping.emulationPlan.slice(0, 20).map(step => (
                          <div key={step.order} className="flex items-start gap-2 text-xs p-2 rounded hover:bg-muted/20">
                            <span className="font-mono text-muted-foreground w-6 shrink-0">{step.order}.</span>
                            <Badge variant="outline" className="text-[9px] px-1 py-0 shrink-0">
                              {step.phase.replace(/_/g, " ")}
                            </Badge>
                            <span className="text-muted-foreground truncate">{step.techniqueName}</span>
                            <Badge className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400 shrink-0">
                              {step.techniqueId}
                            </Badge>
                            <Badge variant="outline" className="text-[9px] px-1 py-0 shrink-0">
                              {step.framework}
                            </Badge>
                          </div>
                        ))}
                        {actorMapping.emulationPlan.length > 20 && (
                          <div className="text-xs text-muted-foreground text-center py-2">
                            +{actorMapping.emulationPlan.length - 20} more steps
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Batch Completeness Scores */}
      {batchScores && batchScores.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-400" /> Profile Completeness Scores
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {batchScores.map(score => (
                <button
                  key={score.actorId}
                  onClick={() => setSelectedActor(score.actorId)}
                  className="text-left p-3 rounded-lg border border-border/50 hover:border-primary/50 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium truncate">{score.actorName}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono">{score.score}/100</span>
                      <Badge className={`text-[9px] px-1 py-0 ${qualityColors[score.profileQuality]}`}>
                        {score.profileQuality}
                      </Badge>
                    </div>
                  </div>
                  <Progress value={score.score} className="h-1 mt-2" />
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Caldera Deployment Tab ──────────────────────────────────────────────────

function CalderaDeploymentTab() {
  const { data: deploymentStatus, isLoading, refetch } = trpc.c2KnowledgeBase.getDeploymentStatus.useQuery();
  const { data: autoGenStats } = trpc.c2KnowledgeBase.getAutoGenerationStats.useQuery();
  const { data: autoGenHistory } = trpc.c2KnowledgeBase.getAutoGenerationHistory.useQuery({ limit: 15 });

  const pushMutation = trpc.c2KnowledgeBase.pushToCaldera.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Deployed to Caldera: ${data.adversaryId}`);
        refetch();
      } else {
        toast.error(data.error || "Push failed");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const batchPushMutation = trpc.c2KnowledgeBase.batchPushToCaldera.useMutation({
    onSuccess: (data) => {
      toast.success(`Batch push: ${data.pushed} deployed, ${data.skipped} skipped, ${data.failed} failed`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const checkAutoGenMutation = trpc.c2KnowledgeBase.checkAutoGeneration.useMutation({
    onSuccess: (data) => {
      if (data.profileGenerated) {
        toast.success(`Auto-generated profile for ${data.actorName}${data.pushedToCaldera ? " and pushed to Caldera" : ""}`);
      } else if (data.thresholdMet) {
        toast.info(`Threshold met but generation skipped: ${data.error || "already exists"}`);
      } else {
        toast.info(`Score ${data.newScore}/100 — below threshold`);
      }
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const statusColors: Record<string, string> = {
    deployed: "text-green-400 bg-green-500/10",
    local_only: "text-blue-400 bg-blue-500/10",
    pending: "text-yellow-400 bg-yellow-500/10",
    failed: "text-red-400 bg-red-500/10",
    updated: "text-cyan-400 bg-cyan-500/10",
  };

  const statusIcons: Record<string, React.ReactNode> = {
    deployed: <CheckCircle2 className="h-3 w-3" />,
    local_only: <CloudUpload className="h-3 w-3" />,
    pending: <Loader2 className="h-3 w-3 animate-spin" />,
    failed: <XCircle className="h-3 w-3" />,
    updated: <RefreshCw className="h-3 w-3" />,
  };

  return (
    <div className="space-y-6">
      {/* Pipeline Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {[
          { label: "Total Checks", value: autoGenStats?.totalChecks ?? 0, icon: Activity },
          { label: "Generated", value: autoGenStats?.totalGenerated ?? 0, icon: Sparkles },
          { label: "Pushed", value: autoGenStats?.totalPushed ?? 0, icon: Upload },
          { label: "Skipped", value: autoGenStats?.totalSkipped ?? 0, icon: ChevronRight },
          { label: "Failed", value: autoGenStats?.totalFailed ?? 0, icon: XCircle },
          { label: "Threshold", value: autoGenStats?.configuredThreshold ?? 60, icon: Settings2 },
        ].map(stat => (
          <Card key={stat.label} className="bg-card/50">
            <CardContent className="p-3 text-center">
              <stat.icon className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
              <div className="text-lg font-bold">{stat.value}</div>
              <div className="text-[10px] text-muted-foreground">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Deployment Status + Actions */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Rocket className="h-5 w-5 text-orange-400" /> Caldera Deployment Status
              </CardTitle>
              <CardDescription>
                Push generated adversary profiles to the live Caldera C2 server for emulation campaigns
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => refetch()}
              >
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
              </Button>
              <Button
                size="sm"
                onClick={() => batchPushMutation.mutate({ dryRun: false, minScore: 60 })}
                disabled={batchPushMutation.isPending}
              >
                {batchPushMutation.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                ) : (
                  <Upload className="h-3.5 w-3.5 mr-1.5" />
                )}
                Batch Push All
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-sm text-muted-foreground">Loading deployment status...</div>
          ) : !deploymentStatus || deploymentStatus.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <CloudUpload className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No adversary profiles generated yet.</p>
              <p className="text-xs">Generate profiles from the Adversary Profiles tab first.</p>
            </div>
          ) : (
            <ScrollArea className="h-80">
              <div className="space-y-2">
                {deploymentStatus.map(item => (
                  <div
                    key={item.actorId}
                    className="flex items-center justify-between p-3 rounded-lg border border-border/50 hover:border-primary/30 transition-all"
                  >
                    <div className="flex items-center gap-3">
                      <Badge className={`text-[10px] px-1.5 py-0.5 ${statusColors[item.status] || ""}`}>
                        {statusIcons[item.status]} <span className="ml-1">{item.status.replace("_", " ")}</span>
                      </Badge>
                      <div>
                        <div className="text-sm font-medium">{item.actorName}</div>
                        <div className="text-xs text-muted-foreground">
                          {item.abilityCount} abilities
                          {item.deployedAt && ` · Deployed ${new Date(item.deployedAt).toLocaleDateString()}`}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      {item.status !== "deployed" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => pushMutation.mutate({ actorId: item.actorId })}
                          disabled={pushMutation.isPending}
                        >
                          {pushMutation.isPending ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <Upload className="h-3 w-3" />
                          )}
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => checkAutoGenMutation.mutate({ actorId: item.actorId })}
                        disabled={checkAutoGenMutation.isPending}
                      >
                        <RefreshCw className="h-3 w-3" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
          {deploymentStatus && deploymentStatus.length > 0 && (
            <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-green-500" /> Deployed: {deploymentStatus.filter(d => d.status === "deployed").length}
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-blue-500" /> Local: {deploymentStatus.filter(d => d.status === "local_only").length}
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-red-500" /> Failed: {deploymentStatus.filter(d => d.status === "failed").length}
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Auto-Generation History */}
      {autoGenHistory && autoGenHistory.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Workflow className="h-5 w-5 text-purple-400" /> Auto-Generation Pipeline History
            </CardTitle>
            <CardDescription>
              Automatic profile generation triggered by threat intel enrichment
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-64">
              <div className="space-y-2">
                {autoGenHistory.map((event, i) => (
                  <div key={i} className="flex items-start gap-3 p-2 rounded-lg hover:bg-muted/20 text-xs">
                    <div className="shrink-0 mt-0.5">
                      {event.profileGenerated ? (
                        <CheckCircle2 className="h-4 w-4 text-green-400" />
                      ) : event.thresholdMet ? (
                        <AlertTriangle className="h-4 w-4 text-yellow-400" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="font-medium">{event.actorName}</div>
                      <div className="text-muted-foreground">
                        Score: {event.newScore}/100 · Source: {event.triggerSource.replace("_", " ")}
                        {event.pushedToCaldera && " · Pushed to Caldera"}
                        {event.error && ` · ${event.error}`}
                      </div>
                    </div>
                    <div className="text-muted-foreground shrink-0">
                      {new Date(event.triggeredAt).toLocaleTimeString()}
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Post-Exploitation Playbook Tab ─────────────────────────────────────────

function PlaybookTab() {
  const [shellPriv, setShellPriv] = useState<string>("user");
  const [platform, setPlatform] = useState<string>("windows");
  const [hasAD, setHasAD] = useState(true);

  const { data: playbook, isLoading } = trpc.c2KnowledgeBase.generatePlaybook.useQuery({
    shellPrivilege: shellPriv as any,
    targetPlatform: platform as any,
    hasActiveDirectory: hasAD,
    objectives: ["Full compromise assessment", "Data exfiltration proof"],
  });

  const phaseColors: Record<string, string> = {
    discovery: "bg-blue-500/10 text-blue-400",
    privilege_escalation: "bg-orange-500/10 text-orange-400",
    credential_access: "bg-red-500/10 text-red-400",
    persistence: "bg-purple-500/10 text-purple-400",
    lateral_movement: "bg-green-500/10 text-green-400",
    collection_exfiltration: "bg-yellow-500/10 text-yellow-400",
    defense_evasion: "bg-emerald-500/10 text-emerald-400",
    execution: "bg-cyan-500/10 text-cyan-400",
    impact: "bg-pink-500/10 text-pink-400",
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Terminal className="h-5 w-5 text-green-400" /> Shell/Agent Context
          </CardTitle>
          <CardDescription>Configure the shell/agent callback context to generate a post-exploitation playbook</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Shell Privilege</label>
              <Select value={shellPriv} onValueChange={setShellPriv}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="system">SYSTEM</SelectItem>
                  <SelectItem value="root">Root</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Platform</label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Active Directory</label>
              <Select value={hasAD ? "yes" : "no"} onValueChange={v => setHasAD(v === "yes")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="yes">Yes</SelectItem>
                  <SelectItem value="no">No</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {playbook && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <BookOpen className="h-5 w-5 text-primary" /> Post-Exploitation Playbook
              </CardTitle>
              <CardDescription>
                {playbook.steps.length} steps · Est. {playbook.estimatedDuration} · {playbook.targetPlatform} ({playbook.shellType})
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Steps */}
              <div className="space-y-3">
                {playbook.steps.map(step => (
                  <div key={step.order} className="border border-border/50 rounded-lg p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="bg-primary/20 rounded-full w-7 h-7 flex items-center justify-center text-xs font-bold shrink-0">
                        {step.order}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold">{step.action}</span>
                          <Badge className={`text-[10px] px-1.5 py-0 ${phaseColors[step.phase] || ""}`}>
                            {step.phase.replace(/_/g, " ")}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {step.framework}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {step.requiredPrivilege}
                          </Badge>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground ml-10">{step.description}</p>
                    <div className="ml-10 mt-2 flex flex-wrap gap-1">
                      {step.techniqueIds.map(t => (
                        <Badge key={t} className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400">{t}</Badge>
                      ))}
                    </div>
                    {step.modules.length > 0 && (
                      <div className="ml-10 mt-1 text-[10px] text-muted-foreground">
                        Modules: {step.modules.join(", ")}
                      </div>
                    )}
                    <div className="ml-10 mt-1 text-[10px] text-muted-foreground/60">
                      Expected: {step.expectedOutput}
                    </div>
                    <div className="ml-10 text-[10px] text-primary/60">
                      Next: {step.nextStepTrigger}
                    </div>
                  </div>
                ))}
              </div>

              {/* OPSEC Guidelines */}
              <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-yellow-400 mb-2 flex items-center gap-2">
                  <Eye className="h-4 w-4" /> OPSEC Guidelines
                </h4>
                <ul className="space-y-1">
                  {playbook.opsecGuidelines.map((g, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-yellow-400 shrink-0" />
                      {g}
                    </li>
                  ))}
                </ul>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

// ─── Comparison Matrix Tab ──────────────────────────────────────────────────

function ComparisonMatrixTab() {
  const { data: matrix, isLoading } = trpc.c2KnowledgeBase.getComparisonMatrix.useQuery();

  if (isLoading || !matrix) return <div className="text-sm text-muted-foreground">Loading...</div>;

  const detectionBadge = (d: string) => {
    const colors: Record<string, string> = {
      "very-hard": "bg-green-500/10 text-green-400",
      hard: "bg-emerald-500/10 text-emerald-400",
      moderate: "bg-yellow-500/10 text-yellow-400",
      easy: "bg-red-500/10 text-red-400",
    };
    return <Badge className={`text-[10px] px-1.5 py-0 ${colors[d] || ""}`}>{d}</Badge>;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-blue-400" /> Framework Comparison Matrix
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/50">
                <th className="text-left p-2 text-muted-foreground">Framework</th>
                <th className="text-center p-2 text-muted-foreground">Platforms</th>
                <th className="text-center p-2 text-muted-foreground">Protocols</th>
                <th className="text-center p-2 text-muted-foreground">Evasion</th>
                <th className="text-center p-2 text-muted-foreground">Detection</th>
                <th className="text-center p-2 text-muted-foreground">Noise</th>
                <th className="text-center p-2 text-muted-foreground">Disk</th>
                <th className="text-center p-2 text-muted-foreground">Post-Exploit</th>
                <th className="text-center p-2 text-muted-foreground">Techniques</th>
              </tr>
            </thead>
            <tbody>
              {matrix.map(row => (
                <tr key={row.framework} className="border-b border-border/30 hover:bg-muted/10">
                  <td className="p-2 font-medium">{row.displayName}</td>
                  <td className="p-2 text-center">
                    <div className="flex gap-1 justify-center">
                      {row.platforms.map(p => (
                        <Badge key={p} variant="outline" className="text-[9px] px-1 py-0">{p}</Badge>
                      ))}
                    </div>
                  </td>
                  <td className="p-2 text-center font-mono">{row.protocols}</td>
                  <td className="p-2 text-center font-mono">{row.evasionCapabilities}</td>
                  <td className="p-2 text-center">{detectionBadge(row.detectionDifficulty)}</td>
                  <td className="p-2 text-center">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">{row.networkNoise}</Badge>
                  </td>
                  <td className="p-2 text-center">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">{row.diskArtifacts}</Badge>
                  </td>
                  <td className="p-2 text-center font-mono">{row.postExploitModules}</td>
                  <td className="p-2 text-center font-mono">{row.techniquesCovered}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

const C2KnowledgeBase: React.FC = () => {
  const { data: stats } = trpc.c2KnowledgeBase.getSummaryStats.useQuery();

  return (
    <AppShell activePath="/c2-knowledge-base">
      <div className="space-y-6 p-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="bg-primary/10 rounded-xl p-3">
              <Brain className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h1 className="font-display text-2xl font-bold tracking-wider">C2 Tactical Knowledge Base</h1>
              <p className="text-muted-foreground text-sm">
                Operational intelligence for C2 framework selection, adversary emulation, and post-exploitation
              </p>
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            {[
              { label: "Frameworks", value: stats.totalFrameworks, icon: Server },
              { label: "Techniques", value: stats.totalTechniques, icon: Crosshair },
              { label: "Post-Exploit", value: stats.totalPostExploitCapabilities, icon: Swords },
              { label: "Evasion", value: stats.totalEvasionCapabilities, icon: Shield },
              { label: "Actors", value: stats.totalActors.toLocaleString(), icon: Target },
              { label: "With Abilities", value: stats.actorsWithAbilities, icon: Layers },
              { label: "Ability Maps", value: stats.totalAbilityMappings.toLocaleString(), icon: Network },
              { label: "Profiles", value: stats.actorsWithProfiles, icon: CheckCircle2 },
            ].map(stat => (
              <Card key={stat.label} className="bg-card/50">
                <CardContent className="p-3 text-center">
                  <stat.icon className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
                  <div className="text-lg font-bold">{stat.value}</div>
                  <div className="text-[10px] text-muted-foreground">{stat.label}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Tabs */}
        <Tabs defaultValue="profiles" className="space-y-4">
          <TabsList className="grid w-full grid-cols-7">
            <TabsTrigger value="profiles" className="text-xs">
              <Server className="h-3.5 w-3.5 mr-1.5" /> Frameworks
            </TabsTrigger>
            <TabsTrigger value="recommend" className="text-xs">
              <Brain className="h-3.5 w-3.5 mr-1.5" /> Advisor
            </TabsTrigger>
            <TabsTrigger value="adversary" className="text-xs">
              <Target className="h-3.5 w-3.5 mr-1.5" /> Adversary Profiles
            </TabsTrigger>
            <TabsTrigger value="deployment" className="text-xs">
              <Rocket className="h-3.5 w-3.5 mr-1.5" /> Deploy & Pipeline
            </TabsTrigger>
            <TabsTrigger value="playbook" className="text-xs">
              <BookOpen className="h-3.5 w-3.5 mr-1.5" /> Playbooks
            </TabsTrigger>
            <TabsTrigger value="matrix" className="text-xs">
              <BarChart3 className="h-3.5 w-3.5 mr-1.5" /> Comparison
            </TabsTrigger>
            <TabsTrigger value="operations" className="text-xs">
              <Rocket className="h-3.5 w-3.5 mr-1.5" /> Operations
            </TabsTrigger>
          </TabsList>

          <TabsContent value="profiles"><FrameworkProfilesTab /></TabsContent>
          <TabsContent value="recommend"><RecommendationTab /></TabsContent>
          <TabsContent value="adversary"><AdversaryProfileTab /></TabsContent>
          <TabsContent value="deployment"><CalderaDeploymentTab /></TabsContent>
          <TabsContent value="playbook"><PlaybookTab /></TabsContent>
          <TabsContent value="matrix"><ComparisonMatrixTab /></TabsContent>
          <TabsContent value="operations"><OperationLauncherTab /></TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
};

export default C2KnowledgeBase;
