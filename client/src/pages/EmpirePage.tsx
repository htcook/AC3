/**
 * Empire C2 Management Page
 *
 * Dedicated interface for managing Empire/Starkiller C2 operations.
 * Provides agent management, listener configuration, module search and
 * execution, stager generation, and live health monitoring.
 */
import React, { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import {
  Crown, Terminal, Server, Shield, Users, Activity,
  CheckCircle2, XCircle, Clock, Loader2, Play, Search,
  Plus, Trash2, RefreshCw, Copy, Eye, Zap, Network,
  AlertTriangle, ChevronRight, Monitor, Lock,
} from "lucide-react";

// ─── Health Banner ──────────────────────────────────────────────────────────

function HealthBanner() {
  const { data: health, isLoading, refetch } = trpc.empire.health.useQuery(undefined, {
    refetchInterval: 30000,
  });

  if (isLoading) {
    return (
      <Card className="bg-muted/20">
        <CardContent className="p-4 flex items-center gap-3">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">Checking Empire server...</span>
        </CardContent>
      </Card>
    );
  }

  const isOnline = health?.connected;

  return (
    <Card className={isOnline ? "border-green-500/30 bg-green-500/5" : "border-yellow-500/30 bg-yellow-500/5"}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {isOnline ? (
              <CheckCircle2 className="h-5 w-5 text-green-400" />
            ) : (
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
            )}
            <div>
              <div className="text-sm font-semibold">
                {isOnline ? "Empire Server Online" : "Empire Server Offline"}
              </div>
              <div className="text-xs text-muted-foreground">
                {isOnline
                  ? `v${health?.version || "5.x"} · ${health?.agentCount || 0} agents · ${health?.activeJobs || 0} listeners`
                  : health?.error || "Server not reachable. Configure EMPIRE_BASE_URL and EMPIRE_API_KEY."}
              </div>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Agents Tab ─────────────────────────────────────────────────────────────

function AgentsTab() {
  const { data: agents, isLoading, refetch } = trpc.empire.listAgents.useQuery(undefined, {
    refetchInterval: 15000,
  });
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [shellCmd, setShellCmd] = useState("");

  const killMut = trpc.empire.killAgent.useMutation({
    onSuccess: () => {
      toast.success("Agent killed");
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const shellMut = trpc.empire.shellCommand.useMutation({
    onSuccess: (result) => {
      toast.success(`Shell task queued: ${result.taskId}`);
      setShellCmd("");
    },
    onError: (err) => toast.error(err.message),
  });

  const statusColors: Record<string, string> = {
    active: "bg-green-500/10 text-green-400",
    dormant: "bg-yellow-500/10 text-yellow-400",
    dead: "bg-red-500/10 text-red-400",
  };

  if (isLoading) {
    return <div className="text-sm text-muted-foreground">Loading agents...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">{agents?.length || 0} agents</div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="h-3.5 w-3.5 mr-1" /> Refresh
        </Button>
      </div>

      {(!agents || agents.length === 0) ? (
        <Card className="bg-muted/10">
          <CardContent className="p-8 text-center">
            <Users className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">No agents connected</p>
            <p className="text-xs text-muted-foreground mt-1">
              Deploy a stager to get agent callbacks. Make sure a listener is running first.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {agents.map(agent => (
            <Card
              key={agent.id}
              className={`cursor-pointer transition-all hover:border-primary/30 ${selectedAgent === agent.id ? "border-primary" : ""}`}
              onClick={() => setSelectedAgent(selectedAgent === agent.id ? null : agent.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Monitor className="h-5 w-5 text-purple-400" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{agent.hostname}</span>
                        <Badge className={`text-[10px] px-1.5 py-0 ${statusColors[agent.status] || ""}`}>
                          {agent.status}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                          {agent.platform}
                        </Badge>
                      </div>
                      <div className="text-xs text-muted-foreground mt-0.5">
                        {agent.username} · {agent.ipAddress} · PID {agent.processId || "N/A"}
                        {agent.metadata?.language && ` · ${agent.metadata.language}`}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {agent.privileges === "admin" || agent.privileges === "system" ? (
                      <Badge className="bg-red-500/10 text-red-400 text-[10px]">
                        <Lock className="h-3 w-3 mr-0.5" /> {agent.privileges}
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-[10px]">{agent.privileges}</Badge>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-400 hover:text-red-300"
                      onClick={(e) => {
                        e.stopPropagation();
                        killMut.mutate({ agentId: agent.id });
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>

                {/* Expanded shell interaction */}
                {selectedAgent === agent.id && (
                  <div className="mt-4 space-y-3">
                    <Separator />
                    <div className="flex items-center gap-2">
                      <Terminal className="h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Enter shell command..."
                        value={shellCmd}
                        onChange={(e) => setShellCmd(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && shellCmd.trim()) {
                            shellMut.mutate({ agentId: agent.id, command: shellCmd });
                          }
                        }}
                        className="text-xs font-mono"
                      />
                      <Button
                        size="sm"
                        onClick={() => {
                          if (shellCmd.trim()) {
                            shellMut.mutate({ agentId: agent.id, command: shellCmd });
                          }
                        }}
                        disabled={shellMut.isPending || !shellCmd.trim()}
                      >
                        {shellMut.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Play className="h-3.5 w-3.5" />
                        )}
                      </Button>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-xs">
                      <div className="bg-muted/20 rounded p-2">
                        <span className="text-muted-foreground">Transport:</span>{" "}
                        <span>{agent.transport}</span>
                      </div>
                      <div className="bg-muted/20 rounded p-2">
                        <span className="text-muted-foreground">Arch:</span>{" "}
                        <span>{agent.architecture}</span>
                      </div>
                      <div className="bg-muted/20 rounded p-2">
                        <span className="text-muted-foreground">Last Seen:</span>{" "}
                        <span>{new Date(agent.lastSeen).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Listeners Tab ──────────────────────────────────────────────────────────

function ListenersTab() {
  const { data: listeners, isLoading, refetch } = trpc.empire.listListeners.useQuery(undefined, {
    refetchInterval: 30000,
  });
  const [showCreate, setShowCreate] = useState(false);
  const [newListener, setNewListener] = useState({
    name: "http-listener",
    template: "http",
    host: "0.0.0.0",
    port: 80,
  });

  const createMut = trpc.empire.createListener.useMutation({
    onSuccess: () => {
      toast.success("Listener created");
      setShowCreate(false);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  if (isLoading) {
    return <div className="text-sm text-muted-foreground">Loading listeners...</div>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {Array.isArray(listeners) ? listeners.length : 0} listeners
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="h-3.5 w-3.5 mr-1" /> New Listener
        </Button>
      </div>

      {(!listeners || !Array.isArray(listeners) || listeners.length === 0) ? (
        <Card className="bg-muted/10">
          <CardContent className="p-8 text-center">
            <Server className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-sm text-muted-foreground">No active listeners</p>
            <p className="text-xs text-muted-foreground mt-1">
              Create a listener to receive agent callbacks.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {listeners.map((listener: any, i: number) => (
            <Card key={listener.name || listener.id || i}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-green-400" />
                    <span className="text-sm font-medium">{listener.name || `Listener ${i + 1}`}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px]">
                    {listener.template || listener.module || "http"}
                  </Badge>
                </div>
                <div className="text-xs text-muted-foreground mt-2">
                  {listener.options?.Host || listener.host || "0.0.0.0"}:{listener.options?.Port || listener.port || 80}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create Listener Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Empire Listener</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Name</label>
              <Input
                value={newListener.name}
                onChange={(e) => setNewListener(prev => ({ ...prev, name: e.target.value }))}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Template</label>
              <Select value={newListener.template} onValueChange={(v) => setNewListener(prev => ({ ...prev, template: v }))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="http">HTTP</SelectItem>
                  <SelectItem value="http_com">HTTP COM</SelectItem>
                  <SelectItem value="http_hop">HTTP Hop</SelectItem>
                  <SelectItem value="http_foreign">HTTP Foreign</SelectItem>
                  <SelectItem value="http_mapi">HTTP MAPI</SelectItem>
                  <SelectItem value="onedrive">OneDrive</SelectItem>
                  <SelectItem value="dbx">Dropbox</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Host</label>
                <Input
                  value={newListener.host}
                  onChange={(e) => setNewListener(prev => ({ ...prev, host: e.target.value }))}
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Port</label>
                <Input
                  type="number"
                  value={newListener.port}
                  onChange={(e) => setNewListener(prev => ({ ...prev, port: parseInt(e.target.value) || 80 }))}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button onClick={() => createMut.mutate(newListener)} disabled={createMut.isPending}>
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Plus className="h-4 w-4 mr-2" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ─── Modules Tab ────────────────────────────────────────────────────────────

function ModulesTab() {
  const [searchQuery, setSearchQuery] = useState("mimikatz");
  const [debouncedQuery, setDebouncedQuery] = useState("mimikatz");
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [execAgentId, setExecAgentId] = useState("");

  // Debounce search
  React.useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const { data: modules, isLoading } = trpc.empire.searchModules.useQuery(
    { query: debouncedQuery },
    { enabled: debouncedQuery.length > 0 },
  );

  const { data: moduleDetail } = trpc.empire.getModule.useQuery(
    { moduleId: selectedModule! },
    { enabled: !!selectedModule },
  );

  const { data: agents } = trpc.empire.listAgents.useQuery();

  const execMut = trpc.empire.executeModule.useMutation({
    onSuccess: (result) => {
      toast.success(`Module task queued: ${result.taskId}`);
    },
    onError: (err) => toast.error(err.message),
  });

  const tacticColors: Record<string, string> = {
    "credential-access": "bg-red-500/10 text-red-400",
    "lateral-movement": "bg-green-500/10 text-green-400",
    "privilege-escalation": "bg-orange-500/10 text-orange-400",
    "persistence": "bg-purple-500/10 text-purple-400",
    "discovery": "bg-blue-500/10 text-blue-400",
    "collection": "bg-yellow-500/10 text-yellow-400",
    "defense-evasion": "bg-emerald-500/10 text-emerald-400",
    "exfiltration": "bg-pink-500/10 text-pink-400",
  };

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search modules (mimikatz, kerberoast, bloodhound, psexec...)"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
        <div className="text-xs text-muted-foreground">{modules?.length || 0} results</div>
      </div>

      {/* Quick filters */}
      <div className="flex flex-wrap gap-1.5">
        {["mimikatz", "kerberoast", "bloodhound", "psexec", "persistence", "privesc", "collection", "lateral"].map(q => (
          <Button
            key={q}
            variant={searchQuery === q ? "default" : "outline"}
            size="sm"
            className="text-xs h-7"
            onClick={() => setSearchQuery(q)}
          >
            {q}
          </Button>
        ))}
      </div>

      {/* Module List */}
      {isLoading ? (
        <div className="text-sm text-muted-foreground">Searching...</div>
      ) : (
        <div className="space-y-2">
          {modules?.map(mod => (
            <Card
              key={mod.id}
              className={`cursor-pointer transition-all hover:border-primary/30 ${selectedModule === mod.id ? "border-primary" : ""}`}
              onClick={() => setSelectedModule(selectedModule === mod.id ? null : mod.id)}
            >
              <CardContent className="p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 min-w-0">
                    <Zap className="h-4 w-4 text-purple-400 shrink-0" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium">{mod.name}</span>
                        {mod.tactic && (
                          <Badge className={`text-[9px] px-1 py-0 ${tacticColors[mod.tactic] || ""}`}>
                            {mod.tactic}
                          </Badge>
                        )}
                        {mod.techniqueId && (
                          <Badge className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400">
                            {mod.techniqueId}
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground truncate mt-0.5">{mod.description}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {mod.platform.map(p => (
                      <Badge key={p} variant="outline" className="text-[9px] px-1 py-0">{p}</Badge>
                    ))}
                  </div>
                </div>

                {/* Expanded: Execute on agent */}
                {selectedModule === mod.id && (
                  <div className="mt-3 pt-3 border-t border-border/50">
                    <div className="text-xs font-mono text-muted-foreground mb-2">{mod.id}</div>
                    <div className="flex items-center gap-2">
                      <Select value={execAgentId} onValueChange={setExecAgentId}>
                        <SelectTrigger className="flex-1 text-xs">
                          <SelectValue placeholder="Select agent..." />
                        </SelectTrigger>
                        <SelectContent>
                          {agents?.map(a => (
                            <SelectItem key={a.id} value={a.id}>
                              {a.hostname} ({a.username})
                            </SelectItem>
                          )) || <SelectItem value="none" disabled>No agents</SelectItem>}
                        </SelectContent>
                      </Select>
                      <Button
                        size="sm"
                        onClick={() => {
                          if (!execAgentId) {
                            toast.error("Select an agent first");
                            return;
                          }
                          execMut.mutate({
                            agentId: execAgentId,
                            moduleId: mod.id,
                          });
                        }}
                        disabled={execMut.isPending || !execAgentId}
                      >
                        {execMut.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" />
                        ) : (
                          <Play className="h-3.5 w-3.5 mr-1" />
                        )}
                        Execute
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Stagers Tab ────────────────────────────────────────────────────────────

function StagersTab() {
  const { data: stagers, isLoading } = trpc.empire.listStagers.useQuery();
  const { data: listeners } = trpc.empire.listListeners.useQuery();
  const [selectedListener, setSelectedListener] = useState("");
  const [selectedTemplate, setSelectedTemplate] = useState("multi/launcher");

  const generateMut = trpc.empire.generateStager.useMutation({
    onSuccess: (result) => {
      toast.success("Stager generated");
      if (result.output) {
        navigator.clipboard.writeText(result.output).catch(() => {});
        toast.info("Stager output copied to clipboard");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const stagerTemplates = [
    { id: "multi/launcher", name: "Multi Launcher", description: "Generic one-liner launcher" },
    { id: "windows/launcher_bat", name: "Windows BAT", description: "Windows batch file launcher" },
    { id: "windows/launcher_vbs", name: "Windows VBS", description: "VBScript launcher" },
    { id: "windows/launcher_sct", name: "Windows SCT", description: "Scriptlet launcher" },
    { id: "windows/dll", name: "Windows DLL", description: "DLL stager for sideloading" },
    { id: "windows/hta", name: "Windows HTA", description: "HTML Application stager" },
    { id: "windows/macro", name: "Office Macro", description: "VBA macro for Office documents" },
    { id: "multi/bash", name: "Bash Launcher", description: "Bash one-liner for Linux/macOS" },
    { id: "multi/pyinstaller", name: "PyInstaller", description: "Compiled Python executable" },
    { id: "osx/applescript", name: "macOS AppleScript", description: "AppleScript launcher" },
    { id: "osx/macho", name: "macOS Mach-O", description: "Native macOS binary" },
  ];

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-400" /> Generate Stager
          </CardTitle>
          <CardDescription>Create a stager payload to deploy Empire agents</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Stager Template</label>
              <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {stagerTemplates.map(t => (
                    <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Listener</label>
              <Select value={selectedListener} onValueChange={setSelectedListener}>
                <SelectTrigger><SelectValue placeholder="Select listener..." /></SelectTrigger>
                <SelectContent>
                  {Array.isArray(listeners) && listeners.length > 0 ? (
                    listeners.map((l: any, i: number) => (
                      <SelectItem key={l.name || i} value={l.name || `listener-${i}`}>
                        {l.name || `Listener ${i + 1}`}
                      </SelectItem>
                    ))
                  ) : (
                    <SelectItem value="none" disabled>No listeners available</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
          </div>
          <Button
            onClick={() => {
              if (!selectedListener) {
                toast.error("Select a listener first");
                return;
              }
              generateMut.mutate({
                template: selectedTemplate,
                listener: selectedListener,
              });
            }}
            disabled={generateMut.isPending || !selectedListener}
          >
            {generateMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : (
              <Zap className="h-4 w-4 mr-2" />
            )}
            Generate Stager
          </Button>

          {generateMut.data?.output && (
            <div className="bg-muted/20 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold">Stager Output</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(generateMut.data?.output || "");
                    toast.success("Copied to clipboard");
                  }}
                >
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              </div>
              <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                {generateMut.data.output}
              </pre>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Stager Templates Reference */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Available Stager Templates</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {stagerTemplates.map(t => (
              <div
                key={t.id}
                className={`p-3 rounded-lg border cursor-pointer transition-all hover:border-primary/30 ${selectedTemplate === t.id ? "border-primary bg-primary/5" : "border-border/50"}`}
                onClick={() => setSelectedTemplate(t.id)}
              >
                <div className="text-sm font-medium">{t.name}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{t.description}</div>
                <div className="text-[10px] font-mono text-muted-foreground/60 mt-1">{t.id}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function EmpirePage() {
  return (
    <AppShell activePath="/empire">
      <div className="space-y-6 p-4">
        {/* Header */}
        <div className="flex items-center gap-4">
          <div className="bg-purple-500/10 rounded-xl p-3">
            <Crown className="h-8 w-8 text-purple-400" />
          </div>
          <div>
            <h1 className="font-display text-2xl font-bold tracking-wider">Empire C2</h1>
            <p className="text-muted-foreground text-sm">
              PowerShell/Python/C# post-exploitation framework with Starkiller GUI integration
            </p>
          </div>
        </div>

        {/* Health Banner */}
        <HealthBanner />

        {/* Tabs */}
        <Tabs defaultValue="agents" className="space-y-4">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="agents" className="text-xs">
              <Users className="h-3.5 w-3.5 mr-1.5" /> Agents
            </TabsTrigger>
            <TabsTrigger value="listeners" className="text-xs">
              <Server className="h-3.5 w-3.5 mr-1.5" /> Listeners
            </TabsTrigger>
            <TabsTrigger value="modules" className="text-xs">
              <Zap className="h-3.5 w-3.5 mr-1.5" /> Modules
            </TabsTrigger>
            <TabsTrigger value="stagers" className="text-xs">
              <Terminal className="h-3.5 w-3.5 mr-1.5" /> Stagers
            </TabsTrigger>
          </TabsList>

          <TabsContent value="agents"><AgentsTab /></TabsContent>
          <TabsContent value="listeners"><ListenersTab /></TabsContent>
          <TabsContent value="modules"><ModulesTab /></TabsContent>
          <TabsContent value="stagers"><StagersTab /></TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
