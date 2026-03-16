import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import {
  Boxes, ChevronLeft, Plus, Flame, Network, Brain,
  RefreshCw, Play, Pause, Cpu, Activity, Shield, Zap
} from "lucide-react";
import { Link } from "wouter";

const OBJECTIVE_OPTIONS = [
  { value: "network_mapping", label: "Network Mapping", desc: "Coordinate agents to map the full network topology" },
  { value: "credential_sweep", label: "Credential Sweep", desc: "Distributed credential harvesting across all compromised hosts" },
  { value: "lateral_movement", label: "Lateral Movement", desc: "Coordinated lateral movement to expand access" },
  { value: "data_exfiltration", label: "Data Exfiltration", desc: "Staged data collection and exfiltration through agent chain" },
  { value: "persistence_mesh", label: "Persistence Mesh", desc: "Establish redundant persistence across multiple hosts" },
  { value: "edr_evasion_test", label: "EDR Evasion Test", desc: "Coordinated EDR evasion testing across endpoints" },
];

export default function EmberSwarmControl() {
  const [showCreate, setShowCreate] = useState(false);
  const [swarmName, setSwarmName] = useState("");
  const [objective, setObjective] = useState("network_mapping");
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);

  const dashboardQuery = trpc.ember.getDashboard.useQuery(undefined, { refetchInterval: 10000 });
  const agentsQuery = trpc.ember.listAgents.useQuery({ state: "active" as any, limit: 100 }, { refetchInterval: 10000 });

  const createSwarm = trpc.ember.createSwarm.useMutation({
    onSuccess: () => {
      toast.success("Swarm created");
      setShowCreate(false);
      setSwarmName("");
      setSelectedAgents([]);
      dashboardQuery.refetch();
    },
    onError: (e) => toast.error(`Failed: ${e.message}`),
  });

  const agents = agentsQuery.data || [];

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
          <div className="p-2 rounded-lg bg-gradient-to-br from-purple-500/20 to-violet-600/20 border border-purple-500/30">
            <Boxes className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">Swarm Control</h1>
            <p className="text-sm text-muted-foreground">Coordinate multi-agent operations with shared intelligence</p>
          </div>
        </div>
        <Button onClick={() => setShowCreate(true)} className="bg-purple-600 hover:bg-purple-700 text-white">
          <Plus className="w-4 h-4 mr-2" /> Create Swarm
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-purple-400">{dashboardQuery.data?.totalSwarms ?? 0}</p>
            <p className="text-xs text-muted-foreground">Active Swarms</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-emerald-400">{agents.length}</p>
            <p className="text-xs text-muted-foreground">Available Agents</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-cyan-400">{dashboardQuery.data?.totalIntel ?? 0}</p>
            <p className="text-xs text-muted-foreground">Shared Intel</p>
          </CardContent>
        </Card>
        <Card className="bg-card/50 border-border/50">
          <CardContent className="p-4 text-center">
            <p className="text-2xl font-bold text-amber-400">6</p>
            <p className="text-xs text-muted-foreground">Objective Types</p>
          </CardContent>
        </Card>
      </div>

      {/* Swarm Objectives */}
      <Card className="bg-card/50 border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Swarm Objectives</CardTitle>
          <CardDescription>Pre-built coordination strategies for multi-agent operations</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {OBJECTIVE_OPTIONS.map((obj) => (
              <Card key={obj.value} className="bg-muted/20 border-border/30 hover:border-purple-500/30 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-2">
                    {obj.value === "network_mapping" ? <Network className="w-4 h-4 text-blue-400" /> :
                     obj.value === "credential_sweep" ? <Shield className="w-4 h-4 text-amber-400" /> :
                     obj.value === "lateral_movement" ? <Zap className="w-4 h-4 text-red-400" /> :
                     obj.value === "data_exfiltration" ? <Activity className="w-4 h-4 text-cyan-400" /> :
                     obj.value === "persistence_mesh" ? <Boxes className="w-4 h-4 text-purple-400" /> :
                     <Brain className="w-4 h-4 text-emerald-400" />}
                    <span className="text-sm font-medium text-foreground">{obj.label}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{obj.desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Empty State */}
      <Card className="bg-card/30 border-border/30">
        <CardContent className="p-12 text-center">
          <Boxes className="w-16 h-16 text-purple-400/20 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-foreground mb-2">No Active Swarms</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Create a swarm to coordinate multiple agents toward a shared objective.
            Agents within a swarm share intelligence, coordinate actions, and adapt collectively.
          </p>
          <Button onClick={() => setShowCreate(true)} className="bg-purple-600 hover:bg-purple-700 text-white">
            <Plus className="w-4 h-4 mr-2" /> Create First Swarm
          </Button>
        </CardContent>
      </Card>

      {/* Create Swarm Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Boxes className="w-4 h-4 text-purple-400" /> Create Swarm
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Swarm Name</Label>
              <Input
                value={swarmName}
                onChange={(e) => setSwarmName(e.target.value)}
                placeholder="Operation Nightfall"
              />
            </div>
            <div className="space-y-2">
              <Label>Objective</Label>
              <Select value={objective} onValueChange={setObjective}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {OBJECTIVE_OPTIONS.map((obj) => (
                    <SelectItem key={obj.value} value={obj.value}>{obj.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Select Agents ({selectedAgents.length} selected)</Label>
              <div className="max-h-48 overflow-y-auto space-y-1 border border-border/30 rounded-lg p-2">
                {agents.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-3">No active agents available</p>
                ) : (
                  agents.map((agent: any) => (
                    <button
                      key={agent.agentId}
                      onClick={() => {
                        setSelectedAgents(prev =>
                          prev.includes(agent.agentId)
                            ? prev.filter(id => id !== agent.agentId)
                            : [...prev, agent.agentId]
                        );
                      }}
                      className={`w-full text-left p-2 rounded-md text-xs flex items-center gap-2 transition-colors ${
                        selectedAgents.includes(agent.agentId)
                          ? "bg-purple-500/20 border border-purple-500/30"
                          : "hover:bg-muted/30"
                      }`}
                    >
                      <div className={`w-2 h-2 rounded-full ${selectedAgents.includes(agent.agentId) ? "bg-purple-400" : "bg-zinc-600"}`} />
                      <span className="font-mono">{agent.name || agent.agentId.slice(0, 12)}</span>
                      <Badge variant="outline" className="text-[9px] ml-auto">{agent.profile}</Badge>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button
              onClick={() => {
                if (!swarmName || selectedAgents.length < 2) {
                  toast.error("Need a name and at least 2 agents");
                  return;
                }
                createSwarm.mutate({
                  name: swarmName,
                  objective,
                  agentIds: selectedAgents,
                });
              }}
              disabled={createSwarm.isPending}
              className="bg-purple-600 hover:bg-purple-700 text-white"
            >
              Create Swarm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
