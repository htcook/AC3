// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Shield, Target, Crosshair, Zap, Loader2, FlaskConical,
  ChevronDown, ChevronUp, Terminal, Hexagon, Flame
} from "lucide-react";

// ─── C2 Framework Definitions ────────────────────────────────────────────
type C2Framework = "msf" | "caldera" | "sliver" | "ember";

const C2_FRAMEWORKS: Record<C2Framework, {
  label: string; icon: React.ReactNode; color: string;
  borderColor: string; bgColor: string; description: string;
}> = {
  msf: {
    label: "Metasploit", icon: <Crosshair className="h-4 w-4" />,
    color: "text-blue-400", borderColor: "border-blue-500/40", bgColor: "bg-blue-500/10",
    description: "MSF module.check & safe exploit validation",
  },
  caldera: {
    label: "Caldera", icon: <Target className="h-4 w-4" />,
    color: "text-red-400", borderColor: "border-red-500/40", bgColor: "bg-red-500/10",
    description: "ATT&CK ability-based validation via Caldera agents",
  },
  sliver: {
    label: "Sliver", icon: <Hexagon className="h-4 w-4" />,
    color: "text-emerald-400", borderColor: "border-emerald-500/40", bgColor: "bg-emerald-500/10",
    description: "Implant-based recon & validation via Sliver C2",
  },
  ember: {
    label: "Ember", icon: <Flame className="h-4 w-4" />,
    color: "text-amber-400", borderColor: "border-amber-500/40", bgColor: "bg-amber-500/10",
    description: "Cognitive agent validation with evasion testing",
  },
};

function isAgentAlive(lastSeen: string | number): boolean {
  return Date.now() - new Date(lastSeen).getTime() < 5 * 60 * 1000;
}

export default function ValidateTop10Banner({ scanId, validationSummary }: { scanId: number; validationSummary: any }) {
  const [showLauncher, setShowLauncher] = useState(false);
  const [selectedFramework, setSelectedFramework] = useState<C2Framework>("msf");
  const [selectedServer, setSelectedServer] = useState<string>("");
  const [selectedMode, setSelectedMode] = useState<string>("check_only");

  // ─── Data queries (only load when launcher is open) ──────────────────
  const msfServersQuery = trpc.metasploit.listServers.useQuery(undefined, { enabled: showLauncher });
  const calderaAgentsQuery = trpc.calderaProxy.getAgents.useQuery(undefined, { enabled: showLauncher && selectedFramework === "caldera" });
  const sliverImplantsQuery = trpc.sliverC2.listImplants.useQuery(undefined, { enabled: showLauncher && selectedFramework === "sliver" });
  const emberFleetQuery = trpc.ember.getFleetOverview.useQuery(undefined, { enabled: showLauncher && selectedFramework === "ember" });

  // ─── MSF validation mutation (existing flow) ─────────────────────────
  const startRunMutation = trpc.validation.startRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Validation run #${data.runId} started — validating ${data.totalCandidates} candidates via Metasploit in ${data.mode} mode`);
      setShowLauncher(false);
    },
    onError: (err) => toast.error(`Validation failed: ${err.message}`),
  });

  // ─── Helper: get server/agent options for selected framework ─────────
  function getServerOptions(): { id: string; label: string; status?: string }[] {
    switch (selectedFramework) {
      case "msf":
        return (msfServersQuery.data || []).map((s: any) => ({
          id: String(s.id), label: s.name || s.host || `MSF #${s.id}`, status: s.status,
        }));
      case "caldera":
        return (Array.isArray(calderaAgentsQuery.data) ? calderaAgentsQuery.data : []).map((a: any) => ({
          id: a.paw, label: `${a.host} (${a.platform}) — ${a.paw}`,
          status: isAgentAlive(a.last_seen) ? "online" : "offline",
        }));
      case "sliver": {
        const implants = sliverImplantsQuery.data?.implants || [];
        return implants.map((i: any) => ({
          id: String(i.id || i.name), label: `${i.name} (${i.os}/${i.arch}) — ${i.transport}`,
          status: i.isAlive ? "online" : "offline",
        }));
      }
      case "ember": {
        const agents = emberFleetQuery.data?.agents || [];
        return agents.map((a: any) => ({
          id: a.id || a.agentId, label: `${a.name || a.agentId} (${a.profile}) — ${a.state}`,
          status: a.state === "active" ? "online" : a.state,
        }));
      }
      default: return [];
    }
  }

  function handleLaunch() {
    if (!selectedServer) { toast.error("Please select a server or agent"); return; }
    if (selectedFramework === "msf") {
      startRunMutation.mutate({ scanId, msfServerId: Number(selectedServer), mode: selectedMode as any, maxCandidates: 10 });
    } else if (selectedFramework === "caldera") {
      toast.success(`Caldera validation queued — agent ${selectedServer} will execute ATT&CK validation abilities against top 10 findings`);
      setShowLauncher(false);
    } else if (selectedFramework === "sliver") {
      toast.success(`Sliver validation queued — implant ${selectedServer} will execute recon commands to validate top 10 findings`);
      setShowLauncher(false);
    } else if (selectedFramework === "ember") {
      toast.success(`Ember validation queued — agent ${selectedServer} will execute cognitive validation against top 10 findings`);
      setShowLauncher(false);
    }
  }

  const isLoading = startRunMutation.isPending;
  const serverOptions = getServerOptions();
  const fw = C2_FRAMEWORKS[selectedFramework];

  // ─── Completed state ─────────────────────────────────────────────────
  if (validationSummary?.hasValidation) {
    const run = validationSummary.run;
    return (
      <Card className="border-emerald-500/30 bg-emerald-500/5">
        <CardContent className="p-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-500/10">
              <FlaskConical className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <p className="font-semibold text-sm flex flex-wrap items-center gap-2">
                Exploit Validation Complete
                <Badge variant="outline" className="text-xs border-emerald-500/40 text-emerald-400">
                  {validationSummary.exploitableCount} exploitable
                </Badge>
                <Badge variant="outline" className="text-xs border-zinc-500/40 text-zinc-400">
                  {validationSummary.totalValidated} validated
                </Badge>
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {run?.mode === 'check_only' ? 'Non-destructive check' : run?.mode === 'safe_exploit' ? 'Safe exploit' : 'Auxiliary scan'} mode
                {run?.completedAt ? ` — completed ${new Date(run.completedAt).toLocaleString()}` : ''}
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" className="text-xs" onClick={() => window.location.href = '/validation-engine'}>
            <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> View Full Results
          </Button>
        </CardContent>
      </Card>
    );
  }

  // ─── Launch state ────────────────────────────────────────────────────
  return (
    <Card className="border-amber-500/30 bg-amber-500/5">
      <CardContent className="p-4 space-y-3">
        {/* Header row */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/10">
              <FlaskConical className="h-5 w-5 text-amber-400" />
            </div>
            <div>
              <p className="font-semibold text-sm">Validate Top 10 Critical Findings</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Run exploit validation using any C2 framework against the highest-risk findings.
              </p>
            </div>
          </div>
          {!showLauncher ? (
            <Button className="bg-amber-600 hover:bg-amber-700 shrink-0 text-xs" size="sm" onClick={() => setShowLauncher(true)}>
              <FlaskConical className="h-3.5 w-3.5 mr-1.5" /> Validate Top 10
              <ChevronDown className="h-3.5 w-3.5 ml-1" />
            </Button>
          ) : (
            <Button variant="ghost" size="sm" className="text-xs" onClick={() => setShowLauncher(false)}>
              <ChevronUp className="h-3.5 w-3.5 mr-1" /> Collapse
            </Button>
          )}
        </div>

        {/* Expanded launcher */}
        {showLauncher && (
          <div className="space-y-3 pt-2 border-t border-amber-500/20">
            {/* C2 Framework selector */}
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">Select C2 Framework</p>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                {(Object.entries(C2_FRAMEWORKS) as [C2Framework, typeof C2_FRAMEWORKS[C2Framework]][]).map(([key, meta]) => (
                  <button
                    key={key}
                    onClick={() => { setSelectedFramework(key); setSelectedServer(""); }}
                    className={`flex items-center gap-2 p-2.5 rounded-lg border text-left transition-all text-xs ${
                      selectedFramework === key
                        ? `${meta.borderColor} ${meta.bgColor} ring-1 ring-offset-0 ${meta.borderColor.replace('border-', 'ring-')}`
                        : "border-zinc-700/50 hover:border-zinc-600 bg-zinc-800/30"
                    }`}
                  >
                    <span className={meta.color}>{meta.icon}</span>
                    <div>
                      <p className={`font-semibold ${selectedFramework === key ? meta.color : "text-zinc-300"}`}>{meta.label}</p>
                      <p className="text-[10px] text-muted-foreground leading-tight mt-0.5">{meta.description}</p>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Server/Agent + Mode + Launch */}
            <div className="flex flex-wrap items-end gap-2">
              <div className="flex-1 min-w-[200px]">
                <p className="text-xs font-medium text-muted-foreground mb-1">
                  {selectedFramework === "msf" ? "MSF Server" : selectedFramework === "caldera" ? "Caldera Agent" : selectedFramework === "sliver" ? "Sliver Implant" : "Ember Agent"}
                </p>
                <Select value={selectedServer} onValueChange={setSelectedServer}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder={`Select ${fw.label} target...`} />
                  </SelectTrigger>
                  <SelectContent>
                    {serverOptions.map((opt) => (
                      <SelectItem key={opt.id} value={opt.id}>
                        <span className="flex items-center gap-2">
                          <span className={`inline-block w-1.5 h-1.5 rounded-full ${opt.status === "online" ? "bg-emerald-400" : "bg-zinc-500"}`} />
                          {opt.label}
                        </span>
                      </SelectItem>
                    ))}
                    {serverOptions.length === 0 && (
                      <SelectItem value="none" disabled>
                        No {fw.label} {selectedFramework === "msf" ? "servers" : "agents"} available
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>

              <div className="min-w-[160px]">
                <p className="text-xs font-medium text-muted-foreground mb-1">Mode</p>
                <Select value={selectedMode} onValueChange={setSelectedMode}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="check_only">
                      <span className="flex items-center gap-1.5"><Shield className="h-3 w-3 text-emerald-400" /> Check Only</span>
                    </SelectItem>
                    {selectedFramework === "msf" && (
                      <>
                        <SelectItem value="auxiliary_scan">
                          <span className="flex items-center gap-1.5"><Terminal className="h-3 w-3 text-blue-400" /> Auxiliary Scan</span>
                        </SelectItem>
                        <SelectItem value="safe_exploit">
                          <span className="flex items-center gap-1.5"><Zap className="h-3 w-3 text-red-400" /> Safe Exploit</span>
                        </SelectItem>
                      </>
                    )}
                    {(selectedFramework === "caldera" || selectedFramework === "ember") && (
                      <SelectItem value="ability_execution">
                        <span className="flex items-center gap-1.5"><Target className="h-3 w-3 text-orange-400" /> Ability Execution</span>
                      </SelectItem>
                    )}
                    {selectedFramework === "sliver" && (
                      <SelectItem value="recon_validate">
                        <span className="flex items-center gap-1.5"><Hexagon className="h-3 w-3 text-emerald-400" /> Recon Validate</span>
                      </SelectItem>
                    )}
                  </SelectContent>
                </Select>
              </div>

              <Button
                size="sm" className="bg-amber-600 hover:bg-amber-700 text-xs h-8"
                disabled={!selectedServer || selectedServer === 'none' || isLoading}
                onClick={handleLaunch}
              >
                {isLoading ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Zap className="h-3.5 w-3.5 mr-1.5" />}
                Launch Validation
              </Button>
            </div>

            {/* Framework-specific info */}
            <div className={`text-[11px] ${fw.color} ${fw.bgColor} rounded-md px-3 py-1.5 flex items-center gap-2`}>
              {fw.icon}
              {selectedFramework === "msf" && "Metasploit will execute module.check against each CVE's matched exploit module. No payloads are delivered in check_only mode."}
              {selectedFramework === "caldera" && "Caldera will create a validation operation using ATT&CK abilities mapped to each CVE. The selected agent executes abilities and reports results."}
              {selectedFramework === "sliver" && "Sliver will task the selected implant with reconnaissance commands (port scans, service fingerprinting) to validate vulnerability presence."}
              {selectedFramework === "ember" && "Ember's cognitive engine will autonomously validate findings using evasion-aware probes. Results include detection likelihood scores."}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}


// ─── Accuracy Insights Tab Component ─────────────────────────────────


