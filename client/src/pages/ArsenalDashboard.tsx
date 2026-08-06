import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import {
  Shield, AlertTriangle, Zap, Target, Activity, Cpu, Radio,
  Search, ChevronRight, Clock, Globe, Lock, Skull, Factory,
  BarChart3, Bell, RefreshCw, Eye, Server, Crosshair, CheckCircle2, XCircle,
  Network, Key, Hash, Ticket, FileKey,
} from "lucide-react";

// ─── Priority Queue Tab ──────────────────────────────────────────────────────

function PriorityQueueTab() {
  const queueQuery = trpc.exploitArsenal.getPriorityQueue.useQuery(
    { limit: 25, minPriority: 0 },
    { retry: false, refetchOnWindowFocus: false }
  );
  const statsQuery = trpc.exploitArsenal.getPriorityQueueStats.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );

  const stats = statsQuery.data;
  const queue = queueQuery.data;

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Queued Exploits" value={stats?.totalQueued || 0} icon={<Crosshair className="w-4 h-4" />} color="text-red-400" />
        <StatCard label="Critical Priority" value={stats?.bySeverity?.critical || 0} icon={<AlertTriangle className="w-4 h-4" />} color="text-red-500" />
        <StatCard label="Actor-Linked" value={stats?.actorLinked || 0} icon={<Skull className="w-4 h-4" />} color="text-purple-400" />
        <StatCard label="Auto-Bumped" value={stats?.autoBumped || 0} icon={<Zap className="w-4 h-4" />} color="text-amber-400" />
      </div>

      {/* Queue Table */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" />
            Threat-Actor Prioritized Exploit Queue
          </CardTitle>
        </CardHeader>
        <CardContent>
          {queueQuery.isLoading ? (
            <div className="text-center py-8 text-zinc-500">Loading priority queue...</div>
          ) : !queue?.items?.length ? (
            <div className="text-center py-8 text-zinc-500">
              <Crosshair className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No items in priority queue</p>
              <p className="text-xs mt-1">CVEs linked to active threat actors will auto-populate here</p>
            </div>
          ) : (
            <div className="space-y-2">
              {queue.items.map((item: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-zinc-800/50 rounded border border-zinc-700/50 hover:border-zinc-600 transition-colors">
                  <div className={`w-2 h-8 rounded-full ${
                    item.priority >= 90 ? "bg-red-500" :
                    item.priority >= 70 ? "bg-orange-500" :
                    item.priority >= 50 ? "bg-yellow-500" : "bg-blue-500"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-zinc-200">{item.cveId}</span>
                      <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400">
                        P{item.priority}
                      </Badge>
                      {item.threatActors?.map((actor: string) => (
                        <Badge key={actor} variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                          {actor}
                        </Badge>
                      ))}
                    </div>
                    <p className="text-xs text-zinc-500 truncate mt-0.5">{item.reason || "Auto-prioritized based on threat actor activity"}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-zinc-500">{item.sector || "multi-sector"}</div>
                    <div className="text-[10px] text-zinc-600">{item.addedAt ? new Date(item.addedAt).toLocaleDateString() : ""}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── PLC Integrity Tab ───────────────────────────────────────────────────────

function PlcIntegrityTab() {
  const statusQuery = trpc.icsOtSecurity.plcMonitoringStatus.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const alertsQuery = trpc.icsOtSecurity.plcGetAlerts.useQuery(
    { limit: 20 },
    { retry: false, refetchOnWindowFocus: false }
  );
  const devicesQuery = trpc.icsOtSecurity.plcGetDevices.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const vulnQuery = trpc.icsOtSecurity.plcVulnerabilityAssessment.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );

  const status = statusQuery.data;
  const alerts = alertsQuery.data || [];
  const devices = devicesQuery.data || [];
  const vuln = vulnQuery.data;

  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard label="Monitored PLCs" value={status?.totalDevices || 0} icon={<Cpu className="w-4 h-4" />} color="text-blue-400" />
        <StatCard label="Healthy" value={status?.healthy || 0} icon={<Shield className="w-4 h-4" />} color="text-green-400" />
        <StatCard label="Degraded" value={status?.degraded || 0} icon={<AlertTriangle className="w-4 h-4" />} color="text-yellow-400" />
        <StatCard label="Compromised" value={status?.compromised || 0} icon={<Skull className="w-4 h-4" />} color="text-red-500" />
        <StatCard label="Active Alerts" value={status?.activeAlerts || 0} icon={<Bell className="w-4 h-4" />} color="text-orange-400" />
      </div>

      {/* Vulnerability Assessment */}
      {vuln && (
        <Card className="bg-zinc-900/80 border-zinc-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
              <Shield className="w-4 h-4 text-amber-400" />
              Fleet Vulnerability Assessment
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400">{vuln.internetExposed || 0}</div>
                <div className="text-xs text-zinc-500">Internet Exposed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-400">{vuln.defaultCredentials || 0}</div>
                <div className="text-xs text-zinc-500">Default Credentials</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-400">{vuln.outdatedFirmware || 0}</div>
                <div className="text-xs text-zinc-500">Outdated Firmware</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-400">{vuln.noBaseline || 0}</div>
                <div className="text-xs text-zinc-500">No Baseline</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Alerts */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            PLC Integrity Alerts
          </CardTitle>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="text-center py-6 text-zinc-500">
              <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No active integrity alerts</p>
              <p className="text-xs mt-1">Alerts trigger when PLC configuration deviates from baseline</p>
            </div>
          ) : (
            <div className="space-y-2 max-h-[300px] overflow-y-auto">
              {alerts.map((alert: any, i: number) => (
                <div key={i} className={`flex items-start gap-3 p-3 rounded border ${
                  alert.severity === "critical" ? "bg-red-950/30 border-red-800/50" :
                  alert.severity === "high" ? "bg-orange-950/30 border-orange-800/50" :
                  "bg-zinc-800/50 border-zinc-700/50"
                }`}>
                  <AlertTriangle className={`w-4 h-4 mt-0.5 ${
                    alert.severity === "critical" ? "text-red-400" :
                    alert.severity === "high" ? "text-orange-400" :
                    "text-yellow-400"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-zinc-200">{alert.alertType?.replace(/_/g, " ").toUpperCase()}</span>
                      <Badge variant="outline" className={`text-[10px] ${
                        alert.severity === "critical" ? "border-red-500/30 text-red-400" :
                        alert.severity === "high" ? "border-orange-500/30 text-orange-400" :
                        "border-yellow-500/30 text-yellow-400"
                      }`}>
                        {alert.severity}
                      </Badge>
                    </div>
                    <p className="text-xs text-zinc-500 mt-0.5">{alert.description}</p>
                    <p className="text-[10px] text-zinc-600 mt-0.5">Device: {alert.deviceId} | {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ""}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Device Fleet */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            Monitored PLC Fleet
          </CardTitle>
        </CardHeader>
        <CardContent>
          {devices.length === 0 ? (
            <div className="text-center py-6 text-zinc-500">
              <Cpu className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No PLCs registered for monitoring</p>
              <p className="text-xs mt-1">Initialize monitoring via ICS/OT Security page</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {devices.slice(0, 10).map((device: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-2 bg-zinc-800/50 rounded border border-zinc-700/30">
                  <div className={`w-2 h-2 rounded-full ${
                    device.status === "healthy" ? "bg-green-500" :
                    device.status === "degraded" ? "bg-yellow-500" :
                    device.status === "compromised" ? "bg-red-500" : "bg-zinc-500"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-zinc-300 truncate">{device.name}</div>
                    <div className="text-[10px] text-zinc-500">{device.vendor} {device.model} | {device.ipAddress}</div>
                  </div>
                  <Badge variant="outline" className="text-[10px]">{device.facilityType?.replace(/_/g, " ")}</Badge>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Utility Playbooks Tab ───────────────────────────────────────────────────

function UtilityPlaybooksTab() {
  const [searchQuery, setSearchQuery] = useState("");
  const [sectorFilter, setSectorFilter] = useState("all");

  const playbooksQuery = trpc.utilityPlaybooks.list.useQuery(
    sectorFilter !== "all" ? { sector: sectorFilter } : undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const summaryQuery = trpc.utilityPlaybooks.summary.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );

  const playbooks = playbooksQuery.data || [];
  const summary = summaryQuery.data;

  const filtered = useMemo(() => {
    if (!searchQuery) return playbooks;
    const q = searchQuery.toLowerCase();
    return playbooks.filter((p: any) =>
      p.name.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      p.threatActors?.some((a: string) => a.toLowerCase().includes(q))
    );
  }, [playbooks, searchQuery]);

  const DIFFICULTY_COLORS: Record<string, string> = {
    basic: "bg-green-500/20 text-green-400 border-green-500/30",
    intermediate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    advanced: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    nation_state: "bg-red-500/20 text-red-400 border-red-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Playbooks" value={summary?.total || 0} icon={<Target className="w-4 h-4" />} color="text-blue-400" />
        <StatCard label="Water/Wastewater" value={(summary?.bySector?.water_treatment || 0) + (summary?.bySector?.water_distribution || 0) + (summary?.bySector?.wastewater || 0)} icon={<Factory className="w-4 h-4" />} color="text-cyan-400" />
        <StatCard label="Electric Power" value={(summary?.bySector?.electric_generation || 0) + (summary?.bySector?.electric_transmission || 0) + (summary?.bySector?.electric_distribution || 0)} icon={<Zap className="w-4 h-4" />} color="text-amber-400" />
        <StatCard label="CISA Advisories" value={summary?.cisaAdvisories?.length || 0} icon={<Shield className="w-4 h-4" />} color="text-red-400" />
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
          <Input
            placeholder="Search playbooks, threat actors, equipment..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-9 bg-zinc-900 border-zinc-700"
          />
        </div>
        <select
          value={sectorFilter}
          onChange={e => setSectorFilter(e.target.value)}
          className="bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-300"
        >
          <option value="all">All Sectors</option>
          <option value="water_treatment">Water Treatment</option>
          <option value="water_distribution">Water Distribution</option>
          <option value="wastewater">Wastewater</option>
          <option value="electric_generation">Electric Generation</option>
          <option value="electric_transmission">Electric Transmission</option>
          <option value="electric_distribution">Electric Distribution</option>
        </select>
      </div>

      {/* Playbook Cards */}
      <div className="space-y-3">
        {filtered.map((playbook: any) => (
          <PlaybookCard key={playbook.id} playbook={playbook} difficultyColors={DIFFICULTY_COLORS} />
        ))}
        {filtered.length === 0 && (
          <div className="text-center py-8 text-zinc-500">
            <Target className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>No playbooks match your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}

function PlaybookCard({ playbook, difficultyColors }: { playbook: any; difficultyColors: Record<string, string> }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card className="bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start gap-3 cursor-pointer" onClick={() => setExpanded(!expanded)}>
          <div className="mt-1">
            <ChevronRight className={`w-4 h-4 text-zinc-500 transition-transform ${expanded ? "rotate-90" : ""}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-zinc-200">{playbook.id}</span>
              <span className="text-sm text-zinc-300">{playbook.name}</span>
              <Badge variant="outline" className={`text-[10px] ${difficultyColors[playbook.difficulty] || ""}`}>
                {playbook.difficulty?.replace(/_/g, " ")}
              </Badge>
            </div>
            <p className="text-xs text-zinc-500 mt-1 line-clamp-2">{playbook.description}</p>
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              {playbook.threatActors?.slice(0, 2).map((actor: string) => (
                <Badge key={actor} variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                  <Skull className="w-3 h-3 mr-1" />{actor}
                </Badge>
              ))}
              {playbook.cisaAdvisories?.map((adv: string) => (
                <Badge key={adv} variant="outline" className="text-[10px] border-red-500/30 text-red-400">
                  {adv}
                </Badge>
              ))}
              <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                {playbook.phases?.length || 0} phases
              </Badge>
            </div>
          </div>
          <div className="text-right shrink-0">
            <div className="text-xs text-zinc-500">{playbook.estimatedDuration}</div>
            <div className="text-[10px] text-zinc-600 mt-1">{playbook.sector?.replace(/_/g, " ")}</div>
          </div>
        </div>

        {expanded && (
          <div className="mt-4 pt-4 border-t border-zinc-800 space-y-4">
            {/* Real-world precedent */}
            <div>
              <h4 className="text-xs font-medium text-zinc-400 mb-1">REAL-WORLD PRECEDENT</h4>
              <p className="text-xs text-zinc-300">{playbook.realWorldPrecedent}</p>
            </div>

            {/* Targeted Equipment */}
            <div>
              <h4 className="text-xs font-medium text-zinc-400 mb-1">TARGETED EQUIPMENT</h4>
              <div className="flex flex-wrap gap-2">
                {playbook.targetedEquipment?.map((eq: any, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px] border-zinc-600 text-zinc-300">
                    {eq.vendor} {eq.model} ({eq.protocol})
                  </Badge>
                ))}
              </div>
            </div>

            {/* Attack Phases */}
            <div>
              <h4 className="text-xs font-medium text-zinc-400 mb-2">ATTACK PHASES</h4>
              <div className="space-y-2">
                {playbook.phases?.map((phase: any) => (
                  <div key={phase.phase} className="flex items-start gap-2 p-2 bg-zinc-800/50 rounded">
                    <div className="w-5 h-5 rounded-full bg-zinc-700 flex items-center justify-center shrink-0">
                      <span className="text-[10px] text-zinc-300">{phase.phase}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-zinc-200">{phase.name}</span>
                        <Badge variant="outline" className="text-[9px] border-zinc-600 text-zinc-400">
                          {phase.mitreIcsId}
                        </Badge>
                      </div>
                      <p className="text-[10px] text-zinc-500 mt-0.5">{phase.description}</p>
                      <div className="text-[10px] text-zinc-600 mt-0.5">
                        Tactic: {phase.mitreTactic} | Duration: {phase.duration}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Physical Impacts */}
            <div>
              <h4 className="text-xs font-medium text-zinc-400 mb-1">PHYSICAL IMPACTS</h4>
              <p className="text-xs text-zinc-300">{playbook.impactDescription}</p>
              <div className="flex flex-wrap gap-1 mt-1">
                {playbook.physicalImpacts?.map((impact: string) => (
                  <Badge key={impact} variant="outline" className="text-[10px] border-red-500/30 text-red-400">
                    {impact.replace(/_/g, " ")}
                  </Badge>
                ))}
              </div>
            </div>

            {/* Mitigations */}
            <div>
              <h4 className="text-xs font-medium text-zinc-400 mb-1">MITIGATIONS</h4>
              <ul className="space-y-1">
                {playbook.mitigations?.map((m: string, i: number) => (
                  <li key={i} className="text-[10px] text-zinc-400 flex items-start gap-1">
                    <span className="text-green-500 mt-0.5">•</span> {m}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Advisory Correlation Tab ────────────────────────────────────────────────

function AdvisoryCorrelationTab() {
  const advisoriesQuery = trpc.advisoryCorrelation.list.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const statsQuery = trpc.advisoryCorrelation.stats.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const correlationQuery = trpc.advisoryCorrelation.correlateAll.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );

  const advisories = advisoriesQuery.data || [];
  const stats = statsQuery.data;
  const correlation = correlationQuery.data;

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Advisories" value={stats?.total || 0} icon={<Shield className="w-4 h-4" />} color="text-blue-400" />
        <StatCard label="Critical" value={stats?.bySeverity?.critical || 0} icon={<AlertTriangle className="w-4 h-4" />} color="text-red-400" />
        <StatCard label="Correlations Found" value={correlation?.totalCorrelations || 0} icon={<Activity className="w-4 h-4" />} color="text-amber-400" />
        <StatCard label="Immediate Action" value={correlation?.byUrgency?.immediate || 0} icon={<Zap className="w-4 h-4" />} color="text-red-500" />
      </div>

      {/* Correlations */}
      {correlation && correlation.results.length > 0 && (
        <Card className="bg-zinc-900/80 border-zinc-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              Auto-Correlated Matches ({correlation.totalCorrelations})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[300px] overflow-y-auto">
              {correlation.results.slice(0, 15).map((result: any, i: number) => (
                <div key={i} className={`p-3 rounded border ${
                  result.urgency === "immediate" ? "bg-red-950/20 border-red-800/50" :
                  result.urgency === "24h" ? "bg-orange-950/20 border-orange-800/50" :
                  "bg-zinc-800/50 border-zinc-700/50"
                }`}>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[10px] ${
                      result.urgency === "immediate" ? "border-red-500/30 text-red-400" :
                      result.urgency === "24h" ? "border-orange-500/30 text-orange-400" :
                      "border-zinc-600 text-zinc-400"
                    }`}>
                      {result.urgency}
                    </Badge>
                    <span className="text-xs text-zinc-300">{result.advisoryId}</span>
                    <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                      {result.correlationType?.replace(/_/g, " ")}
                    </Badge>
                    <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                      {result.confidence} confidence
                    </Badge>
                  </div>
                  <p className="text-xs text-zinc-400 mt-1">{result.impactAssessment}</p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {result.relatedPlaybooks?.map((pb: string) => (
                      <Badge key={pb} variant="outline" className="text-[9px] border-blue-500/30 text-blue-400">
                        Playbook: {pb}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Advisory List */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            DHS/FBI/CISA Advisory Database
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {advisories.map((advisory: any) => (
              <div key={advisory.id} className="p-3 bg-zinc-800/50 rounded border border-zinc-700/50 hover:border-zinc-600 transition-colors">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[10px] ${
                    advisory.severity === "critical" ? "border-red-500/30 text-red-400" :
                    advisory.severity === "high" ? "border-orange-500/30 text-orange-400" :
                    "border-yellow-500/30 text-yellow-400"
                  }`}>
                    {advisory.severity}
                  </Badge>
                  <span className="text-xs font-mono text-zinc-400">{advisory.id}</span>
                  <div className="flex gap-1">
                    {advisory.source?.map((s: string) => (
                      <Badge key={s} variant="outline" className="text-[9px] border-zinc-600 text-zinc-500">
                        {s.toUpperCase()}
                      </Badge>
                    ))}
                  </div>
                </div>
                <p className="text-sm text-zinc-200 mt-1">{advisory.title}</p>
                <p className="text-xs text-zinc-500 mt-1 line-clamp-2">{advisory.summary}</p>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  {advisory.threatActors?.slice(0, 3).map((actor: string) => (
                    <Badge key={actor} variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                      {actor}
                    </Badge>
                  ))}
                  {advisory.targetedSectors?.slice(0, 3).map((sector: string) => (
                    <Badge key={sector} variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400">
                      {sector}
                    </Badge>
                  ))}
                  <span className="text-[10px] text-zinc-600 ml-auto">
                    Updated: {advisory.lastUpdated ? new Date(advisory.lastUpdated).toLocaleDateString() : ""}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Shared Components ───────────────────────────────────────────────────────

function StatCard({ label, value, icon, color }: { label: string; value: number | string; icon: React.ReactNode; color: string }) {
  return (
    <Card className="bg-zinc-900/80 border-zinc-800">
      <CardContent className="p-3">
        <div className="flex items-center justify-between">
          <span className={`${color}`}>{icon}</span>
          <span className={`text-xl font-bold ${color}`}>{value}</span>
        </div>
        <p className="text-[10px] text-zinc-500 mt-1">{label}</p>
      </CardContent>
    </Card>
  );
}

// ─── Validation Feedback Tab ─────────────────────────────────────────────────

function ValidationFeedbackTab() {
  const statsQuery = trpc.offensiveOps.getArsenalValidationStats.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const revalidationQuery = trpc.offensiveOps.getExploitsNeedingRevalidation.useQuery(
    { staleDays: 30 },
    { retry: false, refetchOnWindowFocus: false }
  );
  const stats = statsQuery.data;
  const revalidation = revalidationQuery.data;

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Confirmed Working" value={stats?.confirmedWorking || 0} icon={<CheckCircle2 className="w-4 h-4" />} color="text-green-400" />
        <StatCard label="Failed" value={stats?.failed || 0} icon={<XCircle className="w-4 h-4" />} color="text-red-400" />
        <StatCard label="Partial Success" value={stats?.partialSuccess || 0} icon={<Activity className="w-4 h-4" />} color="text-amber-400" />
        <StatCard label="Avg Success Rate" value={`${stats?.averageSuccessRate || 0}%`} icon={<BarChart3 className="w-4 h-4" />} color="text-blue-400" />
        <StatCard label="Total Runs" value={stats?.totalValidationRuns || 0} icon={<RefreshCw className="w-4 h-4" />} color="text-purple-400" />
      </div>

      {/* Recent Validations */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Activity className="w-4 h-4 text-green-400" />
            Recent Validation Results → Arsenal Feedback
          </CardTitle>
        </CardHeader>
        <CardContent>
          {statsQuery.isLoading ? (
            <div className="text-center py-8 text-zinc-500">Loading validation feedback...</div>
          ) : !stats?.recentValidations?.length ? (
            <div className="text-center py-8 text-zinc-500">
              <CheckCircle2 className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No validation results yet</p>
              <p className="text-xs mt-1">Run exploit validations from Offensive Ops to populate feedback data</p>
            </div>
          ) : (
            <div className="space-y-2">
              {stats.recentValidations.map((v: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-3 bg-zinc-800/50 rounded border border-zinc-700/50">
                  <div className={`w-2 h-8 rounded-full ${
                    v.result === "confirmed" ? "bg-green-500" :
                    v.result === "partial" ? "bg-amber-500" :
                    v.result === "failed" ? "bg-red-500" : "bg-zinc-500"
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-zinc-200">Exploit #{v.exploitScriptId}</span>
                      <Badge variant="outline" className={`text-[10px] ${
                        v.result === "confirmed" ? "border-green-500/30 text-green-400" :
                        v.result === "partial" ? "border-amber-500/30 text-amber-400" :
                        "border-red-500/30 text-red-400"
                      }`}>
                        {v.result?.toUpperCase()}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                        {v.techType?.replace("_", " ")}
                      </Badge>
                    </div>
                    <p className="text-xs text-zinc-500 truncate mt-0.5">
                      Target: {v.targetHost} | Confidence: {v.confidenceScore}% | Evidence: {v.evidenceCount} items
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-zinc-500">{v.validatedAt ? new Date(v.validatedAt).toLocaleDateString() : ""}</div>
                    <div className="text-[10px] text-zinc-600">{v.validatedBy}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Exploits Needing Revalidation */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400" />
            Exploits Needing Revalidation
          </CardTitle>
        </CardHeader>
        <CardContent>
          {revalidationQuery.isLoading ? (
            <div className="text-center py-6 text-zinc-500">Loading...</div>
          ) : !revalidation?.length ? (
            <div className="text-center py-6 text-zinc-500">
              <CheckCircle2 className="w-6 h-6 mx-auto mb-2 opacity-30" />
              <p className="text-xs">All validated exploits are current</p>
            </div>
          ) : (
            <div className="space-y-2">
              {revalidation.slice(0, 10).map((item: any, i: number) => (
                <div key={i} className="flex items-center gap-3 p-2 bg-zinc-800/30 rounded border border-zinc-700/30">
                  <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs text-zinc-300">Exploit #{item.exploitScriptId}</span>
                    <p className="text-[10px] text-zinc-500 truncate">{item.reason}</p>
                  </div>
                  <Badge variant="outline" className={`text-[10px] ${
                    item.currentStatus === "confirmed_working" ? "border-green-500/30 text-green-400" :
                    item.currentStatus === "failed" ? "border-red-500/30 text-red-400" :
                    "border-zinc-600 text-zinc-400"
                  }`}>
                    {item.currentStatus?.replace("_", " ")}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── atexec Lateral Movement Tab ─────────────────────────────────────────────

function AtexecLateralTab() {
  const playbookQuery = trpc.offensiveOps.getAtexecPlaybook.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const validationQuery = trpc.offensiveOps.getAtexecValidationChecks.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );
  const detectionQuery = trpc.offensiveOps.getAtexecDetectionRules.useQuery(
    undefined,
    { retry: false, refetchOnWindowFocus: false }
  );

  const playbook = playbookQuery.data;
  const validation = validationQuery.data;
  const detection = detectionQuery.data;
  const [expandedMethod, setExpandedMethod] = useState<string | null>(null);

  const AUTH_METHOD_ICONS: Record<string, React.ReactNode> = {
    plaintext: <Key className="w-4 h-4 text-green-400" />,
    pass_the_hash: <Hash className="w-4 h-4 text-orange-400" />,
    pass_the_ticket: <Ticket className="w-4 h-4 text-purple-400" />,
    pass_the_key: <FileKey className="w-4 h-4 text-cyan-400" />,
  };

  const AUTH_METHOD_COLORS: Record<string, string> = {
    plaintext: "border-green-500/30 text-green-400",
    pass_the_hash: "border-orange-500/30 text-orange-400",
    pass_the_ticket: "border-purple-500/30 text-purple-400",
    pass_the_key: "border-cyan-500/30 text-cyan-400",
  };

  return (
    <div className="space-y-6">
      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Auth Variants" value={playbook?.totalVariants || 0} icon={<Key className="w-4 h-4" />} color="text-green-400" />
        <StatCard label="Exploit Docs" value={playbook?.exploitDocuments?.length || 0} icon={<Target className="w-4 h-4" />} color="text-red-400" />
        <StatCard label="Validation Checks" value={validation?.totalChecks || 0} icon={<CheckCircle2 className="w-4 h-4" />} color="text-blue-400" />
        <StatCard label="Detection Rules" value={detection?.totalRules || 0} icon={<Shield className="w-4 h-4" />} color="text-amber-400" />
        <StatCard label="MITRE Technique" value="T1053.005" icon={<Network className="w-4 h-4" />} color="text-purple-400" />
      </div>

      {/* Auth Method Variants */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Impacket atexec — Authentication Method Variants
            <Badge variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400 ml-2">
              T1053.005 | Lateral Movement
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {playbookQuery.isLoading ? (
            <div className="text-center py-8 text-zinc-500">Loading atexec playbook...</div>
          ) : !playbook?.authMethods?.length ? (
            <div className="text-center py-8 text-zinc-500">
              <Network className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No atexec playbook entries loaded</p>
            </div>
          ) : (
            <div className="space-y-3">
              {playbook.authMethods.map((method: any) => (
                <div key={method.id} className="bg-zinc-800/50 rounded border border-zinc-700/50 hover:border-zinc-600 transition-colors">
                  <div
                    className="flex items-center gap-3 p-3 cursor-pointer"
                    onClick={() => setExpandedMethod(expandedMethod === method.id ? null : method.id)}
                  >
                    <div className="mt-0.5">
                      {AUTH_METHOD_ICONS[method.authMethod] || <Key className="w-4 h-4 text-zinc-400" />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium text-zinc-200">{method.name}</span>
                        <Badge variant="outline" className={`text-[10px] ${AUTH_METHOD_COLORS[method.authMethod] || "border-zinc-600 text-zinc-400"}`}>
                          {method.authMethod.replace(/_/g, " ").toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                          {method.iocCount} IOCs
                        </Badge>
                        {method.detectionRules > 0 && (
                          <Badge variant="outline" className="text-[10px] border-amber-500/30 text-amber-400">
                            {method.detectionRules} detection rules
                          </Badge>
                        )}
                      </div>
                      <p className="text-xs text-zinc-500 truncate mt-0.5">{method.description}</p>
                    </div>
                    <ChevronRight className={`w-4 h-4 text-zinc-500 transition-transform ${expandedMethod === method.id ? "rotate-90" : ""}`} />
                  </div>
                  {expandedMethod === method.id && (
                    <div className="px-3 pb-3 pt-1 border-t border-zinc-700/50">
                      <div className="space-y-2">
                        <div>
                          <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Command Template</span>
                          <pre className="text-xs text-cyan-300 bg-zinc-950 p-2 rounded mt-1 overflow-x-auto font-mono">
                            {method.commandTemplate}
                          </pre>
                        </div>
                        {method.prerequisites?.length > 0 && (
                          <div>
                            <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Prerequisites</span>
                            <ul className="mt-1 space-y-0.5">
                              {method.prerequisites.map((prereq: string, i: number) => (
                                <li key={i} className="text-xs text-zinc-400 flex items-center gap-1">
                                  <span className="w-1 h-1 rounded-full bg-zinc-500" />
                                  {prereq}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Validation Checks */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-blue-400" />
            Validation Checks (AD Adapter — Event 4698/4699 Correlation)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {validationQuery.isLoading ? (
            <div className="text-center py-6 text-zinc-500">Loading validation checks...</div>
          ) : !validation?.checks?.length ? (
            <div className="text-center py-6 text-zinc-500">
              <CheckCircle2 className="w-6 h-6 mx-auto mb-2 opacity-30" />
              <p className="text-xs">No validation checks defined</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {validation.checks.map((check: any) => (
                <div key={check.id} className="p-3 bg-zinc-800/50 rounded border border-zinc-700/50">
                  <div className="flex items-center gap-2 mb-1">
                    <CheckCircle2 className="w-3 h-3 text-blue-400" />
                    <span className="text-xs font-medium text-zinc-200">{check.name}</span>
                  </div>
                  <p className="text-[10px] text-zinc-500 mb-2">{check.description}</p>
                  <div className="text-[10px] text-zinc-600">
                    <span className="text-green-400/70">Expected:</span> {check.expectedEvidence}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Detection Rules */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Shield className="w-4 h-4 text-amber-400" />
            Detection Rules (Sigma + Suricata)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {detectionQuery.isLoading ? (
            <div className="text-center py-6 text-zinc-500">Loading detection rules...</div>
          ) : !detection?.rules?.length ? (
            <div className="text-center py-6 text-zinc-500">
              <Shield className="w-6 h-6 mx-auto mb-2 opacity-30" />
              <p className="text-xs">No detection rules loaded</p>
            </div>
          ) : (
            <div className="space-y-3">
              {detection.rules.map((rule: any) => (
                <div key={rule.id} className="p-3 bg-zinc-800/50 rounded border border-zinc-700/50">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant="outline" className={`text-[10px] ${
                      rule.type === "sigma" ? "border-blue-500/30 text-blue-400" :
                      rule.type === "suricata" ? "border-green-500/30 text-green-400" :
                      "border-amber-500/30 text-amber-400"
                    }`}>
                      {rule.type.toUpperCase()}
                    </Badge>
                    <span className="text-xs font-medium text-zinc-200">{rule.name}</span>
                  </div>
                  <p className="text-[10px] text-zinc-500 mb-2">{rule.description}</p>
                  <pre className="text-[10px] text-zinc-400 bg-zinc-950 p-2 rounded overflow-x-auto max-h-[120px] overflow-y-auto font-mono">
                    {rule.content?.substring(0, 500)}{rule.content?.length > 500 ? "\n..." : ""}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Exploit Documents */}
      <Card className="bg-zinc-900/80 border-zinc-800">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" />
            Exploit Knowledge Store — atexec Documents
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!playbook?.exploitDocuments?.length ? (
            <div className="text-center py-6 text-zinc-500">
              <Target className="w-6 h-6 mx-auto mb-2 opacity-30" />
              <p className="text-xs">No exploit documents loaded</p>
            </div>
          ) : (
            <div className="space-y-2">
              {playbook.exploitDocuments.map((doc: any) => (
                <div key={doc.id} className="flex items-center gap-3 p-3 bg-zinc-800/50 rounded border border-zinc-700/50">
                  <div className="w-2 h-8 rounded-full bg-red-500" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono text-zinc-200">{doc.id}</span>
                      <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-400">
                        {doc.mitreAttackId}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                        {doc.platform}
                      </Badge>
                      <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                        {doc.language}
                      </Badge>
                    </div>
                    <p className="text-xs text-zinc-500 truncate mt-0.5">{doc.title}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-green-400">{doc.successRate}% success</div>
                    <div className="text-[10px] text-zinc-600">{doc.timesDeployed}x deployed</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function ArsenalDashboard() {
  const [activeTab, setActiveTab] = useState("priority-queue");

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-zinc-100 flex items-center gap-2">
              <Crosshair className="w-5 h-5 text-red-400" />
              Arsenal Dashboard
            </h1>
            <p className="text-sm text-zinc-500 mt-1">
              Unified operational view: exploit priority queue, PLC integrity, utility playbooks, advisory correlation
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">
              <Activity className="w-3 h-3 mr-1" /> LIVE
            </Badge>
          </div>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="priority-queue" className="text-xs">
              <Target className="w-3 h-3 mr-1" /> Priority Queue
            </TabsTrigger>
            <TabsTrigger value="plc-integrity" className="text-xs">
              <Cpu className="w-3 h-3 mr-1" /> PLC Integrity
            </TabsTrigger>
            <TabsTrigger value="utility-playbooks" className="text-xs">
              <Factory className="w-3 h-3 mr-1" /> Utility Playbooks
            </TabsTrigger>
            <TabsTrigger value="advisory-correlation" className="text-xs">
              <Bell className="w-3 h-3 mr-1" /> Advisory Correlation
            </TabsTrigger>
            <TabsTrigger value="validation-feedback" className="text-xs">
              <CheckCircle2 className="w-3 h-3 mr-1" /> Validation Feedback
            </TabsTrigger>
            <TabsTrigger value="atexec-lateral" className="text-xs">
              <Network className="w-3 h-3 mr-1" /> atexec Lateral
            </TabsTrigger>
          </TabsList>

          <TabsContent value="priority-queue">
            <PriorityQueueTab />
          </TabsContent>
          <TabsContent value="plc-integrity">
            <PlcIntegrityTab />
          </TabsContent>
          <TabsContent value="utility-playbooks">
            <UtilityPlaybooksTab />
          </TabsContent>
          <TabsContent value="advisory-correlation">
            <AdvisoryCorrelationTab />
          </TabsContent>
          <TabsContent value="validation-feedback">
            <ValidationFeedbackTab />
          </TabsContent>
          <TabsContent value="atexec-lateral">
            <AtexecLateralTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
