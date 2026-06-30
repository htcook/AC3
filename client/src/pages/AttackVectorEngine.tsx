// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { safeJsonParse } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Crosshair, Shield, Target, Zap, AlertTriangle, Activity, TrendingUp,
  Loader2, RefreshCw, Search, ChevronRight, Swords, GitBranch, Play,
  CheckCircle2, XCircle, Clock, ArrowRight, Layers, Terminal, Bug,
  BarChart3, Eye, Lock, Network, Globe2, Server
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/30",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-500 border-amber-500/30",
  low: "bg-blue-500/10 text-blue-500 border-blue-500/30",
};

const PHASE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  reconnaissance: Search,
  weaponization: Swords,
  delivery: ArrowRight,
  exploitation: Bug,
  installation: Terminal,
  command_control: Server,
  actions_on_objectives: Target,
};

export default function AttackVectorEngine() {
  const [tab, setTab] = useState("vectors");
  const [searchFilter, setSearchFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [showAnalyzeDialog, setShowAnalyzeDialog] = useState(false);
  const [showPlaybookDialog, setShowPlaybookDialog] = useState(false);
  const [selectedVectors, setSelectedVectors] = useState<string[]>([]);
  const [playbookForm, setPlaybookForm] = useState({
    name: "",
    description: "",
    targetEnvironment: "",
    targetPlatform: "linux",
    riskLevel: "medium",
  });

  // Queries
  const killChainPhases = trpc.attackVectorEngine.getKillChainPhases.useQuery();
  const vectors = trpc.attackVectorEngine.listVectors.useQuery({
    severity: severityFilter !== "all" ? severityFilter : undefined,
    limit: 100,
  });
  const dashboard = trpc.attackVectorEngine.getDashboardStats.useQuery();
  const playbooks = trpc.attackVectorEngine.listPlaybooks.useQuery({});

  // Mutations
  const analyzeMutation = (trpc.attackVectorEngine as any).analyzeFromSources.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Analysis Complete: ${data.vectorsCreated} attack vectors identified from ${data.sourcesAnalyzed} sources`);
      vectors.refetch();
      dashboard.refetch();
    },
    onError: (err: any) => toast.error("Analysis failed: " + err.message),
  });

  const generatePlaybookMutation = trpc.attackVectorEngine.generatePlaybook.useMutation({
    onSuccess: () => {
      toast.success("Attack playbook generated with emulation abilities and Metasploit modules mapped");
      playbooks.refetch();
      setShowPlaybookDialog(false);
    },
    onError: (err: any) => toast.error("Playbook generation failed: " + err.message),
  });

  const filteredVectors = useMemo(() => {
    if (!vectors.data) return [];
    return vectors.data.filter((v: any) => {
      if (searchFilter && !(v.title || '').toLowerCase().includes(searchFilter.toLowerCase()) &&
          !v.attackSurface?.toLowerCase().includes(searchFilter.toLowerCase())) return false;
      return true;
    });
  }, [vectors.data, searchFilter]);

  const stats = dashboard.data;

  return (
      <AppShell activePath="/attack-vector-engine">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Crosshair className="h-7 w-7 text-red-500" />
            Attack Vector Engine
          </h1>
          <p className="text-muted-foreground mt-1">
            Cross-reference OSINT, dark web intel, exploits, and threat actor TTPs to identify actionable attack vectors with Cyber C2 and Metasploit mappings
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowAnalyzeDialog(true)}>
            <Search className="h-4 w-4 mr-1" />
            Analyze Sources
          </Button>
          <Button variant="outline" size="sm" onClick={() => {
            vectors.refetch();
            dashboard.refetch();
            playbooks.refetch();
          }}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Dashboard KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Attack Vectors</div>
            <div className="text-3xl font-bold text-red-500 mt-1">{(stats as any)?.totalVectors || (stats as any)?.vectors?.total || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">identified</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Critical</div>
            <div className="text-3xl font-bold text-red-600 mt-1">{(stats as any)?.criticalVectors || (stats as any)?.vectors?.critical || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">immediate risk</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Playbooks</div>
            <div className="text-3xl font-bold text-purple-500 mt-1">{(stats as any)?.totalPlaybooks || (stats as any)?.playbooks?.total || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">generated</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Executions</div>
            <div className="text-3xl font-bold text-blue-500 mt-1">{(stats as any)?.totalExecutions || (stats as any)?.executions?.total || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">runs tracked</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Active</div>
            <div className="text-3xl font-bold text-amber-500 mt-1">{(stats as any)?.activeExecutions || (stats as any)?.executions?.active || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">running now</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-3 px-4">
            <div className="text-xs text-muted-foreground uppercase tracking-wide">Completed</div>
            <div className="text-3xl font-bold text-emerald-500 mt-1">{(stats as any)?.completedExecutions || (stats as any)?.executions?.completed || 0 || 0}</div>
            <div className="text-xs text-muted-foreground">successful</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Tabs value={tab} onValueChange={setTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="vectors">Attack Vectors</TabsTrigger>
          <TabsTrigger value="killchain">Kill Chain</TabsTrigger>
          <TabsTrigger value="playbooks">Attack Playbooks</TabsTrigger>
          <TabsTrigger value="executions">Execution History</TabsTrigger>
        </TabsList>

        {/* Attack Vectors Tab */}
        <TabsContent value="vectors" className="space-y-4">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search vectors by title, attack surface..."
                className="pl-9"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            {selectedVectors.length > 0 && (
              <Button size="sm" onClick={() => setShowPlaybookDialog(true)}>
                <Swords className="h-4 w-4 mr-1" />
                Generate Playbook ({selectedVectors.length})
              </Button>
            )}
          </div>

          {vectors.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : filteredVectors.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Crosshair className="h-10 w-10 mx-auto mb-3 text-muted-foreground opacity-50" />
                <p className="text-muted-foreground">No attack vectors identified yet. Click "Analyze Sources" to cross-reference your OSINT, dark web intel, and exploit data.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {filteredVectors.map((vector: any) => (
                <Card key={vector.id} className="hover:border-primary/30 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-start gap-4">
                      <input
                        type="checkbox"
                        className="mt-1.5 h-4 w-4 rounded border-muted-foreground"
                        checked={selectedVectors.includes(vector.id)}
                        onChange={(e) => {
                          if (e.target.checked) setSelectedVectors([...selectedVectors, vector.id]);
                          else setSelectedVectors(selectedVectors.filter((id) => id !== vector.id));
                        }}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium truncate">{vector.title}</span>
                          <Badge variant="outline" className={SEVERITY_COLORS[vector.severity] || ""}>
                            {vector.severity}
                          </Badge>
                          {vector.attackSurface && (
                            <Badge variant="secondary" className="text-xs">{vector.attackSurface}</Badge>
                          )}
                          {vector.exploitAvailable && (
                            <Badge variant="destructive" className="text-xs">Exploit Available</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground line-clamp-2">{vector.description}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          {vector.cvssScore && (
                            <span className="flex items-center gap-1">
                              <BarChart3 className="h-3 w-3" /> CVSS {vector.cvssScore}
                            </span>
                          )}
                          {vector.mitreTechniques && (
                            <span className="flex items-center gap-1">
                              <Target className="h-3 w-3" /> {safeJsonParse<any[]>(vector.mitreTechniques, []).length} techniques
                            </span>
                          )}
                          {vector.calderaAbilityIds && (
                            <span className="flex items-center gap-1">
                              <Swords className="h-3 w-3 text-purple-500" /> {safeJsonParse<any[]>(vector.calderaAbilityIds, []).length} emulation abilities
                            </span>
                          )}
                          {vector.msfModuleIds && (
                            <span className="flex items-center gap-1">
                              <Terminal className="h-3 w-3 text-blue-500" /> {safeJsonParse<any[]>(vector.msfModuleIds, []).length} MSF modules
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="text-2xl font-bold" style={{
                          color: vector.riskScore >= 8 ? '#ef4444' : vector.riskScore >= 6 ? '#f97316' : vector.riskScore >= 4 ? '#eab308' : '#3b82f6'
                        }}>
                          {vector.riskScore?.toFixed(1) || '—'}
                        </div>
                        <div className="text-xs text-muted-foreground">risk score</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Kill Chain Tab */}
        <TabsContent value="killchain" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch className="h-5 w-5" />
                Cyber Kill Chain Coverage
              </CardTitle>
              <CardDescription>
                Attack vectors mapped across the kill chain phases — from reconnaissance through actions on objectives
              </CardDescription>
            </CardHeader>
            <CardContent>
              {killChainPhases.data ? (
                <div className="space-y-4">
                  {killChainPhases.data.map((phase: any) => {
                    const PhaseIcon = PHASE_ICONS[phase.id] || Target;
                    return (
                      <div key={phase.id} className="border rounded-lg p-4">
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                            <PhaseIcon className="h-5 w-5 text-primary" />
                          </div>
                          <div className="flex-1">
                            <div className="font-medium">{phase.name}</div>
                            <div className="text-xs text-muted-foreground">{phase.description}</div>
                          </div>
                          <div className="text-right">
                            <div className="text-lg font-bold">{phase.vectorCount || 0}</div>
                            <div className="text-xs text-muted-foreground">vectors</div>
                          </div>
                        </div>
                        <div className="flex gap-2 flex-wrap">
                          {phase.calderaAbilities?.length > 0 && (
                            <Badge variant="outline" className="text-xs bg-purple-500/10 text-purple-400 border-purple-500/30">
                              <Swords className="h-3 w-3 mr-1" /> {phase.calderaAbilities.length} Caldera Abilities
                            </Badge>
                          )}
                          {phase.msfModules?.length > 0 && (
                            <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-400 border-blue-500/30">
                              <Terminal className="h-3 w-3 mr-1" /> {phase.msfModules.length} MSF Modules
                            </Badge>
                          )}
                          {phase.atomicTests?.length > 0 && (
                            <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-400 border-amber-500/30">
                              <Bug className="h-3 w-3 mr-1" /> {phase.atomicTests.length} Atomic Tests
                            </Badge>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack Playbooks Tab */}
        <TabsContent value="playbooks" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-medium">Attack Playbooks</h3>
              <p className="text-sm text-muted-foreground">
                Pre/post-exploitation workflows with mapped emulation abilities and Metasploit modules
              </p>
            </div>
          </div>

          {playbooks.isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !playbooks.data || playbooks.data.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Swords className="h-10 w-10 mx-auto mb-3 text-muted-foreground opacity-50" />
                <p className="text-muted-foreground">No playbooks generated yet. Select attack vectors and click "Generate Playbook" to create an engagement plan.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {playbooks.data.map((pb: any) => (
                <Card key={pb.id}>
                  <CardContent className="py-4">
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-medium">{pb.name}</span>
                          <Badge variant="outline" className={SEVERITY_COLORS[pb.riskLevel] || ""}>
                            {pb.riskLevel}
                          </Badge>
                          <Badge variant={pb.status === "approved" ? "default" : pb.status === "completed" ? "secondary" : "outline"}>
                            {pb.status}
                          </Badge>
                          {pb.roeCompliant && (
                            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/30">
                              <Shield className="h-3 w-3 mr-1" /> ROE Compliant
                            </Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground line-clamp-2">{pb.description}</p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          {pb.targetPlatform && <span>Platform: {pb.targetPlatform}</span>}
                          {pb.estimatedDuration && <span>Duration: {pb.estimatedDuration}</span>}
                          {pb.calderaAbilities && (
                            <span className="text-purple-400">
                              {safeJsonParse<any[]>(pb.calderaAbilities, []).length} emulation abilities
                            </span>
                          )}
                          {pb.msfModules && (
                            <span className="text-blue-400">
                              {safeJsonParse<any[]>(pb.msfModules, []).length} MSF modules
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Execution History Tab */}
        <TabsContent value="executions" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Execution History
              </CardTitle>
              <CardDescription>
                Track playbook execution progress through kill chain phases — from pre-exploitation through cleanup
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-muted-foreground">
                <Activity className="h-10 w-10 mx-auto mb-3 opacity-50" />
                <p>Execution history will appear here once playbooks are run against target environments.</p>
                <p className="text-xs mt-1">Each execution tracks progress through: Pre-Exploit → Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → Collection → Exfiltration → Cleanup</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Analyze Sources Dialog */}
      <Dialog open={showAnalyzeDialog} onOpenChange={setShowAnalyzeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Analyze Attack Sources</DialogTitle>
            <DialogDescription>
              Cross-reference OSINT findings, dark web intelligence, exploit catalogs, and threat actor TTPs to identify attack vectors with Cyber C2 and Metasploit mappings.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-4">
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <Globe2 className="h-4 w-4 text-blue-500" />
                <span>OSINT Findings</span>
              </div>
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <AlertTriangle className="h-4 w-4 text-red-500" />
                <span>Dark Web Intel</span>
              </div>
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <Bug className="h-4 w-4 text-amber-500" />
                <span>Exploit Catalog</span>
              </div>
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <Shield className="h-4 w-4 text-purple-500" />
                <span>Threat Actors</span>
              </div>
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <Target className="h-4 w-4 text-emerald-500" />
                <span>Vuln Scan Results</span>
              </div>
              <div className="flex items-center gap-2 p-3 border rounded-lg">
                <Lock className="h-4 w-4 text-orange-500" />
                <span>Credential Leaks</span>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAnalyzeDialog(false)}>Cancel</Button>
            <Button
              onClick={() => {
                analyzeMutation.mutate({
                  sources: ["osint", "darkweb", "exploits", "vulnscans", "credentials", "threat_actors"],
                });
                setShowAnalyzeDialog(false);
              }}
              disabled={analyzeMutation.isPending}
            >
              {analyzeMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Search className="h-4 w-4 mr-1" />}
              Run Analysis
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Generate Playbook Dialog */}
      <Dialog open={showPlaybookDialog} onOpenChange={setShowPlaybookDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Generate Attack Playbook</DialogTitle>
            <DialogDescription>
              Create an engagement playbook from {selectedVectors.length} selected attack vectors with emulation abilities and Metasploit modules mapped to each kill chain phase.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div>
              <label className="text-sm font-medium">Playbook Name</label>
              <Input
                value={playbookForm.name}
                onChange={(e) => setPlaybookForm({ ...playbookForm, name: e.target.value })}
                placeholder="e.g., External Perimeter Assessment Q1 2026"
              />
            </div>
            <div>
              <label className="text-sm font-medium">Description</label>
              <Textarea
                value={playbookForm.description}
                onChange={(e) => setPlaybookForm({ ...playbookForm, description: e.target.value })}
                placeholder="Describe the engagement scope and objectives..."
                rows={3}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Target Environment</label>
                <Input
                  value={playbookForm.targetEnvironment}
                  onChange={(e) => setPlaybookForm({ ...playbookForm, targetEnvironment: e.target.value })}
                  placeholder="e.g., Production AWS"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Target Platform</label>
                <Select value={playbookForm.targetPlatform} onValueChange={(v) => setPlaybookForm({ ...playbookForm, targetPlatform: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="macos">macOS</SelectItem>
                    <SelectItem value="cloud">Cloud (AWS/Azure/GCP)</SelectItem>
                    <SelectItem value="mixed">Mixed Environment</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium">Risk Level</label>
              <Select value={playbookForm.riskLevel} onValueChange={(v) => setPlaybookForm({ ...playbookForm, riskLevel: v })}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="low">Low — Non-destructive reconnaissance only</SelectItem>
                  <SelectItem value="medium">Medium — Standard exploitation with safeguards</SelectItem>
                  <SelectItem value="high">High — Full exploitation including privilege escalation</SelectItem>
                  <SelectItem value="critical">Critical — Unrestricted including data exfiltration simulation</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowPlaybookDialog(false)}>Cancel</Button>
            <Button
              onClick={() => {
                generatePlaybookMutation.mutate({
                  vectorIds: selectedVectors,
                  name: playbookForm.name || `Playbook — ${new Date().toLocaleDateString()}`,
                  description: playbookForm.description,
                  targetEnvironment: playbookForm.targetEnvironment,
                  targetPlatform: playbookForm.targetPlatform,
                  riskLevel: playbookForm.riskLevel,
                });
              }}
              disabled={generatePlaybookMutation.isPending || !playbookForm.name}
            >
              {generatePlaybookMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Swords className="h-4 w-4 mr-1" />}
              Generate Playbook
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
      </AppShell>
  );
}
