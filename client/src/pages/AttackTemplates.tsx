import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  Search, Cloud, Server, Shield, Building2, Cpu, Network,
  ChevronRight, Target, Layers, Zap, AlertTriangle, Lock,
  Globe2, Truck, Heart, DollarSign, Monitor, Rocket, Play
} from "lucide-react";

const ENV_ICONS: Record<string, React.ReactNode> = {
  aws_cloud: <Cloud className="w-4 h-4" />,
  azure_cloud: <Cloud className="w-4 h-4" />,
  azure_m365: <Cloud className="w-4 h-4" />,
  windows_ad: <Monitor className="w-4 h-4" />,
  linux_container: <Cpu className="w-4 h-4" />,
  linux_server: <Server className="w-4 h-4" />,
  linux_cicd: <Cpu className="w-4 h-4" />,
  msp_network: <Network className="w-4 h-4" />,
  healthcare_network: <Heart className="w-4 h-4" />,
  healthcare_iot: <Heart className="w-4 h-4" />,
  financial_network: <DollarSign className="w-4 h-4" />,
  financial_pos: <DollarSign className="w-4 h-4" />,
  government_network: <Building2 className="w-4 h-4" />,
  government_dmz: <Globe2 className="w-4 h-4" />,
};

const ENV_LABELS: Record<string, string> = {
  aws_cloud: "AWS Cloud",
  azure_cloud: "Azure Cloud",
  azure_m365: "Azure / M365",
  windows_ad: "Windows AD",
  linux_container: "Linux / Container",
  linux_server: "Linux Server",
  linux_cicd: "Linux CI/CD",
  msp_network: "MSP Network",
  healthcare_network: "Healthcare",
  healthcare_iot: "Healthcare IoT",
  financial_network: "Financial Services",
  financial_pos: "Financial POS",
  government_network: "Government",
  government_dmz: "Government DMZ",
  hybrid: "Hybrid",
};

const COMPLEXITY_COLORS: Record<string, string> = {
  intermediate: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  advanced: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  "nation-state": "bg-red-500/20 text-red-400 border-red-500/30",
};

const ATTACK_TYPE_LABELS: Record<string, string> = {
  privilege_escalation: "Privilege Escalation",
  data_theft: "Data Theft",
  persistence: "Persistence",
  credential_access: "Credential Access",
  lateral_movement: "Lateral Movement",
  supply_chain: "Supply Chain",
  ransomware: "Ransomware",
  financial_fraud: "Financial Fraud",
  apt_espionage: "APT Espionage",
  ot_disruption: "OT Disruption",
};

export default function AttackTemplates() {
  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState<string>("all");
  const [complexityFilter, setComplexityFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [launchDialogOpen, setLaunchDialogOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<any>(null);
  const [customerName, setCustomerName] = useState("");
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const { data, isLoading } = trpc.threatIntelTraining.listTemplates.useQuery(
    {
      status: "production",
      search: search || undefined,
      limit: 100,
      offset: 0,
    },
    { staleTime: 30_000 }
  );

  const createFromTemplate = trpc.campaignOrchestrator.createFromTemplate.useMutation({
    onSuccess: (result) => {
      toast({
        title: "Campaign Created",
        description: `"${result.name}" created with ${result.stagesCreated} stages. Redirecting...`,
      });
      setLaunchDialogOpen(false);
      setCustomerName("");
      setTimeout(() => navigate(`/campaigns/${result.campaignId}`), 800);
    },
    onError: (err) => {
      toast({
        title: "Failed to create campaign",
        description: err.message,
        variant: "destructive",
      });
    },
  });

  const templates = useMemo(() => {
    let items = data?.templates || [];
    if (envFilter !== "all") {
      items = items.filter((t: any) => t.targetEnvironment === envFilter);
    }
    if (complexityFilter !== "all") {
      items = items.filter((t: any) => t.astComplexity === complexityFilter);
    }
    return items;
  }, [data, envFilter, complexityFilter]);

  // Group templates by environment for the category view
  const groupedByEnv = useMemo(() => {
    const groups: Record<string, any[]> = {};
    for (const t of templates) {
      const env = t.targetEnvironment || "hybrid";
      if (!groups[env]) groups[env] = [];
      groups[env].push(t);
    }
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [templates]);

  const envOptions = useMemo(() => {
    const envs = new Set((data?.templates || []).map((t: any) => t.targetEnvironment));
    return Array.from(envs).filter(Boolean).sort();
  }, [data]);

  function handleLaunch(template: any, e: React.MouseEvent) {
    e.stopPropagation();
    setSelectedTemplate(template);
    setLaunchDialogOpen(true);
  }

  function confirmLaunch() {
    if (!selectedTemplate) return;
    createFromTemplate.mutate({
      templateId: selectedTemplate.id,
      customerName: customerName.trim() || undefined,
    });
  }

  return (
    <AppShell>
      <div className="container max-w-7xl py-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Target className="w-6 h-6 text-amber-400" />
              Attack Templates
            </h1>
            <p className="text-muted-foreground mt-1">
              {data?.total ?? 0} production templates organized by technology stack and network type
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search templates..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <Select value={envFilter} onValueChange={setEnvFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Environment" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Environments</SelectItem>
              {envOptions.map((env) => (
                <SelectItem key={env} value={env}>
                  {ENV_LABELS[env] || env}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={complexityFilter} onValueChange={setComplexityFilter}>
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Complexity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Levels</SelectItem>
              <SelectItem value="intermediate">Intermediate</SelectItem>
              <SelectItem value="advanced">Advanced</SelectItem>
              <SelectItem value="nation-state">Nation-State</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Loading */}
        {isLoading && (
          <div className="text-center py-12 text-muted-foreground">Loading templates...</div>
        )}

        {/* Template Cards by Environment */}
        {!isLoading && groupedByEnv.map(([env, items]) => (
          <div key={env} className="space-y-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              {ENV_ICONS[env] || <Layers className="w-4 h-4" />}
              {ENV_LABELS[env] || env}
              <Badge variant="outline" className="ml-2 text-xs">{items.length}</Badge>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {items.map((t: any) => {
                const phases = (() => { try { return JSON.parse(t.phases || "[]"); } catch { return []; } })();
                const adversary = (() => { try { return JSON.parse(t.calderaAdversaryProfile || "{}"); } catch { return {}; } })();
                const isExpanded = expandedId === t.id;
                return (
                  <Card
                    key={t.id}
                    className={`cursor-pointer transition-all hover:border-primary/50 ${isExpanded ? "border-primary/50 ring-1 ring-primary/20" : ""}`}
                    onClick={() => setExpandedId(isExpanded ? null : t.id)}
                  >
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between gap-2">
                        <CardTitle className="text-sm font-semibold leading-tight">{t.name}</CardTitle>
                        <Badge className={`text-[10px] shrink-0 ${COMPLEXITY_COLORS[t.astComplexity] || "bg-muted text-muted-foreground"}`}>
                          {t.astComplexity?.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-[10px]">
                          {ATTACK_TYPE_LABELS[t.attackType] || t.attackType}
                        </Badge>
                        {adversary.name && (
                          <Badge variant="outline" className="text-[10px] text-primary border-primary/30">
                            {adversary.name}
                          </Badge>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="pt-0">
                      <p className="text-xs text-muted-foreground line-clamp-2">{t.description}</p>
                      {isExpanded && (
                        <div className="mt-3 space-y-3 border-t pt-3">
                          {/* Phases */}
                          <div>
                            <p className="text-xs font-semibold text-muted-foreground mb-1">ATTACK PHASES</p>
                            <div className="space-y-1">
                              {phases.map((p: any, i: number) => (
                                <div key={i} className="flex items-center gap-2 text-xs">
                                  <span className="w-5 h-5 rounded-full bg-primary/20 text-primary flex items-center justify-center text-[10px] font-bold shrink-0">{p.phase || i + 1}</span>
                                  <span>{p.name}</span>
                                  <span className="text-muted-foreground ml-auto font-mono text-[10px]">
                                    {(p.techniques || []).join(", ")}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                          {/* Stats */}
                          <div className="grid grid-cols-3 gap-2 text-center">
                            <div className="bg-muted/50 rounded p-2">
                              <p className="text-[10px] text-muted-foreground">DETECTION</p>
                              <p className="text-sm font-bold">{t.detectionDifficulty}/10</p>
                            </div>
                            <div className="bg-muted/50 rounded p-2">
                              <p className="text-[10px] text-muted-foreground">SUCCESS</p>
                              <p className="text-sm font-bold">{t.successRate ? `${(t.successRate * 100).toFixed(0)}%` : "N/A"}</p>
                            </div>
                            <div className="bg-muted/50 rounded p-2">
                              <p className="text-[10px] text-muted-foreground">DWELL TIME</p>
                              <p className="text-sm font-bold">{t.avgDwellTime || "N/A"}</p>
                            </div>
                          </div>
                          {/* Launch Button */}
                          <Button
                            className="w-full mt-2"
                            size="sm"
                            onClick={(e) => handleLaunch(t, e)}
                          >
                            <Rocket className="w-4 h-4 mr-2" />
                            Launch Campaign from Template
                          </Button>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        ))}

        {!isLoading && templates.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            No templates found matching your filters.
          </div>
        )}
      </div>

      {/* Launch Dialog */}
      <Dialog open={launchDialogOpen} onOpenChange={setLaunchDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Rocket className="w-5 h-5 text-primary" />
              Launch Campaign from Template
            </DialogTitle>
            <DialogDescription>
              This will create a new campaign pre-populated with the attack phases from{" "}
              <span className="font-semibold text-foreground">{selectedTemplate?.name}</span>.
              All stages will be created in draft mode for review before execution.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="customerName">Customer / Target Name (optional)</Label>
              <Input
                id="customerName"
                placeholder="e.g., Acme Corp"
                value={customerName}
                onChange={(e) => setCustomerName(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                If provided, the campaign will be named "{selectedTemplate?.name} — {customerName || 'Customer'}"
              </p>
            </div>
            {selectedTemplate && (
              <div className="bg-muted/50 rounded-lg p-3 space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Template:</span>
                  <span className="font-medium">{selectedTemplate.name}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Attack Type:</span>
                  <span className="font-medium">{ATTACK_TYPE_LABELS[selectedTemplate.attackType] || selectedTemplate.attackType}</span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Phases:</span>
                  <span className="font-medium">
                    {(() => { try { return JSON.parse(selectedTemplate.phases || "[]").length; } catch { return 0; } })()}
                  </span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Complexity:</span>
                  <Badge className={`text-[10px] ${COMPLEXITY_COLORS[selectedTemplate.astComplexity] || ""}`}>
                    {selectedTemplate.astComplexity?.toUpperCase()}
                  </Badge>
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLaunchDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={confirmLaunch} disabled={createFromTemplate.isPending}>
              {createFromTemplate.isPending ? (
                <>Creating...</>
              ) : (
                <>
                  <Play className="w-4 h-4 mr-2" />
                  Create Campaign
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
