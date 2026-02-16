import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { toast } from "sonner";
import {
  Shield, Zap, Cloud, Link2, Key, Lock, Database, Bug,
  ChevronDown, ChevronRight, Target, Layers, AlertTriangle,
  Play, Users, RefreshCw, Plus, Search, Filter,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";

// Category config
const CATEGORY_CONFIG: Record<string, { label: string; icon: any; color: string }> = {
  saas_oauth_compromise: { label: "SaaS OAuth Compromise", icon: Key, color: "text-purple-400" },
  token_abuse: { label: "Token Abuse", icon: Lock, color: "text-red-400" },
  cloud_lateral_movement: { label: "Cloud Lateral Movement", icon: Cloud, color: "text-cyan-400" },
  supply_chain: { label: "Supply Chain", icon: Link2, color: "text-orange-400" },
  credential_harvesting: { label: "Credential Harvesting", icon: Users, color: "text-yellow-400" },
  ransomware_deployment: { label: "Ransomware Deployment", icon: AlertTriangle, color: "text-red-500" },
  data_exfiltration: { label: "Data Exfiltration", icon: Database, color: "text-emerald-400" },
  persistence_implant: { label: "Persistence Implant", icon: Bug, color: "text-pink-400" },
  custom: { label: "Custom", icon: Plus, color: "text-gray-400" },
};

const COMPLEXITY_COLORS: Record<string, string> = {
  low: "bg-green-500/20 text-green-400 border-green-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  expert: "bg-red-500/20 text-red-400 border-red-500/30",
};

export default function CampaignArchetypes() {
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [actorDialogOpen, setActorDialogOpen] = useState(false);
  const [selectedArchetypeSlug, setSelectedArchetypeSlug] = useState<string | null>(null);
  const [selectedActorId, setSelectedActorId] = useState<string>("");

  const { data: archetypes, isLoading, refetch } = trpc.campaignArchetypes.list.useQuery();
  const seedMutation = trpc.campaignArchetypes.seedBuiltIns.useMutation({
    onSuccess: (data) => {
      toast.success(`Seeded ${data.created} new, updated ${data.updated} archetypes`);
      refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  // Actor population query (only runs when both slug and actorId are set)
  const { data: populationData, isLoading: isPopulating } =
    trpc.campaignArchetypes.populateForActor.useQuery(
      { archetypeSlug: selectedArchetypeSlug!, actorId: selectedActorId },
      { enabled: !!selectedArchetypeSlug && !!selectedActorId && actorDialogOpen }
    );

  // Actor list for the dropdown
  const { data: actorList } = trpc.threatIntel.list.useQuery(
    { pageSize: 500 },
    { enabled: actorDialogOpen }
  );

  const filtered = useMemo(() => {
    if (!archetypes) return [];
    return archetypes.filter((a) => {
      const matchSearch =
        !search ||
        a.name.toLowerCase().includes(search.toLowerCase()) ||
        (a.description || "").toLowerCase().includes(search.toLowerCase());
      const matchCategory = categoryFilter === "all" || a.category === categoryFilter;
      return matchSearch && matchCategory;
    });
  }, [archetypes, search, categoryFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Layers className="h-7 w-7 text-primary" />
            Campaign Archetypes
          </h1>
          <p className="text-muted-foreground mt-1">
            Reusable attack patterns that auto-populate with actor-specific MITRE techniques
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => seedMutation.mutate()}
            disabled={seedMutation.isPending}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${seedMutation.isPending ? "animate-spin" : ""}`} />
            Seed Built-ins
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search archetypes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={categoryFilter} onValueChange={setCategoryFilter}>
          <SelectTrigger className="w-[220px]">
            <Filter className="h-4 w-4 mr-2" />
            <SelectValue placeholder="All Categories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => (
              <SelectItem key={key} value={key}>
                {cfg.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Stats */}
      {archetypes && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-primary">{archetypes.length}</div>
              <div className="text-xs text-muted-foreground">Total Archetypes</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-cyan-400">
                {archetypes.filter((a) => a.isBuiltIn).length}
              </div>
              <div className="text-xs text-muted-foreground">Built-in</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-purple-400">
                {new Set(archetypes.map((a) => a.category)).size}
              </div>
              <div className="text-xs text-muted-foreground">Categories</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-4 text-center">
              <div className="text-2xl font-bold text-emerald-400">
                {archetypes.reduce((sum, a) => sum + (a.defaultTechniques?.length || 0), 0)}
              </div>
              <div className="text-xs text-muted-foreground">Total Techniques</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="text-center py-12 text-muted-foreground">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto mb-2" />
          Loading archetypes...
        </div>
      )}

      {/* Empty state */}
      {!isLoading && archetypes && archetypes.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-12 text-center">
            <Layers className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-lg font-semibold mb-2">No Archetypes Found</h3>
            <p className="text-muted-foreground mb-4">
              Click "Seed Built-ins" to populate the 8 built-in campaign archetype templates.
            </p>
            <Button onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
              <RefreshCw className={`h-4 w-4 mr-1 ${seedMutation.isPending ? "animate-spin" : ""}`} />
              Seed Built-in Archetypes
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Archetype Cards */}
      <div className="space-y-3">
        {filtered.map((arch) => {
          const cfg = CATEGORY_CONFIG[arch.category] || CATEGORY_CONFIG.custom;
          const Icon = cfg.icon;
          const isExpanded = expandedId === arch.id;

          return (
            <Card
              key={arch.id}
              className="bg-card/80 border-border/50 hover:border-primary/30 transition-colors"
            >
              <CardHeader
                className="cursor-pointer pb-3"
                onClick={() => setExpandedId(isExpanded ? null : arch.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start gap-3">
                    <div className={`p-2 rounded-lg bg-background/50 ${cfg.color}`}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div>
                      <CardTitle className="text-base flex items-center gap-2">
                        {arch.name}
                        {arch.isBuiltIn && (
                          <Badge variant="outline" className="text-[10px] py-0">
                            BUILT-IN
                          </Badge>
                        )}
                      </CardTitle>
                      <CardDescription className="mt-1 line-clamp-2">
                        {arch.description}
                      </CardDescription>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={COMPLEXITY_COLORS[arch.complexity || "medium"]}>
                      {safeUpper(arch.complexity || "medium")}
                    </Badge>
                    <Badge variant="outline" className="font-mono text-xs">
                      {(arch.defaultTechniques || []).length} TTPs
                    </Badge>
                    {isExpanded ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
                </div>
              </CardHeader>

              {isExpanded && (
                <CardContent className="pt-0 space-y-4">
                  {/* Kill Chain Phases */}
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                      Kill Chain Phases
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {(arch.killChainPhases || []).map((phase: string, i: number) => (
                        <Badge
                          key={i}
                          variant="outline"
                          className="bg-primary/10 text-primary border-primary/30 text-xs"
                        >
                          {phase}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* MITRE Techniques */}
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                      Default MITRE Techniques
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                      {(arch.defaultTechniques || []).map((t: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 text-sm p-2 rounded bg-background/50"
                        >
                          <code className="text-xs text-cyan-400 font-mono">{t.id}</code>
                          <span className="text-foreground/80 truncate">{t.name}</span>
                          <Badge variant="outline" className="ml-auto text-[10px] shrink-0">
                            {t.tactic}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Abilities */}
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                      Caldera Ability Steps
                    </h4>
                    <div className="space-y-1.5">
                      {(arch.defaultAbilities || []).map((a: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-center gap-3 text-sm p-2 rounded bg-background/50"
                        >
                          <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold shrink-0">
                            {a.step}
                          </div>
                          <div className="min-w-0">
                            <div className="font-medium truncate">{a.name}</div>
                            <div className="text-xs text-muted-foreground truncate">
                              {a.description}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Target Platforms & Services */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                        Target Platforms
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {(arch.targetPlatforms || []).map((p: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {safeUpper(p)}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                        Target Services
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {(arch.targetServices || []).map((s: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Prerequisites */}
                  {(arch.prerequisites || []).length > 0 && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                        Prerequisites
                      </h4>
                      <ul className="space-y-1">
                        {(arch.prerequisites || []).map((p: string, i: number) => (
                          <li key={i} className="text-sm text-foreground/80 flex items-start gap-2">
                            <AlertTriangle className="h-3.5 w-3.5 text-yellow-400 mt-0.5 shrink-0" />
                            {p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Detection Guidance */}
                  {arch.detectionGuidance && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                        Detection Guidance
                      </h4>
                      <p className="text-sm text-foreground/70 bg-background/50 p-3 rounded border border-border/30">
                        {arch.detectionGuidance}
                      </p>
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex gap-2 pt-2 border-t border-border/30">
                    <Button
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedArchetypeSlug(arch.slug);
                        setSelectedActorId("");
                        setActorDialogOpen(true);
                      }}
                    >
                      <Target className="h-4 w-4 mr-1" />
                      Auto-Populate for Actor
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={(e) => {
                        e.stopPropagation();
                        toast.info("Campaign generation from archetypes coming soon");
                      }}
                    >
                      <Play className="h-4 w-4 mr-1" />
                      Generate Campaign
                    </Button>
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>

      {/* Actor Population Dialog */}
      <Dialog open={actorDialogOpen} onOpenChange={setActorDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Target className="h-5 w-5 text-primary" />
              Auto-Populate Archetype for Actor
            </DialogTitle>
            <DialogDescription>
              Select a threat actor to see which of their known techniques overlap with this
              archetype's attack pattern.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {/* Actor Selector */}
            <Select value={selectedActorId} onValueChange={setSelectedActorId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a threat actor..." />
              </SelectTrigger>
              <SelectContent>
                {(actorList?.actors || []).map((actor: any) => (
                  <SelectItem key={actor.actorId} value={actor.actorId}>
                    {actor.name} ({safeUpper(actor.type)})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            {/* Population Results */}
            {isPopulating && (
              <div className="text-center py-8 text-muted-foreground">
                <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2" />
                Computing technique overlap...
              </div>
            )}

            {populationData && (
              <div className="space-y-4">
                {/* Coverage Summary */}
                <Card className="bg-card/80">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-semibold">Technique Coverage</h4>
                      <Badge
                        className={
                          populationData.overlap.coveragePercent >= 70
                            ? "bg-green-500/20 text-green-400"
                            : populationData.overlap.coveragePercent >= 40
                            ? "bg-yellow-500/20 text-yellow-400"
                            : "bg-red-500/20 text-red-400"
                        }
                      >
                        {populationData.overlap.coveragePercent}% Match
                      </Badge>
                    </div>
                    <div className="w-full bg-background/50 rounded-full h-2.5 mb-2">
                      <div
                        className="bg-primary h-2.5 rounded-full transition-all"
                        style={{
                          width: `${Math.min(populationData.overlap.coveragePercent, 100)}%`,
                        }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {populationData.overlap.matchCount} of{" "}
                      {populationData.overlap.totalArchetypeTechniques} archetype techniques
                      found in {populationData.actor.name}'s known TTPs
                    </p>
                  </CardContent>
                </Card>

                {/* Matched Techniques */}
                {populationData.overlap.matchedTechniques.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                      Matched Techniques (Actor-Confirmed)
                    </h4>
                    <div className="space-y-1.5">
                      {populationData.overlap.matchedTechniques.map((t: any, i: number) => (
                        <div
                          key={i}
                          className="flex items-center gap-2 text-sm p-2 rounded bg-green-500/5 border border-green-500/20"
                        >
                          <Shield className="h-4 w-4 text-green-400 shrink-0" />
                          <code className="text-xs text-cyan-400 font-mono">{t.id}</code>
                          <span className="truncate">{t.name}</span>
                          <Badge variant="outline" className="ml-auto text-[10px] shrink-0">
                            {t.tactic}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actor Info */}
                <div className="text-xs text-muted-foreground bg-background/50 p-3 rounded">
                  <strong>{populationData.actor.name}</strong> has{" "}
                  {populationData.actor.techniques.length} known techniques,{" "}
                  {(populationData.actor.tools || []).length} tools, and{" "}
                  {(populationData.actor.malware || []).length} malware families.
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
