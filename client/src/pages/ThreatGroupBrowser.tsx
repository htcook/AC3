/**
 * Threat Group Browser — APT, Ransomware & Cybercrime Knowledge Base
 *
 * Browse, search, and filter threat groups by sector, MITRE ATT&CK technique,
 * CVE, or tool. Each group profile includes TTPs, tools, defense recommendations,
 * and detection hints to support hunt sessions and engagement planning.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Shield,
  Search,
  Target,
  Bug,
  Crosshair,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Globe,
  Skull,
  Swords,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Terminal,
  Eye,
  Lock,
  Zap,
  Activity,
  Users,
  Brain,
  Loader2,
  X,
  Filter,
} from "lucide-react";
import { toast } from "sonner";

// ─── Constants ─────────────────────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  apt: "APT",
  ransomware: "Ransomware",
  cybercrime: "Cybercrime",
  hacktivist: "Hacktivist",
};

const TYPE_COLORS: Record<string, string> = {
  apt: "bg-red-500/20 text-red-400 border-red-500/30",
  ransomware: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  cybercrime: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  hacktivist: "bg-green-500/20 text-green-400 border-green-500/30",
};

const THREAT_LEVEL_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-green-500/20 text-green-400",
};

const TOOL_CATEGORY_ICONS: Record<string, React.ReactNode> = {
  malware: <Skull className="w-3 h-3" />,
  rat: <Terminal className="w-3 h-3" />,
  c2: <Radar className="w-3 h-3" />,
  exploit: <Bug className="w-3 h-3" />,
  credential: <Lock className="w-3 h-3" />,
  lateral: <Swords className="w-3 h-3" />,
  exfiltration: <Zap className="w-3 h-3" />,
  persistence: <ShieldAlert className="w-3 h-3" />,
  recon: <Eye className="w-3 h-3" />,
  "living-off-the-land": <Terminal className="w-3 h-3" />,
};

const DEFENSE_PRIORITY_COLORS: Record<string, string> = {
  critical: "border-red-500/50 bg-red-500/5",
  high: "border-orange-500/50 bg-orange-500/5",
  medium: "border-yellow-500/50 bg-yellow-500/5",
};

// ─── Component ─────────────────────────────────────────────────────────────

export default function ThreatGroupBrowser() {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [sectorFilter, setSectorFilter] = useState("");
  const [ttpFilter, setTtpFilter] = useState("");
  const [toolFilter, setToolFilter] = useState("");
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  // Fetch groups with filters
  const { data: groupsData, isLoading } =
    trpc.threatGroupKnowledge.list.useQuery({
      type: typeFilter as any,
      sector: sectorFilter || undefined,
      search: searchQuery || undefined,
      ttp: ttpFilter || undefined,
      tool: toolFilter || undefined,
    });

  // Fetch summary stats
  const { data: summary } = trpc.threatGroupKnowledge.summary.useQuery();

  // Fetch filter options
  const { data: filterOptions } =
    trpc.threatGroupKnowledge.filterOptions.useQuery();

  // Selected group detail
  const selectedGroup = useMemo(() => {
    if (!selectedGroupId || !groupsData?.groups) return null;
    return groupsData.groups.find((g: any) => g.id === selectedGroupId) || null;
  }, [selectedGroupId, groupsData]);

  const hasActiveFilters =
    searchQuery || typeFilter !== "all" || sectorFilter || ttpFilter || toolFilter;

  function clearFilters() {
    setSearchQuery("");
    setTypeFilter("all");
    setSectorFilter("");
    setTtpFilter("");
    setToolFilter("");
  }

  return (
    <AppShell>
      <div className="min-h-screen bg-background">
        <div className="container max-w-[1600px] py-6 space-y-6">
          {/* Header */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <Shield className="w-7 h-7 text-red-400" />
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Threat Group Browser
              </h1>
            </div>
            <p className="text-sm text-muted-foreground max-w-3xl">
              Search and filter APT, ransomware, and cybercrime groups by sector,
              MITRE ATT&CK technique, CVE, or tool. Each profile includes TTPs,
              tools, defense recommendations, and detection hints for hunt sessions
              and engagement planning.
            </p>
          </div>

          {/* Summary Stats */}
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
              <StatCard
                label="Total Groups"
                value={summary.totalGroups}
                color="text-foreground"
              />
              <StatCard
                label="APT"
                value={summary.byType.apt}
                color="text-red-400"
              />
              <StatCard
                label="Ransomware"
                value={summary.byType.ransomware}
                color="text-amber-400"
              />
              <StatCard
                label="Cybercrime"
                value={summary.byType.cybercrime}
                color="text-purple-400"
              />
              <StatCard
                label="Total TTPs"
                value={summary.totalTTPs}
                color="text-blue-400"
              />
              <StatCard
                label="Total CVEs"
                value={summary.totalCVEs}
                color="text-orange-400"
              />
              <StatCard
                label="Total Tools"
                value={summary.totalTools}
                color="text-green-400"
              />
            </div>
          )}

          {/* Filters */}
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex flex-col md:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search groups by name, alias, or description..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9"
                  />
                </div>
                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger className="w-full md:w-[160px]">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="apt">APT</SelectItem>
                    <SelectItem value="ransomware">Ransomware</SelectItem>
                    <SelectItem value="cybercrime">Cybercrime</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={sectorFilter || "all_sectors"}
                  onValueChange={(v) =>
                    setSectorFilter(v === "all_sectors" ? "" : v)
                  }
                >
                  <SelectTrigger className="w-full md:w-[180px]">
                    <SelectValue placeholder="Sector" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all_sectors">All Sectors</SelectItem>
                    {filterOptions?.sectors.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  placeholder="TTP (e.g. T1190)"
                  value={ttpFilter}
                  onChange={(e) => setTtpFilter(e.target.value)}
                  className="w-full md:w-[140px]"
                />
                <Input
                  placeholder="Tool name"
                  value={toolFilter}
                  onChange={(e) => setToolFilter(e.target.value)}
                  className="w-full md:w-[140px]"
                />
                {hasActiveFilters && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearFilters}
                    className="text-muted-foreground"
                  >
                    <X className="w-4 h-4 mr-1" /> Clear
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Main content: list + detail */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Group List */}
            <div className="lg:col-span-4">
              <Card className="border-border/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Filter className="w-4 h-4" />
                    {isLoading
                      ? "Loading..."
                      : `${groupsData?.total ?? 0} Groups`}
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[calc(100vh-380px)]">
                    {isLoading ? (
                      <div className="flex items-center justify-center py-12">
                        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                      </div>
                    ) : groupsData?.groups.length === 0 ? (
                      <div className="text-center py-12 text-muted-foreground text-sm">
                        No groups match your filters
                      </div>
                    ) : (
                      <div className="divide-y divide-border/50">
                        {groupsData?.groups.map((group: any) => (
                          <button
                            key={group.id}
                            onClick={() => setSelectedGroupId(group.id)}
                            className={`w-full text-left p-4 hover:bg-accent/50 transition-colors ${
                              selectedGroupId === group.id
                                ? "bg-accent/70 border-l-2 border-l-primary"
                                : ""
                            }`}
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <div className="font-semibold text-sm text-foreground truncate">
                                  {group.name}
                                </div>
                                <div className="text-xs text-muted-foreground mt-0.5">
                                  {group.origin}
                                </div>
                              </div>
                              <div className="flex flex-col items-end gap-1 shrink-0">
                                <Badge
                                  variant="outline"
                                  className={`text-[10px] ${
                                    TYPE_COLORS[group.type] || ""
                                  }`}
                                >
                                  {TYPE_LABELS[group.type] || group.type}
                                </Badge>
                                <Badge
                                  variant="secondary"
                                  className={`text-[10px] ${
                                    THREAT_LEVEL_COLORS[group.threatLevel] || ""
                                  }`}
                                >
                                  {group.threatLevel}
                                </Badge>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 mt-2 text-[10px] text-muted-foreground">
                              <span>{group.ttps?.length || 0} TTPs</span>
                              <span>·</span>
                              <span>{group.tools?.length || 0} Tools</span>
                              <span>·</span>
                              <span>
                                {group.exploitedCVEs?.length || 0} CVEs
                              </span>
                              {group.active && (
                                <>
                                  <span>·</span>
                                  <span className="text-green-400 flex items-center gap-0.5">
                                    <Activity className="w-3 h-3" /> Active
                                  </span>
                                </>
                              )}
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>
            </div>

            {/* Group Detail */}
            <div className="lg:col-span-8">
              {selectedGroup ? (
                <GroupDetail group={selectedGroup} />
              ) : (
                <Card className="border-border/50 h-[calc(100vh-380px)] flex items-center justify-center">
                  <div className="text-center text-muted-foreground space-y-3">
                    <Shield className="w-12 h-12 mx-auto opacity-30" />
                    <p className="text-sm">
                      Select a threat group to view its profile
                    </p>
                  </div>
                </Card>
              )}
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}

// ─── Sub-components ────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <Card className="border-border/50">
      <CardContent className="p-3 text-center">
        <div className={`text-2xl font-bold ${color}`}>{value}</div>
        <div className="text-[10px] text-muted-foreground uppercase tracking-wider mt-1">
          {label}
        </div>
      </CardContent>
    </Card>
  );
}

function GroupDetail({ group }: { group: any }) {
  const [activeTab, setActiveTab] = useState("overview");

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="text-lg flex items-center gap-2">
              {group.name}
              {group.active && (
                <Badge
                  variant="outline"
                  className="text-green-400 border-green-500/30 text-[10px]"
                >
                  <Activity className="w-3 h-3 mr-1" /> Active
                </Badge>
              )}
            </CardTitle>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              <Badge
                variant="outline"
                className={TYPE_COLORS[group.type] || ""}
              >
                {TYPE_LABELS[group.type] || group.type}
              </Badge>
              <Badge
                variant="secondary"
                className={THREAT_LEVEL_COLORS[group.threatLevel] || ""}
              >
                {group.threatLevel}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {group.origin}
              </span>
              {group.mitreGroupId && (
                <Badge variant="outline" className="text-[10px] font-mono">
                  {group.mitreGroupId}
                </Badge>
              )}
            </div>
            {group.aliases?.length > 0 && (
              <div className="text-xs text-muted-foreground mt-1">
                Also known as: {group.aliases.join(", ")}
              </div>
            )}
          </div>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          {group.description}
        </p>
        <div className="text-xs text-muted-foreground mt-1">
          <strong>Motivation:</strong> {group.motivation}
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <div className="px-6">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="ttps">
                TTPs ({group.ttps?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="tools">
                Tools ({group.tools?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="defenses">Defenses</TabsTrigger>
              <TabsTrigger value="detection">Detection</TabsTrigger>
            </TabsList>
          </div>

          <ScrollArea className="h-[calc(100vh-540px)]">
            <div className="p-6 pt-4">
              {/* Overview Tab */}
              <TabsContent value="overview" className="mt-0 space-y-4">
                {/* Target Sectors */}
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Target Sectors
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {group.targetSectors?.map((s: string) => (
                      <Badge
                        key={s}
                        variant="outline"
                        className="text-xs"
                      >
                        {s}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Target Regions */}
                {group.targetRegions?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                      Target Regions
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {group.targetRegions.map((r: string) => (
                        <Badge
                          key={r}
                          variant="secondary"
                          className="text-xs"
                        >
                          <Globe className="w-3 h-3 mr-1" /> {r}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Initial Access Methods */}
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Initial Access Methods
                  </h3>
                  <div className="space-y-1">
                    {group.initialAccessMethods?.map(
                      (m: string, i: number) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 text-sm"
                        >
                          <Crosshair className="w-3.5 h-3.5 mt-0.5 text-red-400 shrink-0" />
                          <span>{m}</span>
                        </div>
                      )
                    )}
                  </div>
                </div>

                {/* Exploited CVEs */}
                {group.exploitedCVEs?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                      Exploited CVEs
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {group.exploitedCVEs.map((cve: string) => (
                        <Badge
                          key={cve}
                          variant="outline"
                          className="font-mono text-[10px] text-orange-400 border-orange-500/30"
                        >
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Quick TTP Summary */}
                <div>
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                    Primary TTPs
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {group.ttps
                      ?.filter((t: any) => t.frequency === "primary")
                      .slice(0, 6)
                      .map((ttp: any) => (
                        <div
                          key={ttp.techniqueId}
                          className="flex items-start gap-2 p-2 rounded bg-accent/30 text-xs"
                        >
                          <Badge
                            variant="outline"
                            className="font-mono text-[10px] shrink-0"
                          >
                            {ttp.techniqueId}
                          </Badge>
                          <span className="text-muted-foreground">
                            {ttp.techniqueName}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              </TabsContent>

              {/* TTPs Tab */}
              <TabsContent value="ttps" className="mt-0 space-y-3">
                {/* Group by tactic */}
                {(() => {
                  const byTactic: Record<string, any[]> = {};
                  for (const ttp of group.ttps || []) {
                    const tactic = ttp.tactic || "unknown";
                    if (!byTactic[tactic]) byTactic[tactic] = [];
                    byTactic[tactic].push(ttp);
                  }
                  return Object.entries(byTactic).map(([tactic, ttps]) => (
                    <Collapsible key={tactic} defaultOpen>
                      <CollapsibleTrigger className="flex items-center gap-2 w-full text-left py-2 hover:bg-accent/30 rounded px-2 transition-colors">
                        <ChevronDown className="w-4 h-4 text-muted-foreground" />
                        <span className="text-xs font-semibold uppercase tracking-wider">
                          {tactic.replace(/-/g, " ")}
                        </span>
                        <Badge variant="secondary" className="text-[10px] ml-auto">
                          {ttps.length}
                        </Badge>
                      </CollapsibleTrigger>
                      <CollapsibleContent className="pl-6 space-y-2 mt-1">
                        {ttps.map((ttp: any) => (
                          <div
                            key={ttp.techniqueId}
                            className="flex items-start gap-3 p-2 rounded border border-border/50 bg-card"
                          >
                            <Badge
                              variant="outline"
                              className="font-mono text-[10px] shrink-0 mt-0.5"
                            >
                              {ttp.techniqueId}
                            </Badge>
                            <div className="min-w-0">
                              <div className="text-sm font-medium">
                                {ttp.techniqueName}
                              </div>
                              <div className="text-xs text-muted-foreground mt-0.5">
                                {ttp.description}
                              </div>
                            </div>
                            <Badge
                              variant="secondary"
                              className={`text-[10px] shrink-0 ${
                                ttp.frequency === "primary"
                                  ? "text-red-400"
                                  : ttp.frequency === "secondary"
                                  ? "text-yellow-400"
                                  : "text-muted-foreground"
                              }`}
                            >
                              {ttp.frequency}
                            </Badge>
                          </div>
                        ))}
                      </CollapsibleContent>
                    </Collapsible>
                  ));
                })()}
              </TabsContent>

              {/* Tools Tab */}
              <TabsContent value="tools" className="mt-0">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {group.tools?.map((tool: any) => (
                    <div
                      key={tool.name}
                      className="flex items-start gap-3 p-3 rounded border border-border/50 bg-card"
                    >
                      <div className="p-1.5 rounded bg-accent/50 text-muted-foreground">
                        {TOOL_CATEGORY_ICONS[tool.category] || (
                          <Terminal className="w-3 h-3" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-medium flex items-center gap-2">
                          {tool.name}
                          <Badge
                            variant="outline"
                            className="text-[10px] capitalize"
                          >
                            {tool.category.replace(/-/g, " ")}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground mt-0.5">
                          {tool.description}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>

              {/* Defenses Tab */}
              <TabsContent value="defenses" className="mt-0 space-y-3">
                {group.defenseRecommendations?.map(
                  (def: any, i: number) => (
                    <div
                      key={i}
                      className={`p-3 rounded border ${
                        DEFENSE_PRIORITY_COLORS[def.priority] || ""
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Badge
                          variant="outline"
                          className={`text-[10px] capitalize ${
                            def.priority === "critical"
                              ? "text-red-400 border-red-500/30"
                              : def.priority === "high"
                              ? "text-orange-400 border-orange-500/30"
                              : "text-yellow-400 border-yellow-500/30"
                          }`}
                        >
                          {def.priority}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] capitalize">
                          {def.category}
                        </Badge>
                      </div>
                      <p className="text-sm">{def.recommendation}</p>
                      {def.siemQuery && (
                        <div className="mt-2 p-2 rounded bg-background font-mono text-[11px] text-muted-foreground overflow-x-auto">
                          {def.siemQuery}
                        </div>
                      )}
                      {def.mitreTechniques?.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {def.mitreTechniques.map((t: string) => (
                            <Badge
                              key={t}
                              variant="outline"
                              className="font-mono text-[9px]"
                            >
                              {t}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                )}
              </TabsContent>

              {/* Detection Tab */}
              <TabsContent value="detection" className="mt-0 space-y-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Detection Hints & Signatures
                </h3>
                {group.detectionHints?.map((hint: string, i: number) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 p-3 rounded border border-border/50 bg-card text-sm"
                  >
                    <Eye className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <span>{hint}</span>
                  </div>
                ))}
                {(!group.detectionHints ||
                  group.detectionHints.length === 0) && (
                  <p className="text-sm text-muted-foreground">
                    No detection hints available for this group.
                  </p>
                )}
              </TabsContent>
            </div>
          </ScrollArea>
        </Tabs>
      </CardContent>
    </Card>
  );
}
