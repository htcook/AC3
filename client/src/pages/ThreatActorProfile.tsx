import { useState, useMemo } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import {
  ArrowLeft, Shield, Target, Globe2, AlertTriangle, Crosshair,
  Wrench, Bug, ShieldAlert, Eye, Copy, Check, ExternalLink,
  Swords, MapPin, Building2, Fingerprint, Zap, Lock, Search,
  ChevronRight, Activity,
} from "lucide-react";
import { toast } from "sonner";

// ─── Tactic Colors ─────────────────────────────────────────────────────────

const TACTIC_CONFIG: Record<string, { color: string; bg: string }> = {
  "initial-access": { color: "text-red-400", bg: "bg-red-500/10 border-red-500/20" },
  "execution": { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20" },
  "persistence": { color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
  "privilege-escalation": { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
  "defense-evasion": { color: "text-lime-400", bg: "bg-lime-500/10 border-lime-500/20" },
  "credential-access": { color: "text-green-400", bg: "bg-green-500/10 border-green-500/20" },
  "discovery": { color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
  "lateral-movement": { color: "text-teal-400", bg: "bg-teal-500/10 border-teal-500/20" },
  "collection": { color: "text-cyan-400", bg: "bg-cyan-500/10 border-cyan-500/20" },
  "exfiltration": { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20" },
  "command-and-control": { color: "text-indigo-400", bg: "bg-indigo-500/10 border-indigo-500/20" },
  "impact": { color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
  "resource-development": { color: "text-pink-400", bg: "bg-pink-500/10 border-pink-500/20" },
  "reconnaissance": { color: "text-rose-400", bg: "bg-rose-500/10 border-rose-500/20" },
};

const THREAT_LEVEL_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30" },
  low: { color: "text-green-400", bg: "bg-green-500/10 border-green-500/30" },
};

const TYPE_CONFIG: Record<string, { label: string; icon: React.ElementType }> = {
  apt: { label: "APT", icon: Fingerprint },
  ransomware: { label: "Ransomware", icon: Lock },
  cybercrime: { label: "Cybercrime", icon: Bug },
};

const PRIORITY_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/30" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30" },
  low: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/30" },
};

// ─── Main Page ─────────────────────────────────────────────────────────────

export default function ThreatActorProfile() {
  const [, params] = useRoute("/threat-actors/:groupId");
  const [, navigate] = useLocation();
  const groupId = params?.groupId || "";
  const [activeTab, setActiveTab] = useState("overview");
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const { data: profile, isLoading } = trpc.learningEngine.threatActor.groupProfile.useQuery(
    { groupId },
    { enabled: !!groupId }
  );

  const { data: threatStats } = trpc.learningEngine.threatActor.threatStats.useQuery();

  // Find this group's detection stats from the overall threat stats
  const groupStats = useMemo(() => {
    if (!threatStats?.topGroups) return null;
    return threatStats.topGroups.find((g: any) => g.groupId === groupId);
  }, [threatStats, groupId]);

  // Group TTPs by tactic
  const ttpsByTactic = useMemo(() => {
    if (!profile?.ttps) return {};
    const grouped: Record<string, any[]> = {};
    for (const ttp of profile.ttps) {
      const tactic = ttp.tactic || "unknown";
      if (!grouped[tactic]) grouped[tactic] = [];
      grouped[tactic].push(ttp);
    }
    return grouped;
  }, [profile]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    toast.success(`Copied ${label}`);
    setTimeout(() => setCopiedText(null), 2000);
  };

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <AlertTriangle className="h-12 w-12 text-muted-foreground/30" />
        <p className="text-muted-foreground">Threat group not found or unavailable.</p>
        <Button variant="outline" onClick={() => navigate("/llm-learning")}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Learning Dashboard
        </Button>
      </div>
    );
  }

  const threatLevelConf = THREAT_LEVEL_CONFIG[profile.threatLevel] || THREAT_LEVEL_CONFIG.medium;
  const typeConf = TYPE_CONFIG[profile.type] || TYPE_CONFIG.apt;
  const TypeIcon = typeConf.icon;

  return (
    <div className="space-y-6">
      {/* ── Page Purpose ── */}
      <p className="text-sm text-muted-foreground">
        Detailed intelligence profile for a specific threat actor, including TTPs, exploited CVEs, tools, and defense recommendations from the learning engine catalog.
      </p>

      {/* ── Header ── */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/llm-learning")} className="mt-1 shrink-0">
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold tracking-tight">{profile.name}</h1>
            <Badge className={`${threatLevelConf.bg} ${threatLevelConf.color} border text-xs`}>
              {profile.threatLevel?.toUpperCase()}
            </Badge>
            <Badge variant="outline" className="text-xs gap-1">
              <TypeIcon className="h-3 w-3" />
              {typeConf.label}
            </Badge>
            {profile.active && (
              <Badge className="bg-green-500/10 text-green-400 border-green-500/30 border text-xs gap-1">
                <Activity className="h-3 w-3" /> Active
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-1.5 max-w-3xl">{profile.description}</p>
          {profile.aliases.length > 0 && (
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              <span className="text-xs text-muted-foreground">AKA:</span>
              {profile.aliases.map((alias: string) => (
                <Badge key={alias} variant="outline" className="text-[10px]">{alias}</Badge>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Quick Stats ── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="border-border">
          <CardContent className="py-4 px-5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <MapPin className="h-3.5 w-3.5" /> Origin
            </div>
            <p className="text-lg font-bold">{profile.origin}</p>
          </CardContent>
        </Card>
        <Card className="border-border">
          <CardContent className="py-4 px-5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Crosshair className="h-3.5 w-3.5" /> TTPs
            </div>
            <p className="text-lg font-bold">{profile.ttps.length}</p>
          </CardContent>
        </Card>
        <Card className="border-border">
          <CardContent className="py-4 px-5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Bug className="h-3.5 w-3.5" /> CVEs
            </div>
            <p className="text-lg font-bold">{profile.exploitedCVEs.length}</p>
          </CardContent>
        </Card>
        <Card className="border-border">
          <CardContent className="py-4 px-5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Wrench className="h-3.5 w-3.5" /> Tools
            </div>
            <p className="text-lg font-bold">{profile.tools.length}</p>
          </CardContent>
        </Card>
        <Card className="border-border">
          <CardContent className="py-4 px-5">
            <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
              <Target className="h-3.5 w-3.5" /> Detections
            </div>
            <p className="text-lg font-bold">{groupStats?.matchCount ?? "—"}</p>
            {groupStats?.avgConfidence != null && (
              <p className="text-[10px] text-muted-foreground mt-0.5">
                {(groupStats.avgConfidence * 100).toFixed(0)}% avg confidence
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Tabs ── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30 border border-border">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="ttps">TTPs ({profile.ttps.length})</TabsTrigger>
          <TabsTrigger value="cves">CVEs & Tools</TabsTrigger>
          <TabsTrigger value="defense">Defense</TabsTrigger>
        </TabsList>

        {/* ── Overview Tab ── */}
        <TabsContent value="overview" className="mt-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Motivation & Targets */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Swords className="h-4 w-4 text-red-400" /> Motivation & Targeting
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <p className="text-xs text-muted-foreground font-medium mb-1">Motivation</p>
                  <p className="text-sm">{profile.motivation}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground font-medium mb-2">Target Sectors</p>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.targetSectors.map((s: string) => (
                      <Badge key={s} variant="outline" className="text-xs gap-1">
                        <Building2 className="h-3 w-3" /> {s}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground font-medium mb-2">Target Regions</p>
                  <div className="flex flex-wrap gap-1.5">
                    {profile.targetRegions.map((r: string) => (
                      <Badge key={r} variant="outline" className="text-xs gap-1">
                        <Globe2 className="h-3 w-3" /> {r}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Initial Access Methods */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-400" /> Initial Access Methods
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {profile.initialAccessMethods.map((method: string, i: number) => (
                    <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg bg-muted/20 border border-border/50">
                      <ChevronRight className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                      <p className="text-sm">{method}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* MITRE Reference */}
          {profile.mitreGroupId && (
            <Card className="border-border">
              <CardContent className="py-4 px-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Shield className="h-5 w-5 text-blue-400" />
                    <div>
                      <p className="text-sm font-medium">MITRE ATT&CK Reference</p>
                      <p className="text-xs text-muted-foreground">Group ID: {profile.mitreGroupId}</p>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs gap-1"
                    onClick={() => window.open(`https://attack.mitre.org/groups/${profile.mitreGroupId}/`, "_blank")}
                  >
                    View on MITRE <ExternalLink className="h-3 w-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── TTPs Tab ── */}
        <TabsContent value="ttps" className="mt-6 space-y-6">
          <p className="text-sm text-muted-foreground">
            Tactics, Techniques, and Procedures mapped to the MITRE ATT&CK framework. Grouped by tactic phase.
          </p>

          {/* TTP Tactic Distribution */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(ttpsByTactic).map(([tactic, ttps]) => {
              const conf = TACTIC_CONFIG[tactic] || { color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20" };
              return (
                <Card key={tactic} className={`${conf.bg} border`}>
                  <CardContent className="py-3 px-4">
                    <p className={`text-xs font-medium ${conf.color}`}>{tactic.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</p>
                    <p className="text-xl font-bold mt-1">{ttps.length}</p>
                    <p className="text-[10px] text-muted-foreground">techniques</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* TTP Details by Tactic */}
          {Object.entries(ttpsByTactic).map(([tactic, ttps]) => {
            const conf = TACTIC_CONFIG[tactic] || { color: "text-gray-400", bg: "bg-gray-500/10 border-gray-500/20" };
            return (
              <Card key={tactic} className="border-border">
                <CardHeader className="pb-3">
                  <CardTitle className={`text-base ${conf.color}`}>
                    {tactic.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {ttps.map((ttp: any, i: number) => (
                      <div key={i} className="flex items-start gap-4 p-3 rounded-lg bg-muted/20 border border-border/50 hover:bg-muted/30 transition-colors">
                        <div className="shrink-0">
                          <Badge className={`${conf.bg} ${conf.color} border text-[10px] font-mono`}>
                            {ttp.techniqueId}
                          </Badge>
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-medium">{ttp.techniqueName}</p>
                            {ttp.frequency && (
                              <Badge variant="outline" className={`text-[10px] ${ttp.frequency === "primary" ? "text-red-400 border-red-500/30" : "text-yellow-400 border-yellow-500/30"}`}>
                                {ttp.frequency}
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">{ttp.description}</p>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 shrink-0"
                          onClick={() => window.open(`https://attack.mitre.org/techniques/${ttp.techniqueId.replace(".", "/")}/`, "_blank")}
                        >
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </TabsContent>

        {/* ── CVEs & Tools Tab ── */}
        <TabsContent value="cves" className="mt-6 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Exploited CVEs */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Bug className="h-4 w-4 text-red-400" /> Exploited CVEs ({profile.exploitedCVEs.length})
                </CardTitle>
                <CardDescription className="text-xs">Known vulnerabilities actively exploited by this group</CardDescription>
              </CardHeader>
              <CardContent>
                {profile.exploitedCVEs.length > 0 ? (
                  <div className="space-y-2">
                    {profile.exploitedCVEs.map((cve: string) => (
                      <div key={cve} className="flex items-center justify-between p-3 rounded-lg bg-muted/20 border border-border/50 hover:bg-muted/30 transition-colors">
                        <div className="flex items-center gap-3">
                          <Badge className="bg-red-500/10 text-red-400 border-red-500/30 border font-mono text-xs">
                            {cve}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => copyToClipboard(cve, cve)}
                          >
                            {copiedText === cve ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, "_blank")}
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <p className="text-sm text-muted-foreground">No specific CVEs documented for this group.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Tools */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Wrench className="h-4 w-4 text-blue-400" /> Tools & Malware ({profile.tools.length})
                </CardTitle>
                <CardDescription className="text-xs">Custom and commodity tools used by this group</CardDescription>
              </CardHeader>
              <CardContent>
                {profile.tools.length > 0 ? (
                  <div className="space-y-2">
                    {profile.tools.map((tool: any, i: number) => (
                      <div key={i} className="p-3 rounded-lg bg-muted/20 border border-border/50">
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium">{tool.name}</p>
                          <Badge variant="outline" className="text-[10px]">{tool.category}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{tool.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-8 text-center">
                    <p className="text-sm text-muted-foreground">No specific tools documented for this group.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── Defense Tab ── */}
        <TabsContent value="defense" className="mt-6 space-y-6">
          <p className="text-sm text-muted-foreground">
            Actionable defense recommendations and detection rules tailored to this threat actor's known TTPs and tooling.
          </p>

          {/* Defense Recommendations */}
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-emerald-400" /> Defense Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {profile.defenseRecommendations.map((rec: any, i: number) => {
                  const prioConf = PRIORITY_CONFIG[rec.priority] || PRIORITY_CONFIG.medium;
                  return (
                    <div key={i} className="p-4 rounded-lg bg-muted/20 border border-border/50 space-y-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge className={`${prioConf.bg} ${prioConf.color} border text-[10px]`}>
                              {rec.priority}
                            </Badge>
                            <Badge variant="outline" className="text-[10px]">{rec.category}</Badge>
                          </div>
                          <p className="text-sm">{rec.recommendation}</p>
                        </div>
                      </div>

                      {rec.siemQuery && (
                        <div className="relative">
                          <p className="text-[10px] text-muted-foreground font-medium mb-1">SIEM Query</p>
                          <div className="bg-background/50 rounded-lg border border-border p-3 pr-10">
                            <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">{rec.siemQuery}</pre>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="absolute top-6 right-1 h-7 w-7"
                            onClick={() => copyToClipboard(rec.siemQuery, `SIEM query ${i + 1}`)}
                          >
                            {copiedText === `SIEM query ${i + 1}` ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                          </Button>
                        </div>
                      )}

                      {rec.mitreTechniques.length > 0 && (
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] text-muted-foreground">Covers:</span>
                          {rec.mitreTechniques.map((t: string) => (
                            <Badge key={t} variant="outline" className="text-[10px] font-mono">{t}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Detection Hints */}
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Eye className="h-4 w-4 text-cyan-400" /> Detection Hints
              </CardTitle>
              <CardDescription className="text-xs">YARA rules, behavioral indicators, and monitoring guidance</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {profile.detectionHints.map((hint: string, i: number) => (
                  <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-muted/20 border border-border/50">
                    <Search className="h-4 w-4 text-cyan-400 mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">{hint}</pre>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 shrink-0"
                      onClick={() => copyToClipboard(hint, `hint ${i + 1}`)}
                    >
                      {copiedText === `hint ${i + 1}` ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
