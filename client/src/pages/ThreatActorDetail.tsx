import { useState } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  ArrowLeft,
  Shield,
  Globe,
  Target,
  Crosshair,
  Cpu,
  Bug,
  Calendar,
  AlertTriangle,
  Zap,
  RefreshCw,
  Loader2,
  Fingerprint,
  MapPin,
  Clock,
  BookOpen,
  Swords,
  Upload,
  FileText,
  ChevronRight,
  Download,
} from "lucide-react";

// MITRE ATT&CK Tactic colors
const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "bg-slate-600",
  "resource-development": "bg-slate-500",
  "initial-access": "bg-red-700",
  "execution": "bg-red-600",
  "persistence": "bg-orange-700",
  "privilege-escalation": "bg-orange-600",
  "defense-evasion": "bg-yellow-700",
  "credential-access": "bg-yellow-600",
  "discovery": "bg-green-700",
  "lateral-movement": "bg-green-600",
  "collection": "bg-teal-700",
  "command-and-control": "bg-blue-700",
  "exfiltration": "bg-blue-600",
  "impact": "bg-purple-700",
};

const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

function ThreatLevelBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <Badge className={`${colors[level] || colors.medium} border`}>
      {level?.toUpperCase() || "UNKNOWN"}
    </Badge>
  );
}

function ActorTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    apt: "bg-red-500/20 text-red-400 border-red-500/30",
    cybercrime: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    ransomware: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    hacktivist: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };
  return (
    <Badge className={`${colors[type] || colors.unknown} border`}>
      {type?.toUpperCase() || "UNKNOWN"}
    </Badge>
  );
}

function SophisticationBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    "nation-state": "bg-red-500/20 text-red-400",
    "advanced": "bg-orange-500/20 text-orange-400",
    "intermediate": "bg-yellow-500/20 text-yellow-400",
    "basic": "bg-green-500/20 text-green-400",
  };
  return (
    <Badge variant="outline" className={colors[level] || ""}>
      {level || "Unknown"}
    </Badge>
  );
}

export default function ThreatActorDetail() {
  const [, params] = useRoute("/threat-actors/:actorId");
  const [, setLocation] = useLocation();
  const actorId = params?.actorId || "";

  const { data: actor, isLoading, refetch } = trpc.threatActorDb.get.useQuery(
    { actorId },
    { enabled: !!actorId }
  );

  const { data: abilities } = trpc.abilitiesLibrary.byActor.useQuery(
    { actorId },
    { enabled: !!actorId }
  );

  const enrichMutation = trpc.threatActorDb.enrich.useMutation({
    onSuccess: () => {
      toast.success("Threat actor enriched with latest intelligence");
      refetch();
    },
    onError: (err) => toast.error(`Enrichment failed: ${err.message}`),
  });

  const deployMutation = trpc.calderaProxy.createAdversary.useMutation({
    onSuccess: () => toast.success("Adversary profile deployed to Caldera"),
    onError: (err) => toast.error(`Deploy failed: ${err.message}`),
  });

  const [activeTab, setActiveTab] = useState("overview");

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center min-h-[60vh]">
          <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        </div>
      </AppShell>
    );
  }

  if (!actor) {
    return (
      <AppShell>
        <div className="p-6">
          <Button variant="ghost" onClick={() => setLocation("/threat-actors")}>
            <ArrowLeft className="w-4 h-4 mr-2" /> Back
          </Button>
          <div className="text-center py-20 text-muted-foreground">
            Threat actor not found: {actorId}
          </div>
        </div>
      </AppShell>
    );
  }

  // Parse JSON fields safely
  const aliases = (actor.aliases as string[]) || [];
  const techniques = (actor.techniques as Array<{ id: string; name: string; tactic: string; score?: number; description?: string }>) || [];
  const tools = (actor.tools as string[]) || [];
  const malware = (actor.malware as string[]) || [];
  const targetSectors = (actor.targetSectors as string[]) || [];
  const targetRegions = (actor.targetRegions as string[]) || [];
  const activityTimeline = (actor.activityTimeline as Array<{ date: string; event: string; source?: string }>) || [];
  const calderaProfile = actor.calderaProfile as { id?: string; atomicOrdering?: string[]; objectives?: string[] } | null;

  // Group techniques by tactic for the heatmap
  const techniquesByTactic: Record<string, Array<{ id: string; name: string; score?: number }>> = {};
  for (const t of techniques) {
    const tactic = t.tactic || "unknown";
    if (!techniquesByTactic[tactic]) techniquesByTactic[tactic] = [];
    techniquesByTactic[tactic].push(t);
  }

  // Sort tactics by MITRE order
  const sortedTactics = TACTIC_ORDER.filter(t => techniquesByTactic[t]);
  const otherTactics = Object.keys(techniquesByTactic).filter(t => !TACTIC_ORDER.includes(t));
  const allTactics = [...sortedTactics, ...otherTactics];

  const handleSimulate = () => {
    if (calderaProfile) {
      deployMutation.mutate({
        adversary_id: actorId,
        name: actor.name,
        description: `Adversary emulation for ${actor.name}`,
        atomic_ordering: calderaProfile.atomicOrdering || [],
        objective: calderaProfile.objectives?.[0] || `Simulate ${actor.name} TTPs`,
      });
    } else {
      // Auto-generate adversary from techniques
      const abilityIds = techniques.map(t => t.id);
      deployMutation.mutate({
        adversary_id: actorId,
        name: actor.name,
        description: `Auto-generated adversary emulation for ${actor.name} based on ${techniques.length} known techniques`,
        atomic_ordering: abilityIds.slice(0, 20),
        objective: `Emulate ${actor.name} attack patterns`,
      });
    }
  };

  return (
    <AppShell>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="space-y-3">
            <Button variant="ghost" size="sm" onClick={() => setLocation("/threat-actors")}>
              <ArrowLeft className="w-4 h-4 mr-1" /> Back to Threat Actors
            </Button>
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-lg bg-red-500/20 flex items-center justify-center">
                <Shield className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">{actor.name}</h1>
                <div className="flex items-center gap-2 mt-1">
                  <ActorTypeBadge type={actor.type} />
                  <ThreatLevelBadge level={actor.threatLevel || "medium"} />
                  <SophisticationBadge level={actor.sophistication || "intermediate"} />
                  {actor.origin && (
                    <Badge variant="outline" className="gap-1">
                      <Globe className="w-3 h-3" /> {actor.origin}
                    </Badge>
                  )}
                  {actor.confidence && (
                    <Badge variant="outline" className="text-xs">
                      Confidence: {actor.confidence}%
                    </Badge>
                  )}
                </div>
              </div>
            </div>
            {aliases.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-muted-foreground">Also known as:</span>
                {aliases.map((a, i) => (
                  <Badge key={i} variant="secondary" className="text-xs">{a}</Badge>
                ))}
              </div>
            )}
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => enrichMutation.mutate({ actorId })}
              disabled={enrichMutation.isPending}
            >
              {enrichMutation.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-1" />}
              Enrich with LLM
            </Button>
            <Button
              size="sm"
              className="bg-red-600 hover:bg-red-700"
              onClick={handleSimulate}
              disabled={deployMutation.isPending}
            >
              {deployMutation.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Swords className="w-4 h-4 mr-1" />}
              Simulate This Actor
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setLocation(`/template-generator?actor=${actorId}`)}
            >
              <FileText className="w-4 h-4 mr-1" /> Generate Phishing Template
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
              onClick={() => {
                const link = document.createElement('a');
                link.href = `/api/export/detection-rules/${actorId}`;
                link.download = `${actor?.name || actorId}_detection_rules.zip`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                toast.success('Downloading detection rules pack...');
              }}
            >
              <Download className="w-4 h-4 mr-1" /> Download Rules Pack
            </Button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-red-400">{techniques.length}</div>
              <div className="text-xs text-muted-foreground">Techniques</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-orange-400">{allTactics.length}</div>
              <div className="text-xs text-muted-foreground">Tactics</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{tools.length}</div>
              <div className="text-xs text-muted-foreground">Tools</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{malware.length}</div>
              <div className="text-xs text-muted-foreground">Malware</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-green-400">{targetSectors.length}</div>
              <div className="text-xs text-muted-foreground">Target Sectors</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50">
            <CardContent className="p-3 text-center">
              <div className="text-2xl font-bold text-cyan-400">{(abilities as any[])?.length || 0}</div>
              <div className="text-xs text-muted-foreground">Caldera Abilities</div>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/50">
            <TabsTrigger value="overview">
              <BookOpen className="w-4 h-4 mr-1" /> Overview
            </TabsTrigger>
            <TabsTrigger value="techniques">
              <Target className="w-4 h-4 mr-1" /> ATT&CK Heatmap
            </TabsTrigger>
            <TabsTrigger value="tools">
              <Cpu className="w-4 h-4 mr-1" /> Tools & Malware
            </TabsTrigger>
            <TabsTrigger value="timeline">
              <Calendar className="w-4 h-4 mr-1" /> Activity Timeline
            </TabsTrigger>
            <TabsTrigger value="abilities">
              <Zap className="w-4 h-4 mr-1" /> Caldera Abilities
            </TabsTrigger>
            <TabsTrigger value="targeting">
              <Crosshair className="w-4 h-4 mr-1" /> Targeting
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card className="lg:col-span-2 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <BookOpen className="w-5 h-5 text-blue-400" /> Intelligence Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-invert prose-sm max-w-none">
                    {actor.description ? (
                      actor.description.split('\n').map((para, i) => (
                        <p key={i} className="text-muted-foreground leading-relaxed">{para}</p>
                      ))
                    ) : (
                      <p className="text-muted-foreground italic">
                        No detailed intelligence available. Click "Enrich with LLM" to generate a comprehensive profile.
                      </p>
                    )}
                  </div>
                  {actor.dataSource && (
                    <div className="mt-4 pt-4 border-t border-border">
                      <span className="text-xs text-muted-foreground">
                        Source: {actor.dataSource} | Last updated: {new Date(actor.updatedAt).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </CardContent>
              </Card>

              <div className="space-y-4">
                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Fingerprint className="w-4 h-4 text-purple-400" /> Identity
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Actor ID</span>
                      <code className="text-xs bg-muted px-2 py-0.5 rounded">{actor.actorId}</code>
                    </div>
                    {actor.stixId && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">STIX ID</span>
                        <code className="text-xs bg-muted px-2 py-0.5 rounded truncate max-w-[180px]">{actor.stixId}</code>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Motivation</span>
                      <span>{actor.motivation || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">First Seen</span>
                      <span>{actor.firstSeen || "Unknown"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last Active</span>
                      <span>{actor.lastActive || "Unknown"}</span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-card/50">
                  <CardHeader>
                    <CardTitle className="text-sm flex items-center gap-2">
                      <MapPin className="w-4 h-4 text-green-400" /> Origin & Attribution
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm">{actor.origin || "Unknown"}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm capitalize">{actor.sophistication || "Unknown"} sophistication</span>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* ATT&CK Heatmap Tab */}
          <TabsContent value="techniques" className="space-y-4">
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Target className="w-5 h-5 text-red-400" /> MITRE ATT&CK Technique Heatmap
                </CardTitle>
              </CardHeader>
              <CardContent>
                {allTactics.length === 0 ? (
                  <p className="text-muted-foreground text-center py-8">
                    No technique data available. Click "Enrich with LLM" to populate.
                  </p>
                ) : (
                  <div className="space-y-4">
                    {/* Tactic summary bar */}
                    <div className="flex gap-1 h-8 rounded-lg overflow-hidden">
                      {allTactics.map(tactic => {
                        const count = techniquesByTactic[tactic]?.length || 0;
                        const pct = (count / techniques.length) * 100;
                        return (
                          <div
                            key={tactic}
                            className={`${TACTIC_COLORS[tactic] || "bg-gray-600"} relative group cursor-pointer`}
                            style={{ width: `${Math.max(pct, 3)}%` }}
                            title={`${tactic}: ${count} techniques`}
                          >
                            <div className="absolute inset-0 flex items-center justify-center">
                              <span className="text-[10px] font-bold text-white/80 truncate px-1">{count}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Technique grid by tactic */}
                    <div className="space-y-3">
                      {allTactics.map(tactic => (
                        <div key={tactic} className="space-y-1">
                          <div className="flex items-center gap-2">
                            <div className={`w-3 h-3 rounded-sm ${TACTIC_COLORS[tactic] || "bg-gray-600"}`} />
                            <h4 className="text-sm font-semibold capitalize">
                              {tactic.replace(/-/g, " ")}
                            </h4>
                            <Badge variant="secondary" className="text-xs">
                              {techniquesByTactic[tactic]?.length || 0}
                            </Badge>
                          </div>
                          <div className="flex flex-wrap gap-1 pl-5">
                            {techniquesByTactic[tactic]?.map((tech, i) => (
                              <Badge
                                key={i}
                                variant="outline"
                                className={`text-xs cursor-default hover:bg-muted ${
                                  (tech.score || 0) >= 8 ? "border-red-500/50 text-red-400" :
                                  (tech.score || 0) >= 5 ? "border-orange-500/50 text-orange-400" :
                                  "border-border"
                                }`}
                                title={tech.name}
                              >
                                {tech.id}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tools & Malware Tab */}
          <TabsContent value="tools" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-blue-400" /> Tools ({tools.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {tools.length === 0 ? (
                    <p className="text-muted-foreground text-sm">No tool data available.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {tools.map((tool, i) => (
                        <Badge key={i} variant="outline" className="bg-blue-500/10 border-blue-500/30 text-blue-300">
                          <Cpu className="w-3 h-3 mr-1" /> {tool}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Bug className="w-5 h-5 text-purple-400" /> Malware ({malware.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {malware.length === 0 ? (
                    <p className="text-muted-foreground text-sm">No malware data available.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {malware.map((m, i) => (
                        <Badge key={i} variant="outline" className="bg-purple-500/10 border-purple-500/30 text-purple-300">
                          <Bug className="w-3 h-3 mr-1" /> {m}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Activity Timeline Tab */}
          <TabsContent value="timeline" className="space-y-4">
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Calendar className="w-5 h-5 text-green-400" /> Activity Timeline
                </CardTitle>
              </CardHeader>
              <CardContent>
                {activityTimeline.length === 0 ? (
                  <div className="text-center py-8">
                    <Clock className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-muted-foreground">No timeline data available.</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Click "Enrich with LLM" to generate a detailed activity timeline.
                    </p>
                  </div>
                ) : (
                  <div className="relative">
                    <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-border" />
                    <div className="space-y-4">
                      {activityTimeline
                        .sort((a, b) => (b.date || "").localeCompare(a.date || ""))
                        .map((event, i) => (
                          <div key={i} className="relative pl-10">
                            <div className="absolute left-2.5 w-3 h-3 rounded-full bg-primary border-2 border-background" />
                            <div className="bg-muted/30 rounded-lg p-3">
                              <div className="flex items-center gap-2 mb-1">
                                <Badge variant="outline" className="text-xs">
                                  <Calendar className="w-3 h-3 mr-1" /> {event.date}
                                </Badge>
                                {event.source && (
                                  <span className="text-xs text-muted-foreground">
                                    via {event.source}
                                  </span>
                                )}
                              </div>
                              <p className="text-sm">{event.event}</p>
                            </div>
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Caldera Abilities Tab */}
          <TabsContent value="abilities" className="space-y-4">
            <Card className="bg-card/50">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Zap className="w-5 h-5 text-amber-400" /> Caldera Abilities
                </CardTitle>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setLocation(`/abilities-library?actor=${actorId}`)}
                >
                  View in Library <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </CardHeader>
              <CardContent>
                {!abilities || (abilities as any[]).length === 0 ? (
                  <div className="text-center py-8">
                    <Zap className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-muted-foreground">No Caldera abilities mapped for this actor.</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Use the Abilities Library to add abilities for this threat actor.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {(abilities as any[]).map((ability: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                        <div className="flex items-center gap-3">
                          <div className={`w-2 h-8 rounded-full ${TACTIC_COLORS[ability.tactic] || "bg-gray-600"}`} />
                          <div>
                            <div className="font-medium text-sm">{ability.name}</div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <Badge variant="outline" className="text-xs">{ability.techniqueId}</Badge>
                              <span className="text-xs text-muted-foreground capitalize">
                                {ability.tactic?.replace(/-/g, " ")}
                              </span>
                            </div>
                          </div>
                        </div>
                        <Badge variant="secondary" className="text-xs">
                          {ability.abilityId}
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}

                {calderaProfile && (
                  <div className="mt-4 pt-4 border-t border-border">
                    <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <Upload className="w-4 h-4" /> Adversary Profile
                    </h4>
                    <div className="bg-muted/30 rounded-lg p-3 text-sm space-y-2">
                      {calderaProfile.id && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Profile ID</span>
                          <code className="text-xs">{calderaProfile.id}</code>
                        </div>
                      )}
                      {calderaProfile.atomicOrdering && (
                        <div>
                          <span className="text-muted-foreground">Atomic Ordering:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {calderaProfile.atomicOrdering.map((id, i) => (
                              <Badge key={i} variant="outline" className="text-xs">{id}</Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Targeting Tab */}
          <TabsContent value="targeting" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Target className="w-5 h-5 text-red-400" /> Target Sectors ({targetSectors.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {targetSectors.length === 0 ? (
                    <p className="text-muted-foreground text-sm">No sector targeting data available.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {targetSectors.map((sector, i) => (
                        <Badge key={i} variant="outline" className="bg-red-500/10 border-red-500/30">
                          <Crosshair className="w-3 h-3 mr-1" /> {sector}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card className="bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Globe className="w-5 h-5 text-blue-400" /> Target Regions ({targetRegions.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {targetRegions.length === 0 ? (
                    <p className="text-muted-foreground text-sm">No regional targeting data available.</p>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      {targetRegions.map((region, i) => (
                        <Badge key={i} variant="outline" className="bg-blue-500/10 border-blue-500/30">
                          <MapPin className="w-3 h-3 mr-1" /> {region}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Threat Assessment */}
            <Card className="bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-amber-400" /> Threat Assessment
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-lg font-bold text-red-400">{actor.threatLevel?.toUpperCase()}</div>
                    <div className="text-xs text-muted-foreground mt-1">Threat Level</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-lg font-bold text-orange-400 capitalize">{actor.sophistication}</div>
                    <div className="text-xs text-muted-foreground mt-1">Sophistication</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-lg font-bold text-blue-400 capitalize">{actor.motivation || "Unknown"}</div>
                    <div className="text-xs text-muted-foreground mt-1">Motivation</div>
                  </div>
                  <div className="text-center p-4 bg-muted/30 rounded-lg">
                    <div className="text-lg font-bold text-green-400">{actor.confidence || "N/A"}%</div>
                    <div className="text-xs text-muted-foreground mt-1">Attribution Confidence</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
