import { useState } from "react";
import { useRoute, useLocation } from "wouter";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import AttackNavigator from "@/components/AttackNavigator";
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
  ShieldCheck,
  Copy,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Sparkles,
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
            <TabsTrigger value="detection-rules">
              <ShieldCheck className="w-4 h-4 mr-1" /> Detection Rules
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
            <AttackNavigator
              techniques={techniques}
              actorName={actor.name}
              onTechniqueClick={(techId) => {
                window.open(`https://attack.mitre.org/techniques/${techId.replace('.', '/')}/`, '_blank');
              }}
            />
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

          {/* Detection Rules Tab */}
          <TabsContent value="detection-rules" className="space-y-4">
            <DetectionRulesPanel actorId={actorId} actorName={actor.name} techniques={techniques} />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}

// ─── Detection Rules Panel Component ────────────────────────────────────────

function DetectionRulesPanel({ actorId, actorName, techniques }: {
  actorId: string;
  actorName: string;
  techniques: Array<{ id: string; name: string; tactic: string }>;
}) {
  const [generatedRules, setGeneratedRules] = useState<any>(null);
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [filterType, setFilterType] = useState<string>("all");
  const [filterTactic, setFilterTactic] = useState<string>("all");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const generateMutation = trpc.calderaProxy.generateAndValidateActorRules.useMutation({
    onSuccess: (data) => {
      setGeneratedRules(data);
      toast.success(`Generated ${data.totalRules} detection rules for ${actorName}`);
    },
    onError: (err) => toast.error(`Rule generation failed: ${err.message}`),
  });

  const generateLLMMutation = trpc.calderaProxy.generateActorRules.useMutation({
    onSuccess: (data) => {
      setGeneratedRules(data);
      toast.success(`Generated ${data.totalRules} LLM-enhanced rules for ${actorName}`);
    },
    onError: (err) => toast.error(`LLM rule generation failed: ${err.message}`),
  });

  const validateMutation = trpc.calderaProxy.validateRule.useMutation({
    onSuccess: (data) => {
      if (selectedRule) {
        setSelectedRule({ ...selectedRule, validation: data });
      }
      toast.success("Rule validated successfully");
    },
    onError: (err) => toast.error(`Validation failed: ${err.message}`),
  });

  const handleCopy = (ruleContent: string, ruleId: string) => {
    navigator.clipboard.writeText(ruleContent);
    setCopiedId(ruleId);
    setTimeout(() => setCopiedId(null), 2000);
    toast.success("Rule copied to clipboard");
  };

  const filteredRules = generatedRules?.rules?.filter((r: any) => {
    if (filterType !== "all" && r.ruleType !== filterType) return false;
    if (filterTactic !== "all" && r.tactic !== filterTactic) return false;
    return true;
  }) || [];

  const allTactics = generatedRules ? Array.from(new Set((generatedRules.rules || []).map((r: any) => r.tactic))) as string[] : [];

  return (
    <div className="space-y-4">
      {/* Page description */}
      <div className="text-sm text-muted-foreground">
        Auto-generate and validate detection rules (Sigma, YARA, Suricata) from {actorName}'s known TTPs.
        Rules are mapped to specific MITRE ATT&CK techniques and validated for syntax and effectiveness.
      </div>

      {/* Generation Controls */}
      <Card className="bg-card/50">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-amber-400" /> Auto-Generate Detection Rules
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                Generate rules from {techniques.length} known techniques across {Array.from(new Set(techniques.map(t => t.tactic))).length} tactics
              </p>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => generateMutation.mutate({ actorId })}
                disabled={generateMutation.isPending || generateLLMMutation.isPending}
              >
                {generateMutation.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <ShieldCheck className="w-4 h-4 mr-1" />}
                Generate & Validate
              </Button>
              <Button
                size="sm"
                className="bg-amber-600 hover:bg-amber-700"
                onClick={() => generateLLMMutation.mutate({ actorId, useLLM: true })}
                disabled={generateMutation.isPending || generateLLMMutation.isPending}
              >
                {generateLLMMutation.isPending ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Sparkles className="w-4 h-4 mr-1" />}
                LLM-Enhanced Generation
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {generatedRules && (
        <>
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-blue-400">{generatedRules.totalRules}</div>
                <div className="text-xs text-muted-foreground">Total Rules</div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-cyan-400">{generatedRules.rulesByType?.sigma || 0}</div>
                <div className="text-xs text-muted-foreground">Sigma</div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-purple-400">{generatedRules.rulesByType?.yara || 0}</div>
                <div className="text-xs text-muted-foreground">YARA</div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-orange-400">{generatedRules.rulesByType?.suricata || 0}</div>
                <div className="text-xs text-muted-foreground">Suricata</div>
              </CardContent>
            </Card>
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-green-400">
                  {generatedRules.rules?.filter((r: any) => r.validation?.valid).length || generatedRules.rules?.filter((r: any) => r.confidence >= 65).length || 0}
                </div>
                <div className="text-xs text-muted-foreground">Validated</div>
              </CardContent>
            </Card>
          </div>

          {/* Filters */}
          <div className="flex gap-2 flex-wrap">
            <Badge
              variant={filterType === "all" ? "default" : "outline"}
              className="cursor-pointer"
              onClick={() => setFilterType("all")}
            >All Types</Badge>
            {["sigma", "yara", "suricata"].map(t => (
              <Badge
                key={t}
                variant={filterType === t ? "default" : "outline"}
                className="cursor-pointer"
                onClick={() => setFilterType(t)}
              >{t.toUpperCase()}</Badge>
            ))}
            <span className="text-muted-foreground mx-2">|</span>
            <Badge
              variant={filterTactic === "all" ? "default" : "outline"}
              className="cursor-pointer"
              onClick={() => setFilterTactic("all")}
            >All Tactics</Badge>
            {allTactics.map(t => (
              <Badge
                key={t}
                variant={filterTactic === t ? "default" : "outline"}
                className="cursor-pointer capitalize"
                onClick={() => setFilterTactic(t)}
              >{(t as string).replace(/-/g, ' ')}</Badge>
            ))}
          </div>

          {/* Rules Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Rules List */}
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
              {filteredRules.map((rule: any) => (
                <Card
                  key={rule.id}
                  className={`bg-card/50 cursor-pointer transition-colors hover:bg-card/80 ${
                    selectedRule?.id === rule.id ? 'ring-1 ring-primary' : ''
                  }`}
                  onClick={() => setSelectedRule(rule)}
                >
                  <CardContent className="p-3">
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-xs ${
                            rule.ruleType === 'sigma' ? 'border-cyan-500/30 text-cyan-400' :
                            rule.ruleType === 'yara' ? 'border-purple-500/30 text-purple-400' :
                            'border-orange-500/30 text-orange-400'
                          }`}>{rule.ruleType.toUpperCase()}</Badge>
                          <span className="text-sm font-medium truncate">{rule.techniqueName}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <code className="text-xs text-muted-foreground">{rule.techniqueId}</code>
                          <Badge variant="outline" className="text-xs capitalize">{rule.tactic.replace(/-/g, ' ')}</Badge>
                          <Badge variant="outline" className={`text-xs ${
                            rule.severity === 'critical' ? 'border-red-500/30 text-red-400' :
                            rule.severity === 'high' ? 'border-orange-500/30 text-orange-400' :
                            rule.severity === 'medium' ? 'border-yellow-500/30 text-yellow-400' :
                            'border-green-500/30 text-green-400'
                          }`}>{rule.severity}</Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        {rule.validation ? (
                          rule.validation.valid ? (
                            <CheckCircle2 className="w-4 h-4 text-green-400" />
                          ) : (
                            <XCircle className="w-4 h-4 text-red-400" />
                          )
                        ) : (
                          <div className="w-8 h-8 rounded-full flex items-center justify-center bg-muted/50">
                            <span className="text-xs font-bold">{rule.confidence}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {filteredRules.length === 0 && (
                <div className="text-center py-8 text-muted-foreground text-sm">
                  No rules match the current filters.
                </div>
              )}
            </div>

            {/* Rule Detail Panel */}
            <div className="space-y-3">
              {selectedRule ? (
                <>
                  <Card className="bg-card/50">
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm">{selectedRule.ruleName}</CardTitle>
                        <div className="flex gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleCopy(selectedRule.ruleContent, selectedRule.id)}
                          >
                            {copiedId === selectedRule.id ? (
                              <CheckCircle2 className="w-4 h-4 text-green-400" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => validateMutation.mutate({
                              ruleType: selectedRule.ruleType,
                              ruleContent: selectedRule.ruleContent,
                              ruleName: selectedRule.ruleName,
                              techniqueId: selectedRule.techniqueId,
                              useLLM: true,
                            })}
                            disabled={validateMutation.isPending}
                          >
                            {validateMutation.isPending ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <ShieldCheck className="w-3 h-3 mr-1" />}
                            Deep Validate
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <pre className="text-xs bg-black/40 p-3 rounded-lg overflow-x-auto max-h-[300px] overflow-y-auto font-mono leading-relaxed">
                        {selectedRule.ruleContent}
                      </pre>
                      <div className="flex items-center gap-3 mt-3 text-xs text-muted-foreground">
                        <span>Platform: {selectedRule.platform}</span>
                        <span>Data Source: {selectedRule.dataSource}</span>
                        <span>Confidence: {selectedRule.confidence}%</span>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Validation Results */}
                  {selectedRule.validation && (
                    <Card className="bg-card/50">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm flex items-center gap-2">
                          {selectedRule.validation.valid ? (
                            <CheckCircle2 className="w-4 h-4 text-green-400" />
                          ) : (
                            <XCircle className="w-4 h-4 text-red-400" />
                          )}
                          Validation Results
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div className="grid grid-cols-3 gap-2">
                          <div className="text-center p-2 bg-muted/30 rounded">
                            <div className="text-lg font-bold">{selectedRule.validation.effectivenessScore}</div>
                            <div className="text-xs text-muted-foreground">Effectiveness</div>
                          </div>
                          <div className="text-center p-2 bg-muted/30 rounded">
                            <div className={`text-lg font-bold ${
                              selectedRule.validation.falsePositiveRisk === 'low' ? 'text-green-400' :
                              selectedRule.validation.falsePositiveRisk === 'medium' ? 'text-yellow-400' :
                              'text-red-400'
                            }`}>{selectedRule.validation.falsePositiveRisk}</div>
                            <div className="text-xs text-muted-foreground">FP Risk</div>
                          </div>
                          <div className="text-center p-2 bg-muted/30 rounded">
                            <div className="text-lg font-bold">{selectedRule.validation.syntaxErrors?.length || 0}</div>
                            <div className="text-xs text-muted-foreground">Issues</div>
                          </div>
                        </div>

                        {selectedRule.validation.syntaxErrors?.length > 0 && (
                          <div className="space-y-1">
                            <div className="text-xs font-medium text-red-400">Syntax Issues:</div>
                            {selectedRule.validation.syntaxErrors.map((e: any, i: number) => (
                              <div key={i} className="text-xs bg-red-500/10 p-2 rounded flex items-start gap-2">
                                <AlertCircle className="w-3 h-3 mt-0.5 text-red-400 shrink-0" />
                                <span>{e.message}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {selectedRule.validation.suggestions?.length > 0 && (
                          <div className="space-y-1">
                            <div className="text-xs font-medium text-amber-400">Suggestions:</div>
                            {selectedRule.validation.suggestions.map((s: string, i: number) => (
                              <div key={i} className="text-xs bg-amber-500/10 p-2 rounded flex items-start gap-2">
                                <Sparkles className="w-3 h-3 mt-0.5 text-amber-400 shrink-0" />
                                <span>{s}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {selectedRule.validation.llmAnalysis && (
                          <div className="space-y-1">
                            <div className="text-xs font-medium text-blue-400">LLM Analysis:</div>
                            <div className="text-xs bg-blue-500/10 p-3 rounded leading-relaxed">
                              {selectedRule.validation.llmAnalysis}
                            </div>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  )}
                </>
              ) : (
                <Card className="bg-card/50">
                  <CardContent className="p-8 text-center text-muted-foreground">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">Select a rule from the list to view its content and validation results.</p>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>

          {/* Export All */}
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                const allRules = generatedRules.rules.map((r: any) =>
                  `# ${r.ruleName}\n# Technique: ${r.techniqueId} - ${r.techniqueName}\n# Tactic: ${r.tactic}\n# Severity: ${r.severity}\n# Confidence: ${r.confidence}%\n\n${r.ruleContent}`
                ).join('\n\n---\n\n');
                const blob = new Blob([allRules], { type: 'text/plain' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${actorName.replace(/\s+/g, '_')}_detection_rules.txt`;
                a.click();
                URL.revokeObjectURL(url);
                toast.success('Detection rules exported');
              }}
            >
              <Download className="w-4 h-4 mr-1" /> Export All Rules
            </Button>
          </div>
        </>
      )}

      {!generatedRules && !generateMutation.isPending && !generateLLMMutation.isPending && (
        <Card className="bg-card/50">
          <CardContent className="p-8 text-center text-muted-foreground">
            <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">Click "Generate & Validate" to auto-generate detection rules from {actorName}'s {techniques.length} known techniques.</p>
            <p className="text-xs mt-1">Rules will be generated as Sigma, YARA, and Suricata formats where applicable.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
