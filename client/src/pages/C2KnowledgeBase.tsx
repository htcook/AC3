import React, { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import {
  Brain, Shield, Crosshair, Zap, Network, Eye, Server,
  Terminal, Radio, Cpu, Flame, Crown, Target, ChevronRight,
  BarChart3, Lock, Unlock, AlertTriangle, CheckCircle2,
  Play, Loader2, BookOpen, Layers, Swords, ArrowRight,
} from "lucide-react";

// ─── Framework Profiles Tab ─────────────────────────────────────────────────

function FrameworkProfilesTab() {
  const { data: profiles, isLoading } = trpc.c2KnowledgeBase.getFrameworkProfiles.useQuery();
  const [selectedFw, setSelectedFw] = useState<string | null>(null);

  const fwIcons: Record<string, React.ReactNode> = {
    caldera: <Target className="h-5 w-5 text-red-400" />,
    metasploit: <Terminal className="h-5 w-5 text-blue-400" />,
    sliver: <Cpu className="h-5 w-5 text-green-400" />,
    empire: <Crown className="h-5 w-5 text-purple-400" />,
    cobaltstrike: <Crosshair className="h-5 w-5 text-orange-400" />,
    manjusaka: <Flame className="h-5 w-5 text-pink-400" />,
  };

  const detectionColors: Record<string, string> = {
    "very-hard": "text-green-400",
    hard: "text-emerald-400",
    moderate: "text-yellow-400",
    easy: "text-red-400",
  };

  const noiseColors: Record<string, string> = {
    minimal: "text-green-400",
    low: "text-emerald-400",
    moderate: "text-yellow-400",
    high: "text-red-400",
  };

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[1, 2, 3, 4, 5, 6].map(i => (
          <Card key={i} className="animate-pulse bg-card/50">
            <CardContent className="h-48" />
          </Card>
        ))}
      </div>
    );
  }

  const selected = profiles?.find(p => p.id === selectedFw);

  return (
    <div className="space-y-6">
      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {profiles?.map(profile => (
          <Card
            key={profile.id}
            className={`cursor-pointer transition-all hover:border-primary/50 ${selectedFw === profile.id ? "border-primary ring-1 ring-primary/30" : ""}`}
            onClick={() => setSelectedFw(selectedFw === profile.id ? null : profile.id)}
          >
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                {fwIcons[profile.id]}
                <div className="min-w-0">
                  <CardTitle className="text-base">{profile.displayName}</CardTitle>
                  <CardDescription className="text-xs line-clamp-2 mt-1">
                    {profile.description.split(".")[0]}
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Detection:</span>{" "}
                  <span className={detectionColors[profile.opsecProfile.detectionDifficulty]}>
                    {profile.opsecProfile.detectionDifficulty}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Noise:</span>{" "}
                  <span className={noiseColors[profile.opsecProfile.networkNoise]}>
                    {profile.opsecProfile.networkNoise}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Techniques:</span>{" "}
                  <span className="text-foreground font-mono">{profile.totalTechniques}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Post-Exploit:</span>{" "}
                  <span className="text-foreground font-mono">{profile.totalPostExploitCapabilities}</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-1">
                {profile.platforms.map(p => (
                  <Badge key={p} variant="outline" className="text-[10px] px-1.5 py-0">
                    {p}
                  </Badge>
                ))}
              </div>
              <div className="flex flex-wrap gap-1">
                {profile.bestPhases.slice(0, 3).map(phase => (
                  <Badge key={phase} className="text-[10px] px-1.5 py-0 bg-primary/20 text-primary">
                    {phase.replace(/_/g, " ")}
                  </Badge>
                ))}
                {profile.bestPhases.length > 3 && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                    +{profile.bestPhases.length - 3}
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Expanded Detail Panel */}
      {selected && (
        <Card className="border-primary/30">
          <CardHeader>
            <div className="flex items-center gap-3">
              {fwIcons[selected.id]}
              <div>
                <CardTitle>{selected.displayName} — Tactical Profile</CardTitle>
                <CardDescription>{selected.description}</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Primary Use Cases */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Zap className="h-4 w-4 text-yellow-400" /> Primary Use Cases
              </h4>
              <div className="flex flex-wrap gap-2">
                {selected.primaryUseCases.map(uc => (
                  <Badge key={uc} variant="secondary" className="text-xs">{uc}</Badge>
                ))}
              </div>
            </div>

            {/* OPSEC Profile */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Eye className="h-4 w-4 text-green-400" /> OPSEC Profile
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Network Noise</div>
                  <div className={`text-sm font-semibold ${noiseColors[selected.opsecProfile.networkNoise]}`}>
                    {selected.opsecProfile.networkNoise}
                  </div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Disk Artifacts</div>
                  <div className="text-sm font-semibold">{selected.opsecProfile.diskArtifacts}</div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Memory</div>
                  <div className="text-sm font-semibold">{selected.opsecProfile.memoryFootprint}</div>
                </div>
                <div className="bg-muted/30 rounded-lg p-3 text-center">
                  <div className="text-xs text-muted-foreground">Sleep/Jitter</div>
                  <div className="text-sm font-semibold text-xs">{selected.opsecProfile.defaultSleepJitter}</div>
                </div>
              </div>
            </div>

            {/* Evasion Capabilities */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Shield className="h-4 w-4 text-blue-400" /> Evasion Capabilities
              </h4>
              <div className="space-y-2">
                {selected.evasionCapabilities.map((ev, i) => (
                  <div key={i} className="flex items-start gap-3 bg-muted/20 rounded-lg p-3">
                    <Badge
                      variant={ev.effectiveness === "high" ? "default" : "secondary"}
                      className={`text-[10px] shrink-0 ${ev.effectiveness === "high" ? "bg-green-500/20 text-green-400" : ev.effectiveness === "medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-red-500/20 text-red-400"}`}
                    >
                      {ev.effectiveness}
                    </Badge>
                    <div className="min-w-0">
                      <div className="text-sm font-medium">{ev.technique}</div>
                      <div className="text-xs text-muted-foreground">{ev.description}</div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {ev.bypassesDefenses.map(d => (
                          <Badge key={d} variant="outline" className="text-[9px] px-1 py-0">{d}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Post-Exploitation Capabilities */}
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Swords className="h-4 w-4 text-red-400" /> Post-Exploitation Capabilities
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {selected.postExploitCapabilities.map((cap, i) => (
                  <div key={i} className="bg-muted/20 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium">{cap.name}</span>
                      <Badge variant="outline" className="text-[9px] px-1 py-0">
                        {cap.requiredPrivilege}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">{cap.description}</div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {cap.techniqueIds.slice(0, 4).map(t => (
                        <Badge key={t} className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400">{t}</Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* When to Use / Avoid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400" /> Prefer When
                </h4>
                <ul className="space-y-1">
                  {selected.preferWhen.map((w, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-green-400 shrink-0" />
                      {w}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-400" /> Avoid When
                </h4>
                <ul className="space-y-1">
                  {selected.avoidWhen.map((w, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-yellow-400 shrink-0" />
                      {w}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Framework Recommendation Tab ───────────────────────────────────────────

function RecommendationTab() {
  const [platform, setPlatform] = useState<string>("windows");
  const [phase, setPhase] = useState<string>("initial_access");
  const [stealth, setStealth] = useState<string>("high");
  const [hasAD, setHasAD] = useState(true);

  const { data: recommendation, isLoading } = trpc.c2KnowledgeBase.getRecommendation.useQuery({
    targetPlatform: platform as any,
    engagementPhase: phase as any,
    stealthRequired: stealth as any,
    hasActiveDirectory: hasAD,
  });

  const fwColors: Record<string, string> = {
    caldera: "text-red-400",
    metasploit: "text-blue-400",
    sliver: "text-green-400",
    empire: "text-purple-400",
    cobaltstrike: "text-orange-400",
    manjusaka: "text-pink-400",
  };

  return (
    <div className="space-y-6">
      {/* Selection Controls */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Brain className="h-5 w-5 text-primary" /> Engagement Context
          </CardTitle>
          <CardDescription>Configure your engagement parameters to get a C2 framework recommendation</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Platform</label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="mixed">Mixed</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Engagement Phase</label>
              <Select value={phase} onValueChange={setPhase}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="initial_access">Initial Access</SelectItem>
                  <SelectItem value="execution">Execution</SelectItem>
                  <SelectItem value="persistence">Persistence</SelectItem>
                  <SelectItem value="privilege_escalation">Privilege Escalation</SelectItem>
                  <SelectItem value="defense_evasion">Defense Evasion</SelectItem>
                  <SelectItem value="credential_access">Credential Access</SelectItem>
                  <SelectItem value="discovery">Discovery</SelectItem>
                  <SelectItem value="lateral_movement">Lateral Movement</SelectItem>
                  <SelectItem value="collection_exfiltration">Collection/Exfil</SelectItem>
                  <SelectItem value="impact">Impact</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Stealth Required</label>
              <Select value={stealth} onValueChange={setStealth}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="maximum">Maximum</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="moderate">Moderate</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Active Directory</label>
              <Select value={hasAD ? "yes" : "no"} onValueChange={v => setHasAD(v === "yes")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="yes">Yes — AD Environment</SelectItem>
                  <SelectItem value="no">No — Standalone</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recommendation Result */}
      {recommendation && (
        <div className="space-y-4">
          <Card className="border-primary/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-primary" /> Recommendation
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="bg-primary/10 rounded-xl p-4 text-center">
                  <div className="text-xs text-muted-foreground">Primary</div>
                  <div className={`text-lg font-bold ${fwColors[recommendation.primary]}`}>
                    {recommendation.primary.toUpperCase()}
                  </div>
                </div>
                {recommendation.secondary && (
                  <>
                    <ArrowRight className="h-5 w-5 text-muted-foreground" />
                    <div className="bg-muted/30 rounded-xl p-4 text-center">
                      <div className="text-xs text-muted-foreground">Fallback</div>
                      <div className={`text-lg font-bold ${fwColors[recommendation.secondary]}`}>
                        {recommendation.secondary.toUpperCase()}
                      </div>
                    </div>
                  </>
                )}
              </div>
              <p className="text-sm text-muted-foreground">{recommendation.reasoning}</p>

              {recommendation.suggestedModules.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold mb-2">Suggested Modules</h4>
                  <ul className="space-y-1">
                    {recommendation.suggestedModules.map((mod, i) => (
                      <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                        <ChevronRight className="h-3 w-3 mt-0.5 text-primary shrink-0" />
                        {mod}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {recommendation.opsecWarnings.length > 0 && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                  <h4 className="text-sm font-semibold text-yellow-400 mb-1 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" /> OPSEC Warnings
                  </h4>
                  {recommendation.opsecWarnings.map((w, i) => (
                    <p key={i} className="text-xs text-yellow-300/80">{w}</p>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Chain Strategy */}
          {recommendation.chainStrategy && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Layers className="h-5 w-5 text-blue-400" /> Multi-Framework Chain Strategy
                </CardTitle>
                <CardDescription>{recommendation.chainStrategy.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {recommendation.chainStrategy.stages.map((stage, i) => (
                    <div key={i} className="flex items-start gap-3">
                      <div className="bg-primary/20 rounded-full w-7 h-7 flex items-center justify-center text-xs font-bold shrink-0">
                        {i + 1}
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <Badge className={`text-[10px] ${fwColors[stage.framework]}`}>
                            {stage.framework}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {stage.phase.replace(/_/g, " ")}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{stage.purpose}</p>
                        <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                          Handoff: {stage.handoffTrigger}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Adversary Profile Generator Tab ────────────────────────────────────────

function AdversaryProfileTab() {
  const { data: topActors, isLoading: loadingActors } = trpc.c2KnowledgeBase.getTopActors.useQuery({ limit: 20 });
  const { data: batchScores, isLoading: loadingScores } = trpc.c2KnowledgeBase.batchScoreCompleteness.useQuery({ limit: 30, minAbilities: 5 });
  const [selectedActor, setSelectedActor] = useState<string | null>(null);

  const { data: actorMapping } = trpc.c2KnowledgeBase.mapActorToC2.useQuery(
    { actorId: selectedActor! },
    { enabled: !!selectedActor },
  );

  const { data: completeness } = trpc.c2KnowledgeBase.scoreCompleteness.useQuery(
    { actorId: selectedActor! },
    { enabled: !!selectedActor },
  );

  const generateMutation = trpc.c2KnowledgeBase.generateProfile.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Generated adversary profile: ${data.profile?.name}`);
      } else {
        toast.error(data.error || "Failed to generate profile");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const qualityColors: Record<string, string> = {
    excellent: "text-green-400 bg-green-500/10",
    good: "text-emerald-400 bg-emerald-500/10",
    fair: "text-yellow-400 bg-yellow-500/10",
    insufficient: "text-red-400 bg-red-500/10",
  };

  return (
    <div className="space-y-6">
      {/* Top Actors with Abilities */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Target className="h-5 w-5 text-red-400" /> Threat Actors with C2 Ability Mappings
          </CardTitle>
          <CardDescription>
            Select an actor to view their TTP-to-C2 mapping and generate adversary emulation profiles
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingActors ? (
            <div className="text-sm text-muted-foreground">Loading actors...</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
              {topActors?.map(actor => (
                <button
                  key={actor.actorId}
                  onClick={() => setSelectedActor(actor.actorId)}
                  className={`text-left p-3 rounded-lg border transition-all hover:border-primary/50 ${selectedActor === actor.actorId ? "border-primary bg-primary/5" : "border-border/50"}`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium truncate">{actor.name}</span>
                    {actor.hasCalderaProfile && (
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />
                    )}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {actor.abilityCount} abilities
                    {actor.country && ` · ${actor.country}`}
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Selected Actor Detail */}
      {selectedActor && completeness && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Completeness Score */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Profile Completeness</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-center">
                <div className="text-4xl font-bold">{completeness.score}</div>
                <div className="text-xs text-muted-foreground">/100</div>
                <Badge className={`mt-2 ${qualityColors[completeness.profileQuality]}`}>
                  {completeness.profileQuality}
                </Badge>
              </div>
              <Separator />
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">TTPs</span>
                  <span className="font-mono">{completeness.totalTTPs}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Abilities</span>
                  <span className="font-mono">{completeness.totalAbilities}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Tactics</span>
                  <span className="font-mono">{completeness.tacticsRepresented}/{completeness.totalTactics}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Kill Chain</span>
                  <span className="font-mono">{completeness.killChainCoverage}%</span>
                </div>
                <Progress value={completeness.killChainCoverage} className="h-1.5" />
              </div>
              <Separator />
              <div className="flex items-center gap-2">
                {completeness.hasCalderaProfile ? (
                  <Badge className="bg-green-500/10 text-green-400 text-xs">
                    <CheckCircle2 className="h-3 w-3 mr-1" /> Has Profile
                  </Badge>
                ) : completeness.readyForAutoGeneration ? (
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={() => generateMutation.mutate({ actorId: selectedActor })}
                    disabled={generateMutation.isPending}
                  >
                    {generateMutation.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    ) : (
                      <Play className="h-4 w-4 mr-2" />
                    )}
                    Generate Profile
                  </Button>
                ) : (
                  <Badge className="bg-yellow-500/10 text-yellow-400 text-xs">
                    <AlertTriangle className="h-3 w-3 mr-1" /> Not Ready
                  </Badge>
                )}
              </div>
              {completeness.missingPhases.length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Missing Phases:</div>
                  <div className="flex flex-wrap gap-1">
                    {completeness.missingPhases.slice(0, 5).map(p => (
                      <Badge key={p} variant="outline" className="text-[9px] px-1 py-0">{p}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* C2 Framework Breakdown */}
          {actorMapping && (
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base">
                  {actorMapping.actorName} — C2 Module Mapping
                </CardTitle>
                <CardDescription>
                  {actorMapping.mappedToC2}/{actorMapping.totalTTPs} TTPs mapped ({actorMapping.coveragePercent}% coverage)
                  · Recommended: {actorMapping.recommendedPrimaryC2.toUpperCase()}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Framework breakdown bars */}
                <div className="space-y-2">
                  {Object.entries(actorMapping.frameworkBreakdown)
                    .filter(([, data]) => data.moduleCount > 0)
                    .sort(([, a], [, b]) => b.moduleCount - a.moduleCount)
                    .map(([fw, data]) => (
                      <div key={fw} className="flex items-center gap-3">
                        <span className="text-xs font-mono w-24 text-right">{fw}</span>
                        <div className="flex-1">
                          <Progress
                            value={Math.min(100, (data.moduleCount / Math.max(1, actorMapping.totalTTPs)) * 100)}
                            className="h-2"
                          />
                        </div>
                        <span className="text-xs font-mono w-12">{data.moduleCount}</span>
                      </div>
                    ))}
                </div>

                {/* Emulation Plan Preview */}
                {actorMapping.emulationPlan.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold mb-2">Emulation Plan (Kill Chain Order)</h4>
                    <ScrollArea className="h-64">
                      <div className="space-y-1">
                        {actorMapping.emulationPlan.slice(0, 20).map(step => (
                          <div key={step.order} className="flex items-start gap-2 text-xs p-2 rounded hover:bg-muted/20">
                            <span className="font-mono text-muted-foreground w-6 shrink-0">{step.order}.</span>
                            <Badge variant="outline" className="text-[9px] px-1 py-0 shrink-0">
                              {step.phase.replace(/_/g, " ")}
                            </Badge>
                            <span className="text-muted-foreground truncate">{step.techniqueName}</span>
                            <Badge className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400 shrink-0">
                              {step.techniqueId}
                            </Badge>
                            <Badge variant="outline" className="text-[9px] px-1 py-0 shrink-0">
                              {step.framework}
                            </Badge>
                          </div>
                        ))}
                        {actorMapping.emulationPlan.length > 20 && (
                          <div className="text-xs text-muted-foreground text-center py-2">
                            +{actorMapping.emulationPlan.length - 20} more steps
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Batch Completeness Scores */}
      {batchScores && batchScores.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-400" /> Profile Completeness Scores
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {batchScores.map(score => (
                <button
                  key={score.actorId}
                  onClick={() => setSelectedActor(score.actorId)}
                  className="text-left p-3 rounded-lg border border-border/50 hover:border-primary/50 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium truncate">{score.actorName}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono">{score.score}/100</span>
                      <Badge className={`text-[9px] px-1 py-0 ${qualityColors[score.profileQuality]}`}>
                        {score.profileQuality}
                      </Badge>
                    </div>
                  </div>
                  <Progress value={score.score} className="h-1 mt-2" />
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Post-Exploitation Playbook Tab ─────────────────────────────────────────

function PlaybookTab() {
  const [shellPriv, setShellPriv] = useState<string>("user");
  const [platform, setPlatform] = useState<string>("windows");
  const [hasAD, setHasAD] = useState(true);

  const { data: playbook, isLoading } = trpc.c2KnowledgeBase.generatePlaybook.useQuery({
    shellPrivilege: shellPriv as any,
    targetPlatform: platform as any,
    hasActiveDirectory: hasAD,
    objectives: ["Full compromise assessment", "Data exfiltration proof"],
  });

  const phaseColors: Record<string, string> = {
    discovery: "bg-blue-500/10 text-blue-400",
    privilege_escalation: "bg-orange-500/10 text-orange-400",
    credential_access: "bg-red-500/10 text-red-400",
    persistence: "bg-purple-500/10 text-purple-400",
    lateral_movement: "bg-green-500/10 text-green-400",
    collection_exfiltration: "bg-yellow-500/10 text-yellow-400",
    defense_evasion: "bg-emerald-500/10 text-emerald-400",
    execution: "bg-cyan-500/10 text-cyan-400",
    impact: "bg-pink-500/10 text-pink-400",
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Terminal className="h-5 w-5 text-green-400" /> Shell/Agent Context
          </CardTitle>
          <CardDescription>Configure the shell/agent callback context to generate a post-exploitation playbook</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Shell Privilege</label>
              <Select value={shellPriv} onValueChange={setShellPriv}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">User</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="system">SYSTEM</SelectItem>
                  <SelectItem value="root">Root</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Platform</label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Active Directory</label>
              <Select value={hasAD ? "yes" : "no"} onValueChange={v => setHasAD(v === "yes")}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="yes">Yes</SelectItem>
                  <SelectItem value="no">No</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {playbook && (
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <BookOpen className="h-5 w-5 text-primary" /> Post-Exploitation Playbook
              </CardTitle>
              <CardDescription>
                {playbook.steps.length} steps · Est. {playbook.estimatedDuration} · {playbook.targetPlatform} ({playbook.shellType})
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Steps */}
              <div className="space-y-3">
                {playbook.steps.map(step => (
                  <div key={step.order} className="border border-border/50 rounded-lg p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="bg-primary/20 rounded-full w-7 h-7 flex items-center justify-center text-xs font-bold shrink-0">
                        {step.order}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold">{step.action}</span>
                          <Badge className={`text-[10px] px-1.5 py-0 ${phaseColors[step.phase] || ""}`}>
                            {step.phase.replace(/_/g, " ")}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {step.framework}
                          </Badge>
                          <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                            {step.requiredPrivilege}
                          </Badge>
                        </div>
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground ml-10">{step.description}</p>
                    <div className="ml-10 mt-2 flex flex-wrap gap-1">
                      {step.techniqueIds.map(t => (
                        <Badge key={t} className="text-[9px] px-1 py-0 bg-red-500/10 text-red-400">{t}</Badge>
                      ))}
                    </div>
                    {step.modules.length > 0 && (
                      <div className="ml-10 mt-1 text-[10px] text-muted-foreground">
                        Modules: {step.modules.join(", ")}
                      </div>
                    )}
                    <div className="ml-10 mt-1 text-[10px] text-muted-foreground/60">
                      Expected: {step.expectedOutput}
                    </div>
                    <div className="ml-10 text-[10px] text-primary/60">
                      Next: {step.nextStepTrigger}
                    </div>
                  </div>
                ))}
              </div>

              {/* OPSEC Guidelines */}
              <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-4">
                <h4 className="text-sm font-semibold text-yellow-400 mb-2 flex items-center gap-2">
                  <Eye className="h-4 w-4" /> OPSEC Guidelines
                </h4>
                <ul className="space-y-1">
                  {playbook.opsecGuidelines.map((g, i) => (
                    <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                      <ChevronRight className="h-3 w-3 mt-0.5 text-yellow-400 shrink-0" />
                      {g}
                    </li>
                  ))}
                </ul>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

// ─── Comparison Matrix Tab ──────────────────────────────────────────────────

function ComparisonMatrixTab() {
  const { data: matrix, isLoading } = trpc.c2KnowledgeBase.getComparisonMatrix.useQuery();

  if (isLoading || !matrix) return <div className="text-sm text-muted-foreground">Loading...</div>;

  const detectionBadge = (d: string) => {
    const colors: Record<string, string> = {
      "very-hard": "bg-green-500/10 text-green-400",
      hard: "bg-emerald-500/10 text-emerald-400",
      moderate: "bg-yellow-500/10 text-yellow-400",
      easy: "bg-red-500/10 text-red-400",
    };
    return <Badge className={`text-[10px] px-1.5 py-0 ${colors[d] || ""}`}>{d}</Badge>;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-blue-400" /> Framework Comparison Matrix
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/50">
                <th className="text-left p-2 text-muted-foreground">Framework</th>
                <th className="text-center p-2 text-muted-foreground">Platforms</th>
                <th className="text-center p-2 text-muted-foreground">Protocols</th>
                <th className="text-center p-2 text-muted-foreground">Evasion</th>
                <th className="text-center p-2 text-muted-foreground">Detection</th>
                <th className="text-center p-2 text-muted-foreground">Noise</th>
                <th className="text-center p-2 text-muted-foreground">Disk</th>
                <th className="text-center p-2 text-muted-foreground">Post-Exploit</th>
                <th className="text-center p-2 text-muted-foreground">Techniques</th>
              </tr>
            </thead>
            <tbody>
              {matrix.map(row => (
                <tr key={row.framework} className="border-b border-border/30 hover:bg-muted/10">
                  <td className="p-2 font-medium">{row.displayName}</td>
                  <td className="p-2 text-center">
                    <div className="flex gap-1 justify-center">
                      {row.platforms.map(p => (
                        <Badge key={p} variant="outline" className="text-[9px] px-1 py-0">{p}</Badge>
                      ))}
                    </div>
                  </td>
                  <td className="p-2 text-center font-mono">{row.protocols}</td>
                  <td className="p-2 text-center font-mono">{row.evasionCapabilities}</td>
                  <td className="p-2 text-center">{detectionBadge(row.detectionDifficulty)}</td>
                  <td className="p-2 text-center">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">{row.networkNoise}</Badge>
                  </td>
                  <td className="p-2 text-center">
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0">{row.diskArtifacts}</Badge>
                  </td>
                  <td className="p-2 text-center font-mono">{row.postExploitModules}</td>
                  <td className="p-2 text-center font-mono">{row.techniquesCovered}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

const C2KnowledgeBase: React.FC = () => {
  const { data: stats } = trpc.c2KnowledgeBase.getSummaryStats.useQuery();

  return (
    <AppShell activePath="/c2-knowledge-base">
      <div className="space-y-6 p-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="bg-primary/10 rounded-xl p-3">
              <Brain className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h1 className="font-display text-2xl font-bold tracking-wider">C2 Tactical Knowledge Base</h1>
              <p className="text-muted-foreground text-sm">
                Operational intelligence for C2 framework selection, adversary emulation, and post-exploitation
              </p>
            </div>
          </div>
        </div>

        {/* Summary Stats */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            {[
              { label: "Frameworks", value: stats.totalFrameworks, icon: Server },
              { label: "Techniques", value: stats.totalTechniques, icon: Crosshair },
              { label: "Post-Exploit", value: stats.totalPostExploitCapabilities, icon: Swords },
              { label: "Evasion", value: stats.totalEvasionCapabilities, icon: Shield },
              { label: "Actors", value: stats.totalActors.toLocaleString(), icon: Target },
              { label: "With Abilities", value: stats.actorsWithAbilities, icon: Layers },
              { label: "Ability Maps", value: stats.totalAbilityMappings.toLocaleString(), icon: Network },
              { label: "Profiles", value: stats.actorsWithProfiles, icon: CheckCircle2 },
            ].map(stat => (
              <Card key={stat.label} className="bg-card/50">
                <CardContent className="p-3 text-center">
                  <stat.icon className="h-4 w-4 mx-auto text-muted-foreground mb-1" />
                  <div className="text-lg font-bold">{stat.value}</div>
                  <div className="text-[10px] text-muted-foreground">{stat.label}</div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Tabs */}
        <Tabs defaultValue="profiles" className="space-y-4">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="profiles" className="text-xs">
              <Server className="h-3.5 w-3.5 mr-1.5" /> Frameworks
            </TabsTrigger>
            <TabsTrigger value="recommend" className="text-xs">
              <Brain className="h-3.5 w-3.5 mr-1.5" /> Advisor
            </TabsTrigger>
            <TabsTrigger value="adversary" className="text-xs">
              <Target className="h-3.5 w-3.5 mr-1.5" /> Adversary Profiles
            </TabsTrigger>
            <TabsTrigger value="playbook" className="text-xs">
              <BookOpen className="h-3.5 w-3.5 mr-1.5" /> Playbooks
            </TabsTrigger>
            <TabsTrigger value="matrix" className="text-xs">
              <BarChart3 className="h-3.5 w-3.5 mr-1.5" /> Comparison
            </TabsTrigger>
          </TabsList>

          <TabsContent value="profiles"><FrameworkProfilesTab /></TabsContent>
          <TabsContent value="recommend"><RecommendationTab /></TabsContent>
          <TabsContent value="adversary"><AdversaryProfileTab /></TabsContent>
          <TabsContent value="playbook"><PlaybookTab /></TabsContent>
          <TabsContent value="matrix"><ComparisonMatrixTab /></TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
};

export default C2KnowledgeBase;
