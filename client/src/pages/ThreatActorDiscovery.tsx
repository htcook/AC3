import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft,
  Search,
  Radar,
  Globe,
  Shield,
  Zap,
  Target,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Users,
  Sparkles,
} from "lucide-react";

type Strategy = "related_actors" | "sector_gaps" | "recent_campaigns" | "emerging_threats" | "geographic_coverage";

interface DiscoveredActor {
  name: string;
  slug: string;
  actorType: string;
  description: string;
  origin: string;
  motivation: string;
  threatLevel: string;
  aliases: string[];
  targetSectors: string[];
  targetRegions: string[];
  techniques: string[];
  tools: string[];
  malware: string[];
  firstSeen: string | null;
  confidence: number;
  discoverySource: string;
  reasoning: string;
}

const STRATEGIES: { id: Strategy; label: string; description: string; icon: React.ReactNode }[] = [
  {
    id: "related_actors",
    label: "Related Actors",
    description: "Discover groups that collaborate with, compete against, or share infrastructure with actors already in your catalog",
    icon: <Users className="h-5 w-5" />,
  },
  {
    id: "sector_gaps",
    label: "Sector Gap Analysis",
    description: "Find threat actors targeting sectors that are underrepresented in your current catalog",
    icon: <Target className="h-5 w-5" />,
  },
  {
    id: "recent_campaigns",
    label: "Recent Campaigns",
    description: "Identify actors from recent campaigns, advisories, and incident reports not yet catalogued",
    icon: <Zap className="h-5 w-5" />,
  },
  {
    id: "emerging_threats",
    label: "Emerging Threats",
    description: "Discover newly formed or recently active threat groups gaining prominence in the threat landscape",
    icon: <Radar className="h-5 w-5" />,
  },
  {
    id: "geographic_coverage",
    label: "Geographic Coverage",
    description: "Find actors from regions with sparse coverage in your catalog to improve geographic diversity",
    icon: <Globe className="h-5 w-5" />,
  },
];

function threatLevelColor(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-green-400 bg-green-500/10 border-green-500/30";
    default: return "text-zinc-400 bg-zinc-500/10 border-zinc-500/30";
  }
}

function confidenceColor(c: number): string {
  if (c >= 80) return "text-green-400";
  if (c >= 60) return "text-yellow-400";
  if (c >= 40) return "text-orange-400";
  return "text-red-400";
}

export default function ThreatActorDiscovery() {
  const [, navigate] = useLocation();
  const [selectedStrategy, setSelectedStrategy] = useState<Strategy | null>(null);
  const [discoveredActors, setDiscoveredActors] = useState<DiscoveredActor[]>([]);
  const [approvedActors, setApprovedActors] = useState<Set<number>>(new Set());
  const [rejectedActors, setRejectedActors] = useState<Set<number>>(new Set());
  const [expandedCards, setExpandedCards] = useState<Set<number>>(new Set());
  const [isCommitting, setIsCommitting] = useState(false);
  const [commitProgress, setCommitProgress] = useState({ current: 0, total: 0, succeeded: 0, failed: 0 });

  const discoverMutation = trpc.threatIntel.discoverActors.useMutation({
    onSuccess: (data) => {
      if (data.actors && data.actors.length > 0) {
        setDiscoveredActors(data.actors);
        setApprovedActors(new Set());
        setRejectedActors(new Set());
        setExpandedCards(new Set());
        toast.success(`Discovered ${data.actors.length} potential new threat actors`);
      } else {
        setDiscoveredActors([]);
        toast.info(data.message || "No new actors discovered with this strategy");
      }
    },
    onError: (err) => {
      toast.error(`Discovery failed: ${err.message}`);
    },
  });

  const commitMutation = trpc.threatIntel.bulkCommitDiscoveredActors.useMutation();

  const handleDiscover = () => {
    if (!selectedStrategy) return;
    setDiscoveredActors([]);
    setApprovedActors(new Set());
    setRejectedActors(new Set());
    discoverMutation.mutate({ strategy: selectedStrategy });
  };

  const toggleApprove = (idx: number) => {
    setApprovedActors((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
        // Remove from rejected if it was there
        setRejectedActors((rPrev) => {
          const rNext = new Set(rPrev);
          rNext.delete(idx);
          return rNext;
        });
      }
      return next;
    });
  };

  const toggleReject = (idx: number) => {
    setRejectedActors((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
        // Remove from approved if it was there
        setApprovedActors((aPrev) => {
          const aNext = new Set(aPrev);
          aNext.delete(idx);
          return aNext;
        });
      }
      return next;
    });
  };

  const toggleExpand = (idx: number) => {
    setExpandedCards((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const approveAll = () => {
    const all = new Set(discoveredActors.map((_, i) => i));
    setApprovedActors(all);
    setRejectedActors(new Set());
  };

  const rejectAll = () => {
    const all = new Set(discoveredActors.map((_, i) => i));
    setRejectedActors(all);
    setApprovedActors(new Set());
  };

  const handleCommit = async () => {
    const actorsToCommit = discoveredActors.filter((_, i) => approvedActors.has(i));
    if (actorsToCommit.length === 0) {
      toast.warning("No actors approved for commit");
      return;
    }

    setIsCommitting(true);
    setCommitProgress({ current: 0, total: actorsToCommit.length, succeeded: 0, failed: 0 });

    try {
      const result = await commitMutation.mutateAsync({ actors: actorsToCommit });
      setCommitProgress({
        current: result.total,
        total: result.total,
        succeeded: result.succeeded,
        failed: result.failed,
      });
      toast.success(`Committed ${result.succeeded} of ${result.total} actors to catalog`);
    } catch (err: any) {
      toast.error(`Commit failed: ${err.message}`);
    } finally {
      setIsCommitting(false);
    }
  };

  const pendingCount = discoveredActors.length - approvedActors.size - rejectedActors.size;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      {/* Header */}
      <div className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/threat-catalog")}
            className="text-zinc-400 hover:text-zinc-100"
          >
            <ArrowLeft className="h-4 w-4 mr-1" /> Back to Catalog
          </Button>
          <div className="h-6 w-px bg-zinc-700" />
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-cyan-400" />
            <h1 className="text-lg font-bold tracking-tight">THREAT ACTOR DISCOVERY</h1>
          </div>
          <Badge variant="outline" className="ml-auto text-cyan-400 border-cyan-500/30 text-xs">
            LLM-POWERED • GUARDRAIL-PROTECTED
          </Badge>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Strategy Selection */}
        <section>
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">
            Select Discovery Strategy
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {STRATEGIES.map((s) => (
              <Card
                key={s.id}
                className={`cursor-pointer transition-all duration-200 border ${
                  selectedStrategy === s.id
                    ? "border-cyan-500 bg-cyan-500/5 shadow-lg shadow-cyan-500/10"
                    : "border-zinc-800 bg-zinc-900/50 hover:border-zinc-600"
                }`}
                onClick={() => setSelectedStrategy(s.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div className={`p-2 rounded-lg ${selectedStrategy === s.id ? "bg-cyan-500/20 text-cyan-400" : "bg-zinc-800 text-zinc-400"}`}>
                      {s.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-sm">{s.label}</h3>
                      <p className="text-xs text-zinc-500 mt-1 leading-relaxed">{s.description}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="mt-4 flex items-center gap-3">
            <Button
              onClick={handleDiscover}
              disabled={!selectedStrategy || discoverMutation.isPending}
              className="bg-cyan-600 hover:bg-cyan-500 text-white"
            >
              {discoverMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Discovering...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4 mr-2" />
                  Run Discovery
                </>
              )}
            </Button>
            {discoverMutation.isPending && (
              <span className="text-xs text-zinc-500">
                This may take 30-60 seconds as the LLM analyzes your catalog...
              </span>
            )}
          </div>
        </section>

        {/* Discovery Results */}
        {discoveredActors.length > 0 && (
          <section>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">
                  Discovery Results
                </h2>
                <Badge className="bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                  {discoveredActors.length} found
                </Badge>
                {approvedActors.size > 0 && (
                  <Badge className="bg-green-500/10 text-green-400 border-green-500/30">
                    {approvedActors.size} approved
                  </Badge>
                )}
                {rejectedActors.size > 0 && (
                  <Badge className="bg-red-500/10 text-red-400 border-red-500/30">
                    {rejectedActors.size} rejected
                  </Badge>
                )}
                {pendingCount > 0 && (
                  <Badge className="bg-zinc-500/10 text-zinc-400 border-zinc-500/30">
                    {pendingCount} pending
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={approveAll} className="text-green-400 border-green-500/30 hover:bg-green-500/10">
                  <CheckCircle2 className="h-3 w-3 mr-1" /> Approve All
                </Button>
                <Button variant="outline" size="sm" onClick={rejectAll} className="text-red-400 border-red-500/30 hover:bg-red-500/10">
                  <XCircle className="h-3 w-3 mr-1" /> Reject All
                </Button>
              </div>
            </div>

            {/* Guardrail Info Banner */}
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mb-4 flex items-start gap-2">
              <Shield className="h-4 w-4 text-amber-400 mt-0.5 flex-shrink-0" />
              <div className="text-xs text-amber-300/80 leading-relaxed">
                <strong>Hallucination Guardrails Active:</strong> All discovered actors are validated through source citation checks,
                confidence scoring, and cross-referencing against existing data. Review each actor's confidence score and reasoning
                before approving. Actors committed to the catalog will be marked as LLM-discovered and can be further enriched.
              </div>
            </div>

            {/* Actor Cards */}
            <div className="space-y-3">
              {discoveredActors.map((actor, idx) => {
                const isApproved = approvedActors.has(idx);
                const isRejected = rejectedActors.has(idx);
                const isExpanded = expandedCards.has(idx);

                return (
                  <Card
                    key={idx}
                    className={`border transition-all duration-200 ${
                      isApproved
                        ? "border-green-500/40 bg-green-500/5"
                        : isRejected
                        ? "border-red-500/40 bg-red-500/5 opacity-60"
                        : "border-zinc-800 bg-zinc-900/50"
                    }`}
                  >
                    <CardContent className="p-4">
                      {/* Header Row */}
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h3 className="font-bold text-base">{actor.name}</h3>
                            <Badge variant="outline" className="text-[10px] border-zinc-600 text-zinc-400">
                              {actor.actorType?.toUpperCase() || "UNKNOWN"}
                            </Badge>
                            <Badge variant="outline" className={`text-[10px] border ${threatLevelColor(actor.threatLevel)}`}>
                              {actor.threatLevel?.toUpperCase() || "UNKNOWN"}
                            </Badge>
                            <span className={`text-xs font-mono font-bold ${confidenceColor(actor.confidence)}`}>
                              {actor.confidence}% CONFIDENCE
                            </span>
                          </div>
                          <p className="text-xs text-zinc-500 mt-1 line-clamp-2">{actor.description}</p>
                          {actor.origin && actor.origin !== "unknown" && (
                            <span className="text-[10px] text-zinc-600 mt-1 inline-block">
                              Origin: {actor.origin} • Motivation: {actor.motivation || "unknown"}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1 flex-shrink-0">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleExpand(idx)}
                            className="text-zinc-400 hover:text-zinc-100 h-8 w-8 p-0"
                          >
                            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleApprove(idx)}
                            className={`h-8 w-8 p-0 ${isApproved ? "text-green-400 bg-green-500/20" : "text-zinc-500 hover:text-green-400"}`}
                          >
                            <CheckCircle2 className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleReject(idx)}
                            className={`h-8 w-8 p-0 ${isRejected ? "text-red-400 bg-red-500/20" : "text-zinc-500 hover:text-red-400"}`}
                          >
                            <XCircle className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>

                      {/* Quick Tags */}
                      <div className="flex flex-wrap gap-1 mt-2">
                        {(actor.targetSectors || []).slice(0, 4).map((s, i) => (
                          <Badge key={i} variant="outline" className="text-[9px] border-zinc-700 text-zinc-500">
                            {s}
                          </Badge>
                        ))}
                        {(actor.techniques || []).slice(0, 3).map((t, i) => (
                          <Badge key={i} variant="outline" className="text-[9px] border-purple-500/30 text-purple-400">
                            {t}
                          </Badge>
                        ))}
                        {(actor.tools || []).slice(0, 3).map((t, i) => (
                          <Badge key={i} variant="outline" className="text-[9px] border-blue-500/30 text-blue-400">
                            {t}
                          </Badge>
                        ))}
                      </div>

                      {/* Expanded Details */}
                      {isExpanded && (
                        <div className="mt-4 pt-4 border-t border-zinc-800 space-y-3">
                          {/* Reasoning */}
                          <div>
                            <h4 className="text-[10px] font-semibold text-zinc-400 uppercase tracking-wider mb-1">
                              Discovery Reasoning
                            </h4>
                            <p className="text-xs text-zinc-300 leading-relaxed bg-zinc-800/50 rounded p-2">
                              {actor.reasoning || "No reasoning provided"}
                            </p>
                          </div>

                          {/* Full Details Grid */}
                          <div className="grid grid-cols-2 gap-3 text-xs">
                            <div>
                              <span className="text-zinc-500 font-semibold">Aliases:</span>
                              <p className="text-zinc-300">{(actor.aliases || []).join(", ") || "None known"}</p>
                            </div>
                            <div>
                              <span className="text-zinc-500 font-semibold">First Seen:</span>
                              <p className="text-zinc-300">{actor.firstSeen || "Unknown"}</p>
                            </div>
                            <div>
                              <span className="text-zinc-500 font-semibold">Target Sectors:</span>
                              <p className="text-zinc-300">{(actor.targetSectors || []).join(", ") || "Unknown"}</p>
                            </div>
                            <div>
                              <span className="text-zinc-500 font-semibold">Target Regions:</span>
                              <p className="text-zinc-300">{(actor.targetRegions || []).join(", ") || "Unknown"}</p>
                            </div>
                            <div>
                              <span className="text-zinc-500 font-semibold">Techniques:</span>
                              <p className="text-zinc-300">{(actor.techniques || []).join(", ") || "None mapped"}</p>
                            </div>
                            <div>
                              <span className="text-zinc-500 font-semibold">Tools & Malware:</span>
                              <p className="text-zinc-300">
                                {[...(actor.tools || []), ...(actor.malware || [])].join(", ") || "None known"}
                              </p>
                            </div>
                          </div>

                          {/* Discovery Source */}
                          <div className="bg-zinc-800/30 rounded p-2">
                            <span className="text-[10px] text-zinc-500 font-semibold uppercase">Source: </span>
                            <span className="text-[10px] text-zinc-400">{actor.discoverySource || "LLM analysis"}</span>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* Commit Section */}
            <div className="mt-6 pt-6 border-t border-zinc-800">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold">Commit Approved Actors to Catalog</h3>
                  <p className="text-xs text-zinc-500 mt-1">
                    {approvedActors.size} actor{approvedActors.size !== 1 ? "s" : ""} approved for commit.
                    They will be added to your threat catalog with LLM-discovered source attribution.
                  </p>
                </div>
                <Button
                  onClick={handleCommit}
                  disabled={approvedActors.size === 0 || isCommitting}
                  className="bg-green-600 hover:bg-green-500 text-white"
                >
                  {isCommitting ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Committing {commitProgress.current}/{commitProgress.total}...
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Commit {approvedActors.size} Actor{approvedActors.size !== 1 ? "s" : ""}
                    </>
                  )}
                </Button>
              </div>

              {/* Commit Progress */}
              {(isCommitting || commitProgress.total > 0) && (
                <div className="mt-4 space-y-2">
                  <div className="w-full bg-zinc-800 rounded-full h-2">
                    <div
                      className="bg-green-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${commitProgress.total > 0 ? (commitProgress.current / commitProgress.total) * 100 : 0}%` }}
                    />
                  </div>
                  <div className="flex items-center gap-4 text-xs text-zinc-500">
                    <span>Progress: {commitProgress.current}/{commitProgress.total}</span>
                    {commitProgress.succeeded > 0 && (
                      <span className="text-green-400">{commitProgress.succeeded} succeeded</span>
                    )}
                    {commitProgress.failed > 0 && (
                      <span className="text-red-400">{commitProgress.failed} failed</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* Empty State */}
        {!discoverMutation.isPending && discoveredActors.length === 0 && (
          <div className="text-center py-16 text-zinc-600">
            <Radar className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="text-sm">Select a discovery strategy and click "Run Discovery" to find new threat actors</p>
            <p className="text-xs mt-2 text-zinc-700">
              The LLM will analyze your existing catalog of {">"}1700 actors and identify gaps
            </p>
          </div>
        )}

        {/* Discovery Loading State */}
        {discoverMutation.isPending && (
          <div className="text-center py-16">
            <Loader2 className="h-10 w-10 mx-auto mb-4 text-cyan-400 animate-spin" />
            <p className="text-sm text-zinc-400">Analyzing your catalog and searching for new threat actors...</p>
            <p className="text-xs text-zinc-600 mt-2">
              The LLM is cross-referencing your {">"}1700 catalogued actors against known threat intelligence sources
            </p>
            <div className="flex items-center justify-center gap-2 mt-4">
              <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" style={{ animationDelay: "0.2s" }} />
              <div className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" style={{ animationDelay: "0.4s" }} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
