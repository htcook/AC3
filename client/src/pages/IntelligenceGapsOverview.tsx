/**
 * Intelligence Gaps Overview Page
 * 
 * Cross-engagement view of all intelligence gaps across the platform.
 * Accessible from the sidebar under Intelligence & Recon.
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Link } from "wouter";
import {
  AlertTriangle, CheckCircle2, Clock, Filter, Eye, EyeOff,
  Shield, Target, Cpu, Globe, Search, Layers, ChevronRight,
  BarChart3, XCircle, ArrowRight,
} from "lucide-react";

const CATEGORY_META: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  scope_limitation: { icon: <Target className="h-4 w-4" />, color: "text-orange-400", label: "Scope Limitation" },
  tool_limitation: { icon: <Cpu className="h-4 w-4" />, color: "text-yellow-400", label: "Tool Limitation" },
  access_denied: { icon: <Shield className="h-4 w-4" />, color: "text-red-400", label: "Access Denied" },
  time_constraint: { icon: <Clock className="h-4 w-4" />, color: "text-blue-400", label: "Time Constraint" },
  environmental: { icon: <Globe className="h-4 w-4" />, color: "text-purple-400", label: "Environmental" },
  data_quality: { icon: <Search className="h-4 w-4" />, color: "text-cyan-400", label: "Data Quality" },
  methodology: { icon: <Layers className="h-4 w-4" />, color: "text-emerald-400", label: "Methodology" },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

export default function IntelligenceGapsOverview() {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  const gapsQ = trpc.intelligenceGaps.listByEngagement.useQuery({ engagementId: 0 });

  const filteredGaps = useMemo(() => {
    if (!gapsQ.data?.gaps) return [];
    return gapsQ.data.gaps.filter((g: any) => {
      if (statusFilter !== "all" && g.status !== statusFilter) return false;
      if (categoryFilter !== "all" && g.category !== categoryFilter) return false;
      if (severityFilter !== "all" && g.severity !== severityFilter) return false;
      return true;
    });
  }, [gapsQ.data?.gaps, statusFilter, categoryFilter, severityFilter]);

  // Stats
  const stats = useMemo(() => {
    const gaps = gapsQ.data?.gaps || [];
    return {
      total: gaps.length,
      open: gaps.filter((g: any) => g.status === "open").length,
      acknowledged: gaps.filter((g: any) => g.status === "acknowledged").length,
      resolved: gaps.filter((g: any) => g.status === "resolved").length,
      critical: gaps.filter((g: any) => g.severity === "critical").length,
      high: gaps.filter((g: any) => g.severity === "high").length,
    };
  }, [gapsQ.data?.gaps]);

  // Category breakdown
  const categoryBreakdown = useMemo(() => {
    const gaps = gapsQ.data?.gaps || [];
    const counts: Record<string, number> = {};
    gaps.forEach((g: any) => {
      counts[g.category] = (counts[g.category] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [gapsQ.data?.gaps]);

  return (
    <AppShell>
      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-amber-400" />
            Intelligence Gaps
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Cross-engagement view of what was not assessed and why. Gaps are auto-detected when engagements complete.
          </p>
        </div>

        {/* Stats cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-zinc-200">{stats.total}</div>
              <div className="text-xs text-zinc-500">Total Gaps</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-amber-400">{stats.open}</div>
              <div className="text-xs text-zinc-500">Open</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-blue-400">{stats.acknowledged}</div>
              <div className="text-xs text-zinc-500">Acknowledged</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-emerald-400">{stats.resolved}</div>
              <div className="text-xs text-zinc-500">Resolved</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-red-400">{stats.critical}</div>
              <div className="text-xs text-zinc-500">Critical</div>
            </CardContent>
          </Card>
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-3 px-4 text-center">
              <div className="text-2xl font-bold text-orange-400">{stats.high}</div>
              <div className="text-xs text-zinc-500">High</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Category breakdown sidebar */}
          <Card className="bg-zinc-900/50 border-zinc-800 lg:col-span-1">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm text-zinc-300">By Category</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {categoryBreakdown.length === 0 && (
                <div className="text-xs text-zinc-600 py-4 text-center">No gaps detected yet</div>
              )}
              {categoryBreakdown.map(([cat, count]) => {
                const meta = CATEGORY_META[cat] || { icon: <AlertTriangle className="h-4 w-4" />, color: "text-zinc-400", label: cat };
                return (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(categoryFilter === cat ? "all" : cat)}
                    className={`w-full flex items-center gap-2 px-3 py-2 rounded text-sm transition-colors ${
                      categoryFilter === cat
                        ? "bg-cyan-500/10 border border-cyan-500/30 text-cyan-300"
                        : "bg-zinc-800/50 hover:bg-zinc-800 text-zinc-300"
                    }`}
                  >
                    <span className={meta.color}>{meta.icon}</span>
                    <span className="flex-1 text-left truncate">{meta.label}</span>
                    <Badge variant="outline" className="text-xs border-zinc-700 text-zinc-400">{count}</Badge>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          {/* Main gaps list */}
          <div className="lg:col-span-3 space-y-4">
            {/* Filters */}
            <div className="flex flex-wrap gap-3 items-center">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-zinc-500" />
                <span className="text-sm text-zinc-400">Filters:</span>
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[140px] bg-zinc-900 border-zinc-700 text-sm">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="open">Open</SelectItem>
                  <SelectItem value="acknowledged">Acknowledged</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                  <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                </SelectContent>
              </Select>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[140px] bg-zinc-900 border-zinc-700 text-sm">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severity</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
              {(statusFilter !== "all" || categoryFilter !== "all" || severityFilter !== "all") && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => { setStatusFilter("all"); setCategoryFilter("all"); setSeverityFilter("all"); }}
                  className="text-xs text-zinc-500 hover:text-zinc-300"
                >
                  <XCircle className="h-3 w-3 mr-1" /> Clear filters
                </Button>
              )}
              <span className="text-xs text-zinc-600 ml-auto">
                {filteredGaps.length} of {stats.total} gaps
              </span>
            </div>

            {/* Loading */}
            {gapsQ.isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Card key={i} className="bg-zinc-900/50 border-zinc-800">
                    <CardContent className="py-4">
                      <Skeleton className="h-5 w-3/4 mb-2" />
                      <Skeleton className="h-4 w-1/2" />
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}

            {/* Empty state */}
            {!gapsQ.isLoading && filteredGaps.length === 0 && (
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-12 text-center">
                  <CheckCircle2 className="h-12 w-12 text-emerald-500/30 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-zinc-300 mb-2">
                    {stats.total === 0 ? "No Intelligence Gaps Detected" : "No Gaps Match Filters"}
                  </h3>
                  <p className="text-sm text-zinc-500 max-w-md mx-auto">
                    {stats.total === 0
                      ? "Intelligence gaps are automatically detected when engagements complete. Run an engagement to start tracking gaps."
                      : "Try adjusting your filters to see more results."}
                  </p>
                </CardContent>
              </Card>
            )}

            {/* Gap cards */}
            <ScrollArea className="max-h-[calc(100vh-400px)]">
              <div className="space-y-3 pr-2">
                {filteredGaps.map((gap: any) => {
                  const catMeta = CATEGORY_META[gap.category] || { icon: <AlertTriangle className="h-4 w-4" />, color: "text-zinc-400", label: gap.category };
                  const sevClass = SEVERITY_COLORS[gap.severity] || SEVERITY_COLORS.info;
                  return (
                    <Card key={gap.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                      <CardContent className="py-4 space-y-2">
                        <div className="flex items-start gap-3">
                          <span className={catMeta.color + " mt-0.5 shrink-0"}>{catMeta.icon}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-sm font-medium text-zinc-200">{gap.title}</span>
                              <Badge variant="outline" className={`text-xs ${sevClass}`}>
                                {gap.severity}
                              </Badge>
                              <Badge variant="outline" className={`text-xs ${
                                gap.status === "open" ? "border-amber-500/30 text-amber-400" :
                                gap.status === "resolved" ? "border-emerald-500/30 text-emerald-400" :
                                gap.status === "acknowledged" ? "border-blue-500/30 text-blue-400" :
                                "border-zinc-600 text-zinc-400"
                              }`}>
                                {gap.status === "accepted_risk" ? "Accepted Risk" : gap.status}
                              </Badge>
                            </div>
                            <p className="text-xs text-zinc-500 mt-1 line-clamp-2">{gap.description}</p>
                            {gap.recommendation && (
                              <p className="text-xs text-cyan-400/70 mt-1 line-clamp-1">
                                Recommendation: {gap.recommendation}
                              </p>
                            )}
                          </div>
                          <div className="text-right shrink-0">
                            <div className="text-xs text-zinc-600">
                              {gap.engagementId ? (
                                <Link href={`/engagement/${gap.engagementId}`}>
                                  <span className="text-cyan-500/70 hover:text-cyan-400 cursor-pointer flex items-center gap-1">
                                    Eng #{gap.engagementId} <ChevronRight className="h-3 w-3" />
                                  </span>
                                </Link>
                              ) : "Platform-wide"}
                            </div>
                            <div className="text-xs text-zinc-600 mt-0.5">
                              {gap.detectedAt ? new Date(gap.detectedAt).toLocaleDateString() : ""}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </ScrollArea>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
