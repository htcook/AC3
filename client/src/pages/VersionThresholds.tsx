/**
 * Version Thresholds Admin Page
 * ═══════════════════════════════════════════════════════════════════
 *
 * Manages the auto-refresh version threshold system:
 *   - View all thresholds (merged static + dynamic)
 *   - Trigger manual NVD refresh
 *   - Manually set/edit thresholds
 *   - View refresh stats and history
 *   - Delete dynamic overrides (revert to static fallback)
 */

import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  RefreshCw,
  Shield,
  AlertTriangle,
  Clock,
  Database,
  Globe,
  Edit3,
  Trash2,
  Plus,
  Search,
  CheckCircle,
  XCircle,
  Activity,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// ─── Source badge colors ────────────────────────────────────────────

const SOURCE_COLORS: Record<string, string> = {
  static: "bg-zinc-700 text-zinc-200",
  nvd_cve: "bg-amber-900/60 text-amber-300 border border-amber-700/50",
  di_scan: "bg-cyan-900/60 text-cyan-300 border border-cyan-700/50",
  manual: "bg-purple-900/60 text-purple-300 border border-purple-700/50",
};

const SOURCE_ICONS: Record<string, React.ReactNode> = {
  static: <Database className="h-3 w-3" />,
  nvd_cve: <Globe className="h-3 w-3" />,
  di_scan: <Activity className="h-3 w-3" />,
  manual: <Edit3 className="h-3 w-3" />,
};

export default function VersionThresholds() {
  const { toast } = useToast();
  const [searchFilter, setSearchFilter] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);
  const [newTech, setNewTech] = useState("");
  const [newVersion, setNewVersion] = useState("");
  const [newNotes, setNewNotes] = useState("");
  const [editingTech, setEditingTech] = useState<string | null>(null);
  const [editVersion, setEditVersion] = useState("");
  const [showHistory, setShowHistory] = useState(false);
  const [refreshTechs, setRefreshTechs] = useState("");

  // ─── Data fetching ─────────────────────────────────────────────

  const thresholdsQuery = trpc.versionThresholds.getAll.useQuery();
  const statsQuery = trpc.versionThresholds.getStats.useQuery();
  const utils = trpc.useUtils();

  const refreshMutation = trpc.versionThresholds.refresh.useMutation({
    onSuccess: (data) => {
      utils.versionThresholds.getAll.invalidate();
      utils.versionThresholds.getStats.invalidate();
      toast({
        title: "NVD Refresh Complete",
        description: `${data.added} added, ${data.updated} updated, ${data.unchanged} unchanged in ${Math.round(data.duration / 1000)}s`,
      });
    },
    onError: (err) => {
      toast({ title: "Refresh Failed", description: err.message, variant: "destructive" });
    },
  });

  const setMutation = trpc.versionThresholds.set.useMutation({
    onSuccess: (data) => {
      utils.versionThresholds.getAll.invalidate();
      utils.versionThresholds.getStats.invalidate();
      toast({ title: "Threshold Updated", description: `${data.technology} → ${data.minSafeVersion}` });
      setEditingTech(null);
      setShowAddForm(false);
      setNewTech("");
      setNewVersion("");
      setNewNotes("");
    },
    onError: (err) => {
      toast({ title: "Update Failed", description: err.message, variant: "destructive" });
    },
  });

  const deleteMutation = trpc.versionThresholds.delete.useMutation({
    onSuccess: (data) => {
      utils.versionThresholds.getAll.invalidate();
      utils.versionThresholds.getStats.invalidate();
      toast({ title: "Threshold Deleted", description: `${data.technology} reverted to static fallback` });
    },
    onError: (err) => {
      toast({ title: "Delete Failed", description: err.message, variant: "destructive" });
    },
  });

  // ─── Filtered thresholds ──────────────────────────────────────

  const filteredThresholds = useMemo(() => {
    if (!thresholdsQuery.data) return [];
    if (!searchFilter) return thresholdsQuery.data;
    const q = searchFilter.toLowerCase();
    return thresholdsQuery.data.filter(
      (t) =>
        t.technology.toLowerCase().includes(q) ||
        t.minSafeVersion.includes(q) ||
        t.source.includes(q) ||
        (t.latestCveId && t.latestCveId.toLowerCase().includes(q))
    );
  }, [thresholdsQuery.data, searchFilter]);

  const stats = statsQuery.data;

  // ─── Render ───────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#0A0E14] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <Shield className="h-6 w-6 text-cyan-400" />
              Version Threshold Manager
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Auto-refresh outdated version thresholds from NVD CVE data and DI scan learning
            </p>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="border-cyan-800 text-cyan-400 hover:bg-cyan-900/30"
              onClick={() => setShowAddForm(!showAddForm)}
            >
              <Plus className="h-4 w-4 mr-1" /> Add Manual
            </Button>
            <Button
              size="sm"
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              onClick={() => {
                const techs = refreshTechs.trim()
                  ? refreshTechs.split(",").map((t) => t.trim()).filter(Boolean)
                  : undefined;
                refreshMutation.mutate(techs ? { technologies: techs } : undefined);
              }}
              disabled={refreshMutation.isPending}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${refreshMutation.isPending ? "animate-spin" : ""}`} />
              {refreshMutation.isPending ? "Refreshing..." : "Refresh from NVD"}
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="bg-[#111827] border-[#1E293B]">
              <CardContent className="p-4">
                <div className="text-xs text-gray-400 uppercase tracking-wider">Total Thresholds</div>
                <div className="text-2xl font-bold text-white mt-1">{stats.totalThresholds}</div>
                <div className="text-xs text-gray-500 mt-1">
                  {stats.bySource.static} static, {stats.bySource.nvd_cve + stats.bySource.di_scan + stats.bySource.manual} dynamic
                </div>
              </CardContent>
            </Card>
            <Card className="bg-[#111827] border-[#1E293B]">
              <CardContent className="p-4">
                <div className="text-xs text-gray-400 uppercase tracking-wider">NVD Updated</div>
                <div className="text-2xl font-bold text-amber-400 mt-1">{stats.bySource.nvd_cve}</div>
                <div className="text-xs text-gray-500 mt-1">
                  {stats.bySource.di_scan} from DI scan, {stats.bySource.manual} manual
                </div>
              </CardContent>
            </Card>
            <Card className="bg-[#111827] border-[#1E293B]">
              <CardContent className="p-4">
                <div className="text-xs text-gray-400 uppercase tracking-wider">Stale (&gt;30d)</div>
                <div className={`text-2xl font-bold mt-1 ${stats.staleThresholds > 0 ? "text-red-400" : "text-green-400"}`}>
                  {stats.staleThresholds}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {stats.staleThresholds > 0 ? "Needs refresh" : "All current"}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-[#111827] border-[#1E293B]">
              <CardContent className="p-4">
                <div className="text-xs text-gray-400 uppercase tracking-wider">Last Refresh</div>
                <div className="text-sm font-bold text-white mt-1">
                  {stats.lastRefreshTime > 0
                    ? new Date(stats.lastRefreshTime).toLocaleString()
                    : "Never"}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {stats.lastRefreshDuration > 0
                    ? `Took ${Math.round(stats.lastRefreshDuration / 1000)}s`
                    : ""}
                  {stats.nextScheduledRefresh > 0
                    ? ` · Next: ${new Date(stats.nextScheduledRefresh).toLocaleTimeString()}`
                    : ""}
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Refresh History */}
        {stats && stats.refreshHistory.length > 0 && (
          <Card className="bg-[#111827] border-[#1E293B]">
            <CardHeader className="pb-2 cursor-pointer" onClick={() => setShowHistory(!showHistory)}>
              <CardTitle className="text-sm flex items-center gap-2 text-gray-300">
                <Clock className="h-4 w-4" />
                Refresh History ({stats.refreshHistory.length})
                {showHistory ? <ChevronUp className="h-4 w-4 ml-auto" /> : <ChevronDown className="h-4 w-4 ml-auto" />}
              </CardTitle>
            </CardHeader>
            {showHistory && (
              <CardContent className="pt-0">
                <div className="space-y-1">
                  {stats.refreshHistory
                    .slice()
                    .reverse()
                    .map((h, i) => (
                      <div key={i} className="flex items-center justify-between text-xs py-1 border-b border-[#1E293B] last:border-0">
                        <span className="text-gray-400">{new Date(h.time).toLocaleString()}</span>
                        <div className="flex gap-3">
                          <span className="text-green-400">+{h.added} added</span>
                          <span className="text-amber-400">{h.updated} updated</span>
                          <span className="text-gray-500">{Math.round(h.duration / 1000)}s</span>
                        </div>
                      </div>
                    ))}
                </div>
              </CardContent>
            )}
          </Card>
        )}

        {/* Add Manual Form */}
        {showAddForm && (
          <Card className="bg-[#111827] border-cyan-800/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-cyan-400">Add Manual Threshold</CardTitle>
              <CardDescription className="text-xs text-gray-500">
                Set a custom minimum safe version for a technology
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3 items-end">
                <div className="flex-1">
                  <label className="text-xs text-gray-400 block mb-1">Technology</label>
                  <Input
                    placeholder="e.g. nginx, wordpress, openssl"
                    value={newTech}
                    onChange={(e) => setNewTech(e.target.value)}
                    className="bg-[#0A0E14] border-[#1E293B] text-white text-sm"
                  />
                </div>
                <div className="w-40">
                  <label className="text-xs text-gray-400 block mb-1">Min Safe Version</label>
                  <Input
                    placeholder="e.g. 1.25.4"
                    value={newVersion}
                    onChange={(e) => setNewVersion(e.target.value)}
                    className="bg-[#0A0E14] border-[#1E293B] text-white text-sm"
                  />
                </div>
                <div className="flex-1">
                  <label className="text-xs text-gray-400 block mb-1">Notes (optional)</label>
                  <Input
                    placeholder="Reason for override"
                    value={newNotes}
                    onChange={(e) => setNewNotes(e.target.value)}
                    className="bg-[#0A0E14] border-[#1E293B] text-white text-sm"
                  />
                </div>
                <Button
                  size="sm"
                  className="bg-cyan-600 hover:bg-cyan-700"
                  onClick={() => {
                    if (!newTech || !newVersion) return;
                    setMutation.mutate({
                      technology: newTech,
                      minSafeVersion: newVersion,
                      notes: newNotes || undefined,
                    });
                  }}
                  disabled={!newTech || !newVersion || setMutation.isPending}
                >
                  Save
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Selective Refresh */}
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardContent className="p-4">
            <div className="flex gap-3 items-center">
              <div className="flex-1">
                <Input
                  placeholder="Refresh specific techs (comma-separated, e.g. nginx,wordpress) — leave empty for all"
                  value={refreshTechs}
                  onChange={(e) => setRefreshTechs(e.target.value)}
                  className="bg-[#0A0E14] border-[#1E293B] text-white text-sm"
                />
              </div>
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                  <Input
                    placeholder="Search thresholds..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    className="bg-[#0A0E14] border-[#1E293B] text-white text-sm pl-9"
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Thresholds Table */}
        <Card className="bg-[#111827] border-[#1E293B]">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-gray-300">
              Version Thresholds ({filteredThresholds.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            {thresholdsQuery.isLoading ? (
              <div className="text-center text-gray-500 py-8">Loading thresholds...</div>
            ) : filteredThresholds.length === 0 ? (
              <div className="text-center text-gray-500 py-8">No thresholds found</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-[#1E293B]">
                      <th className="text-left py-2 px-3">Technology</th>
                      <th className="text-left py-2 px-3">Min Safe Version</th>
                      <th className="text-left py-2 px-3">Source</th>
                      <th className="text-left py-2 px-3">CVE / Notes</th>
                      <th className="text-left py-2 px-3">Last Updated</th>
                      <th className="text-right py-2 px-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredThresholds.map((t) => (
                      <tr
                        key={t.technology}
                        className="border-b border-[#1E293B]/50 hover:bg-[#1A2332]/50 transition-colors"
                      >
                        <td className="py-2 px-3 font-mono text-white">{t.technology}</td>
                        <td className="py-2 px-3">
                          {editingTech === t.technology ? (
                            <div className="flex gap-1 items-center">
                              <Input
                                value={editVersion}
                                onChange={(e) => setEditVersion(e.target.value)}
                                className="bg-[#0A0E14] border-cyan-700 text-white text-xs h-7 w-28"
                                autoFocus
                              />
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 w-7 p-0 text-green-400 hover:text-green-300"
                                onClick={() => {
                                  setMutation.mutate({
                                    technology: t.technology,
                                    minSafeVersion: editVersion,
                                    notes: `Manual override from ${t.minSafeVersion}`,
                                  });
                                }}
                              >
                                <CheckCircle className="h-4 w-4" />
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 w-7 p-0 text-red-400 hover:text-red-300"
                                onClick={() => setEditingTech(null)}
                              >
                                <XCircle className="h-4 w-4" />
                              </Button>
                            </div>
                          ) : (
                            <span className="font-mono text-cyan-300">{t.minSafeVersion}</span>
                          )}
                        </td>
                        <td className="py-2 px-3">
                          <Badge className={`text-[10px] px-1.5 py-0 ${SOURCE_COLORS[t.source] || "bg-gray-700 text-gray-300"}`}>
                            <span className="mr-1">{SOURCE_ICONS[t.source]}</span>
                            {t.source}
                          </Badge>
                        </td>
                        <td className="py-2 px-3 text-xs text-gray-400 max-w-[300px] truncate">
                          {t.latestCveId && (
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${t.latestCveId}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-amber-400 hover:underline mr-2"
                            >
                              {t.latestCveId}
                            </a>
                          )}
                          {t.latestCveCvss && (
                            <span className={`mr-2 ${t.latestCveCvss >= 9 ? "text-red-400" : t.latestCveCvss >= 7 ? "text-amber-400" : "text-yellow-400"}`}>
                              CVSS {t.latestCveCvss}
                            </span>
                          )}
                          {t.notes && <span className="text-gray-500">{t.notes}</span>}
                        </td>
                        <td className="py-2 px-3 text-xs text-gray-500">
                          {t.lastUpdated > 0 ? (
                            <span title={new Date(t.lastUpdated).toLocaleString()}>
                              {formatRelativeTime(t.lastUpdated)}
                            </span>
                          ) : (
                            <span className="text-gray-600">Built-in</span>
                          )}
                        </td>
                        <td className="py-2 px-3 text-right">
                          <div className="flex gap-1 justify-end">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-7 w-7 p-0 text-gray-400 hover:text-cyan-400"
                              onClick={() => {
                                setEditingTech(t.technology);
                                setEditVersion(t.minSafeVersion);
                              }}
                              title="Edit threshold"
                            >
                              <Edit3 className="h-3.5 w-3.5" />
                            </Button>
                            {t.source !== "static" && (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 w-7 p-0 text-gray-400 hover:text-red-400"
                                onClick={() => deleteMutation.mutate({ technology: t.technology })}
                                title="Delete (revert to static)"
                              >
                                <Trash2 className="h-3.5 w-3.5" />
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Refresh pending indicator */}
        {refreshMutation.isPending && (
          <Card className="bg-amber-900/20 border-amber-700/50">
            <CardContent className="p-4 flex items-center gap-3">
              <RefreshCw className="h-5 w-5 text-amber-400 animate-spin" />
              <div>
                <div className="text-sm text-amber-300 font-medium">NVD Refresh in Progress</div>
                <div className="text-xs text-amber-400/70">
                  Querying NVD CVE API for each technology with CPE mapping. This may take several minutes due to rate limiting...
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

// ─── Helpers ────────────────────────────────────────────────────────

function formatRelativeTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}
