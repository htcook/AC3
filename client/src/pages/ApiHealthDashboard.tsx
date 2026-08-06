/**
 * API Health Dashboard
 * 
 * Real-time monitoring of all external integration health:
 * - Service status grid with latency, error rates, uptime
 * - Circuit breaker states from the API resilience layer
 * - Health check history sparklines
 * - One-click health check triggers
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Activity, AlertTriangle, CheckCircle2, XCircle, Clock, Zap,
  RefreshCw, Search, Filter, Wifi, WifiOff, Shield, Server,
  BarChart3, TrendingUp, TrendingDown, ArrowUpDown, Loader2,
  CircleDot, Timer, Globe, Database, Eye, Lock,
} from "lucide-react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface IntegrationHealth {
  integrationId: string;
  displayName: string;
  category: string;
  status: string;
  lastHealthCheck: {
    id: number;
    integrationId: string;
    status: string;
    latencyMs: number;
    statusCode: number | null;
    errorMessage: string | null;
    checkedAt: string;
  } | null;
  lastHealthStatus: string | null;
  totalCalls: number;
  totalErrors: number;
  avgLatencyMs: number;
}

interface HealthSummary {
  totalIntegrations: number;
  healthy: number;
  degraded: number;
  down: number;
  unknown: number;
  overallStatus: string;
  categories: Record<string, { total: number; healthy: number; degraded: number; down: number }>;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

const statusConfig: Record<string, { icon: typeof CheckCircle2; color: string; bg: string; label: string }> = {
  healthy: { icon: CheckCircle2, color: "text-green-400", bg: "bg-green-500/15 border-green-500/30", label: "Healthy" },
  degraded: { icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30", label: "Degraded" },
  down: { icon: XCircle, color: "text-red-400", bg: "bg-red-500/15 border-red-500/30", label: "Down" },
  unknown: { icon: CircleDot, color: "text-zinc-400", bg: "bg-zinc-500/15 border-zinc-500/30", label: "Unknown" },
  active: { icon: CheckCircle2, color: "text-green-400", bg: "bg-green-500/15 border-green-500/30", label: "Active" },
  inactive: { icon: WifiOff, color: "text-zinc-400", bg: "bg-zinc-500/15 border-zinc-500/30", label: "Inactive" },
};

const categoryIcons: Record<string, typeof Globe> = {
  threat_intel: Globe,
  vulnerability: Shield,
  reconnaissance: Search,
  scanning: Eye,
  cloud: Server,
  identity: Lock,
  database: Database,
};

const formatLatency = (ms: number | null | undefined): string => {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
};

const formatErrorRate = (total: number, errors: number): string => {
  if (total === 0) return "0%";
  return `${((errors / total) * 100).toFixed(1)}%`;
};

const formatNumber = (n: number): string => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
};

const timeAgo = (dateStr: string | null | undefined): string => {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60_000) return "Just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
};

// ─── Component ─────────────────────────────────────────────────────────────────

export default function ApiHealthDashboard() {
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"name" | "latency" | "errors" | "status">("status");
  const [checkingId, setCheckingId] = useState<string | null>(null);

  // ─── Queries ───────────────────────────────────────────────────────────────

  const healthSummaryQ = trpc.integrationRegistry.getHealth.useQuery(undefined, {
    refetchInterval: 30_000,
  });

  const dashboardQ = trpc.integrationRegistry.getHealthDashboard.useQuery(undefined, {
    refetchInterval: 15_000,
  });

  const triggerCheckMut = trpc.integrationRegistry.triggerHealthCheck.useMutation({
    onSuccess: () => {
      dashboardQ.refetch();
      healthSummaryQ.refetch();
      toast.success("Health check completed");
      setCheckingId(null);
    },
    onError: (e) => {
      toast.error(`Health check failed: ${e.message}`);
      setCheckingId(null);
    },
  });

  // ─── Derived Data ──────────────────────────────────────────────────────────

  const summary: HealthSummary | null = healthSummaryQ.data as HealthSummary | null;
  const integrations: IntegrationHealth[] = useMemo(() => {
    if (!dashboardQ.data) return [];
    let items = dashboardQ.data as IntegrationHealth[];

    // Filter by search
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      items = items.filter(i =>
        i.displayName.toLowerCase().includes(q) ||
        i.integrationId.toLowerCase().includes(q) ||
        i.category.toLowerCase().includes(q)
      );
    }

    // Filter by category
    if (categoryFilter !== "all") {
      items = items.filter(i => i.category === categoryFilter);
    }

    // Filter by status
    if (statusFilter !== "all") {
      items = items.filter(i => {
        const s = i.lastHealthCheck?.status || i.lastHealthStatus || "unknown";
        return s === statusFilter;
      });
    }

    // Sort
    items = [...items].sort((a, b) => {
      switch (sortBy) {
        case "name":
          return a.displayName.localeCompare(b.displayName);
        case "latency":
          return (b.avgLatencyMs || 0) - (a.avgLatencyMs || 0);
        case "errors":
          return (b.totalErrors / Math.max(b.totalCalls, 1)) - (a.totalErrors / Math.max(a.totalCalls, 1));
        case "status": {
          const order: Record<string, number> = { down: 0, degraded: 1, unknown: 2, healthy: 3, active: 3 };
          const sa = a.lastHealthCheck?.status || a.lastHealthStatus || "unknown";
          const sb = b.lastHealthCheck?.status || b.lastHealthStatus || "unknown";
          return (order[sa] ?? 2) - (order[sb] ?? 2);
        }
        default:
          return 0;
      }
    });

    return items;
  }, [dashboardQ.data, searchQuery, categoryFilter, statusFilter, sortBy]);

  const categories = useMemo(() => {
    if (!dashboardQ.data) return [];
    const cats = new Set((dashboardQ.data as IntegrationHealth[]).map(i => i.category));
    return Array.from(cats).sort();
  }, [dashboardQ.data]);

  const handleTriggerCheck = (integrationId: string) => {
    setCheckingId(integrationId);
    triggerCheckMut.mutate({ integrationId });
  };

  const handleRefreshAll = () => {
    dashboardQ.refetch();
    healthSummaryQ.refetch();
    toast.success("Refreshing all health data...");
  };

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Activity className="h-6 w-6 text-primary" />
            API Health Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time health monitoring for all external integrations — Caldera, Shodan, SecurityTrails, and more.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefreshAll} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh All
        </Button>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-muted-foreground font-medium">Total</div>
                <Server className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="text-2xl font-bold mt-1">{summary.totalIntegrations}</div>
              <div className="text-xs text-muted-foreground">integrations</div>
            </CardContent>
          </Card>
          <Card className="border-green-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-green-400 font-medium">Healthy</div>
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              </div>
              <div className="text-2xl font-bold text-green-400 mt-1">{summary.healthy}</div>
              <div className="text-xs text-muted-foreground">
                {summary.totalIntegrations > 0
                  ? `${((summary.healthy / summary.totalIntegrations) * 100).toFixed(0)}% uptime`
                  : "—"}
              </div>
            </CardContent>
          </Card>
          <Card className="border-yellow-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-yellow-400 font-medium">Degraded</div>
                <AlertTriangle className="h-4 w-4 text-yellow-400" />
              </div>
              <div className="text-2xl font-bold text-yellow-400 mt-1">{summary.degraded}</div>
              <div className="text-xs text-muted-foreground">slow / partial</div>
            </CardContent>
          </Card>
          <Card className="border-red-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-red-400 font-medium">Down</div>
                <XCircle className="h-4 w-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold text-red-400 mt-1">{summary.down}</div>
              <div className="text-xs text-muted-foreground">unreachable</div>
            </CardContent>
          </Card>
          <Card className="border-zinc-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="text-xs text-zinc-400 font-medium">Unknown</div>
                <CircleDot className="h-4 w-4 text-zinc-400" />
              </div>
              <div className="text-2xl font-bold text-zinc-400 mt-1">{summary.unknown}</div>
              <div className="text-xs text-muted-foreground">not checked</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card className="border-border/50">
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search integrations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-[180px]">
                <Filter className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                {categories.map(cat => (
                  <SelectItem key={cat} value={cat}>
                    {cat.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px]">
                <Activity className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                <SelectItem value="healthy">Healthy</SelectItem>
                <SelectItem value="degraded">Degraded</SelectItem>
                <SelectItem value="down">Down</SelectItem>
                <SelectItem value="unknown">Unknown</SelectItem>
              </SelectContent>
            </Select>
            <Select value={sortBy} onValueChange={(v) => setSortBy(v as any)}>
              <SelectTrigger className="w-[160px]">
                <ArrowUpDown className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="status">By Status</SelectItem>
                <SelectItem value="name">By Name</SelectItem>
                <SelectItem value="latency">By Latency</SelectItem>
                <SelectItem value="errors">By Error Rate</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Integration Grid */}
      {dashboardQ.isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : integrations.length === 0 ? (
        <Card className="border-border/50">
          <CardContent className="p-12 text-center">
            <WifiOff className="h-12 w-12 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">No integrations match your filters.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {integrations.map((integ) => {
            const healthStatus = integ.lastHealthCheck?.status || integ.lastHealthStatus || "unknown";
            const config = statusConfig[healthStatus] || statusConfig.unknown;
            const StatusIcon = config.icon;
            const CategoryIcon = categoryIcons[integ.category] || Server;
            const errorRate = integ.totalCalls > 0 ? (integ.totalErrors / integ.totalCalls) * 100 : 0;
            const isChecking = checkingId === integ.integrationId;

            return (
              <Card key={integ.integrationId} className={`border-border/50 hover:border-border transition-colors`}>
                <CardContent className="p-4 space-y-3">
                  {/* Header Row */}
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2 min-w-0">
                      <CategoryIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                      <div className="min-w-0">
                        <div className="font-medium text-sm truncate">{integ.displayName}</div>
                        <div className="text-xs text-muted-foreground truncate">{integ.integrationId}</div>
                      </div>
                    </div>
                    <Badge variant="outline" className={`shrink-0 ${config.bg}`}>
                      <StatusIcon className={`h-3 w-3 mr-1 ${config.color}`} />
                      {config.label}
                    </Badge>
                  </div>

                  <Separator className="opacity-50" />

                  {/* Metrics Row */}
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                      <div className="text-xs text-muted-foreground">Latency</div>
                      <div className={`text-sm font-mono font-medium ${
                        (integ.avgLatencyMs || 0) > 5000 ? "text-red-400" :
                        (integ.avgLatencyMs || 0) > 2000 ? "text-yellow-400" : "text-foreground"
                      }`}>
                        {formatLatency(integ.avgLatencyMs)}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Error Rate</div>
                      <div className={`text-sm font-mono font-medium ${
                        errorRate > 10 ? "text-red-400" :
                        errorRate > 5 ? "text-yellow-400" : "text-foreground"
                      }`}>
                        {formatErrorRate(integ.totalCalls, integ.totalErrors)}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">Total Calls</div>
                      <div className="text-sm font-mono font-medium">
                        {formatNumber(integ.totalCalls)}
                      </div>
                    </div>
                  </div>

                  {/* Footer Row */}
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      {integ.lastHealthCheck
                        ? timeAgo(integ.lastHealthCheck.checkedAt)
                        : "Never checked"}
                      {integ.lastHealthCheck?.latencyMs != null && (
                        <span className="ml-1 text-muted-foreground/70">
                          ({formatLatency(integ.lastHealthCheck.latencyMs)})
                        </span>
                      )}
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-xs gap-1"
                      onClick={() => handleTriggerCheck(integ.integrationId)}
                      disabled={isChecking}
                    >
                      {isChecking ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <Zap className="h-3 w-3" />
                      )}
                      Check
                    </Button>
                  </div>

                  {/* Error Message (if down) */}
                  {integ.lastHealthCheck?.errorMessage && healthStatus === "down" && (
                    <div className="text-xs text-red-400/80 bg-red-500/10 rounded px-2 py-1.5 font-mono truncate">
                      {integ.lastHealthCheck.errorMessage}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Category Breakdown */}
      {summary?.categories && Object.keys(summary.categories).length > 0 && (
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              Category Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Object.entries(summary.categories).map(([cat, stats]) => {
                const CategoryIcon = categoryIcons[cat] || Server;
                const healthPct = stats.total > 0 ? (stats.healthy / stats.total) * 100 : 0;
                return (
                  <div key={cat} className="flex items-center gap-3 p-2 rounded-md bg-muted/30">
                    <CategoryIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-medium truncate">
                        {cat.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              healthPct >= 80 ? "bg-green-500" :
                              healthPct >= 50 ? "bg-yellow-500" : "bg-red-500"
                            }`}
                            style={{ width: `${healthPct}%` }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground font-mono">
                          {stats.healthy}/{stats.total}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
