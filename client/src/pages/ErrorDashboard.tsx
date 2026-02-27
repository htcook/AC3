/**
 * Error Dashboard — Platform Error Monitoring & Triage
 *
 * This page shows all runtime errors captured across the platform, including
 * client-side React crashes, unhandled promise rejections, and server-side
 * failures. Use it to review, resolve, and purge errors between engagements
 * so no issues are lost during active penetration tests.
 */
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertTriangle,
  Bug,
  CheckCircle2,
  XCircle,
  Search,
  Trash2,
  RefreshCw,
  Eye,
  Shield,
  AlertCircle,
  Info,
  Clock,
  Crosshair,
} from "lucide-react";
import { toast } from "sonner";

const SEVERITY_CONFIG = {
  critical: { icon: XCircle, color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/20" },
  error: { icon: AlertTriangle, color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  warning: { icon: AlertCircle, color: "text-amber-500", bg: "bg-amber-500/10", border: "border-amber-500/20" },
  info: { icon: Info, color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/20" },
} as const;

const SOURCE_LABELS: Record<string, string> = {
  client: "Client JS",
  server: "Server",
  react_boundary: "React Crash",
  unhandled_rejection: "Promise Rejection",
  trpc_middleware: "tRPC Middleware",
};

export default function ErrorDashboard() {

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [resolvedFilter, setResolvedFilter] = useState<string>("unresolved");
  const [engagementFilter, setEngagementFilter] = useState<string>("all");
  const [selectedError, setSelectedError] = useState<any>(null);
  const [purgeDialogOpen, setPurgeDialogOpen] = useState(false);

  // Fetch distinct engagements that have errors
  const engagements = trpc.errorLog.engagements.useQuery();
  const engagementList = (engagements.data || []) as Array<{ engagementId: number; engagementName: string; errorCount: number }>;

  const activeEngagementId = engagementFilter !== "all" ? Number(engagementFilter) : undefined;

  const stats = trpc.errorLog.stats.useQuery(activeEngagementId ? { engagementId: activeEngagementId } : {});
  const errors = trpc.errorLog.list.useQuery({
    limit: 100,
    search: search || undefined,
    severity: severityFilter !== "all" ? severityFilter : undefined,
    source: sourceFilter !== "all" ? sourceFilter : undefined,
    resolved: resolvedFilter === "all" ? undefined : resolvedFilter === "resolved",
    engagementId: activeEngagementId,
  });

  const resolveMutation = trpc.errorLog.resolve.useMutation({
    onSuccess: () => {
      errors.refetch();
      stats.refetch();
      toast.success("Error updated");
    },
  });

  const purgeMutation = trpc.errorLog.purge.useMutation({
    onSuccess: (data) => {
      errors.refetch();
      stats.refetch();
      setPurgeDialogOpen(false);
      toast.success(`Purged ${data.purged} old errors`);
    },
  });

  const errorList = useMemo(() => {
    return (errors.data as any)?.errors || [];
  }, [errors.data]);

  const statsData = stats.data as any;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Error Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          Monitor and triage platform errors captured during operations. Errors are automatically
          logged from React crashes, unhandled exceptions, and server-side failures so nothing
          is lost during active engagements.
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center">
                <Bug className="w-5 h-5 text-red-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{statsData?.total || 0}</p>
                <p className="text-xs text-muted-foreground">Total Errors</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{statsData?.unresolved || 0}</p>
                <p className="text-xs text-muted-foreground">Unresolved</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-600/10 flex items-center justify-center">
                <XCircle className="w-5 h-5 text-red-600" />
              </div>
              <div>
                <p className="text-2xl font-bold">{statsData?.critical || 0}</p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-emerald-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{statsData?.resolved || 0}</p>
                <p className="text-xs text-muted-foreground">Resolved</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search error messages..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="error">Error</SelectItem>
            <SelectItem value="warning">Warning</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        <Select value={sourceFilter} onValueChange={setSourceFilter}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Source" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sources</SelectItem>
            <SelectItem value="client">Client JS</SelectItem>
            <SelectItem value="server">Server</SelectItem>
            <SelectItem value="react_boundary">React Crash</SelectItem>
            <SelectItem value="unhandled_rejection">Promise Rejection</SelectItem>
          </SelectContent>
        </Select>
        <Select value={resolvedFilter} onValueChange={setResolvedFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="unresolved">Unresolved</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>
        <Select value={engagementFilter} onValueChange={setEngagementFilter}>
          <SelectTrigger className="w-[200px]">
            <div className="flex items-center gap-2">
              <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
              <SelectValue placeholder="Engagement" />
            </div>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Engagements</SelectItem>
            {engagementList.map((eng) => (
              <SelectItem key={eng.engagementId} value={String(eng.engagementId)}>
                {eng.engagementName} ({eng.errorCount})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="sm"
          onClick={() => errors.refetch()}
          disabled={errors.isFetching}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${errors.isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="text-destructive hover:text-destructive"
          onClick={() => setPurgeDialogOpen(true)}
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Purge Old
        </Button>
      </div>

      {/* Error List */}
      <div className="space-y-2">
        {errors.isLoading && (
          <div className="text-center py-12 text-muted-foreground">Loading errors...</div>
        )}

        {!errors.isLoading && errorList.length === 0 && (
          <Card className="border-border/50">
            <CardContent className="py-12 text-center">
              <Shield className="w-12 h-12 text-emerald-500/40 mx-auto mb-3" />
              <p className="text-lg font-medium text-foreground/70">No errors found</p>
              <p className="text-sm text-muted-foreground mt-1">
                {resolvedFilter === "unresolved"
                  ? "All clear — no unresolved errors."
                  : "No errors match the current filters."}
              </p>
            </CardContent>
          </Card>
        )}

        {errorList.map((err: any) => {
          const sev = SEVERITY_CONFIG[err.severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.error;
          const SevIcon = sev.icon;
          return (
            <Card
              key={err.id}
              className={`border-border/50 hover:border-border transition-colors cursor-pointer ${
                err.resolved ? "opacity-60" : ""
              }`}
              onClick={() => setSelectedError(err)}
            >
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <div className={`w-8 h-8 rounded-lg ${sev.bg} flex items-center justify-center flex-shrink-0 mt-0.5`}>
                    <SevIcon className={`w-4 h-4 ${sev.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] ${sev.border} ${sev.color}`}>
                        {err.severity}
                      </Badge>
                      <Badge variant="outline" className="text-[10px]">
                        {SOURCE_LABELS[err.source] || err.source}
                      </Badge>
                      {err.page && (
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {err.page}
                        </span>
                      )}
                      {err.resolved && (
                        <Badge className="text-[10px] bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
                          Resolved
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm font-medium mt-1 truncate">{err.message}</p>
                    <div className="flex items-center gap-3 mt-1.5">
                      {(() => {
                        const ctx = typeof err.engagementContext === 'string' ? (() => { try { return JSON.parse(err.engagementContext); } catch { return null; } })() : err.engagementContext;
                        return ctx?.engagementName ? (
                          <Badge variant="outline" className="text-[10px] border-cyan-500/30 text-cyan-400">
                            <Crosshair className="w-2.5 h-2.5 mr-1" />
                            {ctx.engagementName}
                          </Badge>
                        ) : null;
                      })()}
                      <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(err.createdAt).toLocaleString()}
                      </span>
                      {err.occurrenceCount > 1 && (
                        <span className="text-[10px] text-amber-500 font-medium">
                          {err.occurrenceCount}x occurrences
                        </span>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 flex-shrink-0"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedError(err);
                    }}
                  >
                    <Eye className="w-4 h-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Error Detail Dialog */}
      <Dialog open={!!selectedError} onOpenChange={(open) => !open && setSelectedError(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          {selectedError && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {(() => {
                    const sev = SEVERITY_CONFIG[selectedError.severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.error;
                    const SevIcon = sev.icon;
                    return <SevIcon className={`w-5 h-5 ${sev.color}`} />;
                  })()}
                  Error Detail
                </DialogTitle>
                <DialogDescription>
                  {SOURCE_LABELS[selectedError.source] || selectedError.source} —{" "}
                  {new Date(selectedError.createdAt).toLocaleString()}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground uppercase tracking-wider">Message</label>
                  <p className="text-sm font-medium mt-1">{selectedError.message}</p>
                </div>

                {selectedError.page && (
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Page</label>
                    <p className="text-sm font-mono mt-1">{selectedError.page}</p>
                  </div>
                )}

                {selectedError.endpoint && (
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Endpoint</label>
                    <p className="text-sm font-mono mt-1">{selectedError.endpoint}</p>
                  </div>
                )}

                {selectedError.stack && (
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Stack Trace</label>
                    <pre className="text-xs font-mono bg-muted/50 rounded-lg p-3 mt-1 overflow-x-auto max-h-48 whitespace-pre-wrap">
                      {selectedError.stack}
                    </pre>
                  </div>
                )}

                {(() => {
                  const ctx = typeof selectedError.engagementContext === 'string'
                    ? (() => { try { return JSON.parse(selectedError.engagementContext); } catch { return null; } })()
                    : selectedError.engagementContext;
                  return ctx ? (
                    <div>
                      <label className="text-xs text-muted-foreground uppercase tracking-wider">Engagement Context</label>
                      <div className="mt-1 flex flex-wrap gap-2">
                        {ctx.engagementId && (
                          <Badge variant="outline" className="border-cyan-500/30 text-cyan-400">
                            <Crosshair className="w-3 h-3 mr-1" /> ID: {ctx.engagementId}
                          </Badge>
                        )}
                        {ctx.engagementName && (
                          <Badge variant="outline" className="border-cyan-500/30 text-cyan-400">
                            {ctx.engagementName}
                          </Badge>
                        )}
                        {ctx.clientName && (
                          <Badge variant="outline" className="border-purple-500/30 text-purple-400">
                            Client: {ctx.clientName}
                          </Badge>
                        )}
                      </div>
                      {Object.keys(ctx).filter(k => !['engagementId','engagementName','clientName'].includes(k)).length > 0 && (
                        <pre className="text-xs font-mono bg-muted/50 rounded-lg p-3 mt-2 overflow-x-auto max-h-24">
                          {JSON.stringify(
                            Object.fromEntries(Object.entries(ctx).filter(([k]) => !['engagementId','engagementName','clientName'].includes(k))),
                            null, 2
                          )}
                        </pre>
                      )}
                    </div>
                  ) : null;
                })()}

                {selectedError.clientMeta && (
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Client Metadata</label>
                    <pre className="text-xs font-mono bg-muted/50 rounded-lg p-3 mt-1 overflow-x-auto max-h-32">
                      {JSON.stringify(
                        typeof selectedError.clientMeta === "string"
                          ? (() => { try { return JSON.parse(selectedError.clientMeta); } catch { return selectedError.clientMeta; } })()
                          : selectedError.clientMeta,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                )}

                {selectedError.resolveNote && (
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wider">Resolution Note</label>
                    <p className="text-sm mt-1">{selectedError.resolveNote}</p>
                  </div>
                )}
              </div>

              <DialogFooter className="gap-2">
                <Button
                  variant={selectedError.resolved ? "outline" : "default"}
                  onClick={() => {
                    resolveMutation.mutate({
                      id: selectedError.id,
                      resolved: !selectedError.resolved,
                    });
                    setSelectedError({
                      ...selectedError,
                      resolved: !selectedError.resolved,
                    });
                  }}
                  disabled={resolveMutation.isPending}
                >
                  {selectedError.resolved ? (
                    <>
                      <XCircle className="w-4 h-4 mr-2" /> Unresolve
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-4 h-4 mr-2" /> Mark Resolved
                    </>
                  )}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Purge Dialog */}
      <Dialog open={purgeDialogOpen} onOpenChange={setPurgeDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Purge Old Errors</DialogTitle>
            <DialogDescription>
              This will permanently delete all resolved errors older than 30 days.
              Unresolved errors are never purged.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPurgeDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => purgeMutation.mutate({ olderThanDays: 30 })}
              disabled={purgeMutation.isPending}
            >
              {purgeMutation.isPending ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Trash2 className="w-4 h-4 mr-2" />
              )}
              Purge Resolved Errors
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
