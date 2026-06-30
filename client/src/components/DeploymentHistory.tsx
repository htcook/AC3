/**
 * Deployment History Component
 *
 * Shows a timeline of past monitoring stack deployments with status badges,
 * config snapshots, and comparison capabilities.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
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
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  CheckCircle2, XCircle, Clock, Loader2, RotateCcw,
  GitCompare, Eye, BarChart3, Server, ArrowRight,
} from "lucide-react";

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; color: string; label: string }> = {
  pending: { icon: Clock, color: "text-yellow-500", label: "Pending" },
  in_progress: { icon: Loader2, color: "text-blue-500", label: "In Progress" },
  success: { icon: CheckCircle2, color: "text-emerald-500", label: "Success" },
  failed: { icon: XCircle, color: "text-red-500", label: "Failed" },
  rolled_back: { icon: RotateCcw, color: "text-orange-500", label: "Rolled Back" },
};

export default function DeploymentHistory() {
  const [envFilter, setEnvFilter] = useState<string>("all");
  const [compareIds, setCompareIds] = useState<[string, string] | null>(null);

  const { data: deployments, isLoading } = trpc.deploymentHistory.list.useQuery(
    envFilter !== "all" ? { environment: envFilter as any } : undefined
  );
  const { data: stats } = trpc.deploymentHistory.stats.useQuery();
  const { data: comparison } = trpc.deploymentHistory.compareConfigs.useQuery(
    compareIds ? { deploymentIdA: compareIds[0], deploymentIdB: compareIds[1] } : undefined as any,
    { enabled: !!compareIds }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats Summary */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Total Deployments", value: stats.total, color: "text-foreground" },
            { label: "Successful", value: stats.success, color: "text-emerald-500" },
            { label: "Failed", value: stats.failed, color: "text-red-500" },
            { label: "Pending", value: stats.pending, color: "text-yellow-500" },
          ].map((s) => (
            <Card key={s.label}>
              <CardContent className="pt-4 pb-3 text-center">
                <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-xs text-muted-foreground">{s.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Filter + Compare Controls */}
      <div className="flex items-center justify-between">
        <Select value={envFilter} onValueChange={setEnvFilter}>
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Filter by environment" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Environments</SelectItem>
            <SelectItem value="dev">Dev</SelectItem>
            <SelectItem value="staging">Staging</SelectItem>
            <SelectItem value="prod">Production</SelectItem>
          </SelectContent>
        </Select>
        {compareIds && (
          <Button variant="ghost" size="sm" onClick={() => setCompareIds(null)}>
            Clear Comparison
          </Button>
        )}
      </div>

      {/* Comparison Dialog */}
      {comparison && !("error" in comparison) && (
        <Card className="border-blue-500/30 bg-blue-500/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <GitCompare className="h-4 w-4" />
              Config Comparison
            </CardTitle>
            <CardDescription>
              {(comparison as any).deploymentA?.id} vs {(comparison as any).deploymentB?.id} — {(comparison as any).changedCount} change(s)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Field</TableHead>
                  <TableHead>Deployment A</TableHead>
                  <TableHead>Deployment B</TableHead>
                  <TableHead>Changed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {((comparison as any).diffs || []).map((d: any) => (
                  <TableRow key={d.field} className={d.changed ? "bg-yellow-500/5" : ""}>
                    <TableCell className="font-mono text-xs">{d.field}</TableCell>
                    <TableCell className="text-xs">{String(d.valueA ?? "—")}</TableCell>
                    <TableCell className="text-xs">{String(d.valueB ?? "—")}</TableCell>
                    <TableCell>
                      {d.changed ? (
                        <Badge variant="outline" className="text-yellow-600 border-yellow-600">Changed</Badge>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Deployment Timeline */}
      {(!deployments || deployments.length === 0) ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Server className="h-10 w-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-muted-foreground">No deployments recorded yet.</p>
            <p className="text-xs text-muted-foreground mt-1">
              Use the deployment wizard to record your first monitoring stack deployment.
            </p>
          </CardContent>
        </Card>
      ) : (
        <ScrollArea className="h-[500px]">
          <div className="space-y-3">
            {deployments.map((dep: any, idx: number) => {
              const statusCfg = STATUS_CONFIG[dep.status] || STATUS_CONFIG.pending;
              const StatusIcon = statusCfg.icon;
              const config = dep.configSnapshot as Record<string, any> | null;

              return (
                <Card key={dep.deploymentId} className="relative">
                  {/* Timeline connector */}
                  {idx < deployments.length - 1 && (
                    <div className="absolute left-6 top-full w-px h-3 bg-border" />
                  )}
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        <div className={`mt-0.5 ${statusCfg.color}`}>
                          <StatusIcon className={`h-5 w-5 ${dep.status === "in_progress" ? "animate-spin" : ""}`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-medium">{dep.deploymentId}</span>
                            <Badge variant="outline" className="text-xs">{dep.environment}</Badge>
                            <Badge variant="secondary" className="text-xs">{dep.region}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">
                            {dep.stackName}
                            {dep.stackVersion && ` v${dep.stackVersion}`}
                          </p>
                          {config && (
                            <div className="flex gap-3 mt-2 text-xs text-muted-foreground">
                              <span>CPU: {config.cpuThreshold}%</span>
                              <span>Mem: {config.memoryThreshold}%</span>
                              {config.slackWebhookUrl && <span>Slack: ✓</span>}
                              {config.alertEmail && <span>Email: ✓</span>}
                            </div>
                          )}
                          {dep.errorMessage && (
                            <p className="text-xs text-red-400 mt-1">{dep.errorMessage}</p>
                          )}
                          <p className="text-xs text-muted-foreground mt-1">
                            {new Date(dep.createdAt).toLocaleString()}
                            {dep.completedAt && (
                              <> → {new Date(dep.completedAt).toLocaleString()}</>
                            )}
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          title="Compare with another deployment"
                          onClick={() => {
                            if (!compareIds) {
                              setCompareIds([dep.deploymentId, dep.deploymentId]);
                            } else if (compareIds[0] === dep.deploymentId) {
                              setCompareIds(null);
                            } else {
                              setCompareIds([compareIds[0], dep.deploymentId]);
                            }
                          }}
                        >
                          <GitCompare className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </ScrollArea>
      )}
    </div>
  );
}
