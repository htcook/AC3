import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Server,
  Play,
  Trash2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Clock,
  Terminal,
  Loader2,
  Rocket,
  AlertTriangle,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface LabDeployerPanelProps {
  engagementId: number;
}

export function LabDeployerPanel({ engagementId }: LabDeployerPanelProps) {
  const { toast } = useToast();
  const [showLogs, setShowLogs] = useState(false);

  const { data: status, refetch } = trpc.bugBounty.getLabDeploymentStatus.useQuery({
    engagementId,
  });

  const deployMutation = trpc.bugBounty.deployTestLab.useMutation({
    onSuccess: (data) => {
      toast({
        title: data.status === "running" ? "Lab Deployed" : "Deployment Started",
        description: data.labUrl
          ? `Lab available at ${data.labUrl}`
          : `Status: ${data.status}`,
      });
      refetch();
    },
    onError: (err) => {
      toast({ title: "Deploy Failed", description: err.message, variant: "destructive" });
    },
  });

  const destroyMutation = trpc.bugBounty.destroyTestLab.useMutation({
    onSuccess: () => {
      toast({ title: "Lab Destroyed", description: "Test lab has been torn down" });
      refetch();
    },
    onError: (err) => {
      toast({ title: "Destroy Failed", description: err.message, variant: "destructive" });
    },
  });

  const { data: logs } = trpc.bugBounty.getDeploymentLogs.useQuery(
    { deploymentId: status?.latest?.id || "" },
    { enabled: showLogs && !!status?.latest?.id, refetchInterval: 3000 }
  );

  const statusColor = (s: string) => {
    switch (s) {
      case "running": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "failed": return "bg-red-500/10 text-red-400 border-red-500/30";
      case "stopped": case "destroying": return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      default: return "bg-blue-500/10 text-blue-400 border-blue-500/30";
    }
  };

  const statusIcon = (s: string) => {
    switch (s) {
      case "running": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
      case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
      case "stopped": return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      default: return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Deployment Status Card */}
      <Card className="bg-card/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-primary" />
              <CardTitle className="text-base">Scan Server Deployment</CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                className="h-7 text-xs"
              >
                <RefreshCw className="h-3 w-3 mr-1" /> Refresh
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Deploy the Nextcloud test lab to your scan server via SSH
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status?.latest ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 rounded-lg border border-border/50 bg-muted/30">
                <div className="flex items-center gap-3">
                  {statusIcon(status.latest.status)}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{status.latest.id}</span>
                      <Badge variant="outline" className={statusColor(status.latest.status)}>
                        {status.latest.status}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {status.latest.scanServerHost} &middot;{" "}
                      {new Date(status.latest.startedAt).toLocaleString()}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {status.latest.labUrl && (
                    <a
                      href={status.latest.labUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline"
                    >
                      {status.latest.labUrl}
                    </a>
                  )}
                </div>
              </div>

              {status.latest.error && (
                <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/5 text-xs text-red-400">
                  <AlertTriangle className="h-3.5 w-3.5 inline mr-1" />
                  {status.latest.error}
                </div>
              )}

              <div className="flex items-center gap-2">
                {status.latest.status !== "running" && (
                  <Button
                    size="sm"
                    onClick={() => deployMutation.mutate({ engagementId })}
                    disabled={deployMutation.isPending}
                    className="h-8 text-xs"
                  >
                    {deployMutation.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                    ) : (
                      <Rocket className="h-3.5 w-3.5 mr-1" />
                    )}
                    Redeploy
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowLogs(!showLogs)}
                  className="h-8 text-xs"
                >
                  <Terminal className="h-3.5 w-3.5 mr-1" />
                  {showLogs ? "Hide Logs" : "Show Logs"}
                </Button>
                {status.latest.status === "running" && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      if (confirm("Destroy the test lab? This will remove all containers and data.")) {
                        destroyMutation.mutate({ deploymentId: status.latest!.id });
                      }
                    }}
                    disabled={destroyMutation.isPending}
                    className="h-8 text-xs text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="h-3.5 w-3.5 mr-1" />
                    Destroy
                  </Button>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center py-8">
              <Server className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground mb-3">
                No test lab deployed yet. Deploy the Nextcloud test lab to your scan server.
              </p>
              <Button
                onClick={() => deployMutation.mutate({ engagementId })}
                disabled={deployMutation.isPending}
              >
                {deployMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Rocket className="h-4 w-4 mr-2" />
                )}
                Deploy Test Lab
              </Button>
            </div>
          )}

          {/* Deployment Logs */}
          {showLogs && logs && logs.length > 0 && (
            <div className="border border-border/50 rounded-lg overflow-hidden">
              <div className="bg-muted/50 px-3 py-1.5 text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                <Terminal className="h-3 w-3" /> Deployment Logs ({logs.length})
              </div>
              <div className="max-h-64 overflow-y-auto p-2 font-mono text-[11px] space-y-0.5 bg-black/20">
                {logs.map((log: any, i: number) => (
                  <div key={i} className="flex items-start gap-2">
                    <span className="text-muted-foreground shrink-0">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`shrink-0 uppercase w-12 ${
                      log.level === "error" ? "text-red-400" :
                      log.level === "success" ? "text-emerald-400" :
                      log.level === "warn" ? "text-yellow-400" :
                      "text-blue-400"
                    }`}>
                      [{log.level}]
                    </span>
                    <span className="text-muted-foreground shrink-0">[{log.phase}]</span>
                    <span className="text-foreground/80">{log.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Deployment History */}
          {status && status.totalDeployments > 1 && (
            <div className="text-xs text-muted-foreground">
              <Clock className="h-3 w-3 inline mr-1" />
              {status.totalDeployments} total deployments for this engagement
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
