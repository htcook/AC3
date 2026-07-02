import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { useState, useMemo } from "react";
import {
  CheckCircle2, XCircle, AlertTriangle, Loader2, RefreshCw, Circle,
  ShieldCheck
} from "lucide-react";

type StatusInfo = {
  color: string;
  icon: React.ReactNode;
  label: string;
  dotColor: string;
};

function getStatusInfo(status: string | null, enabled: boolean | number): StatusInfo {
  if (!enabled) return {
    color: "text-muted-foreground",
    icon: <div className="w-3 h-3 rounded-full bg-muted-foreground/30" />,
    label: "Disabled",
    dotColor: "bg-muted-foreground/40",
  };
  switch (status) {
    case "connected":
      return { color: "text-green-400", icon: <CheckCircle2 className="w-3 h-3 text-green-400" />, label: "Connected", dotColor: "bg-green-500" };
    case "error":
      return { color: "text-red-400", icon: <XCircle className="w-3 h-3 text-red-400" />, label: "Error", dotColor: "bg-red-500" };
    case "degraded":
      return { color: "text-yellow-400", icon: <AlertTriangle className="w-3 h-3 text-yellow-400" />, label: "Degraded", dotColor: "bg-yellow-500 animate-pulse" };
    default:
      return { color: "text-muted-foreground", icon: <Circle className="w-3 h-3 text-muted-foreground" />, label: "Unchecked", dotColor: "bg-muted-foreground/60" };
  }
}

function formatLastCheck(timestamp: number | null | undefined): string {
  if (!timestamp) return "Never";
  const date = new Date(timestamp);
  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return "Just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  return `${Math.floor(diffHrs / 24)}d ago`;
}

export default function VendorHealthWidget() {
  // ALL hooks must be called unconditionally at the top - no early returns before hooks
  const { data: integrations, isLoading, refetch } = trpc.vendorIntegrations.list.useQuery(undefined, {
    refetchInterval: 300000,
    staleTime: 60000,
  });

  const healthCheckAllMutation = trpc.vendorIntegrations.healthCheckAll.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Health checks completed");
    },
    onError: (err: { message: string }) => {
      toast.error("Health check failed: " + err.message);
    },
  });

  const [checking, setChecking] = useState(false);

  // Compute derived data with useMemo - MUST be called before any conditional returns
  const stats = useMemo(() => {
    if (!integrations || integrations.length === 0) return null;
    return {
      connectedCount: integrations.filter(i => i.status === "connected" && i.enabled).length,
      errorCount: integrations.filter(i => i.status === "error" && i.enabled).length,
      enabledCount: integrations.filter(i => i.enabled).length,
    };
  }, [integrations]);

  // Now safe to do conditional returns - all hooks have been called above
  const runHealthCheck = async () => {
    setChecking(true);
    try {
      await healthCheckAllMutation.mutateAsync();
    } finally {
      setChecking(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
        <span className="text-sm text-muted-foreground">Loading vendor health...</span>
      </div>
    );
  }

  if (!integrations || integrations.length === 0 || !stats) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No vendor integrations configured.</p>
        <p className="text-xs mt-1">Add integrations in Vendor Integrations to monitor health.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Summary bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-xs">
          <span className="text-green-400">{stats.connectedCount} connected</span>
          {stats.errorCount > 0 && <span className="text-red-400">{stats.errorCount} error</span>}
          <span className="text-muted-foreground">{stats.enabledCount} enabled</span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={runHealthCheck}
          disabled={checking}
          className="h-7 text-xs"
        >
          {checking ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1" />}
          Check All
        </Button>
      </div>

      {/* Integration list */}
      <div className="grid gap-2">
        {integrations.map((integration) => {
          const statusInfo = getStatusInfo(integration.status, integration.enabled);
          return (
            <div
              key={integration.id}
              className="flex items-center justify-between p-2 rounded-md bg-card/50 border border-border/50 hover:border-border transition-colors"
            >
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${statusInfo.dotColor}`} />
                <span className="text-sm font-medium">{integration.displayName || integration.vendor || "Unknown"}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] ${statusInfo.color}`}>{statusInfo.label}</span>
                <span className="text-[10px] text-muted-foreground">
                  {formatLastCheck(integration.lastHealthCheck)}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Error details */}
      {integrations.filter(i => i.lastError && i.status === "error").map(i => (
        <div key={`err-${i.id}`} className="text-[10px] text-red-400/80 bg-red-500/5 rounded p-2 border border-red-500/20">
          <span className="font-medium">{i.displayName || i.vendor || "Unknown"}:</span>{" "}
          {typeof i.lastError === "string" ? i.lastError : "Connection error"}
        </div>
      ))}
    </div>
  );
}
