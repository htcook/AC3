import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  Trash2, RefreshCw, Clock, Skull, AlertTriangle, CheckCircle2,
  Loader2, Flame, Shield,
} from "lucide-react";

export default function EmberCleanupControls() {
  const [purgeAllOpen, setPurgeAllOpen] = useState(false);
  const [forceCleanupOpen, setForceCleanupOpen] = useState(false);

  const { data: status, isLoading, refetch } = trpc.ember.getCleanupStatus.useQuery(
    undefined,
    { refetchInterval: 30_000 }
  );

  const forceCleanup = trpc.ember.forceCleanup.useMutation({
    onSuccess: (data) => {
      toast.success(`Cleanup sweep complete: ${data.purgedCount ?? 0} agents purged`);
      setForceCleanupOpen(false);
      refetch();
    },
    onError: (err) => toast.error(`Cleanup failed: ${err.message}`),
  });

  const purgeAllDead = trpc.ember.purgeAllDead.useMutation({
    onSuccess: (data) => {
      toast.success(`Purged ${data.purgedCount ?? 0} dead agents`);
      setPurgeAllOpen(false);
      refetch();
    },
    onError: (err) => toast.error(`Purge failed: ${err.message}`),
  });

  if (isLoading) {
    return (
      <Card className="border-zinc-700/50">
        <CardContent className="p-6 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  const retentionDays = status?.retentionMs
    ? Math.round(status.retentionMs / (1000 * 60 * 60 * 24))
    : 7;
  const sweepIntervalHrs = status?.sweepIntervalMs
    ? Math.round(status.sweepIntervalMs / (1000 * 60 * 60))
    : 1;
  const lastSweep = status?.lastSweepAt
    ? new Date(status.lastSweepAt).toLocaleString()
    : "Never";
  const nextSweep = status?.nextSweepAt
    ? new Date(status.nextSweepAt).toLocaleString()
    : "Pending";
  const deadCount = status?.deadAgentCount ?? 0;
  const totalPurged = status?.totalPurged ?? 0;

  return (
    <Card className="border-zinc-700/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Trash2 className="h-4 w-4 text-red-400" />
            Agent Cleanup Controls
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs"
            onClick={() => refetch()}
          >
            <RefreshCw className="h-3 w-3 mr-1" />
            Refresh
          </Button>
        </div>
        <p className="text-xs text-muted-foreground mt-1">
          Manage dead agent retention and purge operations. Dead agents are automatically
          cleaned up after the retention period expires.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Status Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <Clock className="h-4 w-4 mx-auto mb-1 text-blue-400" />
            <p className="text-lg font-bold">{retentionDays}d</p>
            <p className="text-[10px] text-muted-foreground">Retention</p>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <RefreshCw className="h-4 w-4 mx-auto mb-1 text-cyan-400" />
            <p className="text-lg font-bold">{sweepIntervalHrs}h</p>
            <p className="text-[10px] text-muted-foreground">Sweep Interval</p>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <Skull className="h-4 w-4 mx-auto mb-1 text-red-400" />
            <p className="text-lg font-bold text-red-400">{deadCount}</p>
            <p className="text-[10px] text-muted-foreground">Dead Agents</p>
          </div>
          <div className="bg-zinc-800/50 rounded-lg p-3 text-center">
            <CheckCircle2 className="h-4 w-4 mx-auto mb-1 text-emerald-400" />
            <p className="text-lg font-bold text-emerald-400">{totalPurged}</p>
            <p className="text-[10px] text-muted-foreground">Total Purged</p>
          </div>
        </div>

        {/* Sweep Timeline */}
        <div className="bg-zinc-800/30 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Last Sweep</span>
            <span className="font-mono text-zinc-300">{lastSweep}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Next Sweep</span>
            <span className="font-mono text-zinc-300">{nextSweep}</span>
          </div>
          {status?.lastSweepResult && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Last Result</span>
              <Badge variant="outline" className="text-[10px] font-mono">
                {status.lastSweepResult.purged ?? 0} purged / {status.lastSweepResult.errors ?? 0} errors
              </Badge>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex gap-2">
          {/* Force Cleanup Sweep */}
          <Dialog open={forceCleanupOpen} onOpenChange={setForceCleanupOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm" className="flex-1 text-xs">
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                Force Sweep
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-cyan-400" />
                  Force Cleanup Sweep
                </DialogTitle>
                <DialogDescription>
                  Run an immediate cleanup sweep. This will purge all dead agents that have
                  exceeded the {retentionDays}-day retention period, along with their associated
                  beacons and task history.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setForceCleanupOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={() => forceCleanup.mutate({ retentionDays })}
                  disabled={forceCleanup.isPending}
                  className="bg-cyan-600 hover:bg-cyan-700"
                >
                  {forceCleanup.isPending ? (
                    <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                  ) : (
                    <RefreshCw className="h-4 w-4 mr-1.5" />
                  )}
                  Run Sweep
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          {/* Purge All Dead */}
          <Dialog open={purgeAllOpen} onOpenChange={setPurgeAllOpen}>
            <DialogTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className="flex-1 text-xs border-red-500/30 text-red-400 hover:bg-red-500/10"
                disabled={deadCount === 0}
              >
                <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                Purge All Dead ({deadCount})
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-red-400">
                  <AlertTriangle className="h-5 w-5" />
                  Purge All Dead Agents
                </DialogTitle>
                <DialogDescription>
                  This will immediately remove <strong>{deadCount} dead agent(s)</strong> and
                  all their associated data (beacons, tasks, payloads). This action cannot be undone.
                </DialogDescription>
              </DialogHeader>
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-xs text-red-300">
                <p className="font-semibold mb-1">Warning: Destructive Operation</p>
                <p>All beacon history, task results, and agent metadata will be permanently deleted.</p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setPurgeAllOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="destructive"
                  onClick={() => purgeAllDead.mutate()}
                  disabled={purgeAllDead.isPending}
                >
                  {purgeAllDead.isPending ? (
                    <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                  ) : (
                    <Skull className="h-4 w-4 mr-1.5" />
                  )}
                  Purge {deadCount} Agent{deadCount !== 1 ? "s" : ""}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </CardContent>
    </Card>
  );
}
