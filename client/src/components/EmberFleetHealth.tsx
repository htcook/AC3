// @ts-nocheck
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import {
  Activity, Heart, HeartPulse, Skull, AlertTriangle, Shield,
  RefreshCw, Loader2, Zap, Clock, TrendingUp, TrendingDown,
  CheckCircle2, XCircle, Radio, Flame,
} from "lucide-react";

// ─── Health Status Config ─────────────────────────────────────────────────
const HEALTH_STATUS = {
  healthy: {
    label: "Healthy",
    color: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    badge: "bg-emerald-500/20 text-emerald-300",
    icon: HeartPulse,
    progressColor: "bg-emerald-500",
  },
  stale: {
    label: "Stale",
    color: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    badge: "bg-amber-500/20 text-amber-300",
    icon: AlertTriangle,
    progressColor: "bg-amber-500",
  },
  dead: {
    label: "Dead",
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    badge: "bg-red-500/20 text-red-300",
    icon: Skull,
    progressColor: "bg-red-500",
  },
  unknown: {
    label: "Unknown",
    color: "text-zinc-400",
    bg: "bg-zinc-500/10",
    border: "border-zinc-500/30",
    badge: "bg-zinc-500/20 text-zinc-300",
    icon: AlertTriangle,
    progressColor: "bg-zinc-500",
  },
};

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
}

function getScoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 30) return "text-orange-400";
  return "text-red-400";
}

function getScoreLabel(score: number): string {
  if (score >= 90) return "Excellent";
  if (score >= 70) return "Good";
  if (score >= 50) return "Fair";
  if (score >= 30) return "Poor";
  return "Critical";
}

// ─── Fleet Health Widget ──────────────────────────────────────────────────
export default function EmberFleetHealth() {
  const fleetHealth = trpc.ember.getFleetHealth.useQuery(undefined, {
    refetchInterval: 15_000,
  });

  const forceSweep = trpc.ember.forceHealthSweep.useMutation({
    onSuccess: () => {
      toast.success("Health sweep completed");
      fleetHealth.refetch();
    },
    onError: (err) => toast.error(`Sweep failed: ${err.message}`),
  });

  const data = fleetHealth.data;

  if (fleetHealth.isLoading) {
    return (
      <Card className="border-zinc-700/50">
        <CardContent className="p-6 flex items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground mr-2" />
          <span className="text-sm text-muted-foreground">Loading fleet health...</span>
        </CardContent>
      </Card>
    );
  }

  if (!data || data.totalAgents === 0) {
    return (
      <Card className="border-zinc-700/50">
        <CardContent className="p-6 text-center">
          <Shield className="h-8 w-8 mx-auto text-muted-foreground mb-2" />
          <p className="text-sm text-muted-foreground">No Ember agents deployed</p>
        </CardContent>
      </Card>
    );
  }

  const scoreColor = getScoreColor(data.fleetHealthScore);
  const scoreLabel = getScoreLabel(data.fleetHealthScore);

  return (
    <Card className="border-amber-500/20 bg-gradient-to-br from-amber-500/5 to-transparent">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Flame className="h-4 w-4 text-amber-400" />
            Ember Fleet Health
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[10px] border-zinc-700">
              <Clock className="h-2.5 w-2.5 mr-1" />
              {data.timestamp ? new Date(data.timestamp).toLocaleTimeString() : "N/A"}
            </Badge>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0"
              onClick={() => forceSweep.mutate({})}
              disabled={forceSweep.isPending}
            >
              <RefreshCw className={`h-3 w-3 ${forceSweep.isPending ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Fleet Score */}
        <div className="flex items-center gap-4">
          <div className="text-center">
            <p className={`text-3xl font-bold ${scoreColor}`}>{data.fleetHealthScore}%</p>
            <p className="text-[10px] text-muted-foreground">{scoreLabel}</p>
          </div>
          <div className="flex-1 space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-emerald-400 flex items-center gap-1">
                <HeartPulse className="h-3 w-3" /> Healthy: {data.healthy}
              </span>
              <span className="text-amber-400 flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" /> Stale: {data.stale}
              </span>
              <span className="text-red-400 flex items-center gap-1">
                <Skull className="h-3 w-3" /> Dead: {data.dead}
              </span>
            </div>
            <div className="h-2 rounded-full bg-zinc-800 overflow-hidden flex">
              {data.healthy > 0 && (
                <div
                  className="h-full bg-emerald-500 transition-all"
                  style={{ width: `${(data.healthy / data.totalAgents) * 100}%` }}
                />
              )}
              {data.stale > 0 && (
                <div
                  className="h-full bg-amber-500 transition-all"
                  style={{ width: `${(data.stale / data.totalAgents) * 100}%` }}
                />
              )}
              {data.dead > 0 && (
                <div
                  className="h-full bg-red-500 transition-all"
                  style={{ width: `${(data.dead / data.totalAgents) * 100}%` }}
                />
              )}
            </div>
            <p className="text-[10px] text-muted-foreground text-right">
              {data.totalAgents} total agents
            </p>
          </div>
        </div>

        {/* Per-Agent Health List */}
        <div className="space-y-1.5 max-h-48 overflow-y-auto">
          {data.agents.map((agent) => {
            const cfg = HEALTH_STATUS[agent.status] || HEALTH_STATUS.unknown;
            const Icon = cfg.icon;
            return (
              <div
                key={agent.agentId}
                className={`flex items-center justify-between px-2.5 py-1.5 rounded-md ${cfg.bg} border ${cfg.border}`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Icon className={`h-3.5 w-3.5 flex-shrink-0 ${cfg.color}`} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium truncate">{agent.name}</p>
                    <p className="text-[10px] text-muted-foreground truncate">
                      {agent.hostname || agent.agentId} — {agent.profile}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <div className="text-right">
                    <p className={`text-xs font-semibold ${getScoreColor(agent.healthScore)}`}>
                      {agent.healthScore}%
                    </p>
                    <p className="text-[10px] text-muted-foreground">
                      {agent.silentForSeconds < Infinity
                        ? formatDuration(agent.silentForSeconds)
                        : "N/A"}
                    </p>
                  </div>
                  <Badge className={`text-[9px] ${cfg.badge} border-0`}>
                    {cfg.label}
                  </Badge>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
