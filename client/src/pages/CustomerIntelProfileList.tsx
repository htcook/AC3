/**
 * Customer Intelligence Profile List Page
 * 
 * Shows all customer profiles with posture grades, trends, and links to detail views.
 * Accessible from the sidebar under Intelligence & Recon.
 */

import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import {
  Fingerprint, TrendingUp, TrendingDown, Minus, ChevronRight,
  Shield, ShieldCheck, ShieldAlert, ShieldX, Activity, AlertTriangle,
  Server, Target, BarChart3,
} from "lucide-react";

function gradeColor(grade: string | null): string {
  switch (grade) {
    case "A": return "text-emerald-400";
    case "B": return "text-green-400";
    case "C": return "text-yellow-400";
    case "D": return "text-orange-400";
    case "F": return "text-red-400";
    default: return "text-zinc-500";
  }
}

function gradeIcon(grade: string | null) {
  switch (grade) {
    case "A": return <ShieldCheck className="h-5 w-5 text-emerald-400" />;
    case "B": return <Shield className="h-5 w-5 text-green-400" />;
    case "C": return <ShieldAlert className="h-5 w-5 text-yellow-400" />;
    case "D": return <ShieldAlert className="h-5 w-5 text-orange-400" />;
    case "F": return <ShieldX className="h-5 w-5 text-red-400" />;
    default: return <Shield className="h-5 w-5 text-zinc-500" />;
  }
}

function trendIcon(trend: string | null) {
  switch (trend) {
    case "improving": return <TrendingUp className="h-4 w-4 text-emerald-400" />;
    case "declining": return <TrendingDown className="h-4 w-4 text-red-400" />;
    case "stable": return <Minus className="h-4 w-4 text-zinc-400" />;
    default: return <Activity className="h-4 w-4 text-zinc-500" />;
  }
}

export default function CustomerIntelProfileList() {
  const profilesQ = trpc.customerIntelProfile.listProfiles.useQuery({ limit: 100, offset: 0 });

  return (
    <AppShell>
      <div className="p-6 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
              <Fingerprint className="h-6 w-6 text-cyan-400" />
              Customer Intelligence Profiles
            </h1>
            <p className="text-sm text-zinc-400 mt-1">
              Cumulative cross-engagement intelligence for each customer. Profiles auto-update when engagements complete.
            </p>
          </div>
        </div>

        {/* Loading */}
        {profilesQ.isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Array.from({ length: 6 }).map((_, i) => (
              <Card key={i} className="bg-zinc-900/50 border-zinc-800">
                <CardHeader className="pb-3">
                  <Skeleton className="h-5 w-40" />
                  <Skeleton className="h-4 w-24 mt-1" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <Skeleton className="h-10 w-full" />
                    <Skeleton className="h-4 w-32" />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!profilesQ.isLoading && (!profilesQ.data?.profiles || profilesQ.data.profiles.length === 0) && (
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardContent className="py-12 text-center">
              <Fingerprint className="h-12 w-12 text-zinc-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-zinc-300 mb-2">No Customer Profiles Yet</h3>
              <p className="text-sm text-zinc-500 max-w-md mx-auto">
                Customer intelligence profiles are automatically created when engagements complete.
                Run an engagement to generate the first profile.
              </p>
            </CardContent>
          </Card>
        )}

        {/* Profile cards grid */}
        {profilesQ.data?.profiles && profilesQ.data.profiles.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {profilesQ.data.profiles.map((p) => (
              <Link key={p.customerId} href={`/customer-intel/${encodeURIComponent(p.customerId)}`}>
                <Card className="bg-zinc-900/50 border-zinc-800 hover:border-cyan-800/50 transition-colors cursor-pointer group">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base text-zinc-200 truncate">
                        {p.customerName || p.customerId}
                      </CardTitle>
                      <ChevronRight className="h-4 w-4 text-zinc-600 group-hover:text-cyan-400 transition-colors shrink-0" />
                    </div>
                    <CardDescription className="text-xs">
                      {p.engagementCount} engagement{p.engagementCount !== 1 ? "s" : ""} · {p.diScanCount || 0} DI scan{(p.diScanCount || 0) !== 1 ? "s" : ""}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {/* Posture grade + score */}
                    <div className="flex items-center gap-3">
                      {gradeIcon(p.postureGrade)}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`text-2xl font-bold ${gradeColor(p.postureGrade)}`}>
                            {p.postureGrade || "—"}
                          </span>
                          <span className="text-sm text-zinc-500">
                            {p.postureScore != null ? `${p.postureScore}/100` : "N/A"}
                          </span>
                          {trendIcon(p.postureTrend)}
                          <span className="text-xs text-zinc-500 capitalize">{p.postureTrend || "new"}</span>
                        </div>
                      </div>
                    </div>

                    {/* Stats row */}
                    <div className="grid grid-cols-3 gap-2 text-center">
                      <div className="bg-zinc-800/50 rounded px-2 py-1.5">
                        <div className="text-xs text-zinc-500 flex items-center justify-center gap-1">
                          <Target className="h-3 w-3" /> Findings
                        </div>
                        <div className="text-sm font-medium text-zinc-300">{p.totalFindings || 0}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded px-2 py-1.5">
                        <div className="text-xs text-zinc-500 flex items-center justify-center gap-1">
                          <AlertTriangle className="h-3 w-3" /> Critical
                        </div>
                        <div className="text-sm font-medium text-red-400">{p.totalCritical || 0}</div>
                      </div>
                      <div className="bg-zinc-800/50 rounded px-2 py-1.5">
                        <div className="text-xs text-zinc-500 flex items-center justify-center gap-1">
                          <Server className="h-3 w-3" /> Assets
                        </div>
                        <div className="text-sm font-medium text-zinc-300">{p.attackSurfaceSize || 0}</div>
                      </div>
                    </div>

                    {/* Last updated */}
                    <div className="text-xs text-zinc-600 pt-1 border-t border-zinc-800">
                      Last updated: {p.lastUpdated ? new Date(p.lastUpdated).toLocaleDateString() : "Never"}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  );
}
