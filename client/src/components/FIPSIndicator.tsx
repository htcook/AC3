/**
 * FIPS 140-3 Compliance Status Indicator
 *
 * A compact badge for the dashboard sidebar/header that shows real-time
 * FIPS compliance status. Clicking opens a tooltip with details.
 */

import { trpc } from "@/lib/trpc";
import { Shield, ShieldCheck, ShieldAlert } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useLocation } from "wouter";

export function FIPSIndicator({ collapsed = false }: { collapsed?: boolean }) {
  const { data, isLoading } = trpc.fipsStatus.getStatus.useQuery(undefined, {
    refetchInterval: 60000, // Refresh every 60s
    staleTime: 30000,
  });
  const [, setLocation] = useLocation();

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-2 py-1.5">
        <div className="h-4 w-4 rounded-full bg-zinc-700 animate-pulse shrink-0" />
        {!collapsed && <div className="h-3 w-16 rounded bg-zinc-700 animate-pulse" />}
      </div>
    );
  }

  if (!data) return null;

  const statusConfig = {
    compliant: {
      icon: ShieldCheck,
      color: "text-emerald-400",
      bgColor: "bg-emerald-500/10",
      borderColor: "border-emerald-500/20",
      dotColor: "bg-emerald-400",
      label: "FIPS 140-3",
      description: "All communications FIPS 140-3 compliant",
    },
    partial: {
      icon: Shield,
      color: "text-amber-400",
      bgColor: "bg-amber-500/10",
      borderColor: "border-amber-500/20",
      dotColor: "bg-amber-400",
      label: "FIPS Partial",
      description: "Application-level FIPS enforcement active",
    },
    "non-compliant": {
      icon: ShieldAlert,
      color: "text-red-400",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/20",
      dotColor: "bg-red-400",
      label: "FIPS Alert",
      description: "FIPS compliance issues detected",
    },
  };

  const config = statusConfig[data.overallStatus] || statusConfig["non-compliant"];
  const Icon = config.icon;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => setLocation("/fips-compliance")}
            className={`flex items-center gap-2 px-2 py-1.5 rounded-md transition-all hover:bg-accent/50 w-full group cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-ring`}
          >
            <div className="relative shrink-0">
              <Icon className={`h-4 w-4 ${config.color}`} />
              <span
                className={`absolute -top-0.5 -right-0.5 h-1.5 w-1.5 rounded-full ${config.dotColor} ring-1 ring-background`}
              />
            </div>
            {!collapsed && (
              <div className="flex items-center gap-1.5 min-w-0">
                <span className={`text-xs font-medium ${config.color} truncate`}>
                  {config.label}
                </span>
                <span className="text-[10px] text-zinc-500 tabular-nums">
                  {data.complianceScore}%
                </span>
              </div>
            )}
          </button>
        </TooltipTrigger>
        <TooltipContent
          side="right"
          className="max-w-xs p-3 bg-zinc-900 border-zinc-700"
        >
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Icon className={`h-4 w-4 ${config.color}`} />
              <span className="font-medium text-sm">{config.label}</span>
              <span className={`text-xs ${config.color} ml-auto`}>
                {data.complianceScore}%
              </span>
            </div>
            <p className="text-xs text-zinc-400">{config.description}</p>
            <div className="grid grid-cols-2 gap-1.5 pt-1 border-t border-zinc-800">
              <StatusItem
                label="TLS"
                ok={data.checks.tlsGlobalEnforced}
              />
              <StatusItem
                label="SSH"
                ok={data.checks.sshAlgorithmsEnforced}
              />
              <StatusItem
                label="OpenSSL FIPS"
                ok={data.checks.opensslFipsActive}
              />
              <StatusItem
                label="Cert Pinning"
                ok={data.checks.certPinningActive}
              />
              <StatusItem
                label="Algorithms"
                ok={data.checks.algorithmValidation}
              />
              <StatusItem
                label="No TLS Bypass"
                ok={data.checks.noTlsBypass}
              />
            </div>
            <p className="text-[10px] text-zinc-500 pt-1">
              Click for full compliance details
            </p>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

function StatusItem({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center gap-1">
      <span
        className={`h-1.5 w-1.5 rounded-full shrink-0 ${
          ok ? "bg-emerald-400" : "bg-red-400"
        }`}
      />
      <span className="text-[10px] text-zinc-400 truncate">{label}</span>
    </div>
  );
}
