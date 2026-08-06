/**
 * EvasionStatusIndicator
 *
 * Compact badges showing current evasion level per asset in the engagement header.
 * Color-coded: green (normal), yellow (cautious), orange (moderate/aggressive), red (stealth).
 * Shows tooltip with evasion details on hover.
 */

import { Shield, ShieldAlert, ShieldOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

interface TargetProfile {
  asset: string;
  waf: { detected: boolean; vendor?: string };
  cdn: { detected: boolean; provider?: string };
  recommendedStrategy?: {
    evasionProfile?: {
      name: string;
      rateLimit: number;
      delayMs: number;
    };
  };
  evasionEscalation?: {
    currentLevel: number;
    history: Array<{ reason: string; timestamp: number }>;
  };
}

interface EvasionStatusIndicatorProps {
  targetProfiles: Record<string, TargetProfile> | null | undefined;
  compact?: boolean;
}

const LEVEL_CONFIG: Record<number, { label: string; color: string; bgColor: string; borderColor: string; icon: typeof Shield }> = {
  1: { label: "Normal", color: "text-green-400", bgColor: "bg-green-500/10", borderColor: "border-green-500/30", icon: Shield },
  2: { label: "Cautious", color: "text-yellow-400", bgColor: "bg-yellow-500/10", borderColor: "border-yellow-500/30", icon: Shield },
  3: { label: "Moderate", color: "text-orange-400", bgColor: "bg-orange-500/10", borderColor: "border-orange-500/30", icon: ShieldAlert },
  4: { label: "Aggressive", color: "text-red-400", bgColor: "bg-red-500/10", borderColor: "border-red-500/30", icon: ShieldAlert },
  5: { label: "Stealth", color: "text-red-500", bgColor: "bg-red-600/15", borderColor: "border-red-600/40", icon: ShieldOff },
};

function getMaxEvasionLevel(profiles: Record<string, TargetProfile>): { level: number; count: number; assets: string[] } {
  let maxLevel = 1;
  let escalatedAssets: string[] = [];
  for (const [asset, profile] of Object.entries(profiles)) {
    const level = profile.evasionEscalation?.currentLevel || 1;
    if (level > maxLevel) {
      maxLevel = level;
      escalatedAssets = [asset];
    } else if (level === maxLevel && level > 1) {
      escalatedAssets.push(asset);
    }
  }
  return { level: maxLevel, count: escalatedAssets.length, assets: escalatedAssets };
}

export function EvasionStatusIndicator({ targetProfiles, compact = false }: EvasionStatusIndicatorProps) {
  if (!targetProfiles || Object.keys(targetProfiles).length === 0) return null;

  const { level, count, assets } = getMaxEvasionLevel(targetProfiles);
  const config = LEVEL_CONFIG[level] || LEVEL_CONFIG[1];
  const Icon = config.icon;
  const totalAssets = Object.keys(targetProfiles).length;

  // In compact mode, show just a single badge with the highest level
  if (compact) {
    if (level <= 1) return null; // Don't show badge when everything is normal

    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="outline"
              className={`text-[10px] ${config.color} ${config.bgColor} ${config.borderColor} cursor-help animate-pulse`}
            >
              <Icon className="h-3 w-3 mr-0.5" />
              EVA {level}
            </Badge>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-xs">
            <div className="space-y-1.5">
              <p className="font-semibold text-xs">Evasion Level {level}: {config.label}</p>
              <p className="text-xs text-muted-foreground">
                {count} of {totalAssets} asset{totalAssets !== 1 ? "s" : ""} at elevated evasion
              </p>
              {assets.slice(0, 3).map(a => (
                <div key={a} className="text-[10px] font-mono text-muted-foreground truncate">{a}</div>
              ))}
              {assets.length > 3 && (
                <div className="text-[10px] text-muted-foreground">+{assets.length - 3} more</div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  // Full mode: show per-asset badges
  const entries = Object.entries(targetProfiles);
  return (
    <TooltipProvider>
      <div className="flex items-center gap-1 flex-wrap">
        {entries.map(([asset, profile]) => {
          const assetLevel = profile.evasionEscalation?.currentLevel || 1;
          const assetConfig = LEVEL_CONFIG[assetLevel] || LEVEL_CONFIG[1];
          const AssetIcon = assetConfig.icon;
          const evasionProfile = profile.recommendedStrategy?.evasionProfile;
          const history = profile.evasionEscalation?.history || [];

          return (
            <Tooltip key={asset}>
              <TooltipTrigger asChild>
                <Badge
                  variant="outline"
                  className={`text-[9px] ${assetConfig.color} ${assetConfig.bgColor} ${assetConfig.borderColor} cursor-help ${assetLevel > 2 ? "animate-pulse" : ""}`}
                >
                  <AssetIcon className="h-2.5 w-2.5 mr-0.5" />
                  {asset.length > 20 ? asset.slice(0, 18) + "..." : asset}
                  {assetLevel > 1 && <span className="ml-0.5 font-bold">L{assetLevel}</span>}
                </Badge>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="max-w-sm">
                <div className="space-y-2">
                  <div>
                    <p className="font-semibold text-xs">{asset}</p>
                    <p className={`text-xs ${assetConfig.color}`}>
                      Evasion: {assetConfig.label} (Level {assetLevel})
                    </p>
                  </div>
                  {evasionProfile && (
                    <div className="text-[10px] space-y-0.5 text-muted-foreground">
                      <div>Rate: {evasionProfile.rateLimit} req/s</div>
                      <div>Delay: {evasionProfile.delayMs}ms</div>
                    </div>
                  )}
                  {profile.waf.detected && (
                    <div className="text-[10px] text-yellow-400">
                      WAF: {profile.waf.vendor || "Detected"}
                    </div>
                  )}
                  {profile.cdn.detected && (
                    <div className="text-[10px] text-blue-400">
                      CDN: {profile.cdn.provider || "Detected"}
                    </div>
                  )}
                  {history.length > 0 && (
                    <div className="border-t border-border/50 pt-1">
                      <p className="text-[10px] font-medium mb-0.5">Escalation History:</p>
                      {history.slice(-3).map((h, i) => (
                        <div key={i} className="text-[10px] text-muted-foreground">
                          {new Date(h.timestamp).toLocaleTimeString()}: {h.reason}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}
