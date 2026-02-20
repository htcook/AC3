/**
 * CorroborationPanel — displays IOC corroboration results from the SpicyTIP bridge.
 *
 * Shows matched IOCs with confidence tiers (confirmed / probable / potential),
 * grouped by asset, with severity coloring and expandable details.
 */

import { useState, useEffect, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import {
  Shield, AlertTriangle, Bug, Globe2, Loader2,
  ChevronDown, ChevronUp, ExternalLink, Crosshair,
  CheckCircle2, HelpCircle, Search,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ─── Types ───────────────────────────────────────────────────────────────

interface Asset {
  id: number;
  hostname: string;
  ip?: string | null;
  assetType: string | null;
  riskBand?: string | null;
  hybridRiskScore?: number | null;
}

interface CorroborationMatch {
  asset: string;
  assetType: string;
  matchedIOC: {
    iocType?: string;
    type?: string;
    value?: string;
    ioc?: string;
    malwareFamily?: string;
    confidence?: number;
    reporter?: string;
    firstSeen?: string;
    lastSeen?: string;
    tags?: string[];
    reference?: string;
    threatType?: string;
  };
  corroborationTier: "confirmed" | "probable" | "potential";
}

// ─── Constants ───────────────────────────────────────────────────────────

const TIER_CONFIG = {
  confirmed: {
    label: "CONFIRMED",
    color: "text-red-400 bg-red-500/10 border-red-500/30",
    icon: AlertTriangle,
    description: "Direct match with high-confidence IOC",
  },
  probable: {
    label: "PROBABLE",
    color: "text-orange-400 bg-orange-500/10 border-orange-500/30",
    icon: Shield,
    description: "Strong correlation with known threat indicators",
  },
  potential: {
    label: "POTENTIAL",
    color: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    icon: HelpCircle,
    description: "Possible match requiring further investigation",
  },
};

// ─── Component ───────────────────────────────────────────────────────────

export default function CorroborationPanel({
  assets,
  scanId,
  autoRun = false,
}: {
  assets: Asset[];
  scanId: number;
  autoRun?: boolean;
}) {
  const [hasRun, setHasRun] = useState(false);
  const [expandedAsset, setExpandedAsset] = useState<string | null>(null);

  // Build the asset list for corroboration
  const assetInputs = useMemo(() => {
    const inputs: Array<{ value: string; type: "ip" | "domain" | "url" | "hash" | "email" }> = [];
    const seen = new Set<string>();

    for (const asset of assets) {
      // Add hostname as domain
      if (asset.hostname && !seen.has(asset.hostname)) {
        seen.add(asset.hostname);
        inputs.push({ value: asset.hostname, type: "domain" });
      }
      // Add IP if available
      if (asset.ip && !seen.has(asset.ip)) {
        seen.add(asset.ip);
        inputs.push({ value: asset.ip, type: "ip" });
      }
    }

    return inputs;
  }, [assets]);

  // Corroboration mutation
  const corroborate = trpc.darkwebBridge.corroborateAssets.useMutation({
    onSuccess: () => setHasRun(true),
  });

  // Auto-run on mount if requested
  useEffect(() => {
    if (autoRun && assetInputs.length > 0 && !hasRun && !corroborate.isPending) {
      corroborate.mutate({ assets: assetInputs });
    }
  }, [autoRun, assetInputs.length]);

  const matches = corroborate.data?.matches || [];

  // Group matches by asset
  const groupedMatches = useMemo(() => {
    const groups: Record<string, CorroborationMatch[]> = {};
    for (const match of matches) {
      const key = match.asset;
      if (!groups[key]) groups[key] = [];
      groups[key].push(match as CorroborationMatch);
    }
    return groups;
  }, [matches]);

  // Count by tier
  const tierCounts = useMemo(() => {
    const counts = { confirmed: 0, probable: 0, potential: 0 };
    for (const match of matches) {
      const tier = (match as CorroborationMatch).corroborationTier;
      if (tier in counts) counts[tier]++;
    }
    return counts;
  }, [matches]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-display tracking-wider flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-purple-400" />
            IOC CORROBORATION
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Cross-reference discovered assets against threat indicators via SpicyThreatIntel
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="text-xs"
          onClick={() => corroborate.mutate({ assets: assetInputs })}
          disabled={corroborate.isPending || assetInputs.length === 0}
        >
          {corroborate.isPending ? (
            <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
          ) : (
            <Search className="h-3.5 w-3.5 mr-1.5" />
          )}
          {hasRun ? "Re-run Corroboration" : "Run Corroboration"}
        </Button>
      </div>

      {/* Status */}
      {corroborate.isPending && (
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="p-4 flex items-center gap-3">
            <Loader2 className="h-5 w-5 animate-spin text-purple-400" />
            <div>
              <p className="text-sm font-semibold">Corroborating {assetInputs.length} assets...</p>
              <p className="text-xs text-muted-foreground">Checking against threat indicator database</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Error */}
      {corroborate.error && (
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <div>
              <p className="text-sm font-semibold text-red-400">Corroboration Failed</p>
              <p className="text-xs text-muted-foreground">{corroborate.error.message}</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {hasRun && !corroborate.isPending && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-2xl font-bold">{assetInputs.length}</p>
                <p className="text-[10px] text-muted-foreground tracking-wider">ASSETS CHECKED</p>
              </CardContent>
            </Card>
            <Card className={matches.length > 0 ? "border-red-500/30" : "border-green-500/30"}>
              <CardContent className="p-3 text-center">
                <p className={`text-2xl font-bold ${matches.length > 0 ? "text-red-400" : "text-green-400"}`}>
                  {matches.length}
                </p>
                <p className="text-[10px] text-muted-foreground tracking-wider">IOC MATCHES</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{tierCounts.confirmed}</p>
                <p className="text-[10px] text-muted-foreground tracking-wider">CONFIRMED</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-3 text-center">
                <p className="text-2xl font-bold text-orange-400">{tierCounts.probable + tierCounts.potential}</p>
                <p className="text-[10px] text-muted-foreground tracking-wider">PROBABLE + POTENTIAL</p>
              </CardContent>
            </Card>
          </div>

          {/* No Matches */}
          {matches.length === 0 && (
            <Card className="border-green-500/30 bg-green-500/5">
              <CardContent className="p-6 text-center">
                <CheckCircle2 className="h-10 w-10 text-green-400 mx-auto mb-3" />
                <p className="text-sm font-semibold text-green-400">No IOC Matches Found</p>
                <p className="text-xs text-muted-foreground mt-1">
                  None of the {assetInputs.length} discovered assets matched known threat indicators.
                  This does not guarantee safety — it means no current IOC correlation was found.
                </p>
              </CardContent>
            </Card>
          )}

          {/* Grouped Matches */}
          {Object.entries(groupedMatches)
            .sort((a, b) => {
              // Sort by highest tier first
              const tierOrder = { confirmed: 0, probable: 1, potential: 2 };
              const aTier = Math.min(...a[1].map(m => tierOrder[m.corroborationTier] ?? 3));
              const bTier = Math.min(...b[1].map(m => tierOrder[m.corroborationTier] ?? 3));
              return aTier - bTier;
            })
            .map(([assetValue, assetMatches]) => {
              const isExpanded = expandedAsset === assetValue;
              const highestTier = assetMatches.reduce((best, m) => {
                const order = { confirmed: 0, probable: 1, potential: 2 };
                return (order[m.corroborationTier] ?? 3) < (order[best] ?? 3) ? m.corroborationTier : best;
              }, "potential" as "confirmed" | "probable" | "potential");
              const tierConf = TIER_CONFIG[highestTier];

              return (
                <Card key={assetValue} className={`${tierConf.color} transition-all`}>
                  <CardHeader
                    className="cursor-pointer p-4"
                    onClick={() => setExpandedAsset(isExpanded ? null : assetValue)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <tierConf.icon className="h-5 w-5 shrink-0" />
                        <div>
                          <CardTitle className="text-sm font-mono">{assetValue}</CardTitle>
                          <CardDescription className="text-[10px] mt-0.5">
                            {assetMatches.length} IOC match{assetMatches.length !== 1 ? "es" : ""} — {tierConf.description}
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${tierConf.color}`}>
                          {tierConf.label}
                        </Badge>
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </div>
                  </CardHeader>
                  {isExpanded && (
                    <CardContent className="pt-0 pb-4 px-4 space-y-2">
                      {assetMatches.map((match, idx) => {
                        const ioc = match.matchedIOC;
                        const matchTier = TIER_CONFIG[match.corroborationTier];
                        return (
                          <div key={idx} className="bg-background/50 border border-border/50 p-3 space-y-2">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-[10px]">
                                  {safeUpper(ioc.iocType || ioc.type || "UNK")}
                                </Badge>
                                <span className="font-mono text-xs text-muted-foreground truncate max-w-[300px]">
                                  {ioc.value || ioc.ioc || "—"}
                                </span>
                              </div>
                              <Badge className={`text-[9px] ${matchTier.color}`}>
                                {matchTier.label}
                              </Badge>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
                              {ioc.malwareFamily && (
                                <div>
                                  <span className="text-muted-foreground">Malware: </span>
                                  <span className="text-red-400">{ioc.malwareFamily}</span>
                                </div>
                              )}
                              {ioc.threatType && (
                                <div>
                                  <span className="text-muted-foreground">Threat: </span>
                                  <span className="text-orange-400">{ioc.threatType}</span>
                                </div>
                              )}
                              {ioc.confidence != null && (
                                <div>
                                  <span className="text-muted-foreground">Confidence: </span>
                                  <span className={ioc.confidence > 70 ? "text-red-400" : ioc.confidence > 40 ? "text-amber-400" : "text-muted-foreground"}>
                                    {ioc.confidence}%
                                  </span>
                                </div>
                              )}
                              {ioc.reporter && (
                                <div>
                                  <span className="text-muted-foreground">Reporter: </span>
                                  <span>{ioc.reporter}</span>
                                </div>
                              )}
                            </div>

                            <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                              {ioc.firstSeen && <span>First seen: {new Date(ioc.firstSeen).toLocaleDateString()}</span>}
                              {ioc.lastSeen && <span>Last seen: {new Date(ioc.lastSeen).toLocaleDateString()}</span>}
                              {ioc.tags && ioc.tags.length > 0 && (
                                <span className="flex items-center gap-1">
                                  Tags: {ioc.tags.slice(0, 3).join(", ")}
                                </span>
                              )}
                              {ioc.reference && (
                                <a
                                  href={ioc.reference}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-primary hover:underline flex items-center gap-0.5 ml-auto"
                                >
                                  <ExternalLink className="h-3 w-3" /> Reference
                                </a>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </CardContent>
                  )}
                </Card>
              );
            })}
        </>
      )}

      {/* Not yet run */}
      {!hasRun && !corroborate.isPending && (
        <Card className="border-border">
          <CardContent className="p-8 text-center">
            <Bug className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              Click "Run Corroboration" to cross-reference {assetInputs.length} discovered assets
              against threat indicators for known threat indicators.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
