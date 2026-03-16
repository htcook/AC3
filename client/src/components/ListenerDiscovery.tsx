// @ts-nocheck
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Radar, RefreshCw, Wifi, WifiOff, Plus, Check, Server,
  ChevronDown, ChevronUp, AlertTriangle, Loader2
} from "lucide-react";

const FRAMEWORK_COLORS: Record<string, string> = {
  caldera: "text-red-400 bg-red-500/10 border-red-500/30",
  empire: "text-purple-400 bg-purple-500/10 border-purple-500/30",
  sliver: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  manjusaka: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  metasploit: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
  cobaltstrike: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

const STATUS_INDICATOR: Record<string, { color: string; icon: React.ReactNode }> = {
  active: { color: "text-emerald-400", icon: <Wifi className="w-3 h-3 text-emerald-400" /> },
  inactive: { color: "text-zinc-400", icon: <WifiOff className="w-3 h-3 text-zinc-400" /> },
  unknown: { color: "text-amber-400", icon: <AlertTriangle className="w-3 h-3 text-amber-400" /> },
};

interface ListenerDiscoveryProps {
  onAddUrl: (url: string) => void;
  isUrlSelected: (url: string) => boolean;
}

export default function ListenerDiscovery({ onAddUrl, isUrlSelected }: ListenerDiscoveryProps) {
  const [expanded, setExpanded] = useState(false);
  const listenersQuery = trpc.ember.discoverListeners.useQuery(undefined, {
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

  const listeners = listenersQuery.data || [];
  const activeCount = listeners.filter(l => l.status === "active").length;
  const frameworkGroups = listeners.reduce((acc, l) => {
    if (!acc[l.framework]) acc[l.framework] = [];
    acc[l.framework].push(l);
    return acc;
  }, {} as Record<string, typeof listeners>);

  return (
    <Card className="bg-zinc-900/40 border-border/40">
      <CardHeader
        className="py-3 px-4 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-1.5 rounded-md bg-amber-500/10 border border-amber-500/20">
              <Radar className="w-4 h-4 text-amber-400" />
            </div>
            <div>
              <CardTitle className="text-sm">Live Listener Discovery</CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                {listenersQuery.isLoading
                  ? "Scanning C2 frameworks..."
                  : `${activeCount} active listener${activeCount !== 1 ? "s" : ""} across ${Object.keys(frameworkGroups).length} framework${Object.keys(frameworkGroups).length !== 1 ? "s" : ""}`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={(e) => {
                e.stopPropagation();
                listenersQuery.refetch();
              }}
              disabled={listenersQuery.isFetching}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${listenersQuery.isFetching ? "animate-spin" : ""}`} />
            </Button>
            {expanded ? (
              <ChevronUp className="w-4 h-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="w-4 h-4 text-muted-foreground" />
            )}
          </div>
        </div>
      </CardHeader>

      {expanded && (
        <CardContent className="px-4 pb-4 border-t border-border/30 pt-3">
          {listenersQuery.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" />
              Querying C2 frameworks for active listeners...
            </div>
          ) : listeners.length === 0 ? (
            <div className="text-center py-6 text-sm text-muted-foreground">
              <Server className="w-8 h-8 mx-auto mb-2 opacity-30" />
              <p>No active listeners discovered</p>
              <p className="text-xs mt-1">Configure C2 framework connections to enable auto-discovery</p>
            </div>
          ) : (
            <div className="space-y-4">
              {Object.entries(frameworkGroups).map(([framework, fwListeners]) => (
                <div key={framework} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[10px] uppercase tracking-wider ${FRAMEWORK_COLORS[framework] || ""}`}>
                      {framework}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">
                      {fwListeners.length} listener{fwListeners.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {fwListeners.map((listener) => {
                      const selected = isUrlSelected(listener.callbackUrl);
                      const statusMeta = STATUS_INDICATOR[listener.status] || STATUS_INDICATOR.unknown;
                      return (
                        <button
                          key={listener.id}
                          onClick={() => onAddUrl(listener.callbackUrl)}
                          className={`flex items-center gap-3 p-3 rounded-lg border text-left transition-all ${
                            selected
                              ? "bg-amber-500/5 border-amber-500/40 ring-1 ring-amber-500/20"
                              : "bg-zinc-950/30 border-border/30 hover:border-border/60"
                          }`}
                        >
                          <div className="shrink-0">
                            {selected ? (
                              <Check className="w-4 h-4 text-emerald-400" />
                            ) : (
                              <Plus className="w-4 h-4 text-muted-foreground" />
                            )}
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              {statusMeta.icon}
                              <span className="text-sm font-medium text-foreground truncate">{listener.name}</span>
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <span className="font-mono text-xs text-muted-foreground truncate">{listener.callbackUrl}</span>
                            </div>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="outline" className="text-[8px]">{listener.protocol}</Badge>
                              <span className="text-[10px] text-muted-foreground">Port {listener.port}</span>
                            </div>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}
