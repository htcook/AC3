/**
 * TransportIndicator — Shows the active real-time transport (WS / SSE / Offline)
 * in the sidebar footer, next to the FIPS indicator.
 */
import { Wifi, WifiOff, Radio } from "lucide-react";
import { useWebSocket, type TransportMode, type ConnectionStatus } from "@/hooks/useWebSocket";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useMemo } from "react";

const transportConfig: Record<
  TransportMode,
  Record<ConnectionStatus | "default", { label: string; color: string; icon: typeof Wifi; pulse?: boolean }>
> = {
  websocket: {
    connected: { label: "WebSocket", color: "text-emerald-400", icon: Wifi },
    connecting: { label: "Connecting (WS)", color: "text-amber-400", icon: Wifi, pulse: true },
    disconnected: { label: "Disconnected", color: "text-zinc-500", icon: WifiOff },
    error: { label: "WS Error", color: "text-red-400", icon: WifiOff },
    default: { label: "WebSocket", color: "text-zinc-500", icon: Wifi },
  },
  sse: {
    connected: { label: "SSE Fallback", color: "text-blue-400", icon: Radio },
    connecting: { label: "Connecting (SSE)", color: "text-amber-400", icon: Radio, pulse: true },
    disconnected: { label: "Disconnected", color: "text-zinc-500", icon: WifiOff },
    error: { label: "SSE Error", color: "text-red-400", icon: WifiOff },
    default: { label: "SSE", color: "text-zinc-500", icon: Radio },
  },
  none: {
    connected: { label: "Connected", color: "text-emerald-400", icon: Wifi },
    connecting: { label: "Connecting…", color: "text-amber-400", icon: Wifi, pulse: true },
    disconnected: { label: "Offline", color: "text-zinc-500", icon: WifiOff },
    error: { label: "Connection Error", color: "text-red-400", icon: WifiOff },
    default: { label: "Offline", color: "text-zinc-500", icon: WifiOff },
  },
};

export function TransportIndicator({ collapsed = false }: { collapsed?: boolean }) {
  const { status, transport } = useWebSocket({ enabled: true });

  const cfg = useMemo(() => {
    const modeConfig = transportConfig[transport] || transportConfig.none;
    return modeConfig[status] || modeConfig.default;
  }, [transport, status]);

  const Icon = cfg.icon;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          className={`flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-accent/50 transition-colors w-full text-left ${
            collapsed ? "justify-center" : ""
          }`}
          tabIndex={-1}
        >
          <Icon
            className={`h-4 w-4 shrink-0 ${cfg.color} ${cfg.pulse ? "animate-pulse" : ""}`}
          />
          {!collapsed && (
            <span className={`text-xs font-medium truncate ${cfg.color}`}>
              {cfg.label}
            </span>
          )}
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" className="text-xs">
        <p className="font-medium">{cfg.label}</p>
        <p className="text-muted-foreground">
          Transport: {transport === "none" ? "not connected" : transport.toUpperCase()}
          {" · "}Status: {status}
        </p>
      </TooltipContent>
    </Tooltip>
  );
}
