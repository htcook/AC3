import { useState, useRef, useEffect } from "react";
import { Bell, X, CheckCheck, AlertTriangle, Shield, ExternalLink } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useLocation } from "wouter";

interface NotificationBellProps {
  collapsed?: boolean;
}

export function NotificationBell({ collapsed }: NotificationBellProps) {
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const [, setLocation] = useLocation();

  const { data, refetch } = trpc.executiveDashboard.recentAlerts.useQuery(
    { limit: 20 },
    { refetchInterval: 60_000 } // Poll every 60s
  );

  const dismissMutation = trpc.executiveDashboard.dismissAlert.useMutation({
    onSuccess: () => refetch(),
  });

  const dismissAllMutation = trpc.executiveDashboard.dismissAllAlerts.useMutation({
    onSuccess: () => refetch(),
  });

  const alerts = data?.alerts || [];
  const unreadCount = data?.unreadCount || 0;

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [open]);

  const threatLevelColor = (level: string | null) => {
    switch (level?.toLowerCase()) {
      case "critical": return "text-red-400";
      case "high": return "text-orange-400";
      case "medium": return "text-yellow-400";
      default: return "text-blue-400";
    }
  };

  const threatLevelBg = (level: string | null) => {
    switch (level?.toLowerCase()) {
      case "critical": return "bg-red-500/10 border-red-500/20";
      case "high": return "bg-orange-500/10 border-orange-500/20";
      case "medium": return "bg-yellow-500/10 border-yellow-500/20";
      default: return "bg-blue-500/10 border-blue-500/20";
    }
  };

  const handleAlertClick = (alert: typeof alerts[0]) => {
    // Navigate to executive dashboard with threat briefing
    setLocation("/");
    setOpen(false);
  };

  const formatTime = (ts: number | Date | null) => {
    if (!ts) return "";
    const date = typeof ts === "number" ? new Date(ts) : ts;
    const now = Date.now();
    const diff = now - date.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
    return date.toLocaleDateString();
  };

  if (collapsed) {
    return (
      <div className="relative" ref={dropdownRef}>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={() => setOpen(!open)}
              className="h-9 w-9 flex items-center justify-center rounded-lg hover:bg-accent transition-colors relative"
              aria-label="Notifications"
            >
              <Bell className="h-4 w-4 text-muted-foreground" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 h-4 min-w-4 px-0.5 flex items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              )}
            </button>
          </TooltipTrigger>
          <TooltipContent side="right" sideOffset={8}>
            Threat Alerts {unreadCount > 0 ? `(${unreadCount} new)` : ""}
          </TooltipContent>
        </Tooltip>

        {open && <AlertDropdown
          alerts={alerts}
          unreadCount={unreadCount}
          onDismiss={(id) => dismissMutation.mutate({ alertId: id })}
          onDismissAll={() => dismissAllMutation.mutate()}
          onAlertClick={handleAlertClick}
          threatLevelColor={threatLevelColor}
          threatLevelBg={threatLevelBg}
          formatTime={formatTime}
          position="right"
        />}
      </div>
    );
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 w-full rounded-lg px-2 py-1.5 hover:bg-accent/50 transition-colors text-left relative"
        aria-label="Notifications"
      >
        <Bell className="h-4 w-4 text-muted-foreground shrink-0" />
        <span className="text-sm text-muted-foreground truncate">Threat Alerts</span>
        {unreadCount > 0 && (
          <span className="ml-auto h-5 min-w-5 px-1 flex items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white shrink-0">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {open && <AlertDropdown
        alerts={alerts}
        unreadCount={unreadCount}
        onDismiss={(id) => dismissMutation.mutate({ alertId: id })}
        onDismissAll={() => dismissAllMutation.mutate()}
        onAlertClick={handleAlertClick}
        threatLevelColor={threatLevelColor}
        threatLevelBg={threatLevelBg}
        formatTime={formatTime}
        position="right"
      />}
    </div>
  );
}

// ─── Alert Dropdown Panel ───────────────────────────────────────────────────

interface AlertDropdownProps {
  alerts: Array<{
    id: number;
    actorId: string;
    actorName: string | null;
    relevanceScore: number;
    threatLevel: string | null;
    triggerReason: string | null;
    notificationSent: boolean;
    scanId: number | null;
    dismissed: boolean;
    createdAt: number | Date | null;
  }>;
  unreadCount: number;
  onDismiss: (id: number) => void;
  onDismissAll: () => void;
  onAlertClick: (alert: AlertDropdownProps["alerts"][0]) => void;
  threatLevelColor: (level: string | null) => string;
  threatLevelBg: (level: string | null) => string;
  formatTime: (ts: number | Date | null) => string;
  position?: "right" | "bottom";
}

function AlertDropdown({
  alerts,
  unreadCount,
  onDismiss,
  onDismissAll,
  onAlertClick,
  threatLevelColor,
  threatLevelBg,
  formatTime,
  position = "right",
}: AlertDropdownProps) {
  const positionClass = position === "right"
    ? "left-full top-0 ml-2"
    : "top-full left-0 mt-1";

  return (
    <div
      className={`absolute ${positionClass} z-[100] w-80 max-h-[480px] bg-popover border border-border rounded-xl shadow-2xl overflow-hidden animate-in fade-in-0 zoom-in-95 duration-150`}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b bg-popover/95 backdrop-blur">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" />
          <span className="font-semibold text-sm">Threat Alerts</span>
          {unreadCount > 0 && (
            <span className="h-5 min-w-5 px-1 flex items-center justify-center rounded-full bg-red-500/15 text-red-400 text-[10px] font-bold">
              {unreadCount}
            </span>
          )}
        </div>
        {unreadCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-muted-foreground hover:text-foreground"
            onClick={(e) => { e.stopPropagation(); onDismissAll(); }}
          >
            <CheckCheck className="h-3 w-3 mr-1" />
            Clear all
          </Button>
        )}
      </div>

      {/* Alert list */}
      <div className="overflow-y-auto max-h-[400px] scrollbar-thin scrollbar-thumb-border">
        {alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
            <Bell className="h-8 w-8 text-muted-foreground/30 mb-3" />
            <p className="text-sm text-muted-foreground">No recent alerts</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Alerts fire when threat actors exceed configured relevance thresholds
            </p>
          </div>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.id}
              className={`group flex items-start gap-3 px-4 py-3 border-b border-border/50 cursor-pointer transition-colors hover:bg-accent/30 ${
                !alert.dismissed ? "bg-accent/10" : ""
              }`}
              onClick={() => onAlertClick(alert)}
            >
              {/* Threat level indicator */}
              <div className={`mt-0.5 h-8 w-8 rounded-lg flex items-center justify-center shrink-0 border ${threatLevelBg(alert.threatLevel)}`}>
                <AlertTriangle className={`h-4 w-4 ${threatLevelColor(alert.threatLevel)}`} />
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="font-medium text-sm truncate">{alert.actorName || alert.actorId}</span>
                  <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${threatLevelColor(alert.threatLevel)} bg-current/10`}>
                    {alert.threatLevel || "unknown"}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                  Score: {alert.relevanceScore}/100 — {alert.triggerReason}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[10px] text-muted-foreground/60">
                    {formatTime(alert.createdAt)}
                  </span>
                  <ExternalLink className="h-3 w-3 text-muted-foreground/40 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </div>

              {/* Dismiss button */}
              {!alert.dismissed && (
                <button
                  onClick={(e) => { e.stopPropagation(); onDismiss(alert.id); }}
                  className="mt-1 h-6 w-6 flex items-center justify-center rounded hover:bg-accent transition-colors opacity-0 group-hover:opacity-100 shrink-0"
                  aria-label="Dismiss alert"
                >
                  <X className="h-3 w-3 text-muted-foreground" />
                </button>
              )}
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      {alerts.length > 0 && (
        <div className="px-4 py-2 border-t bg-popover/95 backdrop-blur">
          <button
            onClick={() => onAlertClick(alerts[0])}
            className="text-xs text-primary hover:underline w-full text-center"
          >
            View Executive Threat Briefing
          </button>
        </div>
      )}
    </div>
  );
}
