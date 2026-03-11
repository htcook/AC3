import { useState, useEffect, useCallback, useRef } from "react";
import { trpc } from "@/lib/trpc";
import { useLocation } from "wouter";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Shield, Clock, LogOut } from "lucide-react";

// Warning appears 5 minutes before expiry
const WARNING_THRESHOLD_MS = 5 * 60 * 1000;
// Check interval: every 30 seconds
const CHECK_INTERVAL_MS = 30 * 1000;

export function SessionTimeoutMonitor() {
  const [showWarning, setShowWarning] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState<string>("");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [, setLocation] = useLocation();
  const expiresAtRef = useRef<number | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: session } = trpc.calderaAuth.session.useQuery(undefined, {
    refetchInterval: CHECK_INTERVAL_MS,
    refetchIntervalInBackground: false,
  });

  const refreshMutation = trpc.calderaAuth.refreshSession.useMutation();
  const utils = trpc.useUtils();

  // Format remaining time as "Xm Ys"
  const formatTimeRemaining = useCallback((ms: number): string => {
    if (ms <= 0) return "0s";
    const totalSeconds = Math.floor(ms / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
  }, []);

  // Update countdown display
  const updateCountdown = useCallback(() => {
    if (!expiresAtRef.current) return;
    const remaining = expiresAtRef.current - Date.now();
    if (remaining <= 0) {
      setShowWarning(false);
      // Session expired — redirect to login
      setLocation("/login?expired=true");
      return;
    }
    setTimeRemaining(formatTimeRemaining(remaining));
  }, [formatTimeRemaining, setLocation]);

  // Monitor session expiry
  useEffect(() => {
    if (!session?.authenticated || !session?.expiresAt) {
      expiresAtRef.current = null;
      setShowWarning(false);
      return;
    }

    expiresAtRef.current = session.expiresAt;
    const remaining = session.expiresAt - Date.now();

    if (remaining <= 0) {
      // Already expired
      setLocation("/login?expired=true");
      return;
    }

    if (remaining <= WARNING_THRESHOLD_MS) {
      // Already within warning window
      setShowWarning(true);
      updateCountdown();
      // Start countdown ticker
      if (countdownRef.current) clearInterval(countdownRef.current);
      countdownRef.current = setInterval(updateCountdown, 1000);
    } else {
      // Schedule warning for when we enter the threshold
      setShowWarning(false);
      if (timerRef.current) clearTimeout(timerRef.current);
      const delay = remaining - WARNING_THRESHOLD_MS;
      timerRef.current = setTimeout(() => {
        setShowWarning(true);
        updateCountdown();
        if (countdownRef.current) clearInterval(countdownRef.current);
        countdownRef.current = setInterval(updateCountdown, 1000);
      }, delay) as unknown as ReturnType<typeof setInterval>;
    }

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, [session?.authenticated, session?.expiresAt, setLocation, updateCountdown]);

  // Handle "Stay Logged In" click
  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      const result = await refreshMutation.mutateAsync();
      if (result.success && result.expiresAt) {
        expiresAtRef.current = result.expiresAt;
        setShowWarning(false);
        if (countdownRef.current) clearInterval(countdownRef.current);
        // Invalidate session query to pick up new expiry
        await utils.calderaAuth.session.invalidate();
      } else {
        // Refresh failed — session expired
        setLocation("/login?expired=true");
      }
    } catch {
      setLocation("/login?expired=true");
    } finally {
      setIsRefreshing(false);
    }
  };

  // Handle logout
  const handleLogout = () => {
    setShowWarning(false);
    setLocation("/login");
  };

  if (!showWarning) return null;

  return (
    <Dialog open={showWarning} onOpenChange={(open) => !open && setShowWarning(false)}>
      <DialogContent className="sm:max-w-md border-amber-500/50 bg-background">
        <DialogHeader>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded-full bg-amber-500/10">
              <Shield className="h-6 w-6 text-amber-500" />
            </div>
            <DialogTitle className="text-lg font-semibold">
              Session Expiring Soon
            </DialogTitle>
          </div>
          <DialogDescription className="text-muted-foreground">
            Your session will expire in{" "}
            <span className="font-mono font-semibold text-amber-500">
              {timeRemaining}
            </span>
            . For security, inactive sessions are automatically terminated per NIST SP 800-63B guidelines.
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
          <Clock className="h-4 w-4 text-amber-500 shrink-0" />
          <p className="text-sm text-muted-foreground">
            Click <strong>Stay Logged In</strong> to extend your session, or{" "}
            <strong>Log Out</strong> to end it now.
          </p>
        </div>

        <DialogFooter className="flex gap-2 sm:gap-2">
          <Button
            variant="outline"
            onClick={handleLogout}
            className="gap-2"
          >
            <LogOut className="h-4 w-4" />
            Log Out
          </Button>
          <Button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="gap-2 bg-amber-500 hover:bg-amber-600 text-black font-semibold"
          >
            <Shield className="h-4 w-4" />
            {isRefreshing ? "Refreshing..." : "Stay Logged In"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
