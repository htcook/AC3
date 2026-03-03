import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Monitor, Smartphone, Tablet, Globe, MapPin, Clock, Shield,
  LogOut, AlertTriangle, CheckCircle2, Laptop, Trash2, RefreshCw,
  Activity, Users
} from "lucide-react";
import AppShell from "@/components/AppShell";

const DEVICE_ICONS: Record<string, React.ReactNode> = {
  desktop: <Monitor className="h-8 w-8" />,
  mobile: <Smartphone className="h-8 w-8" />,
  tablet: <Tablet className="h-8 w-8" />,
};

const BROWSER_COLORS: Record<string, string> = {
  Chrome: "text-green-400",
  Firefox: "text-orange-400",
  Safari: "text-blue-400",
  Edge: "text-blue-500",
  Opera: "text-red-400",
  Unknown: "text-zinc-400",
};

const LOGIN_METHOD_LABELS: Record<string, { label: string; color: string }> = {
  oauth: { label: "OAuth", color: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  saml: { label: "SAML SSO", color: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
  api_key: { label: "API Key", color: "bg-purple-500/10 text-purple-400 border-purple-500/20" },
};

export default function SessionManagement() {
  const { user } = useAuth();

  const isAdmin = user?.role === "admin";

  const mySessions = trpc.sessions.listMySessions.useQuery();
  const sessionStats = trpc.sessions.getSessionStats.useQuery();
  const allSessions = trpc.sessions.listAllSessions.useQuery({ limit: 50 }, { enabled: isAdmin });

  const revokeSession = trpc.sessions.revokeSession.useMutation({
    onSuccess: () => {
      toast.success("Session revoked — the session has been terminated.");
      mySessions.refetch();
      sessionStats.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeAllOther = trpc.sessions.revokeAllOtherSessions.useMutation({
    onSuccess: () => {
      toast.success("All other sessions revoked — only your current session remains active.");
      mySessions.refetch();
      sessionStats.refetch();
    },
  });

  const adminRevoke = trpc.sessions.adminRevokeSession.useMutation({
    onSuccess: () => {
      toast.success("Session revoked (admin)");
      allSessions.refetch();
    },
  });

  const adminRevokeAll = trpc.sessions.adminRevokeAllUserSessions.useMutation({
    onSuccess: () => {
      toast.success("All user sessions revoked");
      allSessions.refetch();
    },
  });

  const cleanupExpired = trpc.sessions.cleanupExpired.useMutation({
    onSuccess: (data) => {
      toast.success(`Cleanup complete — ${data.cleaned} expired sessions cleaned.`);
      allSessions.refetch();
    },
  });

  return (
    <AppShell activePath="/sessions">
    <div className="space-y-6 p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-amber-500" />
            Session Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitor and manage active sessions across all your devices.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => { mySessions.refetch(); sessionStats.refetch(); }}>
            <RefreshCw className="h-4 w-4 mr-2" /> Refresh
          </Button>
          <Button variant="destructive" onClick={() => {
            if (confirm("Revoke all other sessions? You'll only remain logged in on this device.")) {
              revokeAllOther.mutate({});
            }
          }} disabled={revokeAllOther.isPending}>
            <LogOut className="h-4 w-4 mr-2" /> Revoke All Other Sessions
          </Button>
        </div>
      </div>

      {/* Stats */}
      {sessionStats.data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard icon={<Activity className="h-5 w-5 text-green-400" />} label="Active Sessions" value={sessionStats.data.activeSessions} />
          <StatCard icon={<Laptop className="h-5 w-5 text-blue-400" />} label="Unique Devices" value={sessionStats.data.uniqueDevices} />
          <StatCard icon={<MapPin className="h-5 w-5 text-amber-400" />} label="Unique Locations" value={sessionStats.data.uniqueLocations} />
          <StatCard icon={<Clock className="h-5 w-5 text-purple-400" />} label="Total Sessions" value={sessionStats.data.totalSessions} />
        </div>
      )}

      <Tabs defaultValue="my-sessions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="my-sessions">My Sessions</TabsTrigger>
          {isAdmin && <TabsTrigger value="all-sessions">All Sessions (Admin)</TabsTrigger>}
        </TabsList>

        {/* My Sessions Tab */}
        <TabsContent value="my-sessions" className="space-y-4">
          {mySessions.data?.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="pt-6 text-center">
                <Monitor className="h-12 w-12 mx-auto mb-4 text-zinc-400" />
                <h3 className="text-lg font-semibold">No Active Sessions</h3>
                <p className="text-sm text-muted-foreground mt-2">
                  Session tracking will begin on your next login.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {mySessions.data?.map((session) => (
                <SessionCard
                  key={session.id}
                  session={session}
                  onRevoke={() => {
                    if (confirm("Revoke this session? The device will be logged out.")) {
                      revokeSession.mutate({ sessionId: session.id });
                    }
                  }}
                  isRevoking={revokeSession.isPending}
                />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Admin All Sessions Tab */}
        {isAdmin && (
          <TabsContent value="all-sessions" className="space-y-4">
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                {allSessions.data?.length || 0} active sessions across all users
              </p>
              <Button variant="outline" size="sm" onClick={() => cleanupExpired.mutate()} disabled={cleanupExpired.isPending}>
                <Trash2 className="h-3.5 w-3.5 mr-1" /> Cleanup Expired
              </Button>
            </div>
            <div className="space-y-2">
              {allSessions.data?.map((session) => (
                <Card key={session.id} className="p-4">
                  <div className="flex items-center gap-4">
                    <div className="shrink-0 text-zinc-400">
                      {DEVICE_ICONS[session.deviceType || "desktop"] || DEVICE_ICONS.desktop}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{session.userName || "Unknown"}</span>
                        <Badge variant="outline" className="text-xs">{session.userRole}</Badge>
                        <Badge variant="outline" className={LOGIN_METHOD_LABELS[session.loginMethod]?.color || ""}>
                          {LOGIN_METHOD_LABELS[session.loginMethod]?.label || session.loginMethod}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-muted-foreground mt-1">
                        <span>{session.browserName} on {session.osName}</span>
                        {session.geoCity && <span className="flex items-center gap-1"><MapPin className="h-3 w-3" />{session.geoCity}, {session.geoCountry}</span>}
                        <span>{session.ipAddress}</span>
                        <span>Last active: {new Date(session.lastActivityAt).toLocaleString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Button variant="ghost" size="sm" className="text-red-500" onClick={() => {
                        if (confirm(`Revoke session for ${session.userName}?`)) {
                          adminRevoke.mutate({ sessionId: session.id });
                        }
                      }}>
                        <LogOut className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="sm" className="text-red-500" onClick={() => {
                        if (confirm(`Revoke ALL sessions for ${session.userName}?`)) {
                          adminRevokeAll.mutate({ userId: session.userId });
                        }
                      }}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
    </AppShell>
  );
}

// ─── Sub-components ─────────────────────────────────────────────────────────

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <Card>
      <CardContent className="pt-4 pb-3">
        <div className="flex items-center gap-3">
          {icon}
          <div>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-xs text-muted-foreground">{label}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function SessionCard({ session, onRevoke, isRevoking }: {
  session: any;
  onRevoke: () => void;
  isRevoking: boolean;
}) {
  const isCurrent = session.isCurrent;
  const loginInfo = LOGIN_METHOD_LABELS[session.loginMethod] || LOGIN_METHOD_LABELS.oauth;

  return (
      <Card className={isCurrent ? "border-amber-500/30 bg-amber-500/5" : ""}>
      <CardContent className="pt-5 pb-4">
        <div className="flex items-start gap-4">
          <div className={`shrink-0 ${isCurrent ? "text-amber-400" : "text-zinc-400"}`}>
            {DEVICE_ICONS[session.deviceType || "desktop"] || DEVICE_ICONS.desktop}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`font-semibold ${BROWSER_COLORS[session.browserName] || BROWSER_COLORS.Unknown}`}>
                {session.browserName} {session.browserVersion}
              </span>
              {isCurrent && <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-xs">Current</Badge>}
              <Badge variant="outline" className={`text-xs ${loginInfo.color}`}>{loginInfo.label}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              {session.osName} {session.osVersion} · {session.deviceType}
            </p>

            <div className="mt-3 space-y-1.5 text-xs">
              {(session.geoCity || session.geoCountry) && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <MapPin className="h-3.5 w-3.5 shrink-0" />
                  <span>{[session.geoCity, session.geoRegion, session.geoCountry].filter(Boolean).join(", ")}</span>
                </div>
              )}
              {session.ipAddress && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Globe className="h-3.5 w-3.5 shrink-0" />
                  <span className="font-mono">{session.ipAddress}</span>
                </div>
              )}
              <div className="flex items-center gap-2 text-muted-foreground">
                <Clock className="h-3.5 w-3.5 shrink-0" />
                <span>Last active: {new Date(session.lastActivityAt).toLocaleString()}</span>
              </div>
              <div className="flex items-center gap-2 text-muted-foreground">
                <Shield className="h-3.5 w-3.5 shrink-0" />
                <span>Created: {new Date(session.createdAt).toLocaleString()}</span>
              </div>
              {session.expiresAt && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  <span>Expires: {new Date(session.expiresAt).toLocaleString()}</span>
                </div>
              )}
            </div>

            {!isCurrent && (
              <Button variant="outline" size="sm" className="mt-3 text-red-500 border-red-500/30 hover:bg-red-500/10"
                onClick={onRevoke} disabled={isRevoking}>
                <LogOut className="h-3.5 w-3.5 mr-1" /> Revoke Session
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
