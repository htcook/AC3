import { useState } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter
} from "@/components/ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger, DropdownMenuSeparator
} from "@/components/ui/dropdown-menu";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import {
  Server, Users, Shield, ArrowRight, Activity, Database,
  AlertTriangle, CheckCircle2, Settings, Cpu, Wifi,
  UserPlus, MoreHorizontal, Mail, KeyRound, Ban, RefreshCw,
  Copy, Eye, EyeOff, Monitor, Trash2, LogOut
} from "lucide-react";

// ─── Health Indicator ────────────────────────────────────────────────
function HealthIndicator({ label, status, detail }: { label: string; status: "healthy" | "warning" | "error"; detail: string }) {
  const colors = { healthy: "bg-emerald-500", warning: "bg-amber-500", error: "bg-red-500" };
  return (
    <div className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg">
      <div className={`w-3 h-3 rounded-full ${colors[status]} shrink-0`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-display tracking-wider">{label}</p>
        <p className="text-[10px] text-muted-foreground">{detail}</p>
      </div>
      <span className={`text-[9px] font-display tracking-widest px-2 py-0.5 rounded-full ${
        status === "healthy" ? "bg-emerald-500/20 text-emerald-400" :
        status === "warning" ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
      }`}>{status.toUpperCase()}</span>
    </div>
  );
}

// ─── Role badge colors ───────────────────────────────────────────────
const ROLE_COLORS: Record<string, string> = {
  admin: "bg-red-500/20 text-red-400 border-red-500/30",
  operator: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  analyst: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  team_lead: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  executive: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  client: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  soc: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  viewer: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-emerald-500/20 text-emerald-400",
  invited: "bg-blue-500/20 text-blue-400",
  suspended: "bg-amber-500/20 text-amber-400",
  deactivated: "bg-red-500/20 text-red-400",
};

const ALL_ROLES = ["admin", "operator", "analyst", "team_lead", "executive", "client", "soc", "viewer"] as const;

export default function AdminHome() {

  const utils = trpc.useUtils();

  // ─── Data queries ─────────────────────────────────────────────────
  const { data: accounts, isLoading: accountsLoading } = trpc.accountAuth.listAccounts.useQuery(undefined, {
    retry: 1,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  const { data: sessions, isLoading: sessionsLoading } = trpc.accountAuth.listSessions.useQuery(undefined, {
    retry: 1,
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  // ─── Mutations ────────────────────────────────────────────────────
  const inviteMutation = trpc.accountAuth.inviteUser.useMutation({
    onSuccess: (data) => {
      utils.accountAuth.listAccounts.invalidate();
      setInviteOpen(false);
      setInviteForm({ email: "", displayName: "", role: "operator", tempPassword: "" });
      toast.success(`${data.email} has been invited as ${data.role}`);
    },
    onError: (err) => {
      toast.error(`Invite failed: ${err.message}`);
    },
  });

  const updateMutation = trpc.accountAuth.updateAccount.useMutation({
    onSuccess: () => {
      utils.accountAuth.listAccounts.invalidate();
      toast.success("Account updated");
    },
    onError: (err) => {
      toast.error(`Update failed: ${err.message}`);
    },
  });

  const resendMutation = trpc.accountAuth.resendInvite.useMutation({
    onSuccess: () => {
      toast.success("Invite resent — new token generated");
    },
    onError: (err) => {
      toast.error(`Resend failed: ${err.message}`);
    },
  });

  const resetMutation = trpc.accountAuth.resetPassword.useMutation({
    onSuccess: (data) => {
      setResetResult(data.tempPassword);
      toast.success("Password reset — temporary password generated");
    },
    onError: (err) => {
      toast.error(`Reset failed: ${err.message}`);
    },
  });

  const revokeSessionMutation = trpc.accountAuth.revokeSession.useMutation({
    onSuccess: () => {
      utils.accountAuth.listSessions.invalidate();
      toast.success("Session revoked");
    },
    onError: (err) => toast.error(`Revoke failed: ${err.message}`),
  });

  const revokeAllSessionsMutation = trpc.accountAuth.revokeAllSessions.useMutation({
    onSuccess: () => {
      utils.accountAuth.listSessions.invalidate();
      toast.success("All sessions revoked for this account");
    },
    onError: (err) => toast.error(`Revoke failed: ${err.message}`),
  });

  // ─── Local state ──────────────────────────────────────────────────
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteForm, setInviteForm] = useState({ email: "", displayName: "", role: "operator", tempPassword: "" });
  const [showTempPassword, setShowTempPassword] = useState(false);
  const [resetResult, setResetResult] = useState<string | null>(null);
  const [showResetPassword, setShowResetPassword] = useState(false);

  // ─── Computed stats ───────────────────────────────────────────────
  const totalAccounts = accounts?.length ?? 0;
  const activeAccounts = accounts?.filter((a) => a.status === "active").length ?? 0;
  const pendingInvites = accounts?.filter((a) => a.status === "invited").length ?? 0;
  const roleCounts = accounts?.reduce((acc, a) => {
    acc[a.role] = (acc[a.role] || 0) + 1;
    return acc;
  }, {} as Record<string, number>) ?? {};

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-display tracking-wider font-bold">ADMIN DASHBOARD</h1>
          <p className="text-sm text-muted-foreground mt-1">System health, user management, and platform configuration</p>
        </div>
        <Link href="/dashboard">
          <Button variant="outline" size="sm" className="text-[10px] font-display tracking-wider gap-1.5">
            <Activity className="w-3.5 h-3.5" />
            OPERATIONS DASHBOARD
            <ArrowRight className="w-3 h-3" />
          </Button>
        </Link>
      </div>

      {/* System Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "TOTAL ACCOUNTS", value: String(totalAccounts), icon: Users, color: "bg-blue-500/80" },
          { label: "ACTIVE", value: String(activeAccounts), icon: CheckCircle2, color: "bg-emerald-500/80" },
          { label: "PENDING INVITES", value: String(pendingInvites), icon: Mail, color: "bg-amber-500/80" },
          { label: "SYSTEM ALERTS", value: "2", icon: AlertTriangle, color: "bg-red-500/80" },
        ].map((stat) => (
          <Card key={stat.label}>
            <CardContent className="p-4">
              <div className={`w-8 h-8 rounded ${stat.color} flex items-center justify-center mb-2`}>
                <stat.icon className="w-4 h-4 text-white" />
              </div>
              <p className="text-2xl font-display font-bold">{stat.value}</p>
              <p className="text-[10px] font-display tracking-widest text-muted-foreground mt-1">{stat.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* System Health + Account Management */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* System Health */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" /> SYSTEM HEALTH
              </CardTitle>
              <Link href="/error-dashboard">
                <Button variant="ghost" size="sm" className="text-[10px] font-display tracking-wider h-7">
                  DETAILS <ArrowRight className="w-3 h-3 ml-1" />
                </Button>
              </Link>
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            <HealthIndicator label="Cyber C2 Server" status="healthy" detail="v4.2.0 — 3 active agents" />
            <HealthIndicator label="Database" status="healthy" detail="TiDB — 2.1GB used, 98.7% uptime" />
            <HealthIndicator label="GoPhish Server" status="healthy" detail="v0.12.1 — 2 active campaigns" />
            <HealthIndicator label="ZAP Proxy" status="warning" detail="High memory usage (87%)" />
            <HealthIndicator label="Nuclei Engine" status="healthy" detail="v3.1.0 — 8,400 templates loaded" />
            <HealthIndicator label="SOCKS Proxy Chain" status="healthy" detail="3 active tunnels" />
          </CardContent>
        </Card>

        {/* Account Management — Live Data */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
                <Users className="w-4 h-4 text-blue-400" /> ACCOUNT MANAGEMENT
              </CardTitle>
              <Button
                variant="default"
                size="sm"
                className="text-[10px] font-display tracking-wider h-7 gap-1"
                onClick={() => setInviteOpen(true)}
              >
                <UserPlus className="w-3 h-3" /> INVITE USER
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* Role breakdown */}
            <div className="flex flex-wrap gap-2 mb-2">
              {Object.entries(roleCounts).sort((a, b) => b[1] - a[1]).map(([role, count]) => (
                <span key={role} className={`text-[9px] font-display tracking-widest px-2 py-1 rounded border ${ROLE_COLORS[role] || "bg-secondary text-foreground"}`}>
                  {role.replace("_", " ").toUpperCase()} ({count})
                </span>
              ))}
            </div>

            {/* Account list */}
            {accountsLoading ? (
              <div className="space-y-2">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-12 bg-secondary/30 rounded animate-pulse" />
                ))}
              </div>
            ) : !accounts?.length ? (
              <div className="text-center py-8">
                <Users className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
                <p className="text-xs text-muted-foreground">No accounts yet. Invite your first team member.</p>
              </div>
            ) : (
              <div className="space-y-1.5 max-h-[320px] overflow-y-auto pr-1">
                {accounts.map((account) => (
                  <div key={account.id} className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-secondary/30 transition-colors group">
                    {/* Status dot */}
                    <div className={`w-2 h-2 rounded-full shrink-0 ${
                      account.status === "active" ? "bg-emerald-500" :
                      account.status === "invited" ? "bg-blue-500 animate-pulse" :
                      account.status === "suspended" ? "bg-amber-500" : "bg-gray-500"
                    }`} />

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium truncate">{account.displayName || account.email}</span>
                        <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded ${ROLE_COLORS[account.role] || ""}`}>
                          {account.role.replace("_", " ").toUpperCase()}
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground truncate">{account.email}</p>
                    </div>

                    {/* Status badge */}
                    <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded hidden sm:inline-block ${STATUS_COLORS[account.status] || ""}`}>
                      {(account.status || '').toUpperCase()}
                    </span>

                    {/* Last login */}
                    <span className="text-[10px] text-muted-foreground hidden lg:block whitespace-nowrap">
                      {account.lastLoginAt ? new Date(account.lastLoginAt).toLocaleDateString() : "Never"}
                    </span>

                    {/* Actions dropdown */}
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity">
                          <MoreHorizontal className="w-3.5 h-3.5" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-48">
                        <DropdownMenuItem className="text-xs" disabled>
                          <Mail className="w-3.5 h-3.5 mr-2" /> {account.email}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />

                        {/* Role change submenu */}
                        {ALL_ROLES.filter((r) => r !== account.role).slice(0, 4).map((role) => (
                          <DropdownMenuItem
                            key={role}
                            className="text-xs"
                            onClick={() => updateMutation.mutate({ accountId: account.id, role })}
                          >
                            <Shield className="w-3.5 h-3.5 mr-2" />
                            Set {role.replace("_", " ")}
                          </DropdownMenuItem>
                        ))}
                        <DropdownMenuSeparator />

                        {/* Password reset */}
                        <DropdownMenuItem
                          className="text-xs"
                          onClick={() => resetMutation.mutate({ accountId: account.id })}
                        >
                          <KeyRound className="w-3.5 h-3.5 mr-2" /> Reset password
                        </DropdownMenuItem>

                        {/* Revoke all sessions */}
                        <DropdownMenuItem
                          className="text-xs text-cyan-400"
                          onClick={() => {
                            if (confirm(`Revoke all active sessions for ${account.displayName || account.email}?`)) {
                              revokeAllSessionsMutation.mutate({ accountId: account.id });
                            }
                          }}
                        >
                          <LogOut className="w-3.5 h-3.5 mr-2" /> Revoke all sessions
                        </DropdownMenuItem>

                        {/* Resend invite (only for invited status) */}
                        {account.status === "invited" && (
                          <DropdownMenuItem
                            className="text-xs"
                            onClick={() => resendMutation.mutate({ accountId: account.id })}
                          >
                            <RefreshCw className="w-3.5 h-3.5 mr-2" /> Resend invite
                          </DropdownMenuItem>
                        )}

                        {/* Suspend / Activate */}
                        {account.status === "active" ? (
                          <DropdownMenuItem
                            className="text-xs text-amber-400"
                            onClick={() => updateMutation.mutate({ accountId: account.id, status: "suspended" })}
                          >
                            <Ban className="w-3.5 h-3.5 mr-2" /> Suspend account
                          </DropdownMenuItem>
                        ) : account.status === "suspended" ? (
                          <DropdownMenuItem
                            className="text-xs text-emerald-400"
                            onClick={() => updateMutation.mutate({ accountId: account.id, status: "active" })}
                          >
                            <CheckCircle2 className="w-3.5 h-3.5 mr-2" /> Reactivate
                          </DropdownMenuItem>
                        ) : null}

                        {/* Deactivate */}
                        {account.status !== "deactivated" && (
                          <DropdownMenuItem
                            className="text-xs text-red-400"
                            onClick={() => updateMutation.mutate({ accountId: account.id, status: "deactivated" })}
                          >
                            <Ban className="w-3.5 h-3.5 mr-2" /> Deactivate
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Active Sessions Management */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
              <Monitor className="w-4 h-4 text-cyan-400" /> ACTIVE SESSIONS
            </CardTitle>
            <span className="text-[10px] font-display tracking-widest text-muted-foreground">
              {sessions?.length ?? 0} ACTIVE
            </span>
          </div>
        </CardHeader>
        <CardContent>
          {sessionsLoading ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-14 bg-secondary/30 rounded animate-pulse" />
              ))}
            </div>
          ) : !sessions?.length ? (
            <div className="text-center py-6">
              <Monitor className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
              <p className="text-xs text-muted-foreground">No active sessions.</p>
            </div>
          ) : (
            <div className="space-y-1.5 max-h-[400px] overflow-y-auto pr-1">
              {sessions.map((session) => (
                <div key={session.id} className="flex items-center gap-3 p-3 rounded-lg hover:bg-secondary/30 transition-colors group border border-transparent hover:border-border">
                  <Monitor className="w-4 h-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium truncate">
                        {session.userDisplayName || session.userEmail || `Account #${session.accountId}`}
                      </span>
                      <span className={`text-[8px] font-display tracking-widest px-1.5 py-0.5 rounded ${
                        ROLE_COLORS[session.userRole || ""] || "bg-secondary text-foreground"
                      }`}>
                        {(session.userRole || "unknown").replace("_", " ").toUpperCase()}
                      </span>
                    </div>
                    <p className="text-[10px] text-muted-foreground truncate">
                      {session.deviceInfo || "Unknown device"} — {session.ipAddress || "Unknown IP"}
                    </p>
                    <p className="text-[9px] text-muted-foreground">
                      Logged in: {session.createdAt ? new Date(session.createdAt).toLocaleString() : "Unknown"}
                      {" | Expires: "}{session.expiresAt ? new Date(session.expiresAt).toLocaleString() : "Unknown"}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 opacity-0 group-hover:opacity-100 transition-opacity text-red-400 hover:text-red-300 hover:bg-red-500/10"
                    onClick={() => revokeSessionMutation.mutate({ sessionId: session.id })}
                    disabled={revokeSessionMutation.isPending}
                  >
                    <LogOut className="w-3.5 h-3.5 mr-1" />
                    <span className="text-[10px] font-display tracking-wider">REVOKE</span>
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* CVE Enrichment Batch Job */}
      <CveEnrichmentCard />

      {/* Quick Admin Actions */}
      <div>
        <h2 className="text-sm font-display tracking-widest text-muted-foreground mb-3">ADMIN TOOLS</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            { href: "/servers", icon: Server, label: "SERVER MANAGEMENT", desc: "Configure C2, proxy, and scanner servers", color: "bg-blue-500/80" },
            { href: "/team", icon: Users, label: "USER & ROLES", desc: "Manage users, roles, and permissions", color: "bg-purple-500/80" },
            { href: "/audit-log", icon: Shield, label: "AUDIT LOG", desc: "Review all platform activity", color: "bg-amber-500/80" },
            { href: "/vendor-integrations", icon: Wifi, label: "INTEGRATIONS", desc: "API keys, webhooks, and connectors", color: "bg-emerald-500/80" },
            { href: "/error-dashboard", icon: AlertTriangle, label: "ERROR DASHBOARD", desc: "System errors and diagnostics", color: "bg-red-500/80" },
            { href: "/tenants", icon: Database, label: "TENANTS", desc: "Multi-tenant configuration", color: "bg-cyan-500/80" },
          ].map((tool) => (
            <Link key={tool.href} href={tool.href}>
              <Card className="group cursor-pointer hover:border-primary/30 transition-all duration-200 hover:shadow-lg hover:shadow-primary/5">
                <CardContent className="p-4 flex items-center gap-4">
                  <div className={`w-10 h-10 rounded-lg ${tool.color} flex items-center justify-center shrink-0`}>
                    <tool.icon className="w-5 h-5 text-white" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-display tracking-wider font-medium">{tool.label}</p>
                    <p className="text-xs text-muted-foreground">{tool.desc}</p>
                  </div>
                  <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </div>

      {/* ─── Invite User Dialog ──────────────────────────────────────── */}
      <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-display tracking-wider">INVITE TEAM MEMBER</DialogTitle>
            <DialogDescription>
              Send an invitation to join the platform. They'll receive a temporary password to set up their account.
            </DialogDescription>
          </DialogHeader>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              inviteMutation.mutate({
                email: inviteForm.email,
                displayName: inviteForm.displayName,
                role: inviteForm.role as any,
                tempPassword: inviteForm.tempPassword || undefined,
              });
            }}
            className="space-y-4"
          >
            <div className="space-y-2">
              <label className="text-[10px] font-display tracking-widest text-muted-foreground">EMAIL ADDRESS</label>
              <Input
                type="email"
                placeholder="partner@company.com"
                value={inviteForm.email}
                onChange={(e) => setInviteForm((f) => ({ ...f, email: e.target.value }))}
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-display tracking-widest text-muted-foreground">DISPLAY NAME</label>
              <Input
                placeholder="Jane Doe"
                value={inviteForm.displayName}
                onChange={(e) => setInviteForm((f) => ({ ...f, displayName: e.target.value }))}
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-display tracking-widest text-muted-foreground">ROLE</label>
              <Select value={inviteForm.role} onValueChange={(v) => setInviteForm((f) => ({ ...f, role: v }))}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ALL_ROLES.map((role) => (
                    <SelectItem key={role} value={role}>
                      {role.replace("_", " ").toUpperCase()}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-display tracking-widest text-muted-foreground">
                TEMPORARY PASSWORD <span className="text-muted-foreground/50">(optional — auto-generated if blank)</span>
              </label>
              <div className="relative">
                <Input
                  type={showTempPassword ? "text" : "password"}
                  placeholder="Min 12 chars, 1 upper, 1 lower, 1 digit, 1 special"
                  value={inviteForm.tempPassword}
                  onChange={(e) => setInviteForm((f) => ({ ...f, tempPassword: e.target.value }))}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                  onClick={() => setShowTempPassword(!showTempPassword)}
                >
                  {showTempPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </Button>
              </div>
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setInviteOpen(false)}>Cancel</Button>
              <Button type="submit" disabled={inviteMutation.isPending}>
                {inviteMutation.isPending ? "Sending..." : "Send Invitation"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ─── Password Reset Result Dialog ────────────────────────────── */}
      <Dialog open={!!resetResult} onOpenChange={() => { setResetResult(null); setShowResetPassword(false); }}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="font-display tracking-wider">PASSWORD RESET</DialogTitle>
            <DialogDescription>
              A new temporary password has been generated. Share it securely with the user.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex items-center gap-2 p-3 bg-secondary/50 rounded-lg border border-border">
              <code className="flex-1 text-sm font-mono break-all">
                {showResetPassword ? resetResult : "••••••••••••••••"}
              </code>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0 shrink-0"
                onClick={() => setShowResetPassword(!showResetPassword)}
              >
                {showResetPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0 shrink-0"
                onClick={() => {
                  if (resetResult) {
                    navigator.clipboard.writeText(resetResult);
                    toast.success("Copied to clipboard");
                  }
                }}
              >
                <Copy className="w-3.5 h-3.5" />
              </Button>
            </div>
            <p className="text-[10px] text-amber-400">
              This password will not be shown again. The user must change it on first login.
            </p>
          </div>
          <DialogFooter>
            <Button onClick={() => { setResetResult(null); setShowResetPassword(false); }}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}


// ─── CVE Enrichment Batch Job Card ──────────────────────────────────
function CveEnrichmentCard() {
  const [isRunning, setIsRunning] = useState(false);
  const stats = trpc.complianceExports.cveEnrichmentStats.useQuery(undefined, {
    staleTime: 30_000,
  });
  const runBatch = trpc.complianceExports.runCveEnrichmentBatch.useMutation({
    onSuccess: (result) => {
      setIsRunning(false);
      toast.success(
        `Enrichment complete: ${result.enriched} enriched, ${result.skipped} skipped, ${result.errors} errors (${(result.duration / 1000).toFixed(1)}s)`
      );
      stats.refetch();
    },
    onError: (err) => {
      setIsRunning(false);
      toast.error(`Enrichment failed: ${err.message}`);
    },
  });

  const handleRun = (forceRefresh = false) => {
    setIsRunning(true);
    runBatch.mutate({ forceRefresh });
  };

  const s = stats.data;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-display tracking-wider flex items-center gap-2">
            <Database className="w-4 h-4 text-blue-400" /> CVE ENRICHMENT
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-[10px] font-display tracking-wider"
              onClick={() => handleRun(false)}
              disabled={isRunning}
            >
              {isRunning ? (
                <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
              ) : (
                <RefreshCw className="w-3 h-3 mr-1" />
              )}
              {isRunning ? "RUNNING..." : "RUN BATCH"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 text-[10px] font-display tracking-wider text-muted-foreground"
              onClick={() => handleRun(true)}
              disabled={isRunning}
            >
              FORCE REFRESH
            </Button>
          </div>
        </div>
        <p className="text-[10px] text-muted-foreground mt-1">
          Pre-populates CVE descriptions, CWE data, and CVSS scores from NVD for all engagement vulnerabilities.
        </p>
      </CardHeader>
      <CardContent>
        {stats.isLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-16 bg-secondary/30 rounded animate-pulse" />
            ))}
          </div>
        ) : s ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="p-3 bg-secondary/30 rounded-lg">
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">CVEs IN ENGAGEMENTS</p>
              <p className="text-lg font-bold text-foreground">{s.totalCvesInEngagements}</p>
            </div>
            <div className="p-3 bg-secondary/30 rounded-lg">
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">ENRICHED</p>
              <p className="text-lg font-bold text-emerald-400">{s.totalEnriched}</p>
            </div>
            <div className="p-3 bg-secondary/30 rounded-lg">
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">WITH CWEs</p>
              <p className="text-lg font-bold text-blue-400">{s.withCwes}</p>
            </div>
            <div className="p-3 bg-secondary/30 rounded-lg">
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">COVERAGE</p>
              <p className="text-lg font-bold text-foreground">{s.coveragePercent}%</p>
            </div>
            {s.newestEnrichment && (
              <div className="col-span-2 md:col-span-4 flex items-center gap-2 text-[10px] text-muted-foreground">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                Last enriched: {new Date(s.newestEnrichment).toLocaleString()}
                {s.withErrors > 0 && (
                  <span className="text-amber-400 ml-2">
                    <AlertTriangle className="w-3 h-3 inline mr-0.5" />
                    {s.withErrors} errors
                  </span>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-4">
            <Database className="w-8 h-8 text-muted-foreground mx-auto mb-2 opacity-50" />
            <p className="text-xs text-muted-foreground">No enrichment data yet. Run the batch job to populate.</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
