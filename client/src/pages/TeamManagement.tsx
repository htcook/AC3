import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Users,
  UserPlus,
  Crown,
  Eye,
  User,
  Zap,
  Cpu,
  Briefcase,
  BarChart3,
  Shield,
  Copy,
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  MoreVertical,
  UserX,
  UserCheck,
  RefreshCw,
  Mail,
  Search,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

const ALL_ROLES = ["admin", "operator", "analyst", "team_lead", "executive", "client", "user", "viewer"] as const;

const ROLE_INFO: Record<string, { icon: any; label: string; color: string }> = {
  admin: { icon: Crown, label: "Administrator", color: "text-red-500" },
  operator: { icon: Zap, label: "Operator", color: "text-primary" },
  analyst: { icon: BarChart3, label: "Analyst", color: "text-blue-500" },
  team_lead: { icon: Cpu, label: "Team Lead", color: "text-purple-500" },
  executive: { icon: Briefcase, label: "Executive", color: "text-amber-500" },
  client: { icon: Shield, label: "Client", color: "text-green-500" },
  user: { icon: User, label: "User", color: "text-muted-foreground" },
  viewer: { icon: Eye, label: "Viewer", color: "text-muted-foreground" },
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-green-500/10 text-green-500 border-green-500/30",
  inactive: "bg-gray-500/10 text-gray-500 border-gray-500/30",
  suspended: "bg-red-500/10 text-red-500 border-red-500/30",
  pending: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
};

export default function TeamManagement() {
  const { user } = useAuth();
  const utils = trpc.useUtils();
  const [searchQuery, setSearchQuery] = useState("");
  const [inviteDialogOpen, setInviteDialogOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<string>("operator");
  const [inviteMessage, setInviteMessage] = useState("");
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);

  const isAdmin = user?.role === "admin";
  const isTeamLead = user?.role === "team_lead";
  const canManage = isAdmin || isTeamLead;

  const team = trpc.account.listTeam.useQuery({ includeInactive: true }, { enabled: canManage });
  const stats = trpc.account.teamStats.useQuery(undefined, { enabled: canManage });
  const invites = trpc.account.listInvites.useQuery({ includeExpired: false }, { enabled: canManage });

  const createInvite = trpc.account.createInvite.useMutation({
    onSuccess: (data) => {
      setGeneratedToken(data.inviteToken);
      toast.success(`Invitation sent to ${data.email}`);
      utils.account.listInvites.invalidate();
      utils.account.teamStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const updateRole = trpc.account.updateRole.useMutation({
    onSuccess: (data) => {
      toast.success(`Role updated to ${data.newRole}`);
      utils.account.listTeam.invalidate();
      utils.account.teamStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const deactivateUser = trpc.account.deactivateUser.useMutation({
    onSuccess: () => {
      toast.success("User deactivated");
      utils.account.listTeam.invalidate();
      utils.account.teamStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const reactivateUser = trpc.account.reactivateUser.useMutation({
    onSuccess: () => {
      toast.success("User reactivated");
      utils.account.listTeam.invalidate();
      utils.account.teamStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeInvite = trpc.account.revokeInvite.useMutation({
    onSuccess: () => {
      toast.success("Invitation revoked");
      utils.account.listInvites.invalidate();
      utils.account.teamStats.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const resendInvite = trpc.account.resendInvite.useMutation({
    onSuccess: (data) => {
      setGeneratedToken(data.inviteToken);
      toast.success(`New invite token generated for ${data.email}`);
      utils.account.listInvites.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const filteredTeam = useMemo(() => {
    if (!team.data) return [];
    if (!searchQuery) return team.data;
    const q = searchQuery.toLowerCase();
    return team.data.filter(
      (u) =>
        u.name?.toLowerCase().includes(q) ||
        u.email?.toLowerCase().includes(q) ||
        (u.role || '').toLowerCase().includes(q) ||
        u.department?.toLowerCase().includes(q)
    );
  }, [team.data, searchQuery]);

  const handleInvite = () => {
    if (!inviteEmail) {
      toast.error("Email is required");
      return;
    }
    createInvite.mutate({
      email: inviteEmail,
      role: inviteRole as any,
      message: inviteMessage || undefined,
    });
  };

  const copyToken = (token: string) => {
    navigator.clipboard.writeText(token);
    toast.success("Invite token copied to clipboard");
  };

  if (!canManage) {
    return (
      <AppShell activePath="/team">
        <div className="flex items-center justify-center min-h-[60vh]">
          <p className="text-muted-foreground">Admin or Team Lead access required</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell activePath="/team">
      <header className="sticky top-0 z-40 bg-background/95 backdrop-blur-sm border-b border-border">
        <div className="px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Users className="w-6 h-6 text-primary" />
            <div>
              <h1 className="font-display text-2xl tracking-wider">TEAM MANAGEMENT</h1>
              <p className="text-sm text-muted-foreground">Manage team members, roles, and invitations</p>
            </div>
          </div>
          <Dialog open={inviteDialogOpen} onOpenChange={(open) => {
            setInviteDialogOpen(open);
            if (!open) {
              setInviteEmail("");
              setInviteRole("operator");
              setInviteMessage("");
              setGeneratedToken(null);
            }
          }}>
            <DialogTrigger asChild>
              <Button className="font-display tracking-wider">
                <UserPlus className="w-4 h-4 mr-2" />
                INVITE MEMBER
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle className="font-display tracking-wider">INVITE TEAM MEMBER</DialogTitle>
                <DialogDescription>
                  Send a FIPS 140-3 compliant invitation with a SHA-256 hashed token.
                  The token expires in 72 hours.
                </DialogDescription>
              </DialogHeader>
              {!generatedToken ? (
                <div className="space-y-4 py-2">
                  <div className="space-y-2">
                    <Label htmlFor="invite-email">Email Address</Label>
                    <Input
                      id="invite-email"
                      type="email"
                      value={inviteEmail}
                      onChange={(e) => setInviteEmail(e.target.value)}
                      placeholder="teammate@organization.com"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="invite-role">Role</Label>
                    <Select value={inviteRole} onValueChange={setInviteRole}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ALL_ROLES.map((role) => {
                          const info = ROLE_INFO[role];
                          if (role === "admin" && !isAdmin) return null;
                          return (
                            <SelectItem key={role} value={role}>
                              <span className="flex items-center gap-2">
                                <info.icon className={`w-4 h-4 ${info.color}`} />
                                {info.label}
                              </span>
                            </SelectItem>
                          );
                        })}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="invite-message">Personal Message (optional)</Label>
                    <Input
                      id="invite-message"
                      value={inviteMessage}
                      onChange={(e) => setInviteMessage(e.target.value)}
                      placeholder="Welcome to the team!"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-4 py-2">
                  <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/30">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle2 className="w-5 h-5 text-green-500" />
                      <span className="font-semibold text-green-500">Invitation Created</span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-3">
                      Share this invite token with {inviteEmail}. They can use it to join with the <strong>{ROLE_INFO[inviteRole]?.label}</strong> role.
                    </p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 p-2 rounded bg-background border border-border text-xs font-mono break-all">
                        {generatedToken}
                      </code>
                      <Button size="sm" variant="outline" onClick={() => copyToken(generatedToken)}>
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">
                      Token is SHA-256 hashed before storage (FIPS 140-3 compliant). Expires in 72 hours.
                    </p>
                  </div>
                </div>
              )}
              <DialogFooter>
                {!generatedToken ? (
                  <Button onClick={handleInvite} disabled={createInvite.isPending}>
                    {createInvite.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Mail className="w-4 h-4 mr-2" />}
                    SEND INVITATION
                  </Button>
                ) : (
                  <Button variant="outline" onClick={() => setInviteDialogOpen(false)}>
                    DONE
                  </Button>
                )}
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
        <div className="w-full h-1 bg-primary" />
      </header>

      <div className="p-6 space-y-6">
        {/* Stats Cards */}
        {stats.data && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <Card className="border-2">
              <CardContent className="p-4 text-center">
                <p className="text-3xl font-bold">{stats.data.totalUsers}</p>
                <p className="text-xs text-muted-foreground font-display tracking-wider">TOTAL USERS</p>
              </CardContent>
            </Card>
            <Card className="border-2">
              <CardContent className="p-4 text-center">
                <p className="text-3xl font-bold text-green-500">{stats.data.statusCounts.active || 0}</p>
                <p className="text-xs text-muted-foreground font-display tracking-wider">ACTIVE</p>
              </CardContent>
            </Card>
            <Card className="border-2">
              <CardContent className="p-4 text-center">
                <p className="text-3xl font-bold text-yellow-500">{stats.data.pendingInvites}</p>
                <p className="text-xs text-muted-foreground font-display tracking-wider">PENDING INVITES</p>
              </CardContent>
            </Card>
            <Card className="border-2">
              <CardContent className="p-4 text-center">
                <p className="text-3xl font-bold text-gray-500">{stats.data.statusCounts.inactive || 0}</p>
                <p className="text-xs text-muted-foreground font-display tracking-wider">INACTIVE</p>
              </CardContent>
            </Card>
            <Card className="border-2">
              <CardContent className="p-4 text-center">
                <p className="text-3xl font-bold text-red-500">{stats.data.statusCounts.suspended || 0}</p>
                <p className="text-xs text-muted-foreground font-display tracking-wider">SUSPENDED</p>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Team Members Table */}
        <Card className="border-2 border-border">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="font-display tracking-wider">TEAM MEMBERS</CardTitle>
                <CardDescription>{filteredTeam.length} members</CardDescription>
              </div>
              <div className="relative w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search members..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Department</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Active</TableHead>
                  {isAdmin && <TableHead className="w-10"></TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredTeam.map((member) => {
                  const roleInfo = ROLE_INFO[member.role] || ROLE_INFO.user;
                  const RoleIcon = roleInfo.icon;
                  return (
                    <TableRow key={member.id}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                            <span className="text-xs font-bold text-primary">
                              {(member.name || "?").charAt(0).toUpperCase()}
                            </span>
                          </div>
                          <div>
                            <p className="font-medium">{member.name || "Unnamed"}</p>
                            {member.title && <p className="text-xs text-muted-foreground">{member.title}</p>}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{member.email || "—"}</TableCell>
                      <TableCell>
                        <span className={`flex items-center gap-1.5 text-sm ${roleInfo.color}`}>
                          <RoleIcon className="w-4 h-4" />
                          {roleInfo.label}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{member.department || "—"}</TableCell>
                      <TableCell>
                        <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[member.status] || STATUS_COLORS.active}`}>
                          {member.status}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {member.lastSignedIn ? new Date(member.lastSignedIn).toLocaleDateString() : "Never"}
                      </TableCell>
                      {isAdmin && (
                        <TableCell>
                          {member.id !== user?.id && (
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                  <MoreVertical className="w-4 h-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {ALL_ROLES.map((role) => (
                                  <DropdownMenuItem
                                    key={role}
                                    disabled={member.role === role}
                                    onClick={() => updateRole.mutate({ userId: member.id, role })}
                                  >
                                    Set as {ROLE_INFO[role]?.label || role}
                                  </DropdownMenuItem>
                                ))}
                                <DropdownMenuSeparator />
                                {member.status === "active" ? (
                                  <DropdownMenuItem
                                    className="text-red-500"
                                    onClick={() => deactivateUser.mutate({ userId: member.id })}
                                  >
                                    <UserX className="w-4 h-4 mr-2" /> Deactivate
                                  </DropdownMenuItem>
                                ) : (
                                  <DropdownMenuItem
                                    className="text-green-500"
                                    onClick={() => reactivateUser.mutate({ userId: member.id })}
                                  >
                                    <UserCheck className="w-4 h-4 mr-2" /> Reactivate
                                  </DropdownMenuItem>
                                )}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  );
                })}
                {filteredTeam.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={isAdmin ? 7 : 6} className="text-center py-8 text-muted-foreground">
                      {searchQuery ? "No members match your search" : "No team members yet"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Pending Invitations */}
        {invites.data && invites.data.length > 0 && (
          <Card className="border-2 border-border">
            <CardHeader>
              <CardTitle className="font-display tracking-wider flex items-center gap-2">
                <Mail className="w-5 h-5" /> PENDING INVITATIONS
              </CardTitle>
              <CardDescription>Active invitations awaiting acceptance</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Email</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Invited By</TableHead>
                    <TableHead>Expires</TableHead>
                    <TableHead className="w-10"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {invites.data.map((invite) => (
                    <TableRow key={invite.id}>
                      <TableCell className="font-medium">{invite.email}</TableCell>
                      <TableCell>
                        <span className="text-sm">{ROLE_INFO[invite.role]?.label || invite.role}</span>
                      </TableCell>
                      <TableCell>
                        <span className={`text-xs px-2 py-0.5 rounded border ${
                          invite.status === "pending" ? STATUS_COLORS.pending :
                          invite.status === "accepted" ? STATUS_COLORS.active :
                          STATUS_COLORS.inactive
                        }`}>
                          {invite.status}
                        </span>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{invite.invitedByName}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {invite.expiresAt ? new Date(invite.expiresAt).toLocaleDateString() : "—"}
                      </TableCell>
                      <TableCell>
                        {invite.status === "pending" && (
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                                <MoreVertical className="w-4 h-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => resendInvite.mutate({ inviteId: invite.id })}>
                                <RefreshCw className="w-4 h-4 mr-2" /> Resend
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="text-red-500"
                                onClick={() => revokeInvite.mutate({ inviteId: invite.id })}
                              >
                                <XCircle className="w-4 h-4 mr-2" /> Revoke
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
