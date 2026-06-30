import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";
import {
  Users, Plus, Shield, Eye, PenTool, Search, Building2,
  UserX, RefreshCw, Clock, Mail, ChevronDown,
} from "lucide-react";

export default function CustomerAccounts() {
  const [filterTenant, setFilterTenant] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null);

  // Form state for creating accounts
  const [formTenantId, setFormTenantId] = useState("");
  const [formName, setFormName] = useState("");
  const [formEmail, setFormEmail] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formRole, setFormRole] = useState<"admin" | "viewer" | "signer">("viewer");

  // Queries
  const tenantsQuery = trpc.tenants.listTenants.useQuery();
  const accountsQuery = trpc.customerPortal.listAccounts.useQuery(
    { tenantId: filterTenant === "all" ? undefined : filterTenant }
  );
  const auditLogQuery = trpc.customerPortal.adminGetAuditLog.useQuery({ limit: 20 });

  // Mutations
  const createMutation = trpc.customerPortal.createAccount.useMutation({
    onSuccess: () => {
      toast.success("Customer account created successfully");
      setCreateOpen(false);
      resetForm();
      accountsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const deactivateMutation = trpc.customerPortal.deactivateAccount.useMutation({
    onSuccess: () => {
      toast.success("Account deactivated");
      setConfirmDeactivate(null);
      accountsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  function resetForm() {
    setFormTenantId("");
    setFormName("");
    setFormEmail("");
    setFormPassword("");
    setFormRole("viewer");
  }

  function handleCreate() {
    if (!formTenantId || !formName || !formEmail || !formPassword) {
      toast.error("All fields are required");
      return;
    }
    createMutation.mutate({
      tenantId: formTenantId,
      contactName: formName,
      email: formEmail,
      password: formPassword,
      role: formRole,
    });
  }

  // Filter accounts by search
  const filteredAccounts = useMemo(() => {
    const accounts = accountsQuery.data || [];
    if (!searchQuery.trim()) return accounts;
    const q = searchQuery.toLowerCase();
    return accounts.filter(
      (a) =>
        a.contactName?.toLowerCase().includes(q) ||
        a.email?.toLowerCase().includes(q) ||
        a.tenantId?.toLowerCase().includes(q)
    );
  }, [accountsQuery.data, searchQuery]);

  const tenantMap = useMemo(() => {
    const map: Record<string, string> = {};
    (tenantsQuery.data || []).forEach((t: any) => {
      map[String(t.id)] = t.name || `Tenant #${t.id}`;
    });
    return map;
  }, [tenantsQuery.data]);

  const roleIcon = (role: string) => {
    switch (role) {
      case "admin": return <Shield className="h-3.5 w-3.5" />;
      case "signer": return <PenTool className="h-3.5 w-3.5" />;
      default: return <Eye className="h-3.5 w-3.5" />;
    }
  };

  const roleColor = (role: string) => {
    switch (role) {
      case "admin": return "bg-red-500/10 text-red-400 border-red-500/20";
      case "signer": return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      default: return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case "active": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "inactive": return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
      case "suspended": return "bg-red-500/10 text-red-400 border-red-500/20";
      default: return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    }
  };

  const activeCount = filteredAccounts.filter(a => a.status === "active").length;
  const inactiveCount = filteredAccounts.filter(a => a.status !== "active").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Users className="h-6 w-6 text-primary" />
            Customer Portal Accounts
          </h1>
          <p className="text-muted-foreground mt-1">
            Create and manage customer portal login accounts. Customers use these credentials to access their
            organization profile, Rules of Engagement, regulatory frameworks, and shared reports.
          </p>
        </div>
        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" /> Create Account
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[480px]">
            <DialogHeader>
              <DialogTitle>Create Customer Account</DialogTitle>
              <DialogDescription>
                Create a new login for a customer to access their portal. They will use email and password to sign in (separate from admin OAuth).
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="tenant">Tenant / Organization</Label>
                <Select value={formTenantId} onValueChange={setFormTenantId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select tenant..." />
                  </SelectTrigger>
                  <SelectContent>
                    {(tenantsQuery.data || []).map((t: any) => (
                      <SelectItem key={t.id} value={String(t.id)}>
                        {t.name || `Tenant #${t.id}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="name">Contact Name</Label>
                <Input
                  id="name"
                  placeholder="John Smith"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="john@acme.com"
                  value={formEmail}
                  onChange={(e) => setFormEmail(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">Initial Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Min 8 characters"
                  value={formPassword}
                  onChange={(e) => setFormPassword(e.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="role">Role</Label>
                <Select value={formRole} onValueChange={(v) => setFormRole(v as any)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="viewer">Viewer — Read-only access</SelectItem>
                    <SelectItem value="admin">Admin — Can edit profile and scope</SelectItem>
                    <SelectItem value="signer">Signer — Can sign RoE documents</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
              <Button onClick={handleCreate} disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create Account"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Users className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{filteredAccounts.length}</p>
                <p className="text-xs text-muted-foreground">Total Accounts</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/10">
                <Shield className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{activeCount}</p>
                <p className="text-xs text-muted-foreground">Active</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-zinc-500/10">
                <UserX className="h-5 w-5 text-zinc-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{inactiveCount}</p>
                <p className="text-xs text-muted-foreground">Inactive</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by name, email, or tenant..."
            className="pl-9"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <Select value={filterTenant} onValueChange={setFilterTenant}>
          <SelectTrigger className="w-full sm:w-[220px]">
            <Building2 className="h-4 w-4 mr-2 text-muted-foreground" />
            <SelectValue placeholder="All Tenants" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tenants</SelectItem>
            {(tenantsQuery.data || []).map((t: any) => (
              <SelectItem key={t.id} value={String(t.id)}>
                {t.name || `Tenant #${t.id}`}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button variant="outline" size="icon" onClick={() => accountsQuery.refetch()}>
          <RefreshCw className={`h-4 w-4 ${accountsQuery.isFetching ? "animate-spin" : ""}`} />
        </Button>
      </div>

      {/* Accounts Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Customer Accounts</CardTitle>
          <CardDescription>
            {filteredAccounts.length} account{filteredAccounts.length !== 1 ? "s" : ""} found
          </CardDescription>
        </CardHeader>
        <CardContent>
          {accountsQuery.isLoading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">Loading accounts...</div>
          ) : filteredAccounts.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Users className="h-10 w-10 mb-3 opacity-40" />
              <p className="text-sm">No customer accounts found</p>
              <p className="text-xs mt-1">Create one to get started</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Tenant</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Login</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAccounts.map((account) => (
                    <TableRow key={account.id}>
                      <TableCell className="font-medium">{account.contactName}</TableCell>
                      <TableCell>
                        <span className="flex items-center gap-1.5 text-sm">
                          <Mail className="h-3.5 w-3.5 text-muted-foreground" />
                          {account.email}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="flex items-center gap-1.5 text-sm">
                          <Building2 className="h-3.5 w-3.5 text-muted-foreground" />
                          {tenantMap[account.tenantId] || account.tenantId}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`gap-1 ${roleColor(account.role)}`}>
                          {roleIcon(account.role)}
                          {account.role}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={statusColor(account.status)}>
                          {account.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {account.lastLoginAt ? (
                          <span className="flex items-center gap-1.5 text-sm text-muted-foreground">
                            <Clock className="h-3.5 w-3.5" />
                            {new Date(account.lastLoginAt).toLocaleDateString()}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">Never</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">
                          {new Date(account.createdAt).toLocaleDateString()}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">
                        {account.status === "active" ? (
                          <Dialog
                            open={confirmDeactivate === account.id}
                            onOpenChange={(open) => setConfirmDeactivate(open ? account.id : null)}
                          >
                            <DialogTrigger asChild>
                              <Button variant="ghost" size="sm" className="text-red-400 hover:text-red-300 hover:bg-red-500/10">
                                <UserX className="h-4 w-4 mr-1" /> Deactivate
                              </Button>
                            </DialogTrigger>
                            <DialogContent>
                              <DialogHeader>
                                <DialogTitle>Deactivate Account</DialogTitle>
                                <DialogDescription>
                                  Are you sure you want to deactivate <strong>{account.contactName}</strong>'s account ({account.email})?
                                  They will no longer be able to log into the customer portal.
                                </DialogDescription>
                              </DialogHeader>
                              <DialogFooter>
                                <Button variant="outline" onClick={() => setConfirmDeactivate(null)}>Cancel</Button>
                                <Button
                                  variant="destructive"
                                  onClick={() => deactivateMutation.mutate({ customerId: account.id })}
                                  disabled={deactivateMutation.isPending}
                                >
                                  {deactivateMutation.isPending ? "Deactivating..." : "Deactivate"}
                                </Button>
                              </DialogFooter>
                            </DialogContent>
                          </Dialog>
                        ) : (
                          <Badge variant="outline" className="text-xs bg-zinc-500/10 text-zinc-500">
                            Deactivated
                          </Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Audit Log */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Recent Customer Activity</CardTitle>
          <CardDescription>Latest actions from customer portal users</CardDescription>
        </CardHeader>
        <CardContent>
          {auditLogQuery.isLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">Loading...</div>
          ) : (auditLogQuery.data || []).length === 0 ? (
            <div className="text-center py-8 text-muted-foreground text-sm">No customer activity yet</div>
          ) : (
            <div className="space-y-2 max-h-[300px] overflow-y-auto">
              {(auditLogQuery.data || []).map((log: any) => (
                <div key={log.id} className="flex items-center gap-3 py-2 px-3 rounded-lg bg-muted/30 text-sm">
                  <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="text-muted-foreground">
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                  <Badge variant="outline" className="text-xs">{log.action}</Badge>
                  <span className="text-muted-foreground">{log.resource}</span>
                  {log.resourceId && (
                    <span className="text-xs text-muted-foreground">#{log.resourceId}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
