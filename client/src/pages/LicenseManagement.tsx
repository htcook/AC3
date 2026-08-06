import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  Key,
  Shield,
  Users,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Copy,
  RefreshCw,
  Plus,
  Ban,
  Eye,
  TrendingUp,
} from "lucide-react";

// ─── Tier Config ────────────────────────────────────────────────────────────

const TIER_CONFIG: Record<string, { label: string; color: string; seats: number; scans: number }> = {
  starter: { label: "Starter", color: "bg-blue-500/20 text-blue-400 border-blue-500/30", seats: 5, scans: 50 },
  professional: { label: "Professional", color: "bg-purple-500/20 text-purple-400 border-purple-500/30", seats: 25, scans: 500 },
  enterprise: { label: "Enterprise", color: "bg-amber-500/20 text-amber-400 border-amber-500/30", seats: -1, scans: -1 },
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: any }> = {
  active: { label: "Active", color: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
  expired: { label: "Expired", color: "bg-orange-500/20 text-orange-400 border-orange-500/30", icon: Clock },
  revoked: { label: "Revoked", color: "bg-red-500/20 text-red-400 border-red-500/30", icon: XCircle },
};

// ─── Issue License Dialog ───────────────────────────────────────────────────

function IssueLicenseDialog({ onSuccess }: { onSuccess: () => void }) {
  const [open, setOpen] = useState(false);
  const [orgName, setOrgName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [contactName, setContactName] = useState("");
  const [tier, setTier] = useState<"starter" | "professional" | "enterprise">("starter");
  const [expiryDays, setExpiryDays] = useState(365);
  const [deploymentDomain, setDeploymentDomain] = useState("");
  const [notes, setNotes] = useState("");
  const { toast } = useToast();

  const issueMutation = trpc.licenseAdmin.issueLicense.useMutation({
    onSuccess: (data) => {
      toast({
        title: "License Issued",
        description: `License for ${data.orgName} (${data.tier}) created successfully.`,
      });
      setOpen(false);
      resetForm();
      onSuccess();
    },
    onError: (err) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  function resetForm() {
    setOrgName("");
    setContactEmail("");
    setContactName("");
    setTier("starter");
    setExpiryDays(365);
    setDeploymentDomain("");
    setNotes("");
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="h-4 w-4" />
          Issue License
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Issue New License</DialogTitle>
          <DialogDescription>
            Generate a license key for a customer organization.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="orgName">Organization Name *</Label>
            <Input id="orgName" value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Corp" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label htmlFor="contactName">Contact Name</Label>
              <Input id="contactName" value={contactName} onChange={(e) => setContactName(e.target.value)} placeholder="John Doe" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="contactEmail">Contact Email</Label>
              <Input id="contactEmail" type="email" value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="john@acme.com" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="grid gap-2">
              <Label>Tier</Label>
              <Select value={tier} onValueChange={(v) => setTier(v as any)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="starter">Starter (5 seats, 50 scans)</SelectItem>
                  <SelectItem value="professional">Professional (25 seats, 500 scans)</SelectItem>
                  <SelectItem value="enterprise">Enterprise (Unlimited)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="expiryDays">License Duration (days)</Label>
              <Input id="expiryDays" type="number" value={expiryDays} onChange={(e) => setExpiryDays(Number(e.target.value))} min={1} max={3650} />
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="domain">Deployment Domain</Label>
            <Input id="domain" value={deploymentDomain} onChange={(e) => setDeploymentDomain(e.target.value)} placeholder="ac3.acme.com" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="notes">Notes</Label>
            <Textarea id="notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Internal notes about this license..." rows={2} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            onClick={() => issueMutation.mutate({
              orgName, contactEmail: contactEmail || undefined, contactName: contactName || undefined,
              tier, expiryDays, deploymentDomain: deploymentDomain || undefined, notes: notes || undefined,
            })}
            disabled={!orgName || issueMutation.isPending}
          >
            {issueMutation.isPending ? "Generating..." : "Issue License"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── License Key Viewer ─────────────────────────────────────────────────────

function LicenseKeyViewer({ orgId }: { orgId: string }) {
  const [show, setShow] = useState(false);
  const { toast } = useToast();
  const keyQuery = trpc.licenseAdmin.getFullLicenseKey.useQuery(
    { orgId },
    { enabled: show }
  );

  const copyKey = () => {
    if (keyQuery.data?.licenseKey) {
      navigator.clipboard.writeText(keyQuery.data.licenseKey);
      toast({ title: "Copied", description: "License key copied to clipboard" });
    }
  };

  if (!show) {
    return (
      <Button variant="ghost" size="sm" onClick={() => setShow(true)} className="gap-1 text-xs">
        <Eye className="h-3 w-3" /> View Key
      </Button>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <code className="text-xs bg-muted px-2 py-1 rounded max-w-[200px] truncate">
        {keyQuery.data?.licenseKey ?? "Loading..."}
      </code>
      <Button variant="ghost" size="sm" onClick={copyKey} className="h-6 w-6 p-0">
        <Copy className="h-3 w-3" />
      </Button>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function LicenseManagement() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [tierFilter, setTierFilter] = useState<string>("");
  const { toast } = useToast();

  const licensesQuery = trpc.licenseAdmin.listLicenses.useQuery({
    status: statusFilter || undefined,
    tier: tierFilter || undefined,
    limit: 100,
  });

  const analyticsQuery = trpc.licenseAdmin.getAnalytics.useQuery();

  const revokeMutation = trpc.licenseAdmin.revokeLicense.useMutation({
    onSuccess: () => {
      toast({ title: "License Revoked" });
      licensesQuery.refetch();
      analyticsQuery.refetch();
    },
  });

  const renewMutation = trpc.licenseAdmin.renewLicense.useMutation({
    onSuccess: () => {
      toast({ title: "License Renewed" });
      licensesQuery.refetch();
      analyticsQuery.refetch();
    },
  });

  const analytics = analyticsQuery.data;
  const licenses = licensesQuery.data?.licenses ?? [];

  function getStatusForLicense(lic: any): string {
    if (lic.status === "revoked") return "revoked";
    if (lic.expiresAt < Date.now()) return "expired";
    return "active";
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Key className="h-6 w-6 text-primary" />
            License Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Issue, monitor, and manage customer license keys
          </p>
        </div>
        <IssueLicenseDialog onSuccess={() => { licensesQuery.refetch(); analyticsQuery.refetch(); }} />
      </div>

      {/* Analytics Cards */}
      {analytics && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-blue-500/10">
                  <Shield className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{analytics.totalLicenses}</p>
                  <p className="text-xs text-muted-foreground">Total Licenses</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10">
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{analytics.activeLicenses}</p>
                  <p className="text-xs text-muted-foreground">Active</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-amber-500/10">
                  <AlertTriangle className="h-5 w-5 text-amber-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{analytics.expiringWithin30Days}</p>
                  <p className="text-xs text-muted-foreground">Expiring Soon</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/10">
                  <TrendingUp className="h-5 w-5 text-purple-400" />
                </div>
                <div>
                  <p className="text-2xl font-bold">
                    {analytics.tierDistribution.find((t) => t.tier === "enterprise")?.count ?? 0}
                  </p>
                  <p className="text-xs text-muted-foreground">Enterprise</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Tier Distribution */}
      {analytics && analytics.tierDistribution.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Tier Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              {analytics.tierDistribution.map((t) => {
                const cfg = TIER_CONFIG[t.tier] ?? { label: t.tier, color: "bg-muted text-muted-foreground" };
                const pct = analytics.totalLicenses > 0 ? Math.round((t.count / analytics.totalLicenses) * 100) : 0;
                return (
                  <div key={t.tier} className="flex-1">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{cfg.label}</span>
                      <span className="text-xs text-muted-foreground">{t.count} ({pct}%)</span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${t.tier === "starter" ? "bg-blue-500" : t.tier === "professional" ? "bg-purple-500" : "bg-amber-500"}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[160px]"><SelectValue placeholder="All Statuses" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="revoked">Revoked</SelectItem>
          </SelectContent>
        </Select>
        <Select value={tierFilter} onValueChange={setTierFilter}>
          <SelectTrigger className="w-[160px]"><SelectValue placeholder="All Tiers" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Tiers</SelectItem>
            <SelectItem value="starter">Starter</SelectItem>
            <SelectItem value="professional">Professional</SelectItem>
            <SelectItem value="enterprise">Enterprise</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => licensesQuery.refetch()} className="gap-1">
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {/* License Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left p-3 font-medium text-muted-foreground">Organization</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Tier</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Seats</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Scans/Period</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">Expires</th>
                  <th className="text-left p-3 font-medium text-muted-foreground">License Key</th>
                  <th className="text-right p-3 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {licenses.length === 0 && (
                  <tr>
                    <td colSpan={8} className="text-center py-12 text-muted-foreground">
                      No licenses issued yet. Click "Issue License" to create one.
                    </td>
                  </tr>
                )}
                {licenses.map((lic: any) => {
                  const status = getStatusForLicense(lic);
                  const statusCfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.active;
                  const tierCfg = TIER_CONFIG[lic.tier] ?? TIER_CONFIG.starter;
                  const StatusIcon = statusCfg.icon;
                  const daysLeft = Math.ceil((lic.expiresAt - Date.now()) / (1000 * 60 * 60 * 24));

                  return (
                    <tr key={lic.orgId} className="border-b border-border/30 hover:bg-muted/30 transition-colors">
                      <td className="p-3">
                        <div>
                          <p className="font-medium">{lic.orgName}</p>
                          {lic.contactEmail && (
                            <p className="text-xs text-muted-foreground">{lic.contactEmail}</p>
                          )}
                        </div>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline" className={tierCfg.color}>
                          {tierCfg.label}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <Badge variant="outline" className={`gap-1 ${statusCfg.color}`}>
                          <StatusIcon className="h-3 w-3" />
                          {statusCfg.label}
                        </Badge>
                      </td>
                      <td className="p-3 text-muted-foreground">
                        {lic.maxSeats === -1 ? "∞" : lic.maxSeats}
                      </td>
                      <td className="p-3 text-muted-foreground">
                        {lic.maxScansPerPeriod === -1 ? "∞" : lic.maxScansPerPeriod}
                      </td>
                      <td className="p-3">
                        <div>
                          <p className={`text-sm ${daysLeft < 30 && status === "active" ? "text-amber-400" : "text-muted-foreground"}`}>
                            {status === "revoked"
                              ? "Revoked"
                              : daysLeft < 0
                              ? `Expired ${Math.abs(daysLeft)}d ago`
                              : `${daysLeft}d remaining`}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(lic.expiresAt).toLocaleDateString()}
                          </p>
                        </div>
                      </td>
                      <td className="p-3">
                        <LicenseKeyViewer orgId={lic.orgId} />
                      </td>
                      <td className="p-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {status === "active" && (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="gap-1 text-xs"
                                onClick={() => renewMutation.mutate({ orgId: lic.orgId, additionalDays: 365 })}
                                disabled={renewMutation.isPending}
                              >
                                <RefreshCw className="h-3 w-3" /> Renew
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="gap-1 text-xs text-red-400 hover:text-red-300"
                                onClick={() => {
                                  if (confirm(`Revoke license for ${lic.orgName}?`)) {
                                    revokeMutation.mutate({ orgId: lic.orgId, reason: "Admin revocation" });
                                  }
                                }}
                                disabled={revokeMutation.isPending}
                              >
                                <Ban className="h-3 w-3" /> Revoke
                              </Button>
                            </>
                          )}
                          {status === "revoked" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="gap-1 text-xs"
                              onClick={() => renewMutation.mutate({ orgId: lic.orgId, additionalDays: 365 })}
                              disabled={renewMutation.isPending}
                            >
                              <RefreshCw className="h-3 w-3" /> Reactivate
                            </Button>
                          )}
                          {status === "expired" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="gap-1 text-xs"
                              onClick={() => renewMutation.mutate({ orgId: lic.orgId, additionalDays: 365 })}
                              disabled={renewMutation.isPending}
                            >
                              <RefreshCw className="h-3 w-3" /> Renew
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
