import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  RefreshCw, Plus, Trash2, Play, Clock, CheckCircle2,
  XCircle, AlertTriangle, Shield, Loader2, History,
  Key, Cloud, Settings2,
} from "lucide-react";
import AppShell from "@/components/AppShell";

export default function CredentialAutoRotation() {
  const [activeTab, setActiveTab] = useState("policies");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    credentialId: 0,
    provider: "aws" as "aws" | "azure" | "gcp",
    credentialName: "",
    enabled: true,
    rotationIntervalDays: 90,
  });

  const policies = trpc.credentialAutoRotation.listPolicies.useQuery();
  const summary = trpc.credentialAutoRotation.getSummary.useQuery();
  const duePolicies = trpc.credentialAutoRotation.getDuePolicies.useQuery();
  const auditTrail = trpc.credentialAutoRotation.getAuditTrail.useQuery({ limit: 50 });
  const credentials = trpc.cloudCredentials.listCredentials.useQuery();
  const utils = trpc.useUtils();

  const createMutation = trpc.credentialAutoRotation.createPolicy.useMutation({
    onSuccess: () => {
      toast.success("Rotation policy created");
      setShowCreateDialog(false);
      utils.credentialAutoRotation.listPolicies.invalidate();
      utils.credentialAutoRotation.getSummary.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const updateMutation = trpc.credentialAutoRotation.updatePolicy.useMutation({
    onSuccess: () => {
      toast.success("Policy updated");
      utils.credentialAutoRotation.listPolicies.invalidate();
      utils.credentialAutoRotation.getSummary.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.credentialAutoRotation.deletePolicy.useMutation({
    onSuccess: () => {
      toast.success("Policy deleted");
      utils.credentialAutoRotation.listPolicies.invalidate();
      utils.credentialAutoRotation.getSummary.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const rotateMutation = trpc.credentialAutoRotation.executeRotation.useMutation({
    onSuccess: (data) => {
      toast.success(`Rotation complete: ${data.oldKeyId} → ${data.newKeyId}`);
      utils.credentialAutoRotation.listPolicies.invalidate();
      utils.credentialAutoRotation.getAuditTrail.invalidate();
      utils.credentialAutoRotation.getSummary.invalidate();
    },
    onError: (err) => toast.error(`Rotation failed: ${err.message}`),
  });

  const providerIcon = (provider: string) => {
    switch (provider) {
      case "aws": return <Cloud className="h-4 w-4 text-amber-500" />;
      case "azure": return <Cloud className="h-4 w-4 text-blue-500" />;
      case "gcp": return <Cloud className="h-4 w-4 text-green-500" />;
      default: return <Cloud className="h-4 w-4" />;
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case "success": return <Badge className="bg-green-500/20 text-green-400 border-green-500/30"><CheckCircle2 className="h-3 w-3 mr-1" />Success</Badge>;
      case "failed": return <Badge className="bg-red-500/20 text-red-400 border-red-500/30"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
      case "in_progress": return <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30"><Loader2 className="h-3 w-3 mr-1 animate-spin" />In Progress</Badge>;
      case "rollback": return <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30"><AlertTriangle className="h-3 w-3 mr-1" />Rollback</Badge>;
      default: return <Badge variant="outline">{status}</Badge>;
    }
  };

  const [auditFilter] = useState<{ policyId?: number; credentialId?: number }>({});

  return (
    <AppShell activePath="/credential-auto-rotation">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <RefreshCw className="h-6 w-6 text-green-500" />
            Credential Auto-Rotation
          </h1>
          <p className="text-muted-foreground mt-1">
            Automated rotation of AWS, Azure, and GCP credentials with full audit trail
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button><Plus className="h-4 w-4 mr-1.5" />New Policy</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Rotation Policy</DialogTitle>
              <DialogDescription>
                Configure automatic credential rotation for a cloud provider credential.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div>
                <Label>Cloud Credential</Label>
                <Select
                  value={newPolicy.credentialId ? String(newPolicy.credentialId) : ""}
                  onValueChange={(val) => {
                    const cred = credentials.data?.find((c: any) => c.id === Number(val));
                    setNewPolicy(prev => ({
                      ...prev,
                      credentialId: Number(val),
                      provider: (cred?.provider || "aws") as any,
                      credentialName: cred?.credentialName || "",
                    }));
                  }}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select credential..." />
                  </SelectTrigger>
                  <SelectContent>
                    {(credentials.data || []).map((cred: any) => (
                      <SelectItem key={cred.id} value={String(cred.id)}>
                        {cred.provider.toUpperCase()} — {cred.credentialName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Rotation Interval (days)</Label>
                <Input
                  type="number"
                  min={1}
                  max={365}
                  value={newPolicy.rotationIntervalDays}
                  onChange={(e) => setNewPolicy(prev => ({ ...prev, rotationIntervalDays: Number(e.target.value) }))}
                />
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={newPolicy.enabled}
                  onCheckedChange={(checked) => setNewPolicy(prev => ({ ...prev, enabled: checked }))}
                />
                <Label>Enable auto-rotation</Label>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateDialog(false)}>Cancel</Button>
              <Button
                onClick={() => createMutation.mutate(newPolicy)}
                disabled={!newPolicy.credentialId || createMutation.isPending}
              >
                {createMutation.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Plus className="h-4 w-4 mr-1.5" />}
                Create Policy
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Summary Cards */}
      {summary.data && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <SummaryCard label="Total Policies" value={summary.data.totalPolicies} icon={Settings2} color="slate" />
          <SummaryCard label="Enabled" value={summary.data.enabledPolicies} icon={Shield} color="green" />
          <SummaryCard label="Due Now" value={summary.data.duePolicies} icon={AlertTriangle} color={summary.data.duePolicies > 0 ? "amber" : "slate"} />
          <SummaryCard label="Rotated (24h)" value={summary.data.recentRotations} icon={CheckCircle2} color="blue" />
          <SummaryCard label="Failed (24h)" value={summary.data.failedRotations} icon={XCircle} color={summary.data.failedRotations > 0 ? "red" : "slate"} />
          <SummaryCard
            label="Next Rotation"
            value={summary.data.nextRotationDate
              ? new Date(summary.data.nextRotationDate).toLocaleDateString()
              : "—"}
            icon={Clock}
            color="purple"
            isText
          />
        </div>
      )}

      {/* Due Policies Alert */}
      {duePolicies.data && duePolicies.data.length > 0 && (
        <Card className="border-amber-500/20 bg-amber-500/5">
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <div>
                <p className="font-medium text-amber-400">
                  {duePolicies.data.length} credential(s) due for rotation
                </p>
                <p className="text-sm text-muted-foreground">
                  {duePolicies.data.map((p: any) => p.credentialName).join(", ")}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="policies">
            <Key className="h-4 w-4 mr-1.5" /> Policies
          </TabsTrigger>
          <TabsTrigger value="audit">
            <History className="h-4 w-4 mr-1.5" /> Audit Trail
          </TabsTrigger>
        </TabsList>

        {/* Policies Tab */}
        <TabsContent value="policies" className="space-y-3">
          {policies.isLoading ? (
            <Card><CardContent className="py-8 text-center text-muted-foreground">Loading policies...</CardContent></Card>
          ) : !policies.data?.length ? (
            <Card>
              <CardContent className="py-12 text-center">
                <RefreshCw className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-lg font-medium">No rotation policies</p>
                <p className="text-sm text-muted-foreground mt-1">Create a policy to automate credential rotation</p>
                <Button className="mt-4" onClick={() => setShowCreateDialog(true)}>
                  <Plus className="h-4 w-4 mr-1.5" />Create First Policy
                </Button>
              </CardContent>
            </Card>
          ) : (
            policies.data.map((policy: any) => (
              <Card key={policy.id}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {providerIcon(policy.provider)}
                      <div>
                        <p className="font-medium">{policy.credentialName}</p>
                        <p className="text-xs text-muted-foreground">
                          {policy.provider.toUpperCase()} · Every {policy.rotationIntervalDays} days
                          {policy.lastRotatedAt && (
                            <> · Last rotated: {new Date(policy.lastRotatedAt).toLocaleDateString()}</>
                          )}
                          {policy.nextRotationAt && (
                            <> · Next: {new Date(policy.nextRotationAt).toLocaleDateString()}</>
                          )}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Switch
                        checked={policy.enabled}
                        onCheckedChange={(checked) =>
                          updateMutation.mutate({ id: policy.id, enabled: checked })
                        }
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => rotateMutation.mutate({ policyId: policy.id })}
                        disabled={rotateMutation.isPending}
                      >
                        {rotateMutation.isPending ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Play className="h-3.5 w-3.5" />
                        )}
                        <span className="ml-1.5">Rotate Now</span>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => {
                          if (confirm("Delete this rotation policy?")) {
                            deleteMutation.mutate({ id: policy.id });
                          }
                        }}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </div>
                  {policy.retryCount > 0 && (
                    <p className="text-xs text-amber-400 mt-2">
                      Retry count: {policy.retryCount}/{policy.maxRetries}
                    </p>
                  )}
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Audit Trail Tab */}
        <TabsContent value="audit" className="space-y-3">
          {auditTrail.isLoading ? (
            <Card><CardContent className="py-8 text-center text-muted-foreground">Loading audit trail...</CardContent></Card>
          ) : !auditTrail.data?.length ? (
            <Card>
              <CardContent className="py-12 text-center">
                <History className="h-12 w-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-lg font-medium">No rotation history</p>
                <p className="text-sm text-muted-foreground mt-1">Rotation audit entries will appear here after the first rotation</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Rotation Audit Log</CardTitle>
                <CardDescription>{auditTrail.data.length} entries</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {auditTrail.data.map((entry: any) => (
                    <div key={entry.id} className="flex items-start justify-between py-3 border-b border-border/50 last:border-0">
                      <div className="flex items-start gap-3">
                        {providerIcon(entry.provider)}
                        <div>
                          <div className="flex items-center gap-2">
                            {statusBadge(entry.status)}
                            <span className="text-xs text-muted-foreground">
                              {entry.createdAt ? new Date(entry.createdAt).toLocaleString() : "—"}
                            </span>
                          </div>
                          {entry.oldKeyIdentifier && (
                            <p className="text-xs text-muted-foreground mt-1">
                              <code className="bg-muted px-1 rounded">{entry.oldKeyIdentifier}</code>
                              {entry.newKeyIdentifier && (
                                <> → <code className="bg-muted px-1 rounded">{entry.newKeyIdentifier}</code></>
                              )}
                            </p>
                          )}
                          {entry.errorMessage && (
                            <p className="text-xs text-red-400 mt-1">{entry.errorMessage}</p>
                          )}
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">
                          {entry.durationMs}ms
                        </p>
                        <p className="text-xs text-muted-foreground">
                          by {entry.initiatedBy}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}

function SummaryCard({ label, value, icon: Icon, color, isText }: {
  label: string;
  value: number | string;
  icon: any;
  color: string;
  isText?: boolean;
}) {
  const colorClasses: Record<string, string> = {
    slate: "text-slate-400 bg-slate-500/10 border-slate-500/20",
    green: "text-green-500 bg-green-500/10 border-green-500/20",
    amber: "text-amber-500 bg-amber-500/10 border-amber-500/20",
    blue: "text-blue-500 bg-blue-500/10 border-blue-500/20",
    red: "text-red-500 bg-red-500/10 border-red-500/20",
    purple: "text-purple-500 bg-purple-500/10 border-purple-500/20",
  };
  return (
    <div className={`p-3 rounded-lg border ${colorClasses[color] || colorClasses.slate}`}>
      <Icon className={`h-4 w-4 mb-1 ${colorClasses[color]?.split(" ")[0]}`} />
      <p className={`${isText ? "text-sm" : "text-xl"} font-bold`}>{value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
    </div>
  );
}
