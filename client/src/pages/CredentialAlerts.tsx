import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Bell, BellRing, Shield, ShieldAlert, Clock, CheckCircle2, AlertTriangle, Plus, Play, Trash2 } from "lucide-react";
import AppShell from "@/components/AppShell";

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const alertTypeIcons: Record<string, any> = {
  expiring_soon: Clock,
  expired: ShieldAlert,
  rotation_due: AlertTriangle,
  validation_failed: Shield,
};

export default function CredentialAlerts() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [newRule, setNewRule] = useState({ credentialId: "", alertName: "", thresholdDays: "30", notifyOwner: true });

  const statsQuery = trpc.credentialAlerts.getStats.useQuery();
  const rulesQuery = trpc.credentialAlerts.listRules.useQuery();
  const historyQuery = trpc.credentialAlerts.getAlertHistory.useQuery();
  const credentialsQuery = trpc.cloudCredentials.listCredentials.useQuery();

  const createRuleMut = trpc.credentialAlerts.createRule.useMutation({
    onSuccess: () => { toast.success("Alert rule created"); rulesQuery.refetch(); setShowCreateDialog(false); },
    onError: (e) => toast.error(e.message),
  });
  const updateRuleMut = trpc.credentialAlerts.updateRule.useMutation({
    onSuccess: () => { toast.success("Rule updated"); rulesQuery.refetch(); },
  });
  const deleteRuleMut = trpc.credentialAlerts.deleteRule.useMutation({
    onSuccess: () => { toast.success("Rule deleted"); rulesQuery.refetch(); },
  });
  const runCheckMut = trpc.credentialAlerts.runExpiryCheck.useMutation({
    onSuccess: (data) => {
      toast.success(`Check complete: ${data.alertsGenerated} alert(s), ${data.notificationsSent} notification(s)`);
      historyQuery.refetch();
      statsQuery.refetch();
    },
    onError: (e) => toast.error(e.message),
  });
  const acknowledgeMut = trpc.credentialAlerts.acknowledgeAlert.useMutation({
    onSuccess: () => { toast.success("Alert acknowledged"); historyQuery.refetch(); statsQuery.refetch(); },
  });

  const stats = statsQuery.data;
  const rules = rulesQuery.data || [];
  const history = historyQuery.data || [];
  const credentials = credentialsQuery.data || [];

  return (
    <AppShell>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <BellRing className="h-6 w-6 text-amber-400" />
              Credential Rotation Alerts
            </h1>
            <p className="text-muted-foreground mt-1">Monitor credential expiry and automate rotation notifications</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => runCheckMut.mutate()} disabled={runCheckMut.isPending}>
              <Play className="h-4 w-4 mr-2" />
              {runCheckMut.isPending ? "Checking..." : "Run Check Now"}
            </Button>
            <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
              <DialogTrigger asChild>
                <Button><Plus className="h-4 w-4 mr-2" />New Rule</Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader><DialogTitle>Create Alert Rule</DialogTitle></DialogHeader>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium">Credential</label>
                    <Select value={newRule.credentialId} onValueChange={v => setNewRule(p => ({ ...p, credentialId: v }))}>
                      <SelectTrigger><SelectValue placeholder="Select credential" /></SelectTrigger>
                      <SelectContent>
                        {credentials.map((c: any) => (
                          <SelectItem key={c.id} value={String(c.id)}>{c.credentialName} ({c.provider})</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Alert Name</label>
                    <Input value={newRule.alertName} onChange={e => setNewRule(p => ({ ...p, alertName: e.target.value }))} placeholder="e.g., AWS Key Rotation Alert" />
                  </div>
                  <div>
                    <label className="text-sm font-medium">Threshold (days before expiry)</label>
                    <Input type="number" value={newRule.thresholdDays} onChange={e => setNewRule(p => ({ ...p, thresholdDays: e.target.value }))} />
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={newRule.notifyOwner} onCheckedChange={v => setNewRule(p => ({ ...p, notifyOwner: v }))} />
                    <label className="text-sm">Notify project owner on critical/high alerts</label>
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={() => createRuleMut.mutate({
                    credentialId: parseInt(newRule.credentialId),
                    alertName: newRule.alertName,
                    thresholdDays: parseInt(newRule.thresholdDays),
                    notifyOwner: newRule.notifyOwner,
                  })} disabled={!newRule.credentialId || !newRule.alertName}>
                    Create Rule
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold">{stats?.totalRules ?? 0}</div>
              <div className="text-xs text-muted-foreground">Total Rules</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold text-green-400">{stats?.enabledRules ?? 0}</div>
              <div className="text-xs text-muted-foreground">Active Rules</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold">{stats?.totalAlerts ?? 0}</div>
              <div className="text-xs text-muted-foreground">Total Alerts</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold text-amber-400">{stats?.unacknowledgedAlerts ?? 0}</div>
              <div className="text-xs text-muted-foreground">Unacknowledged</div>
            </CardContent>
          </Card>
          <Card className="bg-card/50 border-border/50">
            <CardContent className="pt-4 pb-3 px-4">
              <div className="text-2xl font-bold text-red-400">{stats?.criticalAlerts ?? 0}</div>
              <div className="text-xs text-muted-foreground">Critical</div>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="dashboard">Alert Rules</TabsTrigger>
            <TabsTrigger value="history">Alert History</TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="space-y-4">
            {rules.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="py-12 text-center">
                  <Bell className="h-12 w-12 mx-auto text-muted-foreground/50 mb-4" />
                  <p className="text-muted-foreground">No alert rules configured. Create one to start monitoring credential expiry.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {rules.map((rule: any) => {
                  const cred = credentials.find((c: any) => c.id === rule.credentialId);
                  return (
                    <Card key={rule.id} className="bg-card/50 border-border/50">
                      <CardContent className="py-4 px-5">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <Switch
                              checked={rule.isEnabled}
                              onCheckedChange={v => updateRuleMut.mutate({ ruleId: rule.id, isEnabled: v })}
                            />
                            <div>
                              <div className="font-medium">{rule.alertName}</div>
                              <div className="text-sm text-muted-foreground">
                                {cred ? `${cred.credentialName} (${cred.provider.toUpperCase()})` : `Credential #${rule.credentialId}`}
                                {" · "}{rule.thresholdDays} day threshold
                                {rule.notifyOwner && " · Notifications enabled"}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {rule.lastCheckedAt && (
                              <span className="text-xs text-muted-foreground">
                                Last checked: {new Date(rule.lastCheckedAt).toLocaleDateString()}
                              </span>
                            )}
                            <Button variant="ghost" size="sm" onClick={() => deleteRuleMut.mutate({ ruleId: rule.id })}>
                              <Trash2 className="h-4 w-4 text-red-400" />
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>

          <TabsContent value="history" className="space-y-4">
            {history.length === 0 ? (
              <Card className="bg-card/50 border-border/50">
                <CardContent className="py-12 text-center">
                  <CheckCircle2 className="h-12 w-12 mx-auto text-green-400/50 mb-4" />
                  <p className="text-muted-foreground">No alerts generated yet. Run a check to scan credentials.</p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {history.map((alert: any) => {
                  const Icon = alertTypeIcons[alert.alertType] || AlertTriangle;
                  return (
                    <Card key={alert.id} className="bg-card/50 border-border/50">
                      <CardContent className="py-4 px-5">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Icon className="h-5 w-5 text-muted-foreground" />
                            <div>
                              <div className="flex items-center gap-2">
                                <Badge className={severityColors[alert.severity]}>{alert.severity}</Badge>
                                <span className="font-medium text-sm">{alert.alertType.replace(/_/g, " ")}</span>
                                {alert.credentialProvider && (
                                  <Badge variant="outline">{alert.credentialProvider.toUpperCase()}</Badge>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">{alert.message}</p>
                              <div className="text-xs text-muted-foreground mt-1">
                                {new Date(alert.createdAt).toLocaleString()}
                                {alert.daysUntilExpiry !== null && ` · ${alert.daysUntilExpiry} days until expiry`}
                              </div>
                            </div>
                          </div>
                          <div>
                            {alert.acknowledgedAt ? (
                              <Badge variant="outline" className="text-green-400">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                Acknowledged
                              </Badge>
                            ) : (
                              <Button variant="outline" size="sm" onClick={() => acknowledgeMut.mutate({ alertId: alert.id })}>
                                Acknowledge
                              </Button>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
