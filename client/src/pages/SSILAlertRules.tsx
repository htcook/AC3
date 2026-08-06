/**
 * SSIL Alert Rules — Observation-based alerting with threshold triggers
 * Author: Harrison Cook — AceofCloud
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Bell,
  Plus,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Trash2,
  Settings,
  Zap,
  Eye,
  EyeOff,
} from "lucide-react";

const TRIGGER_TYPES = [
  { value: "critical_cve", label: "Critical CVE Detected", icon: "🔴" },
  { value: "new_open_port", label: "New Open Port", icon: "🔓" },
  { value: "high_severity_signal", label: "High Severity Signal", icon: "⚠️" },
  { value: "risk_score_threshold", label: "Risk Score Threshold", icon: "📊" },
  { value: "observation_count", label: "Observation Burst", icon: "📈" },
  { value: "new_vulnerability", label: "New Vulnerability", icon: "🐛" },
  { value: "tls_expiry", label: "TLS Certificate Expiry", icon: "🔒" },
  { value: "misconfiguration", label: "Misconfiguration", icon: "⚙️" },
  { value: "custom", label: "Custom Rule", icon: "🔧" },
] as const;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

function AlertStatsCards() {
  const { data: stats } = trpc.ssil.getAlertStats.useQuery();
  if (!stats) return null;

  const cards = [
    { label: "Total Rules", value: stats.totalRules, icon: Settings, color: "text-blue-400" },
    { label: "Enabled", value: stats.enabledRules, icon: Zap, color: "text-green-400" },
    { label: "Total Alerts", value: stats.totalAlerts, icon: Bell, color: "text-yellow-400" },
    { label: "Unacknowledged", value: stats.unacknowledged, icon: AlertTriangle, color: "text-red-400" },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((c) => (
        <Card key={c.label} className="bg-card/50 border-border/50">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider">{c.label}</p>
                <p className={`text-2xl font-mono font-bold ${c.color}`}>{c.value}</p>
              </div>
              <c.icon className={`w-8 h-8 ${c.color} opacity-50`} />
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function CreateRuleDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [triggerType, setTriggerType] = useState<string>("critical_cve");
  const [notifyOwner, setNotifyOwner] = useState(true);
  const [cooldown, setCooldown] = useState(60);

  const createMutation = trpc.ssil.createAlertRule.useMutation({
    onSuccess: () => {
      toast.success("Alert rule created");
      setOpen(false);
      setName("");
      setDescription("");
      onCreated();
    },
    onError: (err) => toast.error(err.message),
  });

  const handleCreate = () => {
    if (!name.trim()) {
      toast.error("Rule name is required");
      return;
    }
    createMutation.mutate({
      name,
      description,
      triggerType: triggerType as any,
      conditions: {},
      notifyOwner,
      cooldownMinutes: cooldown,
      isEnabled: true,
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <Plus className="w-4 h-4" /> New Rule
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="font-display tracking-wider">CREATE ALERT RULE</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 pt-2">
          <div>
            <Label className="text-xs uppercase tracking-wider">Rule Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g., Critical CVE Alert" className="mt-1" />
          </div>
          <div>
            <Label className="text-xs uppercase tracking-wider">Description</Label>
            <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this rule monitors..." className="mt-1" rows={2} />
          </div>
          <div>
            <Label className="text-xs uppercase tracking-wider">Trigger Type</Label>
            <Select value={triggerType} onValueChange={setTriggerType}>
              <SelectTrigger className="mt-1">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TRIGGER_TYPES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.icon} {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <Label className="text-xs uppercase tracking-wider">Notify Owner</Label>
              <p className="text-xs text-muted-foreground">Send push notification on trigger</p>
            </div>
            <Switch checked={notifyOwner} onCheckedChange={setNotifyOwner} />
          </div>
          <div>
            <Label className="text-xs uppercase tracking-wider">Cooldown (minutes)</Label>
            <Input type="number" value={cooldown} onChange={(e) => setCooldown(Number(e.target.value))} min={1} className="mt-1 w-32" />
          </div>
          <Button onClick={handleCreate} disabled={createMutation.isPending} className="w-full">
            {createMutation.isPending ? "Creating..." : "Create Rule"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RulesTab() {
  const utils = trpc.useUtils();
  const { data: rules, isLoading } = trpc.ssil.listAlertRules.useQuery();
  const toggleMutation = trpc.ssil.toggleAlertRule.useMutation({
    onSuccess: () => utils.ssil.listAlertRules.invalidate(),
  });
  const deleteMutation = trpc.ssil.deleteAlertRule.useMutation({
    onSuccess: () => {
      utils.ssil.listAlertRules.invalidate();
      utils.ssil.getAlertStats.invalidate();
      toast.success("Rule deleted");
    },
  });
  const seedMutation = trpc.ssil.seedDefaultAlertRules.useMutation({
    onSuccess: (data) => {
      utils.ssil.listAlertRules.invalidate();
      utils.ssil.getAlertStats.invalidate();
      toast.success(`Seeded ${data.seeded} default rules`);
    },
  });

  if (isLoading) return <div className="text-center py-8 text-muted-foreground">Loading rules...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-display tracking-wider text-muted-foreground uppercase">
          Alert Rules ({rules?.length || 0})
        </h3>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
            {seedMutation.isPending ? "Seeding..." : "Seed Defaults"}
          </Button>
          <CreateRuleDialog onCreated={() => {
            utils.ssil.listAlertRules.invalidate();
            utils.ssil.getAlertStats.invalidate();
          }} />
        </div>
      </div>

      {(!rules || rules.length === 0) ? (
        <Card className="bg-card/30 border-dashed border-border/50">
          <CardContent className="p-8 text-center">
            <Bell className="w-12 h-12 mx-auto text-muted-foreground/30 mb-3" />
            <p className="text-muted-foreground">No alert rules configured</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Click "Seed Defaults" to add recommended rules, or create a custom one.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {rules.map((rule: any) => {
            const trigger = TRIGGER_TYPES.find((t) => t.value === rule.triggerType);
            return (
              <Card key={rule.ruleId} className="bg-card/50 border-border/50 hover:border-border transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <span className="text-xl">{trigger?.icon || "📋"}</span>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-display tracking-wider text-sm">{rule.name}</span>
                          <Badge variant="outline" className="text-[10px]">
                            {trigger?.label || rule.triggerType}
                          </Badge>
                          {rule.notifyOwner && (
                            <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-400">
                              NOTIFY
                            </Badge>
                          )}
                        </div>
                        {rule.description && (
                          <p className="text-xs text-muted-foreground truncate mt-0.5">{rule.description}</p>
                        )}
                        <p className="text-[10px] text-muted-foreground/60 mt-1">
                          Cooldown: {rule.cooldownMinutes}min
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Switch
                        checked={rule.isEnabled}
                        onCheckedChange={(checked) =>
                          toggleMutation.mutate({ ruleId: rule.ruleId, isEnabled: checked })
                        }
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-red-400"
                        onClick={() => deleteMutation.mutate({ ruleId: rule.ruleId })}
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function HistoryTab() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [ackFilter, setAckFilter] = useState<string>("all");
  const utils = trpc.useUtils();

  const { data, isLoading } = trpc.ssil.getAlertHistory.useQuery({
    limit: 100,
    severity: severityFilter === "all" ? undefined : severityFilter as any,
    acknowledged: ackFilter === "all" ? undefined : ackFilter === "yes",
  });

  const ackMutation = trpc.ssil.acknowledgeAlert.useMutation({
    onSuccess: () => {
      utils.ssil.getAlertHistory.invalidate();
      utils.ssil.getAlertStats.invalidate();
      toast.success("Alert acknowledged");
    },
  });

  const dismissMutation = trpc.ssil.dismissAlert.useMutation({
    onSuccess: () => {
      utils.ssil.getAlertHistory.invalidate();
      utils.ssil.getAlertStats.invalidate();
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        <Select value={ackFilter} onValueChange={setAckFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="no">Unacknowledged</SelectItem>
            <SelectItem value="yes">Acknowledged</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground ml-auto">
          {data?.total || 0} alerts total
        </span>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-muted-foreground">Loading alert history...</div>
      ) : !data?.alerts?.length ? (
        <Card className="bg-card/30 border-dashed border-border/50">
          <CardContent className="p-8 text-center">
            <CheckCircle className="w-12 h-12 mx-auto text-green-400/30 mb-3" />
            <p className="text-muted-foreground">No alerts triggered yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Alerts will appear here when observation thresholds are crossed.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {data.alerts.map((alert: any) => (
            <Card key={alert.alertId} className="bg-card/50 border-border/50">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className={SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info}>
                        {alert.severity?.toUpperCase()}
                      </Badge>
                      <span className="font-display tracking-wider text-sm">{alert.title}</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 whitespace-pre-line line-clamp-3">
                      {alert.message}
                    </p>
                    <div className="flex items-center gap-3 mt-2 text-[10px] text-muted-foreground/60">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(alert.triggeredAt).toLocaleString()}
                      </span>
                      {alert.matchedAssetHost && (
                        <span>Asset: {alert.matchedAssetHost}</span>
                      )}
                      {alert.notificationSent && (
                        <Badge variant="outline" className="text-[9px] border-green-500/30 text-green-400">
                          NOTIFIED
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    {!alert.acknowledgedAt && !alert.dismissedAt && (
                      <>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs gap-1"
                          onClick={() => ackMutation.mutate({ alertId: alert.alertId })}
                        >
                          <Eye className="w-3 h-3" /> Ack
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs gap-1 text-muted-foreground"
                          onClick={() => dismissMutation.mutate({ alertId: alert.alertId })}
                        >
                          <EyeOff className="w-3 h-3" /> Dismiss
                        </Button>
                      </>
                    )}
                    {alert.acknowledgedAt && (
                      <Badge variant="outline" className="text-[10px] border-green-500/30 text-green-400">
                        ACK by {alert.acknowledgedBy}
                      </Badge>
                    )}
                    {alert.dismissedAt && (
                      <Badge variant="outline" className="text-[10px]">DISMISSED</Badge>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export default function SSILAlertRules() {
  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-display tracking-wider">ALERT RULES</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Observation-based alerting with threshold triggers and owner notifications
            </p>
          </div>
          <Shield className="w-8 h-8 text-primary opacity-50" />
        </div>

        {/* Stats */}
        <AlertStatsCards />

        {/* Tabs */}
        <Tabs defaultValue="rules">
          <TabsList>
            <TabsTrigger value="rules">Rules</TabsTrigger>
            <TabsTrigger value="history">Alert History</TabsTrigger>
          </TabsList>
          <TabsContent value="rules" className="mt-4">
            <RulesTab />
          </TabsContent>
          <TabsContent value="history" className="mt-4">
            <HistoryTab />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
