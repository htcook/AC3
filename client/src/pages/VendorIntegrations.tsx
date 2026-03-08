import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Shield, Server, Activity, AlertTriangle, CheckCircle2, XCircle,
  RefreshCw, Settings, Zap, Database, Clock, ChevronRight, Loader2,
  Link2, Unlink, Eye, EyeOff, Trash2, Play, Search
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Types ───────────────────────────────────────────────────────────────────

type VendorName = "crowdstrike" | "sentinelone" | "defender" | "splunk" | "xsoar" | "sentinel" | "cortex_xdr";

interface VendorMeta {
  vendor: VendorName;
  displayName: string;
  category: string;
  authType: string;
  requiredFields: string[];
  optionalFields: string[];
  defaultBaseUrl: string;
  description: string;
  capabilities: string[];
}

// ─── Constants ───────────────────────────────────────────────────────────────

const VENDOR_ICONS: Record<VendorName, React.ReactNode> = {
  crowdstrike: <Shield className="h-5 w-5 text-red-400" />,
  sentinelone: <Shield className="h-5 w-5 text-purple-400" />,
  defender: <Shield className="h-5 w-5 text-blue-400" />,
  splunk: <Database className="h-5 w-5 text-green-400" />,
  xsoar: <Zap className="h-5 w-5 text-yellow-400" />,
  sentinel: <Database className="h-5 w-5 text-cyan-400" />,
  cortex_xdr: <Shield className="h-5 w-5 text-orange-400" />,
};

const VENDOR_COLORS: Record<VendorName, string> = {
  crowdstrike: "border-red-500/30 bg-red-950/20",
  sentinelone: "border-purple-500/30 bg-purple-950/20",
  defender: "border-blue-500/30 bg-blue-950/20",
  splunk: "border-green-500/30 bg-green-950/20",
  xsoar: "border-yellow-500/30 bg-yellow-950/20",
  sentinel: "border-cyan-500/30 bg-cyan-950/20",
  cortex_xdr: "border-orange-500/30 bg-orange-950/20",
};

const CATEGORY_BADGES: Record<string, string> = {
  EDR: "bg-red-900/50 text-red-300 border-red-700/50",
  SIEM: "bg-green-900/50 text-green-300 border-green-700/50",
  SOAR: "bg-yellow-900/50 text-yellow-300 border-yellow-700/50",
  XDR: "bg-orange-900/50 text-orange-300 border-orange-700/50",
};

const STATUS_CONFIG: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  connected: { icon: <CheckCircle2 className="h-4 w-4" />, color: "text-emerald-400", label: "Connected" },
  disconnected: { icon: <XCircle className="h-4 w-4" />, color: "text-zinc-500", label: "Disconnected" },
  error: { icon: <AlertTriangle className="h-4 w-4" />, color: "text-red-400", label: "Error" },
  unconfigured: { icon: <Unlink className="h-4 w-4" />, color: "text-zinc-600", label: "Not Configured" },
};

// ─── Vendor Card ─────────────────────────────────────────────────────────────

function VendorCard({
  meta,
  integration,
  onConfigure,
  onHealthCheck,
  onToggle,
  onSync,
  onDelete,
}: {
  meta: VendorMeta;
  integration?: any;
  onConfigure: () => void;
  onHealthCheck: () => void;
  onToggle: (enabled: boolean) => void;
  onSync: () => void;
  onDelete: () => void;
}) {
  const status = integration?.status || "unconfigured";
  const statusCfg = STATUS_CONFIG[status] || STATUS_CONFIG.unconfigured;
  const isConfigured = !!integration?.hasAuthConfig;

  return (
    <Card className={`border ${VENDOR_COLORS[meta.vendor]} transition-all hover:border-opacity-60`}>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            {VENDOR_ICONS[meta.vendor]}
            <div>
              <CardTitle className="text-base text-zinc-100">{meta.displayName}</CardTitle>
              <CardDescription className="text-xs text-zinc-500 mt-0.5">{meta.description}</CardDescription>
            </div>
          </div>
          <Badge variant="outline" className={CATEGORY_BADGES[meta.category] || ""}>
            {meta.category}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Status Row */}
        <div className="flex items-center justify-between">
          <div className={`flex items-center gap-2 ${statusCfg.color}`}>
            {statusCfg.icon}
            <span className="text-sm font-medium">{statusCfg.label}</span>
          </div>
          {integration && (
            <Switch
              checked={integration.enabled}
              onCheckedChange={onToggle}
              disabled={!isConfigured}
            />
          )}
        </div>

        {/* Last Health Check */}
        {integration?.lastHealthCheck && (
          <div className="text-xs text-zinc-500 flex items-center gap-1">
            <Clock className="h-3 w-3" />
            Last checked: {new Date(integration.lastHealthCheck).toLocaleString()}
          </div>
        )}

        {/* Error */}
        {integration?.lastError && (
          <div className="text-xs text-red-400 bg-red-950/30 rounded p-2 border border-red-900/50">
            {integration.lastError}
          </div>
        )}

        {/* Capabilities */}
        <div className="flex flex-wrap gap-1">
          {meta.capabilities.map((cap) => (
            <Badge key={cap} variant="outline" className="text-[10px] border-zinc-700 text-zinc-400">
              {cap}
            </Badge>
          ))}
        </div>

        {/* Actions */}
        <div className="flex gap-2 pt-1">
          <Button size="sm" variant="outline" onClick={onConfigure} className="flex-1 text-xs">
            <Settings className="h-3 w-3 mr-1" />
            {isConfigured ? "Edit" : "Configure"}
          </Button>
          {isConfigured && (
            <>
              <Button size="sm" variant="outline" onClick={onHealthCheck} className="text-xs">
                <Activity className="h-3 w-3 mr-1" />
                Test
              </Button>
              <Button size="sm" variant="outline" onClick={onSync} className="text-xs" disabled={!integration?.enabled}>
                <RefreshCw className="h-3 w-3 mr-1" />
                Sync
              </Button>
            </>
          )}
          {integration && (
            <Button size="sm" variant="outline" onClick={onDelete} className="text-xs text-red-400 hover:text-red-300">
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Configure Modal ─────────────────────────────────────────────────────────

function ConfigurePanel({
  meta,
  existingConfig,
  onSave,
  onCancel,
}: {
  meta: VendorMeta;
  existingConfig?: any;
  onSave: (data: any) => void;
  onCancel: () => void;
}) {
  const [baseUrl, setBaseUrl] = useState(existingConfig?.connectionConfig?.baseUrl || meta.defaultBaseUrl);
  const [authFields, setAuthFields] = useState<Record<string, string>>({});
  const [showSecrets, setShowSecrets] = useState(false);
  const [saving, setSaving] = useState(false);

  const allFields = [...meta.requiredFields, ...meta.optionalFields];

  const handleSave = async () => {
    // Validate required fields
    for (const field of meta.requiredFields) {
      if (!authFields[field]?.trim()) {
        toast.error(`${field} is required`);
        return;
      }
    }
    if (!baseUrl.trim()) {
      toast.error("Base URL is required");
      return;
    }

    setSaving(true);
    try {
      await onSave({
        vendor: meta.vendor,
        displayName: meta.displayName,
        authConfig: authFields,
        connectionConfig: { baseUrl: baseUrl.replace(/\/$/, "") },
        enabled: true,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="border border-zinc-700 bg-zinc-900/80">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {VENDOR_ICONS[meta.vendor]}
            <div>
              <CardTitle className="text-base text-zinc-100">Configure {meta.displayName}</CardTitle>
              <CardDescription className="text-xs text-zinc-500">
                Auth type: {(meta.authType || '').toUpperCase()} | Required: {meta.requiredFields.join(", ")}
              </CardDescription>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={onCancel} className="text-zinc-400">
            Cancel
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Base URL */}
        <div className="space-y-2">
          <Label className="text-zinc-300 text-sm">Base URL</Label>
          <Input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder={meta.defaultBaseUrl || "https://your-instance.example.com"}
            className="bg-zinc-800 border-zinc-700 text-zinc-200"
          />
          {meta.vendor === "crowdstrike" && (
            <p className="text-xs text-zinc-500">US-1: api.crowdstrike.com | US-2: api.us-2.crowdstrike.com | EU-1: api.eu-1.crowdstrike.com</p>
          )}
        </div>

        {/* Auth Fields */}
        {allFields.map((field) => (
          <div key={field} className="space-y-2">
            <div className="flex items-center justify-between">
              <Label className="text-zinc-300 text-sm">
                {field}
                {meta.requiredFields.includes(field) && <span className="text-red-400 ml-1">*</span>}
              </Label>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowSecrets(!showSecrets)}
                className="h-6 px-2 text-zinc-500"
              >
                {showSecrets ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
              </Button>
            </div>
            <Input
              type={showSecrets ? "text" : "password"}
              value={authFields[field] || ""}
              onChange={(e) => setAuthFields({ ...authFields, [field]: e.target.value })}
              placeholder={`Enter ${field}`}
              className="bg-zinc-800 border-zinc-700 text-zinc-200 font-mono text-sm"
            />
          </div>
        ))}

        <Button onClick={handleSave} disabled={saving} className="w-full bg-emerald-600 hover:bg-emerald-700">
          {saving ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Link2 className="h-4 w-4 mr-2" />}
          Save & Connect
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Sync History Panel ──────────────────────────────────────────────────────

function SyncHistoryPanel({ integrationId }: { integrationId: number }) {
  const { data: history, isLoading } = trpc.vendorIntegrations.syncHistory.useQuery(
    { integrationId, limit: 20 },
  );

  if (isLoading) return <div className="text-zinc-500 text-sm p-4">Loading sync history...</div>;
  if (!history?.length) return <div className="text-zinc-500 text-sm p-4">No sync events yet</div>;

  return (
    <div className="space-y-2">
      {history.map((event: any, i: number) => (
        <div key={i} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded border border-zinc-700/50">
          <div className="flex items-center gap-3">
            <Badge
              variant="outline"
              className={
                event.status === "success" ? "border-emerald-700 text-emerald-400" :
                event.status === "failed" ? "border-red-700 text-red-400" :
                "border-yellow-700 text-yellow-400"
              }
            >
              {event.status}
            </Badge>
            <div>
              <span className="text-sm text-zinc-200">{event.eventType}</span>
              {event.recordsProcessed > 0 && (
                <span className="text-xs text-zinc-500 ml-2">{event.recordsProcessed} records</span>
              )}
            </div>
          </div>
          <div className="text-xs text-zinc-500">
            {event.durationMs && <span className="mr-3">{event.durationMs}ms</span>}
            {new Date(event.createdAt).toLocaleString()}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Cached Data Browser ─────────────────────────────────────────────────────

function CachedDataPanel() {
  const [filters, setFilters] = useState<{
    hostname?: string;
    ipAddress?: string;
    severity?: string;
    dataType?: string;
  }>({});

  const { data: cachedData, isLoading, refetch } = trpc.vendorIntegrations.queryCachedData.useQuery(
    { ...filters, limit: 100 },
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="grid grid-cols-4 gap-3">
        <Input
          placeholder="Filter by hostname"
          value={filters.hostname || ""}
          onChange={(e) => setFilters({ ...filters, hostname: e.target.value || undefined })}
          className="bg-zinc-800 border-zinc-700 text-zinc-200 text-sm"
        />
        <Input
          placeholder="Filter by IP"
          value={filters.ipAddress || ""}
          onChange={(e) => setFilters({ ...filters, ipAddress: e.target.value || undefined })}
          className="bg-zinc-800 border-zinc-700 text-zinc-200 text-sm"
        />
        <Select value={filters.severity || "all"} onValueChange={(v) => setFilters({ ...filters, severity: v === "all" ? undefined : v })}>
          <SelectTrigger className="bg-zinc-800 border-zinc-700 text-zinc-200 text-sm">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" onClick={() => refetch()} className="text-sm">
          <Search className="h-3 w-3 mr-1" /> Search
        </Button>
      </div>

      {/* Results */}
      {isLoading ? (
        <div className="text-zinc-500 text-sm p-4">Loading...</div>
      ) : !cachedData?.length ? (
        <div className="text-center py-8 text-zinc-500">
          <Database className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No cached vendor data. Configure and sync an integration to populate.</p>
        </div>
      ) : (
        <div className="space-y-1">
          {cachedData.map((item: any) => (
            <div key={item.id} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded border border-zinc-700/50 hover:border-zinc-600/50">
              <div className="flex items-center gap-3">
                <Badge
                  variant="outline"
                  className={
                    item.severity === "critical" ? "border-red-700 text-red-400" :
                    item.severity === "high" ? "border-orange-700 text-orange-400" :
                    item.severity === "medium" ? "border-yellow-700 text-yellow-400" :
                    "border-zinc-700 text-zinc-400"
                  }
                >
                  {item.severity || "info"}
                </Badge>
                <div>
                  <span className="text-sm text-zinc-200">{item.title}</span>
                  <div className="flex gap-3 mt-0.5">
                    {item.hostname && <span className="text-xs text-zinc-500">{item.hostname}</span>}
                    {item.ipAddress && <span className="text-xs text-zinc-500">{item.ipAddress}</span>}
                    {item.dataType && <Badge variant="outline" className="text-[10px] border-zinc-700 text-zinc-500">{item.dataType}</Badge>}
                  </div>
                </div>
              </div>
              <span className="text-xs text-zinc-500">
                {item.detectedAt ? new Date(item.detectedAt).toLocaleDateString() : ""}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function VendorIntegrations() {
  const [activeTab, setActiveTab] = useState("overview");
  const [configuringVendor, setConfiguringVendor] = useState<VendorName | null>(null);
  const [selectedIntegrationId, setSelectedIntegrationId] = useState<number | null>(null);

  const { data: catalog } = trpc.vendorIntegrations.vendorCatalog.useQuery();
  const { data: integrations, refetch: refetchIntegrations } = trpc.vendorIntegrations.list.useQuery();

  const upsertMutation = trpc.vendorIntegrations.upsert.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      setConfiguringVendor(null);
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const healthCheckMutation = trpc.vendorIntegrations.healthCheck.useMutation({
    onSuccess: (result) => {
      if (result.status === "connected") toast.success(`Connected — ${result.latencyMs}ms latency`);
      else toast.error(`Health check: ${result.status} — ${result.message}`);
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleMutation = trpc.vendorIntegrations.toggleEnabled.useMutation({
    onSuccess: (result) => {
      toast.success(result.enabled ? "Integration enabled" : "Integration disabled");
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.vendorIntegrations.delete.useMutation({
    onSuccess: () => {
      toast.success("Integration removed");
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const syncMutation = trpc.vendorIntegrations.syncData.useMutation({
    onSuccess: (data) => {
      const total = data.results.reduce((sum: number, r: any) => sum + r.count, 0);
      toast.success(`Synced ${total} records in ${data.totalDurationMs}ms`);
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const healthCheckAllMutation = trpc.vendorIntegrations.healthCheckAll.useMutation({
    onSuccess: (results) => {
      const connected = results.filter((r: any) => r.result.status === "connected").length;
      toast.success(`${connected}/${results.length} integrations connected`);
      refetchIntegrations();
    },
    onError: (err) => toast.error(err.message),
  });

  const integrationMap = useMemo(() => {
    const map: Record<string, any> = {};
    integrations?.forEach((i: any) => { map[i.vendor] = i; });
    return map;
  }, [integrations]);

  const getDefaultSyncTypes = (vendor: VendorName): string[] => {
    switch (vendor) {
      case "crowdstrike": return ["hosts", "detections", "incidents"];
      case "sentinelone": return ["hosts", "threats", "alerts"];
      case "defender": return ["hosts", "alerts", "vulnerabilities"];
      case "splunk": return ["notable_events"];
      case "xsoar": return ["incidents", "indicators"];
      case "sentinel": return ["incidents", "hunting_queries", "analytics_rules"];
      case "cortex_xdr": return ["incidents", "alerts", "endpoints"];
      default: return [];
    }
  };

  // ─── Summary Stats ─────────────────────────────────────────────────────────

  const stats = useMemo(() => {
    if (!integrations) return { total: 0, connected: 0, errors: 0, unconfigured: 5 };
    return {
      total: integrations.length,
      connected: integrations.filter((i: any) => i.status === "connected").length,
      errors: integrations.filter((i: any) => i.status === "error").length,
      unconfigured: (catalog?.length || 5) - integrations.length,
    };
  }, [integrations, catalog]);

  return (
      <AppShell activePath="/vendor-integrations">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 tracking-tight flex items-center gap-3">
            <Server className="h-7 w-7 text-emerald-400" />
            Vendor Integrations
          </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Manage all third-party tool and service integrations. Configure API connections to Shodan, Censys, SecurityTrails, VirusTotal, and other security tools. Test connection health, view API usage metrics, and manage authentication credentials. This page is your central hub for ensuring all external data sources and tools are properly connected and functioning.</p>
          <p className="text-sm text-zinc-500 mt-1">
            Connect EDR, SIEM, and SOAR platforms for unified security operations
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => healthCheckAllMutation.mutate()}
            disabled={healthCheckAllMutation.isPending}
          >
            {healthCheckAllMutation.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Activity className="h-4 w-4 mr-1" />}
            Test All
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="border border-zinc-700/50 bg-zinc-800/30">
          <CardContent className="p-4 flex items-center gap-3">
            <Server className="h-8 w-8 text-zinc-400" />
            <div>
              <p className="text-2xl font-bold text-zinc-100">{catalog?.length || 5}</p>
              <p className="text-xs text-zinc-500">Available</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border border-emerald-700/30 bg-emerald-950/20">
          <CardContent className="p-4 flex items-center gap-3">
            <CheckCircle2 className="h-8 w-8 text-emerald-400" />
            <div>
              <p className="text-2xl font-bold text-emerald-400">{stats.connected}</p>
              <p className="text-xs text-zinc-500">Connected</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border border-red-700/30 bg-red-950/20">
          <CardContent className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-8 w-8 text-red-400" />
            <div>
              <p className="text-2xl font-bold text-red-400">{stats.errors}</p>
              <p className="text-xs text-zinc-500">Errors</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border border-zinc-700/30 bg-zinc-800/30">
          <CardContent className="p-4 flex items-center gap-3">
            <Unlink className="h-8 w-8 text-zinc-500" />
            <div>
              <p className="text-2xl font-bold text-zinc-400">{stats.unconfigured}</p>
              <p className="text-xs text-zinc-500">Not Configured</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-800/50 border border-zinc-700/50">
          <TabsTrigger value="overview" className="text-sm">
            <Server className="h-3.5 w-3.5 mr-1.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="data" className="text-sm">
            <Database className="h-3.5 w-3.5 mr-1.5" /> Cached Data
          </TabsTrigger>
          {selectedIntegrationId && (
            <TabsTrigger value="history" className="text-sm">
              <Clock className="h-3.5 w-3.5 mr-1.5" /> Sync History
            </TabsTrigger>
          )}
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          {/* Configure Panel (if active) */}
          {configuringVendor && catalog && (
            <ConfigurePanel
              meta={catalog.find((c: VendorMeta) => c.vendor === configuringVendor)!}
              existingConfig={integrationMap[configuringVendor]}
              onSave={(data) => upsertMutation.mutate(data)}
              onCancel={() => setConfiguringVendor(null)}
            />
          )}

          {/* Vendor Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {catalog?.map((meta: VendorMeta) => (
              <VendorCard
                key={meta.vendor}
                meta={meta}
                integration={integrationMap[meta.vendor]}
                onConfigure={() => setConfiguringVendor(meta.vendor)}
                onHealthCheck={() => {
                  const integration = integrationMap[meta.vendor];
                  if (integration) healthCheckMutation.mutate({ id: integration.id });
                }}
                onToggle={(enabled) => {
                  const integration = integrationMap[meta.vendor];
                  if (integration) toggleMutation.mutate({ id: integration.id, enabled });
                }}
                onSync={() => {
                  const integration = integrationMap[meta.vendor];
                  if (integration) {
                    setSelectedIntegrationId(integration.id);
                    syncMutation.mutate({
                      id: integration.id,
                      dataTypes: getDefaultSyncTypes(meta.vendor) as any,
                    });
                  }
                }}
                onDelete={() => {
                  const integration = integrationMap[meta.vendor];
                  if (integration && confirm(`Remove ${meta.displayName} integration?`)) {
                    deleteMutation.mutate({ id: integration.id });
                  }
                }}
              />
            ))}
          </div>
        </TabsContent>

        {/* Cached Data Tab */}
        <TabsContent value="data">
          <CachedDataPanel />
        </TabsContent>

        {/* Sync History Tab */}
        <TabsContent value="history">
          {selectedIntegrationId ? (
            <SyncHistoryPanel integrationId={selectedIntegrationId} />
          ) : (
            <div className="text-center py-8 text-zinc-500">
              <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">Select an integration to view sync history</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
