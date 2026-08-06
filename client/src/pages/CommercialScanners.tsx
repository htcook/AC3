import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Shield,
  Plus,
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
  Trash2,
  Activity,
  AlertTriangle,
  Play,
  Download,
  Server,
  ShieldCheck,
  Wifi,
  WifiOff,
  ToggleLeft,
  ToggleRight,
  Search,
  Filter,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════
// PAGE: Commercial Scanner Connectors (FedRAMP/NIST/DoD)
// ═══════════════════════════════════════════════════════════════════════

export default function CommercialScanners() {
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState("");
  const [formName, setFormName] = useState("");
  const [formUrl, setFormUrl] = useState("");
  const [formCredentials, setFormCredentials] = useState<Record<string, string>>({});
  const [activeTab, setActiveTab] = useState<"connectors" | "scans" | "findings">("connectors");
  const [searchFilter, setSearchFilter] = useState("");

  // Queries
  const { data: platforms } = trpc.commercialScanners.listPlatforms.useQuery();
  const { data: connectors, isLoading: connectorsLoading, refetch: refetchConnectors } = trpc.commercialScanners.listConnectors.useQuery();
  const { data: stats } = trpc.commercialScanners.getStats.useQuery();
  const { data: scans, refetch: refetchScans } = trpc.commercialScanners.listScans.useQuery({ limit: 50 });
  const { data: findings, refetch: refetchFindings } = trpc.commercialScanners.listFindings.useQuery({ limit: 100 });

  // Mutations
  const addConnector = trpc.commercialScanners.addConnector.useMutation({
    onSuccess: (data) => {
      toast.success(`Connector "${data.name}" added for ${data.platform}`);
      refetchConnectors();
      resetForm();
    },
    onError: (err) => toast.error(`Failed: ${err.message}`),
  });

  const testConnection = trpc.commercialScanners.testConnection.useMutation({
    onSuccess: (data) => {
      if (data.authenticated) {
        toast.success(`Connection healthy — API v${data.apiVersion || "unknown"}`);
      } else if (data.reachable) {
        toast.error("Reachable but authentication failed");
      } else {
        toast.error(`Unreachable: ${data.error}`);
      }
      refetchConnectors();
    },
    onError: (err) => toast.error(`Test failed: ${err.message}`),
  });

  const removeConnector = trpc.commercialScanners.removeConnector.useMutation({
    onSuccess: () => {
      toast.success("Connector removed");
      refetchConnectors();
    },
    onError: (err) => toast.error(`Remove failed: ${err.message}`),
  });

  const toggleConnector = trpc.commercialScanners.toggleConnector.useMutation({
    onSuccess: () => {
      refetchConnectors();
    },
    onError: (err) => toast.error(`Toggle failed: ${err.message}`),
  });

  const triggerScan = trpc.commercialScanners.triggerScan.useMutation({
    onSuccess: (data) => {
      toast.success(`Scan started: ${data.scanId}`);
      refetchScans();
    },
    onError: (err) => toast.error(`Scan failed: ${err.message}`),
  });

  const importResults = trpc.commercialScanners.importResults.useMutation({
    onSuccess: (data) => {
      toast.success(`Imported ${data.imported} findings (${data.critical} critical, ${data.high} high)`);
      refetchScans();
      refetchFindings();
    },
    onError: (err) => toast.error(`Import failed: ${err.message}`),
  });

  function resetForm() {
    setShowAddForm(false);
    setSelectedPlatform("");
    setFormName("");
    setFormUrl("");
    setFormCredentials({});
  }

  function handleAddConnector() {
    if (!selectedPlatform || !formName || !formUrl) {
      toast.error("Platform, name, and URL are required");
      return;
    }
    addConnector.mutate({
      platform: selectedPlatform,
      name: formName,
      baseUrl: formUrl,
      credentials: formCredentials,
    });
  }

  const selectedPlatformMeta = platforms?.find(p => p.id === selectedPlatform);

  const filteredConnectors = connectors?.filter(c =>
    !searchFilter || c.name.toLowerCase().includes(searchFilter.toLowerCase()) || c.platform.toLowerCase().includes(searchFilter.toLowerCase())
  );

  return (
    <AppShell>
      <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <ShieldCheck className="w-7 h-7 text-emerald-500" />
              Commercial Scanner Connectors
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              FedRAMP / NIST 800-53 / DoD RMF compliant vulnerability scanning platforms
            </p>
          </div>
          <Button onClick={() => setShowAddForm(true)} className="gap-2">
            <Plus className="w-4 h-4" /> Add Connector
          </Button>
        </div>

        {/* Stats Bar */}
        {stats && (
          <div className="grid grid-cols-5 gap-4">
            <StatCard label="Connectors" value={stats.totalConnectors} icon={<Server className="w-4 h-4" />} />
            <StatCard label="Total Scans" value={stats.totalScans} icon={<Activity className="w-4 h-4" />} />
            <StatCard label="Total Findings" value={stats.totalFindings} icon={<Shield className="w-4 h-4" />} />
            <StatCard label="Open Findings" value={stats.openFindings} icon={<AlertTriangle className="w-4 h-4 text-amber-500" />} />
            <StatCard label="Critical Open" value={stats.criticalOpen} icon={<XCircle className="w-4 h-4 text-red-500" />} color="text-red-500" />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {(["connectors", "scans", "findings"] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${
                activeTab === tab
                  ? "text-foreground border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "connectors" && (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="relative flex-1 max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search connectors..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Button variant="outline" size="sm" onClick={() => refetchConnectors()} className="gap-1">
                <RefreshCw className="w-3.5 h-3.5" /> Refresh
              </Button>
            </div>

            {connectorsLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
              </div>
            ) : !filteredConnectors?.length ? (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No connectors configured yet</p>
                <p className="text-xs mt-1">Click "Add Connector" to connect a commercial scanner</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {filteredConnectors.map(c => (
                  <ConnectorCard
                    key={c.connectorId}
                    connector={c}
                    onTest={() => testConnection.mutate({ connectorId: c.connectorId })}
                    onRemove={() => removeConnector.mutate({ connectorId: c.connectorId })}
                    onToggle={() => toggleConnector.mutate({ connectorId: c.connectorId, enabled: !c.enabled })}
                    onScan={(scanType: string) => triggerScan.mutate({ connectorId: c.connectorId, scanType })}
                    testing={testConnection.isPending}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "scans" && (
          <div className="space-y-3">
            {!scans?.length ? (
              <div className="text-center py-12 text-muted-foreground">
                <Activity className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No scans yet — trigger a scan from a connector</p>
              </div>
            ) : (
              <div className="border border-border rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left px-4 py-2 font-medium">Scan ID</th>
                      <th className="text-left px-4 py-2 font-medium">Platform</th>
                      <th className="text-left px-4 py-2 font-medium">Type</th>
                      <th className="text-left px-4 py-2 font-medium">Status</th>
                      <th className="text-left px-4 py-2 font-medium">Findings</th>
                      <th className="text-left px-4 py-2 font-medium">Started</th>
                      <th className="text-right px-4 py-2 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {scans.map(scan => (
                      <tr key={scan.scanId} className="hover:bg-muted/30">
                        <td className="px-4 py-2 font-mono text-xs">{scan.scanId.slice(0, 16)}</td>
                        <td className="px-4 py-2">
                          <Badge variant="outline" className="text-xs">{scan.platform}</Badge>
                        </td>
                        <td className="px-4 py-2">{scan.scanType}</td>
                        <td className="px-4 py-2">
                          <ScanStatusBadge status={scan.status} />
                        </td>
                        <td className="px-4 py-2">
                          {scan.findingsCount ? (
                            <span className="text-xs">
                              {scan.criticalCount ? <span className="text-red-500 font-bold">{scan.criticalCount}C</span> : null}
                              {scan.highCount ? <span className="text-orange-500 ml-1">{scan.highCount}H</span> : null}
                              {scan.mediumCount ? <span className="text-amber-500 ml-1">{scan.mediumCount}M</span> : null}
                              {scan.lowCount ? <span className="text-blue-500 ml-1">{scan.lowCount}L</span> : null}
                            </span>
                          ) : "—"}
                        </td>
                        <td className="px-4 py-2 text-xs text-muted-foreground">{scan.startedAt || "—"}</td>
                        <td className="px-4 py-2 text-right">
                          {scan.status === "completed" && !scan.findingsCount && (
                            <Button size="sm" variant="ghost" className="gap-1 text-xs"
                              onClick={() => importResults.mutate({ scanId: scan.scanId })}
                              disabled={importResults.isPending}
                            >
                              <Download className="w-3 h-3" /> Import
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === "findings" && (
          <div className="space-y-3">
            {!findings?.length ? (
              <div className="text-center py-12 text-muted-foreground">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No findings imported yet</p>
              </div>
            ) : (
              <div className="border border-border rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left px-4 py-2 font-medium">Severity</th>
                      <th className="text-left px-4 py-2 font-medium">Title</th>
                      <th className="text-left px-4 py-2 font-medium">CVE</th>
                      <th className="text-left px-4 py-2 font-medium">Platform</th>
                      <th className="text-left px-4 py-2 font-medium">Asset</th>
                      <th className="text-left px-4 py-2 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {findings.map(f => (
                      <tr key={f.findingId} className="hover:bg-muted/30">
                        <td className="px-4 py-2">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-4 py-2 max-w-[300px] truncate">{f.title}</td>
                        <td className="px-4 py-2 font-mono text-xs">{f.cveId || "—"}</td>
                        <td className="px-4 py-2">
                          <Badge variant="outline" className="text-xs">{f.platform}</Badge>
                        </td>
                        <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[200px]">{f.affectedAsset || "—"}</td>
                        <td className="px-4 py-2">
                          <Badge variant={f.status === "open" ? "destructive" : "secondary"} className="text-xs">
                            {f.status}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Add Connector Modal */}
        {showAddForm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-card border border-border rounded-xl p-6 w-full max-w-lg max-h-[80vh] overflow-y-auto shadow-2xl">
              <h2 className="text-lg font-bold mb-4">Add Commercial Scanner Connector</h2>

              {/* Platform Selection */}
              <label className="text-sm font-medium text-muted-foreground">Platform</label>
              <select
                value={selectedPlatform}
                onChange={(e) => {
                  setSelectedPlatform(e.target.value);
                  setFormCredentials({});
                }}
                className="w-full mt-1 mb-3 px-3 py-2 rounded-md border border-border bg-background text-foreground text-sm"
              >
                <option value="">Select a platform...</option>
                {platforms?.map(p => (
                  <option key={p.id} value={p.id}>{p.name} — {p.fedRampLevel}</option>
                ))}
              </select>

              {selectedPlatformMeta && (
                <div className="mb-3 p-3 bg-muted/50 rounded-lg text-xs space-y-1">
                  <p><strong>Vendor:</strong> {selectedPlatformMeta.vendor}</p>
                  <p><strong>FedRAMP Level:</strong> {selectedPlatformMeta.fedRampLevel}</p>
                  <p><strong>Scan Types:</strong> {selectedPlatformMeta.scanTypes?.join(", ")}</p>
                </div>
              )}

              <label className="text-sm font-medium text-muted-foreground">Display Name</label>
              <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="e.g. Production Tenable" className="mb-3 mt-1" />

              <label className="text-sm font-medium text-muted-foreground">Base URL</label>
              <Input value={formUrl} onChange={(e) => setFormUrl(e.target.value)} placeholder="https://cloud.tenable.com" className="mb-3 mt-1" />

              <label className="text-sm font-medium text-muted-foreground">Credentials</label>
              <div className="space-y-2 mt-1 mb-4">
                {selectedPlatformMeta?.requiredCredentials?.map((cred: string) => (
                  <div key={cred}>
                    <label className="text-xs text-muted-foreground">{cred}</label>
                    <Input
                      type="password"
                      value={formCredentials[cred] || ""}
                      onChange={(e) => setFormCredentials(prev => ({ ...prev, [cred]: e.target.value }))}
                      placeholder={`Enter ${cred}`}
                    />
                  </div>
                )) || (
                  <>
                    <Input
                      placeholder="API Key"
                      type="password"
                      value={formCredentials["apiKey"] || ""}
                      onChange={(e) => setFormCredentials(prev => ({ ...prev, apiKey: e.target.value }))}
                    />
                  </>
                )}
              </div>

              <div className="flex gap-2 justify-end">
                <Button variant="outline" onClick={resetForm}>Cancel</Button>
                <Button onClick={handleAddConnector} disabled={addConnector.isPending} className="gap-1">
                  {addConnector.isPending && <Loader2 className="w-3 h-3 animate-spin" />}
                  Add Connector
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}

// ─── Sub-components ──────────────────────────────────────────────────

function StatCard({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color?: string }) {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
        {icon} {label}
      </div>
      <div className={`text-2xl font-bold ${color || "text-foreground"}`}>{value}</div>
    </div>
  );
}

function ConnectorCard({ connector, onTest, onRemove, onToggle, onScan, testing }: {
  connector: any;
  onTest: () => void;
  onRemove: () => void;
  onToggle: () => void;
  onScan: (scanType: string) => void;
  testing: boolean;
}) {
  const healthColor = connector.healthStatus === "healthy" ? "text-emerald-500"
    : connector.healthStatus === "auth_failed" ? "text-amber-500"
    : connector.healthStatus === "unreachable" ? "text-red-500"
    : "text-muted-foreground";

  const HealthIcon = connector.healthStatus === "healthy" ? CheckCircle
    : connector.healthStatus === "unreachable" ? WifiOff
    : connector.healthStatus === "auth_failed" ? AlertTriangle
    : Wifi;

  return (
    <div className={`bg-card border rounded-lg p-4 transition-all ${connector.enabled ? "border-border" : "border-border/50 opacity-60"}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <HealthIcon className={`w-4 h-4 ${healthColor}`} />
          <h3 className="font-semibold text-sm">{connector.name}</h3>
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="sm" onClick={onToggle} className="h-7 w-7 p-0">
            {connector.enabled ? <ToggleRight className="w-4 h-4 text-emerald-500" /> : <ToggleLeft className="w-4 h-4" />}
          </Button>
          <Button variant="ghost" size="sm" onClick={onRemove} className="h-7 w-7 p-0 text-red-500 hover:text-red-600">
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      <div className="space-y-1 text-xs text-muted-foreground mb-3">
        <p><strong>Platform:</strong> {connector.platform}</p>
        <p><strong>URL:</strong> {connector.baseUrl}</p>
        <p><strong>FedRAMP:</strong> {connector.fedRampLevel || "N/A"}</p>
        {connector.healthMessage && <p><strong>Status:</strong> {connector.healthMessage}</p>}
        {connector.lastHealthCheck && <p><strong>Last Check:</strong> {connector.lastHealthCheck}</p>}
      </div>

      <div className="flex flex-wrap gap-1 mb-3">
        {connector.scanTypes?.map((t: string) => (
          <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
        ))}
      </div>

      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={onTest} disabled={testing} className="gap-1 text-xs">
          {testing ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
          Test
        </Button>
        {connector.scanTypes?.[0] && (
          <Button size="sm" variant="outline" onClick={() => onScan(connector.scanTypes[0])} className="gap-1 text-xs">
            <Play className="w-3 h-3" /> Scan
          </Button>
        )}
      </div>
    </div>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    running: "bg-blue-500/10 text-blue-500 border-blue-500/30",
    completed: "bg-emerald-500/10 text-emerald-500 border-emerald-500/30",
    failed: "bg-red-500/10 text-red-500 border-red-500/30",
    import_failed: "bg-amber-500/10 text-amber-500 border-amber-500/30",
    pending: "bg-muted text-muted-foreground border-border",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${variants[status] || variants.pending}`}>
      {status}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-500 border-red-500/30",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/30",
    medium: "bg-amber-500/10 text-amber-500 border-amber-500/30",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/30",
    info: "bg-muted text-muted-foreground border-border",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border uppercase ${colors[severity] || colors.info}`}>
      {severity}
    </span>
  );
}
