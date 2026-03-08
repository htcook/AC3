import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import {
  Server,
  Plus,
  Loader2,
  CheckCircle,
  XCircle,
  RefreshCw,
  Trash2,
  Shield,
  Activity,
  AlertTriangle,
  Eye,
  EyeOff,
  Wifi,
  WifiOff,
} from "lucide-react";

// ═══════════════════════════════════════════════════════════════════════
// PAGE: SIEM Connectors
// ═══════════════════════════════════════════════════════════════════════

export default function SiemConnectors() {
  const [showAddForm, setShowAddForm] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Form state
  const [formName, setFormName] = useState("");
  const [formBackend, setFormBackend] = useState<"wazuh" | "elastic">("wazuh");
  const [formUrl, setFormUrl] = useState("");
  const [formUsername, setFormUsername] = useState("");
  const [formPassword, setFormPassword] = useState("");
  const [formApiKey, setFormApiKey] = useState("");
  const [formIndex, setFormIndex] = useState("");
  const [formInsecure, setFormInsecure] = useState(true);
  const [formUseSecurityDetections, setFormUseSecurityDetections] = useState(false);

  // Queries
  const { data: connections, isLoading, refetch } = trpc.siemConnectors.listConnections.useQuery();

  // Mutations
  const saveConnection = trpc.siemConnectors.saveConnection.useMutation({
    onSuccess: (data: any) => {
      if (data.connected) {
        toast.success(`Connected to ${formBackend} — ${data.status.version || "unknown version"}`);
      } else {
        toast.error(`Connection saved but test failed: ${data.status.error}`);
      }
      refetch();
      resetForm();
    },
    onError: (err: any) => toast.error(`Failed to save: ${err.message}`),
  });

  const testConnection = trpc.siemConnectors.testConnection.useMutation({
    onSuccess: (data: any) => {
      if (data.connected) {
        toast.success(`Connection OK — ${data.version || "unknown"} (${data.alertCount ?? 0} alerts)`);
      } else {
        toast.error(`Test failed: ${data.error}`);
      }
      refetch();
    },
    onError: (err: any) => toast.error(`Test failed: ${err.message}`),
  });

  const toggleConnection = trpc.siemConnectors.toggleConnection.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Connection toggled");
    },
  });

  const deleteConnection = trpc.siemConnectors.deleteConnection.useMutation({
    onSuccess: () => {
      refetch();
      toast.success("Connection deleted");
    },
  });

  function resetForm() {
    setShowAddForm(false);
    setFormName("");
    setFormBackend("wazuh");
    setFormUrl("");
    setFormUsername("");
    setFormPassword("");
    setFormApiKey("");
    setFormIndex("");
    setFormInsecure(true);
    setFormUseSecurityDetections(false);
  }

  function handleSave() {
    if (!formName.trim() || !formUrl.trim()) {
      toast.error("Name and URL are required");
      return;
    }
    saveConnection.mutate({
      name: formName,
      config: {
        backend: formBackend,
        baseUrl: formUrl,
        username: formUsername || undefined,
        password: formPassword || undefined,
        apiKey: formApiKey || undefined,
        insecure: formInsecure,
        ...(formBackend === "wazuh"
          ? { wazuhAlertIndex: formIndex || undefined }
          : { elasticIndex: formIndex || undefined }),
        useSecurityDetections: formUseSecurityDetections,
      },
    });
  }

  return (
    <AppShell>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-display text-3xl flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              SIEM CONNECTORS
            </h1>
            <p className="text-muted-foreground mt-1">
              Connect Wazuh and Elastic SIEM instances for live alert ingestion and detection correlation during campaigns.
            </p>
          </div>
          <Button
            className="font-display bg-primary hover:bg-primary/90"
            onClick={() => setShowAddForm(!showAddForm)}
          >
            <Plus className="w-4 h-4 mr-2" />
            ADD CONNECTION
          </Button>
        </div>

        <div className="w-full h-0.5 bg-primary" />

        {/* Add Connection Form */}
        {showAddForm && (
          <div className="bg-card border-2 border-primary p-6">
            <h2 className="font-display text-xl mb-4">NEW SIEM CONNECTION</h2>

            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  CONNECTION NAME
                </label>
                <Input
                  value={formName}
                  onChange={(e: any) => setFormName(e.target.value)}
                  placeholder="e.g., Production Wazuh"
                  className="bg-secondary border-border"
                />
              </div>
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  BACKEND
                </label>
                <div className="flex gap-2">
                  <button
                    onClick={() => setFormBackend("wazuh")}
                    className={`flex-1 px-4 py-2 text-sm font-display tracking-wider border-2 transition-colors ${
                      formBackend === "wazuh"
                        ? "bg-primary border-primary"
                        : "border-border hover:border-primary"
                    }`}
                  >
                    WAZUH
                  </button>
                  <button
                    onClick={() => setFormBackend("elastic")}
                    className={`flex-1 px-4 py-2 text-sm font-display tracking-wider border-2 transition-colors ${
                      formBackend === "elastic"
                        ? "bg-primary border-primary"
                        : "border-border hover:border-primary"
                    }`}
                  >
                    ELASTIC
                  </button>
                </div>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  BASE URL
                </label>
                <Input
                  value={formUrl}
                  onChange={(e: any) => setFormUrl(e.target.value)}
                  placeholder={
                    formBackend === "wazuh"
                      ? "https://wazuh-manager:55000"
                      : "https://elasticsearch:9200"
                  }
                  className="bg-secondary border-border font-mono"
                />
              </div>
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  INDEX PATTERN
                </label>
                <Input
                  value={formIndex}
                  onChange={(e: any) => setFormIndex(e.target.value)}
                  placeholder={
                    formBackend === "wazuh"
                      ? "wazuh-alerts-*"
                      : ".siem-signals-* or .alerts-security.*"
                  }
                  className="bg-secondary border-border font-mono"
                />
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  USERNAME
                </label>
                <Input
                  value={formUsername}
                  onChange={(e: any) => setFormUsername(e.target.value)}
                  placeholder="admin"
                  className="bg-secondary border-border"
                />
              </div>
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  PASSWORD
                </label>
                <div className="relative">
                  <Input
                    type={showPassword ? "text" : "password"}
                    value={formPassword}
                    onChange={(e: any) => setFormPassword(e.target.value)}
                    placeholder="••••••••"
                    className="bg-secondary border-border pr-10"
                  />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-xs font-display tracking-wider text-muted-foreground mb-2">
                  API KEY {formBackend === "elastic" && "(PREFERRED)"}
                </label>
                <Input
                  type="password"
                  value={formApiKey}
                  onChange={(e: any) => setFormApiKey(e.target.value)}
                  placeholder="Base64-encoded API key"
                  className="bg-secondary border-border"
                />
              </div>
            </div>

            <div className="flex items-center gap-6 mb-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formInsecure}
                  onChange={(e) => setFormInsecure(e.target.checked)}
                  className="accent-primary"
                />
                <span className="text-sm">Skip TLS verification (self-signed certs)</span>
              </label>
              {formBackend === "elastic" && (
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formUseSecurityDetections}
                    onChange={(e) => setFormUseSecurityDetections(e.target.checked)}
                    className="accent-primary"
                  />
                  <span className="text-sm">Use Elastic Security detection rules</span>
                </label>
              )}
            </div>

            <div className="flex gap-2">
              <Button
                className="font-display bg-primary hover:bg-primary/90"
                onClick={handleSave}
                disabled={saveConnection.isPending}
              >
                {saveConnection.isPending ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <CheckCircle className="w-4 h-4 mr-2" />
                )}
                SAVE & TEST
              </Button>
              <Button variant="outline" className="font-display" onClick={resetForm}>
                CANCEL
              </Button>
            </div>
          </div>
        )}

        {/* Connections List */}
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
          </div>
        ) : connections && connections.length > 0 ? (
          <div className="space-y-3">
            {connections.map((conn: any) => (
              <div
                key={conn.id}
                className={`bg-card border-2 p-4 transition-colors ${
                  conn.connected ? "border-green-500/30" : "border-border"
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div
                      className={`w-10 h-10 flex items-center justify-center ${
                        conn.connected ? "bg-green-500/20" : "bg-red-500/20"
                      }`}
                    >
                      {conn.connected ? (
                        <Wifi className="w-5 h-5 text-green-400" />
                      ) : (
                        <WifiOff className="w-5 h-5 text-red-400" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-display text-lg">{conn.name}</span>
                        <Badge
                          variant={conn.backend === "wazuh" ? "default" : "secondary"}
                          className="font-display text-xs"
                        >
                          {(conn.backend || '').toUpperCase()}
                        </Badge>
                        {!conn.enabled && (
                          <Badge variant="outline" className="text-xs text-muted-foreground">
                            DISABLED
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        <span className="font-mono">{conn.baseUrl}</span>
                        {conn.version && <span>v{conn.version}</span>}
                        {conn.clusterName && <span>{conn.clusterName}</span>}
                        {conn.alertCount !== null && (
                          <span className="flex items-center gap-1">
                            <Activity className="w-3 h-3" />
                            {conn.alertCount.toLocaleString()} alerts
                          </span>
                        )}
                      </div>
                      {conn.errorMessage && (
                        <div className="flex items-center gap-1 text-xs text-red-400 mt-1">
                          <AlertTriangle className="w-3 h-3" />
                          {conn.errorMessage}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="font-display"
                      onClick={() => testConnection.mutate({ id: conn.id })}
                      disabled={testConnection.isPending}
                    >
                      {testConnection.isPending ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <RefreshCw className="w-4 h-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="font-display"
                      onClick={() =>
                        toggleConnection.mutate({
                          id: conn.id,
                          enabled: !conn.enabled,
                        })
                      }
                    >
                      {conn.enabled ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-red-400 hover:text-red-300 font-display"
                      onClick={() => {
                        if (confirm("Delete this connection?")) {
                          deleteConnection.mutate({ id: conn.id });
                        }
                      }}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-card border-2 border-border p-12 text-center">
            <Server className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="font-display text-xl mb-2">NO SIEM CONNECTIONS</h3>
            <p className="text-muted-foreground mb-4 max-w-md mx-auto">
              Connect your Wazuh or Elastic SIEM to enable live alert ingestion and detection
              correlation during red team campaigns.
            </p>
            <Button
              className="font-display bg-primary hover:bg-primary/90"
              onClick={() => setShowAddForm(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              ADD YOUR FIRST CONNECTION
            </Button>
          </div>
        )}

        {/* How It Works */}
        <div className="bg-card border-2 border-border p-6">
          <h2 className="font-display text-xl mb-4">HOW SIEM CORRELATION WORKS</h2>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="space-y-2">
              <div className="w-8 h-8 bg-primary/20 flex items-center justify-center font-display text-primary">
                1
              </div>
              <h3 className="font-display">CONNECT</h3>
              <p className="text-sm text-muted-foreground">
                Add your Wazuh Manager or Elasticsearch endpoint. The connector authenticates and
                verifies access to alert indices.
              </p>
            </div>
            <div className="space-y-2">
              <div className="w-8 h-8 bg-primary/20 flex items-center justify-center font-display text-primary">
                2
              </div>
              <h3 className="font-display">CORRELATE</h3>
              <p className="text-sm text-muted-foreground">
                During a campaign, click "SIEM Correlation" on the Campaign Detail page. Alerts are
                matched to MITRE ATT&CK techniques in your campaign.
              </p>
            </div>
            <div className="space-y-2">
              <div className="w-8 h-8 bg-primary/20 flex items-center justify-center font-display text-primary">
                3
              </div>
              <h3 className="font-display">SCORE</h3>
              <p className="text-sm text-muted-foreground">
                The Evasion Scorecard computes real-time detection coverage — showing which
                techniques were caught and which slipped through.
              </p>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
